import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  ArrowRight,
  BrainCircuit,
  FileWarning,
  RefreshCw,
  ScrollText,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { api } from "../api/client";
import { hasPermission, isSystemTier, isTenantTier, loadSession } from "../auth/session";
import { ControlRail, type ControlSignal } from "../components/ControlRail";
import { StatusPill } from "../components/StatusPill";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { Hint } from "../components/primitives/Hint";
import { nodeStatusLabel, resultLabel, type StatusTone } from "../lib/status";
import { humanizeToken } from "../lib/text";
import "./Dashboard.css";

interface RuntimeSnapshot {
  deployment_id: string;
  config: { db_revision: number | null };
  outbox: { unpublished_count: number; oldest_unpublished_age_seconds: number | null };
  dead_letters: { count: number };
  scanner: { total: number; active: number; draining: number; offline: number };
}

interface QuarantineRow {
  tenant_message_id: string;
}

interface AuditEvent {
  id: string;
  created_at: string;
  actor_login: string;
  action: string;
  resource_type: string;
  result: string;
}

interface AuditEventPage {
  events: AuditEvent[];
}

interface ScannerOperationsResponse {
  node: { node_id: string; status: string };
}

interface DomainSecuritySummary {
  domains_total: number;
  verified_domains: number;
  messages_30d: number;
  open_notifications: number;
}

interface DomainSecurityPage {
  summary: DomainSecuritySummary;
}

type HealthRow = {
  key: string;
  label: string;
  pending: boolean;
  tone: StatusTone;
  value: string;
};

function timeAgo(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function formatAge(seconds: number | null): string | null {
  if (seconds === null) return null;
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86_400)}d`;
}

function outboxTone(unpublished: number, oldest: number | null): StatusTone {
  if (oldest !== null && oldest > 300) return "threat";
  if (unpublished > 0) return "review";
  return "clean";
}

function dashboardOutboxDetail(unpublished: number, oldestAge: string | null): string {
  if (unpublished === 0) return "Publication queue is clear; inspect runtime controls";
  return oldestAge
    ? `${unpublished} waiting to publish · oldest ${oldestAge}`
    : `${unpublished} message${unpublished === 1 ? "" : "s"} waiting to publish`;
}

function healthTone(healthy: boolean): StatusTone {
  return healthy ? "clean" : "threat";
}

function Skeleton({ width }: { width?: string }) {
  return <span className="skeleton" style={width ? { width } : undefined} />;
}

export function Dashboard() {
  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const current = session.data ?? null;
  const systemTier = isSystemTier(current);
  const tenantTier = isTenantTier(current);
  const canOperations = hasPermission(current, "operations:view");
  const canScanner = hasPermission(current, "scanner:operations:view");
  const canDomainSecurity = hasPermission(current, "domain-security:view");

  const runtime = useQuery({
    queryKey: ["operations-runtime"],
    queryFn: ({ signal }) => api.get<RuntimeSnapshot>("/operations/runtime", signal),
    staleTime: 15_000,
    enabled: canOperations,
  });

  const quarantine = useQuery({
    queryKey: ["quarantine"],
    queryFn: ({ signal }) => api.get<QuarantineRow[]>("/quarantine", signal),
    staleTime: 15_000,
    enabled: hasPermission(current, "quarantine:view"),
  });

  const activity = useQuery({
    queryKey: ["dashboard-audit"],
    queryFn: ({ signal }) => api.get<AuditEventPage>("/audit/events?limit=5", signal),
    staleTime: 15_000,
    enabled: hasPermission(current, "audit:view"),
  });

  const scanner = useQuery({
    queryKey: ["scanner-operations"],
    queryFn: ({ signal }) => api.get<ScannerOperationsResponse>("/scanner-operations", signal),
    staleTime: 15_000,
    enabled: canScanner,
  });

  const domainSecurity = useQuery({
    queryKey: ["domain-security"],
    queryFn: ({ signal }) => api.get<DomainSecurityPage>("/domain-security", signal),
    staleTime: 15_000,
    enabled: canDomainSecurity,
  });

  // A query the operator cannot reach stays disabled, so it must not count as
  // loading or failed: a tenant page would otherwise report a load failure for
  // platform data it is never allowed to read.
  const visibleQueries = [
    ...(hasPermission(current, "quarantine:view") ? [quarantine] : []),
    ...(hasPermission(current, "audit:view") ? [activity] : []),
    ...(canOperations ? [runtime] : []),
    ...(canScanner ? [scanner] : []),
    ...(canDomainSecurity ? [domainSecurity] : []),
  ];

  const failed = visibleQueries.some((query) => query.isError);
  const loading = visibleQueries.some((query) => query.isLoading);

  function retry() {
    if (canOperations) void runtime.refetch();
    if (canScanner) void scanner.refetch();
    if (canDomainSecurity) void domainSecurity.refetch();
    void quarantine.refetch();
    void activity.refetch();
  }

  const data = runtime.data;
  const outbox = data?.outbox;
  const deadLetters = data?.dead_letters.count ?? null;
  const scannerNodes = data ? `${data.scanner.active}/${data.scanner.total}` : null;
  const quarantined = quarantine.data?.length ?? null;
  const nodeStatus = scanner.data?.node.status ?? null;
  const oldestAge = outbox ? formatAge(outbox.oldest_unpublished_age_seconds) : null;
  const domainSummary = domainSecurity.data?.summary ?? null;
  const openFindings = domainSummary?.open_notifications ?? null;
  const unverifiedDomains = domainSummary
    ? Math.max(0, domainSummary.domains_total - domainSummary.verified_domains)
    : null;
  const workspaceTitle = systemTier ? "System overview" : "Security overview";

  const outboxStale =
    outbox !== undefined &&
    outbox.oldest_unpublished_age_seconds !== null &&
    outbox.oldest_unpublished_age_seconds > 300;
  const scannerDegraded = nodeStatus !== null && nodeStatus !== "healthy";
  const attentionItems: Array<{
    label: string;
    detail: string;
    to: string;
    tone: StatusTone;
  }> = [];
  if (deadLetters !== null && deadLetters > 0) {
    attentionItems.push({
      label: `${deadLetters} dead letter${deadLetters === 1 ? "" : "s"} need review`,
      detail: "Failed messages are held for review in Operations.",
      to: "/operations",
      tone: "threat",
    });
  }
  if (outboxStale) {
    attentionItems.push({
      label: "Publication queue is overdue",
      detail: `The oldest waiting message is ${oldestAge ?? "unknown"} old.`,
      to: "/operations",
      tone: "threat",
    });
  }
  if (quarantined !== null && quarantined > 0) {
    attentionItems.push({
      label: `${quarantined} held message${quarantined === 1 ? "" : "s"} waiting for a decision`,
      detail: "Work the highest-severity ones first. Releasing needs re-authentication.",
      to: "/quarantine",
      tone: "review",
    });
  }
  if (openFindings !== null && openFindings > 0) {
    attentionItems.push({
      label: `${openFindings} domain security finding${openFindings === 1 ? "" : "s"} open`,
      detail:
        "Each one names the domain and the check that failed. Acknowledging records who decided.",
      to: "/domain-security",
      tone: "review",
    });
  }
  if (unverifiedDomains !== null && unverifiedDomains > 0) {
    attentionItems.push({
      label: `${unverifiedDomains} domain${unverifiedDomains === 1 ? "" : "s"} still unverified`,
      detail: "Verification proves the domain belongs to this customer before mail flows on it.",
      to: "/customers",
      tone: "review",
    });
  }
  if (scannerDegraded) {
    attentionItems.push({
      label: `Scanner node is ${nodeStatusLabel(nodeStatus as string).toLowerCase()}`,
      detail: "Reduced scanner health slows how quickly new mail is classified.",
      to: "/scanner-operations",
      tone: "review",
    });
  }
  // "Nothing needs attention" is a claim about the signals this operator is
  // allowed to read, so it waits for every one of them to actually load.
  const signalsReady =
    visibleQueries.length > 0 &&
    !loading &&
    visibleQueries.every((query) => query.isSuccess || query.isError);
  const attentionResolved = !failed && signalsReady && attentionItems.length === 0;

  const commandActions = [
    hasPermission(current, "quarantine:view")
      ? {
          to: "/quarantine",
          icon: ShieldAlert,
          label: "Triage quarantine",
          detail:
            quarantined !== null
              ? `${quarantined} message${quarantined === 1 ? "" : "s"} waiting for a decision`
              : "Review held mail and release only with re-authentication",
        }
      : null,
    canOperations
      ? {
          to: "/operations",
          icon: Server,
          label: "Inspect runtime",
          detail: outbox
            ? dashboardOutboxDetail(outbox.unpublished_count, oldestAge)
            : "Check nodes, queues, config versions and refresh controls",
        }
      : null,
    canScanner
      ? {
          to: "/scanner-operations",
          icon: BrainCircuit,
          label: "Check scanner health",
          detail: nodeStatus
            ? `Primary node ${nodeStatusLabel(nodeStatus).toLowerCase()}`
            : "Confirm scanner node health",
        }
      : null,
    canDomainSecurity
      ? {
          to: "/domain-security",
          icon: ShieldCheck,
          label: "Review domain security",
          detail:
            openFindings !== null
              ? `${openFindings} open finding${openFindings === 1 ? "" : "s"} across ${
                  domainSummary?.domains_total ?? 0
                } domain${domainSummary?.domains_total === 1 ? "" : "s"}`
              : "Check SPF, DKIM, DMARC and BIMI posture for your domains",
        }
      : null,
    hasPermission(current, "policies:view")
      ? {
          to: "/policies",
          icon: SlidersHorizontal,
          label: tenantTier ? "Manage your mail controls" : "Manage policy",
          detail: tenantTier
            ? "Adjust the families your customer owns; platform floors stay locked"
            : "Adjust mail controls for a customer without disabling security floors",
        }
      : null,
    hasPermission(current, "audit:view")
      ? {
          to: "/audit-log",
          icon: ScrollText,
          label: "Review audit",
          detail: "Trace administrative and security-sensitive actions",
        }
      : null,
    canOperations
      ? {
          to: "/operations",
          icon: FileWarning,
          label: "Inspect dead letters",
          detail:
            deadLetters !== null
              ? `${deadLetters} failed message${deadLetters === 1 ? "" : "s"} need review`
              : "Inspect failed publication and re-injection messages",
        }
      : null,
  ].filter((action): action is NonNullable<typeof action> => action !== null);

  const signals: Array<ControlSignal | null> = [
    hasPermission(current, "quarantine:view")
      ? {
          label: "Quarantine",
          value: quarantine.isSuccess
            ? quarantined
            : quarantine.isError
              ? "Unavailable"
              : "Loading",
          detail: quarantine.isSuccess
            ? "Messages on hold. Open the quarantine queue to review them."
            : "The count appears once held mail finishes loading.",
          tone: quarantine.isSuccess ? (quarantined ? "attention" : "healthy") : "neutral",
        }
      : null,
    canDomainSecurity
      ? {
          label: "Unresolved findings",
          value: domainSecurity.isSuccess
            ? (openFindings ?? "—")
            : domainSecurity.isError
              ? "Unavailable"
              : "Loading",
          detail: domainSecurity.isSuccess
            ? "Unacknowledged domain security findings for this customer."
            : "The count appears once domain security loads.",
          tone: domainSecurity.isSuccess ? (openFindings ? "attention" : "healthy") : "neutral",
        }
      : null,
    canOperations
      ? {
          label: "Pending publication",
          value: runtime.isSuccess
            ? (outbox?.unpublished_count ?? "—")
            : runtime.isError
              ? "Unavailable"
              : "Loading",
          detail: runtime.isSuccess
            ? "Messages waiting to be published. Inspect runtime operations."
            : "The count appears once the runtime status loads.",
          tone: runtime.isSuccess
            ? outbox?.unpublished_count
              ? "attention"
              : "healthy"
            : "neutral",
        }
      : null,
    canOperations
      ? {
          label: "Dead letters",
          value: runtime.isSuccess
            ? (deadLetters ?? "—")
            : runtime.isError
              ? "Unavailable"
              : "Loading",
          detail: runtime.isSuccess
            ? "Messages that need review. Nothing changes from this dashboard."
            : "The count appears once the runtime status loads.",
          tone: runtime.isSuccess ? (deadLetters ? "attention" : "healthy") : "neutral",
        }
      : null,
  ];
  const controlSignals = signals.filter((signal): signal is ControlSignal => signal !== null);

  const healthRows: HealthRow[] = [];
  if (hasPermission(current, "quarantine:view")) {
    healthRows.push({
      key: "quarantine",
      label: "Quarantine",
      pending: quarantine.isPending,
      tone: healthTone(quarantined === 0),
      value:
        quarantined === null
          ? "Unavailable"
          : quarantined === 0
            ? "Nothing held"
            : `${quarantined} held`,
    });
  }
  if (canDomainSecurity) {
    healthRows.push({
      key: "domain-findings",
      label: "Domain findings",
      pending: domainSecurity.isPending,
      tone: healthTone(openFindings === 0),
      value:
        openFindings === null
          ? "Unavailable"
          : openFindings === 0
            ? "All acknowledged"
            : `${openFindings} open`,
    });
    healthRows.push({
      key: "verified-domains",
      label: "Verified domains",
      pending: domainSecurity.isPending,
      tone: healthTone(unverifiedDomains === 0),
      value: domainSummary
        ? `${domainSummary.verified_domains} of ${domainSummary.domains_total}`
        : "Unavailable",
    });
  }
  if (canScanner) {
    healthRows.push({
      key: "scanner-node",
      label: "Scanner node",
      pending: scanner.isPending,
      tone: healthTone(nodeStatus === "healthy"),
      value: nodeStatus === null ? "Unavailable" : nodeStatusLabel(nodeStatus),
    });
  }
  if (canOperations) {
    healthRows.push({
      key: "pending-publication",
      label: "Pending publication",
      pending: runtime.isPending,
      tone: outbox
        ? outboxTone(outbox.unpublished_count, outbox.oldest_unpublished_age_seconds)
        : "threat",
      value: outbox
        ? outbox.unpublished_count === 0
          ? "Clear"
          : `${outbox.unpublished_count} waiting`
        : "Unavailable",
    });
    healthRows.push({
      key: "dead-letters",
      label: "Dead letters",
      pending: runtime.isPending,
      tone: healthTone(deadLetters === 0),
      value:
        deadLetters === null
          ? "Unavailable"
          : deadLetters === 0
            ? "None"
            : `${deadLetters} pending`,
    });
    healthRows.push({
      key: "configuration",
      label: "Configuration",
      pending: runtime.isPending,
      tone: healthTone(data?.config.db_revision !== null && data !== undefined),
      value:
        data === undefined
          ? "Unavailable"
          : data.config.db_revision !== null
            ? `Version ${data.config.db_revision} current`
            : "Unknown",
    });
  }

  return (
    <div className="dashboard">
      <WorkspaceHeader
        eyebrow={
          systemTier
            ? "Platform overview"
            : tenantTier
              ? "Your mail security"
              : "Customer security operations"
        }
        title={workspaceTitle}
        description={
          systemTier
            ? "Review this installation, manage its security posture, and open a customer only through the Customer entry workflow."
            : tenantTier
              ? "Review mail security for your customer. Platform runtime health is managed by your provider."
              : "Review mail-security signals and use the controls allowed for this workspace."
        }
        scope={systemTier ? "All customers" : tenantTier ? "Your customer" : "Customer workspace"}
        actions={
          <button type="button" className="btn btn-ghost dashboard-reload" onClick={retry}>
            <RefreshCw size={14} aria-hidden="true" />
            Refresh signals
          </button>
        }
      >
        <p className="dashboard-subtitle">
          {data
            ? `Installation ${data.deployment_id} · configuration version ${data.config.db_revision ?? "unknown"}`
            : tenantTier && domainSummary !== null
              ? `${domainSummary.domains_total} domain${
                  domainSummary.domains_total === 1 ? "" : "s"
                } · ${domainSummary.messages_30d.toLocaleString("en-US")} messages in the last 30 days`
              : tenantTier
                ? "Live status loads from the pages your roles can open."
                : "Live status loads from the operations pages."}
        </p>
      </WorkspaceHeader>

      <ControlRail
        title={
          systemTier
            ? "Platform priority queue"
            : tenantTier
              ? "Customer priority queue"
              : "Security priority queue"
        }
        summary="These links open where you can investigate or act."
        signals={controlSignals}
      />

      {(attentionItems.length > 0 || attentionResolved) && (
        <section className="card attention-panel" aria-label="Needs attention">
          <div className="section-head">
            <h2 className="section-title">Needs attention</h2>
          </div>
          {attentionItems.length === 0 ? (
            <p className="dashboard-empty">
              {tenantTier
                ? "Nothing needs attention in your customer's signals right now."
                : "Nothing requires operator attention right now. The queues and scanner health are clear."}
            </p>
          ) : (
            <ul className="attention-list">
              {attentionItems.map((item) => (
                <li key={item.label} className="attention-item">
                  <StatusPill
                    tone={item.tone}
                    label={item.tone === "threat" ? "Act now" : "Review"}
                  />
                  <div className="attention-copy">
                    <strong>{item.label}</strong>
                    <span>{item.detail}</span>
                  </div>
                  <Link to={item.to} className="section-link">
                    Open <ArrowRight size={14} aria-hidden="true" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {failed ? (
        <div className="dashboard-error" role="alert">
          Some dashboard data could not be loaded. The pages behind each metric remain available.
          <button type="button" className="btn btn-ghost" onClick={retry}>
            Retry
          </button>
        </div>
      ) : null}

      <section className="card metric-strip" aria-label="Key metrics">
        {hasPermission(current, "quarantine:view") ? (
          <Link to="/quarantine" className="metric-stat primary">
            <span className="metric-label">Quarantined now</span>
            <span className={`metric-value${quarantined ? " attention" : ""}`}>
              {quarantine.isPending ? <Skeleton width="2.5ch" /> : (quarantined ?? "—")}
            </span>
            <span className="metric-cta">Open quarantine</span>
          </Link>
        ) : null}
        {canDomainSecurity ? (
          <>
            <Link to="/domain-security" className="metric-stat">
              <span className="metric-label">Open domain findings</span>
              <span className={`metric-value${openFindings ? " attention" : ""}`}>
                {domainSecurity.isPending ? <Skeleton width="2.5ch" /> : (openFindings ?? "—")}
              </span>
              <span className="metric-cta">Open domain security</span>
            </Link>
            <Link to="/customers" className="metric-stat">
              <span className="metric-label">Unverified domains</span>
              <span className={`metric-value${unverifiedDomains ? " attention" : ""}`}>
                {domainSecurity.isPending ? <Skeleton width="2.5ch" /> : (unverifiedDomains ?? "—")}
              </span>
              <span className="metric-cta">Open your organisation</span>
            </Link>
          </>
        ) : null}
        {canOperations ? (
          <>
            <Link to="/operations" className="metric-stat">
              <span className="metric-label">
                <Hint label="Messages recorded but not yet published to the next system. Open Operations to review.">
                  <span className="hint-term">Pending publication</span>
                </Hint>
              </span>
              <span className="metric-value">
                {runtime.isPending ? (
                  <Skeleton width="2.5ch" />
                ) : (
                  (outbox?.unpublished_count ?? "—")
                )}
              </span>
              <span className="metric-cta">
                {oldestAge ? `Oldest ${oldestAge} · ` : ""}Open operations
              </span>
            </Link>
            <Link to="/operations" className="metric-stat">
              <span className="metric-label">Dead letters</span>
              <span className={`metric-value${deadLetters ? " threat" : ""}`}>
                {runtime.isPending ? <Skeleton width="2.5ch" /> : (deadLetters ?? "—")}
              </span>
              <span className="metric-cta">Open operations</span>
            </Link>
          </>
        ) : null}
        {canScanner ? (
          <Link to="/scanner-operations" className="metric-stat">
            <span className="metric-label">Scanner nodes active</span>
            <span className="metric-value">
              {runtime.isPending ? <Skeleton width="3ch" /> : (scannerNodes ?? "—")}
            </span>
            <span className="metric-cta">Open scanner operations</span>
          </Link>
        ) : null}
      </section>

      <section className="card command-panel" aria-labelledby="command-panel-heading">
        <div className="section-head command-panel-head">
          <div>
            <span className="eyebrow">
              {systemTier
                ? "System shortcuts"
                : tenantTier
                  ? "Your shortcuts"
                  : "Security shortcuts"}
            </span>
            <h2 id="command-panel-heading" className="section-title">
              Choose where to work
            </h2>
          </div>
          {canOperations ? (
            <Link to="/operations" className="section-link">
              Runtime operations <ArrowRight size={14} aria-hidden="true" />
            </Link>
          ) : null}
        </div>
        <div className="command-grid">
          {commandActions.map((action) => {
            const Icon = action.icon;
            return (
              <Link key={action.label} to={action.to} className="command-action">
                <span className="command-action-icon">
                  <Icon size={19} aria-hidden="true" />
                </span>
                <span>
                  <span className="command-action-label">{action.label}</span>
                  <span className="command-action-detail">{action.detail}</span>
                </span>
                <ArrowRight className="command-action-arrow" size={16} aria-hidden="true" />
              </Link>
            );
          })}
        </div>
      </section>

      <div className="dashboard-sections">
        <section className="card">
          <div className="section-head">
            <h2 className="section-title">Recent activity</h2>
            <Link to="/audit-log" className="section-link">
              Audit log <ArrowRight size={14} aria-hidden="true" />
            </Link>
          </div>
          {activity.isLoading ? (
            <div className="activity-list">
              {[0, 1, 2].map((index) => (
                <div className="activity-item" key={index}>
                  <Skeleton width="70px" />
                  <Skeleton width="60%" />
                </div>
              ))}
            </div>
          ) : (activity.data?.events.length ?? 0) === 0 ? (
            <p className="dashboard-empty">No administrative activity recorded yet.</p>
          ) : (
            <div className="activity-list">
              {activity.data?.events.map((event) => (
                <div className="activity-item" key={event.id}>
                  <span className="activity-time">{timeAgo(event.created_at)}</span>
                  <span className="activity-text">
                    <strong>{event.actor_login}</strong> {humanizeToken(event.action)} on{" "}
                    {humanizeToken(event.resource_type)} · {resultLabel(event.result)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="card">
          <h2 className="section-title">
            {systemTier ? "System health" : tenantTier ? "Your mail security" : "Workspace health"}
          </h2>
          <div className="health-list">
            {healthRows.map((row) => (
              <div className="health-item" key={row.key}>
                <span>{row.label}</span>
                {row.pending ? (
                  <Skeleton width="90px" />
                ) : (
                  <StatusPill tone={row.tone} label={row.value} />
                )}
              </div>
            ))}
          </div>
          {tenantTier ? (
            <p className="dashboard-empty">
              Platform runtime health, scanner nodes and model registries are operated by your
              provider. Nothing on this page changes mail flow.
            </p>
          ) : null}
        </section>
      </div>
    </div>
  );
}

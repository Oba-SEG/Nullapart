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
  SlidersHorizontal,
} from "lucide-react";
import { api } from "../api/client";
import { isSystemAdmin, loadSession } from "../auth/session";
import { ControlRail } from "../components/ControlRail";
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
  const runtime = useQuery({
    queryKey: ["operations-runtime"],
    queryFn: ({ signal }) => api.get<RuntimeSnapshot>("/operations/runtime", signal),
    staleTime: 15_000,
  });

  const quarantine = useQuery({
    queryKey: ["quarantine"],
    queryFn: ({ signal }) => api.get<QuarantineRow[]>("/quarantine", signal),
    staleTime: 15_000,
  });

  const activity = useQuery({
    queryKey: ["dashboard-audit"],
    queryFn: ({ signal }) => api.get<AuditEventPage>("/audit/events?limit=5", signal),
    staleTime: 15_000,
  });

  const scanner = useQuery({
    queryKey: ["scanner-operations"],
    queryFn: ({ signal }) => api.get<ScannerOperationsResponse>("/scanner-operations", signal),
    staleTime: 15_000,
  });

  const failed = [runtime, quarantine, activity, scanner].some((query) => query.isError);
  const loading = [runtime, quarantine, activity, scanner].some((query) => query.isLoading);

  function retry() {
    void runtime.refetch();
    void quarantine.refetch();
    void activity.refetch();
    void scanner.refetch();
  }

  const data = runtime.data;
  const outbox = data?.outbox;
  const deadLetters = data?.dead_letters.count ?? null;
  const scannerNodes = data ? `${data.scanner.active}/${data.scanner.total}` : null;
  const quarantined = quarantine.data?.length ?? null;
  const nodeStatus = scanner.data?.node.status ?? null;
  const oldestAge = outbox ? formatAge(outbox.oldest_unpublished_age_seconds) : null;
  const systemAdmin = isSystemAdmin(session.data ?? null);
  const workspaceTitle = systemAdmin ? "System overview" : "Security overview";

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
  if (scannerDegraded) {
    attentionItems.push({
      label: `Scanner node is ${nodeStatusLabel(nodeStatus as string).toLowerCase()}`,
      detail: "Reduced scanner health slows how quickly new mail is classified.",
      to: "/scanner-operations",
      tone: "review",
    });
  }
  const attentionResolved = !loading && !failed && attentionItems.length === 0;

  const commandActions = [
    {
      to: "/quarantine",
      icon: ShieldAlert,
      label: "Triage quarantine",
      detail:
        quarantined !== null
          ? `${quarantined} message${quarantined === 1 ? "" : "s"} waiting for a decision`
          : "Review held mail and release only with re-authentication",
    },
    {
      to: "/operations",
      icon: Server,
      label: "Inspect runtime",
      detail: outbox
        ? dashboardOutboxDetail(outbox.unpublished_count, oldestAge)
        : "Check nodes, queues, config versions and refresh controls",
    },
    {
      to: "/scanner-operations",
      icon: BrainCircuit,
      label: "Check scanner health",
      detail: nodeStatus
        ? `Primary node ${nodeStatusLabel(nodeStatus).toLowerCase()}`
        : "Confirm scanner node health",
    },
    {
      to: "/policies",
      icon: SlidersHorizontal,
      label: "Manage policy",
      detail: "Adjust mail controls for a customer without disabling security floors",
    },
    {
      to: "/audit-log",
      icon: ScrollText,
      label: "Review audit",
      detail: "Trace administrative and security-sensitive actions",
    },
    {
      to: "/operations",
      icon: FileWarning,
      label: "Inspect dead letters",
      detail:
        deadLetters !== null
          ? `${deadLetters} failed message${deadLetters === 1 ? "" : "s"} need review`
          : "Inspect failed publication and re-injection messages",
    },
  ] as const;

  return (
    <div className="dashboard">
      <WorkspaceHeader
        eyebrow={systemAdmin ? "Platform overview" : "Customer security operations"}
        title={workspaceTitle}
        description={
          systemAdmin
            ? "Review this installation, manage its security posture, and open a customer only through the Customer entry workflow."
            : "Review mail-security signals and use the controls allowed for this workspace."
        }
        scope={systemAdmin ? "All customers" : "Customer workspace"}
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
            : "Live status loads from the operations pages."}
        </p>
      </WorkspaceHeader>

      <ControlRail
        title={systemAdmin ? "Platform priority queue" : "Security priority queue"}
        summary="These links open where you can investigate or act."
        signals={[
          {
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
          },
          {
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
          },
          {
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
          },
        ]}
      />

      {(attentionItems.length > 0 || attentionResolved) && (
        <section className="card attention-panel" aria-label="Needs attention">
          <div className="section-head">
            <h2 className="section-title">Needs attention</h2>
          </div>
          {attentionItems.length === 0 ? (
            <p className="dashboard-empty">
              Nothing requires operator attention right now. The queues and scanner health are
              clear.
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
        <Link to="/quarantine" className="metric-stat primary">
          <span className="metric-label">Quarantined now</span>
          <span className={`metric-value${quarantined ? " attention" : ""}`}>
            {loading ? <Skeleton width="2.5ch" /> : (quarantined ?? "—")}
          </span>
          <span className="metric-cta">Open quarantine</span>
        </Link>
        <Link to="/operations" className="metric-stat">
          <span className="metric-label">
            <Hint label="Messages recorded but not yet published to the next system. Open Operations to review.">
              <span className="hint-term">Pending publication</span>
            </Hint>
          </span>
          <span className="metric-value">
            {loading ? <Skeleton width="2.5ch" /> : (outbox?.unpublished_count ?? "—")}
          </span>
          <span className="metric-cta">
            {oldestAge ? `Oldest ${oldestAge} · ` : ""}Open operations
          </span>
        </Link>
        <Link to="/operations" className="metric-stat">
          <span className="metric-label">Dead letters</span>
          <span className={`metric-value${deadLetters ? " threat" : ""}`}>
            {loading ? <Skeleton width="2.5ch" /> : (deadLetters ?? "—")}
          </span>
          <span className="metric-cta">Open operations</span>
        </Link>
        <Link to="/scanner-operations" className="metric-stat">
          <span className="metric-label">Scanner nodes active</span>
          <span className="metric-value">
            {loading ? <Skeleton width="3ch" /> : (scannerNodes ?? "—")}
          </span>
          <span className="metric-cta">Open scanner operations</span>
        </Link>
      </section>

      <section className="card command-panel" aria-labelledby="command-panel-heading">
        <div className="section-head command-panel-head">
          <div>
            <span className="eyebrow">
              {systemAdmin ? "System shortcuts" : "Security shortcuts"}
            </span>
            <h2 id="command-panel-heading" className="section-title">
              Choose where to work
            </h2>
          </div>
          <Link to="/operations" className="section-link">
            Runtime operations <ArrowRight size={14} aria-hidden="true" />
          </Link>
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
          <h2 className="section-title">System health</h2>
          <div className="health-list">
            <div className="health-item">
              <span>Scanner node</span>
              {nodeStatus === null ? (
                <Skeleton width="90px" />
              ) : (
                <StatusPill
                  tone={healthTone(nodeStatus === "healthy")}
                  label={nodeStatusLabel(nodeStatus)}
                />
              )}
            </div>
            <div className="health-item">
              <span>Pending publication</span>
              {outbox ? (
                <StatusPill
                  tone={outboxTone(outbox.unpublished_count, outbox.oldest_unpublished_age_seconds)}
                  label={
                    outbox.unpublished_count === 0 ? "Clear" : `${outbox.unpublished_count} waiting`
                  }
                />
              ) : (
                <Skeleton width="90px" />
              )}
            </div>
            <div className="health-item">
              <span>Dead letters</span>
              {deadLetters === null ? (
                <Skeleton width="90px" />
              ) : (
                <StatusPill
                  tone={healthTone(deadLetters === 0)}
                  label={deadLetters === 0 ? "None" : `${deadLetters} pending`}
                />
              )}
            </div>
            <div className="health-item">
              <span>Configuration</span>
              {data ? (
                <StatusPill
                  tone={healthTone(data.config.db_revision !== null)}
                  label={
                    data.config.db_revision !== null
                      ? `Version ${data.config.db_revision} current`
                      : "Unknown"
                  }
                />
              ) : (
                <Skeleton width="120px" />
              )}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

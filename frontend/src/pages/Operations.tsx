import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import { hasPermission, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
import "./Operations.css";

type RefreshTarget = "deployment" | "tenant" | "node";

interface ConfigScope {
  scope: "system" | "deployment" | "tenant";
  scope_id: string;
  revision_number: number;
  published_by: string;
  published_at: string;
}

interface RuntimeNode {
  id: string;
  node_type: string;
  role: string;
  status: string;
  hostname: string | null;
  version: string;
  config_revision: number | null;
  last_health_check: string | null;
  stale: boolean | null;
}

interface RuntimeSnapshot {
  deployment_id: string;
  config: { db_revision: number | null; scopes: ConfigScope[] };
  nodes: RuntimeNode[];
  outbox: { unpublished_count: number; oldest_unpublished_age_seconds: number | null };
  dead_letters: { count: number };
  scanner: { total: number; active: number; draining: number; offline: number };
  smtp: { commissioning: "not_configured" | "recorded"; detail: string };
}

interface Tier3Capability {
  capability_id: string;
  display_name: string;
  owner: string;
  sli: string;
  slo_target: string;
  error_budget: string;
  measurement_source: string;
  rto_minutes: number;
  rpo_minutes: number;
  dependency_map: string;
  redundancy_design: string;
  degraded_mode: string;
  capacity_threshold: string;
  runbook: string;
  readiness_state: "defined" | "instrumented" | "alerting_active" | "tested" | "not_ready";
  last_exercise_at: string | null;
  updated_at: string;
}

interface AlertRule {
  alert_key: string;
  capability_id: string;
  severity: "ticket" | "page";
  burn_rate: string;
  long_window_minutes: number;
  short_window_minutes: number;
  threshold_description: string;
  owner: string;
  runbook: string;
  suppression: string;
  escalation: string;
  enabled: boolean;
  last_tested_at: string | null;
}

interface ReadinessCheck {
  check_id: string;
  category: string;
  title: string;
  status: "ready" | "partial" | "not_ready" | "blocked";
  owner: string;
  evidence_ref: string;
  runbook: string | null;
  last_verified_at: string | null;
  notes: string;
}

interface OperationsHardening {
  deployment_id: string;
  generated_at: string;
  summary: {
    tier3_capabilities: number;
    capabilities_tested: number;
    alert_rules: number;
    enabled_alert_rules: number;
    readiness_ready: number;
    readiness_partial: number;
    readiness_not_ready: number;
    readiness_blocked: number;
  };
  tier3_capabilities: Tier3Capability[];
  alert_rules: AlertRule[];
  readiness_checks: ReadinessCheck[];
}

interface RefreshBody {
  target: RefreshTarget;
  node_id?: string;
}

interface RefreshResult {
  requested_at: string;
  target: string;
  scope_id: string;
}

const REFRESH_TARGET_OPTIONS: { value: RefreshTarget; label: string }[] = [
  { value: "deployment", label: "Deployment (whole deployment)" },
  { value: "tenant", label: "Tenant (this customer)" },
  { value: "node", label: "Node (single registered node)" },
];

const NODE_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : "";
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    const message = String((error as ApiError).message);
    if (errorCode(error) === "RATE_LIMITED") {
      return `${message} Please wait a moment before retrying.`;
    }
    return message;
  }
  return "Runtime operations are temporarily unavailable.";
}

function refreshErrorMessage(error: unknown): string {
  const code = errorCode(error);
  if (code === "NOT_FOUND" || code === "HTTP_404") {
    return "Node was not found";
  }
  return errorMessage(error);
}

function nodeIdError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return "Enter the node id shown in the nodes table.";
  }
  if (!NODE_ID_PATTERN.test(trimmed)) {
    return "Use 1 to 64 characters: letters, digits, dot, underscore or hyphen.";
  }
  return undefined;
}

function formatAge(seconds: number | null): string {
  if (seconds === null) return "unknown";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86_400)}d`;
}

function outboxLabel(outbox: RuntimeSnapshot["outbox"]): string {
  const backlog = `${outbox.unpublished_count} unpublished`;
  if (outbox.unpublished_count === 0) return backlog;
  return `${backlog} · oldest ${formatAge(outbox.oldest_unpublished_age_seconds)}`;
}

function outboxToneClass(outbox: RuntimeSnapshot["outbox"]): string {
  const oldest = outbox.oldest_unpublished_age_seconds;
  if (oldest !== null && oldest > 300) return "operations-metric-error";
  if (outbox.unpublished_count > 0) return "operations-metric-warning";
  return "";
}

function staleBadge(stale: boolean | null) {
  if (stale === true) {
    return <span className="operations-badge operations-badge-warning">stale config</span>;
  }
  if (stale === false) {
    return <span className="operations-badge operations-badge-ok">current</span>;
  }
  return <span className="operations-badge operations-badge-muted">unknown</span>;
}

function statusBadge(status: string) {
  const tone =
    status === "ready" || status === "tested" || status === "alerting_active"
      ? "ok"
      : status === "not_ready" || status === "blocked"
        ? "error"
        : "warning";
  return (
    <span className={`operations-badge operations-badge-${tone}`}>
      {status.replaceAll("_", " ")}
    </span>
  );
}

function minutesLabel(minutes: number): string {
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h`;
}

export function Operations() {
  const queryClient = useQueryClient();

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const snapshot = useQuery({
    queryKey: ["operations-runtime"],
    queryFn: ({ signal }) => api.get<RuntimeSnapshot>("/operations/runtime", signal),
  });
  const hardening = useQuery({
    queryKey: ["operations-hardening"],
    queryFn: ({ signal }) => api.get<OperationsHardening>("/operations/hardening", signal),
  });

  const current = session.data ?? null;
  const canManage = hasPermission(current, "operations:manage");

  const [dialogOpen, setDialogOpen] = useState(false);
  const [target, setTarget] = useState<RefreshTarget>("deployment");
  const [nodeId, setNodeId] = useState("");
  const [showErrors, setShowErrors] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useMutation({
    mutationFn: (body: RefreshBody) =>
      api.post<RefreshResult>("/operations/refresh", body, {
        idempotencyKey: randomUuid(),
      }),
    onSuccess: async (result) => {
      setNotice(
        `Refresh requested for ${result.scope_id} at ${new Date(result.requested_at).toLocaleString()}.`,
      );
      setDialogOpen(false);
      setTarget("deployment");
      setNodeId("");
      setShowErrors(false);
      await queryClient.invalidateQueries({ queryKey: ["operations-runtime"] });
    },
  });

  function openDialog() {
    setNotice(null);
    setTarget("deployment");
    setNodeId("");
    setShowErrors(false);
    refresh.reset();
    setDialogOpen(true);
  }

  function closeDialog() {
    setDialogOpen(false);
    setShowErrors(false);
    refresh.reset();
  }

  function submitRefresh() {
    if (target === "node" && nodeIdError(nodeId) !== undefined) {
      setShowErrors(true);
      return;
    }
    setShowErrors(false);
    refresh.mutate(target === "node" ? { target, node_id: nodeId.trim() } : { target });
  }

  const data = snapshot.data;
  const scopes = data?.config.scopes ?? [];
  const nodes = data?.nodes ?? [];
  const smtpCommissioning = data?.smtp.commissioning ?? null;
  const hardeningData = hardening.data;

  return (
    <div className="operations-page">
      <header className="operations-header">
        <div>
          <h1 className="operations-title">Runtime operations</h1>
          <p className="operations-subtitle">
            Published configuration, registered nodes and durable queue health for this deployment.
            Values are reported by the running stack; nothing on this page is estimated.
          </p>
          {data ? <p className="operations-meta">Deployment {data.deployment_id}</p> : null}
        </div>
        <div className="operations-header-actions">
          <Button type="button" onClick={() => void snapshot.refetch()}>
            Reload
          </Button>
          {canManage ? (
            <Button type="button" variant="primary" onClick={openDialog}>
              Refresh
            </Button>
          ) : null}
        </div>
      </header>

      {notice ? (
        <p className="operations-notice" role="status">
          {notice}
        </p>
      ) : null}

      {snapshot.isPending ? (
        <div className="operations-state" role="status">
          Loading runtime snapshot…
        </div>
      ) : null}
      {snapshot.isError ? (
        <div className="operations-state error" role="alert">
          {errorMessage(snapshot.error)}
          <StepUpPrompt error={snapshot.error} />
        </div>
      ) : null}
      {hardening.isError ? (
        <div className="operations-state error" role="alert">
          {errorMessage(hardening.error)}
          <StepUpPrompt error={hardening.error} />
        </div>
      ) : null}

      {data ? (
        <>
          <section className="card operations-stats" aria-label="Runtime summary">
            <div className="stat-row">
              <span>DB config revision</span>
              <strong>{data.config.db_revision ?? "none"}</strong>
            </div>
            <div className={`stat-row ${outboxToneClass(data.outbox)}`.trim()}>
              <span>Outbox backlog</span>
              <strong>{outboxLabel(data.outbox)}</strong>
            </div>
            <div className="stat-row">
              <span>Dead letters</span>
              <strong>{data.dead_letters.count}</strong>
            </div>
            <div className="stat-row">
              <span>Scanner nodes</span>
              <strong>
                {data.scanner.active}/{data.scanner.total}
              </strong>
            </div>
          </section>

          {hardening.isPending ? (
            <div className="operations-state" role="status">
              Loading operations-hardening evidence…
            </div>
          ) : null}

          {hardeningData ? (
            <>
              <section className="card operations-stats" aria-label="Phase 9 hardening summary">
                <div className="stat-row">
                  <span>Tier-3 capabilities</span>
                  <strong>{hardeningData.summary.tier3_capabilities}</strong>
                </div>
                <div className="stat-row operations-metric-warning">
                  <span>Enabled burn alerts</span>
                  <strong>
                    {hardeningData.summary.enabled_alert_rules}/{hardeningData.summary.alert_rules}
                  </strong>
                </div>
                <div className="stat-row">
                  <span>Readiness ready</span>
                  <strong>{hardeningData.summary.readiness_ready}</strong>
                </div>
                <div
                  className={`stat-row ${
                    hardeningData.summary.readiness_not_ready > 0 ? "operations-metric-error" : ""
                  }`.trim()}
                >
                  <span>Not ready</span>
                  <strong>{hardeningData.summary.readiness_not_ready}</strong>
                </div>
              </section>

              <section className="card" aria-labelledby="operations-tier3-heading">
                <h2 id="operations-tier3-heading">Tier-3 SLO capabilities</h2>
                <p className="operations-hint">
                  These are deployment-scoped production-critical capabilities from Phase 9. They
                  define SLI/SLO targets, recovery objectives and degraded-mode behaviour without
                  claiming production sign-off.
                </p>
                <div className="operations-table-wrap">
                  <table className="operations-table">
                    <caption className="sr-only">Tier-3 SLO capability register</caption>
                    <thead>
                      <tr>
                        <th scope="col">Capability</th>
                        <th scope="col">Owner</th>
                        <th scope="col">SLO / budget</th>
                        <th scope="col">RTO/RPO</th>
                        <th scope="col">State</th>
                        <th scope="col">Runbook</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hardeningData.tier3_capabilities.map((capability) => (
                        <tr key={capability.capability_id}>
                          <td>
                            <span className="operations-node-id">{capability.display_name}</span>
                            <span className="operations-meta">{capability.sli}</span>
                          </td>
                          <td>{capability.owner}</td>
                          <td>
                            {capability.slo_target}
                            <span className="operations-meta">
                              Budget: {capability.error_budget}
                            </span>
                          </td>
                          <td>
                            {minutesLabel(capability.rto_minutes)} /{" "}
                            {minutesLabel(capability.rpo_minutes)}
                          </td>
                          <td>{statusBadge(capability.readiness_state)}</td>
                          <td className="operations-scope-id" title={capability.runbook}>
                            {capability.runbook}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="card" aria-labelledby="operations-alerts-heading">
                <h2 id="operations-alerts-heading">Burn-rate alert rules</h2>
                <p className="operations-hint">
                  Phase 9 requires fast, sustained and slow-burn paths. Rules remain inactive until
                  monitoring is live and tested.
                </p>
                <div className="operations-table-wrap">
                  <table className="operations-table">
                    <caption className="sr-only">Burn-rate alert definitions</caption>
                    <thead>
                      <tr>
                        <th scope="col">Rule</th>
                        <th scope="col">Severity</th>
                        <th scope="col">Burn</th>
                        <th scope="col">Windows</th>
                        <th scope="col">Enabled</th>
                        <th scope="col">Escalation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hardeningData.alert_rules.map((rule) => (
                        <tr key={rule.alert_key}>
                          <td>
                            <span className="operations-node-id">{rule.alert_key}</span>
                            <span className="operations-meta">{rule.threshold_description}</span>
                          </td>
                          <td>{statusBadge(rule.severity)}</td>
                          <td>{rule.burn_rate}x</td>
                          <td>
                            {minutesLabel(rule.long_window_minutes)} +{" "}
                            {minutesLabel(rule.short_window_minutes)}
                          </td>
                          <td>{statusBadge(rule.enabled ? "ready" : "not_ready")}</td>
                          <td>{rule.escalation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="card" aria-labelledby="operations-readiness-heading">
                <h2 id="operations-readiness-heading">Production-readiness evidence</h2>
                <p className="operations-hint">
                  A ready product still needs deployment evidence: exercises, monitoring, restore
                  proof, source controls and production approvals are tracked here.
                </p>
                <div className="operations-table-wrap">
                  <table className="operations-table">
                    <caption className="sr-only">Production-readiness checks</caption>
                    <thead>
                      <tr>
                        <th scope="col">Check</th>
                        <th scope="col">Category</th>
                        <th scope="col">Status</th>
                        <th scope="col">Owner</th>
                        <th scope="col">Evidence</th>
                        <th scope="col">Notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hardeningData.readiness_checks.map((check) => (
                        <tr key={check.check_id}>
                          <td>{check.title}</td>
                          <td>{check.category.replaceAll("_", " ")}</td>
                          <td>{statusBadge(check.status)}</td>
                          <td>{check.owner}</td>
                          <td className="operations-scope-id" title={check.evidence_ref}>
                            {check.evidence_ref}
                          </td>
                          <td>{check.notes}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          ) : null}

          <section className="card" aria-labelledby="operations-nodes-heading">
            <h2 id="operations-nodes-heading">Nodes</h2>
            {nodes.length === 0 ? (
              <p className="operations-hint">
                No nodes are registered for this deployment yet. Nodes appear here once the running
                stack registers them with the control plane; no rows are shown until then.
              </p>
            ) : (
              <div className="operations-table-wrap">
                <table className="operations-table">
                  <caption className="sr-only">Registered runtime nodes</caption>
                  <thead>
                    <tr>
                      <th scope="col">Node</th>
                      <th scope="col">Type</th>
                      <th scope="col">Role</th>
                      <th scope="col">Status</th>
                      <th scope="col">Version</th>
                      <th scope="col">Config revision</th>
                      <th scope="col">Last health check</th>
                      <th scope="col">Config freshness</th>
                    </tr>
                  </thead>
                  <tbody>
                    {nodes.map((node) => (
                      <tr key={node.id}>
                        <td>
                          <span className="operations-node-id">{node.id}</span>
                          {node.hostname ? (
                            <span className="operations-meta">{node.hostname}</span>
                          ) : null}
                        </td>
                        <td>{node.node_type}</td>
                        <td>{node.role}</td>
                        <td>
                          <span className="operations-badge">{node.status}</span>
                        </td>
                        <td>{node.version}</td>
                        <td>{node.config_revision ?? "—"}</td>
                        <td>
                          {node.last_health_check
                            ? new Date(node.last_health_check).toLocaleString()
                            : "never"}
                        </td>
                        <td>{staleBadge(node.stale)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card" aria-labelledby="operations-config-heading">
            <h2 id="operations-config-heading">Config revisions</h2>
            {scopes.length === 0 ? (
              <p className="operations-hint">
                No configuration scopes have been published for this deployment yet.
              </p>
            ) : (
              <div className="operations-table-wrap">
                <table className="operations-table">
                  <caption className="sr-only">Published configuration scopes</caption>
                  <thead>
                    <tr>
                      <th scope="col">Scope</th>
                      <th scope="col">Scope id</th>
                      <th scope="col">Revision</th>
                      <th scope="col">Published by</th>
                      <th scope="col">Published at</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scopes.map((entry) => (
                      <tr key={`${entry.scope}:${entry.scope_id}`}>
                        <td>
                          <span className="operations-badge">{entry.scope}</span>
                        </td>
                        <td className="operations-scope-id" title={entry.scope_id}>
                          {entry.scope_id}
                        </td>
                        <td>{entry.revision_number}</td>
                        <td>{entry.published_by}</td>
                        <td>{new Date(entry.published_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {smtpCommissioning ? (
            <section className="card operations-smtp" aria-labelledby="operations-smtp-heading">
              <h2 id="operations-smtp-heading">SMTP commissioning</h2>
              <p>
                <span
                  className={`operations-badge operations-badge-${smtpCommissioning === "recorded" ? "ok" : "muted"}`}
                >
                  {smtpCommissioning.replace("_", " ")}
                </span>
                <span>{data.smtp.detail}</span>
              </p>
            </section>
          ) : null}
        </>
      ) : null}

      <Dialog open={dialogOpen} onClose={closeDialog} title="Request configuration refresh">
        <form
          className="operations-form"
          onSubmit={(event) => {
            event.preventDefault();
            submitRefresh();
          }}
        >
          <p className="operations-hint">
            The refresh is audited and emits a config change event so registered nodes reload the
            published revision. The scope is resolved server-side from your session.
          </p>
          <Select
            label="Target"
            value={target}
            options={REFRESH_TARGET_OPTIONS}
            onChange={(event) => {
              const next = event.target.value;
              setTarget(next === "tenant" || next === "node" ? next : "deployment");
              setShowErrors(false);
            }}
          />
          {target === "node" ? (
            <Input
              label="Node id"
              value={nodeId}
              onChange={(event) => setNodeId(event.target.value)}
              placeholder="mx-1"
              maxLength={64}
              error={showErrors ? nodeIdError(nodeId) : undefined}
              hint="The id shown in the nodes table, up to 64 characters."
            />
          ) : null}
          {refresh.isError ? (
            <>
              <p className="operations-error" role="alert">
                {refreshErrorMessage(refresh.error)}
              </p>
              <StepUpPrompt error={refresh.error} />
            </>
          ) : null}
          <div className="operations-form-actions">
            <Button
              type="button"
              variant="ghost"
              onClick={closeDialog}
              disabled={refresh.isPending}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={refresh.isPending}>
              Confirm refresh
            </Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}

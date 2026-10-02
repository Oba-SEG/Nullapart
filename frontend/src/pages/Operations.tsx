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

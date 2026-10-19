import { useQuery } from "@tanstack/react-query";
import { Download, ScrollText } from "lucide-react";
import { useMemo, useState } from "react";

import { api, type ApiError } from "../api/client";
import { isTenantTier, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { ControlRail, type ControlSignal } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import "./AuditLog.css";

import { actorRoleLabels, auditActionLabel } from "../lib/labels";
import { notify } from "../lib/notify";
import { checkpointStatusLabel, resultLabel } from "../lib/status";
import { humanizeToken } from "../lib/text";
interface AuditEvent {
  id: string;
  created_at: string;
  actor_login: string;
  actor_roles: string[];
  impersonated_subject: string | null;
  impersonated_customer: string | null;
  customer_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  result: string;
  reason: string | null;
  source_ip: string | null;
  trace_id: string;
}

interface AuditEventPage {
  events: AuditEvent[];
  next_cursor: string | null;
}

interface AuditDetailField {
  key: string;
  value: string;
}

interface AuditEventDetail extends AuditEvent {
  session_id: string | null;
  details: AuditDetailField[];
}

interface AuditCheckpointStatus {
  state: "current" | "stale" | "not_configured";
  last_checkpoint_at: string | null;
  covers_events_through: string | null;
  checkpoint_sequence: number | null;
  event_count: number | null;
  root_hash: string | null;
  signer_key_id: string | null;
  archive_uri: string | null;
}

interface AuditFilters {
  action: string;
  actor_login: string;
  result: string;
}

const EMPTY_FILTERS: AuditFilters = { action: "", actor_login: "", result: "" };

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "Audit data is temporarily unavailable.";
}

function buildQuery(filters: AuditFilters, cursor?: string): string {
  const params = new URLSearchParams();
  if (filters.action.trim()) params.set("action", filters.action.trim());
  if (filters.actor_login.trim()) params.set("actor_login", filters.actor_login.trim());
  if (filters.result) params.set("result", filters.result);
  params.set("limit", "50");
  if (cursor) params.set("cursor", cursor);
  const query = params.toString();
  return query ? `?${query}` : "";
}

export function AuditLog() {
  const [filters, setFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [appended, setAppended] = useState<AuditEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadMoreError, setLoadMoreError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [exportError, setExportError] = useState<unknown>(null);

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
  });
  const canExport = session.data?.permissions?.includes("audit:export") ?? false;
  // The integrity checkpoint describes the whole append-only ledger of this
  // installation, not the events inside a customer scope, so the tenant console
  // neither reads nor advertises it.
  const tenant = isTenantTier(session.data ?? null);

  const page = useQuery({
    queryKey: ["audit-events", filters],
    queryFn: ({ signal }) => api.get<AuditEventPage>(`/audit/events${buildQuery(filters)}`, signal),
  });

  const checkpoint = useQuery({
    queryKey: ["audit-checkpoint-status"],
    queryFn: ({ signal }) => api.get<AuditCheckpointStatus>("/audit/checkpoint-status", signal),
    // Gated on the resolved session, not just the tier: a pending query reads
    // as "not a tenant" and would issue a platform read from a tenant console.
    enabled: session.isSuccess && !tenant,
  });

  const detail = useQuery({
    queryKey: ["audit-event", selected],
    queryFn: ({ signal }) =>
      api.get<AuditEventDetail>(`/audit/events/${encodeURIComponent(selected ?? "")}`, signal),
    enabled: selected !== null,
  });

  const events = useMemo(() => [...(page.data?.events ?? []), ...appended], [page.data, appended]);
  const cursor = appended.length > 0 ? nextCursor : (page.data?.next_cursor ?? null);

  function applyFilters(next: AuditFilters) {
    setFilters(next);
    setAppended([]);
    setNextCursor(null);
    setLoadMoreError(null);
  }

  async function loadMore() {
    if (!cursor) return;
    setLoadingMore(true);
    setLoadMoreError(null);
    try {
      const next = await api.get<AuditEventPage>(`/audit/events${buildQuery(filters, cursor)}`);
      setAppended((current) => [...current, ...next.events]);
      setNextCursor(next.next_cursor);
    } catch (error) {
      setLoadMoreError(errorMessage(error));
    } finally {
      setLoadingMore(false);
    }
  }

  async function exportCsv() {
    setExportError(null);
    try {
      const blob = await api.download("POST", "/audit/events/export", {
        action: filters.action.trim() || null,
        actor_login: filters.actor_login.trim() || null,
        result: filters.result || null,
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "nullapart-audit-export.csv";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      notify("Audit export downloaded. The export was recorded in the audit log.");
    } catch (error) {
      setExportError(error);
    }
  }

  const signals: ControlSignal[] = [
    {
      label: "Records",
      value: page.isSuccess ? events.length : page.isError ? "Unavailable" : "Loading",
      detail: page.isSuccess
        ? "Audit events loaded under the current filters."
        : "The count appears once the events load.",
    },
    ...(tenant
      ? []
      : [
          {
            label: "Checkpoint",
            value: checkpoint.isSuccess
              ? checkpointStatusLabel(checkpoint.data.state)
              : checkpoint.isError
                ? "Unavailable"
                : "Loading",
            detail: checkpoint.isSuccess
              ? "Integrity checkpoint state for this installation."
              : "Checkpoint status appears once the data loads.",
            tone: (checkpoint.isSuccess
              ? checkpoint.data.state === "current"
                ? "healthy"
                : "attention"
              : "neutral") as ControlSignal["tone"],
          },
        ]),
    {
      label: "Export",
      value: canExport ? "Allowed" : "Restricted",
      detail: "CSV export needs its own permission and is recorded in the log.",
    },
  ];

  return (
    <div className="audit-page">
      <WorkspaceHeader
        eyebrow="Evidence & accountability"
        title="Audit log"
        description="Review administrative and security events you are allowed to see. Records stay redacted, append-only and never show raw event data."
        scope="Read only"
        actions={
          <Hint label="Download the events you can see as a CSV file. Export needs the audit export permission and is recorded.">
            <Button onClick={() => void exportCsv()} disabled={!canExport || events.length === 0}>
              <Download size={16} aria-hidden="true" />
              Export CSV
            </Button>
          </Hint>
        }
      />

      <ControlRail
        title="Evidence queue"
        summary="Filters narrow the records in view. Export is a separate action and needs re-authentication."
        signals={signals}
      />

      <WorkflowGuide
        title="Turn records into an investigation trail"
        description="Search the record, open an event to see its context, then export only the scoped events you are allowed to handle."
        steps={[
          {
            label: "Filter",
            detail: "Narrow by actor, action and result before reviewing individual records.",
          },
          {
            label: "Inspect",
            detail: "Open an event without exposing protected message content or raw event data.",
          },
          {
            label: "Export",
            detail: "Create a scoped CSV only when events must leave the console.",
          },
        ]}
      />

      {canExport && (
        <p className="audit-hint">Exports are limited, recorded and require re-authentication.</p>
      )}

      {tenant ? null : (
        <section className="card audit-checkpoint" aria-label="Audit checkpoint status">
          <div>
            <h2>Checkpoint status</h2>
            {checkpoint.isPending && <p role="status">Loading checkpoint status…</p>}
            {checkpoint.isError && (
              <p className="audit-state error" role="alert">
                {errorMessage(checkpoint.error)}
              </p>
            )}
            {checkpoint.isSuccess && (
              <>
                <p className={`audit-checkpoint-state audit-checkpoint-${checkpoint.data.state}`}>
                  {checkpointStatusLabel(checkpoint.data.state)}
                </p>
                <p className="audit-meta">
                  {checkpoint.data.last_checkpoint_at
                    ? `Last checkpoint ${new Date(
                        checkpoint.data.last_checkpoint_at,
                      ).toLocaleString()}`
                    : "No checkpoint has been recorded for this installation yet."}
                </p>
              </>
            )}
          </div>
          {checkpoint.data?.root_hash && (
            <dl className="audit-checkpoint-detail">
              <div>
                <dt>Sequence</dt>
                <dd>{checkpoint.data.checkpoint_sequence}</dd>
              </div>
              <div>
                <dt>Events covered</dt>
                <dd>{checkpoint.data.event_count}</dd>
              </div>
              <div>
                <dt>Root hash</dt>
                <dd className="audit-hash">{checkpoint.data.root_hash}</dd>
              </div>
              <div>
                <dt>Signer</dt>
                <dd>{checkpoint.data.signer_key_id}</dd>
              </div>
            </dl>
          )}
        </section>
      )}

      <section className="audit-controls" aria-label="Audit filters">
        <Input
          label="Actor login"
          value={filters.actor_login}
          onChange={(event) => applyFilters({ ...filters, actor_login: event.target.value })}
          placeholder="For example ob1"
        />
        <Input
          label="Action"
          value={filters.action}
          onChange={(event) => applyFilters({ ...filters, action: event.target.value })}
          placeholder="For example session_login"
          hint="Actions are recorded under their internal name, so this filter matches that name."
        />
        <Select
          label="Result"
          value={filters.result}
          onChange={(event) => applyFilters({ ...filters, result: event.target.value })}
          options={[
            { value: "", label: "Any result" },
            { value: "success", label: "Success" },
            { value: "denied", label: "Denied" },
            { value: "failed", label: "Failed" },
          ]}
        />
      </section>

      {page.isPending && (
        <div className="audit-state" role="status">
          Loading audit events…
        </div>
      )}
      {page.isError && (
        <div className="audit-state error" role="alert">
          {errorMessage(page.error)}
        </div>
      )}
      {exportError ? (
        <div className="audit-state error" role="alert">
          {errorMessage(exportError)}
          <StepUpPrompt error={exportError} />
        </div>
      ) : null}
      {loadMoreError && (
        <div className="audit-state error" role="alert">
          {loadMoreError}
        </div>
      )}
      {page.isSuccess && events.length === 0 && (
        <div className="audit-state">No audit events match these filters.</div>
      )}

      {events.length > 0 && (
        <div className="card audit-table-wrap">
          <table className="audit-table">
            <caption className="sr-only">Audit events you can view</caption>
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Result</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td>
                    <button
                      type="button"
                      className="audit-row-button"
                      onClick={() => setSelected(event.id)}
                    >
                      {new Date(event.created_at).toLocaleString()}
                    </button>
                    <span className="audit-meta">Trace {event.trace_id}</span>
                  </td>
                  <td>
                    {event.actor_login}
                    <span className="audit-meta">
                      {actorRoleLabels(event.actor_roles, tenant).join(", ")}
                    </span>
                    {event.impersonated_subject && (
                      <span className="audit-meta">Acted as {event.impersonated_subject}</span>
                    )}
                    {event.impersonated_customer && (
                      <span className="audit-meta">Entered {event.impersonated_customer}</span>
                    )}
                  </td>
                  <td>
                    {auditActionLabel(event.action)}
                    <span className="audit-meta">
                      {event.customer_id ?? (tenant ? "—" : "Platform")}
                    </span>
                  </td>
                  <td>
                    {humanizeToken(event.resource_type)}
                    <span className="audit-meta">{event.resource_id ?? "—"}</span>
                  </td>
                  <td>
                    <span className={`audit-result audit-result-${event.result}`}>
                      {resultLabel(event.result)}
                    </span>
                  </td>
                  <td>{event.reason ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {cursor && (
        <div className="audit-more">
          <Button onClick={() => void loadMore()} loading={loadingMore}>
            Load older events
          </Button>
        </div>
      )}

      <aside className="audit-state">
        <ScrollText size={20} aria-hidden="true" />
        {tenant
          ? "Reading and exporting are recorded too. Every event here belongs to your customer."
          : "Reading and exporting are recorded too. Support accounts see only their own activity unless a cross-customer permission is granted."}
      </aside>

      <Dialog open={selected !== null} onClose={() => setSelected(null)} title="Audit event detail">
        {detail.isPending && <p role="status">Loading event…</p>}
        {detail.isError && (
          <p className="audit-state error" role="alert">
            {errorMessage(detail.error)}
          </p>
        )}
        {detail.isSuccess && (
          <dl className="audit-detail">
            <div>
              <dt>Event</dt>
              <dd>{detail.data.id}</dd>
            </div>
            <div>
              <dt>Actor</dt>
              <dd>
                {detail.data.actor_login} (
                {actorRoleLabels(detail.data.actor_roles, tenant).join(", ")})
              </dd>
            </div>
            <div>
              <dt>Action</dt>
              <dd>
                {auditActionLabel(detail.data.action)} · {resultLabel(detail.data.result)}
                <span className="audit-meta">{detail.data.action}</span>
              </dd>
            </div>
            <div>
              <dt>Resource</dt>
              <dd>
                {humanizeToken(detail.data.resource_type)} · {detail.data.resource_id ?? "—"}
              </dd>
            </div>
            <div>
              <dt>Session</dt>
              <dd>{detail.data.session_id ?? "—"}</dd>
            </div>
            <div>
              <dt>Details</dt>
              <dd>
                {detail.data.details.length === 0 ? (
                  <span>—</span>
                ) : (
                  <ul className="audit-detail-fields">
                    {detail.data.details.map((field) => (
                      <li key={field.key}>
                        <span className="audit-detail-key">{field.key}</span>
                        <span className="audit-detail-value">{field.value}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </div>
          </dl>
        )}
      </Dialog>
    </div>
  );
}

import { useQuery } from "@tanstack/react-query";
import { Download, ScrollText } from "lucide-react";
import { useMemo, useState } from "react";

import { api, type ApiError } from "../api/client";
import { loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import "./AuditLog.css";

import { notify } from "../lib/notify";
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

  const page = useQuery({
    queryKey: ["audit-events", filters],
    queryFn: ({ signal }) => api.get<AuditEventPage>(`/audit/events${buildQuery(filters)}`, signal),
  });

  const checkpoint = useQuery({
    queryKey: ["audit-checkpoint-status"],
    queryFn: ({ signal }) => api.get<AuditCheckpointStatus>("/audit/checkpoint-status", signal),
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

  return (
    <div className="audit-page">
      <header className="page-header">
        <div>
          <h1 className="page-title">Audit log</h1>
          <p className="audit-subtitle">
            Administrative and security events, scoped to your authorized view. Details are rendered
            as redacted key/value pairs — raw event JSON is never returned.
          </p>
        </div>
        <Button onClick={() => void exportCsv()} disabled={!canExport || events.length === 0}>
          <Download size={16} aria-hidden="true" />
          Export CSV
        </Button>
      </header>

      {canExport && (
        <p className="audit-hint">
          Exports are limited, audited and require step-up authentication.
        </p>
      )}

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
                {checkpoint.data.state === "current"
                  ? "Current"
                  : checkpoint.data.state === "stale"
                    ? "Stale"
                    : "Not configured"}
              </p>
              <p className="audit-meta">
                {checkpoint.data.last_checkpoint_at
                  ? `Last checkpoint ${new Date(
                      checkpoint.data.last_checkpoint_at,
                    ).toLocaleString()}`
                  : "No immutable checkpoint has been recorded for this deployment yet."}
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
              <dd>{checkpoint.data.root_hash}</dd>
            </div>
            <div>
              <dt>Signer</dt>
              <dd>{checkpoint.data.signer_key_id}</dd>
            </div>
          </dl>
        )}
      </section>

      <section className="audit-controls" aria-label="Audit filters">
        <label className="search-box">
          <span className="sr-only">Filter by actor</span>
          <input
            className="search-input"
            value={filters.actor_login}
            onChange={(event) => applyFilters({ ...filters, actor_login: event.target.value })}
            placeholder="Filter by actor login"
          />
        </label>
        <label>
          <span className="sr-only">Filter by action</span>
          <input
            value={filters.action}
            onChange={(event) => applyFilters({ ...filters, action: event.target.value })}
            placeholder="Filter by action"
          />
        </label>
        <label>
          <span className="sr-only">Filter by result</span>
          <select
            value={filters.result}
            onChange={(event) => applyFilters({ ...filters, result: event.target.value })}
          >
            <option value="">All results</option>
            <option value="success">Success</option>
            <option value="denied">Denied</option>
            <option value="failed">Failed</option>
          </select>
        </label>
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
            <caption className="sr-only">Audit events in your authorized scope</caption>
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
                    <span className="audit-meta">{event.actor_roles.join(", ")}</span>
                    {event.impersonated_subject && (
                      <span className="audit-meta">Acted as {event.impersonated_subject}</span>
                    )}
                    {event.impersonated_customer && (
                      <span className="audit-meta">Entered {event.impersonated_customer}</span>
                    )}
                  </td>
                  <td>
                    {humanizeToken(event.action)}
                    <span className="audit-meta">{event.action}</span>
                    <span className="audit-meta">{event.customer_id ?? "platform scope"}</span>
                  </td>
                  <td>
                    {event.resource_type}
                    <span className="audit-meta">{event.resource_id ?? "—"}</span>
                  </td>
                  <td>
                    <span className={`audit-result audit-result-${event.result}`}>
                      {event.result}
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
        Reads and exports are themselves audited. Support sessions only see their own activity
        unless a cross-customer permission is granted.
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
                {detail.data.actor_login} ({detail.data.actor_roles.join(", ")})
              </dd>
            </div>
            <div>
              <dt>Action</dt>
              <dd>
                {humanizeToken(detail.data.action)} · {detail.data.result}
                <span className="audit-meta">{detail.data.action}</span>
              </dd>
            </div>
            <div>
              <dt>Resource</dt>
              <dd>
                {detail.data.resource_type} · {detail.data.resource_id ?? "—"}
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

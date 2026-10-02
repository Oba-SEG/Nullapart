import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useState } from "react";

import type { ApiError } from "../api/client";
import {
  getMessageContent,
  getTraceTransaction,
  type TraceFlowStage,
  type TraceTransaction,
} from "../api/trace";
import { hasPermission, loadSession } from "../auth/session";
import { MessageContent } from "../components/MessageContent";
import { Button } from "../components/primitives/Button";
import { StatusPill } from "../components/StatusPill";
import { severityTone } from "../lib/status";
import "./MessageDetail.css";

const STAGE_LABELS: Record<string, string> = {
  accepted: "Accepted",
  authenticated: "Authenticated",
  bounced: "Bounced",
  content_scanned: "Content scanned",
  deferred: "Deferred",
  delivered: "Delivered",
  delivery_attempted: "Delivery attempted",
  parsed: "Parsed",
  policy_evaluated: "Policy evaluated",
  queued: "Queued",
  quarantined: "Quarantined",
  received: "Received",
  rejected: "Rejected",
  scored: "Scored",
  spam_checked: "Spam checked",
};

function errorMessage(error: unknown, fallback: string): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return fallback;
}

function errorCode(error: unknown): string {
  if (typeof error === "object" && error !== null && "code" in error) {
    return String((error as { code: unknown }).code).toUpperCase();
  }
  return "";
}

function isNotFound(error: unknown): boolean {
  const code = errorCode(error);
  return code.includes("404") || code.includes("NOT_FOUND");
}

function isForbidden(error: unknown): boolean {
  const code = errorCode(error);
  return code.includes("403") || code.includes("FORBIDDEN") || code.includes("PERMISSION_DENIED");
}

/** Renders serde_json auth values as text; objects fall back to JSON, then String(). */
function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    const json = JSON.stringify(value) as string | undefined;
    return json ?? String(value);
  } catch {
    return String(value);
  }
}

function formatTimestamp(value: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

function stageLabel(stage: string): string {
  const known = STAGE_LABELS[stage.toLowerCase()];
  if (known) return known;
  const words = stage
    .split(/[_-]+/)
    .filter((word) => word.length > 0)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1));
  return words.length > 0 ? words.join(" ") : stage;
}

function orderedStages(stages: TraceFlowStage[]): TraceFlowStage[] {
  return [...stages].sort(
    (left, right) => new Date(left.at).getTime() - new Date(right.at).getTime(),
  );
}

export function MessageDetail() {
  const { messageId = "" } = useParams({ from: "/messages/$messageId" });
  const [contentOpen, setContentOpen] = useState(false);

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const canViewContent = hasPermission(session.data ?? null, "trace:content");

  const detail = useQuery({
    queryKey: ["mail-trace-transaction", messageId],
    queryFn: ({ signal }) => getTraceTransaction(messageId, signal),
    enabled: messageId.length > 0,
  });

  const content = useQuery({
    queryKey: ["mail-trace-content", messageId],
    queryFn: ({ signal }) => getMessageContent(messageId, signal),
    enabled: contentOpen && canViewContent,
  });

  const data: TraceTransaction | undefined = detail.data;
  const stages = data ? orderedStages(data.flow_stages) : [];

  return (
    <div className="detail-page">
      <header className="detail-header">
        <div>
          <Link to="/messages" className="detail-back">
            <ArrowLeft size={16} aria-hidden="true" /> Back to messages
          </Link>
          <h1 className="detail-title">Message trace</h1>
          <p className="detail-subtitle">
            Transaction metadata, authentication results, delivery attempts and scanner findings for
            one mail transaction. Raw message bodies are only rendered through the sandboxed content
            view.
          </p>
        </div>
        {canViewContent && (
          <div className="detail-actions">
            <Button
              onClick={() => setContentOpen((open) => !open)}
              aria-expanded={contentOpen}
              aria-controls="message-content-section"
            >
              {contentOpen ? "Close message content" : "View message content"}
            </Button>
          </div>
        )}
      </header>

      {detail.isError && isNotFound(detail.error) && (
        <div className="detail-state" role="alert">
          <h2 className="detail-state-title">Message not found</h2>
          <p>
            This transaction is not visible in your scope, or it has aged out of the trace window.
          </p>
          <Link to="/messages">Back to messages</Link>
        </div>
      )}

      {detail.isError && !isNotFound(detail.error) && (
        <div className="detail-state error" role="alert">
          {errorMessage(detail.error, "Message trace is temporarily unavailable.")}
        </div>
      )}

      {detail.isPending && (
        <div className="detail-state" role="status">
          Loading message trace…
        </div>
      )}

      {data && (
        <>
          <section className="card detail-facts-card" aria-label="Transaction summary">
            <h2 className="detail-section-title">Transaction</h2>
            <dl className="detail-facts">
              <dt>Transaction ID</dt>
              <dd className="detail-mono">{data.transaction_id}</dd>
              <dt>Direction</dt>
              <dd>{data.direction}</dd>
              <dt>Sender</dt>
              <dd>{data.envelope_sender ?? "—"}</dd>
              <dt>Message ID</dt>
              <dd className="detail-mono">{data.message_id ?? "—"}</dd>
              <dt>Content hash</dt>
              <dd className="detail-mono">{data.content_hash ?? "—"}</dd>
              <dt>Received</dt>
              <dd>{formatTimestamp(data.received_at)}</dd>
            </dl>
          </section>

          <section className="card" aria-label="Flow timeline">
            <h2 className="detail-section-title">Flow timeline</h2>
            {stages.length === 0 ? (
              <p className="detail-subtitle">No flow stages are recorded for this transaction.</p>
            ) : (
              <ol className="detail-timeline">
                {stages.map((stage, index) => (
                  <li key={`${stage.stage}-${index}`}>
                    <span className="detail-timeline-label">{stageLabel(stage.stage)}</span>
                    <span className="detail-timeline-time">{formatTimestamp(stage.at)}</span>
                  </li>
                ))}
              </ol>
            )}
          </section>

          <section className="card" aria-label="Recipients">
            <h2 className="detail-section-title">Recipients</h2>
            {data.recipients.length === 0 ? (
              <p className="detail-subtitle">No recipients are recorded.</p>
            ) : (
              <div className="detail-table-wrap">
                <table className="detail-table">
                  <caption className="sr-only">Envelope recipients</caption>
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>ORCPT</th>
                      <th>Notify</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recipients.map((recipient) => (
                      <tr key={recipient.address}>
                        <td>{recipient.address}</td>
                        <td className="detail-mono">{recipient.orcpt ?? "—"}</td>
                        <td>{recipient.notify ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card" aria-label="Authentication results">
            <h2 className="detail-section-title">Authentication</h2>
            <dl className="detail-facts">
              <dt>SPF</dt>
              <dd>{formatValue(data.auth.spf_result)}</dd>
              <dt>DKIM</dt>
              <dd>{formatValue(data.auth.dkim_result)}</dd>
              <dt>DMARC</dt>
              <dd>{formatValue(data.auth.dmarc_result)}</dd>
              <dt>ARC</dt>
              <dd>{formatValue(data.auth.arc_result)}</dd>
            </dl>
          </section>

          <section className="card" aria-label="Postfix queue ids">
            <h2 className="detail-section-title">Postfix queue IDs</h2>
            {data.postfix_queue_ids.length === 0 ? (
              <p className="detail-subtitle">No queue IDs are recorded.</p>
            ) : (
              <ul className="detail-queue-list">
                {data.postfix_queue_ids.map((queueId) => (
                  <li key={queueId} className="detail-mono">
                    {queueId}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card" aria-label="Tenant instances">
            <h2 className="detail-section-title">Tenant instances</h2>
            {data.instances.length === 0 ? (
              <p className="detail-subtitle">No tenant instances are recorded.</p>
            ) : (
              <div className="detail-table-wrap">
                <table className="detail-table">
                  <caption className="sr-only">Tenant message instances</caption>
                  <thead>
                    <tr>
                      <th>Tenant message</th>
                      <th>Disposition</th>
                      <th>Remediation</th>
                      <th>Created</th>
                      <th>Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.instances.map((instance) => (
                      <tr key={instance.tenant_message_id}>
                        <td className="detail-mono">{instance.tenant_message_id}</td>
                        <td>{instance.disposition}</td>
                        <td>{instance.remediation_type ?? "—"}</td>
                        <td>{formatTimestamp(instance.created_at)}</td>
                        <td>{formatTimestamp(instance.updated_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card" aria-label="Delivery attempts">
            <h2 className="detail-section-title">Delivery attempts</h2>
            {data.delivery_attempts.length === 0 ? (
              <p className="detail-subtitle">No delivery attempts are recorded.</p>
            ) : (
              <div className="detail-table-wrap">
                <table className="detail-table detail-attempts">
                  <caption className="sr-only">SMTP delivery attempts</caption>
                  <thead>
                    <tr>
                      <th>Attempt</th>
                      <th>Status</th>
                      <th>SMTP code</th>
                      <th>Enhanced code</th>
                      <th>Message</th>
                      <th>Scheduled</th>
                      <th>Completed</th>
                      <th>Next retry</th>
                      <th>Queue ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.delivery_attempts.map((attempt) => (
                      <tr key={attempt.attempt_number}>
                        <td>{attempt.attempt_number}</td>
                        <td>{attempt.status}</td>
                        <td className="detail-mono">{attempt.smtp_code ?? "—"}</td>
                        <td className="detail-mono">{attempt.enhanced_code ?? "—"}</td>
                        <td>{attempt.smtp_message ?? "—"}</td>
                        <td>{formatTimestamp(attempt.scheduled_at)}</td>
                        <td>{formatTimestamp(attempt.completed_at)}</td>
                        <td>{formatTimestamp(attempt.next_retry_at)}</td>
                        <td className="detail-mono">{attempt.postfix_queue_id ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card" aria-label="Findings">
            <h2 className="detail-section-title">Findings</h2>
            {data.findings.length === 0 ? (
              <p className="detail-subtitle">No scanner findings are recorded.</p>
            ) : (
              <ul className="detail-findings">
                {data.findings.map((finding) => (
                  <li key={finding.id}>
                    <span className="detail-finding-head">
                      <StatusPill tone={severityTone(finding.severity)} label={finding.severity} />
                      <span className="detail-finding-category">{finding.category}</span>
                    </span>
                    <span>{finding.description}</span>
                    <span className="detail-meta">
                      Scanner {finding.scanner_type} · {formatTimestamp(finding.created_at)}
                    </span>
                    {finding.false_positive && (
                      <span className="detail-false-positive">False positive</span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>

          {contentOpen && (
            <section
              className="card detail-content"
              id="message-content-section"
              aria-label="Message content"
            >
              {content.isError && (
                <div className="detail-state error" role="alert">
                  {isForbidden(content.error)
                    ? "You do not have permission to view message content."
                    : errorMessage(content.error, "Message content is temporarily unavailable.")}
                </div>
              )}
              {content.isFetching && (
                <div className="detail-state" role="status">
                  Loading message content…
                </div>
              )}
              {content.data && (
                <MessageContent data={content.data} onClose={() => setContentOpen(false)} />
              )}
            </section>
          )}
        </>
      )}
    </div>
  );
}

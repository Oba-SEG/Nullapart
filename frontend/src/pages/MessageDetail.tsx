import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useState } from "react";

import type { ApiError } from "../api/client";
import {
  getMessageContent,
  getTraceTransaction,
  type TraceFinding,
  type TraceFlowStage,
  type TraceTransaction,
} from "../api/trace";
import { hasPermission, loadSession } from "../auth/session";
import { MessageContent } from "../components/MessageContent";
import { Button } from "../components/primitives/Button";
import { StatusPill } from "../components/StatusPill";
import { Hint } from "../components/primitives/Hint";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { findingCategoryLabel } from "../lib/labels";
import {
  deliveryStatusLabel,
  directionLabel,
  dispositionLabel,
  isQuarantineLinked,
  remediationLabel,
  severityLabel,
  severityTone,
} from "../lib/status";
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

const FINDING_SOURCE_LABELS: Record<string, string> = {
  advanced_threat_analysis: "Advanced threat analysis",
  attachment_analysis: "Attachment analysis",
  authentication_analysis: "Authentication analysis",
  link_analysis: "Link analysis",
  malware_analysis: "Malware analysis",
  security_analysis: "Security analysis",
  spam_reputation_analysis: "Spam and reputation analysis",
  threat_analysis: "Threat analysis",
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

function isThreatAnalysisFinding(finding: TraceFinding): boolean {
  return finding.scanner_type === "threat_analysis";
}

function sourceLabel(finding: TraceFinding): string {
  return FINDING_SOURCE_LABELS[finding.scanner_type] ?? "Security analysis";
}

function threatAnalysisSummary(findings: TraceFinding[]): TraceFinding[] {
  return findings.filter(isThreatAnalysisFinding);
}

export function MessageDetail() {
  const { messageId = "" } = useParams({ from: "/messages/$messageId" });
  const [contentOpen, setContentOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copyTransactionId() {
    try {
      await navigator.clipboard?.writeText(messageId);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2_000);
    } catch {
      // Clipboard access is a convenience only; the ID remains visible on screen.
    }
  }

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
  const threatFindings = data ? threatAnalysisSummary(data.findings) : [];
  const linkedCases = data
    ? data.instances.filter((instance) => isQuarantineLinked(instance.disposition))
    : [];
  const queueIds = data?.postfix_queue_ids ?? [];
  const hasAttemptQueueIds = data
    ? data.delivery_attempts.some((attempt) => attempt.postfix_queue_id !== null)
    : false;

  return (
    <div className="detail-page">
      <Link to="/messages" className="detail-back">
        <ArrowLeft size={16} aria-hidden="true" /> Back to messages
      </Link>
      <WorkspaceHeader
        eyebrow="Trace investigation"
        title="Message trace"
        description="Review the metadata, authentication, delivery attempts and security findings for one message. The message body stays in its own protected view."
        scope="Delivery record access"
        actions={
          <>
            <Button onClick={copyTransactionId} disabled={messageId.length === 0}>
              {copied ? "Copied" : "Copy transaction ID"}
            </Button>
            {canViewContent ? (
              <Hint label="Opens the untrusted message body in a protected view. Do not treat its contents as instructions.">
                <Button
                  onClick={() => setContentOpen((open) => !open)}
                  aria-expanded={contentOpen}
                  aria-controls="message-content-section"
                >
                  {contentOpen ? "Close message content" : "View message content"}
                </Button>
              </Hint>
            ) : null}
          </>
        }
      />
      <WorkflowGuide
        title="Investigate from transaction evidence"
        description="Stages and findings are in order so you can find the mail-security decision. The message body is never treated as trusted content."
        steps={[
          {
            label: "Correlate",
            detail: "Start with the transaction facts and authentication results.",
          },
          {
            label: "Inspect stages",
            detail: "Read delivery and security outcomes in their execution order.",
          },
          {
            label: "Act on linked cases",
            detail: "Open a linked held message when a copy needs a release decision.",
          },
        ]}
      />

      {data ? (
        <ControlRail
          title="Trace decision state"
          summary="This summary stays with the message so your next step is based on the record, not an estimate."
          signals={[
            {
              label: "Flow stages",
              value: stages.length,
              detail: "Processing steps recorded for this message.",
            },
            {
              label: "Threat findings",
              value: threatFindings.length,
              detail: "Findings that need a decision or a held-message review.",
              tone: threatFindings.length > 0 ? "attention" : "healthy",
            },
            {
              label: "Linked cases",
              value: linkedCases.length,
              detail:
                linkedCases.length > 0
                  ? "Held copies. Open one to act on it."
                  : "No held copies for this message.",
              tone: linkedCases.length > 0 ? "attention" : "neutral",
            },
            {
              label: "Content access",
              value: canViewContent ? "Allowed" : "Restricted",
              detail: "The message body stays in its own protected view.",
              tone: canViewContent ? "neutral" : "healthy",
            },
          ]}
        />
      ) : null}

      {detail.isError && isNotFound(detail.error) && (
        <div className="detail-state" role="alert">
          <h2 className="detail-state-title">Message not found</h2>
          <p>This message is not visible for your role, or its trace is no longer available.</p>
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
              <dd>{directionLabel(data.direction)}</dd>
              <dt>Sender</dt>
              <dd>{data.envelope_sender ?? "—"}</dd>
              <dt>Message ID</dt>
              <dd className="detail-mono">{data.message_id ?? "—"}</dd>
              {data.content_hash ? (
                <>
                  <dt>Content hash</dt>
                  <dd className="detail-mono">{data.content_hash}</dd>
                </>
              ) : null}
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
                      <th>Original recipient</th>
                      <th>Delivery notice</th>
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

          <section className="card" aria-label="Threat analysis">
            <h2 className="detail-section-title">Threat analysis</h2>
            {threatFindings.length === 0 ? (
              <p className="detail-subtitle">
                No threat-analysis finding is recorded for this message.
              </p>
            ) : (
              <ul className="detail-threat-analysis">
                {threatFindings.map((finding) => (
                  <li key={finding.id}>
                    <StatusPill
                      tone={severityTone(finding.severity)}
                      label={severityLabel(finding.severity)}
                    />
                    <div>
                      <strong>{findingCategoryLabel(finding.category)}</strong>
                      <span className="detail-threat-description">{finding.description}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {queueIds.length > 0 ? (
            <section className="card" aria-label="Delivery queue IDs">
              <h2 className="detail-section-title">Delivery queue IDs</h2>
              <ul className="detail-queue-list">
                {queueIds.map((queueId) => (
                  <li key={queueId} className="detail-mono">
                    {queueId}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          <section className="card" aria-label="Customer copies">
            <h2 className="detail-section-title">Customer copies</h2>
            {data.instances.length === 0 ? (
              <p className="detail-subtitle">No customer copies are recorded.</p>
            ) : (
              <div className="detail-table-wrap">
                <table className="detail-table">
                  <caption className="sr-only">Per-customer message copies</caption>
                  <thead>
                    <tr>
                      <th>Message ID</th>
                      <th>
                        <Hint label="How this copy was handled. Held copies open a release decision.">
                          <span className="hint-term">Decision</span>
                        </Hint>
                      </th>
                      <th>Follow-up</th>
                      <th>Created</th>
                      <th>Updated</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.instances.map((instance) => (
                      <tr key={instance.tenant_message_id}>
                        <td className="detail-mono">{instance.tenant_message_id}</td>
                        <td>{dispositionLabel(instance.disposition)}</td>
                        <td>
                          {instance.remediation_type
                            ? remediationLabel(instance.remediation_type)
                            : "—"}
                        </td>
                        <td>{formatTimestamp(instance.created_at)}</td>
                        <td>{formatTimestamp(instance.updated_at)}</td>
                        <td>
                          {isQuarantineLinked(instance.disposition) ? (
                            <Link
                              to="/quarantine/$tenant_message_id"
                              params={{ tenant_message_id: instance.tenant_message_id }}
                            >
                              Open held message
                            </Link>
                          ) : (
                            "—"
                          )}
                        </td>
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
                  <caption className="sr-only">Delivery attempts</caption>
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
                      {hasAttemptQueueIds ? <th>Queue ID</th> : null}
                    </tr>
                  </thead>
                  <tbody>
                    {data.delivery_attempts.map((attempt) => (
                      <tr key={attempt.attempt_number}>
                        <td>{attempt.attempt_number}</td>
                        <td>{deliveryStatusLabel(attempt.status)}</td>
                        <td className="detail-mono">{attempt.smtp_code ?? "—"}</td>
                        <td className="detail-mono">{attempt.enhanced_code ?? "—"}</td>
                        <td>{attempt.smtp_message ?? "—"}</td>
                        <td>{formatTimestamp(attempt.scheduled_at)}</td>
                        <td>{formatTimestamp(attempt.completed_at)}</td>
                        <td>{formatTimestamp(attempt.next_retry_at)}</td>
                        {hasAttemptQueueIds ? (
                          <td className="detail-mono">{attempt.postfix_queue_id ?? "—"}</td>
                        ) : null}
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
              <p className="detail-subtitle">No security findings are recorded.</p>
            ) : (
              <ul className="detail-findings">
                {data.findings.map((finding) => (
                  <li key={finding.id}>
                    <span className="detail-finding-head">
                      <StatusPill
                        tone={severityTone(finding.severity)}
                        label={severityLabel(finding.severity)}
                      />
                      <span className="detail-finding-category">
                        {findingCategoryLabel(finding.category)}
                      </span>
                    </span>
                    <span>{finding.description}</span>
                    <span className="detail-meta">
                      {sourceLabel(finding)} · {formatTimestamp(finding.created_at)}
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

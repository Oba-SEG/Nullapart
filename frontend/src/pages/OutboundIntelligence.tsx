import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, RefreshCw, Send, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import { hasPermission, loadSession } from "../auth/session";
import { StatusPill } from "../components/StatusPill";
import { randomUuid } from "../lib/ids";
import type { StatusTone } from "../lib/status";
import "./OutboundIntelligence.css";

interface OutboundIntelligenceSummary {
  messages_1h: number;
  recipients_1h: number;
  unique_recipients_1h: number;
  active_senders_1h: number;
  campaigns_observed: number;
  approved_bulk_senders: number;
  open_security_events: number;
  critical_security_events: number;
}

interface ApprovedBulkSender {
  id: string;
  sender_address: string;
  sending_domain: string;
  source_kind: SourceKind;
  source_id: string;
  source_ip: string | null;
  max_messages_per_minute: number;
  max_messages_per_hour: number;
  max_recipients_per_message: number;
  max_unique_recipients_per_hour: number;
  active: boolean;
  reason: string;
  approved_by: string;
  updated_at: string;
  expires_at: string | null;
}

interface SenderBehaviour {
  sender_address: string;
  sending_domain: string;
  source_kind: SourceKind;
  source_id: string;
  source_ip: string | null;
  messages_1h: number;
  recipients_1h: number;
  unique_recipients_1h: number;
  new_recipients_1h: number;
  bounce_failures_1h: number;
  malware_observations_1h: number;
  auth_source_changes_1h: number;
  unusual_time_observations_1h: number;
  latest_seen_at: string;
}

interface Campaign {
  fingerprint: string;
  algorithm: string;
  message_count: number;
  recipient_count: number;
  disposition: string;
  first_seen_at: string;
  last_seen_at: string;
}

interface SecurityEvent {
  id: string;
  event_type: string;
  severity: "info" | "warning" | "critical";
  outcome: string;
  reason_code: string;
  sender_address: string | null;
  source_id: string | null;
  campaign_fingerprint: string | null;
  status: string;
  message_count: number;
  first_seen_at: string;
  last_seen_at: string;
  cooldown_until: string | null;
}

interface PolicyHistory {
  id: string;
  action: string;
  actor_login: string;
  resource_id: string | null;
  result: string;
  created_at: string;
}

interface OutboundIntelligenceResponse {
  deployment_id: string;
  generated_at: string;
  summary: OutboundIntelligenceSummary;
  approved_senders: ApprovedBulkSender[];
  sender_behaviour: SenderBehaviour[];
  campaigns: Campaign[];
  security_events: SecurityEvent[];
  policy_history: PolicyHistory[];
}

type SourceKind = "smtp_mta" | "internal_api" | "webhook" | "connector";

interface ApprovedBulkSenderRequest {
  sender_address: string;
  sending_domain: string;
  source_kind: SourceKind;
  source_id: string;
  source_ip?: string;
  max_messages_per_minute: number;
  max_messages_per_hour: number;
  max_recipients_per_message: number;
  max_unique_recipients_per_hour: number;
  active: boolean;
  reason: string;
}

const sourceKindLabels: Record<SourceKind, string> = {
  smtp_mta: "SMTP MTA",
  internal_api: "Internal API",
  webhook: "Webhook",
  connector: "Connector",
};

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "Outbound intelligence is temporarily unavailable.";
}

function formatDate(value: string | null): string {
  if (!value) return "none";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function severityTone(severity: SecurityEvent["severity"]): StatusTone {
  if (severity === "critical") return "threat";
  if (severity === "warning") return "review";
  return "clean";
}

function dispositionTone(disposition: string): StatusTone {
  if (["blocked", "held", "suspend_outbound", "block_sender"].includes(disposition)) {
    return "threat";
  }
  if (["warned", "throttled", "defer", "warning"].includes(disposition)) return "review";
  return "clean";
}

function percent(part: number, total: number): string {
  if (total <= 0) return "—";
  return `${Math.round((part / total) * 100)}%`;
}

function SummaryCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="outbound-summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function initialApprovalForm(): ApprovedBulkSenderRequest {
  return {
    sender_address: "",
    sending_domain: "",
    source_kind: "smtp_mta",
    source_id: "",
    source_ip: "",
    max_messages_per_minute: 20,
    max_messages_per_hour: 500,
    max_recipients_per_message: 100,
    max_unique_recipients_per_hour: 5000,
    active: true,
    reason: "",
  };
}

export function OutboundIntelligence() {
  const queryClient = useQueryClient();
  const [approvalForm, setApprovalForm] =
    useState<ApprovedBulkSenderRequest>(initialApprovalForm());
  const [notice, setNotice] = useState<string | null>(null);
  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
  });
  const intelligence = useQuery({
    queryKey: ["outbound-intelligence"],
    queryFn: ({ signal }) =>
      api.get<OutboundIntelligenceResponse>("/outbound-intelligence", signal),
    refetchInterval: 60_000,
  });
  const canManage = hasPermission(session.data ?? null, "outbound-intelligence:manage");
  const saveApproval = useMutation({
    mutationFn: (request: ApprovedBulkSenderRequest) =>
      api.post<{ sender_address: string; active: boolean }>(
        "/outbound-intelligence/approved-senders",
        {
          ...request,
          source_ip: request.source_ip?.trim() ? request.source_ip.trim() : undefined,
        },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async (result) => {
      setNotice(
        `${result.sender_address} is now ${result.active ? "approved" : "inactive"} for outbound bulk.`,
      );
      setApprovalForm(initialApprovalForm());
      await queryClient.invalidateQueries({ queryKey: ["outbound-intelligence"] });
    },
  });

  if (intelligence.isPending) {
    return (
      <div className="outbound-state" role="status">
        Loading outbound intelligence…
      </div>
    );
  }

  if (intelligence.isError) {
    return (
      <div className="outbound-state error" role="alert">
        {errorMessage(intelligence.error)}
      </div>
    );
  }

  const data = intelligence.data;
  const submitError = saveApproval.isError ? errorMessage(saveApproval.error) : null;

  return (
    <div className="outbound-page">
      <header className="page-header outbound-header">
        <div>
          <h1 className="page-title">Outbound intelligence</h1>
          <p className="outbound-subtitle">
            Sender, source, campaign and containment controls for deployment {data.deployment_id}.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-ghost"
          onClick={() => void intelligence.refetch()}
          aria-label="Refresh outbound intelligence"
        >
          <RefreshCw size={14} aria-hidden="true" />
          Refresh
        </button>
      </header>

      {notice ? (
        <div className="outbound-notice" role="status">
          {notice}
        </div>
      ) : null}
      {submitError ? (
        <div className="outbound-notice error" role="alert">
          {submitError}
        </div>
      ) : null}

      <section className="card outbound-summary" aria-label="Outbound summary">
        <SummaryCard label="Messages" value={data.summary.messages_1h} detail="last hour" />
        <SummaryCard label="Recipients" value={data.summary.recipients_1h} detail="last hour" />
        <SummaryCard
          label="Unique recipients"
          value={data.summary.unique_recipients_1h}
          detail="deduplicated hourly"
        />
        <SummaryCard
          label="Active senders"
          value={data.summary.active_senders_1h}
          detail="seen in last hour"
        />
        <SummaryCard
          label="Approved bulk"
          value={data.summary.approved_bulk_senders}
          detail="active sender/source approvals"
        />
        <SummaryCard
          label="Open events"
          value={data.summary.open_security_events}
          detail={`${data.summary.critical_security_events} critical`}
        />
      </section>

      {data.security_events.length > 0 ? (
        <section className="card outbound-events" aria-labelledby="outbound-events-heading">
          <h2 id="outbound-events-heading">Held, blocked and warning events</h2>
          <div className="outbound-event-list">
            {data.security_events.map((event) => (
              <article className="outbound-event" key={event.id}>
                <ShieldAlert size={16} aria-hidden="true" />
                <div>
                  <div className="outbound-event-title">
                    <strong>{event.event_type.replaceAll("_", " ")}</strong>
                    <StatusPill tone={severityTone(event.severity)} label={event.severity} />
                    <StatusPill tone={dispositionTone(event.outcome)} label={event.outcome} />
                  </div>
                  <p>
                    {event.sender_address ?? "unknown sender"} via{" "}
                    {event.source_id ?? "unknown source"} · {event.reason_code} ·{" "}
                    {event.message_count} observed messages
                  </p>
                  <small>
                    Last seen {formatDate(event.last_seen_at)}
                    {event.cooldown_until
                      ? ` · cooldown until ${formatDate(event.cooldown_until)}`
                      : ""}
                  </small>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="card outbound-grid-section" aria-labelledby="sender-behaviour-heading">
        <div className="outbound-section-head">
          <h2 id="sender-behaviour-heading">Sender/source behaviour</h2>
          <span>{formatDate(data.generated_at)}</span>
        </div>
        {data.sender_behaviour.length === 0 ? (
          <div className="outbound-empty">
            <Send size={22} aria-hidden="true" />
            <p>No outbound sender metrics in the current one-hour window.</p>
          </div>
        ) : (
          <div className="outbound-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Sender/source</th>
                  <th>Volume</th>
                  <th>Recipient mix</th>
                  <th>Risk signals</th>
                  <th>Latest</th>
                </tr>
              </thead>
              <tbody>
                {data.sender_behaviour.map((sender) => (
                  <tr key={`${sender.sender_address}-${sender.source_id}`}>
                    <td>
                      <strong>{sender.sender_address}</strong>
                      <span>
                        {sourceKindLabels[sender.source_kind]} · {sender.source_id}
                        {sender.source_ip ? ` · ${sender.source_ip}` : ""}
                      </span>
                    </td>
                    <td>
                      {sender.messages_1h} messages
                      <span>{sender.recipients_1h} recipients</span>
                    </td>
                    <td>
                      {sender.unique_recipients_1h} unique
                      <span>
                        {percent(sender.new_recipients_1h, sender.unique_recipients_1h)} new
                      </span>
                    </td>
                    <td>
                      {sender.bounce_failures_1h} bounces/failures
                      <span>
                        {sender.malware_observations_1h} malware · {sender.auth_source_changes_1h}{" "}
                        auth changes · {sender.unusual_time_observations_1h} unusual time
                      </span>
                    </td>
                    <td>{formatDate(sender.latest_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="outbound-two-column">
        <section className="card outbound-approved" aria-labelledby="approved-senders-heading">
          <h2 id="approved-senders-heading">Approved bulk senders</h2>
          {data.approved_senders.length === 0 ? (
            <p className="outbound-muted">No sender/source approval is configured.</p>
          ) : (
            <div className="outbound-approved-list">
              {data.approved_senders.map((approval) => (
                <article key={approval.id}>
                  <div>
                    <strong>{approval.sender_address}</strong>
                    <span>
                      {sourceKindLabels[approval.source_kind]} · {approval.source_id}
                    </span>
                  </div>
                  <StatusPill
                    tone={approval.active ? "clean" : "review"}
                    label={approval.active ? "active" : "inactive"}
                  />
                  <p>{approval.reason}</p>
                  <small>
                    {approval.max_messages_per_hour}/h · {approval.max_recipients_per_message}{" "}
                    recipients/message · expires {formatDate(approval.expires_at)}
                  </small>
                </article>
              ))}
            </div>
          )}
        </section>

        {canManage ? (
          <section className="card outbound-approval-form" aria-labelledby="approve-bulk-heading">
            <h2 id="approve-bulk-heading">Approve or update bulk sender</h2>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                saveApproval.mutate(approvalForm);
              }}
            >
              <label>
                Sender address
                <input
                  value={approvalForm.sender_address}
                  onChange={(event) =>
                    setApprovalForm((current) => ({
                      ...current,
                      sender_address: event.target.value,
                    }))
                  }
                  placeholder="bulk@example.com"
                  required
                />
              </label>
              <label>
                Sending domain
                <input
                  value={approvalForm.sending_domain}
                  onChange={(event) =>
                    setApprovalForm((current) => ({
                      ...current,
                      sending_domain: event.target.value,
                    }))
                  }
                  placeholder="example.com"
                  required
                />
              </label>
              <label>
                Source kind
                <select
                  value={approvalForm.source_kind}
                  onChange={(event) =>
                    setApprovalForm((current) => ({
                      ...current,
                      source_kind: event.target.value as SourceKind,
                    }))
                  }
                >
                  {Object.entries(sourceKindLabels).map(([value, label]) => (
                    <option value={value} key={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Source ID
                <input
                  value={approvalForm.source_id}
                  onChange={(event) =>
                    setApprovalForm((current) => ({
                      ...current,
                      source_id: event.target.value,
                    }))
                  }
                  placeholder="mx-1 or connector id"
                  required
                />
              </label>
              <label>
                Source IP optional
                <input
                  value={approvalForm.source_ip ?? ""}
                  onChange={(event) =>
                    setApprovalForm((current) => ({
                      ...current,
                      source_ip: event.target.value,
                    }))
                  }
                  placeholder="192.0.2.10"
                />
              </label>
              <div className="outbound-form-grid">
                <label>
                  Msg/min
                  <input
                    type="number"
                    min={1}
                    value={approvalForm.max_messages_per_minute}
                    onChange={(event) =>
                      setApprovalForm((current) => ({
                        ...current,
                        max_messages_per_minute: Number(event.target.value),
                      }))
                    }
                    required
                  />
                </label>
                <label>
                  Msg/hour
                  <input
                    type="number"
                    min={1}
                    value={approvalForm.max_messages_per_hour}
                    onChange={(event) =>
                      setApprovalForm((current) => ({
                        ...current,
                        max_messages_per_hour: Number(event.target.value),
                      }))
                    }
                    required
                  />
                </label>
                <label>
                  Recipients/message
                  <input
                    type="number"
                    min={1}
                    value={approvalForm.max_recipients_per_message}
                    onChange={(event) =>
                      setApprovalForm((current) => ({
                        ...current,
                        max_recipients_per_message: Number(event.target.value),
                      }))
                    }
                    required
                  />
                </label>
                <label>
                  Unique recipients/hour
                  <input
                    type="number"
                    min={1}
                    value={approvalForm.max_unique_recipients_per_hour}
                    onChange={(event) =>
                      setApprovalForm((current) => ({
                        ...current,
                        max_unique_recipients_per_hour: Number(event.target.value),
                      }))
                    }
                    required
                  />
                </label>
              </div>
              <label>
                Reason
                <textarea
                  value={approvalForm.reason}
                  onChange={(event) =>
                    setApprovalForm((current) => ({ ...current, reason: event.target.value }))
                  }
                  placeholder="Approved campaign or connector business purpose"
                  required
                />
              </label>
              <label className="outbound-checkbox">
                <input
                  type="checkbox"
                  checked={approvalForm.active}
                  onChange={(event) =>
                    setApprovalForm((current) => ({
                      ...current,
                      active: event.target.checked,
                    }))
                  }
                />
                Active approval
              </label>
              <button type="submit" className="btn btn-primary" disabled={saveApproval.isPending}>
                Save approval
              </button>
            </form>
          </section>
        ) : null}
      </div>

      <div className="outbound-two-column">
        <section className="card outbound-campaigns" aria-labelledby="campaigns-heading">
          <h2 id="campaigns-heading">Campaign fingerprints</h2>
          {data.campaigns.length === 0 ? (
            <p className="outbound-muted">No campaign fingerprints have been observed.</p>
          ) : (
            <div className="outbound-table-wrap compact">
              <table>
                <thead>
                  <tr>
                    <th>Fingerprint</th>
                    <th>Volume</th>
                    <th>Disposition</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.campaigns.map((campaign) => (
                    <tr key={`${campaign.algorithm}-${campaign.fingerprint}`}>
                      <td>
                        <strong>{campaign.fingerprint}</strong>
                        <span>{campaign.algorithm}</span>
                      </td>
                      <td>
                        {campaign.message_count} messages
                        <span>{campaign.recipient_count} recipients</span>
                      </td>
                      <td>
                        <StatusPill
                          tone={dispositionTone(campaign.disposition)}
                          label={campaign.disposition}
                        />
                      </td>
                      <td>{formatDate(campaign.last_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="card outbound-history" aria-labelledby="policy-history-heading">
          <h2 id="policy-history-heading">Policy/action history</h2>
          {data.policy_history.length === 0 ? (
            <p className="outbound-muted">No outbound approval changes recorded yet.</p>
          ) : (
            <div className="outbound-history-list">
              {data.policy_history.map((entry) => (
                <article key={entry.id}>
                  <CheckCircle2 size={15} aria-hidden="true" />
                  <div>
                    <strong>{entry.action.replaceAll("_", " ")}</strong>
                    <p>
                      {entry.resource_id ?? "outbound policy"} by {entry.actor_login}
                    </p>
                    <small>{formatDate(entry.created_at)}</small>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      </div>

      <section className="card outbound-notification-state" aria-labelledby="notification-heading">
        <div>
          <h2 id="notification-heading">Notification and incident state</h2>
          <p>
            Critical compromised-sender and suspended-outbound events are aggregated before incident
            creation. Open events above are the customer-visible queue for Support/System follow-up.
          </p>
        </div>
        {data.summary.open_security_events > 0 ? (
          <AlertTriangle size={22} aria-hidden="true" />
        ) : (
          <CheckCircle2 size={22} aria-hidden="true" />
        )}
      </section>
    </div>
  );
}

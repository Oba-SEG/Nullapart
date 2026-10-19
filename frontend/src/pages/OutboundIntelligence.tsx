import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Pencil,
  Power,
  RefreshCw,
  Send,
  ShieldAlert,
} from "lucide-react";
import { useRef, useState } from "react";

import { api, type ApiError } from "../api/client";
import { expiryError, expiryToRfc3339 } from "../api/policies";
import { hasPermission, isTenantTier, loadSession } from "../auth/session";
import { StatusPill } from "../components/StatusPill";
import { ControlRail } from "../components/ControlRail";
import { Hint } from "../components/primitives/Hint";
import { Dialog } from "../components/primitives/Dialog";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { randomUuid } from "../lib/ids";
import {
  auditActionLabel,
  fingerprintVersionLabel,
  outboundEventLabel,
  outboundOutcomeLabel,
  reasonCodeLabel,
  tenantResourceReference,
} from "../lib/labels";
import { severityLabel, type StatusTone } from "../lib/status";
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
  remediation_runbook: string | null;
  remediation_summary: string | null;
  credential_rotation_recommended: boolean;
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
  /** Which installation answered. The customer answer omits the key. */
  deployment_id?: string;
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
  expires_at?: string | null;
}

interface ApprovedSenderWriteResult {
  sender_address: string;
  active: boolean;
  changed: boolean;
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
    expires_at: "",
  };
}

/** Mirrors the server-side bound: an audited reason of 8-512 characters. */
function approvalReasonError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length < 8) return "Enter a reason of at least 8 characters.";
  if (trimmed.length > 512) return "Enter a reason of at most 512 characters.";
  return undefined;
}

/** Converts a stored RFC3339 expiry into a `datetime-local` input value. */
function expiryToLocalInput(value: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

export function OutboundIntelligence() {
  const queryClient = useQueryClient();
  const [approvalForm, setApprovalForm] =
    useState<ApprovedBulkSenderRequest>(initialApprovalForm());
  const [notice, setNotice] = useState<string | null>(null);
  const [editingApprovalId, setEditingApprovalId] = useState<string | null>(null);
  const [toggleTarget, setToggleTarget] = useState<{
    approval: ApprovedBulkSender;
    active: boolean;
  } | null>(null);
  const [toggleReason, setToggleReason] = useState("");
  const [showToggleError, setShowToggleError] = useState(false);
  const approvalFormRef = useRef<HTMLElement>(null);
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
  const tenant = isTenantTier(session.data ?? null);
  const saveApproval = useMutation({
    mutationFn: (request: ApprovedBulkSenderRequest) =>
      api.post<ApprovedSenderWriteResult>(
        "/outbound-intelligence/approved-senders",
        {
          ...request,
          source_ip: request.source_ip?.trim() ? request.source_ip.trim() : undefined,
          expires_at: expiryToRfc3339(request.expires_at ?? ""),
        },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async (result) => {
      setNotice(
        result.changed
          ? `${result.sender_address} approval is now ${result.active ? "On" : "Off"}.`
          : `${result.sender_address} approval was already ${result.active ? "On" : "Off"}; nothing changed.`,
      );
      setApprovalForm(initialApprovalForm());
      setEditingApprovalId(null);
      await queryClient.invalidateQueries({ queryKey: ["outbound-intelligence"] });
    },
  });
  const toggleApproval = useMutation({
    mutationFn: (request: { approval: ApprovedBulkSender; active: boolean; reason: string }) =>
      api.post<ApprovedSenderWriteResult>(
        "/outbound-intelligence/approved-senders",
        {
          sender_address: request.approval.sender_address,
          sending_domain: request.approval.sending_domain,
          source_kind: request.approval.source_kind,
          source_id: request.approval.source_id,
          source_ip: request.approval.source_ip ?? undefined,
          max_messages_per_minute: request.approval.max_messages_per_minute,
          max_messages_per_hour: request.approval.max_messages_per_hour,
          max_recipients_per_message: request.approval.max_recipients_per_message,
          max_unique_recipients_per_hour: request.approval.max_unique_recipients_per_hour,
          active: request.active,
          reason: request.reason,
          expires_at: request.approval.expires_at ?? null,
        },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async (result) => {
      setNotice(
        result.changed
          ? `${result.sender_address} approval is now ${result.active ? "On" : "Off"}.`
          : `${result.sender_address} approval was already ${result.active ? "On" : "Off"}; nothing changed.`,
      );
      setToggleTarget(null);
      setToggleReason("");
      setShowToggleError(false);
      await queryClient.invalidateQueries({ queryKey: ["outbound-intelligence"] });
    },
  });

  function beginEditApproval(approval: ApprovedBulkSender) {
    setApprovalForm({
      sender_address: approval.sender_address,
      sending_domain: approval.sending_domain,
      source_kind: approval.source_kind,
      source_id: approval.source_id,
      source_ip: approval.source_ip ?? "",
      max_messages_per_minute: approval.max_messages_per_minute,
      max_messages_per_hour: approval.max_messages_per_hour,
      max_recipients_per_message: approval.max_recipients_per_message,
      max_unique_recipients_per_hour: approval.max_unique_recipients_per_hour,
      active: approval.active,
      reason: approval.reason,
      expires_at: expiryToLocalInput(approval.expires_at),
    });
    setEditingApprovalId(approval.id);
    saveApproval.reset();
    approvalFormRef.current?.scrollIntoView?.({ block: "start" });
  }

  function cancelEditApproval() {
    setApprovalForm(initialApprovalForm());
    setEditingApprovalId(null);
    saveApproval.reset();
  }

  function openToggle(approval: ApprovedBulkSender, active: boolean) {
    setToggleTarget({ approval, active });
    setToggleReason("");
    setShowToggleError(false);
    toggleApproval.reset();
  }

  function closeToggle() {
    setToggleTarget(null);
    setToggleReason("");
    setShowToggleError(false);
    toggleApproval.reset();
  }

  function submitToggle() {
    if (!toggleTarget) return;
    if (approvalReasonError(toggleReason) !== undefined) {
      setShowToggleError(true);
      return;
    }
    toggleApproval.mutate({
      approval: toggleTarget.approval,
      active: toggleTarget.active,
      reason: toggleReason.trim(),
    });
  }

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
  const toggleError = toggleApproval.isError ? errorMessage(toggleApproval.error) : null;
  const toggleReasonProblem = toggleTarget === null ? undefined : approvalReasonError(toggleReason);
  const toggleReasonVisible =
    toggleTarget !== null &&
    (showToggleError || toggleReason.length > 0) &&
    toggleReasonProblem !== undefined;
  const approvalExpiryProblem = expiryError(approvalForm.expires_at ?? "");
  const editingApproval = editingApprovalId
    ? (data.approved_senders.find((approval) => approval.id === editingApprovalId) ?? null)
    : null;

  return (
    <div className="outbound-page">
      <WorkspaceHeader
        eyebrow="Outbound protection"
        title="Outbound intelligence"
        description={
          tenant
            ? "Review the senders, source ranges, campaigns and containment controls for your customer."
            : "Review sender, source, campaign and containment controls for this installation."
        }
        scope="Outbound enforcement controls"
        actions={
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => void intelligence.refetch()}
            aria-label="Refresh outbound intelligence"
          >
            <RefreshCw size={14} aria-hidden="true" />
            Refresh
          </button>
        }
      />

      <ControlRail
        title="Outbound risk queue"
        summary="Read the open events first, then change sender limits or stop a sender where your role allows."
        signals={[
          {
            label: "Open events",
            value: data.summary.open_security_events,
            detail: "Outbound events still awaiting closure.",
            tone: data.summary.open_security_events > 0 ? "attention" : "healthy",
          },
          {
            label: "Critical",
            value: data.summary.critical_security_events,
            detail: "Critical events that need attention now.",
            tone: data.summary.critical_security_events > 0 ? "attention" : "healthy",
          },
          {
            label: "Approved senders",
            value: data.summary.approved_bulk_senders,
            detail: "Bulk senders approved to send right now.",
            tone: "healthy",
          },
        ]}
      />

      <WorkflowGuide
        title="Act on outbound risk deliberately"
        description="Use what senders are doing to decide whether a sender needs an approved limit, a source fix, or to be stopped."
        steps={[
          { label: "Assess", detail: "Read the current sender, campaign and event details." },
          {
            label: "Authorize",
            detail: "Create or change a sender's approved limits, with a reason.",
          },
          {
            label: "Contain",
            detail: "Apply the control your role allows, then refresh to confirm it took.",
          },
        ]}
      />

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
          detail="counted once in the last hour"
        />
        <SummaryCard
          label="Active senders"
          value={data.summary.active_senders_1h}
          detail="seen in last hour"
        />
        <SummaryCard
          label="Approved bulk"
          value={data.summary.approved_bulk_senders}
          detail="approvals that are on right now"
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
                    <strong>{outboundEventLabel(event.event_type)}</strong>
                    <StatusPill
                      tone={severityTone(event.severity)}
                      label={severityLabel(event.severity)}
                    />
                    <StatusPill
                      tone={dispositionTone(event.outcome)}
                      label={outboundOutcomeLabel(event.outcome)}
                    />
                  </div>
                  <p>
                    {event.sender_address ?? "unknown sender"} via{" "}
                    {event.source_id ?? "unknown source"} · {reasonCodeLabel(event.reason_code)} ·{" "}
                    {event.message_count} observed messages
                  </p>
                  {event.remediation_summary ? (
                    <p className="outbound-event-remediation">
                      Action: {event.remediation_summary}
                      {event.credential_rotation_recommended
                        ? " Rotate the credentials this sender uses."
                        : ""}
                    </p>
                  ) : null}
                  {event.remediation_runbook ? (
                    <small>Runbook: {event.remediation_runbook}</small>
                  ) : null}
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
            <p>No senders recorded in the last hour.</p>
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
            <p className="outbound-muted">No bulk senders are approved yet.</p>
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
                    label={approval.active ? "On" : "Off"}
                  />
                  <p>{approval.reason}</p>
                  <small>
                    {approval.max_messages_per_hour}/h · {approval.max_recipients_per_message}{" "}
                    recipients/message · expires {formatDate(approval.expires_at)}
                  </small>
                  {canManage ? (
                    <div className="outbound-approval-actions">
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => beginEditApproval(approval)}
                      >
                        <Pencil size={13} aria-hidden="true" />
                        Edit limits
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => openToggle(approval, !approval.active)}
                      >
                        <Power size={13} aria-hidden="true" />
                        {approval.active ? "Deactivate" : "Reactivate"}
                      </button>
                    </div>
                  ) : null}
                </article>
              ))}
            </div>
          )}
        </section>

        {canManage ? (
          <section
            className="card outbound-approval-form"
            aria-labelledby="approve-bulk-heading"
            ref={approvalFormRef}
          >
            <h2 id="approve-bulk-heading">
              {editingApproval ? "Update approved bulk sender" : "Approve bulk sender"}
            </h2>
            {editingApproval ? (
              <p className="outbound-editing-note">
                Editing {editingApproval.sender_address} ({editingApproval.source_id}). Saving
                updates this approval rather than adding a new one.
                <button type="button" className="btn btn-ghost" onClick={cancelEditApproval}>
                  Cancel edit
                </button>
              </p>
            ) : null}
            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (approvalExpiryProblem) return;
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
              <label>
                Expires optional
                <input
                  type="datetime-local"
                  value={approvalForm.expires_at ?? ""}
                  onChange={(event) =>
                    setApprovalForm((current) => ({ ...current, expires_at: event.target.value }))
                  }
                  aria-invalid={
                    Boolean(approvalForm.expires_at) && approvalExpiryProblem !== undefined
                  }
                />
              </label>
              {approvalForm.expires_at && approvalExpiryProblem ? (
                <p className="outbound-form-error" role="alert">
                  {approvalExpiryProblem}
                </p>
              ) : null}
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
              <Hint
                label={`Approving a sender raises the limits applied to mail leaving ${
                  tenant ? "your customer" : "this installation"
                }.`}
              >
                <button type="submit" className="btn btn-primary" disabled={saveApproval.isPending}>
                  {editingApproval ? "Update approval" : "Save approval"}
                </button>
              </Hint>
            </form>
          </section>
        ) : null}
      </div>

      <div className="outbound-two-column">
        <section className="card outbound-campaigns" aria-labelledby="campaigns-heading">
          <h2 id="campaigns-heading">Campaign fingerprints</h2>
          {data.campaigns.length === 0 ? (
            <p className="outbound-muted">No campaigns have been recorded yet.</p>
          ) : (
            <div className="outbound-table-wrap compact">
              <table>
                <thead>
                  <tr>
                    <th>Fingerprint</th>
                    <th>Volume</th>
                    <th>Action taken</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.campaigns.map((campaign) => (
                    <tr key={`${campaign.algorithm}-${campaign.fingerprint}`}>
                      <td>
                        <strong>{campaign.fingerprint}</strong>
                        <span>{fingerprintVersionLabel(campaign.algorithm)}</span>
                      </td>
                      <td>
                        {campaign.message_count} messages
                        <span>{campaign.recipient_count} recipients</span>
                      </td>
                      <td>
                        <StatusPill
                          tone={dispositionTone(campaign.disposition)}
                          label={outboundOutcomeLabel(campaign.disposition)}
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
          <h2 id="policy-history-heading">Recent changes</h2>
          {data.policy_history.length === 0 ? (
            <p className="outbound-muted">No outbound approval changes recorded yet.</p>
          ) : (
            <div className="outbound-history-list">
              {data.policy_history.map((entry) => (
                <article key={entry.id}>
                  <CheckCircle2 size={15} aria-hidden="true" />
                  <div>
                    <strong>{auditActionLabel(entry.action)}</strong>
                    <p>
                      {tenant
                        ? (tenantResourceReference("approved_bulk_sender", entry.resource_id) ??
                          "your sender approvals")
                        : (entry.resource_id ?? "outbound policy")}{" "}
                      by {entry.actor_login}
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
            {tenant
              ? "When a sender is compromised or outbound is stopped, related events are grouped before an incident is raised. The open events above are what your customer sees and what your provider follows up on."
              : "When a sender is compromised or outbound is stopped, related events are grouped before an incident is raised. The open events above are what the customer can see and what Support and System follow up on."}
          </p>
        </div>
        {data.summary.open_security_events > 0 ? (
          <AlertTriangle size={22} aria-hidden="true" />
        ) : (
          <CheckCircle2 size={22} aria-hidden="true" />
        )}
      </section>

      <Dialog
        open={toggleTarget !== null}
        onClose={closeToggle}
        title={toggleTarget?.active ? "Reactivate approved sender" : "Deactivate approved sender"}
      >
        {toggleTarget ? (
          <form
            className="outbound-toggle-form"
            onSubmit={(event) => {
              event.preventDefault();
              submitToggle();
            }}
          >
            <p className="outbound-toggle-summary">
              <strong>{toggleTarget.approval.sender_address}</strong> via{" "}
              {sourceKindLabels[toggleTarget.approval.source_kind]} ·{" "}
              {toggleTarget.approval.source_id} becomes{" "}
              <strong>{toggleTarget.active ? "On" : "Off"}</strong>. Rate limits and expiry are
              kept.
            </p>
            <label>
              Reason
              <textarea
                value={toggleReason}
                onChange={(event) => setToggleReason(event.target.value)}
                rows={3}
                placeholder={
                  toggleTarget.active
                    ? "Why is this approval being reactivated?"
                    : "Why is this approval being suspended?"
                }
                aria-invalid={toggleReasonVisible}
              />
            </label>
            {toggleReasonVisible && toggleReasonProblem !== undefined ? (
              <p className="outbound-form-error" role="alert">
                {toggleReasonProblem}
              </p>
            ) : null}
            {toggleError ? (
              <>
                <p className="outbound-form-error" role="alert">
                  {toggleError}
                </p>
                <StepUpPrompt error={toggleApproval.error} />
              </>
            ) : null}
            <div className="outbound-form-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={closeToggle}
                disabled={toggleApproval.isPending}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={toggleApproval.isPending}>
                {toggleTarget.active ? "Reactivate approval" : "Deactivate approval"}
              </button>
            </div>
          </form>
        ) : null}
      </Dialog>
    </div>
  );
}

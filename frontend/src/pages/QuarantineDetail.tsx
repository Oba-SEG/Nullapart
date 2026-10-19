import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import { isTenantTier, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
import { randomUuid } from "../lib/ids";
import { auditActionLabel, findingCategoryLabel, reasonCodeLabel } from "../lib/labels";
import { notify } from "../lib/notify";
import {
  checkOutcomeLabel,
  requirementLabel,
  resultLabel,
  scannerStatusLabel,
  severityLabel,
} from "../lib/status";
import "./Quarantine.css";

interface QuarantineFinding {
  id: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  created_at: string;
}

interface QuarantineRetention {
  retention_class: string;
  artifact_created_at: string;
  quarantined_at: string;
  released_at?: string | null;
}

interface QuarantineScannerResult {
  capability: string;
  status: string;
  required: boolean;
  duration_ms?: number | null;
  completed_at: string;
}

interface QuarantineAuditEntry {
  action: string;
  actor_login: string;
  result: string;
  created_at: string;
}

interface QuarantineDetail {
  tenant_message_id: string;
  transaction_id: string;
  reason_code: string;
  sender: string;
  recipient_count: number;
  findings: QuarantineFinding[];
  quarantined_at: string;
  released_at?: string | null;
  release_allowed: boolean;
  released_by?: string | null;
  release_reason?: string | null;
  retention?: QuarantineRetention | null;
  scanner_results: QuarantineScannerResult[];
  audit: QuarantineAuditEntry[];
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "Quarantine detail is temporarily unavailable.";
}

export function QuarantineDetail() {
  const { tenant_message_id: tenantMessageId = "" } = useParams({
    from: "/quarantine/$tenant_message_id",
  });
  const queryClient = useQueryClient();
  const [releaseReason, setReleaseReason] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
  });
  const tenant = isTenantTier(session.data ?? null);

  const detail = useQuery({
    queryKey: ["quarantine", tenantMessageId],
    queryFn: ({ signal }) =>
      api.get<QuarantineDetail>(`/quarantine/${encodeURIComponent(tenantMessageId)}`, signal),
    enabled: tenantMessageId.length > 0,
  });

  const release = useMutation({
    mutationFn: async (reason: string) =>
      api.post<unknown>(
        `/quarantine/${encodeURIComponent(tenantMessageId)}/release`,
        { release_reason: reason },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async () => {
      setDialogOpen(false);
      setReleaseReason("");
      notify("Message released. The release was recorded in the audit log.");
      await queryClient.invalidateQueries({ queryKey: ["quarantine"] });
    },
  });

  const data = detail.data;

  return (
    <div className="quarantine-page">
      <Link to="/quarantine" className="quarantine-back">
        <ArrowLeft size={16} aria-hidden="true" /> Back to quarantine
      </Link>
      <WorkspaceHeader
        eyebrow="Mail on hold"
        title="Held message"
        description={
          tenant
            ? "Review how long this message was held, who acted on it and what the security checks found. The message body is never shown here."
            : "Review how long this message was held, who acted on it and the scanner results. The message body is never shown here."
        }
        scope="Release controls"
      />
      <WorkflowGuide
        title="Verify before release"
        description="The release control is only available for eligible cases. It never replaces investigation."
        steps={[
          {
            label: "Read findings",
            detail: tenant
              ? "Compare the hold reason with what the security checks found."
              : "Compare the hold reason with the scanner results.",
          },
          {
            label: "Confirm impact",
            detail: "Review how long it was held, the recipient count and prior actions.",
          },
          {
            label: "Release safely",
            detail:
              "Release only when it is clearly justified. You will re-authenticate and record why.",
          },
        ]}
      />

      {data ? (
        <ControlRail
          title="Case decision state"
          summary="Use this case state to confirm the investigation is complete before releasing."
          signals={[
            {
              label: "Findings",
              value: data.findings.length,
              detail: tenant
                ? "Security findings recorded for this message."
                : "Scanner findings recorded for this message.",
              tone: data.findings.some(
                (finding) => finding.severity === "critical" || finding.severity === "high",
              )
                ? "attention"
                : "neutral",
            },
            // Whether a required engine came back healthy is the platform's own
            // health, not a fact about the customer's mail. A tenant read gets
            // the findings and the release state.
            ...(tenant
              ? []
              : [
                  {
                    label: "Required checks",
                    value: `${data.scanner_results.filter((result) => result.required && result.status === "healthy").length}/${data.scanner_results.filter((result) => result.required).length}`,
                    detail: "Required scanner checks that completed cleanly.",
                  },
                ]),
            {
              label: "Release",
              value: data.released_at ? "Released" : data.release_allowed ? "Ready" : "Blocked",
              detail: data.released_at
                ? "This message was already released and recorded."
                : "Even when ready, you will re-authenticate and record why.",
              tone: data.released_at ? "healthy" : "attention",
            },
          ]}
        />
      ) : null}

      {detail.isPending && (
        <div className="quarantine-state" role="status">
          Loading case detail…
        </div>
      )}
      {detail.isError && (
        <div className="quarantine-state error" role="alert">
          {errorMessage(detail.error)}
        </div>
      )}

      {data && (
        <>
          <div className="case-action-bar">
            <div className="case-action-context">
              <span className="case-action-id">{data.tenant_message_id}</span>
              <span className="case-action-reason">{reasonCodeLabel(data.reason_code)}</span>
            </div>
            {data.released_at ? (
              <span className="case-action-released">
                Released {new Date(data.released_at).toLocaleString()}
              </span>
            ) : (
              <Hint label="Releasing returns this message to delivery. You will re-authenticate first, and the release is recorded.">
                <Button
                  variant="danger"
                  disabled={!data.release_allowed}
                  onClick={() => {
                    setReleaseReason("");
                    release.reset();
                    setDialogOpen(true);
                  }}
                >
                  Release message
                </Button>
              </Hint>
            )}
          </div>

          <section className="card quarantine-detail-grid" aria-label="Message metadata">
            <div>
              <h2 className="quarantine-section-title">Message</h2>
              <dl className="quarantine-facts">
                <dt>Message ID</dt>
                <dd className="quarantine-meta">{data.tenant_message_id}</dd>
                <dt>Transaction</dt>
                <dd className="quarantine-meta">{data.transaction_id}</dd>
                <dt>Sender</dt>
                <dd>{data.sender}</dd>
                <dt>Recipients</dt>
                <dd>{data.recipient_count}</dd>
                <dt>Reason</dt>
                <dd>{reasonCodeLabel(data.reason_code)}</dd>
                <dt>Quarantined</dt>
                <dd>{new Date(data.quarantined_at).toLocaleString()}</dd>
                <dt>Released</dt>
                <dd>{data.released_at ? new Date(data.released_at).toLocaleString() : "Active"}</dd>
              </dl>
            </div>
            <div>
              <h2 className="quarantine-section-title">Retention</h2>
              {data.retention ? (
                <dl className="quarantine-facts">
                  <dt>Class</dt>
                  <dd>{data.retention.retention_class}</dd>
                  <dt>Artifact created</dt>
                  <dd>{new Date(data.retention.artifact_created_at).toLocaleString()}</dd>
                  <dt>Quarantined</dt>
                  <dd>{new Date(data.retention.quarantined_at).toLocaleString()}</dd>
                  <dt>Released</dt>
                  <dd>
                    {data.retention.released_at
                      ? new Date(data.retention.released_at).toLocaleString()
                      : "Within quarantine retention"}
                  </dd>
                </dl>
              ) : (
                <p className="quarantine-subtitle">Retention state is unavailable.</p>
              )}
            </div>
          </section>

          <section className="card" aria-label={tenant ? "Security checks" : "Scanner results"}>
            <h2 className="quarantine-section-title">
              {tenant ? "Security checks" : "Scanner results"}
            </h2>
            {data.scanner_results.length === 0 ? (
              <p className="quarantine-subtitle">
                {tenant ? "No security checks are recorded." : "No scanner results are recorded."}
              </p>
            ) : (
              <table className="quarantine-table">
                <caption className="sr-only">
                  {tenant
                    ? "Security checks run for this message"
                    : "Scanner results for this message"}
                </caption>
                <thead>
                  <tr>
                    <th>{tenant ? "Check" : "Scanner check"}</th>
                    <th>{tenant ? "Result" : "Status"}</th>
                    {tenant ? null : (
                      <>
                        <th>Requirement</th>
                        <th>Duration</th>
                      </>
                    )}
                    <th>Completed</th>
                  </tr>
                </thead>
                <tbody>
                  {data.scanner_results.map((result) => (
                    <tr key={`${result.capability}-${result.completed_at}`}>
                      <td>{result.capability}</td>
                      <td>
                        {tenant
                          ? checkOutcomeLabel(result.status)
                          : scannerStatusLabel(result.status)}
                      </td>
                      {tenant ? null : (
                        <>
                          <td>{requirementLabel(result.required ? "required" : "optional")}</td>
                          <td>
                            {result.duration_ms === null || result.duration_ms === undefined
                              ? "—"
                              : `${result.duration_ms} ms`}
                          </td>
                        </>
                      )}
                      <td>{new Date(result.completed_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="card" aria-label="Findings">
            <h2 className="quarantine-section-title">Findings</h2>
            {data.findings.length === 0 ? (
              <p className="quarantine-subtitle">Held without publishable finding detail.</p>
            ) : (
              <ul className="quarantine-findings">
                {data.findings.map((finding) => (
                  <li key={finding.id}>
                    <span className={`severity severity-${finding.severity}`}>
                      {severityLabel(finding.severity)}: {findingCategoryLabel(finding.category)}
                    </span>
                    <span className="quarantine-finding-description">
                      Finding: {finding.description}
                    </span>
                    <span className="quarantine-meta">
                      {new Date(finding.created_at).toLocaleString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card" aria-label="Audit history">
            <h2 className="quarantine-section-title">Audit</h2>
            {data.audit.length === 0 ? (
              <p className="quarantine-subtitle">No administrative action has been recorded.</p>
            ) : (
              <ul className="quarantine-audit">
                {data.audit.map((entry) => (
                  <li key={`${entry.action}-${entry.created_at}`}>
                    <strong>{auditActionLabel(entry.action)}</strong> · {resultLabel(entry.result)}
                    <span className="quarantine-meta">
                      {entry.actor_login} · {new Date(entry.created_at).toLocaleString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {data.release_reason && (
              <p className="quarantine-subtitle">
                Release reason: {data.release_reason}
                {data.released_by ? ` · released by ${data.released_by}` : ""}
              </p>
            )}
          </section>

          <aside className="quarantine-state">
            <ShieldAlert size={20} aria-hidden="true" />
            {tenant
              ? "Each check is described by what it found for your mail. Message content is never shown here."
              : "Each result names a product capability only. Engine names, versions, endpoints and message content are never shown."}
          </aside>

          <Dialog
            open={dialogOpen}
            onClose={() => {
              setDialogOpen(false);
              setReleaseReason("");
              release.reset();
            }}
            title="Release held message"
          >
            <form
              className="quarantine-dialog"
              onSubmit={(event) => {
                event.preventDefault();
                const reason = releaseReason.trim();
                if (reason) release.mutate(reason);
              }}
            >
              <p>
                Releasing returns this message to delivery. You will re-authenticate, and the
                release is recorded in the audit log.
              </p>
              <ul>
                <li>Message: {data.tenant_message_id}</li>
                <li>Sender: {data.sender}</li>
                <li>Reason: {reasonCodeLabel(data.reason_code)}</li>
              </ul>
              <label>
                Release reason
                <textarea
                  value={releaseReason}
                  onChange={(event) => setReleaseReason(event.target.value)}
                  placeholder="Why are you releasing this message?"
                  maxLength={500}
                  required
                  rows={4}
                />
              </label>
              {releaseReason.trim().length === 0 ? (
                <p className="dialog-hint" id="quarantine-detail-release-hint">
                  Enter a release reason to enable confirmation.
                </p>
              ) : null}
              {release.isError && (
                <>
                  <p className="quarantine-state error" role="alert">
                    {errorMessage(release.error)}
                  </p>
                  <StepUpPrompt error={release.error} />
                </>
              )}
              <Button
                type="submit"
                variant="danger"
                loading={release.isPending}
                disabled={releaseReason.trim().length === 0}
                aria-describedby={
                  releaseReason.trim().length === 0 ? "quarantine-detail-release-hint" : undefined
                }
              >
                Release message
              </Button>
            </form>
          </Dialog>
        </>
      )}
    </div>
  );
}

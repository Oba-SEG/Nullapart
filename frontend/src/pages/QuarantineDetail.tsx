import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { randomUuid } from "../lib/ids";
import { notify } from "../lib/notify";
import { humanizeToken } from "../lib/text";
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
        eyebrow="Security disposition"
        title="Quarantine case"
        description="Review tenant-scoped retention, audit linkage and capability-level scanner results. Raw MIME and active email HTML are never rendered here."
        scope="Case-level release controls"
      />
      <WorkflowGuide
        title="Verify before release"
        description="The release control remains unavailable until the case is eligible; it is never a substitute for investigation."
        steps={[
          {
            label: "Read findings",
            detail: "Compare the disposition reason with scanner capability results.",
          },
          {
            label: "Confirm impact",
            detail: "Review retention, recipient count and prior audit events.",
          },
          {
            label: "Release safely",
            detail:
              "Use the recorded step-up workflow only when the exceptional release is justified.",
          },
        ]}
      />

      {data ? (
        <ControlRail
          title="Case decision state"
          summary="Use this server-reported case state to determine whether investigation is complete before considering the exceptional release action."
          signals={[
            {
              label: "Findings",
              value: data.findings.length,
              detail: "Published normalized findings for this case.",
              tone: data.findings.some(
                (finding) => finding.severity === "critical" || finding.severity === "high",
              )
                ? "attention"
                : "neutral",
            },
            {
              label: "Required scanners",
              value: `${data.scanner_results.filter((result) => result.required && result.status === "healthy").length}/${data.scanner_results.filter((result) => result.required).length}`,
              detail: "Required capability results that completed healthy.",
            },
            {
              label: "Release",
              value: data.released_at ? "released" : data.release_allowed ? "eligible" : "blocked",
              detail: data.released_at
                ? "The release is already recorded in the case audit trail."
                : "Eligibility does not remove step-up or justification requirements.",
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
              <span className="case-action-reason">{data.reason_code}</span>
            </div>
            {data.released_at ? (
              <span className="case-action-released">
                Released {new Date(data.released_at).toLocaleString()}
              </span>
            ) : (
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
                <dd>
                  {humanizeToken(data.reason_code)}
                  <span className="quarantine-meta">{data.reason_code}</span>
                </dd>
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

          <section className="card" aria-label="Scanner results">
            <h2 className="quarantine-section-title">Scanner results</h2>
            {data.scanner_results.length === 0 ? (
              <p className="quarantine-subtitle">No normalized scanner results are retained.</p>
            ) : (
              <table className="quarantine-table">
                <caption className="sr-only">Normalized scanner results for this case</caption>
                <thead>
                  <tr>
                    <th>Capability</th>
                    <th>Status</th>
                    <th>Class</th>
                    <th>Duration</th>
                    <th>Completed</th>
                  </tr>
                </thead>
                <tbody>
                  {data.scanner_results.map((result) => (
                    <tr key={`${result.capability}-${result.completed_at}`}>
                      <td>{result.capability}</td>
                      <td>{result.status}</td>
                      <td>{result.required ? "required" : "optional"}</td>
                      <td>
                        {result.duration_ms === null || result.duration_ms === undefined
                          ? "—"
                          : `${result.duration_ms} ms`}
                      </td>
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
                      {finding.severity}: {finding.category}
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
                    <strong>{entry.action}</strong> — {entry.result}
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
            Scanner entries are product capabilities only. Engine names, versions, endpoints and
            message content are never returned by this API.
          </aside>

          <Dialog
            open={dialogOpen}
            onClose={() => {
              setDialogOpen(false);
              setReleaseReason("");
              release.reset();
            }}
            title="Release quarantined message"
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
                Release requires a step-up authenticated session and creates an immutable audit and
                delivery record.
              </p>
              <ul>
                <li>Message: {data.tenant_message_id}</li>
                <li>Sender: {data.sender}</li>
                <li>Reason: {data.reason_code}</li>
              </ul>
              <label>
                Release reason
                <textarea
                  value={releaseReason}
                  onChange={(event) => setReleaseReason(event.target.value)}
                  placeholder="Why is this release authorized?"
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
                Confirm authorized release
              </Button>
            </form>
          </Dialog>
        </>
      )}
    </div>
  );
}

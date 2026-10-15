import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Search, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";

import { api, type ApiError } from "../api/client";
import { StatusPill } from "../components/StatusPill";
import { severityTone } from "../lib/status";
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

interface QuarantineCase {
  tenant_message_id: string;
  transaction_id: string;
  reason_code: string;
  sender: string;
  recipient_count: number;
  findings: QuarantineFinding[];
  quarantined_at: string;
  released_at?: string | null;
  release_allowed: boolean;
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "Quarantine data is temporarily unavailable.";
}

export function Quarantine() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [selected, setSelected] = useState<QuarantineCase | null>(null);
  const [releaseReason, setReleaseReason] = useState("");

  const cases = useQuery({
    queryKey: ["quarantine"],
    queryFn: ({ signal }) => api.get<QuarantineCase[]>("/quarantine", signal),
  });
  const release = useMutation({
    mutationFn: async ({ item, reason }: { item: QuarantineCase; reason: string }) =>
      api.post<QuarantineCase>(
        `/quarantine/${encodeURIComponent(item.tenant_message_id)}/release`,
        { release_reason: reason },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async () => {
      setSelected(null);
      setReleaseReason("");
      notify("Message released. The release was recorded in the audit log.");
      await queryClient.invalidateQueries({ queryKey: ["quarantine"] });
    },
  });

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (cases.data ?? []).filter((item) => {
      const matchesText =
        !needle ||
        item.sender.toLowerCase().includes(needle) ||
        item.tenant_message_id.toLowerCase().includes(needle) ||
        item.transaction_id.toLowerCase().includes(needle) ||
        item.reason_code.toLowerCase().includes(needle);
      const matchesSeverity =
        severity === "all" || item.findings.some((finding) => finding.severity === severity);
      return matchesText && matchesSeverity;
    });
  }, [cases.data, search, severity]);
  const casesAvailable = cases.isSuccess;
  const casesState = cases.isError ? "Unavailable" : "Loading";

  return (
    <div className="quarantine-page">
      <WorkspaceHeader
        eyebrow="Security disposition"
        title="Quarantine"
        description="Review tenant-scoped security holds using normalized, content-safe evidence. Release remains step-up protected and auditable at case level."
        scope="Case disposition controls"
      />

      <ControlRail
        title="Quarantine review queue"
        summary="Work highest-severity active cases first. Opening a case is required before any exceptional release decision."
        signals={[
          {
            label: "Cases",
            value: casesAvailable ? filtered.length : casesState,
            detail: casesAvailable
              ? "Cases matching the current severity filter."
              : "No case queue is inferred until the query succeeds.",
          },
          {
            label: "Critical",
            value: casesAvailable
              ? filtered.filter((item) =>
                  item.findings.some((finding) => finding.severity === "critical"),
                ).length
              : casesState,
            detail: casesAvailable
              ? "Filtered cases carrying a critical published finding."
              : "Critical finding state is unavailable until the case query succeeds.",
            tone: casesAvailable ? "attention" : "neutral",
          },
          {
            label: "Release eligible",
            value: casesAvailable
              ? filtered.filter((item) => item.release_allowed && !item.released_at).length
              : casesState,
            detail: casesAvailable
              ? "Cases that may enter the step-up release workflow."
              : "Release eligibility is unavailable until the case query succeeds.",
            tone: casesAvailable ? "attention" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Resolve a security disposition safely"
        description="A release is an exceptional, tenant-scoped decision. Investigate the case before requesting the step-up and idempotent release operation."
        steps={[
          {
            label: "Triage",
            detail: "Prioritize severity, findings and retention state from the case list.",
          },
          {
            label: "Investigate",
            detail: "Open the case to review safe metadata and its audit linkage.",
          },
          {
            label: "Release only if justified",
            detail: "Complete step-up and record the authorized, idempotent release.",
          },
        ]}
      />

      <section className="quarantine-controls" aria-label="Quarantine filters">
        <label className="search-box">
          <span className="sr-only">Search quarantine</span>
          <Search size={18} className="search-icon" aria-hidden="true" />
          <input
            className="search-input"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search sender, transaction, or reason"
          />
        </label>
        <label>
          <span className="sr-only">Filter by severity</span>
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Informational</option>
          </select>
        </label>
      </section>

      {cases.isPending && (
        <div className="quarantine-state" role="status">
          Loading quarantined messages…
        </div>
      )}
      {cases.isError && (
        <div className="quarantine-state error" role="alert">
          {errorMessage(cases.error)}
        </div>
      )}
      {cases.isSuccess && filtered.length === 0 && (
        <div className="quarantine-state">No active quarantine cases match these filters.</div>
      )}

      {filtered.length > 0 && (
        <div className="card quarantine-table-wrap">
          <table className="quarantine-table">
            <caption className="sr-only">Active tenant quarantine cases</caption>
            <thead>
              <tr>
                <th>Message</th>
                <th>Sender</th>
                <th>Findings</th>
                <th>Reason</th>
                <th>Quarantined</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={item.tenant_message_id}>
                  <td>
                    <Link
                      to="/quarantine/$tenant_message_id"
                      params={{ tenant_message_id: item.tenant_message_id }}
                    >
                      <strong>{item.tenant_message_id}</strong>
                    </Link>
                    <span className="quarantine-meta">Transaction {item.transaction_id}</span>
                  </td>
                  <td>
                    {item.sender}
                    <span className="quarantine-meta">
                      {item.recipient_count} recipient{item.recipient_count === 1 ? "" : "s"}
                    </span>
                  </td>
                  <td>
                    {item.findings.length === 0 ? (
                      <span>Held without publishable finding detail</span>
                    ) : (
                      item.findings.map((finding) => (
                        <div className="quarantine-finding-summary" key={finding.id}>
                          <div className="finding-head">
                            <StatusPill
                              tone={severityTone(finding.severity)}
                              label={finding.severity}
                            />
                            <span className="finding-category">Category: {finding.category}</span>
                          </div>
                          <span className="quarantine-finding-description">
                            Finding: {finding.description}
                          </span>
                        </div>
                      ))
                    )}
                  </td>
                  <td>
                    {humanizeToken(item.reason_code)}
                    <span className="quarantine-meta">{item.reason_code}</span>
                  </td>
                  <td>{new Date(item.quarantined_at).toLocaleString()}</td>
                  <td>
                    <Button
                      size="sm"
                      variant="danger"
                      disabled={!item.release_allowed}
                      onClick={() => {
                        setSelected(item);
                        setReleaseReason("");
                        release.reset();
                      }}
                    >
                      Release
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <aside className="quarantine-state">
        <ShieldAlert size={20} aria-hidden="true" />
        Raw MIME and active email HTML are never rendered here. Findings are server-normalized
        summaries only.
      </aside>

      <Dialog
        open={selected !== null}
        onClose={() => {
          setSelected(null);
          setReleaseReason("");
          release.reset();
        }}
        title="Release quarantined message"
      >
        {selected && (
          <form
            className="quarantine-dialog"
            onSubmit={(event) => {
              event.preventDefault();
              const reason = releaseReason.trim();
              if (reason) release.mutate({ item: selected, reason });
            }}
          >
            <p>
              Release requires a step-up authenticated session and creates an immutable audit and
              delivery record.
            </p>
            <ul>
              <li>Message: {selected.tenant_message_id}</li>
              <li>Sender: {selected.sender}</li>
              <li>Reason: {selected.reason_code}</li>
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
              <p className="dialog-hint" id="quarantine-release-hint">
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
                releaseReason.trim().length === 0 ? "quarantine-release-hint" : undefined
              }
            >
              Confirm authorized release
            </Button>
          </form>
        )}
      </Dialog>
    </div>
  );
}

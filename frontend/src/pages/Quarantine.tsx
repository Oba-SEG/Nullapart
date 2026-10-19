import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Search, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";

import { api, type ApiError } from "../api/client";
import { StatusPill } from "../components/StatusPill";
import { findingCategoryLabel } from "../lib/labels";
import { severityLabel, severityTone } from "../lib/status";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
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
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(new Set());
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkReason, setBulkReason] = useState("");

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
  const bulkRelease = useMutation({
    mutationFn: async ({ items, reason }: { items: QuarantineCase[]; reason: string }) => {
      const failed: string[] = [];
      for (const item of items) {
        try {
          await api.post(
            `/quarantine/${encodeURIComponent(item.tenant_message_id)}/release`,
            { release_reason: reason },
            { idempotencyKey: randomUuid() },
          );
        } catch (error) {
          // Step-up must surface immediately and abort the batch; every
          // completed release in the batch is already durable and audited.
          if ((error as ApiError).code === "STEP_UP_REQUIRED") throw error;
          failed.push(item.tenant_message_id);
        }
      }
      return failed;
    },
    onSuccess: (failed) => {
      if (failed.length === 0) {
        notify("Selected messages released. Every release was recorded in the audit log.");
      } else {
        notify(
          `${failed.length} of the selected messages could not be released. Each attempt is recorded in the audit log.`,
          "error",
        );
      }
      setBulkOpen(false);
      setBulkReason("");
      setSelectedIds(new Set());
      void queryClient.invalidateQueries({ queryKey: ["quarantine"] });
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
  const eligibleFiltered = useMemo(
    () => filtered.filter((item) => item.release_allowed && !item.released_at),
    [filtered],
  );
  const selectedCases = useMemo(
    () => filtered.filter((item) => selectedIds.has(item.tenant_message_id)),
    [filtered, selectedIds],
  );
  const releaseableSelected = useMemo(
    () => selectedCases.filter((item) => item.release_allowed && !item.released_at),
    [selectedCases],
  );
  const allEligibleSelected =
    eligibleFiltered.length > 0 &&
    eligibleFiltered.every((item) => selectedIds.has(item.tenant_message_id));

  function toggleSelected(id: string, checked: boolean) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (checked) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  }

  const casesAvailable = cases.isSuccess;
  const casesState = cases.isError ? "Unavailable" : "Loading";

  return (
    <div className="quarantine-page">
      <WorkspaceHeader
        eyebrow="Mail on hold"
        title="Quarantine"
        description="Review held mail using safe metadata: headers and scanner results, never the message body. Releasing a message returns it to delivery."
        scope="Release decisions"
      />

      <ControlRail
        title="Quarantine review queue"
        summary="Work the highest-severity cases first. Open a case before releasing anything."
        signals={[
          {
            label: "Cases",
            value: casesAvailable ? filtered.length : casesState,
            detail: casesAvailable
              ? "Held messages that match the current severity filter."
              : "The count appears once held mail finishes loading.",
          },
          {
            label: "Critical",
            value: casesAvailable
              ? filtered.filter((item) =>
                  item.findings.some((finding) => finding.severity === "critical"),
                ).length
              : casesState,
            detail: casesAvailable
              ? "Cases with a critical scanner finding."
              : "The count appears once held mail finishes loading.",
            tone: casesAvailable ? "attention" : "neutral",
          },
          {
            label: "Ready to release",
            value: casesAvailable
              ? filtered.filter((item) => item.release_allowed && !item.released_at).length
              : casesState,
            detail: casesAvailable
              ? "Cases you can release now."
              : "The count appears once held mail finishes loading.",
            tone: casesAvailable ? "attention" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Release held mail safely"
        description="Releasing a message returns it to delivery. Investigate the case first. You will re-authenticate and record why."
        steps={[
          {
            label: "Triage",
            detail: "Sort by severity, findings and how long the message has been held.",
          },
          {
            label: "Investigate",
            detail: "Open the case to review its safe metadata and history.",
          },
          {
            label: "Release only if justified",
            detail:
              "Release only when the reason is clear. You will re-authenticate and record why.",
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
            placeholder="Search by sender, transaction, or reason"
          />
        </label>
        <label>
          <span className="sr-only">Filter by severity</span>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Informational</option>
          </select>
        </label>
        {releaseableSelected.length > 0 ? (
          <div className="quarantine-bulk-bar">
            <span>
              {releaseableSelected.length} message
              {releaseableSelected.length === 1 ? "" : "s"} ready to release
            </span>
            <Hint label="Releasing returns these held messages to delivery. Each release is recorded in the audit log.">
              <Button
                size="sm"
                variant="danger"
                onClick={() => {
                  setBulkOpen(true);
                  setBulkReason("");
                  bulkRelease.reset();
                }}
              >
                Release selected
              </Button>
            </Hint>
            <Button size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>
              Clear selection
            </Button>
          </div>
        ) : null}
      </section>

      {cases.isPending && (
        <div className="quarantine-state" role="status">
          Loading held mail…
        </div>
      )}
      {cases.isError && (
        <div className="quarantine-state error" role="alert">
          {errorMessage(cases.error)}
        </div>
      )}
      {cases.isSuccess && filtered.length === 0 && (
        <div className="quarantine-state quarantine-empty">
          <p className="quarantine-empty-title">No held messages match these filters.</p>
          <p className="quarantine-empty-detail">
            Messages appear here as soon as the gateway holds them. To review delivered mail, open
            Messages.
          </p>
          <Link to="/messages" className="btn btn-ghost">
            Open Messages
          </Link>
        </div>
      )}

      {filtered.length > 0 && (
        <div className="card quarantine-table-wrap">
          <table className="quarantine-table">
            <caption className="sr-only">Active held messages</caption>
            <thead>
              <tr>
                <th scope="col" className="quarantine-select-col">
                  <input
                    type="checkbox"
                    aria-label="Select all ready-to-release messages"
                    checked={allEligibleSelected}
                    onChange={(event) => {
                      setSelectedIds(
                        event.target.checked
                          ? new Set(eligibleFiltered.map((item) => item.tenant_message_id))
                          : new Set(),
                      );
                    }}
                  />
                </th>
                <th>Message</th>
                <th>Sender</th>
                <th>Findings</th>
                <th>Reason</th>
                <th>Quarantined</th>
                <th>
                  <Hint label="Release returns a held message to delivery. It is only available for cases marked ready to release.">
                    <span className="hint-term">Action</span>
                  </Hint>
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={item.tenant_message_id}>
                  <td className="quarantine-select-col">
                    <input
                      type="checkbox"
                      aria-label={`Select message ${item.tenant_message_id}`}
                      checked={selectedIds.has(item.tenant_message_id)}
                      disabled={!item.release_allowed || Boolean(item.released_at)}
                      onChange={(event) =>
                        toggleSelected(item.tenant_message_id, event.target.checked)
                      }
                    />
                  </td>
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
                      <span>Held with no finding detail</span>
                    ) : (
                      item.findings.map((finding) => (
                        <div className="quarantine-finding-summary" key={finding.id}>
                          <div className="finding-head">
                            <StatusPill
                              tone={severityTone(finding.severity)}
                              label={severityLabel(finding.severity)}
                            />
                            <span className="finding-category">
                              Category: {findingCategoryLabel(finding.category)}
                            </span>
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
                  <td>
                    {new Date(item.quarantined_at).toLocaleString()}
                    {item.released_at ? (
                      <span className="quarantine-released-chip">
                        Released {new Date(item.released_at).toLocaleString()}
                      </span>
                    ) : null}
                  </td>
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
        The message body is never shown here. Findings are safe summaries of headers and scanner
        results only.
      </aside>

      <Dialog
        open={selected !== null}
        onClose={() => {
          setSelected(null);
          setReleaseReason("");
          release.reset();
        }}
        title="Release held message"
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
              Releasing returns this message to delivery. You will re-authenticate, and the release
              is recorded in the audit log.
            </p>
            <ul>
              <li>Message: {selected.tenant_message_id}</li>
              <li>Sender: {selected.sender}</li>
              <li>Reason: {humanizeToken(selected.reason_code)}</li>
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
              Release message
            </Button>
          </form>
        )}
      </Dialog>

      <Dialog
        open={bulkOpen}
        onClose={() => {
          setBulkOpen(false);
          setBulkReason("");
          bulkRelease.reset();
        }}
        title="Release selected messages"
      >
        <form
          className="quarantine-dialog"
          onSubmit={(event) => {
            event.preventDefault();
            const reason = bulkReason.trim();
            if (reason && releaseableSelected.length > 0) {
              bulkRelease.mutate({ items: releaseableSelected, reason });
            }
          }}
        >
          <p>
            Each message is released with the same reason and recorded in the audit log. Released
            messages return to delivery and cannot be pulled back here.
          </p>
          <ul>
            {releaseableSelected.map((item) => (
              <li key={item.tenant_message_id}>
                {item.tenant_message_id} <span>from {item.sender}</span>
              </li>
            ))}
          </ul>
          <label>
            Release reason
            <textarea
              value={bulkReason}
              onChange={(event) => setBulkReason(event.target.value)}
              placeholder="Why are you releasing these messages?"
              maxLength={500}
              required
              rows={4}
            />
          </label>
          {bulkRelease.isError && (
            <>
              <p className="quarantine-state error" role="alert">
                {errorMessage(bulkRelease.error)} Messages released before this point stay released.
              </p>
              <StepUpPrompt error={bulkRelease.error} />
            </>
          )}
          <Button
            type="submit"
            variant="danger"
            loading={bulkRelease.isPending}
            disabled={bulkReason.trim().length === 0 || releaseableSelected.length === 0}
          >
            Release {releaseableSelected.length} selected message
            {releaseableSelected.length === 1 ? "" : "s"}
          </Button>
        </form>
      </Dialog>
    </div>
  );
}

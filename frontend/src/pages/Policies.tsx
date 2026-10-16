import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import {
  MANAGEMENT_LEVELS,
  tierAllows,
  type ManagementLevel,
  type PolicyList,
  type RevisionSummary,
} from "../api/policies";
import { Hint } from "../components/primitives/Hint";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { ControlRail } from "../components/ControlRail";
import { HINTS, MANAGEMENT_LEVEL_LABELS } from "../lib/labels";
import "./Policies.css";

type LevelFilter = "all" | ManagementLevel;

const LEVEL_FILTERS: LevelFilter[] = ["all", ...MANAGEMENT_LEVELS];

const LEVEL_LABELS: Record<LevelFilter, string> = {
  all: "All levels",
  ...MANAGEMENT_LEVEL_LABELS,
};

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : "";
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    const message = String((error as ApiError).message);
    if (errorCode(error) === "RATE_LIMITED") {
      return `${message} Please wait a moment before retrying.`;
    }
    return message;
  }
  return "Policy data is temporarily unavailable.";
}

function activeRevisionLabel(active: RevisionSummary): string {
  const publishedAt = new Date(active.published_at);
  return `#${active.revision_number} · by ${active.published_by} · ${publishedAt.toLocaleString()}`;
}

export function Policies() {
  const [level, setLevel] = useState<LevelFilter>("all");
  const [onlyEditable, setOnlyEditable] = useState(false);

  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: ({ signal }) => api.get<PolicyList>("/policies", signal),
  });

  // The tier comes from the server, resolved from the roles it issued. A
  // deployment-defined role the administrator placed at system level reaches
  // system families here, which a builtin-role-name check used to deny.
  const callerTier = policies.data?.caller_tier ?? null;
  const allRows = policies.data?.families ?? [];
  const isEditable = (managementLevel: ManagementLevel) => tierAllows(callerTier, managementLevel);
  const editableCount = allRows.filter((family) => isEditable(family.management_level)).length;
  const rows = allRows.filter(
    (family) =>
      (level === "all" || family.management_level === level) &&
      (!onlyEditable || isEditable(family.management_level)),
  );
  const policiesAvailable = policies.isSuccess;
  const policiesState = policies.isError ? "Unavailable" : "Loading";

  return (
    <div className="policies-page">
      <WorkspaceHeader
        eyebrow="Configuration governance"
        title="Policies"
        description="Open a policy family to read its revisions and publish a new one. Each family says which management level may change it, and your level decides whether the editor opens."
        scope={
          policiesAvailable
            ? `${editableCount} of ${allRows.length} families open for editing`
            : "Versioned policy controls"
        }
        actions={
          <Link to="/policies/features" className="btn btn-primary">
            Feature overrides
          </Link>
        }
      />

      <ControlRail
        title="Policy release queue"
        summary="Filter by the level you administer, or show only the families your roles can change. Opening a family you cannot change shows why."
        signals={[
          {
            label: "In view",
            value: policiesAvailable ? rows.length : policiesState,
            detail: policiesAvailable
              ? `${LEVEL_LABELS[level]} policy families currently shown.`
              : "The policy queue has not returned yet.",
          },
          {
            label: "Your level",
            value: policiesAvailable
              ? callerTier === null
                ? "None"
                : MANAGEMENT_LEVEL_LABELS[callerTier]
              : policiesState,
            detail: policiesAvailable
              ? HINTS.callerTier
              : "Your level is shown once the policy list returns.",
          },
          {
            label: "Security floors",
            value: policiesAvailable
              ? rows.filter((row) => row.security_floor).length
              : policiesState,
            detail: policiesAvailable
              ? "Families that keep enforcing their floor while you change them."
              : "Security-floor counts are unavailable until the policy list returns.",
            tone: policiesAvailable ? "attention" : "neutral",
          },
          {
            label: "Published",
            value: policiesAvailable
              ? rows.filter((row) => row.active_revision !== null).length
              : policiesState,
            detail: policiesAvailable
              ? "Families with a revision in force right now."
              : "Published revision state is unavailable until the policy list returns.",
            tone: policiesAvailable ? "healthy" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Publish a policy revision"
        description="Revisions are versioned and audited. Publishing replaces the revision in force; the previous one stays in history."
        steps={[
          {
            label: "Locate",
            detail: "Filter by level, or show only the families your roles can change.",
          },
          {
            label: "Revise",
            detail:
              "Open the family, edit its rules in order, and check each rule reads as you mean it.",
          },
          {
            label: "Publish",
            detail:
              "Publish with your reason; the new revision takes effect and is recorded against you.",
          },
        ]}
      />

      <div className="policies-filters">
        <div className="policies-filters" role="group" aria-label="Filter by management level">
          {LEVEL_FILTERS.map((value) => (
            <button
              key={value}
              type="button"
              className={`policies-chip${level === value ? " policies-chip-active" : ""}`}
              aria-pressed={level === value}
              onClick={() => setLevel(value)}
            >
              {LEVEL_LABELS[value]}
            </button>
          ))}
        </div>
        {policiesAvailable && allRows.length > 0 ? (
          <button
            type="button"
            className={`policies-chip${onlyEditable ? " policies-chip-active" : ""}`}
            aria-pressed={onlyEditable}
            onClick={() => setOnlyEditable((value) => !value)}
          >
            {onlyEditable ? "Showing what you can change" : "Show only what you can change"}
          </button>
        ) : null}
      </div>

      {policies.isPending ? (
        <div className="policies-state" role="status">
          Loading policy families…
        </div>
      ) : null}
      {policies.isError ? (
        <div className="policies-state error" role="alert">
          {errorMessage(policies.error)}
          <StepUpPrompt error={policies.error} />
        </div>
      ) : null}
      {policies.isSuccess && allRows.length === 0 ? (
        <div className="policies-state">
          No policy families are available in this deployment yet. They appear here once the
          platform publishes them.
        </div>
      ) : null}
      {policies.isSuccess && allRows.length > 0 && rows.length === 0 ? (
        <div className="policies-state">
          {onlyEditable
            ? "None of these families open for editing at your level. Clear the filter to read them."
            : "No policy family matches this management level."}
        </div>
      ) : null}

      {rows.length > 0 ? (
        <div className="card policies-table-wrap">
          <table className="policies-table">
            <caption className="sr-only">Policy families in this deployment</caption>
            <thead>
              <tr>
                <th scope="col">Family</th>
                <th scope="col">What it governs</th>
                <th scope="col">
                  <Hint label="The management level allowed to change this family. Your level has to reach it.">
                    <span className="hint-term">Changeable at</span>
                  </Hint>
                </th>
                <th scope="col">Revision in force</th>
                <th scope="col">Revisions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((family) => {
                const editable = isEditable(family.management_level);
                return (
                  <tr key={family.family_key}>
                    <td>
                      <div className="policies-name">
                        <Link
                          to="/policies/$familyKey"
                          params={{ familyKey: family.family_key }}
                          aria-label={family.display_name}
                        >
                          {family.display_name}
                        </Link>
                        <code className="policies-key">{family.family_key}</code>
                      </div>
                    </td>
                    <td className="policies-description">{family.description}</td>
                    <td>
                      {editable ? (
                        <span
                          className={`policies-badge policies-level-${family.management_level}`}
                        >
                          {MANAGEMENT_LEVEL_LABELS[family.management_level]}
                        </span>
                      ) : (
                        <Hint
                          label={`This family changes at ${
                            MANAGEMENT_LEVEL_LABELS[family.management_level]
                          } level. ${
                            callerTier === null
                              ? "Your roles do not carry a policy level."
                              : `Your roles reach ${MANAGEMENT_LEVEL_LABELS[callerTier]} level.`
                          }`}
                        >
                          <span className="policies-lock">
                            Needs {MANAGEMENT_LEVEL_LABELS[family.management_level]}
                          </span>
                        </Hint>
                      )}
                      {family.security_floor ? (
                        <>
                          {" "}
                          <Hint label={HINTS.securityFloor}>
                            <span className="policies-badge policies-floor">Security floor</span>
                          </Hint>
                        </>
                      ) : null}
                    </td>
                    <td className="policies-active">
                      {family.active_revision ? (
                        <span className="policies-revision">
                          {activeRevisionLabel(family.active_revision)}
                        </span>
                      ) : (
                        <span className="policies-empty">Nothing published yet</span>
                      )}
                    </td>
                    <td>{family.revision_count}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { api, type ApiError } from "../api/client";
import {
  MANAGEMENT_LEVELS,
  type ManagementLevel,
  type PolicyList,
  type RevisionSummary,
} from "../api/policies";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { ControlRail } from "../components/ControlRail";
import "./Policies.css";

type LevelFilter = "all" | ManagementLevel;

const LEVEL_FILTERS: LevelFilter[] = ["all", ...MANAGEMENT_LEVELS];

const LEVEL_LABELS: Record<LevelFilter, string> = {
  all: "All levels",
  customer: "Customer",
  support: "Support",
  system: "System",
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

  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: ({ signal }) => api.get<PolicyList>("/policies", signal),
  });

  const allRows = policies.data?.families ?? [];
  const rows = allRows.filter((family) => level === "all" || family.management_level === level);
  const policiesAvailable = policies.isSuccess;
  const policiesState = policies.isError ? "Unavailable" : "Loading";

  return (
    <div className="policies-page">
      <WorkspaceHeader
        eyebrow="Configuration governance"
        title="Policies"
        description="Review policy families by management level, then open a family to draft, validate and publish a versioned revision. The server enforces who may publish each level."
        scope="Versioned policy controls"
        actions={
          <Link to="/policies/features" className="btn btn-primary">
            Feature overrides
          </Link>
        }
      />

      <ControlRail
        title="Policy release queue"
        summary="The selected management level determines which policy families are in view; open a family to use its controlled revision workflow."
        signals={[
          {
            label: "In view",
            value: policiesAvailable ? rows.length : policiesState,
            detail: policiesAvailable
              ? `${LEVEL_LABELS[level]} policy families currently shown.`
              : "The policy release queue has not produced an authoritative result yet.",
          },
          {
            label: "Security floors",
            value: policiesAvailable
              ? rows.filter((row) => row.security_floor).length
              : policiesState,
            detail: policiesAvailable
              ? "Families whose floor remains enforced during change."
              : "Security-floor counts are unavailable until the policy query succeeds.",
            tone: policiesAvailable ? "attention" : "neutral",
          },
          {
            label: "Published",
            value: policiesAvailable
              ? rows.filter((row) => row.active_revision !== null).length
              : policiesState,
            detail: policiesAvailable
              ? "Families with a current published revision."
              : "Published revision state is unavailable until the policy query succeeds.",
            tone: policiesAvailable ? "healthy" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Publish policy by authority level"
        description="Use the filter to locate the family you own, then work through its versioned revision workflow."
        steps={[
          {
            label: "Locate",
            detail: "Filter families by the management level you are permitted to administer.",
          },
          {
            label: "Revise",
            detail: "Open the family and prepare a validated, versioned revision.",
          },
          {
            label: "Publish",
            detail:
              "Publish only through the server-authorized workflow and use audit history to verify it.",
          },
        ]}
      />

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
        <div className="policies-state">No policy families are seeded in this deployment.</div>
      ) : null}
      {policies.isSuccess && allRows.length > 0 && rows.length === 0 ? (
        <div className="policies-state">No policy families match this management level.</div>
      ) : null}

      {rows.length > 0 ? (
        <div className="card policies-table-wrap">
          <table className="policies-table">
            <caption className="sr-only">Policy families in this deployment</caption>
            <thead>
              <tr>
                <th scope="col">Family</th>
                <th scope="col">Description</th>
                <th scope="col">Management level</th>
                <th scope="col">Active revision</th>
                <th scope="col">Revisions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((family) => (
                <tr key={family.family_key}>
                  <td>
                    <Link
                      to="/policies/$familyKey"
                      params={{ familyKey: family.family_key }}
                      aria-label={family.family_key}
                    >
                      {family.family_key}
                      <span className="sr-only">. </span>
                    </Link>
                  </td>
                  <td className="policies-description">{family.description}</td>
                  <td>
                    <span className={`policies-badge policies-level-${family.management_level}`}>
                      {family.management_level}
                    </span>
                    {family.security_floor ? (
                      <>
                        {" "}
                        <span className="policies-badge policies-floor">security floor</span>
                      </>
                    ) : null}
                  </td>
                  <td className="policies-active">
                    {family.active_revision ? (
                      <span className="policies-revision">
                        {activeRevisionLabel(family.active_revision)}
                      </span>
                    ) : (
                      <span className="policies-empty">not published</span>
                    )}
                  </td>
                  <td>{family.revision_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

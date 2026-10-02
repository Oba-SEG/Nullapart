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

  return (
    <div className="policies-page">
      <header className="policies-header">
        <div>
          <h1 className="policies-title">Policies</h1>
          <p className="policies-subtitle">
            Policy families define how mail is evaluated and dispositioned. Revisions are versioned
            and audited; the server enforces which management level may publish each family.
          </p>
        </div>
        <Link to="/policies/features" className="btn btn-primary">
          Feature overrides
        </Link>
      </header>

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

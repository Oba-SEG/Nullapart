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
import {
  HINTS,
  MANAGEMENT_LEVEL_LABELS,
  TENANT_LEVEL_LABELS,
  familyDisplayName,
  tenantLevelBucket,
  type TenantLevelBucket,
} from "../lib/labels";
import "./Policies.css";

type LevelFilter = "all" | ManagementLevel;

const LEVEL_FILTERS: LevelFilter[] = ["all", ...MANAGEMENT_LEVELS];

const LEVEL_LABELS: Record<LevelFilter, string> = {
  all: "All levels",
  ...MANAGEMENT_LEVEL_LABELS,
};

/**
 * A customer console does not administer a level ladder it cannot reach, so the
 * three published levels are two buckets for a tenant: families their own roles
 * can change, and families their provider changes.
 */
type TenantBucketFilter = "all" | TenantLevelBucket;

const TENANT_BUCKET_FILTERS: TenantBucketFilter[] = ["all", "yours", "provider"];

const TENANT_BUCKET_LABELS: Record<TenantBucketFilter, string> = {
  all: "All families",
  yours: TENANT_LEVEL_LABELS.yours,
  provider: TENANT_LEVEL_LABELS.provider,
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
  const [tenantBucket, setTenantBucket] = useState<TenantBucketFilter>("all");
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
  const tenantTier = callerTier === "customer";
  const editableCount = allRows.filter((family) => isEditable(family.management_level)).length;
  const rows = allRows.filter((family) => {
    if (onlyEditable && !isEditable(family.management_level)) return false;
    return tenantTier
      ? tenantBucket === "all" || tenantLevelBucket(family.management_level) === tenantBucket
      : level === "all" || family.management_level === level;
  });
  const policiesAvailable = policies.isSuccess;
  const policiesState = policies.isError ? "Unavailable" : "Loading";

  return (
    <div className="policies-page">
      <WorkspaceHeader
        eyebrow="Configuration governance"
        title="Policies"
        description={
          tenantTier
            ? "Open a family marked Yours to change to read its revisions and publish a new one. Families your provider changes are listed by name so you know who to ask, but they do not open here."
            : "Open a policy family to read its revisions and publish a new one. Each family says which management level may change it, and your level decides whether the editor opens."
        }
        scope={
          policiesAvailable
            ? `${editableCount} of ${allRows.length} families open for editing`
            : "Versioned policy controls"
        }
        actions={
          // Feature overrides are a deployment-configuration surface. A tenant
          // console does not offer it, so the entry is hidden for the customer
          // level the server published.
          tenantTier ? null : (
            <Link to="/policies/features" className="btn btn-primary">
              Feature overrides
            </Link>
          )
        }
      />

      <ControlRail
        title="Policy release queue"
        summary={
          tenantTier
            ? "Filter by what your roles can change. Families marked Needs your provider are named here so you can ask about them; they do not open in this console."
            : "Filter by the level you administer, or show only the families your roles can change. Opening a family you cannot change shows why."
        }
        signals={[
          {
            label: "In view",
            value: policiesAvailable ? rows.length : policiesState,
            detail: !policiesAvailable
              ? "The policy queue has not returned yet."
              : tenantTier
                ? tenantBucket === "all"
                  ? "Every policy family your provider publishes."
                  : tenantBucket === "yours"
                    ? "Families your own roles can change."
                    : "Families your provider changes."
                : `${LEVEL_LABELS[level]} policy families currently shown.`,
          },
          {
            label: tenantTier ? "Your scope" : "Your level",
            value: policiesAvailable
              ? callerTier === null
                ? "None"
                : tenantTier
                  ? "Your organisation"
                  : MANAGEMENT_LEVEL_LABELS[callerTier]
              : policiesState,
            detail: policiesAvailable
              ? tenantTier
                ? "You change what belongs to your own organisation. Your provider changes the rest."
                : HINTS.callerTier
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
        <div
          className="policies-filters"
          role="group"
          aria-label={tenantTier ? "Filter by what you can change" : "Filter by management level"}
        >
          {tenantTier
            ? TENANT_BUCKET_FILTERS.map((value) => (
                <button
                  key={value}
                  type="button"
                  className={`policies-chip${tenantBucket === value ? " policies-chip-active" : ""}`}
                  aria-pressed={tenantBucket === value}
                  onClick={() => setTenantBucket(value)}
                >
                  {TENANT_BUCKET_LABELS[value]}
                </button>
              ))
            : LEVEL_FILTERS.map((value) => (
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
          {tenantTier
            ? "No policy family is open to your organisation yet. Ask your provider if you expect one here."
            : "No policy families are available in this deployment yet. They appear here once the platform publishes them."}
        </div>
      ) : null}
      {policies.isSuccess && allRows.length > 0 && rows.length === 0 ? (
        <div className="policies-state">
          {onlyEditable
            ? tenantTier
              ? "None of these families are yours to change. Clear the filter to read them."
              : "None of these families open for editing at your level. Clear the filter to read them."
            : tenantTier
              ? "No policy family matches this filter. Clear it to read the rest."
              : "No policy family matches this management level."}
        </div>
      ) : null}

      {rows.length > 0 ? (
        <div className="card policies-table-wrap">
          <table className="policies-table">
            <caption className="sr-only">
              {tenantTier
                ? "Policy families for your organisation"
                : "Policy families in this deployment"}
            </caption>
            <thead>
              <tr>
                <th scope="col">Family</th>
                <th scope="col">What it governs</th>
                <th scope="col">
                  <Hint
                    label={
                      tenantTier
                        ? "Whether your own roles can publish a new revision of this family, or your provider has to."
                        : "The management level allowed to change this family. Your level has to reach it."
                    }
                  >
                    <span className="hint-term">
                      {tenantTier ? "Who can change it" : "Changeable at"}
                    </span>
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
                        {/* A tenant link into a provider family always 403s and
                            writes a Denied row into that tenant's own audit log,
                            so the name is information rather than a dead end. */}
                        {tenantTier && !editable ? (
                          <span>
                            {familyDisplayName(family.family_key, family.display_name, tenantTier)}
                          </span>
                        ) : (
                          <Link
                            to="/policies/$familyKey"
                            params={{ familyKey: family.family_key }}
                            aria-label={familyDisplayName(
                              family.family_key,
                              family.display_name,
                              tenantTier,
                            )}
                          >
                            {familyDisplayName(family.family_key, family.display_name, tenantTier)}
                          </Link>
                        )}
                        {/* The family key is how the platform stores the family. A
                            tenant governs their overrides by name; the policy detail
                            page already withholds the key from them, so the list
                            can't be the row that leaks it. */}
                        {tenantTier ? null : (
                          <code className="policies-key">{family.family_key}</code>
                        )}
                      </div>
                    </td>
                    <td className="policies-description">{family.description}</td>
                    <td>
                      {tenantTier ? (
                        editable ? (
                          <Hint label="Your own roles can publish a new revision of this family for your organisation.">
                            <span
                              className={`policies-badge policies-level-${family.management_level} hint-term`}
                            >
                              {TENANT_LEVEL_LABELS.yours}
                            </span>
                          </Hint>
                        ) : (
                          <Hint label="Your provider changes this family. Ask them if it needs to change for your organisation.">
                            <span className="policies-lock hint-term">
                              {TENANT_LEVEL_LABELS.provider}
                            </span>
                          </Hint>
                        )
                      ) : editable ? (
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

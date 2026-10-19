import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useId, useState } from "react";

import { api, type ApiError } from "../api/client";
import {
  OVERRIDE_VALUE_KINDS,
  decodeOverrideValue,
  encodeOverrideValue,
  expiryError,
  expiryToRfc3339,
  overrideReasonError,
  writableScopes,
  type Feature,
  type FeatureList,
  type FeatureOverride,
  type OverrideScope,
  type OverrideValueKind,
  type OverrideWriteResult,
} from "../api/policies";
import { hasPermission, isTenantTier, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { ControlRail, type ControlSignal } from "../components/ControlRail";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import {
  HINTS,
  OVERRIDE_SCOPE_LABELS,
  describeOverrideValue,
  overrideScopeLabel,
  overrideValueKindLabel,
} from "../lib/labels";
import { randomUuid } from "../lib/ids";
import "./FeatureOverrides.css";

/**
 * Snake_case identifiers stay breakable after each underscore so table cells
 * wrap at word boundaries instead of chopping mid-token. The `<wbr>` element
 * is a pure break opportunity: it adds no characters, so the rendered and
 * accessible text remains exactly the raw identifier.
 */
function BreakableToken({ text }: { text: string }) {
  const parts = text.split("_");
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {part}
          {index < parts.length - 1 ? (
            <>
              _<wbr />
            </>
          ) : null}
        </Fragment>
      ))}
    </>
  );
}

/**
 * Primary position holds the human label from the catalog. The raw id sits under
 * it on a platform read only: it is the handle the write path is addressed by and
 * what audit records name, and a customer console neither needs to quote it nor
 * should print a snake_case key that names the technique.
 */
function FeatureName({ feature, showKey }: { feature: Feature; showKey: boolean }) {
  return (
    <div className="features-name">
      <strong>{feature.display_name}</strong>
      {showKey ? (
        <Hint label={HINTS.internalIdentifier}>
          <code className="features-key">
            <BreakableToken text={feature.feature_id} />
          </code>
        </Hint>
      ) : null}
    </div>
  );
}

interface OverrideDraft {
  feature: Feature;
  scope: OverrideScope;
  kind: OverrideValueKind;
  typed: string;
  reason: string;
  expiresAt: string;
}

interface OverrideRequest {
  featureId: string;
  featureName: string;
  scope: OverrideScope;
  value: string;
  reason: string;
  expiresAt: string | null;
}

interface ClearOverrideRequest {
  featureId: string;
  featureName: string;
  scope: OverrideScope;
  reason: string;
}

type OverrideRowProps = {
  feature: Feature;
  override: FeatureOverride;
  canClear: (scope: OverrideScope) => boolean;
  onClear: (feature: Feature, override: FeatureOverride) => void;
  /** A customer reads their own decisions, not a ladder they were never shown. */
  tenant: boolean;
};

function OverrideRow({ feature, override, canClear, onClear, tenant }: OverrideRowProps) {
  return (
    <div className="features-override">
      <span className="features-override-head">
        <strong>{overrideScopeLabel(override.scope, override.scope_id, tenant)}</strong>
        <code>{describeOverrideValue(override.value, tenant)}</code>
      </span>
      <span className="features-meta">
        set by {override.owner_display_name} · {formatDate(override.created_at)} ·{" "}
        {override.expires_at ? `expires ${formatDate(override.expires_at)}` : "no expiry"}
      </span>
      {canClear(override.scope) ? (
        <button
          type="button"
          className="btn btn-ghost features-clear"
          onClick={() => onClear(feature, override)}
        >
          {tenant ? "Take this back" : "Clear this override"}
        </button>
      ) : (
        <Hint
          label={
            tenant
              ? "Your roles can read these settings but cannot change them. Ask your provider if one needs to move."
              : "Your roles cannot change anything set at this level."
          }
        >
          <span className="features-lock">{tenant ? "Read-only" : "Set by a higher level"}</span>
        </Hint>
      )}
    </div>
  );
}

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
  return "Feature settings are unavailable right now. Your changes were not saved.";
}

function formatDate(value: string | null): string {
  if (!value) return "never";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

/** Newest first; the newest override leads the cell and the rest collapse. */
function overridesNewestFirst(overrides: FeatureOverride[]): FeatureOverride[] {
  return [...overrides].sort((left, right) => {
    const byDate = Date.parse(right.created_at) - Date.parse(left.created_at);
    return byDate !== 0 ? byDate : right.revision - left.revision;
  });
}

/**
 * The override level in words, for the seat reading it. A customer is not shown
 * the ladder, so their own level is "your setting" rather than a tier name.
 */
function scopePhrase(scope: OverrideScope, tenant: boolean): string {
  return tenant ? "your setting" : OVERRIDE_SCOPE_LABELS[scope].toLowerCase();
}

/**
 * Who the value in force now reflects. A customer is not shown the ladder, so
 * their write answer says `you` or `your provider`; an operator reads the level.
 */
function decidedByPhrase(
  result: { winning_scope?: OverrideScope; governed_by?: "you" | "provider" },
  tenant: boolean,
): string {
  if (tenant) return result.governed_by === "you" ? "you" : "your provider";
  return result.winning_scope ? OVERRIDE_SCOPE_LABELS[result.winning_scope].toLowerCase() : "you";
}

export function FeatureOverrides() {
  const queryClient = useQueryClient();
  const reasonInputId = useId();
  const clearReasonInputId = useId();

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });

  const current = session.data ?? null;
  // A customer session may write its own Customer-scope overrides, so the read
  // is the same query on both seats and only the projection differs: a tenant
  // answer carries no ladder, no platform floors and only its own override rows.
  const tenant = isTenantTier(current);

  const features = useQuery({
    queryKey: ["features"],
    queryFn: ({ signal }) => api.get<FeatureList>("/features", signal),
    enabled: !session.isPending,
  });

  const canManage = hasPermission(current, "policies:manage");
  // Published by the server from the same ladder the write path enforces, so a
  // row that looks editable here is one the API will actually accept.
  const sessionScopes = features.data?.allowed_override_scopes ?? [];

  const [onlyEditable, setOnlyEditable] = useState(false);
  const [editing, setEditing] = useState<OverrideDraft | null>(null);
  const [showErrors, setShowErrors] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [clearing, setClearing] = useState<{ feature: Feature; override: FeatureOverride } | null>(
    null,
  );
  const [clearReason, setClearReason] = useState("");
  const [showClearErrors, setShowClearErrors] = useState(false);

  const saveOverride = useMutation({
    mutationFn: (request: OverrideRequest) =>
      api.put<OverrideWriteResult>(
        `/features/${encodeURIComponent(request.featureId)}/overrides`,
        {
          scope: request.scope,
          value: request.value,
          reason: request.reason,
          expires_at: request.expiresAt,
        },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async (updated, request) => {
      setNotice(
        `${request.featureName} is now ${describeOverrideValue(
          updated.effective_value,
          tenant,
        )}, set by ${decidedByPhrase(updated, tenant)}.`,
      );
      setEditing(null);
      setShowErrors(false);
      await queryClient.invalidateQueries({ queryKey: ["features"] });
    },
  });

  const clearOverride = useMutation({
    mutationFn: (request: ClearOverrideRequest) =>
      api.put<OverrideWriteResult>(
        `/features/${encodeURIComponent(request.featureId)}/overrides`,
        { scope: request.scope, value: "inherit", reason: request.reason, expires_at: null },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async (updated, request) => {
      setNotice(
        `Cleared at ${scopePhrase(request.scope, tenant)}. ` +
          `${request.featureName} is now ${describeOverrideValue(
            updated.effective_value,
            tenant,
          )}, set by ${decidedByPhrase(updated, tenant)}.`,
      );
      setClearing(null);
      setClearReason("");
      setShowClearErrors(false);
      await queryClient.invalidateQueries({ queryKey: ["features"] });
    },
  });

  function editableScopes(feature: Feature): OverrideScope[] {
    return canManage ? writableScopes(feature.allowed_scopes, sessionScopes) : [];
  }

  function canClearAt(scope: OverrideScope): boolean {
    return canManage && sessionScopes.includes(scope);
  }

  function openEditor(feature: Feature) {
    const scopes = editableScopes(feature);
    const decoded = decodeOverrideValue(feature.effective_value);
    // A customer answer withholds the ladder, so it opens at the one level that
    // answer can list; an operator starts at the level currently deciding.
    const deciding = feature.winning_scope;
    setEditing({
      feature,
      scope:
        deciding !== undefined && scopes.includes(deciding) ? deciding : (scopes[0] ?? "tenant"),
      kind: decoded.kind,
      typed: decoded.typed,
      reason: "",
      expiresAt: "",
    });
    setShowErrors(false);
    saveOverride.reset();
  }

  function closeEditor() {
    setEditing(null);
    setShowErrors(false);
    saveOverride.reset();
  }

  function openClear(feature: Feature, override: FeatureOverride) {
    setClearing({ feature, override });
    setClearReason("");
    setShowClearErrors(false);
    clearOverride.reset();
  }

  function closeClear() {
    setClearing(null);
    setClearReason("");
    setShowClearErrors(false);
    clearOverride.reset();
  }

  function submitClear() {
    if (!clearing) return;
    if (overrideReasonError(clearReason) !== undefined) {
      setShowClearErrors(true);
      return;
    }
    clearOverride.mutate({
      featureId: clearing.feature.feature_id,
      featureName: clearing.feature.display_name,
      scope: clearing.override.scope,
      reason: clearReason.trim(),
    });
  }

  function submitOverride() {
    if (!editing) return;
    const reasonProblem = overrideReasonError(editing.reason);
    const expiryProblem = expiryError(editing.expiresAt);
    const typedEmpty = editing.kind === "typed" && editing.typed.trim().length === 0;
    if (reasonProblem !== undefined || expiryProblem !== undefined || typedEmpty) {
      setShowErrors(true);
      return;
    }
    saveOverride.mutate({
      featureId: editing.feature.feature_id,
      featureName: editing.feature.display_name,
      scope: editing.scope,
      value: encodeOverrideValue(editing.kind, editing.typed.trim()),
      reason: editing.reason.trim(),
      expiresAt: expiryToRfc3339(editing.expiresAt),
    });
  }

  const allRows = features.data?.features ?? [];
  const editableCount = allRows.filter((feature) => editableScopes(feature).length > 0).length;
  const rows = onlyEditable
    ? allRows.filter((feature) => editableScopes(feature).length > 0)
    : allRows;
  const featuresAvailable = features.isSuccess;
  const featuresState = features.isError ? "Unavailable" : "Loading";
  const reasonError = editing === null ? undefined : overrideReasonError(editing.reason);
  const reasonVisible =
    editing !== null && (showErrors || editing.reason.length > 0) && reasonError !== undefined;
  const expiryFailure = editing === null ? undefined : expiryError(editing.expiresAt);
  const expiryVisible =
    editing !== null && (showErrors || editing.expiresAt.length > 0) && expiryFailure !== undefined;
  const typedMissing =
    editing !== null && editing.kind === "typed" && editing.typed.trim().length === 0
      ? "Enter the value to use for this setting."
      : undefined;
  const clearReasonProblem = clearing === null ? undefined : overrideReasonError(clearReason);
  const clearReasonVisible =
    clearing !== null &&
    (showClearErrors || clearReason.length > 0) &&
    clearReasonProblem !== undefined;

  const providerDecided = allRows.filter((row) => row.governed_by === "provider").length;
  const mandatoryRows = allRows.filter((row) => row.mandatory).length;
  const killSwitchRows = allRows.filter((row) => row.kill_switch).length;

  const emergencyStops: ControlSignal = {
    label: "Emergency stops",
    value: featuresAvailable ? killSwitchRows : featuresState,
    detail: featuresAvailable ? HINTS.emergencyStop : "Not available yet.",
    tone: featuresAvailable ? "attention" : "neutral",
  };

  // A customer answer withholds the platform floors and emergency stops, so a
  // tenant rail reports the one fact its projection does publish: how many
  // values in force are the provider's decision rather than the customer's.
  const signals: ControlSignal[] = [
    {
      label: "Settings",
      value: featuresAvailable ? allRows.length : featuresState,
      detail: featuresAvailable
        ? tenant
          ? "Settings your sending is configured for."
          : "Features this deployment can be configured for."
        : "The settings list has not returned yet.",
    },
    {
      label: "You can change",
      value: featuresAvailable ? editableCount : featuresState,
      detail: featuresAvailable
        ? tenant
          ? "Settings your roles can turn on, off or give a value."
          : "Settings with at least one level your roles can write."
        : "Changeable settings are counted once the list returns.",
      tone: featuresAvailable && editableCount === 0 ? "attention" : "neutral",
    },
    tenant
      ? {
          label: "Set by your provider",
          value: featuresAvailable ? providerDecided : featuresState,
          detail: featuresAvailable
            ? "Your provider decided these, so they stay in force while you change the rest."
            : "Not available yet.",
        }
      : {
          label: "Security floors",
          value: featuresAvailable ? mandatoryRows : featuresState,
          detail: featuresAvailable
            ? HINTS.securityFloor
            : "Floor counts are unavailable until the settings list returns.",
          tone: featuresAvailable ? "attention" : "neutral",
        },
    ...(tenant ? [] : [emergencyStops]),
  ];

  return (
    <div className="features-page">
      <WorkspaceHeader
        eyebrow={tenant ? "Your sending" : "Controlled rollout"}
        title={tenant ? "Feature settings" : "Feature overrides"}
        description={
          tenant
            ? "Turn a setting on or off for your sending, or give it a value of your own. Anything your provider already decided is marked on the row. Every change needs a reason and can be undone."
            : "Turn a feature on or off for a group of customers, a whole deployment, or everywhere at once. Every change needs a reason, is signed by you, and can be cleared again."
        }
        scope={`${editableCount} of ${allRows.length} settings ${
          tenant ? "yours to change" : "changeable by you"
        }`}
      />

      <ControlRail
        title={tenant ? "What decides your mail today" : "Effective configuration"}
        summary={
          tenant
            ? "Each row shows the value in force for your sending and who decided it. A row without a change action is one your roles cannot move; the reason is written on the row."
            : "Each row shows the value in force and who set it. A row without an edit action is one your roles cannot change; the reason is written on the row."
        }
        signals={signals}
      />

      <WorkflowGuide
        title={
          tenant ? "Change a setting and get it back" : "Make a reversible configuration change"
        }
        description={
          tenant
            ? "Your own setting never switches off something your provider requires. If a setting is one they must keep on, the console tells you that instead of changing it."
            : "A feature override is a rollout control. It cannot switch off a security floor or a platform emergency stop."
        }
        steps={[
          {
            label: "Compare",
            detail: tenant
              ? "Read the value in force for your sending and see whether you or your provider decided it."
              : "Read the value in force against the default, and see which level set it.",
          },
          {
            label: "Justify",
            detail: tenant
              ? "Write why, and add a date to revert automatically when the change is temporary."
              : "Pick the level to change at, write why, and add an expiry when it is temporary.",
          },
          {
            label: "Verify",
            detail: tenant
              ? "After saving, the row shows your new value and you can clear it again."
              : "After saving, the row shows the new value in force and who set it.",
          },
        ]}
      />

      {notice ? (
        <p className="features-notice" role="status">
          {notice}
        </p>
      ) : null}

      {featuresAvailable && allRows.length > 0 ? (
        <div className="features-filters">
          <button
            type="button"
            className={`features-chip${onlyEditable ? " features-chip-active" : ""}`}
            aria-pressed={onlyEditable}
            onClick={() => setOnlyEditable((value) => !value)}
          >
            {onlyEditable ? "Showing what you can change" : "Show only what you can change"}
          </button>
          {canManage ? null : (
            <Hint label={tenant ? HINTS.readOnlyTenant : HINTS.callerTier}>
              <span className="features-lock">
                {tenant
                  ? "Read-only: your roles cannot change these settings"
                  : "Read-only: your role cannot manage policy settings"}
              </span>
            </Hint>
          )}
        </div>
      ) : null}

      {features.isPending ? (
        <div className="features-state" role="status">
          Loading feature settings…
        </div>
      ) : null}
      {features.isError ? (
        <div className="features-state error" role="alert">
          {errorMessage(features.error)}
          <StepUpPrompt error={features.error} />
        </div>
      ) : null}
      {features.isSuccess && allRows.length === 0 ? (
        <div className="features-state">
          {tenant
            ? "Nothing is open for your customer to change right now. Settings your provider decides are listed here once they let you change one."
            : "No features are available to configure in this deployment yet. Feature settings appear here once they are published."}
        </div>
      ) : null}
      {features.isSuccess && allRows.length > 0 && rows.length === 0 ? (
        <div className="features-state">
          None of these settings can be changed by your roles. Clear the filter to read them.
        </div>
      ) : null}

      {rows.length > 0 ? (
        <div className="card features-table-wrap">
          <table className="features-table">
            <caption className="sr-only">
              {tenant ? "Feature settings for your sending" : "Feature settings in this deployment"}
            </caption>
            <thead>
              <tr>
                <th scope="col">{tenant ? "Setting" : "Feature"}</th>
                {tenant ? null : <th scope="col">What it controls</th>}
                {tenant ? null : <th scope="col">Default</th>}
                <th scope="col">
                  <Hint label={tenant ? HINTS.inheritTenant : HINTS.winningScope}>
                    <span className="hint-term">
                      {tenant ? "On for your sending" : "Value in force"}
                    </span>
                  </Hint>
                </th>
                <th scope="col">{tenant ? "Changes you have made" : "Overrides"}</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((feature) => {
                const writable = editableScopes(feature);
                return (
                  <tr key={feature.feature_id}>
                    <td>
                      <FeatureName feature={feature} showKey={!tenant} />
                      <span className="features-badges">
                        {feature.mandatory ? (
                          <Hint label={HINTS.securityFloor}>
                            <span className="features-badge features-badge-mandatory">
                              Security floor
                            </span>
                          </Hint>
                        ) : null}
                        {feature.kill_switch ? (
                          <Hint label={HINTS.emergencyStop}>
                            <span className="features-badge features-badge-kill">
                              Emergency stop
                            </span>
                          </Hint>
                        ) : null}
                      </span>
                    </td>
                    {tenant ? null : (
                      <td className="features-description">{feature.description}</td>
                    )}
                    {tenant ? null : (
                      <td className="features-value">
                        {describeOverrideValue(feature.default_value)}
                      </td>
                    )}
                    <td>
                      <span className="features-value">
                        {describeOverrideValue(feature.effective_value, tenant)}
                      </span>
                      <span className="features-meta">
                        set by {decidedByPhrase(feature, tenant)}
                      </span>
                    </td>
                    <td>
                      {feature.overrides.length === 0 ? (
                        <span className="features-meta">
                          {tenant
                            ? "You have not changed this setting"
                            : "Nothing set below the default"}
                        </span>
                      ) : (
                        (() => {
                          const ordered = overridesNewestFirst(feature.overrides);
                          const [leading, ...older] = ordered;
                          return (
                            <div className="features-overrides">
                              <OverrideRow
                                feature={feature}
                                override={leading}
                                canClear={canClearAt}
                                onClear={openClear}
                                tenant={tenant}
                              />
                              {older.length > 0 ? (
                                <details className="features-override-history">
                                  <summary>Earlier changes ({older.length})</summary>
                                  {older.map((override) => (
                                    <OverrideRow
                                      key={override.id}
                                      feature={feature}
                                      override={override}
                                      canClear={canClearAt}
                                      onClear={openClear}
                                      tenant={tenant}
                                    />
                                  ))}
                                </details>
                              ) : null}
                            </div>
                          );
                        })()
                      )}
                    </td>
                    <td>
                      {writable.length > 0 ? (
                        <Button type="button" size="sm" onClick={() => openEditor(feature)}>
                          Change
                        </Button>
                      ) : (
                        <Hint
                          label={
                            canManage
                              ? tenant
                                ? "Your roles cannot change this setting. Ask your provider if it needs to move."
                                : `This setting is only changed at ${feature.allowed_scopes
                                    .map((scope) => OVERRIDE_SCOPE_LABELS[scope].toLowerCase())
                                    .join(" or ")}. Your roles can write ${
                                    sessionScopes.length === 0
                                      ? "no override level"
                                      : sessionScopes
                                          .map((scope) =>
                                            OVERRIDE_SCOPE_LABELS[scope].toLowerCase(),
                                          )
                                          .join(" or ")
                                  }.`
                              : tenant
                                ? HINTS.readOnlyTenant
                                : HINTS.readOnly
                          }
                        >
                          <span className="features-lock">
                            {canManage
                              ? tenant
                                ? "Set by your provider"
                                : "Locked at your level"
                              : "Read-only"}
                          </span>
                        </Hint>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}

      <Dialog
        open={editing !== null}
        onClose={closeEditor}
        title={`Change ${editing?.feature.display_name ?? "a feature setting"}`}
      >
        {editing ? (
          <form
            className="features-form"
            onSubmit={(event) => {
              event.preventDefault();
              submitOverride();
            }}
          >
            <p className="features-hint">
              {tenant
                ? "Your reason and name are recorded with this change. You may be asked to sign in again first."
                : "Your reason and name are recorded with this change and can be read in the audit log. You may be asked to sign in again first."}
            </p>
            {tenant ? (
              <div className="features-field">
                <span className="features-field-label">Change it for</span>
                <strong>Your sending</strong>
                <span className="features-meta">
                  The value in force today was set by {decidedByPhrase(editing.feature, tenant)}.
                </span>
              </div>
            ) : (
              <Select
                label="Change it for"
                value={editing.scope}
                options={writableScopes(editing.feature.allowed_scopes, sessionScopes).map(
                  (scope) => ({
                    value: scope,
                    label: OVERRIDE_SCOPE_LABELS[scope],
                  }),
                )}
                onChange={(event) =>
                  setEditing({ ...editing, scope: event.target.value as OverrideScope })
                }
              />
            )}
            <Select
              label="New value"
              value={editing.kind}
              options={OVERRIDE_VALUE_KINDS.map((kind) => ({
                value: kind,
                label: overrideValueKindLabel(kind, tenant),
                disabled: kind === "disabled" && editing.feature.mandatory,
              }))}
              onChange={(event) =>
                setEditing({ ...editing, kind: event.target.value as OverrideValueKind })
              }
            />
            {editing.kind === "inherit" ? (
              <p className="features-hint">{tenant ? HINTS.inheritTenant : HINTS.inherit}</p>
            ) : null}
            {editing.feature.mandatory ? (
              <p className="features-hint">
                This one is a security floor, so it cannot be switched off. Turn it on or set a
                value for it.
              </p>
            ) : null}
            {editing.kind === "typed" ? (
              <Input
                label="Value to use"
                value={editing.typed}
                onChange={(event) => setEditing({ ...editing, typed: event.target.value })}
                placeholder="rate_limit=10"
                maxLength={256}
                error={showErrors ? typedMissing : undefined}
                hint={
                  tenant
                    ? "Sent exactly as you type it. Your provider decides what a valid value looks like."
                    : "Sent exactly as you type it. The feature decides what a valid value looks like."
                }
              />
            ) : null}
            <div className="features-field">
              <label htmlFor={reasonInputId} className="features-field-label">
                Why this change
              </label>
              <textarea
                id={reasonInputId}
                className="features-textarea"
                value={editing.reason}
                onChange={(event) => setEditing({ ...editing, reason: event.target.value })}
                rows={3}
                maxLength={500}
                aria-invalid={reasonVisible}
                placeholder="What this change is for, and how you will know it worked."
              />
              {reasonVisible && reasonError !== undefined ? (
                <p className="features-error" role="alert">
                  {reasonError}
                </p>
              ) : null}
            </div>
            <Input
              label="Revert automatically (optional)"
              type="datetime-local"
              value={editing.expiresAt}
              onChange={(event) => setEditing({ ...editing, expiresAt: event.target.value })}
              error={expiryVisible ? expiryFailure : undefined}
              hint="Leave empty to keep this change until you clear it."
            />
            {saveOverride.isError ? (
              <>
                <p className="features-error" role="alert">
                  {errorMessage(saveOverride.error)}
                </p>
                <StepUpPrompt error={saveOverride.error} />
              </>
            ) : null}
            <div className="features-form-actions">
              <Button
                type="button"
                variant="ghost"
                onClick={closeEditor}
                disabled={saveOverride.isPending}
              >
                Keep current value
              </Button>
              <Button type="submit" variant="primary" loading={saveOverride.isPending}>
                Save change
              </Button>
            </div>
          </form>
        ) : null}
      </Dialog>

      <Dialog
        open={clearing !== null}
        onClose={closeClear}
        title={
          tenant
            ? `Take back your change to ${clearing?.feature.display_name ?? "this setting"}`
            : `Clear ${clearing?.feature.display_name ?? "override"}`
        }
      >
        {clearing ? (
          <form
            className="features-form"
            onSubmit={(event) => {
              event.preventDefault();
              submitClear();
            }}
          >
            <p className="features-hint">
              {tenant ? HINTS.inheritTenant : HINTS.inherit} Your reason is recorded with the
              change.
            </p>
            <div className="features-field">
              <label htmlFor={clearReasonInputId} className="features-field-label">
                Why this is being retired
              </label>
              <textarea
                id={clearReasonInputId}
                className="features-textarea"
                value={clearReason}
                onChange={(event) => setClearReason(event.target.value)}
                rows={3}
                maxLength={500}
                aria-invalid={clearReasonVisible}
                placeholder="What changed that makes this override unnecessary?"
              />
              {clearReasonVisible && clearReasonProblem !== undefined ? (
                <p className="features-error" role="alert">
                  {clearReasonProblem}
                </p>
              ) : null}
            </div>
            {clearOverride.isError ? (
              <>
                <p className="features-error" role="alert">
                  {errorMessage(clearOverride.error)}
                </p>
                <StepUpPrompt error={clearOverride.error} />
              </>
            ) : null}
            <div className="features-form-actions">
              <Button
                type="button"
                variant="ghost"
                onClick={closeClear}
                disabled={clearOverride.isPending}
              >
                {tenant ? "Keep your change" : "Keep the override"}
              </Button>
              <Button type="submit" variant="primary" loading={clearOverride.isPending}>
                {tenant ? "Take back your change" : "Clear override"}
              </Button>
            </div>
          </form>
        ) : null}
      </Dialog>
    </div>
  );
}

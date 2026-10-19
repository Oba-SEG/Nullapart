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
import { ControlRail } from "../components/ControlRail";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import {
  HINTS,
  OVERRIDE_SCOPE_LABELS,
  OVERRIDE_VALUE_KIND_LABELS,
  describeOverrideValue,
  overrideScopeLabel,
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
 * Primary position holds the human label from the catalog; the raw id sits
 * under it as evidence, because audit records name the id, not the label.
 */
function FeatureName({ feature }: { feature: Feature }) {
  return (
    <div className="features-name">
      <strong>{feature.display_name}</strong>
      <Hint label={HINTS.internalIdentifier}>
        <code className="features-key">
          <BreakableToken text={feature.feature_id} />
        </code>
      </Hint>
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
};

function OverrideRow({ feature, override, canClear, onClear }: OverrideRowProps) {
  return (
    <div className="features-override">
      <span className="features-override-head">
        <strong>{overrideScopeLabel(override.scope, override.scope_id)}</strong>
        <code>{describeOverrideValue(override.value)}</code>
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
          Clear this override
        </button>
      ) : (
        <Hint label={`Your roles cannot change anything set at this level.`}>
          <span className="features-lock">Set by a higher level</span>
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
  // Feature overrides are a deployment-configuration surface. The navigation
  // entry is already hidden at the customer level; this stops the direct URL
  // from fetching and painting the platform's rollout catalog into a tenant
  // console. The API remains the authorization boundary.
  const tenant = isTenantTier(current);

  const features = useQuery({
    queryKey: ["features"],
    queryFn: ({ signal }) => api.get<FeatureList>("/features", signal),
    enabled: !session.isPending && !tenant,
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
        `${request.featureName} is now ${describeOverrideValue(updated.effective_value)}, set by ${OVERRIDE_SCOPE_LABELS[
          updated.winning_scope
        ].toLowerCase()}.`,
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
        `Cleared at ${OVERRIDE_SCOPE_LABELS[request.scope].toLowerCase()}. ` +
          `${request.featureName} is now ${describeOverrideValue(updated.effective_value)}, set by ${OVERRIDE_SCOPE_LABELS[
            updated.winning_scope
          ].toLowerCase()}.`,
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
    setEditing({
      feature,
      scope: scopes.includes(feature.winning_scope)
        ? feature.winning_scope
        : (scopes[0] ?? "tenant"),
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

  if (tenant) {
    return (
      <div className="features-page">
        <WorkspaceHeader
          eyebrow="Controlled rollout"
          title="Feature overrides"
          description="Which features are switched on for your sending is decided by your provider. A customer console does not list or change them."
          scope="Set by your provider"
        />
        <div className="features-state">
          Nothing here is open to your customer. Ask your provider if a feature needs to be turned
          on for your sending.
        </div>
      </div>
    );
  }

  return (
    <div className="features-page">
      <WorkspaceHeader
        eyebrow="Controlled rollout"
        title="Feature overrides"
        description="Turn a feature on or off for a group of customers, a whole deployment, or everywhere at once. Every change needs a reason, is signed by you, and can be cleared again."
        scope={`${editableCount} of ${allRows.length} settings changeable by you`}
      />

      <ControlRail
        title="Effective configuration"
        summary="Each row shows the value in force and who set it. A row without an edit action is one your roles cannot change; the reason is written on the row."
        signals={[
          {
            label: "Settings",
            value: featuresAvailable ? allRows.length : featuresState,
            detail: featuresAvailable
              ? "Features this deployment can be configured for."
              : "The settings list has not returned yet.",
          },
          {
            label: "You can change",
            value: featuresAvailable ? editableCount : featuresState,
            detail: featuresAvailable
              ? "Settings with at least one level your roles can write."
              : "Changeable settings are counted once the list returns.",
            tone: featuresAvailable && editableCount === 0 ? "attention" : "neutral",
          },
          {
            label: "Security floors",
            value: featuresAvailable
              ? allRows.filter((row) => row.mandatory).length
              : featuresState,
            detail: featuresAvailable
              ? HINTS.securityFloor
              : "Floor counts are unavailable until the settings list returns.",
            tone: featuresAvailable ? "attention" : "neutral",
          },
          {
            label: "Emergency stops",
            value: featuresAvailable
              ? allRows.filter((row) => row.kill_switch).length
              : featuresState,
            detail: featuresAvailable ? HINTS.emergencyStop : "Not available yet.",
            tone: featuresAvailable ? "attention" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Make a reversible configuration change"
        description="A feature override is a rollout control. It cannot switch off a security floor or a platform emergency stop."
        steps={[
          {
            label: "Compare",
            detail: "Read the value in force against the default, and see which level set it.",
          },
          {
            label: "Justify",
            detail:
              "Pick the level to change at, write why, and add an expiry when it is temporary.",
          },
          {
            label: "Verify",
            detail: "After saving, the row shows the new value in force and who set it.",
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
            <Hint label={HINTS.callerTier}>
              <span className="features-lock">
                Read-only: your role cannot manage policy settings
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
          No features are available to configure in this deployment yet. Feature settings appear
          here once the platform publishes them.
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
            <caption className="sr-only">Feature settings in this deployment</caption>
            <thead>
              <tr>
                <th scope="col">Feature</th>
                <th scope="col">What it controls</th>
                <th scope="col">Default</th>
                <th scope="col">
                  <Hint label={HINTS.winningScope}>
                    <span className="hint-term">Value in force</span>
                  </Hint>
                </th>
                <th scope="col">Overrides</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((feature) => {
                const writable = editableScopes(feature);
                return (
                  <tr key={feature.feature_id}>
                    <td>
                      <FeatureName feature={feature} />
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
                    <td className="features-description">{feature.description}</td>
                    <td className="features-value">
                      {describeOverrideValue(feature.default_value)}
                    </td>
                    <td>
                      <span className="features-value">
                        {describeOverrideValue(feature.effective_value)}
                      </span>
                      <span className="features-meta">
                        set by {OVERRIDE_SCOPE_LABELS[feature.winning_scope].toLowerCase()}
                      </span>
                    </td>
                    <td>
                      {feature.overrides.length === 0 ? (
                        <span className="features-meta">Nothing set below the default</span>
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
                              ? `This setting is only changed at ${feature.allowed_scopes
                                  .map((scope) => OVERRIDE_SCOPE_LABELS[scope].toLowerCase())
                                  .join(" or ")}. Your roles can write ${
                                  sessionScopes.length === 0
                                    ? "no override level"
                                    : sessionScopes
                                        .map((scope) => OVERRIDE_SCOPE_LABELS[scope].toLowerCase())
                                        .join(" or ")
                                }.`
                              : HINTS.readOnly
                          }
                        >
                          <span className="features-lock">
                            {canManage ? "Locked at your level" : "Read-only"}
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
              Your reason and name are recorded with this change and can be read in the audit log.
              You may be asked to sign in again first.
            </p>
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
            <Select
              label="New value"
              value={editing.kind}
              options={OVERRIDE_VALUE_KINDS.map((kind) => ({
                value: kind,
                label:
                  kind === "typed"
                    ? OVERRIDE_VALUE_KIND_LABELS.typed
                    : OVERRIDE_VALUE_KIND_LABELS[kind],
                disabled: kind === "disabled" && editing.feature.mandatory,
              }))}
              onChange={(event) =>
                setEditing({ ...editing, kind: event.target.value as OverrideValueKind })
              }
            />
            {editing.kind === "inherit" ? <p className="features-hint">{HINTS.inherit}</p> : null}
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
                hint="Sent exactly as you type it. The feature decides what a valid value looks like."
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
        title={`Clear ${clearing?.feature.display_name ?? "override"}`}
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
              {HINTS.inherit} Your reason is recorded with the change.
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
                Keep the override
              </Button>
              <Button type="submit" variant="primary" loading={clearOverride.isPending}>
                Clear override
              </Button>
            </div>
          </form>
        ) : null}
      </Dialog>
    </div>
  );
}

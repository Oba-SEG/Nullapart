import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";

import { api, type ApiError } from "../api/client";
import {
  OVERRIDE_VALUE_KINDS,
  decodeOverrideValue,
  encodeOverrideValue,
  expiryError,
  expiryToRfc3339,
  overrideReasonError,
  scopesForRoles,
  type Feature,
  type FeatureList,
  type OverrideScope,
  type OverrideValueKind,
  type OverrideWriteResult,
} from "../api/policies";
import { hasPermission, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
import "./FeatureOverrides.css";

const SCOPE_LABELS: Record<OverrideScope, string> = {
  system: "System (whole deployment)",
  deployment: "Deployment",
  tenant: "Tenant (this customer)",
};

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
  scope: OverrideScope;
  value: string;
  reason: string;
  expiresAt: string | null;
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
  return "Feature data is temporarily unavailable.";
}

export function FeatureOverrides() {
  const queryClient = useQueryClient();
  const reasonInputId = useId();

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const features = useQuery({
    queryKey: ["features"],
    queryFn: ({ signal }) => api.get<FeatureList>("/features", signal),
  });

  const current = session.data ?? null;
  const roles = current?.roles ?? [];
  const canManage = hasPermission(current, "policies:manage");

  const [editing, setEditing] = useState<OverrideDraft | null>(null);
  const [showErrors, setShowErrors] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

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
        `${request.featureId} now resolves to ${updated.effective_value} at ${updated.winning_scope} scope.`,
      );
      setEditing(null);
      setShowErrors(false);
      await queryClient.invalidateQueries({ queryKey: ["features"] });
    },
  });

  function openEditor(feature: Feature) {
    const scopes = scopesForRoles(feature.allowed_scopes, roles);
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
      scope: editing.scope,
      value: encodeOverrideValue(editing.kind, editing.typed.trim()),
      reason: editing.reason.trim(),
      expiresAt: expiryToRfc3339(editing.expiresAt),
    });
  }

  const rows = features.data?.features ?? [];
  const reasonError = editing === null ? undefined : overrideReasonError(editing.reason);
  const reasonVisible =
    editing !== null && (showErrors || editing.reason.length > 0) && reasonError !== undefined;
  const expiryFailure = editing === null ? undefined : expiryError(editing.expiresAt);
  const expiryVisible =
    editing !== null && (showErrors || editing.expiresAt.length > 0) && expiryFailure !== undefined;
  const typedMissing =
    editing !== null && editing.kind === "typed" && editing.typed.trim().length === 0
      ? "Enter the typed value to store for this feature."
      : undefined;

  return (
    <div className="features-page">
      <header className="features-header">
        <div>
          <h1 className="features-title">Feature overrides</h1>
          <p className="features-subtitle">
            Feature switches are server-authoritative configuration. Overrides are scoped, audited
            and never a substitute for authorization; mandatory security floors and kill switches
            cannot be defeated from this page.
          </p>
        </div>
      </header>

      {notice ? (
        <p className="features-notice" role="status">
          {notice}
        </p>
      ) : null}

      {features.isPending ? (
        <div className="features-state" role="status">
          Loading feature switches…
        </div>
      ) : null}
      {features.isError ? (
        <div className="features-state error" role="alert">
          {errorMessage(features.error)}
          <StepUpPrompt error={features.error} />
        </div>
      ) : null}
      {features.isSuccess && rows.length === 0 ? (
        <div className="features-state">No feature switches are seeded in this deployment.</div>
      ) : null}

      {rows.length > 0 ? (
        <div className="card features-table-wrap">
          <table className="features-table">
            <caption className="sr-only">Feature switches in this deployment</caption>
            <thead>
              <tr>
                <th scope="col">Feature</th>
                <th scope="col">Description</th>
                <th scope="col">Default</th>
                <th scope="col">Effective value</th>
                <th scope="col">Overrides</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((feature) => (
                <tr key={feature.feature_id}>
                  <td>
                    <span className="features-id">{feature.feature_id}</span>
                    <span className="features-badges">
                      {feature.mandatory ? (
                        <span className="features-badge features-badge-mandatory">mandatory</span>
                      ) : null}
                      {feature.kill_switch ? (
                        <span className="features-badge features-badge-kill">kill switch</span>
                      ) : null}
                    </span>
                  </td>
                  <td className="features-description">{feature.description}</td>
                  <td className="features-value">{feature.default_value}</td>
                  <td>
                    <span className="features-value">{feature.effective_value}</span>
                    <span className="features-meta">wins at {feature.winning_scope} scope</span>
                  </td>
                  <td>{feature.overrides.length}</td>
                  <td>
                    {canManage && scopesForRoles(feature.allowed_scopes, roles).length > 0 ? (
                      <Button type="button" size="sm" onClick={() => openEditor(feature)}>
                        Edit override
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <Dialog
        open={editing !== null}
        onClose={closeEditor}
        title={`Edit override · ${editing?.feature.feature_id ?? ""}`}
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
              The override is stored for the scope you select; the scope identifier is resolved
              server-side from your session. Every change is audited.
            </p>
            <Select
              label="Scope"
              value={editing.scope}
              options={scopesForRoles(editing.feature.allowed_scopes, roles).map((scope) => ({
                value: scope,
                label: SCOPE_LABELS[scope],
              }))}
              onChange={(event) =>
                setEditing({ ...editing, scope: event.target.value as OverrideScope })
              }
            />
            <Select
              label="Override value"
              value={editing.kind}
              options={OVERRIDE_VALUE_KINDS.map((kind) => ({
                value: kind,
                label: kind,
                disabled: kind === "disabled" && editing.feature.mandatory,
              }))}
              onChange={(event) =>
                setEditing({ ...editing, kind: event.target.value as OverrideValueKind })
              }
            />
            {editing.feature.mandatory ? (
              <p className="features-hint">
                Mandatory security features cannot be disabled; only inherit, enabled or a typed
                value are accepted.
              </p>
            ) : null}
            {editing.kind === "typed" ? (
              <Input
                label="Typed value"
                value={editing.typed}
                onChange={(event) => setEditing({ ...editing, typed: event.target.value })}
                placeholder="rate_limit=10"
                maxLength={256}
                error={showErrors ? typedMissing : undefined}
                hint="Stored exactly as typed; the typed: prefix is added on save."
              />
            ) : null}
            <div className="features-field">
              <label htmlFor={reasonInputId} className="features-field-label">
                Reason
              </label>
              <textarea
                id={reasonInputId}
                className="features-textarea"
                value={editing.reason}
                onChange={(event) => setEditing({ ...editing, reason: event.target.value })}
                rows={3}
                maxLength={500}
                aria-invalid={reasonVisible}
              />
              {reasonVisible && reasonError !== undefined ? (
                <p className="features-error" role="alert">
                  {reasonError}
                </p>
              ) : null}
            </div>
            <Input
              label="Expires (optional)"
              type="datetime-local"
              value={editing.expiresAt}
              onChange={(event) => setEditing({ ...editing, expiresAt: event.target.value })}
              error={expiryVisible ? expiryFailure : undefined}
              hint="Leave empty for an override that does not expire."
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
                Cancel
              </Button>
              <Button type="submit" variant="primary" loading={saveOverride.isPending}>
                Save override
              </Button>
            </div>
          </form>
        ) : null}
      </Dialog>
    </div>
  );
}

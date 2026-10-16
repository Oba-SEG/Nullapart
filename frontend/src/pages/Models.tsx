import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BrainCircuit,
  CheckCircle2,
  GitCompareArrows,
  Power,
  RotateCcw,
  ShieldAlert,
} from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";

import { type ApiError } from "../api/client";
import {
  activateModel,
  approveModel,
  listModels,
  listShadowEvaluations,
  recordShadowEvaluation,
  registerModel,
  rejectModel,
  rollbackModel,
  type InlineModel,
  type RecordShadowEvaluationInput,
  type RegisterModelInput,
  type ShadowEvaluation,
} from "../api/models";
import { hasPermission, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { StatusPill } from "../components/StatusPill";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { ControlRail } from "../components/ControlRail";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { Hint } from "../components/primitives/Hint";
import { randomUuid } from "../lib/ids";
import { approvalStateLabel, HINTS, shadowResultLabel } from "../lib/labels";
import { notify } from "../lib/notify";
import type { StatusTone } from "../lib/status";
import "./Models.css";

interface RegisterDraft {
  model_id: string;
  model_version: string;
  input_schema_version: string;
  training_dataset_version: string;
  code_commit: string;
  artifact_uri: string;
  artifact_sha256: string;
  deployment_regions: string;
  metrics: MetricFields;
}

interface ShadowDraft {
  candidate: string;
  evaluation_set_id: string;
  input_schema_version: string;
  metrics: ShadowMetricFields;
  comparison: ShadowComparisonFields;
  result: ShadowEvaluation["result"];
}

interface MetricFields {
  macro_f1: string;
  macro_roc_auc: string;
  ham_false_positive_rate: string;
  latency_p95_ms: string;
}

interface ShadowMetricFields {
  macro_f1_delta: string;
}

interface ShadowComparisonFields {
  decision: string;
}

type MetricSpec = {
  label: string;
  key: string;
  hint: string;
};

/**
 * A score and a duration need different wording: one hint for all four fields
 * told an operator to type 0.98 into the latency box.
 */
const SCORE_HINT = "Between 0 and 1, for example 0.98.";
const LATENCY_HINT = "Whole milliseconds, for example 420.";

const REGISTER_METRIC_FIELDS: MetricSpec[] = [
  { label: "Macro F1", key: "macro_f1", hint: SCORE_HINT },
  { label: "ROC-AUC", key: "macro_roc_auc", hint: SCORE_HINT },
  {
    label: "Clean-mail false positive rate",
    key: "ham_false_positive_rate",
    hint: "Share of legitimate mail the model flagged, between 0 and 1.",
  },
  { label: "95th percentile latency (ms)", key: "latency_p95_ms", hint: LATENCY_HINT },
];

const SHADOW_METRIC_FIELDS: MetricSpec[] = [
  { label: "Macro F1 change", key: "macro_f1_delta", hint: SCORE_HINT },
];

const COMPARISON_DECISION_OPTIONS = [
  { value: "manual_review", label: "Manual review" },
  { value: "promote_candidate", label: "Promote candidate" },
  { value: "hold_active", label: "Hold active model" },
  { value: "retune_thresholds", label: "Retune thresholds" },
];

/** Exported for tests: jsdom's number input sanitizes values like "1e400" to
 * "", so the finite-value guard can only be exercised through the validator
 * the field-level error renders. */
export function metricFieldError(value: string, label: string): string | undefined {
  if (value.trim() === "") return `${label} is required.`;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return `${label} must be a finite number.`;
  return undefined;
}

function parseMetricFields(fields: MetricFields): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const spec of REGISTER_METRIC_FIELDS) {
    const raw = fields[spec.key as keyof MetricFields];
    const error = metricFieldError(raw, spec.label);
    if (error) throw new Error(error);
    out[spec.key] = Number(raw);
  }
  return out;
}

function parseShadowMetricFields(fields: ShadowMetricFields): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const spec of SHADOW_METRIC_FIELDS) {
    const raw = fields[spec.key as keyof ShadowMetricFields];
    const error = metricFieldError(raw, spec.label);
    if (error) throw new Error(error);
    out[spec.key] = Number(raw);
  }
  return out;
}

function parseShadowComparisonFields(fields: ShadowComparisonFields): Record<string, unknown> {
  const decision = fields.decision.trim();
  if (!decision) throw new Error("Decision is required.");
  if (decision.length > 64) throw new Error("Decision must be 64 characters or fewer.");
  return { decision };
}

type ModelAction =
  | { type: "approve"; model: InlineModel }
  | { type: "activate"; model: InlineModel }
  | { type: "rollback"; model: InlineModel }
  | { type: "reject"; model: InlineModel; reason: string };

const defaultRegisterDraft: RegisterDraft = {
  model_id: "",
  model_version: "",
  input_schema_version: "1",
  training_dataset_version: "",
  code_commit: "",
  artifact_uri: "",
  artifact_sha256: "",
  deployment_regions: "local",
  metrics: {
    macro_f1: "",
    macro_roc_auc: "",
    ham_false_positive_rate: "",
    latency_p95_ms: "",
  },
};

const defaultShadowDraft: ShadowDraft = {
  candidate: "",
  evaluation_set_id: "",
  input_schema_version: "1",
  metrics: { macro_f1_delta: "" },
  comparison: { decision: "manual_review" },
  result: "inconclusive",
};

function formatTimestamp(value: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

function formatShort(value: string | null, length = 12): string {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

function formatMetric(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  if (Math.abs(value) < 1) return value.toFixed(3);
  return value.toFixed(2);
}

function metricValue(model: InlineModel, keys: string[]): string {
  for (const key of keys) {
    const value = model.metrics[key];
    if (typeof value === "number") return formatMetric(value);
  }
  return "—";
}

function activationLabel(model: InlineModel): string {
  if (model.activated_at && !model.deactivated_at) return "Active";
  if (model.deactivated_at) return "Inactive";
  return "Not active";
}

function approvalTone(model: InlineModel): StatusTone {
  if (model.approval_state === "approved") return "clean";
  if (model.approval_state === "rejected") return "threat";
  return "review";
}

function activationTone(model: InlineModel): StatusTone {
  if (model.activated_at && !model.deactivated_at) return "clean";
  if (model.deactivated_at) return "muted";
  return "review";
}

function latestShadowSummary(evaluations: ShadowEvaluation[] | undefined): string {
  const latest = evaluations?.[0];
  if (!latest) return "No shadow evaluation recorded";
  const compared = latest.active_model_id
    ? ` vs ${latest.active_model_id}/${latest.active_model_version ?? "unknown"}`
    : "";
  return `${shadowResultLabel(latest.result)}${compared} · ${latest.evaluation_set_id}`;
}

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return fallback;
}

/**
 * Explains a control that is switched off. A disabled button tells an operator
 * nothing about why, so the reason rides on a tooltip and the control stays
 * visible: seeing the action is how an operator learns the card can be acted on
 * once the model reaches the right state.
 */
function Explained({ lock, children }: { lock: string; children: ReactNode }) {
  if (lock === "") return <>{children}</>;
  return <Hint label={lock}>{children}</Hint>;
}

function modelKey(model: InlineModel): string {
  return `${model.model_id}/${model.model_version}`;
}

const ACTION_COPY: Record<
  ModelAction["type"],
  { title: string; consequence: string; confirm: string }
> = {
  approve: {
    title: "Approve model",
    consequence:
      "Approval is a separate audited transition. The model still does not run until it is activated.",
    confirm: "Confirm approval",
  },
  activate: {
    title: "Activate model",
    consequence:
      "This replaces the currently active runtime model for this deployment. The superseded model is recorded as the rollback target. Requires step-up.",
    confirm: "Confirm activation",
  },
  rollback: {
    title: "Roll back to this model",
    consequence:
      "This re-activates the recorded rollback target and deactivates the current model. Requires step-up.",
    confirm: "Confirm rollback",
  },
  reject: {
    title: "Reject model",
    consequence: "Rejection is terminal for this version.",
    confirm: "Confirm rejection",
  },
};

function actionModel(request: ModelAction): InlineModel {
  return request.model;
}

export function Models() {
  const queryClient = useQueryClient();
  const [registerDraft, setRegisterDraft] = useState<RegisterDraft>(defaultRegisterDraft);
  const [shadowDraft, setShadowDraft] = useState<ShadowDraft>(defaultShadowDraft);
  const [rejectReasons, setRejectReasons] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<ModelAction | null>(null);

  function requestAction(request: ModelAction) {
    setPendingAction(request);
  }

  function cancelPendingAction() {
    setPendingAction(null);
  }

  function confirmPendingAction() {
    if (!pendingAction) return;
    action.mutate(pendingAction);
    setPendingAction(null);
  }

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const canManage = hasPermission(session.data ?? null, "models:manage");

  const models = useQuery({
    queryKey: ["models"],
    queryFn: ({ signal }) => listModels(signal),
  });

  const modelRows = useMemo(() => models.data?.models ?? [], [models.data]);
  const activeModel = modelRows.find((model) => model.activated_at && !model.deactivated_at);
  const modelsAvailable = models.isSuccess;
  const modelsState = models.isError ? "Unavailable" : "Loading";

  const shadowQueries = useQueries({
    queries: modelRows.map((model) => ({
      queryKey: ["model-shadow-evaluations", model.model_id, model.model_version],
      queryFn: ({ signal }: { signal?: AbortSignal }) =>
        listShadowEvaluations(model.model_id, model.model_version, signal),
      enabled: models.isSuccess,
      staleTime: 60_000,
    })),
  });

  const shadowByModel = new Map<string, ShadowEvaluation[]>();
  modelRows.forEach((model, index) => {
    shadowByModel.set(modelKey(model), shadowQueries[index]?.data?.evaluations ?? []);
  });

  const candidateOptions = useMemo(
    () =>
      modelRows.map((model) => ({
        value: modelKey(model),
        label: modelKey(model),
      })),
    [modelRows],
  );

  const selectedCandidate =
    modelRows.find((model) => modelKey(model) === shadowDraft.candidate) ?? modelRows[0] ?? null;

  const register = useMutation({
    mutationFn: (body: RegisterModelInput) => registerModel(body, randomUuid()),
    onSuccess: async (model) => {
      notify(`Registered ${model.model_id}/${model.model_version}. Approval is still required.`);
      setRegisterDraft(defaultRegisterDraft);
      setFormError(null);
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
  });

  const action = useMutation({
    mutationFn: async (request: ModelAction) => {
      if (request.type === "approve") {
        return approveModel(request.model.model_id, request.model.model_version, randomUuid());
      }
      if (request.type === "activate") {
        return activateModel(request.model.model_id, request.model.model_version, randomUuid());
      }
      if (request.type === "rollback") {
        return rollbackModel(request.model.model_id, request.model.model_version, randomUuid());
      }
      return rejectModel(
        request.model.model_id,
        request.model.model_version,
        request.reason,
        randomUuid(),
      );
    },
    onSuccess: async (model) => {
      notify(`Updated ${model.model_id}/${model.model_version}.`);
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
  });

  const recordShadow = useMutation({
    mutationFn: (body: { model: InlineModel; evaluation: RecordShadowEvaluationInput }) =>
      recordShadowEvaluation(
        body.model.model_id,
        body.model.model_version,
        body.evaluation,
        randomUuid(),
      ),
    onSuccess: async () => {
      notify("Shadow evaluation recorded.");
      setShadowDraft((current) => ({
        ...defaultShadowDraft,
        candidate: current.candidate,
      }));
      await queryClient.invalidateQueries({ queryKey: ["model-shadow-evaluations"] });
    },
  });

  function submitRegister() {
    try {
      const body: RegisterModelInput = {
        model_id: registerDraft.model_id.trim(),
        model_version: registerDraft.model_version.trim(),
        input_schema_version: Number.parseInt(registerDraft.input_schema_version, 10),
        training_dataset_version: registerDraft.training_dataset_version.trim(),
        code_commit: registerDraft.code_commit.trim(),
        artifact_uri: registerDraft.artifact_uri.trim(),
        artifact_sha256: registerDraft.artifact_sha256.trim(),
        deployment_regions: registerDraft.deployment_regions
          .split(",")
          .map((region) => region.trim())
          .filter(Boolean),
        metrics: parseMetricFields(registerDraft.metrics),
      };
      setFormError(null);
      register.mutate(body);
    } catch (error) {
      setFormError(errorMessage(error, "Model registration form is invalid."));
    }
  }

  function submitShadowEvaluation() {
    const model = selectedCandidate;
    if (!model) {
      setFormError("Select a candidate model before recording shadow evidence.");
      return;
    }
    try {
      const evaluation: RecordShadowEvaluationInput = {
        evaluation_set_id: shadowDraft.evaluation_set_id.trim(),
        input_schema_version: Number.parseInt(shadowDraft.input_schema_version, 10),
        active_model_id: activeModel?.model_id ?? null,
        active_model_version: activeModel?.model_version ?? null,
        metrics: parseShadowMetricFields(shadowDraft.metrics),
        comparison: parseShadowComparisonFields(shadowDraft.comparison),
        result: shadowDraft.result,
      };
      setFormError(null);
      recordShadow.mutate({ model, evaluation });
    } catch (error) {
      setFormError(errorMessage(error, "Shadow evaluation form is invalid."));
    }
  }

  function rollbackAllowed(model: InlineModel): boolean {
    return (
      activeModel?.rollback_model_id === model.model_id &&
      activeModel?.rollback_model_version === model.model_version
    );
  }

  function rejectReason(model: InlineModel): string {
    return rejectReasons[modelKey(model)] ?? "";
  }

  return (
    <div className="models-page">
      <WorkspaceHeader
        eyebrow="Model governance"
        title="Inline ML control plane"
        description="Register candidates, record shadow evidence, approve with step-up and activate exactly one runtime model. Customer trace pages never expose these internal model details."
        scope="Restricted model release controls"
        actions={
          <div className="models-runtime-chip" aria-label="Active inline ML model">
            <span>Active runtime</span>
            <strong>{activeModel ? modelKey(activeModel) : "none"}</strong>
          </div>
        }
      />

      <ControlRail
        title="Model release state"
        summary="The current runtime is visible here so candidate evidence and rollback decisions are evaluated against a concrete deployment state."
        signals={[
          {
            label: "Registered",
            value: modelsAvailable ? modelRows.length : modelsState,
            detail: modelsAvailable
              ? "Candidate and historical model artifacts in the registry."
              : "Registry state has not produced an authoritative result yet.",
          },
          {
            label: "Runtime",
            value: modelsAvailable ? (activeModel ? "One active" : "None active") : modelsState,
            detail: modelsAvailable
              ? "Exactly one model may serve at a time."
              : "Runtime model state is unavailable until the registry query succeeds.",
            tone: modelsAvailable ? (activeModel ? "healthy" : "attention") : "neutral",
          },
          {
            label: "Shadow evidence",
            value: modelsAvailable ? Array.from(shadowByModel.values()).flat().length : modelsState,
            detail: modelsAvailable
              ? "Recorded comparison evaluations across registered models."
              : "Shadow evidence is unavailable until the registry query succeeds.",
          },
        ]}
      />

      <WorkflowGuide
        title="Promote a model with evidence"
        description="The release path is intentionally constrained so an unverified artifact cannot become runtime behavior."
        steps={[
          { label: "Register", detail: "Record the candidate artifact and immutable digest." },
          {
            label: "Evaluate",
            detail: "Capture shadow evidence against the active runtime model.",
          },
          {
            label: "Approve & activate",
            detail: "Step up to promote one approved model, retaining a bounded rollback target.",
          },
        ]}
      />

      <section className="models-summary" aria-label="Inline ML operating boundaries">
        <article className="card models-boundary-card">
          <BrainCircuit size={20} aria-hidden="true" />
          <div>
            <h2>Registry-gated runtime</h2>
            <p>
              The loaded artifact must be approved, active and digest-matched before inference can
              serve.
            </p>
          </div>
        </article>
        <article className="card models-boundary-card">
          <GitCompareArrows size={20} aria-hidden="true" />
          <div>
            <h2>Shadow before rollout</h2>
            <p>Candidate versions are compared against the active model before activation.</p>
          </div>
        </article>
        <article className="card models-boundary-card">
          <RotateCcw size={20} aria-hidden="true" />
          <div>
            <h2>Audited rollback</h2>
            <p>The rollback target is constrained to the active model’s recorded predecessor.</p>
          </div>
        </article>
      </section>

      {models.isPending ? (
        <div className="card models-state" role="status">
          Loading inline ML registry…
        </div>
      ) : null}

      {models.isError ? (
        <div className="card models-state models-state-error" role="alert">
          {errorMessage(models.error, "Inline ML registry is temporarily unavailable.")}
          <StepUpPrompt error={models.error} />
        </div>
      ) : null}

      {formError ? (
        <div className="card models-state models-state-error" role="alert">
          {formError}
        </div>
      ) : null}

      {canManage ? (
        <section className="models-admin-grid" aria-label="Model administration">
          <article className="card models-admin-card">
            <div className="models-admin-head">
              <CheckCircle2 size={18} aria-hidden="true" />
              <div>
                <h2>Register candidate artifact</h2>
                <p>Registration is evidence only. Approval and activation are separate actions.</p>
              </div>
            </div>
            <div className="models-form-grid">
              <Input
                label="Model ID"
                value={registerDraft.model_id}
                onChange={(event) =>
                  setRegisterDraft((draft) => ({ ...draft, model_id: event.target.value }))
                }
              />
              <Input
                label="Version"
                value={registerDraft.model_version}
                onChange={(event) =>
                  setRegisterDraft((draft) => ({ ...draft, model_version: event.target.value }))
                }
              />
              <Input
                label="Input schema"
                type="number"
                min="1"
                value={registerDraft.input_schema_version}
                onChange={(event) =>
                  setRegisterDraft((draft) => ({
                    ...draft,
                    input_schema_version: event.target.value,
                  }))
                }
              />
              <Input
                label="Dataset version"
                value={registerDraft.training_dataset_version}
                onChange={(event) =>
                  setRegisterDraft((draft) => ({
                    ...draft,
                    training_dataset_version: event.target.value,
                  }))
                }
              />
              <Input
                label="Code commit"
                hint="Lowercase Git SHA, 7-40 hex characters"
                value={registerDraft.code_commit}
                onChange={(event) =>
                  setRegisterDraft((draft) => ({ ...draft, code_commit: event.target.value }))
                }
              />
              <Input
                label="Regions"
                hint="Comma-separated registry regions"
                value={registerDraft.deployment_regions}
                onChange={(event) =>
                  setRegisterDraft((draft) => ({
                    ...draft,
                    deployment_regions: event.target.value,
                  }))
                }
              />
            </div>
            <Input
              label="Artifact URI"
              value={registerDraft.artifact_uri}
              onChange={(event) =>
                setRegisterDraft((draft) => ({ ...draft, artifact_uri: event.target.value }))
              }
            />
            <Input
              label="Artifact SHA-256"
              value={registerDraft.artifact_sha256}
              onChange={(event) =>
                setRegisterDraft((draft) => ({ ...draft, artifact_sha256: event.target.value }))
              }
            />
            <fieldset className="models-fieldset">
              <legend>Metrics</legend>
              <div className="models-form-grid">
                {REGISTER_METRIC_FIELDS.map((field) => {
                  const raw = registerDraft.metrics[field.key as keyof MetricFields];
                  const error = raw === "" ? undefined : metricFieldError(raw, field.label);
                  return (
                    <Input
                      key={field.key}
                      label={field.label}
                      type="number"
                      step="any"
                      inputMode="decimal"
                      value={raw}
                      hint={field.hint}
                      error={error}
                      onChange={(event) =>
                        setRegisterDraft((draft) => ({
                          ...draft,
                          metrics: { ...draft.metrics, [field.key]: event.target.value },
                        }))
                      }
                    />
                  );
                })}
              </div>
            </fieldset>
            <div className="models-actions">
              <Button
                type="button"
                variant="primary"
                loading={register.isPending}
                onClick={submitRegister}
              >
                Register model
              </Button>
              {register.isError ? (
                <span className="models-error">
                  {errorMessage(register.error, "Registration failed.")}
                  <StepUpPrompt error={register.error} />
                </span>
              ) : null}
            </div>
          </article>

          <article className="card models-admin-card">
            <div className="models-admin-head">
              <GitCompareArrows size={18} aria-hidden="true" />
              <div>
                <h2>Record shadow evaluation</h2>
                <p>Attach evaluation evidence before a candidate is promoted.</p>
              </div>
            </div>
            <Select
              label="Candidate"
              value={
                shadowDraft.candidate || (selectedCandidate ? modelKey(selectedCandidate) : "")
              }
              options={candidateOptions}
              placeholder="Select candidate"
              onChange={(event) =>
                setShadowDraft((draft) => ({ ...draft, candidate: event.target.value }))
              }
              disabled={candidateOptions.length === 0}
            />
            <div className="models-form-grid">
              <Input
                label="Evaluation set"
                value={shadowDraft.evaluation_set_id}
                onChange={(event) =>
                  setShadowDraft((draft) => ({
                    ...draft,
                    evaluation_set_id: event.target.value,
                  }))
                }
              />
              <Input
                label="Input schema"
                type="number"
                min="1"
                value={shadowDraft.input_schema_version}
                onChange={(event) =>
                  setShadowDraft((draft) => ({
                    ...draft,
                    input_schema_version: event.target.value,
                  }))
                }
              />
            </div>
            <Select
              label="Result"
              value={shadowDraft.result}
              options={[
                { value: "inconclusive", label: "Inconclusive" },
                { value: "candidate_better", label: "Candidate performed better" },
                { value: "candidate_worse", label: "Candidate performed worse" },
                { value: "rollback_rehearsed", label: "Rollback rehearsed" },
              ]}
              onChange={(event) =>
                setShadowDraft((draft) => ({
                  ...draft,
                  result: event.target.value as ShadowEvaluation["result"],
                }))
              }
            />
            <fieldset className="models-fieldset">
              <legend>Shadow metrics</legend>
              <div className="models-form-grid">
                {SHADOW_METRIC_FIELDS.map((field) => {
                  const raw = shadowDraft.metrics[field.key as keyof ShadowMetricFields];
                  const error = raw === "" ? undefined : metricFieldError(raw, field.label);
                  return (
                    <Input
                      key={field.key}
                      label={field.label}
                      type="number"
                      step="any"
                      inputMode="decimal"
                      value={raw}
                      hint={field.hint}
                      error={error}
                      onChange={(event) =>
                        setShadowDraft((draft) => ({
                          ...draft,
                          metrics: { ...draft.metrics, [field.key]: event.target.value },
                        }))
                      }
                    />
                  );
                })}
              </div>
            </fieldset>
            <Select
              label="Comparison decision"
              value={shadowDraft.comparison.decision}
              options={COMPARISON_DECISION_OPTIONS}
              onChange={(event) =>
                setShadowDraft((draft) => ({
                  ...draft,
                  comparison: { ...draft.comparison, decision: event.target.value },
                }))
              }
            />
            <div className="models-actions">
              <Button
                type="button"
                variant="clean"
                loading={recordShadow.isPending}
                onClick={submitShadowEvaluation}
                disabled={!selectedCandidate}
              >
                Record shadow evidence
              </Button>
              {recordShadow.isError ? (
                <span className="models-error">
                  {errorMessage(recordShadow.error, "Shadow evaluation failed.")}
                  <StepUpPrompt error={recordShadow.error} />
                </span>
              ) : null}
            </div>
          </article>
        </section>
      ) : (
        <div className="card models-readonly-note">
          <ShieldAlert size={18} aria-hidden="true" />
          <span>
            Your roles allow you to review model evidence, not to approve, activate or roll back a
            model. Those actions need the model management permission.
          </span>
        </div>
      )}

      {models.data && modelRows.length === 0 ? (
        <div className="card models-state">No inline ML models are registered.</div>
      ) : null}

      {models.data && modelRows.length > 0 ? (
        <div className="models-list">
          {modelRows.map((model) => {
            const key = modelKey(model);
            const evaluations = shadowByModel.get(key);
            const canApprove = canManage && model.approval_state === "pending";
            const canReject = canApprove;
            const canActivate =
              canManage &&
              model.approval_state === "approved" &&
              !(model.activated_at && !model.deactivated_at);
            const canRollback = canManage && rollbackAllowed(model);
            const approveLock =
              model.approval_state === "pending"
                ? ""
                : `This model is already ${approvalStateLabel(model.approval_state).toLowerCase()}.`;
            const activateLock =
              model.approval_state !== "approved"
                ? "Only an approved model can score live mail. Approve it first."
                : model.activated_at && !model.deactivated_at
                  ? "This model is already the active one."
                  : "";
            const rollbackLock = rollbackAllowed(model)
              ? ""
              : "Rollback targets the model that was active immediately before the current one.";
            const rejectLock =
              canApprove && rejectReason(model).trim().length >= 10
                ? ""
                : canApprove
                  ? "Give a reason of at least 10 characters."
                  : approveLock || "Only a model awaiting approval can be rejected.";
            return (
              <article className="card model-card" key={model.id}>
                <div className="model-card-head">
                  <div>
                    <p className="model-eyebrow">Model</p>
                    <h2>
                      {model.model_id} <span>{model.model_version}</span>
                    </h2>
                  </div>
                  <div className="model-pills">
                    <Hint label={HINTS.modelApproval}>
                      <StatusPill
                        tone={approvalTone(model)}
                        label={approvalStateLabel(model.approval_state)}
                      />
                    </Hint>
                    <StatusPill tone={activationTone(model)} label={activationLabel(model)} />
                  </div>
                </div>

                <dl className="model-facts">
                  <dt>Input schema</dt>
                  <dd>v{model.input_schema_version}</dd>
                  <dt>Dataset</dt>
                  <dd>{model.training_dataset_version}</dd>
                  <dt>Commit</dt>
                  <dd className="model-mono">{formatShort(model.code_commit)}</dd>
                  <dt>Artifact SHA</dt>
                  <dd className="model-mono">{formatShort(model.artifact_sha256, 16)}</dd>
                  <dt>Regions</dt>
                  <dd>{model.deployment_regions.join(", ") || "—"}</dd>
                  <dt>Registered</dt>
                  <dd>{formatTimestamp(model.registered_at)}</dd>
                  <dt>Activated</dt>
                  <dd>{formatTimestamp(model.activated_at)}</dd>
                  <dt>Rollback target</dt>
                  <dd>
                    {model.rollback_model_id
                      ? `${model.rollback_model_id}/${model.rollback_model_version ?? "unknown"}`
                      : "—"}
                  </dd>
                </dl>

                <div className="model-metrics" aria-label="Model metric summary">
                  <span>
                    Macro F1 <strong>{metricValue(model, ["macro_f1", "macroF1"])}</strong>
                  </span>
                  <span>
                    ROC-AUC <strong>{metricValue(model, ["macro_roc_auc", "roc_auc"])}</strong>
                  </span>
                  <span>
                    Ham FP <strong>{metricValue(model, ["ham_false_positive_rate"])}</strong>
                  </span>
                  <span>
                    p95 ms <strong>{metricValue(model, ["latency_p95_ms", "p95_ms"])}</strong>
                  </span>
                </div>

                <div className="model-shadow" aria-label="Shadow evaluation summary">
                  <span className="model-shadow-label">Latest shadow evaluation</span>
                  <span>{latestShadowSummary(evaluations)}</span>
                </div>

                {canManage ? (
                  <div className="model-control-deck" aria-label={`Actions for ${key}`}>
                    <div className="model-primary-actions">
                      <Explained lock={approveLock}>
                        <Button
                          type="button"
                          size="sm"
                          variant="primary"
                          disabled={!canApprove}
                          loading={action.isPending}
                          onClick={() => requestAction({ type: "approve", model })}
                        >
                          Approve
                        </Button>
                      </Explained>
                      <Explained lock={activateLock}>
                        <Button
                          type="button"
                          size="sm"
                          variant="clean"
                          disabled={!canActivate}
                          loading={action.isPending}
                          onClick={() => requestAction({ type: "activate", model })}
                        >
                          <Power size={14} aria-hidden="true" />
                          Activate
                        </Button>
                      </Explained>
                      <Explained lock={rollbackLock}>
                        <Button
                          type="button"
                          size="sm"
                          variant="danger"
                          disabled={!canRollback}
                          loading={action.isPending}
                          onClick={() => requestAction({ type: "rollback", model })}
                        >
                          Roll back to this
                        </Button>
                      </Explained>
                    </div>
                    <div className="model-reject-row">
                      <Input
                        label="Reject reason"
                        value={rejectReason(model)}
                        onChange={(event) =>
                          setRejectReasons((current) => ({
                            ...current,
                            [key]: event.target.value,
                          }))
                        }
                        disabled={!canReject}
                      />
                      <Explained lock={rejectLock}>
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          disabled={!canReject || rejectReason(model).trim().length < 10}
                          loading={action.isPending}
                          onClick={() =>
                            action.mutate({
                              type: "reject",
                              model,
                              reason: rejectReason(model).trim(),
                            })
                          }
                        >
                          Reject
                        </Button>
                      </Explained>
                    </div>
                    {action.isError ? (
                      <div className="models-error" role="alert">
                        {errorMessage(action.error, "Model action failed.")}
                        <StepUpPrompt error={action.error} />
                      </div>
                    ) : null}
                  </div>
                ) : null}

                {model.deactivation_reason ? (
                  <p className="model-note">Deactivated: {model.deactivation_reason}</p>
                ) : null}
              </article>
            );
          })}
        </div>
      ) : null}

      <Dialog
        open={pendingAction !== null}
        onClose={cancelPendingAction}
        title={pendingAction ? ACTION_COPY[pendingAction.type].title : "Confirm"}
      >
        {pendingAction ? (
          <form
            className="models-confirm"
            onSubmit={(event) => {
              event.preventDefault();
              confirmPendingAction();
            }}
          >
            <p>
              {pendingAction.type === "reject" ? "Reject" : "Apply this to"}{" "}
              <strong>{modelKey(actionModel(pendingAction))}</strong>?
            </p>
            <p className="model-note">{ACTION_COPY[pendingAction.type].consequence}</p>
            <div className="models-actions">
              <Button
                type="button"
                variant="ghost"
                loading={action.isPending}
                onClick={cancelPendingAction}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant={pendingAction.type === "rollback" ? "danger" : "primary"}
                loading={action.isPending}
              >
                {ACTION_COPY[pendingAction.type].confirm}
              </Button>
            </div>
          </form>
        ) : null}
      </Dialog>
    </div>
  );
}

import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BrainCircuit,
  CheckCircle2,
  GitCompareArrows,
  Power,
  RotateCcw,
  ShieldAlert,
} from "lucide-react";
import { useMemo, useState } from "react";

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
import { Button } from "../components/primitives/Button";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
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
  metrics: string;
}

interface ShadowDraft {
  candidate: string;
  evaluation_set_id: string;
  input_schema_version: string;
  metrics: string;
  comparison: string;
  result: ShadowEvaluation["result"];
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
  metrics:
    '{\n  "macro_f1": 0,\n  "macro_roc_auc": 0,\n  "ham_false_positive_rate": 0,\n  "latency_p95_ms": 0\n}',
};

const defaultShadowDraft: ShadowDraft = {
  candidate: "",
  evaluation_set_id: "",
  input_schema_version: "1",
  metrics: '{\n  "macro_f1_delta": 0\n}',
  comparison: '{\n  "decision": "manual_review"\n}',
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
  if (model.activated_at && !model.deactivated_at) return "active";
  if (model.deactivated_at) return "inactive";
  return "not active";
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
  return `${latest.result.replaceAll("_", " ")}${compared} · ${latest.evaluation_set_id}`;
}

function parseJsonObject(value: string, label: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  if (Object.keys(parsed).length === 0) {
    throw new Error(`${label} cannot be empty.`);
  }
  return parsed as Record<string, unknown>;
}

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return fallback;
}

function modelKey(model: InlineModel): string {
  return `${model.model_id}/${model.model_version}`;
}

export function Models() {
  const queryClient = useQueryClient();
  const [registerDraft, setRegisterDraft] = useState<RegisterDraft>(defaultRegisterDraft);
  const [shadowDraft, setShadowDraft] = useState<ShadowDraft>(defaultShadowDraft);
  const [rejectReasons, setRejectReasons] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);

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
        metrics: parseJsonObject(registerDraft.metrics, "Metrics"),
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
        metrics: parseJsonObject(shadowDraft.metrics, "Shadow metrics"),
        comparison: parseJsonObject(shadowDraft.comparison, "Shadow comparison"),
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
      <header className="page-header models-command-header">
        <div>
          <h1 className="page-title">Inline ML control plane</h1>
          <p className="page-subtitle">
            Register candidate artifacts, record shadow evidence, approve with step-up, activate the
            one runtime model and rehearse rollback. Customer trace pages still hide these internal
            model details.
          </p>
        </div>
        <div className="models-runtime-chip" aria-label="Active inline ML model">
          <span>Active runtime</span>
          <strong>{activeModel ? modelKey(activeModel) : "none"}</strong>
        </div>
      </header>

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
            <label className="models-textarea-label" htmlFor="model-metrics-json">
              Metrics JSON
            </label>
            <textarea
              id="model-metrics-json"
              className="models-textarea"
              value={registerDraft.metrics}
              onChange={(event) =>
                setRegisterDraft((draft) => ({ ...draft, metrics: event.target.value }))
              }
              rows={7}
            />
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
                { value: "candidate_better", label: "Candidate better" },
                { value: "candidate_worse", label: "Candidate worse" },
                { value: "rollback_rehearsed", label: "Rollback rehearsed" },
              ]}
              onChange={(event) =>
                setShadowDraft((draft) => ({
                  ...draft,
                  result: event.target.value as ShadowEvaluation["result"],
                }))
              }
            />
            <label className="models-textarea-label" htmlFor="shadow-metrics-json">
              Shadow metrics JSON
            </label>
            <textarea
              id="shadow-metrics-json"
              className="models-textarea"
              value={shadowDraft.metrics}
              onChange={(event) =>
                setShadowDraft((draft) => ({ ...draft, metrics: event.target.value }))
              }
              rows={5}
            />
            <label className="models-textarea-label" htmlFor="shadow-comparison-json">
              Comparison JSON
            </label>
            <textarea
              id="shadow-comparison-json"
              className="models-textarea"
              value={shadowDraft.comparison}
              onChange={(event) =>
                setShadowDraft((draft) => ({ ...draft, comparison: event.target.value }))
              }
              rows={5}
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
          <span>Your session can view model evidence but cannot change runtime state.</span>
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
                    <StatusPill
                      tone={approvalTone(model)}
                      label={model.approval_state.replaceAll("_", " ")}
                    />
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
                      <Button
                        type="button"
                        size="sm"
                        variant="primary"
                        disabled={!canApprove}
                        loading={action.isPending}
                        onClick={() => action.mutate({ type: "approve", model })}
                      >
                        Approve
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="clean"
                        disabled={!canActivate}
                        loading={action.isPending}
                        onClick={() => action.mutate({ type: "activate", model })}
                      >
                        <Power size={14} aria-hidden="true" />
                        Activate
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="danger"
                        disabled={!canRollback}
                        loading={action.isPending}
                        onClick={() => action.mutate({ type: "rollback", model })}
                      >
                        Roll back to this
                      </Button>
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
    </div>
  );
}

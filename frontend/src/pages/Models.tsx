import { useQueries, useQuery } from "@tanstack/react-query";
import { BrainCircuit, GitCompareArrows, RotateCcw } from "lucide-react";

import {
  listModels,
  listShadowEvaluations,
  type InlineModel,
  type ShadowEvaluation,
} from "../api/models";
import { StatusPill } from "../components/StatusPill";
import type { StatusTone } from "../lib/status";
import "./Models.css";

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

export function Models() {
  const models = useQuery({
    queryKey: ["models"],
    queryFn: ({ signal }) => listModels(signal),
  });

  const shadowQueries = useQueries({
    queries: (models.data?.models ?? []).map((model) => ({
      queryKey: ["model-shadow-evaluations", model.model_id, model.model_version],
      queryFn: ({ signal }: { signal?: AbortSignal }) =>
        listShadowEvaluations(model.model_id, model.model_version, signal),
      enabled: models.isSuccess,
      staleTime: 60_000,
    })),
  });

  const shadowByModel = new Map<string, ShadowEvaluation[]>();
  (models.data?.models ?? []).forEach((model, index) => {
    shadowByModel.set(
      `${model.model_id}/${model.model_version}`,
      shadowQueries[index]?.data?.evaluations ?? [],
    );
  });

  return (
    <div className="models-page">
      <header className="page-header">
        <div>
          <h1 className="page-title">Inline ML models</h1>
          <p className="page-subtitle">
            System diagnostics for model approval, activation, shadow evaluation and rollback
            readiness. Customer trace pages keep product-level threat analysis separate from these
            internal details.
          </p>
        </div>
      </header>

      <section className="models-summary" aria-label="Inline ML operating boundaries">
        <article className="card models-boundary-card">
          <BrainCircuit size={20} aria-hidden="true" />
          <div>
            <h2>Evidence only</h2>
            <p>
              Inline ML contributes bounded security evidence. Policy remains the only disposition
              engine.
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
            <h2>Rollback recorded</h2>
            <p>Active versions retain an approved rollback target when one exists.</p>
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
          Inline ML registry is temporarily unavailable.
        </div>
      ) : null}

      {models.data && models.data.models.length === 0 ? (
        <div className="card models-state">No inline ML models are registered.</div>
      ) : null}

      {models.data && models.data.models.length > 0 ? (
        <div className="models-list">
          {models.data.models.map((model) => {
            const key = `${model.model_id}/${model.model_version}`;
            const evaluations = shadowByModel.get(key);
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

import { api } from "./client";

export interface InlineModel {
  id: string;
  model_id: string;
  model_version: string;
  input_schema_version: number;
  training_dataset_version: string;
  code_commit: string;
  metrics: Record<string, unknown>;
  artifact_uri: string;
  artifact_sha256: string;
  deployment_regions: string[];
  approval_state: "pending" | "approved" | "rejected";
  approved_by: string | null;
  /** Whose decision this was, in the words an operator reads. Present whenever
   * the matching `*_by` reference is: the server resolves the stored identity id
   * and falls back to that id when no display name exists. */
  approved_by_name: string | null;
  approved_at: string | null;
  approval_note: string | null;
  activated_at: string | null;
  activated_by: string | null;
  activated_by_name: string | null;
  deactivated_at: string | null;
  deactivated_by: string | null;
  deactivated_by_name: string | null;
  deactivation_reason: string | null;
  rollback_model_id: string | null;
  rollback_model_version: string | null;
  registered_by: string;
  registered_by_name: string;
  registered_at: string;
  updated_at: string;
}

export interface InlineModelList {
  models: InlineModel[];
}

export interface ShadowEvaluation {
  id: string;
  candidate_model_id: string;
  candidate_model_version: string;
  active_model_id: string | null;
  active_model_version: string | null;
  input_schema_version: number;
  evaluation_set_id: string;
  metrics: Record<string, unknown>;
  comparison: Record<string, unknown>;
  result: "candidate_better" | "candidate_worse" | "inconclusive" | "rollback_rehearsed";
  created_by: string;
  created_at: string;
}

export interface ShadowEvaluationList {
  evaluations: ShadowEvaluation[];
}

export interface RegisterModelInput {
  model_id: string;
  model_version: string;
  input_schema_version: number;
  training_dataset_version: string;
  code_commit: string;
  metrics: Record<string, unknown>;
  artifact_uri: string;
  artifact_sha256: string;
  deployment_regions: string[];
}

export interface RecordShadowEvaluationInput {
  evaluation_set_id: string;
  active_model_id: string | null;
  active_model_version: string | null;
  input_schema_version: number;
  metrics: Record<string, unknown>;
  comparison: Record<string, unknown>;
  result: ShadowEvaluation["result"];
}

export function listModels(signal?: AbortSignal): Promise<InlineModelList> {
  return api.get<InlineModelList>("/admin/models", signal);
}

export function listShadowEvaluations(
  modelId: string,
  modelVersion: string,
  signal?: AbortSignal,
): Promise<ShadowEvaluationList> {
  return api.get<ShadowEvaluationList>(
    `/admin/models/${encodeURIComponent(modelId)}/${encodeURIComponent(
      modelVersion,
    )}/shadow-evaluations`,
    signal,
  );
}

export function registerModel(
  body: RegisterModelInput,
  idempotencyKey: string,
): Promise<InlineModel> {
  return api.post<InlineModel>("/admin/models", body, { idempotencyKey });
}

export function approveModel(
  modelId: string,
  modelVersion: string,
  idempotencyKey: string,
): Promise<InlineModel> {
  return api.post<InlineModel>(
    `/admin/models/${encodeURIComponent(modelId)}/${encodeURIComponent(modelVersion)}/approve`,
    undefined,
    { idempotencyKey },
  );
}

export function rejectModel(
  modelId: string,
  modelVersion: string,
  reason: string,
  idempotencyKey: string,
): Promise<InlineModel> {
  return api.post<InlineModel>(
    `/admin/models/${encodeURIComponent(modelId)}/${encodeURIComponent(modelVersion)}/reject`,
    { reason },
    { idempotencyKey },
  );
}

export function activateModel(
  modelId: string,
  modelVersion: string,
  idempotencyKey: string,
): Promise<InlineModel> {
  return api.post<InlineModel>(
    `/admin/models/${encodeURIComponent(modelId)}/${encodeURIComponent(modelVersion)}/activate`,
    undefined,
    { idempotencyKey },
  );
}

export function rollbackModel(
  modelId: string,
  modelVersion: string,
  idempotencyKey: string,
): Promise<InlineModel> {
  return api.post<InlineModel>(
    `/admin/models/${encodeURIComponent(modelId)}/${encodeURIComponent(modelVersion)}/rollback`,
    undefined,
    { idempotencyKey },
  );
}

export function recordShadowEvaluation(
  modelId: string,
  modelVersion: string,
  body: RecordShadowEvaluationInput,
  idempotencyKey: string,
): Promise<ShadowEvaluation> {
  return api.post<ShadowEvaluation>(
    `/admin/models/${encodeURIComponent(modelId)}/${encodeURIComponent(
      modelVersion,
    )}/shadow-evaluations`,
    body,
    { idempotencyKey },
  );
}

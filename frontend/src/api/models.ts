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
  approved_at: string | null;
  approval_note: string | null;
  activated_at: string | null;
  activated_by: string | null;
  deactivated_at: string | null;
  deactivated_by: string | null;
  deactivation_reason: string | null;
  rollback_model_id: string | null;
  rollback_model_version: string | null;
  registered_by: string;
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

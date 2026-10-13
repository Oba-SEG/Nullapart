//! Phase 7 regional Deep AI control plane slice.
//!
//! This module intentionally wires governance and access controls before any
//! autonomous model behaviour: skills are versioned, artifact access is scoped
//! and short lived, output is schema/provenance validated, and model results
//! never execute actions.

use axum::{
    extract::{rejection::JsonRejection, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use nullapart_mail_contracts::transaction::DeploymentId;
use nullapart_policy::{CustomerLifecycle, TenantContext};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::admin_audit::{source_ip_from, AuditEventRecord, PostgresAuditStore};
use crate::idempotency::{claim, complete, ClaimOutcome};
use crate::policy_admin::set_scope;

pub const DEEP_AI_VIEW_PERMISSION: &str = "deep-ai:view";
pub const DEEP_AI_MANAGE_PERMISSION: &str = "deep-ai:manage";

const DEEP_AI_PATH: &str = "/api/v1/deep-ai";
const DEEP_AI_GRANTS_PATH: &str = "/api/v1/deep-ai/artifact-grants";
const DEEP_AI_RESULTS_PATH: &str = "/api/v1/deep-ai/analysis-results";
const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const GRANT_OPERATION: &str = "deep-ai-artifact-grant";
const RESULT_OPERATION: &str = "deep-ai-analysis-result";
const AUDIT_RESOURCE_GRANT: &str = "deep_ai_artifact_grant";
const AUDIT_RESOURCE_RESULT: &str = "deep_ai_analysis_result";

#[derive(Clone)]
pub struct DeepAiState {
    pool: PgPool,
    deployment_id: DeploymentId,
}

impl DeepAiState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self {
            pool,
            deployment_id,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiEnvelope<T> {
    data: T,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct DeepAiResponse {
    deployment_id: String,
    generated_at: DateTime<Utc>,
    summary: DeepAiSummary,
    skills: Vec<DeepAiSkillView>,
    model_releases: Vec<DeepAiModelReleaseView>,
    regional_benchmarks: Vec<DeepAiBenchmarkView>,
    artifact_grants: Vec<DeepAiArtifactGrantView>,
    analysis_results: Vec<DeepAiAnalysisResultView>,
    training_datasets: Vec<DeepAiTrainingDatasetView>,
}

#[derive(Debug, Default, Serialize)]
struct DeepAiSummary {
    released_skills: i64,
    approved_model_releases: i64,
    approved_regional_benchmarks: i64,
    active_artifact_grants: i64,
    valid_results_24h: i64,
    invalid_or_error_results_24h: i64,
    approved_training_datasets: i64,
}

#[derive(Debug, Serialize)]
struct DeepAiSkillView {
    skill_id: String,
    skill_version: String,
    owner: String,
    purpose: String,
    allowed_data_classes: Vec<String>,
    allowed_tools: Vec<String>,
    max_input_tokens: i32,
    max_output_tokens: i32,
    max_artifacts: i32,
    timeout_ms: i32,
    concurrency_limit: i32,
    model_requirement: String,
    prompt_template_version: String,
    input_schema_version: String,
    output_schema_version: String,
    evaluation_suite_version: String,
    release_state: String,
    rollback_skill_version: Option<String>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct DeepAiModelReleaseView {
    region: String,
    model_release: String,
    backend: String,
    serving_contract: String,
    quantization: String,
    context_window: i32,
    approval_state: String,
    rollback_to_model_release: Option<String>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct DeepAiBenchmarkView {
    region: String,
    model_release: String,
    accelerator_family: String,
    quantization: String,
    vram_gb: f64,
    gpu_count: i32,
    topology: String,
    model_load_seconds: f64,
    tokens_per_second: f64,
    concurrent_requests: i32,
    context_target_tokens: i32,
    multimodal_supported: bool,
    availability_notes: String,
    failover_notes: String,
    cost_per_case_estimate: f64,
    approved: bool,
    approval_note: String,
    measured_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct DeepAiArtifactGrantView {
    id: Uuid,
    tenant_message_id: Option<Uuid>,
    artifact_id: Uuid,
    resource_type: String,
    purpose: String,
    skill_id: String,
    skill_version: String,
    artifact_type: String,
    expires_at: DateTime<Utc>,
    created_by: String,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct DeepAiAnalysisResultView {
    id: Uuid,
    skill_id: String,
    skill_version: String,
    model_release: String,
    artifact_grant_id: Uuid,
    classification: String,
    attack_type: String,
    severity: String,
    confidence: f64,
    impersonated_entity: Option<String>,
    evidence_references: Value,
    recommended_action: String,
    analyst_summary: String,
    processing_duration_ms: i64,
    validation_state: String,
    error_code: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct DeepAiTrainingDatasetView {
    dataset_version: String,
    region: String,
    allowed_data_classes: Vec<String>,
    provenance: String,
    labeling_process: String,
    approval_state: String,
    deletion_withdrawal_process: String,
    evaluation_split_protected: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct CreateGrantRequest {
    tenant_message_id: Option<Uuid>,
    artifact_id: Uuid,
    resource_type: String,
    purpose: String,
    skill_id: String,
    skill_version: String,
    artifact_type: String,
    ttl_minutes: i64,
}

#[derive(Debug, Serialize)]
struct CreateGrantResponse {
    id: Uuid,
    expires_at: DateTime<Utc>,
    artifact_id: Uuid,
    skill_id: String,
    skill_version: String,
    purpose: String,
    created: bool,
}

#[derive(Debug, Deserialize)]
struct RecordResultRequest {
    artifact_grant_id: Uuid,
    skill_id: String,
    skill_version: String,
    model_release: String,
    classification: String,
    attack_type: String,
    severity: String,
    confidence: f64,
    impersonated_entity: Option<String>,
    evidence_references: Value,
    observations: Value,
    recommended_action: String,
    analyst_summary: String,
    processing_duration_ms: i64,
}

#[derive(Debug, Serialize)]
struct RecordResultResponse {
    id: Uuid,
    classification: String,
    severity: String,
    validation_state: &'static str,
    created: bool,
}

struct ValidatedGrantRequest {
    tenant_message_id: Option<Uuid>,
    artifact_id: Uuid,
    resource_type: String,
    purpose: String,
    skill_id: String,
    skill_version: String,
    artifact_type: String,
    expires_at: DateTime<Utc>,
}

struct ValidatedResultRequest {
    artifact_grant_id: Uuid,
    skill_id: String,
    skill_version: String,
    model_release: String,
    classification: String,
    attack_type: String,
    severity: String,
    confidence: f64,
    impersonated_entity: Option<String>,
    evidence_references: Value,
    observations: Value,
    recommended_action: String,
    analyst_summary: String,
    processing_duration_ms: i64,
}

struct GrantRecord {
    id: Uuid,
    customer_id: String,
    skill_id: String,
    skill_version: String,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

struct DeepAiAudit<'a> {
    action: &'a str,
    resource_type: &'a str,
    resource_id: Option<String>,
    details: Value,
}

enum IdempotencyRejection {
    Missing,
    Invalid,
}

pub fn deep_ai_router(state: DeepAiState) -> Router {
    Router::new()
        .route(DEEP_AI_PATH, get(get_deep_ai))
        .route(DEEP_AI_GRANTS_PATH, post(post_artifact_grant))
        .route(DEEP_AI_RESULTS_PATH, post(post_analysis_result))
        .with_state(state)
}

async fn get_deep_ai(
    State(state): State<DeepAiState>,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !authorized(&state, &context, DEEP_AI_VIEW_PERMISSION) {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }

    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if set_scope(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    .is_err()
    {
        return unavailable();
    }

    let response = match load_deep_ai_response(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    (StatusCode::OK, Json(ApiEnvelope { data: response })).into_response()
}

async fn post_artifact_grant(
    State(state): State<DeepAiState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<CreateGrantRequest>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !authorized(&state, &context, DEEP_AI_MANAGE_PERMISSION) {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => return invalid_request(),
    };
    let request = match validate_grant_request(request) {
        Ok(request) => request,
        Err(_) => return invalid_request(),
    };
    let idempotency_key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };

    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if set_scope(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    .is_err()
    {
        return unavailable();
    }
    match claim(&mut transaction, &idempotency_key, GRANT_OPERATION).await {
        Ok(ClaimOutcome::Fresh) => {},
        Ok(ClaimOutcome::Replay(value)) => return replay_response(value),
        Ok(ClaimOutcome::InProgress) => return conflict("A matching request is still in progress"),
        Ok(ClaimOutcome::OperationMismatch) => {
            return conflict("Idempotency key operation mismatch")
        },
        Err(_) => return unavailable(),
    }

    if ensure_skill_released(
        &mut transaction,
        &state.deployment_id.0,
        &request.skill_id,
        &request.skill_version,
    )
    .await
    .is_err()
    {
        return invalid_request();
    }
    if ensure_artifact_eligible(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
        &request,
    )
    .await
    .is_err()
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "ARTIFACT_NOT_ELIGIBLE",
            "Artifact is not eligible for Deep AI access",
        );
    }

    let response = match insert_artifact_grant(
        &mut transaction,
        &state.deployment_id.0,
        &context,
        &headers,
        &request,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(envelope) = envelope(&response) else {
        return unavailable();
    };
    if complete(
        &mut transaction,
        &idempotency_key,
        GRANT_OPERATION,
        envelope,
    )
    .await
    .is_err()
    {
        return unavailable();
    }
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    (StatusCode::CREATED, Json(ApiEnvelope { data: response })).into_response()
}

async fn post_analysis_result(
    State(state): State<DeepAiState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<RecordResultRequest>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !authorized(&state, &context, DEEP_AI_MANAGE_PERMISSION) {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => return invalid_request(),
    };
    let request = match validate_result_request(request) {
        Ok(request) => request,
        Err(_) => return invalid_request(),
    };
    let idempotency_key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };

    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if set_scope(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    .is_err()
    {
        return unavailable();
    }
    match claim(&mut transaction, &idempotency_key, RESULT_OPERATION).await {
        Ok(ClaimOutcome::Fresh) => {},
        Ok(ClaimOutcome::Replay(value)) => return replay_response(value),
        Ok(ClaimOutcome::InProgress) => return conflict("A matching request is still in progress"),
        Ok(ClaimOutcome::OperationMismatch) => {
            return conflict("Idempotency key operation mismatch")
        },
        Err(_) => return unavailable(),
    }

    let grant = match load_grant_for_result(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
        request.artifact_grant_id,
    )
    .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    if grant.skill_id != request.skill_id
        || grant.skill_version != request.skill_version
        || grant.revoked_at.is_some()
        || grant.expires_at <= Utc::now()
    {
        return invalid_request();
    }
    if structured_output_is_valid(&request, &grant).is_err() {
        return invalid_request();
    }
    let response = match insert_analysis_result(
        &mut transaction,
        &state.deployment_id.0,
        &grant.customer_id,
        &context,
        &headers,
        &request,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(envelope) = envelope(&response) else {
        return unavailable();
    };
    if complete(
        &mut transaction,
        &idempotency_key,
        RESULT_OPERATION,
        envelope,
    )
    .await
    .is_err()
    {
        return unavailable();
    }
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    (StatusCode::CREATED, Json(ApiEnvelope { data: response })).into_response()
}

async fn load_deep_ai_response(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<DeepAiResponse, Response> {
    Ok(DeepAiResponse {
        deployment_id: deployment_id.to_string(),
        generated_at: Utc::now(),
        summary: load_summary(transaction, deployment_id, customer_id).await?,
        skills: load_skills(transaction, deployment_id).await?,
        model_releases: load_model_releases(transaction, deployment_id).await?,
        regional_benchmarks: load_benchmarks(transaction, deployment_id).await?,
        artifact_grants: load_artifact_grants(transaction, deployment_id, customer_id).await?,
        analysis_results: load_analysis_results(transaction, deployment_id, customer_id).await?,
        training_datasets: load_training_datasets(transaction, deployment_id).await?,
    })
}

async fn load_summary(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<DeepAiSummary, Response> {
    sqlx::query(
        "SELECT \
            (SELECT count(*) FROM deep_ai_skills WHERE deployment_id = $1 AND release_state = 'released')::bigint AS released_skills, \
            (SELECT count(*) FROM deep_ai_model_releases WHERE deployment_id = $1 AND approval_state = 'approved')::bigint AS approved_model_releases, \
            (SELECT count(*) FROM deep_ai_regional_benchmarks WHERE deployment_id = $1 AND approved = true)::bigint AS approved_regional_benchmarks, \
            (SELECT count(*) FROM deep_ai_artifact_access_grants WHERE deployment_id = $1 AND customer_id = $2 \
                AND revoked_at IS NULL AND expires_at > now())::bigint AS active_artifact_grants, \
            (SELECT count(*) FROM deep_ai_analysis_results WHERE deployment_id = $1 AND customer_id = $2 \
                AND validation_state = 'valid' AND created_at >= now() - interval '24 hours')::bigint AS valid_results_24h, \
            (SELECT count(*) FROM deep_ai_analysis_results WHERE deployment_id = $1 AND customer_id = $2 \
                AND validation_state <> 'valid' AND created_at >= now() - interval '24 hours')::bigint AS invalid_or_error_results_24h, \
            (SELECT count(*) FROM deep_ai_training_datasets WHERE deployment_id = $1 AND approval_state = 'approved')::bigint AS approved_training_datasets",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_one(&mut **transaction)
    .await
    .map(|row| DeepAiSummary {
        released_skills: row.get("released_skills"),
        approved_model_releases: row.get("approved_model_releases"),
        approved_regional_benchmarks: row.get("approved_regional_benchmarks"),
        active_artifact_grants: row.get("active_artifact_grants"),
        valid_results_24h: row.get("valid_results_24h"),
        invalid_or_error_results_24h: row.get("invalid_or_error_results_24h"),
        approved_training_datasets: row.get("approved_training_datasets"),
    })
    .map_err(|_| unavailable())
}

async fn load_skills(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
) -> Result<Vec<DeepAiSkillView>, Response> {
    sqlx::query(
        "SELECT skill_id, skill_version, owner, purpose, allowed_data_classes, allowed_tools, \
                max_input_tokens, max_output_tokens, max_artifacts, timeout_ms, concurrency_limit, \
                model_requirement, prompt_template_version, input_schema_version, output_schema_version, \
                evaluation_suite_version, release_state, rollback_skill_version, updated_at \
         FROM deep_ai_skills WHERE deployment_id = $1 \
         ORDER BY skill_id, skill_version",
    )
    .bind(deployment_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| DeepAiSkillView {
                skill_id: row.get("skill_id"),
                skill_version: row.get("skill_version"),
                owner: row.get("owner"),
                purpose: row.get("purpose"),
                allowed_data_classes: row.get("allowed_data_classes"),
                allowed_tools: row.get("allowed_tools"),
                max_input_tokens: row.get("max_input_tokens"),
                max_output_tokens: row.get("max_output_tokens"),
                max_artifacts: row.get("max_artifacts"),
                timeout_ms: row.get("timeout_ms"),
                concurrency_limit: row.get("concurrency_limit"),
                model_requirement: row.get("model_requirement"),
                prompt_template_version: row.get("prompt_template_version"),
                input_schema_version: row.get("input_schema_version"),
                output_schema_version: row.get("output_schema_version"),
                evaluation_suite_version: row.get("evaluation_suite_version"),
                release_state: row.get("release_state"),
                rollback_skill_version: row.get("rollback_skill_version"),
                updated_at: row.get("updated_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_model_releases(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
) -> Result<Vec<DeepAiModelReleaseView>, Response> {
    sqlx::query(
        "SELECT region, model_release, backend, serving_contract, quantization, context_window, \
                approval_state, rollback_to_model_release, updated_at \
         FROM deep_ai_model_releases WHERE deployment_id = $1 \
         ORDER BY region, model_release",
    )
    .bind(deployment_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| DeepAiModelReleaseView {
                region: row.get("region"),
                model_release: row.get("model_release"),
                backend: row.get("backend"),
                serving_contract: row.get("serving_contract"),
                quantization: row.get("quantization"),
                context_window: row.get("context_window"),
                approval_state: row.get("approval_state"),
                rollback_to_model_release: row.get("rollback_to_model_release"),
                updated_at: row.get("updated_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_benchmarks(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
) -> Result<Vec<DeepAiBenchmarkView>, Response> {
    sqlx::query(
        "SELECT region, model_release, accelerator_family, quantization, vram_gb::float8 AS vram_gb, \
                gpu_count, topology, model_load_seconds::float8 AS model_load_seconds, \
                tokens_per_second::float8 AS tokens_per_second, concurrent_requests, \
                context_target_tokens, multimodal_supported, availability_notes, failover_notes, \
                cost_per_case_estimate::float8 AS cost_per_case_estimate, approved, approval_note, measured_at \
         FROM deep_ai_regional_benchmarks WHERE deployment_id = $1 \
         ORDER BY approved DESC, measured_at DESC LIMIT 25",
    )
    .bind(deployment_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| DeepAiBenchmarkView {
                region: row.get("region"),
                model_release: row.get("model_release"),
                accelerator_family: row.get("accelerator_family"),
                quantization: row.get("quantization"),
                vram_gb: row.get("vram_gb"),
                gpu_count: row.get("gpu_count"),
                topology: row.get("topology"),
                model_load_seconds: row.get("model_load_seconds"),
                tokens_per_second: row.get("tokens_per_second"),
                concurrent_requests: row.get("concurrent_requests"),
                context_target_tokens: row.get("context_target_tokens"),
                multimodal_supported: row.get("multimodal_supported"),
                availability_notes: row.get("availability_notes"),
                failover_notes: row.get("failover_notes"),
                cost_per_case_estimate: row.get("cost_per_case_estimate"),
                approved: row.get("approved"),
                approval_note: row.get("approval_note"),
                measured_at: row.get("measured_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_artifact_grants(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<DeepAiArtifactGrantView>, Response> {
    sqlx::query(
        "SELECT id, tenant_message_id, artifact_id, resource_type, purpose, skill_id, skill_version, \
                artifact_type, expires_at, created_by, created_at, revoked_at \
         FROM deep_ai_artifact_access_grants \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY created_at DESC LIMIT 50",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| DeepAiArtifactGrantView {
                id: row.get("id"),
                tenant_message_id: row.get("tenant_message_id"),
                artifact_id: row.get("artifact_id"),
                resource_type: row.get("resource_type"),
                purpose: row.get("purpose"),
                skill_id: row.get("skill_id"),
                skill_version: row.get("skill_version"),
                artifact_type: row.get("artifact_type"),
                expires_at: row.get("expires_at"),
                created_by: row.get("created_by"),
                created_at: row.get("created_at"),
                revoked_at: row.get("revoked_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_analysis_results(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<DeepAiAnalysisResultView>, Response> {
    sqlx::query(
        "SELECT id, skill_id, skill_version, model_release, artifact_grant_id, classification, \
                attack_type, severity, confidence::float8 AS confidence, impersonated_entity, \
                evidence_references, recommended_action, analyst_summary, processing_duration_ms, \
                validation_state, error_code, created_at \
         FROM deep_ai_analysis_results \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY created_at DESC LIMIT 50",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| DeepAiAnalysisResultView {
                id: row.get("id"),
                skill_id: row.get("skill_id"),
                skill_version: row.get("skill_version"),
                model_release: row.get("model_release"),
                artifact_grant_id: row.get("artifact_grant_id"),
                classification: row.get("classification"),
                attack_type: row.get("attack_type"),
                severity: row.get("severity"),
                confidence: row.get("confidence"),
                impersonated_entity: row.get("impersonated_entity"),
                evidence_references: row.get("evidence_references"),
                recommended_action: row.get("recommended_action"),
                analyst_summary: row.get("analyst_summary"),
                processing_duration_ms: row.get("processing_duration_ms"),
                validation_state: row.get("validation_state"),
                error_code: row.get("error_code"),
                created_at: row.get("created_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_training_datasets(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
) -> Result<Vec<DeepAiTrainingDatasetView>, Response> {
    sqlx::query(
        "SELECT dataset_version, region, allowed_data_classes, provenance, labeling_process, \
                approval_state, deletion_withdrawal_process, evaluation_split_protected, created_at \
         FROM deep_ai_training_datasets WHERE deployment_id = $1 \
         ORDER BY created_at DESC LIMIT 25",
    )
    .bind(deployment_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| DeepAiTrainingDatasetView {
                dataset_version: row.get("dataset_version"),
                region: row.get("region"),
                allowed_data_classes: row.get("allowed_data_classes"),
                provenance: row.get("provenance"),
                labeling_process: row.get("labeling_process"),
                approval_state: row.get("approval_state"),
                deletion_withdrawal_process: row.get("deletion_withdrawal_process"),
                evaluation_split_protected: row.get("evaluation_split_protected"),
                created_at: row.get("created_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn ensure_skill_released(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    skill_id: &str,
    skill_version: &str,
) -> Result<(), ()> {
    let released = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
            SELECT 1 FROM deep_ai_skills \
            WHERE deployment_id = $1 AND skill_id = $2 AND skill_version = $3 \
              AND release_state = 'released' \
         )",
    )
    .bind(deployment_id)
    .bind(skill_id)
    .bind(skill_version)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ())?;
    released.then_some(()).ok_or(())
}

async fn ensure_artifact_eligible(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    request: &ValidatedGrantRequest,
) -> Result<(), ()> {
    if request.resource_type == "quarantine_case" {
        let Some(tenant_message_id) = request.tenant_message_id else {
            return Err(());
        };
        let eligible = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                SELECT 1 FROM quarantine_cases \
                WHERE deployment_id = $1 AND customer_id = $2 AND tenant_message_id = $3 \
                  AND artifact_id = $4 AND released_at IS NULL \
            )",
        )
        .bind(deployment_id)
        .bind(customer_id)
        .bind(tenant_message_id)
        .bind(request.artifact_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| ())?;
        return eligible.then_some(()).ok_or(());
    }
    let eligible = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
            SELECT 1 FROM artifacts \
            WHERE deployment_id = $1 AND customer_id = $2 AND id = $3 \
        )",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(request.artifact_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ())?;
    eligible.then_some(()).ok_or(())
}

async fn insert_artifact_grant(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    context: &TenantContext,
    headers: &HeaderMap,
    request: &ValidatedGrantRequest,
) -> Result<CreateGrantResponse, Response> {
    let row = sqlx::query(
        "INSERT INTO deep_ai_artifact_access_grants \
            (deployment_id, customer_id, tenant_message_id, artifact_id, resource_type, purpose, \
             skill_id, skill_version, artifact_type, expires_at, created_by, trace_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
         RETURNING id, expires_at",
    )
    .bind(deployment_id)
    .bind(&context.customer_id.0)
    .bind(request.tenant_message_id)
    .bind(request.artifact_id)
    .bind(&request.resource_type)
    .bind(&request.purpose)
    .bind(&request.skill_id)
    .bind(&request.skill_version)
    .bind(&request.artifact_type)
    .bind(request.expires_at)
    .bind(&context.actor.login)
    .bind(&context.trace_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| unavailable())?;
    let response = CreateGrantResponse {
        id: row.get("id"),
        expires_at: row.get("expires_at"),
        artifact_id: request.artifact_id,
        skill_id: request.skill_id.clone(),
        skill_version: request.skill_version.clone(),
        purpose: request.purpose.clone(),
        created: true,
    };
    write_audit(
        transaction,
        deployment_id,
        context,
        headers,
        DeepAiAudit {
            action: "deep_ai_artifact_grant_created",
            resource_type: AUDIT_RESOURCE_GRANT,
            resource_id: Some(response.id.to_string()),
            details: json!({
                "artifact_id": response.artifact_id,
                "tenant_message_id": request.tenant_message_id,
                "resource_type": request.resource_type,
                "purpose": request.purpose,
                "skill_id": request.skill_id,
                "skill_version": request.skill_version,
                "artifact_type": request.artifact_type,
                "expires_at": response.expires_at,
            }),
        },
    )
    .await?;
    Ok(response)
}

async fn load_grant_for_result(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    grant_id: Uuid,
) -> Result<GrantRecord, Response> {
    sqlx::query(
        "SELECT id, customer_id, skill_id, skill_version, expires_at, revoked_at \
         FROM deep_ai_artifact_access_grants \
         WHERE deployment_id = $1 AND customer_id = $2 AND id = $3",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(grant_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| unavailable())?
    .map(|row| GrantRecord {
        id: row.get("id"),
        customer_id: row.get("customer_id"),
        skill_id: row.get("skill_id"),
        skill_version: row.get("skill_version"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
    })
    .ok_or_else(|| {
        api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Artifact grant was not found",
        )
    })
}

async fn insert_analysis_result(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    context: &TenantContext,
    headers: &HeaderMap,
    request: &ValidatedResultRequest,
) -> Result<RecordResultResponse, Response> {
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO deep_ai_analysis_results \
            (deployment_id, customer_id, skill_id, skill_version, model_release, artifact_grant_id, \
             classification, attack_type, severity, confidence, impersonated_entity, evidence_references, \
             observations, recommended_action, analyst_summary, processing_duration_ms, validation_state) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'valid') \
         RETURNING id",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(&request.skill_id)
    .bind(&request.skill_version)
    .bind(&request.model_release)
    .bind(request.artifact_grant_id)
    .bind(&request.classification)
    .bind(&request.attack_type)
    .bind(&request.severity)
    .bind(request.confidence)
    .bind(&request.impersonated_entity)
    .bind(&request.evidence_references)
    .bind(&request.observations)
    .bind(&request.recommended_action)
    .bind(&request.analyst_summary)
    .bind(request.processing_duration_ms)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| unavailable())?;
    write_audit(
        transaction,
        deployment_id,
        context,
        headers,
        DeepAiAudit {
            action: "deep_ai_analysis_result_recorded",
            resource_type: AUDIT_RESOURCE_RESULT,
            resource_id: Some(id.to_string()),
            details: json!({
                "artifact_grant_id": request.artifact_grant_id,
                "skill_id": request.skill_id,
                "skill_version": request.skill_version,
                "model_release": request.model_release,
                "classification": request.classification,
                "severity": request.severity,
                "recommended_action": request.recommended_action,
            }),
        },
    )
    .await?;
    Ok(RecordResultResponse {
        id,
        classification: request.classification.clone(),
        severity: request.severity.clone(),
        validation_state: "valid",
        created: true,
    })
}

async fn write_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    context: &TenantContext,
    headers: &HeaderMap,
    event: DeepAiAudit<'_>,
) -> Result<(), Response> {
    let (impersonated_subject, impersonated_customer) = match &context.impersonation {
        Some(impersonation) => (
            impersonation.impersonated_subject.clone(),
            Some(impersonation.impersonated_customer.0.clone()),
        ),
        None => (None, None),
    };
    let record = AuditEventRecord {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        actor_id: context.actor.actor_id.0.to_string(),
        actor_login: context.actor.login.clone(),
        actor_roles: context.actor.roles.clone(),
        impersonated_subject,
        impersonated_customer,
        customer_id: Some(context.customer_id.0.clone()),
        action: event.action.to_string(),
        resource_type: event.resource_type.to_string(),
        resource_id: event.resource_id,
        result: "success".to_string(),
        source_ip: source_ip_from(headers),
        session_id: Some(context.session_id.clone()),
        trace_id: context.trace_id.clone(),
        details: event.details,
    };
    PostgresAuditStore::insert_record(transaction, deployment_id, &record)
        .await
        .map_err(|_| unavailable())
}

fn validate_grant_request(request: CreateGrantRequest) -> Result<ValidatedGrantRequest, ()> {
    let skill_id = request.skill_id.trim().to_string();
    let skill_version = request.skill_version.trim().to_string();
    let resource_type = request.resource_type.trim().to_string();
    let purpose = request.purpose.trim().to_string();
    let artifact_type = request.artifact_type.trim().to_string();
    if !valid_skill_id(&skill_id)
        || !matches!(skill_version.as_str(), "v1" | "v2" | "v3")
        || !matches!(
            resource_type.as_str(),
            "quarantine_case"
                | "blocked_message"
                | "reported_phishing"
                | "confirmed_threat"
                | "false_positive_review"
                | "false_negative_review"
                | "held_for_deep_analysis"
        )
        || !matches!(
            purpose.as_str(),
            "security_analysis"
                | "bec_analysis"
                | "impersonation_analysis"
                | "case_summary"
                | "campaign_correlation"
                | "false_positive_review"
                | "false_negative_review"
        )
        || !matches!(
            artifact_type.as_str(),
            "message_rfc822"
                | "headers"
                | "text_extract"
                | "attachment_extract"
                | "scanner_metadata"
        )
        || !(5..=1440).contains(&request.ttl_minutes)
    {
        return Err(());
    }
    Ok(ValidatedGrantRequest {
        tenant_message_id: request.tenant_message_id,
        artifact_id: request.artifact_id,
        resource_type,
        purpose,
        skill_id,
        skill_version,
        artifact_type,
        expires_at: Utc::now() + Duration::minutes(request.ttl_minutes),
    })
}

fn validate_result_request(request: RecordResultRequest) -> Result<ValidatedResultRequest, ()> {
    let skill_id = request.skill_id.trim().to_string();
    let skill_version = request.skill_version.trim().to_string();
    let model_release = request.model_release.trim().to_string();
    let classification = request.classification.trim().to_string();
    let attack_type = request.attack_type.trim().to_string();
    let severity = request.severity.trim().to_string();
    let recommended_action = request.recommended_action.trim().to_string();
    let analyst_summary = request.analyst_summary.trim().to_string();
    if !valid_skill_id(&skill_id)
        || !matches!(skill_version.as_str(), "v1" | "v2" | "v3")
        || model_release.is_empty()
        || model_release.len() > 160
        || !matches!(
            classification.as_str(),
            "clean" | "suspicious" | "malicious" | "unknown" | "error"
        )
        || !matches!(
            attack_type.as_str(),
            "none" | "phishing" | "bec" | "impersonation" | "malware" | "spam" | "scam" | "unknown"
        )
        || !matches!(
            severity.as_str(),
            "info" | "low" | "medium" | "high" | "critical" | "unknown"
        )
        || !(0.0..=1.0).contains(&request.confidence)
        || !matches!(
            recommended_action.as_str(),
            "deliver" | "hold" | "quarantine" | "block" | "escalate" | "release" | "unknown"
        )
        || request.processing_duration_ms < 0
        || !(12..=4000).contains(&analyst_summary.len())
        || !request.evidence_references.is_array()
        || !request.observations.is_array()
    {
        return Err(());
    }
    Ok(ValidatedResultRequest {
        artifact_grant_id: request.artifact_grant_id,
        skill_id,
        skill_version,
        model_release,
        classification,
        attack_type,
        severity,
        confidence: request.confidence,
        impersonated_entity: request.impersonated_entity,
        evidence_references: request.evidence_references,
        observations: request.observations,
        recommended_action,
        analyst_summary,
        processing_duration_ms: request.processing_duration_ms,
    })
}

fn structured_output_is_valid(
    request: &ValidatedResultRequest,
    grant: &GrantRecord,
) -> Result<(), ()> {
    let evidence = request.evidence_references.as_array().ok_or(())?;
    if evidence.is_empty() || evidence.len() > 50 {
        return Err(());
    }
    let expected = format!("grant:{}", grant.id);
    if !evidence.iter().any(|reference| {
        reference
            .as_str()
            .map(|value| value == expected)
            .unwrap_or(false)
    }) {
        return Err(());
    }
    Ok(())
}

fn valid_skill_id(value: &str) -> bool {
    value.starts_with("security.")
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '.')
}

fn authorized(state: &DeepAiState, context: &TenantContext, permission: &str) -> bool {
    context.customer_lifecycle == CustomerLifecycle::Active
        && context.deployment_id == state.deployment_id
        && context
            .permissions
            .iter()
            .any(|granted| granted == permission)
}

fn require_idempotency_key(headers: &HeaderMap) -> Result<String, IdempotencyRejection> {
    let Some(raw) = headers.get(IDEMPOTENCY_HEADER) else {
        return Err(IdempotencyRejection::Missing);
    };
    let Ok(value) = raw.to_str() else {
        return Err(IdempotencyRejection::Invalid);
    };
    if value.is_empty() || value.len() > 128 {
        return Err(IdempotencyRejection::Invalid);
    }
    Ok(value.to_string())
}

fn idempotency_rejection_response(rejection: IdempotencyRejection) -> Response {
    match rejection {
        IdempotencyRejection::Missing => api_error(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_REQUIRED",
            "Idempotency key is required",
        ),
        IdempotencyRejection::Invalid => invalid_request(),
    }
}

fn envelope<T: Serialize>(data: &T) -> Option<Value> {
    serde_json::to_value(ApiEnvelope { data }).ok()
}

fn replay_response(value: Value) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

fn invalid_request() -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "INVALID_REQUEST",
        "Request is invalid",
    )
}

fn conflict(message: &'static str) -> Response {
    api_error(StatusCode::CONFLICT, "CONFLICT", message)
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        "Deep AI is unavailable",
    )
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use nullapart_mail_contracts::{transaction::CustomerId, ActorId};
    use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;

    fn state() -> DeepAiState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse");
        DeepAiState::new(pool, DeploymentId::new("LOCAL-TEST"))
    }

    fn context(permissions: Vec<String>) -> TenantContext {
        TenantContext {
            region: RegionId::new("local"),
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "admin@example.test".to_string(),
                roles: vec!["system_admin".to_string()],
                authentication_assurance: AuthenticationAssurance::StepUp,
            },
            customer_id: CustomerId::new("customer-1"),
            customer_internal_key: 1,
            customer_display_name: "Customer 1".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            impersonation: None,
            permissions,
            config_revision: 1,
            session_id: "session-1".to_string(),
            trace_id: "trace-1".to_string(),
            correlation_id: "correlation-1".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    #[test]
    fn validates_scoped_artifact_grant_request() {
        let request = validate_grant_request(CreateGrantRequest {
            tenant_message_id: Some(Uuid::new_v4()),
            artifact_id: Uuid::new_v4(),
            resource_type: "quarantine_case".to_string(),
            purpose: "security_analysis".to_string(),
            skill_id: "security.message.deep_analysis".to_string(),
            skill_version: "v1".to_string(),
            artifact_type: "message_rfc822".to_string(),
            ttl_minutes: 30,
        })
        .expect("request should validate");
        assert_eq!(request.skill_id, "security.message.deep_analysis");
        assert!(request.expires_at > Utc::now());
    }

    #[test]
    fn rejects_overbroad_or_unknown_grant_request() {
        assert!(validate_grant_request(CreateGrantRequest {
            tenant_message_id: None,
            artifact_id: Uuid::new_v4(),
            resource_type: "entire_customer_mailbox".to_string(),
            purpose: "security_analysis".to_string(),
            skill_id: "security.message.deep_analysis".to_string(),
            skill_version: "v1".to_string(),
            artifact_type: "message_rfc822".to_string(),
            ttl_minutes: 30,
        })
        .is_err());
        assert!(validate_grant_request(CreateGrantRequest {
            tenant_message_id: None,
            artifact_id: Uuid::new_v4(),
            resource_type: "quarantine_case".to_string(),
            purpose: "security_analysis".to_string(),
            skill_id: "security.message.deep_analysis".to_string(),
            skill_version: "v1".to_string(),
            artifact_type: "message_rfc822".to_string(),
            ttl_minutes: 10_000,
        })
        .is_err());
    }

    #[test]
    fn structured_output_requires_existing_grant_reference() {
        let grant_id = Uuid::new_v4();
        let grant = GrantRecord {
            id: grant_id,
            customer_id: "customer-1".to_string(),
            skill_id: "security.message.deep_analysis".to_string(),
            skill_version: "v1".to_string(),
            expires_at: Utc::now() + Duration::minutes(30),
            revoked_at: None,
        };
        let request = validate_result_request(RecordResultRequest {
            artifact_grant_id: grant_id,
            skill_id: "security.message.deep_analysis".to_string(),
            skill_version: "v1".to_string(),
            model_release: "local-qwen3.5-9b-phase7".to_string(),
            classification: "malicious".to_string(),
            attack_type: "phishing".to_string(),
            severity: "high".to_string(),
            confidence: 0.91,
            impersonated_entity: None,
            evidence_references: json!([format!("grant:{grant_id}")]),
            observations: json!(["Credential lure and brand impersonation."]),
            recommended_action: "quarantine".to_string(),
            analyst_summary: "Deep AI identified a credential lure with trusted evidence."
                .to_string(),
            processing_duration_ms: 1200,
        })
        .expect("result request should validate");
        assert!(structured_output_is_valid(&request, &grant).is_ok());
    }

    #[test]
    fn structured_output_rejects_hallucinated_evidence() {
        let grant = GrantRecord {
            id: Uuid::new_v4(),
            customer_id: "customer-1".to_string(),
            skill_id: "security.message.deep_analysis".to_string(),
            skill_version: "v1".to_string(),
            expires_at: Utc::now() + Duration::minutes(30),
            revoked_at: None,
        };
        let request = validate_result_request(RecordResultRequest {
            artifact_grant_id: grant.id,
            skill_id: "security.message.deep_analysis".to_string(),
            skill_version: "v1".to_string(),
            model_release: "local-qwen3.5-9b-phase7".to_string(),
            classification: "malicious".to_string(),
            attack_type: "phishing".to_string(),
            severity: "high".to_string(),
            confidence: 0.91,
            impersonated_entity: None,
            evidence_references: json!(["artifact:unknown"]),
            observations: json!(["Credential lure and brand impersonation."]),
            recommended_action: "quarantine".to_string(),
            analyst_summary: "Deep AI identified a credential lure with trusted evidence."
                .to_string(),
            processing_duration_ms: 1200,
        })
        .expect("result request should validate");
        assert!(structured_output_is_valid(&request, &grant).is_err());
    }

    #[tokio::test]
    async fn unauthenticated_deep_ai_projection_is_401() {
        let app = deep_ai_router(state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/deep-ai")
                    .body(Body::empty())
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_permission_is_403_before_database_access() {
        let app = deep_ai_router(state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/deep-ai")
                    .extension(context(vec!["trace:view".to_string()]))
                    .body(Body::empty())
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

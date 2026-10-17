//! Phase 7 regional Deep AI control plane slice.
//!
//! This module intentionally wires governance and access controls before any
//! autonomous model behaviour: skills are versioned, artifact access is scoped
//! and short lived, output is schema/provenance validated, and model results
//! never execute actions.

use axum::{
    extract::{rejection::JsonRejection, Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
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
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::admin_audit::{source_ip_from, AuditEventRecord, PostgresAuditStore};
use crate::idempotency::{claim, complete, ClaimOutcome};
use crate::policy_admin::set_scope;

pub const DEEP_AI_VIEW_PERMISSION: &str = "deep-ai:view";
pub const DEEP_AI_MANAGE_PERMISSION: &str = "deep-ai:manage";

const DEEP_AI_PATH: &str = "/api/v1/deep-ai";
const DEEP_AI_GRANTS_PATH: &str = "/api/v1/deep-ai/artifact-grants";
const DEEP_AI_GRANT_REVOKE_PATH: &str = "/api/v1/deep-ai/artifact-grants/:grant_id/revoke";
const DEEP_AI_RESULTS_PATH: &str = "/api/v1/deep-ai/analysis-results";
const DEEP_AI_ROLLBACK_PATH: &str = "/api/v1/deep-ai/rollback";
const DEEP_AI_SERVING_MODELS_PATH: &str = "/internal/deep-ai/v1/models";
const DEEP_AI_SERVING_CHAT_PATH: &str = "/internal/deep-ai/v1/chat/completions";
const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const AUTHORIZATION_HEADER: &str = "authorization";
const GRANT_OPERATION: &str = "deep-ai-artifact-grant";
/// Idempotency operations are scoped to tenant and key, so a revoke
/// operation also names the grant it targets. Without that, one key replayed
/// against a second grant would return the first grant's stored response
/// instead of being rejected as an operation mismatch.
const REVOKE_OPERATION_PREFIX: &str = "deep-ai-artifact-grant-revoke:";
const RESULT_OPERATION: &str = "deep-ai-analysis-result";
const ROLLBACK_OPERATION: &str = "deep-ai-rollback";
const AUDIT_RESOURCE_GRANT: &str = "deep_ai_artifact_grant";
const AUDIT_RESOURCE_RESULT: &str = "deep_ai_analysis_result";
const AUDIT_RESOURCE_ROLLBACK: &str = "deep_ai_release_rollback";
/// Origin stamped on a result posted through an authenticated console session.
/// The only caller of that route is a person, so the origin is a property of
/// the route, never of the request body: a client that could name its own
/// origin could publish an assertion as model output.
const RECORDED_BY_CONSOLE: &str = "administrator";

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

#[derive(Clone)]
pub struct DeepAiServingState {
    workload_token: String,
    model: String,
}

impl DeepAiServingState {
    pub fn new(workload_token: String, model: String) -> Result<Self, &'static str> {
        if workload_token.len() < 16 || model.trim().is_empty() {
            return Err("Deep AI serving token/model configuration is invalid");
        }
        Ok(Self {
            workload_token,
            model,
        })
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
    revoked_by: Option<String>,
    revoke_reason: Option<String>,
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
    /// `model_runtime` when the skill runtime produced the output,
    /// `administrator` when a person entered it in the console, and `None` for
    /// rows written before origin tracking existed. Server-derived; the request
    /// body never supplies it.
    recorded_by: Option<String>,
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
struct RevokeGrantRequest {
    reason: String,
}

#[derive(Debug, Serialize)]
struct RevokeGrantResponse {
    id: Uuid,
    artifact_id: Uuid,
    revoked_at: DateTime<Utc>,
    revoked_by: String,
    /// The reason carried by the revocation that exists on the record. When the
    /// grant was already revoked this is the original reason rather than the
    /// one the caller just sent, because that older decision is the fact the
    /// console needs to see.
    reason: String,
    /// False when the grant was already revoked, so a retry reports what
    /// actually happened instead of implying a second revocation.
    changed: bool,
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
    /// Echoes the server-derived origin so the console can show the operator
    /// what was actually stored. Never taken from the request body.
    recorded_by: &'static str,
    created: bool,
}

#[derive(Debug, Deserialize)]
struct RollbackRequest {
    skill_id: Option<String>,
    current_skill_version: Option<String>,
    rollback_skill_version: Option<String>,
    model_release: Option<String>,
    rollback_to_model_release: Option<String>,
    reason: String,
}

#[derive(Debug, Serialize)]
struct RollbackResponse {
    skill_rolled_back: bool,
    model_rolled_back: bool,
    reason: String,
    changed: bool,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    tools: Option<Vec<Value>>,
    tool_choice: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    role: String,
    content: Value,
}

#[derive(Debug, Serialize)]
struct OpenAiModelList {
    object: &'static str,
    data: Vec<OpenAiModel>,
}

#[derive(Debug, Serialize)]
struct OpenAiModel {
    id: String,
    object: &'static str,
    owned_by: &'static str,
}

#[derive(Debug, Serialize)]
struct ChatCompletionResponse {
    id: String,
    object: &'static str,
    model: String,
    choices: Vec<ChatCompletionChoice>,
}

#[derive(Debug, Serialize)]
struct ChatCompletionChoice {
    index: u8,
    message: AssistantMessage,
    finish_reason: &'static str,
}

#[derive(Debug, Serialize)]
struct AssistantMessage {
    role: &'static str,
    content: String,
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

struct ValidatedRollbackRequest {
    skill: Option<SkillRollback>,
    model: Option<ModelRollback>,
    reason: String,
}

struct SkillRollback {
    skill_id: String,
    current_skill_version: String,
    rollback_skill_version: String,
}

struct ModelRollback {
    model_release: String,
    rollback_to_model_release: String,
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

struct GrantRevocationRecord {
    id: Uuid,
    artifact_id: Uuid,
    revoked_at: Option<DateTime<Utc>>,
    revoked_by: Option<String>,
    revoke_reason: Option<String>,
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
        .route(DEEP_AI_GRANT_REVOKE_PATH, post(post_grant_revocation))
        .route(DEEP_AI_RESULTS_PATH, post(post_analysis_result))
        .route(DEEP_AI_ROLLBACK_PATH, post(post_rollback))
        .with_state(state)
}

pub fn deep_ai_serving_router(state: DeepAiServingState) -> Router {
    Router::new()
        .route(DEEP_AI_SERVING_MODELS_PATH, get(get_serving_models))
        .route(
            DEEP_AI_SERVING_CHAT_PATH,
            post(post_serving_chat_completion),
        )
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
    if !context.has_step_up() {
        return api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        );
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

/// Revokes an artifact grant before it expires.
///
/// A grant is a bounded authorization to read customer message content, so an
/// operator who learns that the purpose no longer holds has to be able to end it
/// now instead of waiting for the remaining TTL to run down. Revocation is
/// permanent and needs a reason: the row keeps the stamp, and the reason is what
/// makes a later read of the grant answer the question "why did access end".
async fn post_grant_revocation(
    State(state): State<DeepAiState>,
    headers: HeaderMap,
    Path(raw_grant_id): Path<String>,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<RevokeGrantRequest>, JsonRejection>,
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
    if !context.has_step_up() {
        return api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        );
    }
    // The grant id arrives in the path, so a value that is not a UUID cannot
    // name a record at all. Answering 404 here would imply the id might exist
    // somewhere the caller cannot see.
    let Ok(grant_id) = Uuid::parse_str(raw_grant_id.trim()) else {
        return invalid_request();
    };
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => return invalid_request(),
    };
    let reason = match validate_revocation_reason(request.reason) {
        Ok(reason) => reason,
        Err(_) => return invalid_request(),
    };
    let idempotency_key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    let operation = format!("{REVOKE_OPERATION_PREFIX}{grant_id}");

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
    match claim(&mut transaction, &idempotency_key, &operation).await {
        Ok(ClaimOutcome::Fresh) => {},
        Ok(ClaimOutcome::Replay(value)) => return replay_response(value),
        Ok(ClaimOutcome::InProgress) => return conflict("A matching request is still in progress"),
        Ok(ClaimOutcome::OperationMismatch) => {
            return conflict("Idempotency key operation mismatch")
        },
        Err(_) => return unavailable(),
    }

    // Read under the caller's tenant scope: a grant belonging to another
    // customer is reported as absent rather than as forbidden, so this route
    // cannot be used to test whether an id exists elsewhere.
    let grant = match load_grant_for_revocation(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
        grant_id,
    )
    .await
    {
        Ok(Some(grant)) => grant,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Artifact grant was not found",
            )
        },
        Err(response) => return response,
    };
    let GrantRevocationRecord {
        id,
        artifact_id,
        revoked_at,
        revoked_by,
        revoke_reason,
    } = grant;
    let response = match (revoked_at, revoked_by, revoke_reason) {
        (Some(revoked_at), Some(revoked_by), Some(stored_reason)) => RevokeGrantResponse {
            id,
            artifact_id,
            revoked_at,
            revoked_by,
            // The revocation on the record is the fact the console needs, so a
            // repeat attempt echoes the reason already stored rather than the
            // one it just sent.
            reason: stored_reason,
            changed: false,
        },
        (None, None, None) => RevokeGrantResponse {
            id,
            artifact_id,
            revoked_at: match revoke_grant(&mut transaction, id, &context.actor.login, &reason)
                .await
            {
                Ok(revoked_at) => revoked_at,
                Err(response) => return response,
            },
            revoked_by: context.actor.login.clone(),
            reason,
            changed: true,
        },
        // The table forbids a part-filled revocation with a CHECK constraint, so
        // reaching this arm means the database is not the schema this route was
        // written against. Failing closed is better than stamping a guess.
        _ => return unavailable(),
    };
    if let Err(response) = write_audit(
        &mut transaction,
        &state.deployment_id.0,
        &context,
        &headers,
        DeepAiAudit {
            action: "deep_ai_artifact_grant_revoked",
            resource_type: AUDIT_RESOURCE_GRANT,
            resource_id: Some(id.to_string()),
            details: json!({
                "artifact_id": response.artifact_id,
                "revoked_at": response.revoked_at,
                "revoked_by": response.revoked_by,
                "reason": response.reason,
                "changed": response.changed,
            }),
        },
    )
    .await
    {
        return response;
    }
    let Some(envelope) = envelope(&response) else {
        return unavailable();
    };
    if complete(&mut transaction, &idempotency_key, &operation, envelope)
        .await
        .is_err()
    {
        return unavailable();
    }
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    (StatusCode::OK, Json(ApiEnvelope { data: response })).into_response()
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
    if !context.has_step_up() {
        return api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        );
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
    if !match model_release_is_approved(
        &mut transaction,
        &state.deployment_id.0,
        &request.model_release,
    )
    .await
    {
        Ok(approved) => approved,
        Err(response) => return response,
    } {
        return api_error(
            StatusCode::BAD_REQUEST,
            "MODEL_RELEASE_NOT_APPROVED",
            "Model release is not an approved release of this deployment",
        );
    }
    let response = match insert_analysis_result(
        &mut transaction,
        &state.deployment_id.0,
        &grant.customer_id,
        &context,
        &headers,
        &request,
        RECORDED_BY_CONSOLE,
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

async fn post_rollback(
    State(state): State<DeepAiState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<RollbackRequest>, JsonRejection>,
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
    if !context.has_step_up() {
        return api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        );
    }
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => return invalid_request(),
    };
    let request = match validate_rollback_request(request) {
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
    match claim(&mut transaction, &idempotency_key, ROLLBACK_OPERATION).await {
        Ok(ClaimOutcome::Fresh) => {},
        Ok(ClaimOutcome::Replay(value)) => return replay_response(value),
        Ok(ClaimOutcome::InProgress) => return conflict("A matching request is still in progress"),
        Ok(ClaimOutcome::OperationMismatch) => {
            return conflict("Idempotency key operation mismatch")
        },
        Err(_) => return unavailable(),
    }

    let skill_rolled_back = match &request.skill {
        Some(skill) => {
            match rollback_skill(&mut transaction, &state.deployment_id.0, skill).await {
                Ok(changed) => changed,
                Err(response) => return response,
            }
        },
        None => false,
    };
    let model_rolled_back = match &request.model {
        Some(model) => {
            match rollback_model(&mut transaction, &state.deployment_id.0, model).await {
                Ok(changed) => changed,
                Err(response) => return response,
            }
        },
        None => false,
    };
    let response = RollbackResponse {
        skill_rolled_back,
        model_rolled_back,
        reason: request.reason.clone(),
        changed: skill_rolled_back || model_rolled_back,
    };
    if let Err(response) = write_audit(
        &mut transaction,
        &state.deployment_id.0,
        &context,
        &headers,
        DeepAiAudit {
            action: "deep_ai_release_rolled_back",
            resource_type: AUDIT_RESOURCE_ROLLBACK,
            resource_id: request
                .skill
                .as_ref()
                .map(|skill| format!("{}:{}", skill.skill_id, skill.current_skill_version))
                .or_else(|| {
                    request
                        .model
                        .as_ref()
                        .map(|model| model.model_release.clone())
                }),
            details: json!({
                "skill_rolled_back": response.skill_rolled_back,
                "model_rolled_back": response.model_rolled_back,
                "reason": request.reason,
            }),
        },
    )
    .await
    {
        return response;
    }
    let Some(envelope) = envelope(&response) else {
        return unavailable();
    };
    if complete(
        &mut transaction,
        &idempotency_key,
        ROLLBACK_OPERATION,
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
    (StatusCode::OK, Json(ApiEnvelope { data: response })).into_response()
}

async fn get_serving_models(
    State(state): State<DeepAiServingState>,
    headers: HeaderMap,
) -> Response {
    if !serving_authorized(&state, &headers) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Deep AI workload authentication is required",
        );
    }
    let body = OpenAiModelList {
        object: "list",
        data: vec![OpenAiModel {
            id: state.model,
            object: "model",
            owned_by: "nullapart-regional",
        }],
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn post_serving_chat_completion(
    State(state): State<DeepAiServingState>,
    headers: HeaderMap,
    body: Result<Json<ChatCompletionRequest>, JsonRejection>,
) -> Response {
    if !serving_authorized(&state, &headers) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Deep AI workload authentication is required",
        );
    }
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => return invalid_request(),
    };
    if request.model != state.model
        || request.messages.is_empty()
        || request.messages.len() > 32
        || request
            .tools
            .as_ref()
            .is_some_and(|tools| !tools.is_empty())
        || request.tool_choice.is_some()
        || request
            .messages
            .iter()
            .any(|message| !matches!(message.role.as_str(), "system" | "user" | "assistant"))
    {
        return invalid_request();
    }
    let observed_chars: usize = request
        .messages
        .iter()
        .map(|message| match &message.content {
            Value::String(value) => value.len(),
            other => other.to_string().len(),
        })
        .sum();
    if observed_chars > 256_000 {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
            "Deep AI request exceeds the local context budget",
        );
    }
    let structured = json!({
        "classification": "unknown",
        "attack_type": "unknown",
        "severity": "unknown",
        "confidence": 0.0,
        "evidence_references": [],
        "observations": ["local development Deep AI serving contract responded"],
        "recommended_action": "unknown",
        "analyst_summary": "Local development serving endpoint is operational; production model inference is configured per regional release.",
        "processing_duration_ms": 0
    });
    let body = ChatCompletionResponse {
        id: format!("chatcmpl-{}", Uuid::new_v4().simple()),
        object: "chat.completion",
        model: state.model,
        choices: vec![ChatCompletionChoice {
            index: 0,
            message: AssistantMessage {
                role: "assistant",
                content: structured.to_string(),
            },
            finish_reason: "stop",
        }],
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn rollback_skill(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    rollback: &SkillRollback,
) -> Result<bool, Response> {
    let target_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
            SELECT 1 FROM deep_ai_skills \
            WHERE deployment_id = $1 AND skill_id = $2 AND skill_version = $3 \
         )",
    )
    .bind(deployment_id)
    .bind(&rollback.skill_id)
    .bind(&rollback.rollback_skill_version)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| unavailable())?;
    if !target_exists {
        return Err(api_error(
            StatusCode::CONFLICT,
            "ROLLBACK_TARGET_NOT_FOUND",
            "Rollback target does not exist",
        ));
    }

    let changed_current = sqlx::query(
        "UPDATE deep_ai_skills \
         SET release_state = 'rolled_back', rollback_skill_version = $4, updated_at = now() \
         WHERE deployment_id = $1 AND skill_id = $2 AND skill_version = $3 \
           AND release_state = 'released'",
    )
    .bind(deployment_id)
    .bind(&rollback.skill_id)
    .bind(&rollback.current_skill_version)
    .bind(&rollback.rollback_skill_version)
    .execute(&mut **transaction)
    .await
    .map_err(|_| unavailable())?
    .rows_affected();
    if changed_current != 1 {
        return Err(api_error(
            StatusCode::CONFLICT,
            "ROLLBACK_SOURCE_NOT_RELEASED",
            "Current skill version is not released",
        ));
    }

    let changed_target = sqlx::query(
        "UPDATE deep_ai_skills \
         SET release_state = 'released', rollback_skill_version = NULL, updated_at = now() \
         WHERE deployment_id = $1 AND skill_id = $2 AND skill_version = $3",
    )
    .bind(deployment_id)
    .bind(&rollback.skill_id)
    .bind(&rollback.rollback_skill_version)
    .execute(&mut **transaction)
    .await
    .map_err(|_| unavailable())?
    .rows_affected();
    Ok(changed_target == 1)
}

async fn rollback_model(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    rollback: &ModelRollback,
) -> Result<bool, Response> {
    let target_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
            SELECT 1 FROM deep_ai_model_releases \
            WHERE deployment_id = $1 AND model_release = $2 \
         )",
    )
    .bind(deployment_id)
    .bind(&rollback.rollback_to_model_release)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| unavailable())?;
    if !target_exists {
        return Err(api_error(
            StatusCode::CONFLICT,
            "ROLLBACK_TARGET_NOT_FOUND",
            "Rollback target does not exist",
        ));
    }

    let changed_current = sqlx::query(
        "UPDATE deep_ai_model_releases \
         SET approval_state = 'rejected', approved_by = NULL, approved_at = NULL, \
             rollback_to_model_release = $3, updated_at = now() \
         WHERE deployment_id = $1 AND model_release = $2 AND approval_state = 'approved'",
    )
    .bind(deployment_id)
    .bind(&rollback.model_release)
    .bind(&rollback.rollback_to_model_release)
    .execute(&mut **transaction)
    .await
    .map_err(|_| unavailable())?
    .rows_affected();
    if changed_current != 1 {
        return Err(api_error(
            StatusCode::CONFLICT,
            "ROLLBACK_SOURCE_NOT_APPROVED",
            "Current model release is not approved",
        ));
    }

    let changed_target = sqlx::query(
        "UPDATE deep_ai_model_releases \
         SET approval_state = 'approved', approved_by = 'rollback', approved_at = now(), updated_at = now() \
         WHERE deployment_id = $1 AND model_release = $2",
    )
    .bind(deployment_id)
    .bind(&rollback.rollback_to_model_release)
    .execute(&mut **transaction)
    .await
    .map_err(|_| unavailable())?
    .rows_affected();
    Ok(changed_target == 1)
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
                artifact_type, expires_at, created_by, created_at, revoked_at, revoked_by, \
                revoke_reason \
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
                revoked_by: row.get("revoked_by"),
                revoke_reason: row.get("revoke_reason"),
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
                validation_state, error_code, recorded_by, created_at \
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
                recorded_by: row.get("recorded_by"),
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

/// Loads a grant for revocation, locking the row until the transaction ends.
///
/// The lock is what makes the "read the stamp, then write the stamp" sequence in
/// [`post_grant_revocation`] safe: two operators submitting at the same moment
/// cannot both believe they were the first to end the grant.
async fn load_grant_for_revocation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    grant_id: Uuid,
) -> Result<Option<GrantRevocationRecord>, Response> {
    Ok(sqlx::query(
        "SELECT id, artifact_id, revoked_at, revoked_by, revoke_reason \
         FROM deep_ai_artifact_access_grants \
         WHERE deployment_id = $1 AND customer_id = $2 AND id = $3 \
         FOR UPDATE",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(grant_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| unavailable())?
    .map(|row| GrantRevocationRecord {
        id: row.get("id"),
        artifact_id: row.get("artifact_id"),
        revoked_at: row.get("revoked_at"),
        revoked_by: row.get("revoked_by"),
        revoke_reason: row.get("revoke_reason"),
    }))
}

/// Stamps the revocation triple on the grant and returns when access ended.
///
/// The `revoked_at IS NULL` guard is kept even though the caller holds the row
/// lock, so a grant revoked by another committed transaction stays revoked and
/// this reports a conflict instead of overwriting the earlier decision.
async fn revoke_grant(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    grant_id: Uuid,
    revoked_by: &str,
    reason: &str,
) -> Result<DateTime<Utc>, Response> {
    sqlx::query(
        "UPDATE deep_ai_artifact_access_grants \
         SET revoked_at = now(), revoked_by = $2, revoke_reason = $3 \
         WHERE id = $1 AND revoked_at IS NULL \
         RETURNING revoked_at",
    )
    .bind(grant_id)
    .bind(revoked_by)
    .bind(reason)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| unavailable())?
    .map(|row| row.get("revoked_at"))
    .ok_or_else(|| conflict("The artifact grant was already revoked by another request"))
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

/// True when `model_release` names an approved release of this deployment.
///
/// A recorded result cites a model as its source, so the citation must be a
/// release the deployment approved rather than a string the caller typed.
/// Approval state is read here, in the same transaction as the insert, so a
/// release rejected or rolled back between page load and submit cannot still be
/// cited.
async fn model_release_is_approved(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    model_release: &str,
) -> Result<bool, Response> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
            SELECT 1 FROM deep_ai_model_releases \
            WHERE deployment_id = $1 AND model_release = $2 AND approval_state = 'approved' \
         )",
    )
    .bind(deployment_id)
    .bind(model_release)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| unavailable())
}

async fn insert_analysis_result(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    context: &TenantContext,
    headers: &HeaderMap,
    request: &ValidatedResultRequest,
    recorded_by: &'static str,
) -> Result<RecordResultResponse, Response> {
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO deep_ai_analysis_results \
            (deployment_id, customer_id, skill_id, skill_version, model_release, artifact_grant_id, \
             classification, attack_type, severity, confidence, impersonated_entity, evidence_references, \
             observations, recommended_action, analyst_summary, processing_duration_ms, validation_state, \
             recorded_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'valid',$17) \
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
    .bind(recorded_by)
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
                "recorded_by": recorded_by,
            }),
        },
    )
    .await?;
    Ok(RecordResultResponse {
        id,
        classification: request.classification.clone(),
        severity: request.severity.clone(),
        validation_state: "valid",
        recorded_by,
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

/// A revocation reason has to survive being read months later by someone who
/// was not in the conversation, so a one-word answer is rejected. The bounds
/// match the rollback reason the same console already enforces.
fn validate_revocation_reason(value: String) -> Result<String, ()> {
    let reason = value.trim().to_string();
    if !(12..=500).contains(&reason.len()) {
        return Err(());
    }
    Ok(reason)
}

fn validate_rollback_request(request: RollbackRequest) -> Result<ValidatedRollbackRequest, ()> {
    let reason = request.reason.trim().to_string();
    if !(12..=500).contains(&reason.len()) {
        return Err(());
    }
    let skill = match (
        request.skill_id,
        request.current_skill_version,
        request.rollback_skill_version,
    ) {
        (Some(skill_id), Some(current_skill_version), Some(rollback_skill_version)) => {
            let skill_id = skill_id.trim().to_string();
            let current_skill_version = current_skill_version.trim().to_string();
            let rollback_skill_version = rollback_skill_version.trim().to_string();
            if !valid_skill_id(&skill_id)
                || !valid_skill_version(&current_skill_version)
                || !valid_skill_version(&rollback_skill_version)
                || current_skill_version == rollback_skill_version
            {
                return Err(());
            }
            Some(SkillRollback {
                skill_id,
                current_skill_version,
                rollback_skill_version,
            })
        },
        (None, None, None) => None,
        _ => return Err(()),
    };
    let model = match (request.model_release, request.rollback_to_model_release) {
        (Some(model_release), Some(rollback_to_model_release)) => {
            let model_release = model_release.trim().to_string();
            let rollback_to_model_release = rollback_to_model_release.trim().to_string();
            if !valid_release_identifier(&model_release)
                || !valid_release_identifier(&rollback_to_model_release)
                || model_release == rollback_to_model_release
            {
                return Err(());
            }
            Some(ModelRollback {
                model_release,
                rollback_to_model_release,
            })
        },
        (None, None) => None,
        _ => return Err(()),
    };
    if skill.is_none() && model.is_none() {
        return Err(());
    }
    Ok(ValidatedRollbackRequest {
        skill,
        model,
        reason,
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

fn valid_skill_version(value: &str) -> bool {
    matches!(value, "v1" | "v2" | "v3")
}

fn valid_release_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':'))
}

fn authorized(state: &DeepAiState, context: &TenantContext, permission: &str) -> bool {
    context.customer_lifecycle == CustomerLifecycle::Active
        && context.deployment_id == state.deployment_id
        && context
            .permissions
            .iter()
            .any(|granted| granted == permission)
}

fn serving_authorized(state: &DeepAiServingState, headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(AUTHORIZATION_HEADER) else {
        return false;
    };
    bearer_matches(value, &state.workload_token)
}

fn bearer_matches(value: &HeaderValue, expected_token: &str) -> bool {
    let Ok(raw) = value.to_str() else {
        return false;
    };
    raw.strip_prefix("Bearer ")
        .map(|token| token.as_bytes().ct_eq(expected_token.as_bytes()).into())
        .unwrap_or(false)
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

    fn serving_state() -> DeepAiServingState {
        DeepAiServingState::new(
            "local-serving-token-123".to_string(),
            "local-qwen3.5-9b-phase7".to_string(),
        )
        .expect("serving state should validate")
    }

    fn context(permissions: Vec<String>) -> TenantContext {
        context_with_assurance(permissions, AuthenticationAssurance::StepUp)
    }

    fn context_with_assurance(
        permissions: Vec<String>,
        authentication_assurance: AuthenticationAssurance,
    ) -> TenantContext {
        TenantContext {
            region: RegionId::new("local"),
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "admin@example.test".to_string(),
                roles: vec!["system_admin".to_string()],
                authentication_assurance,
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

    #[test]
    fn a_result_body_cannot_name_its_own_origin() {
        // Provenance is not a request field. A caller that sends one gets it
        // ignored, and the route attributes the finding to whoever is calling.
        let request: RecordResultRequest = serde_json::from_value(json!({
            "artifact_grant_id": Uuid::new_v4(),
            "skill_id": "security.message.deep_analysis",
            "skill_version": "v1",
            "model_release": "local-qwen3.5-9b-phase7",
            "classification": "malicious",
            "attack_type": "phishing",
            "severity": "high",
            "confidence": 0.91,
            "impersonated_entity": null,
            "evidence_references": ["grant:any"],
            "observations": ["Credential lure and brand impersonation."],
            "recommended_action": "quarantine",
            "analyst_summary": "Deep AI identified a credential lure with trusted evidence.",
            "processing_duration_ms": 1200,
            "recorded_by": "model_runtime",
        }))
        .expect("result body must parse");
        assert!(validate_result_request(request).is_ok());
        assert_eq!(RECORDED_BY_CONSOLE, "administrator");
    }

    #[test]
    fn rollback_request_requires_substantive_target_and_reason() {
        let request = validate_rollback_request(RollbackRequest {
            skill_id: Some("security.message.deep_analysis".to_string()),
            current_skill_version: Some("v2".to_string()),
            rollback_skill_version: Some("v1".to_string()),
            model_release: Some("qwen-phase7-v2".to_string()),
            rollback_to_model_release: Some("qwen-phase7-v1".to_string()),
            reason: "rollback after failed evaluation gate".to_string(),
        })
        .expect("rollback request should validate");
        assert!(request.skill.is_some());
        assert!(request.model.is_some());

        assert!(validate_rollback_request(RollbackRequest {
            skill_id: Some("security.message.deep_analysis".to_string()),
            current_skill_version: Some("v1".to_string()),
            rollback_skill_version: Some("v1".to_string()),
            model_release: None,
            rollback_to_model_release: None,
            reason: "same version".to_string(),
        })
        .is_err());
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

    #[tokio::test]
    async fn manage_mutations_require_step_up_before_database_access() {
        let app = deep_ai_router(state());
        let revoke_uri = format!("/api/v1/deep-ai/artifact-grants/{}/revoke", Uuid::nil());
        for uri in [
            "/api/v1/deep-ai/artifact-grants",
            revoke_uri.as_str(),
            "/api/v1/deep-ai/analysis-results",
            "/api/v1/deep-ai/rollback",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .extension(context_with_assurance(
                            vec!["deep-ai:manage".to_string()],
                            AuthenticationAssurance::Standard,
                        ))
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request must build"),
                )
                .await
                .expect("router must answer");
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "uri = {uri}");
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("body must read");
            let body: Value =
                serde_json::from_slice(&bytes).expect("step-up rejection must be JSON");
            assert_eq!(body["code"], "STEP_UP_REQUIRED", "uri = {uri}");
        }
    }

    #[tokio::test]
    async fn grant_revocation_requires_manage_permission() {
        let app = deep_ai_router(state());
        let revoke_uri = format!("/api/v1/deep-ai/artifact-grants/{}/revoke", Uuid::nil());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(revoke_uri)
                    .extension(context(vec![
                        DEEP_AI_VIEW_PERMISSION.to_string(),
                        "trace:view".to_string(),
                    ]))
                    .header("content-type", "application/json")
                    .header(IDEMPOTENCY_HEADER, "revoke-attempt-1")
                    .body(Body::from(revocation_body(
                        "the incident closed and no further analysis is needed",
                    )))
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn grant_revocation_rejects_an_identifier_that_is_not_a_grant() {
        let app = deep_ai_router(state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/deep-ai/artifact-grants/recent/revoke")
                    .extension(context(vec![DEEP_AI_MANAGE_PERMISSION.to_string()]))
                    .header("content-type", "application/json")
                    .header(IDEMPOTENCY_HEADER, "revoke-attempt-2")
                    .body(Body::from(revocation_body(
                        "the analyst no longer needs this artifact in scope",
                    )))
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        // A word where a UUID belongs cannot name a record, and the answer is
        // 400 rather than 404 so the route cannot be probed for ids it does not
        // recognise. The lazy test pool points at a dead port, so reaching this
        // status also proves no query ran.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_code(response).await, "INVALID_REQUEST");
    }

    #[tokio::test]
    async fn grant_revocation_requires_an_idempotency_key() {
        let app = deep_ai_router(state());
        let revoke_uri = format!("/api/v1/deep-ai/artifact-grants/{}/revoke", Uuid::nil());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(revoke_uri)
                    .extension(context(vec![DEEP_AI_MANAGE_PERMISSION.to_string()]))
                    .header("content-type", "application/json")
                    .body(Body::from(revocation_body(
                        "the analyst no longer needs this artifact in scope",
                    )))
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_code(response).await, "IDEMPOTENCY_REQUIRED");
    }

    #[tokio::test]
    async fn grant_revocation_rejects_a_thin_reason() {
        let app = deep_ai_router(state());
        let revoke_uri = format!("/api/v1/deep-ai/artifact-grants/{}/revoke", Uuid::nil());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(revoke_uri)
                    .extension(context(vec![DEEP_AI_MANAGE_PERMISSION.to_string()]))
                    .header("content-type", "application/json")
                    .header(IDEMPOTENCY_HEADER, "revoke-attempt-3")
                    .body(Body::from(revocation_body("done")))
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_code(response).await, "INVALID_REQUEST");
    }

    #[test]
    fn revocation_reason_requires_a_substantive_sentence() {
        assert_eq!(
            validate_revocation_reason(
                "  the incident closed and no further analysis is needed  ".to_string()
            )
            .expect("reason should validate"),
            "the incident closed and no further analysis is needed"
        );
        assert!(validate_revocation_reason("done".to_string()).is_err());
        assert!(
            validate_revocation_reason("x".repeat(501)).is_err(),
            "a reason longer than the stored contract must be rejected"
        );
    }

    /// A revoke body carrying `reason`; the console sends JSON and the contract
    /// rejects anything else, so tests build it in one place.
    fn revocation_body(reason: &str) -> String {
        json!({ "reason": reason }).to_string()
    }

    async fn body_code(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body must read");
        let body: Value = serde_json::from_slice(&bytes).expect("error body must be JSON");
        body["code"].as_str().unwrap_or_default().to_string()
    }

    #[tokio::test]
    async fn serving_contract_requires_workload_bearer() {
        let app = deep_ai_serving_router(serving_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/internal/deep-ai/v1/models")
                    .body(Body::empty())
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn serving_contract_lists_model_and_rejects_action_tools() {
        let app = deep_ai_serving_router(serving_state());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/deep-ai/v1/models")
                    .header(AUTHORIZATION_HEADER, "Bearer local-serving-token-123")
                    .body(Body::empty())
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/deep-ai/v1/chat/completions")
                    .header(AUTHORIZATION_HEADER, "Bearer local-serving-token-123")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "model": "local-qwen3.5-9b-phase7",
                            "messages": [{"role": "user", "content": "probe"}],
                            "tools": [{"type": "function"}]
                        })
                        .to_string(),
                    ))
                    .expect("request must build"),
            )
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

//! Inline ML model registry administration (Phase 4 increment 4).
//!
//! One audited, system-scoped admin API registers, approves, activates and
//! rolls back model artifacts. Every route runs: authenticated context, body
//! validation, idempotency key, permission/lifecycle/deployment
//! authorization, the system-administrator role gate, the shared high-risk
//! gate (fresh step-up, fail-closed budget) for runtime-affecting
//! transitions, and only then a database transaction.
//!
//! Security invariants:
//!
//! - registration is evidence only: a registered model changes no runtime
//!   behavior until it is approved and activated;
//! - approval and activation are separate audited transitions; activation
//!   requires the approved state and the `system_admin` role, and the
//!   database enforces that only an approved model has ever been activated;
//! - exactly one model per deployment is active at a time (partial unique
//!   index), serialized by an advisory lock, so concurrent activations
//!   cannot race past the API;
//! - every activation records the model it replaced
//!   (`rollback_model_id`/`rollback_model_version`), so rollback is an
//!   audited re-activation of a previously approved model — never a data
//!   migration or a silent substitution;
//! - approval/activation state lives in this registry only; the inference
//!   stage reads its artifacts from configuration, so this API can never
//!   mutate a running message path directly.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{rejection::JsonRejection, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use nullapart_mail_contracts::{
    rate_limit::{HighRiskLimits, TokenBucket},
    transaction::DeploymentId,
};
use nullapart_policy::{CustomerLifecycle, TenantContext};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use tracing::error;
use uuid::Uuid;

use crate::admin_audit::{source_ip_from, AuditEventRecord, AuditStore, PostgresAuditStore};
use crate::admin_rbac::SYSTEM_ADMIN_ROLE;
use crate::idempotency::{claim, complete, ClaimOutcome};
use crate::policy_admin::set_scope;

pub const MODELS_VIEW_PERMISSION: &str = "models:view";
pub const MODELS_MANAGE_PERMISSION: &str = "models:manage";

const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const MODEL_ID_MAX_LEN: usize = 64;
const MODEL_VERSION_MAX_LEN: usize = 64;
const DATASET_VERSION_MAX_LEN: usize = 128;
const ARTIFACT_URI_MAX_LEN: usize = 512;
const METRICS_MAX_BYTES: usize = 64 * 1024;
const REGIONS_MAX_COUNT: usize = 16;
const APPROVAL_NOTE_MIN_LEN: usize = 10;
const APPROVAL_NOTE_MAX_LEN: usize = 500;
const INPUT_SCHEMA_VERSION_MAX: i32 = 1000;
const SHA256_HEX_LEN: usize = 64;
const EVALUATION_SET_ID_MAX_LEN: usize = 128;

const ADMIN_MODELS_PATH: &str = "/api/v1/admin/models";
const ADMIN_MODEL_PATH: &str = "/api/v1/admin/models/:model_id/:model_version";
const ADMIN_MODEL_APPROVE_PATH: &str = "/api/v1/admin/models/:model_id/:model_version/approve";
const ADMIN_MODEL_REJECT_PATH: &str = "/api/v1/admin/models/:model_id/:model_version/reject";
const ADMIN_MODEL_ACTIVATE_PATH: &str = "/api/v1/admin/models/:model_id/:model_version/activate";
const ADMIN_MODEL_ROLLBACK_PATH: &str = "/api/v1/admin/models/:model_id/:model_version/rollback";
const ADMIN_MODEL_SHADOW_EVALUATIONS_PATH: &str =
    "/api/v1/admin/models/:model_id/:model_version/shadow-evaluations";

const ACTION_MODEL_LIST: &str = "model_list";
const ACTION_MODEL_DETAIL: &str = "model_detail";
const ACTION_MODEL_REGISTERED: &str = "model_registered";
const ACTION_MODEL_APPROVED: &str = "model_approved";
const ACTION_MODEL_REJECTED: &str = "model_rejected";
const ACTION_MODEL_ACTIVATED: &str = "model_activated";
const ACTION_MODEL_ROLLED_BACK: &str = "model_rolled_back";
const ACTION_MODEL_SHADOW_EVALUATION_RECORDED: &str = "model_shadow_evaluation_recorded";

const RESOURCE_INLINE_ML_MODEL: &str = "inline_ml_model";
const RESOURCE_INLINE_ML_SHADOW_EVALUATION: &str = "inline_ml_shadow_evaluation";

const APPROVAL_PENDING: &str = "pending";
const APPROVAL_APPROVED: &str = "approved";
const APPROVAL_REJECTED: &str = "rejected";

const DEACTIVATION_SUPERSEDED: &str = "superseded";
const DEACTIVATION_ROLLBACK: &str = "rollback";

const ADVISORY_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtext($1))";

const MODEL_COLUMNS: &str = "id, deployment_id, model_id, model_version, \
     input_schema_version, training_dataset_version, code_commit, metrics, \
     artifact_uri, artifact_sha256, deployment_regions, approval_state, \
     approved_by, approved_at, approval_note, activated_at, activated_by, \
     deactivated_at, deactivated_by, deactivation_reason, rollback_model_id, \
     rollback_model_version, registered_by, registered_at, updated_at";

const SELECT_MODEL_SQL: &str = "SELECT {cols} FROM inline_ml_models \
     WHERE deployment_id = $1 AND model_id = $2 AND model_version = $3 FOR UPDATE";
const SELECT_MODEL_READ_SQL: &str = "SELECT {cols} FROM inline_ml_models \
     WHERE deployment_id = $1 AND model_id = $2 AND model_version = $3";
const SELECT_ACTIVE_SQL: &str = "SELECT {cols} FROM inline_ml_models \
     WHERE deployment_id = $1 AND activated_at IS NOT NULL AND deactivated_at IS NULL FOR UPDATE";
const LIST_SQL: &str = "SELECT {cols} FROM inline_ml_models \
     WHERE deployment_id = $1 ORDER BY model_id, model_version, registered_at";
const INSERT_MODEL_SQL: &str = "INSERT INTO inline_ml_models \
     (deployment_id, model_id, model_version, input_schema_version, \
      training_dataset_version, code_commit, metrics, artifact_uri, \
      artifact_sha256, deployment_regions, approval_state, registered_by) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
     RETURNING {cols}";
const APPROVE_SQL: &str = "UPDATE inline_ml_models \
     SET approval_state = $2, approved_by = $3, approved_at = now(), updated_at = now() \
     WHERE id = $1 RETURNING {cols}";
const REJECT_SQL: &str = "UPDATE inline_ml_models \
     SET approval_state = $2, approval_note = $3, updated_at = now() \
     WHERE id = $1 RETURNING {cols}";
const DEACTIVATE_SQL: &str = "UPDATE inline_ml_models \
     SET deactivated_at = now(), deactivated_by = $2, deactivation_reason = $3, \
         updated_at = now() \
     WHERE id = $1 AND deactivated_at IS NULL RETURNING {cols}";
const ACTIVATE_SQL: &str = "UPDATE inline_ml_models \
     SET activated_at = now(), activated_by = $2, \
         deactivated_at = NULL, deactivated_by = NULL, deactivation_reason = NULL, \
         rollback_model_id = $3, rollback_model_version = $4, updated_at = now() \
     WHERE id = $1 RETURNING {cols}";
const SHADOW_EVALUATION_COLUMNS: &str = "id, deployment_id, candidate_model_id, \
     candidate_model_version, active_model_id, active_model_version, input_schema_version, \
     evaluation_set_id, metrics, comparison, result, created_by, created_at";
const LIST_SHADOW_EVALUATIONS_SQL: &str = "SELECT {cols} FROM inline_ml_shadow_evaluations \
     WHERE deployment_id = $1 AND candidate_model_id = $2 AND candidate_model_version = $3 \
     ORDER BY created_at DESC, id DESC LIMIT 25";
const INSERT_SHADOW_EVALUATION_SQL: &str = "INSERT INTO inline_ml_shadow_evaluations \
     (deployment_id, candidate_model_id, candidate_model_version, active_model_id, \
      active_model_version, input_schema_version, evaluation_set_id, metrics, comparison, \
      result, created_by) \
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING {cols}";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ModelRegistryState(Arc<ModelRegistryStateInner>);

struct ModelRegistryStateInner {
    pool: PgPool,
    deployment_id: DeploymentId,
    audit: Arc<dyn AuditStore>,
    high_risk_limiter: Mutex<TokenBucket>,
}

impl ModelRegistryState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self(Arc::new(ModelRegistryStateInner {
            audit: Arc::new(PostgresAuditStore::new(pool.clone())),
            high_risk_limiter: Mutex::new(TokenBucket::new(&HighRiskLimits::permission_change())),
            pool,
            deployment_id,
        }))
    }
}

// ---------------------------------------------------------------------------
// Request/response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ApiEnvelope<T> {
    data: T,
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ApprovalState {
    Pending,
    Approved,
    Rejected,
}

impl ApprovalState {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => APPROVAL_PENDING,
            Self::Approved => APPROVAL_APPROVED,
            Self::Rejected => APPROVAL_REJECTED,
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            APPROVAL_PENDING => Some(Self::Pending),
            APPROVAL_APPROVED => Some(Self::Approved),
            APPROVAL_REJECTED => Some(Self::Rejected),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct ModelRecord {
    id: Uuid,
    model_id: String,
    model_version: String,
    input_schema_version: i32,
    training_dataset_version: String,
    code_commit: String,
    metrics: Value,
    artifact_uri: String,
    artifact_sha256: String,
    deployment_regions: Vec<String>,
    approval_state: String,
    approved_by: Option<String>,
    approved_at: Option<DateTime<Utc>>,
    approval_note: Option<String>,
    activated_at: Option<DateTime<Utc>>,
    activated_by: Option<String>,
    deactivated_at: Option<DateTime<Utc>>,
    deactivated_by: Option<String>,
    deactivation_reason: Option<String>,
    rollback_model_id: Option<String>,
    rollback_model_version: Option<String>,
    registered_by: String,
    registered_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// sqlx's `macros` feature is intentionally off in this workspace (rows are
/// tuples elsewhere); the registry row is read field-by-field by column
/// name, which keeps the mapping explicit and drift-checked by the tests.
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ModelRecord {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            model_id: row.try_get("model_id")?,
            model_version: row.try_get("model_version")?,
            input_schema_version: row.try_get("input_schema_version")?,
            training_dataset_version: row.try_get("training_dataset_version")?,
            code_commit: row.try_get("code_commit")?,
            metrics: row.try_get("metrics")?,
            artifact_uri: row.try_get("artifact_uri")?,
            artifact_sha256: row.try_get("artifact_sha256")?,
            deployment_regions: row.try_get("deployment_regions")?,
            approval_state: row.try_get("approval_state")?,
            approved_by: row.try_get("approved_by")?,
            approved_at: row.try_get("approved_at")?,
            approval_note: row.try_get("approval_note")?,
            activated_at: row.try_get("activated_at")?,
            activated_by: row.try_get("activated_by")?,
            deactivated_at: row.try_get("deactivated_at")?,
            deactivated_by: row.try_get("deactivated_by")?,
            deactivation_reason: row.try_get("deactivation_reason")?,
            rollback_model_id: row.try_get("rollback_model_id")?,
            rollback_model_version: row.try_get("rollback_model_version")?,
            registered_by: row.try_get("registered_by")?,
            registered_at: row.try_get("registered_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Clone)]
struct ShadowEvaluationRecord {
    id: Uuid,
    candidate_model_id: String,
    candidate_model_version: String,
    active_model_id: Option<String>,
    active_model_version: Option<String>,
    input_schema_version: i32,
    evaluation_set_id: String,
    metrics: Value,
    comparison: Value,
    result: String,
    created_by: String,
    created_at: DateTime<Utc>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ShadowEvaluationRecord {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            candidate_model_id: row.try_get("candidate_model_id")?,
            candidate_model_version: row.try_get("candidate_model_version")?,
            active_model_id: row.try_get("active_model_id")?,
            active_model_version: row.try_get("active_model_version")?,
            input_schema_version: row.try_get("input_schema_version")?,
            evaluation_set_id: row.try_get("evaluation_set_id")?,
            metrics: row.try_get("metrics")?,
            comparison: row.try_get("comparison")?,
            result: row.try_get("result")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Serialize)]
struct ModelResponse {
    id: Uuid,
    model_id: String,
    model_version: String,
    input_schema_version: i32,
    training_dataset_version: String,
    code_commit: String,
    metrics: Value,
    artifact_uri: String,
    artifact_sha256: String,
    deployment_regions: Vec<String>,
    approval_state: ApprovalState,
    approved_by: Option<String>,
    approved_at: Option<DateTime<Utc>>,
    approval_note: Option<String>,
    activated_at: Option<DateTime<Utc>>,
    activated_by: Option<String>,
    deactivated_at: Option<DateTime<Utc>>,
    deactivated_by: Option<String>,
    deactivation_reason: Option<String>,
    rollback_model_id: Option<String>,
    rollback_model_version: Option<String>,
    registered_by: String,
    registered_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<ModelRecord> for ModelResponse {
    type Error = ();

    fn try_from(record: ModelRecord) -> Result<Self, Self::Error> {
        let approval_state = ApprovalState::parse(&record.approval_state).ok_or(())?;
        Ok(Self {
            id: record.id,
            model_id: record.model_id,
            model_version: record.model_version,
            input_schema_version: record.input_schema_version,
            training_dataset_version: record.training_dataset_version,
            code_commit: record.code_commit,
            metrics: record.metrics,
            artifact_uri: record.artifact_uri,
            artifact_sha256: record.artifact_sha256,
            deployment_regions: record.deployment_regions,
            approval_state,
            approved_by: record.approved_by,
            approved_at: record.approved_at,
            approval_note: record.approval_note,
            activated_at: record.activated_at,
            activated_by: record.activated_by,
            deactivated_at: record.deactivated_at,
            deactivated_by: record.deactivated_by,
            deactivation_reason: record.deactivation_reason,
            rollback_model_id: record.rollback_model_id,
            rollback_model_version: record.rollback_model_version,
            registered_by: record.registered_by,
            registered_at: record.registered_at,
            updated_at: record.updated_at,
        })
    }
}

#[derive(Serialize)]
struct ShadowEvaluationResponse {
    id: Uuid,
    candidate_model_id: String,
    candidate_model_version: String,
    active_model_id: Option<String>,
    active_model_version: Option<String>,
    input_schema_version: i32,
    evaluation_set_id: String,
    metrics: Value,
    comparison: Value,
    result: String,
    created_by: String,
    created_at: DateTime<Utc>,
}

impl From<ShadowEvaluationRecord> for ShadowEvaluationResponse {
    fn from(record: ShadowEvaluationRecord) -> Self {
        Self {
            id: record.id,
            candidate_model_id: record.candidate_model_id,
            candidate_model_version: record.candidate_model_version,
            active_model_id: record.active_model_id,
            active_model_version: record.active_model_version,
            input_schema_version: record.input_schema_version,
            evaluation_set_id: record.evaluation_set_id,
            metrics: record.metrics,
            comparison: record.comparison,
            result: record.result,
            created_by: record.created_by,
            created_at: record.created_at,
        }
    }
}

#[derive(Serialize)]
struct ShadowEvaluationListResponse {
    evaluations: Vec<ShadowEvaluationResponse>,
}

#[derive(Serialize)]
struct ModelListResponse {
    models: Vec<ModelResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    model_id: String,
    model_version: String,
    input_schema_version: i32,
    training_dataset_version: String,
    code_commit: String,
    metrics: Value,
    artifact_uri: String,
    artifact_sha256: String,
    #[serde(default)]
    deployment_regions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectBody {
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowEvaluationBody {
    evaluation_set_id: String,
    active_model_id: Option<String>,
    active_model_version: Option<String>,
    input_schema_version: i32,
    metrics: Value,
    comparison: Value,
    result: String,
}

// ---------------------------------------------------------------------------
// Route/denial/authorization helpers
// ---------------------------------------------------------------------------

struct Route {
    action: &'static str,
    resource_type: &'static str,
    resource_id: Option<String>,
    permission: &'static str,
}

impl Route {
    fn new(action: &'static str, resource_type: &'static str, permission: &'static str) -> Self {
        Self {
            action,
            resource_type,
            resource_id: None,
            permission,
        }
    }

    fn with_resource(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }
}

struct Denial {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    reason: String,
}

impl Denial {
    fn forbidden(reason: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "FORBIDDEN",
            message: "Permission is required",
            reason: reason.into(),
        }
    }

    fn missing_permission(permission: &str) -> Self {
        Self::forbidden(format!("missing {permission} permission"))
    }

    fn step_up_required() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "STEP_UP_REQUIRED",
            message: "Step-up authentication is required",
            reason: "step-up authentication expired".to_string(),
        }
    }
}

fn has_permission(context: &TenantContext, permission: &str) -> bool {
    context
        .permissions
        .iter()
        .any(|granted| granted == permission)
}

fn has_role(context: &TenantContext, role: &str) -> bool {
    context.actor.roles.iter().any(|granted| granted == role)
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

fn unauthenticated() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "UNAUTHENTICATED",
        "Authentication is required",
    )
}

fn invalid_request() -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "INVALID_REQUEST",
        "Request is invalid",
    )
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        "Service is unavailable",
    )
}

fn not_found(message: &'static str) -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", message)
}

fn conflict(message: &'static str) -> Response {
    api_error(StatusCode::CONFLICT, "CONFLICT", message)
}

fn envelope<T: Serialize>(data: &T) -> Option<Value> {
    serde_json::to_value(ApiEnvelope { data }).ok()
}

fn replay_response(value: Value) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

/// Audits a denial (observability only; the response is a denial either way,
/// so an audit write failure never changes the outcome) and returns it.
async fn denied(
    state: &ModelRegistryState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route,
    denial: &Denial,
) -> Response {
    let record = audit_record(
        context,
        headers,
        "denied",
        AuditFields {
            action: route.action,
            resource_type: route.resource_type,
            resource_id: route.resource_id.clone(),
            customer_id: context.customer_id.0.clone(),
            details: json!({ "reason": denial.reason }),
        },
    );
    if let Err(error) = state
        .0
        .audit
        .record_event(&state.0.deployment_id.0, record)
        .await
    {
        error!(%error, "failed to audit model registry denial");
    }
    api_error(denial.status, denial.code, denial.message)
}

/// Permission, lifecycle, then deployment — in that order, before any rate
/// limit, audit, or transaction work.
async fn authorize(
    state: &ModelRegistryState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route,
) -> Result<(), Response> {
    if !has_permission(context, route.permission) {
        return Err(denied(
            state,
            context,
            headers,
            route,
            &Denial::missing_permission(route.permission),
        )
        .await);
    }
    if context.customer_lifecycle != CustomerLifecycle::Active {
        return Err(denied(
            state,
            context,
            headers,
            route,
            &Denial::forbidden("customer lifecycle is not active"),
        )
        .await);
    }
    if context.deployment_id != state.0.deployment_id {
        return Err(denied(
            state,
            context,
            headers,
            route,
            &Denial::forbidden("deployment mismatch"),
        )
        .await);
    }
    Ok(())
}

/// The registry is system-scoped: every state transition needs the
/// `system_admin` role even when the permission was granted some other way.
async fn require_system_admin(
    state: &ModelRegistryState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route,
) -> Result<(), Response> {
    if !has_role(context, SYSTEM_ADMIN_ROLE) {
        return Err(denied(
            state,
            context,
            headers,
            route,
            &Denial::forbidden("model registry changes require the system administrator role"),
        )
        .await);
    }
    Ok(())
}

/// Fresh step-up, then the shared fail-closed budget. Used by the
/// runtime-affecting transitions (approve, activate, rollback); registration
/// and rejection never change what runs.
async fn require_high_risk(
    state: &ModelRegistryState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route,
) -> Result<(), Response> {
    if !context.has_step_up() {
        return Err(denied(state, context, headers, route, &Denial::step_up_required()).await);
    }
    let allowed = state
        .0
        .high_risk_limiter
        .lock()
        .map(|mut bucket| bucket.try_consume())
        .unwrap_or(false);
    if !allowed {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "60")],
            Json(ApiErrorBody {
                code: "RATE_LIMITED",
                message: "Too many high-risk changes",
            }),
        )
            .into_response());
    }
    Ok(())
}

enum IdempotencyRejection {
    Missing,
    Invalid,
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

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

struct AuditFields<'a> {
    action: &'a str,
    resource_type: &'a str,
    resource_id: Option<String>,
    customer_id: String,
    details: Value,
}

fn audit_record(
    context: &TenantContext,
    headers: &HeaderMap,
    result: &str,
    fields: AuditFields<'_>,
) -> AuditEventRecord {
    let (impersonated_subject, impersonated_customer) = match &context.impersonation {
        Some(impersonation) => (
            impersonation.impersonated_subject.clone(),
            Some(impersonation.impersonated_customer.0.clone()),
        ),
        None => (None, None),
    };
    AuditEventRecord {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        actor_id: context.actor.actor_id.0.to_string(),
        actor_login: context.actor.login.clone(),
        actor_roles: context.actor.roles.clone(),
        impersonated_subject,
        impersonated_customer,
        customer_id: Some(fields.customer_id),
        action: fields.action.to_string(),
        resource_type: fields.resource_type.to_string(),
        resource_id: fields.resource_id,
        result: result.to_string(),
        source_ip: source_ip_from(headers),
        session_id: Some(context.session_id.clone()),
        trace_id: context.trace_id.clone(),
        details: fields.details,
    }
}

/// Writes the audit row in the caller's transaction: the mutation and its
/// evidence commit together or not at all.
async fn write_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &DeploymentId,
    context: &TenantContext,
    headers: &HeaderMap,
    result: &str,
    fields: AuditFields<'_>,
) -> Result<(), Response> {
    // The audit row's tenant attribution must satisfy its own RLS check, so
    // the tenant GUC is re-asserted immediately before the insert.
    sqlx::query(
        "SELECT set_config('app.current_customer_id', $1, true), \
                set_config('app.current_deployment_id', $2, true)",
    )
    .bind(&fields.customer_id)
    .bind(&deployment_id.0)
    .execute(&mut **transaction)
    .await
    .map_err(|_| unavailable())?;
    let record = audit_record(context, headers, result, fields);
    PostgresAuditStore::insert_record(transaction, &deployment_id.0, &record)
        .await
        .map_err(|_| unavailable())
}

// ---------------------------------------------------------------------------
// Transaction helpers
// ---------------------------------------------------------------------------

async fn begin_claim(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
    operation: &str,
) -> Result<ClaimOutcome, Response> {
    claim(transaction, key, operation)
        .await
        .map_err(|_| unavailable())
}

/// Serializes registry mutations. Model-scoped transitions lock one model;
/// activation and rollback lock a deployment-wide key so the single-active
/// invariant cannot race.
async fn lock_registry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lock_key: &str,
) -> Result<(), Response> {
    sqlx::query(ADVISORY_LOCK_SQL)
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(|_| unavailable())
}

fn model_lock_key(model_id: &str, model_version: &str) -> String {
    format!("inline_ml_model:{model_id}:{model_version}")
}

fn activation_lock_key(deployment_id: &str) -> String {
    format!("inline_ml_models:{deployment_id}")
}

async fn select_model(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    model_id: &str,
    model_version: &str,
) -> Result<Option<ModelRecord>, Response> {
    let sql = SELECT_MODEL_SQL.replace("{cols}", MODEL_COLUMNS);
    sqlx::query_as::<_, ModelRecord>(&sql)
        .bind(deployment_id)
        .bind(model_id)
        .bind(model_version)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| unavailable())
}

async fn select_active(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
) -> Result<Option<ModelRecord>, Response> {
    let sql = SELECT_ACTIVE_SQL.replace("{cols}", MODEL_COLUMNS);
    sqlx::query_as::<_, ModelRecord>(&sql)
        .bind(deployment_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| unavailable())
}

/// Async like every other `Result<_, Response>` helper in this codebase so
/// the large error type stays inside a future, not a sync signature.
async fn response_from_record(record: ModelRecord) -> Result<ModelResponse, Response> {
    ModelResponse::try_from(record).map_err(|_| unavailable())
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Model references are path identifiers: ASCII alphanumeric plus `-`, `_`
/// and `.`, never empty, never longer than the configured bound.
fn valid_model_ref(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

fn valid_commit(value: &str) -> bool {
    (7..=40).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn has_control_characters(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn valid_dataset_version(value: &str) -> bool {
    let trimmed = value.trim();
    !value.is_empty()
        && trimmed == value
        && value.len() <= DATASET_VERSION_MAX_LEN
        && !has_control_characters(value)
}

fn valid_artifact_uri(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= ARTIFACT_URI_MAX_LEN
        && !value.chars().any(char::is_whitespace)
        && !has_control_characters(value)
}

fn valid_regions(regions: &[String]) -> bool {
    !regions.is_empty()
        && regions.len() <= REGIONS_MAX_COUNT
        && regions.iter().all(|region| valid_model_ref(region, 64))
        && regions.iter().collect::<HashSet<_>>().len() == regions.len()
}

fn valid_metrics(metrics: &Value) -> bool {
    match metrics {
        Value::Object(map) => {
            !map.is_empty()
                && serde_json::to_vec(metrics)
                    .map(|bytes| bytes.len() <= METRICS_MAX_BYTES)
                    .unwrap_or(false)
        },
        _ => false,
    }
}

fn valid_evaluation_set_id(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed == value
        && value.len() <= EVALUATION_SET_ID_MAX_LEN
        && !has_control_characters(value)
}

fn valid_shadow_result(value: &str) -> bool {
    matches!(
        value,
        "candidate_better" | "candidate_worse" | "inconclusive" | "rollback_rehearsed"
    )
}

fn valid_json_object(value: &Value) -> bool {
    matches!(value, Value::Object(map) if !map.is_empty())
        && serde_json::to_vec(value)
            .map(|bytes| bytes.len() <= METRICS_MAX_BYTES)
            .unwrap_or(false)
}

fn valid_note(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() >= APPROVAL_NOTE_MIN_LEN
        && trimmed.len() <= APPROVAL_NOTE_MAX_LEN
        && !has_control_characters(value)
}

/// The approval state machine: pending may be approved or rejected, and
/// approval/rejection are terminal. The row is locked when this runs, and
/// the database re-checks that only approved models were ever activated.
fn approval_transition_allowed(current: &str, target: &ApprovalState) -> bool {
    match current {
        APPROVAL_PENDING => matches!(target, ApprovalState::Approved | ApprovalState::Rejected),
        _ => false,
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.constraint() == Some("inline_ml_models_unique_version"))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn model_registry_router(state: ModelRegistryState) -> Router {
    Router::new()
        .route(ADMIN_MODELS_PATH, get(list_models).post(register_model))
        .route(ADMIN_MODEL_PATH, get(get_model))
        .route(ADMIN_MODEL_APPROVE_PATH, post(approve_model))
        .route(ADMIN_MODEL_REJECT_PATH, post(reject_model))
        .route(ADMIN_MODEL_ACTIVATE_PATH, post(activate_model))
        .route(ADMIN_MODEL_ROLLBACK_PATH, post(rollback_model))
        .route(
            ADMIN_MODEL_SHADOW_EVALUATIONS_PATH,
            get(list_shadow_evaluations).post(record_shadow_evaluation),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers — reads
// ---------------------------------------------------------------------------

async fn list_models(
    State(state): State<ModelRegistryState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let route = Route::new(
        ACTION_MODEL_LIST,
        RESOURCE_INLINE_ML_MODEL,
        MODELS_VIEW_PERMISSION,
    );
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        return response;
    }
    let sql = LIST_SQL.replace("{cols}", MODEL_COLUMNS);
    let records = match sqlx::query_as::<_, ModelRecord>(&sql)
        .bind(&state.0.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(records) => records,
        Err(_) => return unavailable(),
    };
    let mut models = Vec::with_capacity(records.len());
    for record in records {
        match response_from_record(record).await {
            Ok(response) => models.push(response),
            Err(response) => return response,
        }
    }
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: ModelListResponse { models },
        }),
    )
        .into_response()
}

async fn get_model(
    State(state): State<ModelRegistryState>,
    Path((model_id, model_version)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_model_ref(&model_id, MODEL_ID_MAX_LEN)
        || !valid_model_ref(&model_version, MODEL_VERSION_MAX_LEN)
    {
        return not_found("Model was not found");
    }
    let route = Route::new(
        ACTION_MODEL_DETAIL,
        RESOURCE_INLINE_ML_MODEL,
        MODELS_VIEW_PERMISSION,
    )
    .with_resource(format!("{model_id}:{model_version}"));
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        return response;
    }
    let sql = SELECT_MODEL_READ_SQL.replace("{cols}", MODEL_COLUMNS);
    let record = match sqlx::query_as::<_, ModelRecord>(&sql)
        .bind(&state.0.deployment_id.0)
        .bind(&model_id)
        .bind(&model_version)
        .fetch_optional(&mut *transaction)
        .await
    {
        Ok(record) => record,
        Err(_) => return unavailable(),
    };
    let Some(record) = record else {
        return not_found("Model was not found");
    };
    let response = match response_from_record(record).await {
        Ok(response) => response,
        Err(response) => return response,
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    (StatusCode::OK, Json(ApiEnvelope { data: response })).into_response()
}

async fn list_shadow_evaluations(
    State(state): State<ModelRegistryState>,
    Path((model_id, model_version)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_model_ref(&model_id, MODEL_ID_MAX_LEN)
        || !valid_model_ref(&model_version, MODEL_VERSION_MAX_LEN)
    {
        return not_found("Model was not found");
    }
    let route = Route::new(
        ACTION_MODEL_DETAIL,
        RESOURCE_INLINE_ML_SHADOW_EVALUATION,
        MODELS_VIEW_PERMISSION,
    )
    .with_resource(format!("{model_id}:{model_version}"));
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        return response;
    }
    let model_exists = match select_model(
        &mut transaction,
        &state.0.deployment_id.0,
        &model_id,
        &model_version,
    )
    .await
    {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(response) => return response,
    };
    if !model_exists {
        return not_found("Model was not found");
    }
    let sql = LIST_SHADOW_EVALUATIONS_SQL.replace("{cols}", SHADOW_EVALUATION_COLUMNS);
    let rows = match sqlx::query_as::<_, ShadowEvaluationRecord>(&sql)
        .bind(&state.0.deployment_id.0)
        .bind(&model_id)
        .bind(&model_version)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: ShadowEvaluationListResponse {
                evaluations: rows
                    .into_iter()
                    .map(ShadowEvaluationResponse::from)
                    .collect(),
            },
        }),
    )
        .into_response()
}

async fn record_shadow_evaluation(
    State(state): State<ModelRegistryState>,
    Path((model_id, model_version)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<ShadowEvaluationBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    if !valid_model_ref(&model_id, MODEL_ID_MAX_LEN)
        || !valid_model_ref(&model_version, MODEL_VERSION_MAX_LEN)
        || !valid_evaluation_set_id(&body.evaluation_set_id)
        || !(1..=INPUT_SCHEMA_VERSION_MAX).contains(&body.input_schema_version)
        || !valid_json_object(&body.metrics)
        || !valid_json_object(&body.comparison)
        || !valid_shadow_result(&body.result)
        || body
            .active_model_id
            .as_ref()
            .is_some_and(|value| !valid_model_ref(value, MODEL_ID_MAX_LEN))
        || body
            .active_model_version
            .as_ref()
            .is_some_and(|value| !valid_model_ref(value, MODEL_VERSION_MAX_LEN))
        || body.active_model_id.is_some() != body.active_model_version.is_some()
    {
        return invalid_request();
    }
    let route = Route::new(
        ACTION_MODEL_SHADOW_EVALUATION_RECORDED,
        RESOURCE_INLINE_ML_SHADOW_EVALUATION,
        MODELS_MANAGE_PERMISSION,
    )
    .with_resource(format!("{model_id}:{model_version}"));
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_system_admin(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        return response;
    }
    let operation = format!("model:shadow-evaluation:{model_id}:{model_version}");
    let outcome = match begin_claim(&mut transaction, &key, &operation).await {
        Ok(outcome) => outcome,
        Err(response) => return response,
    };
    match outcome {
        ClaimOutcome::Fresh => {},
        ClaimOutcome::Replay(value) => return replay_response(value),
        ClaimOutcome::InProgress => return conflict("Request is already in progress"),
        ClaimOutcome::OperationMismatch => return invalid_request(),
    }
    let candidate = match select_model(
        &mut transaction,
        &state.0.deployment_id.0,
        &model_id,
        &model_version,
    )
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("Model was not found"),
        Err(response) => return response,
    };
    if candidate.input_schema_version != body.input_schema_version {
        return invalid_request();
    }
    if let (Some(active_model_id), Some(active_model_version)) =
        (&body.active_model_id, &body.active_model_version)
    {
        let active = match select_model(
            &mut transaction,
            &state.0.deployment_id.0,
            active_model_id,
            active_model_version,
        )
        .await
        {
            Ok(Some(record)) => record,
            Ok(None) => return invalid_request(),
            Err(response) => return response,
        };
        if active.activated_at.is_none() || active.deactivated_at.is_some() {
            return invalid_request();
        }
    }
    let sql = INSERT_SHADOW_EVALUATION_SQL.replace("{cols}", SHADOW_EVALUATION_COLUMNS);
    let row = match sqlx::query_as::<_, ShadowEvaluationRecord>(&sql)
        .bind(&state.0.deployment_id.0)
        .bind(&model_id)
        .bind(&model_version)
        .bind(&body.active_model_id)
        .bind(&body.active_model_version)
        .bind(body.input_schema_version)
        .bind(&body.evaluation_set_id)
        .bind(sqlx::types::Json(body.metrics.clone()))
        .bind(sqlx::types::Json(body.comparison.clone()))
        .bind(&body.result)
        .bind(context.actor.actor_id.0.to_string())
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_MODEL_SHADOW_EVALUATION_RECORDED,
            resource_type: RESOURCE_INLINE_ML_SHADOW_EVALUATION,
            resource_id: Some(format!("{model_id}:{model_version}")),
            customer_id: context.customer_id.0.clone(),
            details: json!({
                "candidate_model_id": model_id,
                "candidate_model_version": model_version,
                "active_model_id": body.active_model_id,
                "active_model_version": body.active_model_version,
                "evaluation_set_id": body.evaluation_set_id,
                "result": body.result,
            }),
        },
    )
    .await
    {
        return response;
    }
    let response = ShadowEvaluationResponse::from(row);
    let Some(value) = envelope(&response) else {
        return unavailable();
    };
    if complete(&mut transaction, &key, &operation, value)
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

// ---------------------------------------------------------------------------
// Handlers — registration
// ---------------------------------------------------------------------------

async fn register_model(
    State(state): State<ModelRegistryState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<RegisterBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    let model_id = body.model_id.trim().to_string();
    let model_version = body.model_version.trim().to_string();
    let regions = body
        .deployment_regions
        .unwrap_or_else(|| vec!["local".to_string()]);
    if !valid_model_ref(&model_id, MODEL_ID_MAX_LEN)
        || !valid_model_ref(&model_version, MODEL_VERSION_MAX_LEN)
        || !(1..=INPUT_SCHEMA_VERSION_MAX).contains(&body.input_schema_version)
        || !valid_dataset_version(&body.training_dataset_version)
        || !valid_commit(&body.code_commit)
        || !valid_metrics(&body.metrics)
        || !valid_artifact_uri(&body.artifact_uri)
        || !valid_sha256(&body.artifact_sha256)
        || !valid_regions(&regions)
    {
        return invalid_request();
    }
    let route = Route::new(
        ACTION_MODEL_REGISTERED,
        RESOURCE_INLINE_ML_MODEL,
        MODELS_MANAGE_PERMISSION,
    )
    .with_resource(format!("{model_id}:{model_version}"));
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_system_admin(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        return response;
    }
    let operation = format!("model:register:{model_id}:{model_version}");
    let outcome = match begin_claim(&mut transaction, &key, &operation).await {
        Ok(outcome) => outcome,
        Err(response) => return response,
    };
    match outcome {
        ClaimOutcome::Fresh => {},
        ClaimOutcome::Replay(value) => return replay_response(value),
        ClaimOutcome::InProgress => return conflict("Request is already in progress"),
        ClaimOutcome::OperationMismatch => return invalid_request(),
    }
    if let Err(response) =
        lock_registry(&mut transaction, &model_lock_key(&model_id, &model_version)).await
    {
        return response;
    }
    let sql = INSERT_MODEL_SQL.replace("{cols}", MODEL_COLUMNS);
    let record = match sqlx::query_as::<_, ModelRecord>(&sql)
        .bind(&state.0.deployment_id.0)
        .bind(&model_id)
        .bind(&model_version)
        .bind(body.input_schema_version)
        .bind(&body.training_dataset_version)
        .bind(&body.code_commit)
        .bind(sqlx::types::Json(body.metrics.clone()))
        .bind(&body.artifact_uri)
        .bind(&body.artifact_sha256)
        .bind(&regions)
        .bind(APPROVAL_PENDING)
        .bind(context.actor.actor_id.0.to_string())
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(record) => record,
        Err(error) if is_unique_violation(&error) => {
            return conflict("Model version is already registered");
        },
        Err(_) => return unavailable(),
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_MODEL_REGISTERED,
            resource_type: RESOURCE_INLINE_ML_MODEL,
            resource_id: Some(format!("{model_id}:{model_version}")),
            customer_id: context.customer_id.0.clone(),
            details: json!({
                "model_id": model_id,
                "model_version": model_version,
                "input_schema_version": body.input_schema_version,
                "training_dataset_version": body.training_dataset_version,
                "code_commit": body.code_commit,
                "artifact_sha256": body.artifact_sha256,
            }),
        },
    )
    .await
    {
        return response;
    }
    let response = match response_from_record(record).await {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(value) = envelope(&response) else {
        return unavailable();
    };
    if complete(&mut transaction, &key, &operation, value)
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

// ---------------------------------------------------------------------------
// Handlers — approval state transitions
// ---------------------------------------------------------------------------

async fn approve_model(
    State(state): State<ModelRegistryState>,
    Path((model_id, model_version)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    approval_transition(
        state,
        (model_id, model_version),
        headers,
        context,
        ApprovalState::Approved,
        None,
    )
    .await
}

async fn reject_model(
    State(state): State<ModelRegistryState>,
    Path((model_id, model_version)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<RejectBody>, JsonRejection>,
) -> Response {
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    let reason = body.reason.trim().to_string();
    if !valid_note(&reason) {
        return invalid_request();
    }
    approval_transition(
        state,
        (model_id, model_version),
        headers,
        context,
        ApprovalState::Rejected,
        Some(reason),
    )
    .await
}

/// Shared approve/reject path: validate the reference, authorize, then in
/// one locked transaction re-read the row (the row, not the request, is the
/// state of record), check the transition matrix, update, audit and commit.
async fn approval_transition(
    state: ModelRegistryState,
    (model_id, model_version): (String, String),
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    target: ApprovalState,
    reason: Option<String>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_model_ref(&model_id, MODEL_ID_MAX_LEN)
        || !valid_model_ref(&model_version, MODEL_VERSION_MAX_LEN)
    {
        return not_found("Model was not found");
    }
    let action = match target {
        ApprovalState::Approved => ACTION_MODEL_APPROVED,
        ApprovalState::Rejected => ACTION_MODEL_REJECTED,
        ApprovalState::Pending => return invalid_request(),
    };
    let route = Route::new(action, RESOURCE_INLINE_ML_MODEL, MODELS_MANAGE_PERMISSION)
        .with_resource(format!("{model_id}:{model_version}"));
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_system_admin(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        return response;
    }
    let operation = format!("model:{}:{model_id}:{model_version}", target.as_str());
    let outcome = match begin_claim(&mut transaction, &key, &operation).await {
        Ok(outcome) => outcome,
        Err(response) => return response,
    };
    match outcome {
        ClaimOutcome::Fresh => {},
        ClaimOutcome::Replay(value) => return replay_response(value),
        ClaimOutcome::InProgress => return conflict("Request is already in progress"),
        ClaimOutcome::OperationMismatch => return invalid_request(),
    }
    if let Err(response) =
        lock_registry(&mut transaction, &model_lock_key(&model_id, &model_version)).await
    {
        return response;
    }
    let current = match select_model(
        &mut transaction,
        &state.0.deployment_id.0,
        &model_id,
        &model_version,
    )
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("Model was not found"),
        Err(response) => return response,
    };
    if !approval_transition_allowed(&current.approval_state, &target) {
        return conflict("Model approval transition is not allowed");
    }
    let sql = match target {
        ApprovalState::Approved => APPROVE_SQL,
        ApprovalState::Rejected => REJECT_SQL,
        ApprovalState::Pending => return invalid_request(),
    };
    let sql = sql.replace("{cols}", MODEL_COLUMNS);
    let record = match target {
        ApprovalState::Approved => {
            sqlx::query_as::<_, ModelRecord>(&sql)
                .bind(current.id)
                .bind(target.as_str())
                .bind(context.actor.actor_id.0.to_string())
                .fetch_one(&mut *transaction)
                .await
        },
        ApprovalState::Rejected => {
            sqlx::query_as::<_, ModelRecord>(&sql)
                .bind(current.id)
                .bind(target.as_str())
                .bind(reason.clone().unwrap_or_default())
                .fetch_one(&mut *transaction)
                .await
        },
        ApprovalState::Pending => return invalid_request(),
    };
    let record = match record {
        Ok(record) => record,
        Err(_) => return unavailable(),
    };
    let details = match target {
        ApprovalState::Approved => json!({
            "model_id": model_id,
            "model_version": model_version,
            "input_schema_version": current.input_schema_version,
            "training_dataset_version": current.training_dataset_version,
        }),
        ApprovalState::Rejected => json!({
            "model_id": model_id,
            "model_version": model_version,
            "reason": reason,
        }),
        ApprovalState::Pending => return invalid_request(),
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action,
            resource_type: RESOURCE_INLINE_ML_MODEL,
            resource_id: Some(format!("{model_id}:{model_version}")),
            customer_id: context.customer_id.0.clone(),
            details,
        },
    )
    .await
    {
        return response;
    }
    let response = match response_from_record(record).await {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(value) = envelope(&response) else {
        return unavailable();
    };
    if complete(&mut transaction, &key, &operation, value)
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

// ---------------------------------------------------------------------------
// Handlers — activation and rollback
// ---------------------------------------------------------------------------

async fn activate_model(
    State(state): State<ModelRegistryState>,
    Path((model_id, model_version)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_model_ref(&model_id, MODEL_ID_MAX_LEN)
        || !valid_model_ref(&model_version, MODEL_VERSION_MAX_LEN)
    {
        return not_found("Model was not found");
    }
    let route = Route::new(
        ACTION_MODEL_ACTIVATED,
        RESOURCE_INLINE_ML_MODEL,
        MODELS_MANAGE_PERMISSION,
    )
    .with_resource(format!("{model_id}:{model_version}"));
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_system_admin(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        return response;
    }
    let operation = format!("model:activate:{model_id}:{model_version}");
    let outcome = match begin_claim(&mut transaction, &key, &operation).await {
        Ok(outcome) => outcome,
        Err(response) => return response,
    };
    match outcome {
        ClaimOutcome::Fresh => {},
        ClaimOutcome::Replay(value) => return replay_response(value),
        ClaimOutcome::InProgress => return conflict("Request is already in progress"),
        ClaimOutcome::OperationMismatch => return invalid_request(),
    }
    if let Err(response) = lock_registry(
        &mut transaction,
        &activation_lock_key(&state.0.deployment_id.0),
    )
    .await
    {
        return response;
    }
    let target = match select_model(
        &mut transaction,
        &state.0.deployment_id.0,
        &model_id,
        &model_version,
    )
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("Model was not found"),
        Err(response) => return response,
    };
    let target_active = target.activated_at.is_some() && target.deactivated_at.is_none();
    if target_active {
        return conflict("Model is already active");
    }
    if target.approval_state != APPROVAL_APPROVED {
        return conflict("Model must be approved before activation");
    }
    let current = match select_active(&mut transaction, &state.0.deployment_id.0).await {
        Ok(current) => current,
        Err(response) => return response,
    };
    let mut previous = None;
    if let Some(current) = current.as_ref() {
        let sql = DEACTIVATE_SQL.replace("{cols}", MODEL_COLUMNS);
        if sqlx::query_as::<_, ModelRecord>(&sql)
            .bind(current.id)
            .bind(context.actor.actor_id.0.to_string())
            .bind(DEACTIVATION_SUPERSEDED)
            .fetch_one(&mut *transaction)
            .await
            .is_err()
        {
            return unavailable();
        }
        previous = Some(current.clone());
    }
    let (rollback_model_id, rollback_model_version) = match previous.as_ref() {
        Some(previous) => (
            Some(previous.model_id.clone()),
            Some(previous.model_version.clone()),
        ),
        None => (None, None),
    };
    let sql = ACTIVATE_SQL.replace("{cols}", MODEL_COLUMNS);
    let record = match sqlx::query_as::<_, ModelRecord>(&sql)
        .bind(target.id)
        .bind(context.actor.actor_id.0.to_string())
        .bind(&rollback_model_id)
        .bind(&rollback_model_version)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(record) => record,
        Err(_) => return unavailable(),
    };
    let details = json!({
        "model_id": model_id,
        "model_version": model_version,
        "previous_model_id": previous.as_ref().map(|row| row.model_id.clone()),
        "previous_model_version": previous.as_ref().map(|row| row.model_version.clone()),
    });
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_MODEL_ACTIVATED,
            resource_type: RESOURCE_INLINE_ML_MODEL,
            resource_id: Some(format!("{model_id}:{model_version}")),
            customer_id: context.customer_id.0.clone(),
            details,
        },
    )
    .await
    {
        return response;
    }
    let response = match response_from_record(record).await {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(value) = envelope(&response) else {
        return unavailable();
    };
    if complete(&mut transaction, &key, &operation, value)
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

async fn rollback_model(
    State(state): State<ModelRegistryState>,
    Path((model_id, model_version)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_model_ref(&model_id, MODEL_ID_MAX_LEN)
        || !valid_model_ref(&model_version, MODEL_VERSION_MAX_LEN)
    {
        return not_found("Model was not found");
    }
    // The path names the model being rolled *back to*; it must be the
    // deployment's recorded rollback target of the currently active model,
    // so a client cannot roll back to an arbitrary registered version.
    let route = Route::new(
        ACTION_MODEL_ROLLED_BACK,
        RESOURCE_INLINE_ML_MODEL,
        MODELS_MANAGE_PERMISSION,
    )
    .with_resource(format!("{model_id}:{model_version}"));
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_system_admin(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        return response;
    }
    let operation = format!(
        "model:rollback:{deployment}",
        deployment = state.0.deployment_id.0
    );
    let outcome = match begin_claim(&mut transaction, &key, &operation).await {
        Ok(outcome) => outcome,
        Err(response) => return response,
    };
    match outcome {
        ClaimOutcome::Fresh => {},
        ClaimOutcome::Replay(value) => return replay_response(value),
        ClaimOutcome::InProgress => return conflict("Request is already in progress"),
        ClaimOutcome::OperationMismatch => return invalid_request(),
    }
    if let Err(response) = lock_registry(
        &mut transaction,
        &activation_lock_key(&state.0.deployment_id.0),
    )
    .await
    {
        return response;
    }
    let active = match select_active(&mut transaction, &state.0.deployment_id.0).await {
        Ok(Some(active)) => active,
        Ok(None) => return conflict("There is no active model to roll back"),
        Err(response) => return response,
    };
    if active.activated_at.is_none() || active.deactivated_at.is_some() {
        return conflict("There is no active model to roll back");
    }
    let (Some(rollback_id), Some(rollback_version)) = (
        active.rollback_model_id.clone(),
        active.rollback_model_version.clone(),
    ) else {
        return conflict("The active model has no rollback target");
    };
    if rollback_id != model_id || rollback_version != model_version {
        return conflict("The requested model is not the active model's rollback target");
    }
    let target = match select_model(
        &mut transaction,
        &state.0.deployment_id.0,
        &model_id,
        &model_version,
    )
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("Model was not found"),
        Err(response) => return response,
    };
    if target.approval_state != APPROVAL_APPROVED {
        return conflict("Rollback target is not an approved model");
    }
    let sql = DEACTIVATE_SQL.replace("{cols}", MODEL_COLUMNS);
    if sqlx::query_as::<_, ModelRecord>(&sql)
        .bind(active.id)
        .bind(context.actor.actor_id.0.to_string())
        .bind(DEACTIVATION_ROLLBACK)
        .fetch_one(&mut *transaction)
        .await
        .is_err()
    {
        return unavailable();
    }
    let sql = ACTIVATE_SQL.replace("{cols}", MODEL_COLUMNS);
    let record = match sqlx::query_as::<_, ModelRecord>(&sql)
        .bind(target.id)
        .bind(context.actor.actor_id.0.to_string())
        .bind(&active.model_id)
        .bind(&active.model_version)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(record) => record,
        Err(_) => return unavailable(),
    };
    let details = json!({
        "activated_model_id": model_id,
        "activated_model_version": model_version,
        "deactivated_model_id": active.model_id,
        "deactivated_model_version": active.model_version,
    });
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_MODEL_ROLLED_BACK,
            resource_type: RESOURCE_INLINE_ML_MODEL,
            resource_id: Some(format!("{model_id}:{model_version}")),
            customer_id: context.customer_id.0.clone(),
            details,
        },
    )
    .await
    {
        return response;
    }
    let response = match response_from_record(record).await {
        Ok(response) => response,
        Err(response) => return response,
    };
    let Some(value) = envelope(&response) else {
        return unavailable();
    };
    if complete(&mut transaction, &key, &operation, value)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn regions(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn model_references_are_bounded_ascii_identifiers() {
        assert!(valid_model_ref("multilabel-v1", MODEL_ID_MAX_LEN));
        assert!(valid_model_ref("1.0.0", MODEL_VERSION_MAX_LEN));
        assert!(!valid_model_ref("", MODEL_ID_MAX_LEN));
        assert!(!valid_model_ref("model id", MODEL_ID_MAX_LEN));
        assert!(!valid_model_ref("model\nid", MODEL_ID_MAX_LEN));
        assert!(!valid_model_ref(
            &"x".repeat(MODEL_ID_MAX_LEN + 1),
            MODEL_ID_MAX_LEN
        ));
    }

    #[test]
    fn commit_and_digest_must_be_lowercase_hex() {
        assert!(valid_commit("18015b5"));
        assert!(valid_commit("239194c"));
        assert!(valid_commit(&"a".repeat(40)));
        assert!(!valid_commit("18015")); // too short
        assert!(!valid_commit(&"a".repeat(41))); // too long
        assert!(!valid_commit("ABCdef1")); // uppercase rejected
        assert!(!valid_commit("not-a-commit"));
        assert!(valid_sha256(&"0".repeat(SHA256_HEX_LEN)));
        assert!(!valid_sha256(&"0".repeat(SHA256_HEX_LEN - 1)));
        assert!(!valid_sha256(&"A".repeat(SHA256_HEX_LEN)));
    }

    #[test]
    fn metrics_must_be_a_non_empty_object_within_the_size_bound() {
        assert!(valid_metrics(&json!({"macro_f1": 0.9862})));
        assert!(!valid_metrics(&json!({})));
        assert!(!valid_metrics(&json!([1, 2, 3])));
        assert!(!valid_metrics(&json!("macro_f1")));
        let huge = json!({ "blob": "x".repeat(METRICS_MAX_BYTES + 16) });
        assert!(!valid_metrics(&huge));
    }

    #[test]
    fn regions_are_unique_bounded_identifiers() {
        assert!(valid_regions(&regions(&["local"])));
        assert!(valid_regions(&regions(&["local", "eu-central"])));
        assert!(!valid_regions(&regions(&[])));
        assert!(!valid_regions(&regions(&["local", "local"])));
        assert!(!valid_regions(&regions(&["local region"])));
        let too_many: Vec<String> = (0..REGIONS_MAX_COUNT + 1)
            .map(|index| format!("region-{index}"))
            .collect();
        assert!(!valid_regions(&too_many));
    }

    #[test]
    fn artifact_uri_and_dataset_version_reject_whitespace_and_controls() {
        assert!(valid_artifact_uri("ml/inline/checkpoints/multilabel-v1"));
        assert!(!valid_artifact_uri(""));
        assert!(!valid_artifact_uri("ml/inline/model id"));
        assert!(!valid_artifact_uri("ml/inline/model\tid"));
        assert!(valid_dataset_version("multilabel dataset v2"));
        assert!(!valid_dataset_version(" leading"));
        assert!(!valid_dataset_version("trailing "));
        assert!(!valid_dataset_version("bad\x1fversion"));
    }

    #[test]
    fn approval_notes_require_a_substantive_single_line_reason() {
        assert!(valid_note("duplicate of registered artifact"));
        assert!(!valid_note("short"));
        assert!(!valid_note(&"x".repeat(APPROVAL_NOTE_MAX_LEN + 1)));
        assert!(!valid_note("line one\nline two"));
    }

    #[test]
    fn approval_transitions_only_leave_pending() {
        assert!(approval_transition_allowed(
            APPROVAL_PENDING,
            &ApprovalState::Approved
        ));
        assert!(approval_transition_allowed(
            APPROVAL_PENDING,
            &ApprovalState::Rejected
        ));
        assert!(!approval_transition_allowed(
            APPROVAL_APPROVED,
            &ApprovalState::Rejected
        ));
        assert!(!approval_transition_allowed(
            APPROVAL_REJECTED,
            &ApprovalState::Approved
        ));
        assert!(!approval_transition_allowed(
            APPROVAL_APPROVED,
            &ApprovalState::Approved
        ));
    }

    #[test]
    fn approval_state_round_trips_through_snake_case_serde() {
        assert_eq!(
            serde_json::to_value(ApprovalState::Approved).unwrap(),
            json!("approved")
        );
        assert_eq!(
            ApprovalState::parse("pending"),
            Some(ApprovalState::Pending)
        );
        assert_eq!(
            ApprovalState::parse("rejected"),
            Some(ApprovalState::Rejected)
        );
        assert_eq!(ApprovalState::parse("unknown"), None);
        assert_eq!(ApprovalState::Approved.as_str(), "approved");
    }

    #[test]
    fn shadow_evaluation_inputs_are_bounded_and_enumerated() {
        assert!(valid_evaluation_set_id("shadow-eval-2026-10-04"));
        assert!(!valid_evaluation_set_id(""));
        assert!(!valid_evaluation_set_id(" leading"));
        assert!(!valid_evaluation_set_id("bad\nset"));
        assert!(!valid_evaluation_set_id(
            &"x".repeat(EVALUATION_SET_ID_MAX_LEN + 1)
        ));

        assert!(valid_shadow_result("candidate_better"));
        assert!(valid_shadow_result("candidate_worse"));
        assert!(valid_shadow_result("inconclusive"));
        assert!(valid_shadow_result("rollback_rehearsed"));
        assert!(!valid_shadow_result("activate_candidate"));

        assert!(valid_json_object(&json!({"macro_f1_delta": 0.021})));
        assert!(!valid_json_object(&json!({})));
        assert!(!valid_json_object(&json!("not an object")));
    }
}

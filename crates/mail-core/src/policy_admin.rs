//! Policy family administration and feature override management for the local
//! control plane.
//!
//! Every route runs: authenticated context, body validation, idempotency key,
//! permission/lifecycle/deployment authorization, the static family catalog
//! (an unknown family is a 404 before any query), the management-tier or
//! scope-role gate, the shared high-risk gate (fresh step-up, fail-closed
//! budget), and only then a database transaction.
//!
//! Security invariants:
//!
//! - revision scope is derived from the family's management level and the
//!   server-resolved tenant context, never from the request;
//! - a system-scope revision needs the deployment scope and a tenant-scope
//!   revision the customer scope, so a forgotten scope fails closed;
//! - a feature override can never disable a mandatory security floor;
//! - the caller's scope identity for an override is server-derived, so a
//!   client-supplied scope identifier can only produce a 400.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{rejection::JsonRejection, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use nullapart_mail_contracts::{
    policy::PolicyRule,
    rate_limit::{HighRiskLimits, TokenBucket},
    transaction::DeploymentId,
};
use nullapart_policy::{
    CustomerLifecycle, FeatureDefinition, FeatureEvaluator, FeatureId, FeatureOverride,
    FeatureValue, OverrideScope, TenantContext,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::admin_audit::{source_ip_from, AuditEventRecord, AuditStore, PostgresAuditStore};
use crate::admin_rbac::{BUILTIN_ROLES, SUPPORT_ROLE, SYSTEM_ADMIN_ROLE};
use crate::idempotency::{claim, complete, ClaimOutcome};

pub const POLICIES_VIEW_PERMISSION: &str = "policies:view";
pub const POLICIES_MANAGE_PERMISSION: &str = "policies:manage";

const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const FAMILY_KEY_MAX_LEN: usize = 64;
const FEATURE_ID_MAX_LEN: usize = 128;
const RULE_NAME_MAX_LEN: usize = 128;
const RULE_PRIORITY_MIN: i32 = -1000;
const RULE_PRIORITY_MAX: i32 = 1000;
const REASON_CODE_MAX_LEN: usize = 64;
const MAX_RULES: usize = 200;
const REASON_MIN_LEN: usize = 10;
const REASON_MAX_LEN: usize = 500;
const VALUE_MAX_LEN: usize = 256;
const TYPED_PREFIX: &str = "typed:";
const SYSTEM_SCOPE_ID: &str = "system";

const POLICIES_PATH: &str = "/api/v1/policies";
const POLICY_PATH: &str = "/api/v1/policies/:family_key";
const POLICY_REVISIONS_PATH: &str = "/api/v1/policies/:family_key/revisions";
const POLICY_REFRESH_PATH: &str = "/api/v1/policies/:family_key/refresh";
const FEATURES_PATH: &str = "/api/v1/features";
const FEATURE_OVERRIDE_PATH: &str = "/api/v1/features/:feature_id/overrides";

const ACTION_POLICY_LIST: &str = "policy_list";
const ACTION_POLICY_DETAIL: &str = "policy_detail";
const ACTION_FEATURE_LIST: &str = "feature_list";
const ACTION_POLICY_PUBLISHED: &str = "policy_published";
const ACTION_POLICY_REFRESHED: &str = "policy_refresh_requested";
const ACTION_FEATURE_OVERRIDE_CHANGED: &str = "feature_override_changed";

const RESOURCE_POLICY_FAMILY: &str = "policy_family";
const RESOURCE_FEATURE: &str = "feature";

const EVENT_CONFIG_CHANGED: &str = "config.changed";
const EVENT_FEATURE_CHANGED: &str = "feature.changed";

/// Every policy family with its management level, ordered by family key. It
/// mirrors the seeded `policy_families` rows so the offline tier gate and the
/// 404-before-database check need no query; the ignored database test asserts
/// the two cannot drift.
pub const POLICY_FAMILY_MANAGEMENT_LEVELS: [(&str, &str); 24] = [
    ("attachments", "customer"),
    ("authentication", "system"),
    ("bulk_sending", "support"),
    ("connection_security", "system"),
    ("connectors_remediation", "customer"),
    ("content_security", "system"),
    ("dmarc_bimi", "system"),
    ("geolocation", "support"),
    ("greylisting", "support"),
    ("impersonation", "system"),
    ("inbound_routing", "customer"),
    ("malware", "system"),
    ("ml_threat_classification", "support"),
    ("notifications", "support"),
    ("outbound_abuse", "support"),
    ("outbound_routing", "customer"),
    ("quarantine", "support"),
    ("recipient_controls", "support"),
    ("retention", "support"),
    ("sender_reputation", "support"),
    ("spam_filtering", "support"),
    ("transport_security", "system"),
    ("url_security", "system"),
    ("vip_protection", "support"),
];

const FAMILY_ACTIVE_SQL: &str = "SELECT f.family_key, f.description, f.management_level, \
     f.security_floor, r.revision_number, r.published_by, r.published_at, r.scope_level \
     FROM policy_families f \
     LEFT JOIN LATERAL ( \
         SELECT pr.revision_number, pr.published_by, pr.published_at, pr.scope_level \
         FROM policy_revisions pr \
         WHERE pr.family_id = f.family_key AND pr.deactivated_at IS NULL \
           AND pr.deployment_id = $1 \
           AND (pr.scope_level = 'system' OR pr.customer_id = $2) \
           AND pr.scope_level = \
             CASE WHEN f.management_level = 'system' THEN 'system' ELSE 'tenant' END \
         ORDER BY pr.revision_number DESC \
         LIMIT 1 \
     ) r ON true \
     WHERE ($3::TEXT IS NULL OR f.family_key = $3) \
     ORDER BY f.family_key";
const REVISION_COUNTS_SQL: &str = "SELECT family_id, count(*)::bigint FROM policy_revisions \
     WHERE family_id IS NOT NULL AND deployment_id = $1 \
       AND (scope_level = 'system' OR customer_id = $2) \
       AND ($3::TEXT IS NULL OR family_id = $3) \
     GROUP BY family_id";
const FAMILY_REVISIONS_SQL: &str = "SELECT revision_number, published_by, published_at, \
     scope_level, activated_at, deactivated_at, rules FROM policy_revisions \
     WHERE family_id = $1 AND deployment_id = $2 \
       AND (scope_level = 'system' OR customer_id = $3) \
     ORDER BY revision_number DESC \
     LIMIT 20";
const PUBLISH_NEXT_SQL: &str = "SELECT COALESCE(MAX(revision_number), 0) + 1 \
     FROM policy_revisions \
     WHERE family_id = $1 AND scope_level = $2 AND deployment_id = $3 \
       AND customer_id IS NOT DISTINCT FROM $4";
const PUBLISH_INSERT_SQL: &str = "INSERT INTO policy_revisions \
     (id, customer_id, deployment_id, family_id, scope_level, revision_number, rules, \
      published_by, published_at, activated_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now()) \
     RETURNING published_at";
const PUBLISH_DEACTIVATE_SQL: &str = "UPDATE policy_revisions SET deactivated_at = now() \
     WHERE family_id = $1 AND scope_level = $2 AND deployment_id = $3 \
       AND customer_id IS NOT DISTINCT FROM $4 \
       AND deactivated_at IS NULL AND id <> $5";
/// `config_revisions` is the read model behind the runtime operations
/// snapshot, so every publish must record its scope there in the same
/// transaction. RLS keeps the row inside the scope it names: a system row
/// requires a deployment context and a tenant row requires that tenant.
const CONFIG_REVISION_INSERT_SQL: &str = "INSERT INTO config_revisions \
     (id, scope, scope_id, config, published_by) VALUES ($1, $2, $3, $4, $5)";
const ADVISORY_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtext($1))";
const OUTBOX_INSERT_SQL: &str = "INSERT INTO outbox_events \
     (event_type, event_version, payload, idempotency_key, customer_id, deployment_id, trace_id) \
     VALUES ($1, $2, $3, $4, $5, $6, $7)";
const FEATURE_DEFINITIONS_SQL: &str = "SELECT feature_id, description, default_value, mandatory, \
     kill_switch, allowed_scopes FROM feature_definitions ORDER BY feature_id";
const FEATURE_DEFINITION_SQL: &str = "SELECT feature_id, description, default_value, mandatory, \
     kill_switch, allowed_scopes FROM feature_definitions WHERE feature_id = $1";
const FEATURE_OVERRIDES_SQL: &str = "SELECT id, feature_id, scope, scope_id, value, owner, \
     reason, revision, created_at, expires_at FROM feature_overrides \
     ORDER BY revision, created_at";
const OVERRIDE_MAX_REVISION_SQL: &str = "SELECT COALESCE(MAX(revision), 0) + 1 \
     FROM feature_overrides WHERE feature_id = $1 AND scope = $2 AND scope_id = $3";
const OVERRIDE_INSERT_SQL: &str = "INSERT INTO feature_overrides \
     (id, feature_id, scope, scope_id, value, owner, reason, revision, expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
     RETURNING id, created_at";

#[derive(Clone)]
pub struct AdminPolicyState(Arc<AdminPolicyStateInner>);

struct AdminPolicyStateInner {
    pool: PgPool,
    deployment_id: DeploymentId,
    audit: Arc<dyn AuditStore>,
    high_risk_limiter: std::sync::Mutex<TokenBucket>,
}

impl AdminPolicyState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self(Arc::new(AdminPolicyStateInner {
            audit: Arc::new(PostgresAuditStore::new(pool.clone())),
            high_risk_limiter: std::sync::Mutex::new(TokenBucket::new(
                &HighRiskLimits::permission_change(),
            )),
            pool,
            deployment_id,
        }))
    }
}

#[derive(Serialize)]
struct ApiEnvelope<T> {
    data: T,
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RevisionScope {
    System,
    Tenant,
}

impl RevisionScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Tenant => "tenant",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "system" => Some(Self::System),
            "tenant" => Some(Self::Tenant),
            _ => None,
        }
    }

    /// The scope a family publishes at: System-managed families are shared by
    /// the deployment, everything else belongs to the active customer.
    fn for_management_level(management_level: &str) -> Option<Self> {
        match management_level {
            "system" => Some(Self::System),
            "customer" | "support" => Some(Self::Tenant),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct RevisionSummaryResponse {
    revision_number: i64,
    published_by: String,
    published_at: DateTime<Utc>,
    scope_level: RevisionScope,
}

#[derive(Serialize)]
struct RevisionDetailResponse {
    revision_number: i64,
    published_by: String,
    published_at: DateTime<Utc>,
    scope_level: RevisionScope,
    activated_at: Option<DateTime<Utc>>,
    deactivated_at: Option<DateTime<Utc>>,
    rules_count: i64,
    rules: Option<Value>,
}

#[derive(Serialize)]
struct FamilySummaryResponse {
    family_key: String,
    description: String,
    management_level: String,
    security_floor: bool,
    revision_count: i64,
    active_revision: Option<RevisionSummaryResponse>,
}

#[derive(Serialize)]
struct PolicyListResponse {
    families: Vec<FamilySummaryResponse>,
}

#[derive(Serialize)]
struct PolicyDetailResponse {
    family: FamilySummaryResponse,
    revisions: Vec<RevisionDetailResponse>,
}

#[derive(Serialize)]
struct PublishResponse {
    family_key: String,
    revision_number: i64,
    published_at: DateTime<Utc>,
    rules_count: i64,
}

#[derive(Serialize)]
struct RefreshResponse {
    family_key: String,
    refresh_requested_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct FeatureOverrideResponse {
    id: Uuid,
    scope: OverrideScope,
    scope_id: String,
    value: String,
    owner: String,
    reason: String,
    revision: i64,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct FeatureResponse {
    feature_id: FeatureId,
    description: String,
    default_value: String,
    mandatory: bool,
    kill_switch: bool,
    allowed_scopes: Vec<OverrideScope>,
    effective_value: String,
    winning_scope: OverrideScope,
    overrides: Vec<FeatureOverrideResponse>,
}

#[derive(Serialize)]
struct FeatureListResponse {
    features: Vec<FeatureResponse>,
}

#[derive(Serialize)]
struct OverrideWriteResponse {
    id: Uuid,
    scope: OverrideScope,
    scope_id: String,
    value: String,
    owner: String,
    reason: String,
    revision: i64,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    effective_value: String,
    winning_scope: OverrideScope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishPolicyBody {
    rules: Vec<PolicyRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideBody {
    scope: OverrideScope,
    value: String,
    reason: String,
    expires_at: Option<DateTime<Utc>>,
}

pub fn policy_admin_router(state: AdminPolicyState) -> Router {
    Router::new()
        .route(POLICIES_PATH, get(list_families))
        .route(POLICY_PATH, get(get_family))
        .route(POLICY_REVISIONS_PATH, post(publish_family))
        .route(POLICY_REFRESH_PATH, post(refresh_family))
        .route(FEATURES_PATH, get(list_features))
        .route(FEATURE_OVERRIDE_PATH, put(write_override))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Authorization helpers
// ---------------------------------------------------------------------------

struct Route<'a> {
    action: &'static str,
    resource_type: &'static str,
    resource_id: Option<String>,
    permission: &'static str,
    marker: std::marker::PhantomData<&'a ()>,
}

impl Route<'_> {
    fn new(action: &'static str, resource_type: &'static str, permission: &'static str) -> Self {
        Self {
            action,
            resource_type,
            resource_id: None,
            permission,
            marker: std::marker::PhantomData,
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

    fn not_found(message: &'static str, reason: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NOT_FOUND",
            message,
            reason: reason.to_string(),
        }
    }
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

fn has_permission(context: &TenantContext, permission: &str) -> bool {
    context
        .permissions
        .iter()
        .any(|granted| granted == permission)
}

fn has_role(context: &TenantContext, role: &str) -> bool {
    context.actor.roles.iter().any(|granted| granted == role)
}

fn management_tier(management_level: &str) -> Option<u8> {
    match management_level {
        "customer" => Some(0),
        "support" => Some(1),
        "system" => Some(2),
        _ => None,
    }
}

/// The highest policy tier this session's builtin roles carry. A session with
/// no recognized role grants nothing, so the gate fails closed.
fn caller_tier(context: &TenantContext) -> Option<u8> {
    context
        .actor
        .roles
        .iter()
        .filter_map(|role| {
            BUILTIN_ROLES
                .iter()
                .find(|builtin| builtin.key == role)
                .and_then(|builtin| management_tier(builtin.role_level))
        })
        .max()
}

fn family_tier(family_key: &str) -> Option<u8> {
    POLICY_FAMILY_MANAGEMENT_LEVELS
        .iter()
        .find(|(key, _)| *key == family_key)
        .and_then(|(_, management_level)| management_tier(management_level))
}

/// Audits a denial (observability only; the response is a denial either way,
/// so an audit write failure never changes the outcome) and returns it.
async fn denied(
    state: &AdminPolicyState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route<'_>,
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
        error!(%error, "failed to audit policy administration denial");
    }
    api_error(denial.status, denial.code, denial.message)
}

/// Permission, lifecycle, then deployment — in that order, before any rate
/// limit, audit, or transaction work.
async fn authorize(
    state: &AdminPolicyState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route<'_>,
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

/// Resolves the family through the static catalog first, so an unknown key is
/// a 404 before a query, and then enforces the management tier of the family.
async fn require_family_tier(
    state: &AdminPolicyState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route<'_>,
    family_key: &str,
) -> Result<(), Response> {
    let Some(required) = family_tier(family_key) else {
        return Err(denied(
            state,
            context,
            headers,
            route,
            &Denial::not_found("Policy family was not found", "unknown policy family"),
        )
        .await);
    };
    let Some(caller) = caller_tier(context) else {
        return Err(denied(
            state,
            context,
            headers,
            route,
            &Denial::forbidden("session holds no management tier"),
        )
        .await);
    };
    if caller < required {
        return Err(denied(
            state,
            context,
            headers,
            route,
            &Denial::forbidden("management tier below the policy family level"),
        )
        .await);
    }
    Ok(())
}

fn scope_role_allowed(context: &TenantContext, scope: OverrideScope) -> bool {
    match scope {
        OverrideScope::System => has_role(context, SYSTEM_ADMIN_ROLE),
        OverrideScope::Deployment => {
            has_role(context, SYSTEM_ADMIN_ROLE) || has_role(context, SUPPORT_ROLE)
        },
        OverrideScope::Tenant => true,
    }
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

/// Fresh step-up, then the shared fail-closed permission-change budget:
/// permission checks come first, and neither gate ever writes.
async fn require_high_risk(
    state: &AdminPolicyState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route<'_>,
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

async fn write_outbox(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_type: &str,
    payload: Value,
    idempotency_key: String,
    context: &TenantContext,
    deployment_id: &DeploymentId,
) -> Result<(), Response> {
    sqlx::query(OUTBOX_INSERT_SQL)
        .bind(event_type)
        .bind(1_i32)
        .bind(sqlx::types::Json(payload))
        .bind(idempotency_key)
        .bind(&context.customer_id.0)
        .bind(&deployment_id.0)
        .bind(&context.trace_id)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(|_| unavailable())
}

// ---------------------------------------------------------------------------
// Transaction helpers
// ---------------------------------------------------------------------------

async fn set_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(|_| unavailable())
}

/// Claims the idempotency key inside the caller's transaction. Error paths
/// drop the transaction, rolling back both the claim and any partial work, so
/// a failed request never burns its key.
async fn begin_claim(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
    operation: &str,
) -> Result<ClaimOutcome, Response> {
    claim(transaction, key, operation)
        .await
        .map_err(|_| unavailable())
}

/// Serializes publishers of one family and scope so revision numbers and the
/// single-active-revision invariant cannot race.
async fn lock_family_scope(
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

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn has_control_characters(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn valid_reason(value: &str) -> bool {
    value.len() >= REASON_MIN_LEN && value.len() <= REASON_MAX_LEN
}

fn valid_feature_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= FEATURE_ID_MAX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= REASON_CODE_MAX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_rules(rules: &[PolicyRule]) -> bool {
    rules.len() <= MAX_RULES
        && rules.iter().all(|rule| {
            let name = rule.name.trim();
            !name.is_empty()
                && name.len() <= RULE_NAME_MAX_LEN
                && !has_control_characters(name)
                && (RULE_PRIORITY_MIN..=RULE_PRIORITY_MAX).contains(&rule.priority)
                && valid_reason_code(&rule.action.reason_code.0)
        })
}

/// Decodes the canonical feature override value. The wire form is exact:
/// `inherit`, `enabled`, `disabled` or `typed:<payload>`.
fn parse_feature_value(raw: &str) -> Option<FeatureValue> {
    if raw.len() > VALUE_MAX_LEN {
        return None;
    }
    match raw {
        "inherit" => Some(FeatureValue::Inherit),
        "enabled" => Some(FeatureValue::Enabled),
        "disabled" => Some(FeatureValue::Disabled),
        _ => raw
            .strip_prefix(TYPED_PREFIX)
            .filter(|payload| !payload.is_empty())
            .map(|payload| FeatureValue::Typed(payload.to_string())),
    }
}

fn encode_feature_value(value: &FeatureValue) -> String {
    match value {
        FeatureValue::Inherit => "inherit".to_string(),
        FeatureValue::Enabled => "enabled".to_string(),
        FeatureValue::Disabled => "disabled".to_string(),
        FeatureValue::Typed(payload) => format!("{TYPED_PREFIX}{payload}"),
    }
}

/// A mandatory security floor must be refused outright rather than stored and
/// silently ignored, so the caller learns the override did not apply.
fn blocks_mandatory_disable(mandatory: bool, value: &FeatureValue) -> bool {
    mandatory && value.is_disabled()
}

fn parse_override_scope(raw: &str) -> Option<OverrideScope> {
    match raw {
        "system" => Some(OverrideScope::System),
        "deployment" => Some(OverrideScope::Deployment),
        "tenant" => Some(OverrideScope::Tenant),
        _ => None,
    }
}

fn scope_id_for(state: &AdminPolicyState, context: &TenantContext, scope: OverrideScope) -> String {
    match scope {
        OverrideScope::System => SYSTEM_SCOPE_ID.to_string(),
        OverrideScope::Deployment => state.0.deployment_id.0.clone(),
        OverrideScope::Tenant => context.customer_id.0.clone(),
    }
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

type FamilyActiveRow = (
    String,
    String,
    String,
    bool,
    Option<i64>,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<String>,
);
type CountRow = (String, i64);
type RevisionRow = (
    i64,
    String,
    DateTime<Utc>,
    String,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    sqlx::types::Json<Value>,
);
type FeatureDefinitionRow = (String, String, String, bool, bool, Vec<String>);
type FeatureOverrideRow = (
    Uuid,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

fn definition_from_row(row: FeatureDefinitionRow) -> Option<FeatureDefinition> {
    let default_value = parse_feature_value(&row.2)?;
    let allowed_scopes = row
        .5
        .iter()
        .map(|scope| parse_override_scope(scope))
        .collect::<Option<Vec<OverrideScope>>>()?;
    Some(FeatureDefinition {
        feature_id: FeatureId::new(&row.0),
        description: row.1,
        default_value,
        mandatory: row.3,
        kill_switch: row.4,
        allowed_scopes,
    })
}

fn override_from_row(row: FeatureOverrideRow) -> Option<LoadedOverride> {
    Some(LoadedOverride {
        id: row.0,
        item: FeatureOverride {
            feature_id: FeatureId::new(&row.1),
            scope: parse_override_scope(&row.2)?,
            scope_id: row.3,
            value: parse_feature_value(&row.4)?,
            owner: row.5,
            reason: row.6,
            revision: row.7,
            created_at: row.8,
            expires_at: row.9,
        },
    })
}

struct LoadedOverride {
    id: Uuid,
    item: FeatureOverride,
}

fn override_response(loaded: &LoadedOverride) -> FeatureOverrideResponse {
    let item = &loaded.item;
    FeatureOverrideResponse {
        id: loaded.id,
        scope: item.scope,
        scope_id: item.scope_id.clone(),
        value: encode_feature_value(&item.value),
        owner: item.owner.clone(),
        reason: item.reason.clone(),
        revision: item.revision,
        created_at: item.created_at,
        expires_at: item.expires_at,
    }
}

fn active_revision(row: &FamilyActiveRow) -> Option<RevisionSummaryResponse> {
    Some(RevisionSummaryResponse {
        revision_number: row.4?,
        published_by: row.5.clone()?,
        published_at: row.6?,
        scope_level: RevisionScope::parse(row.7.as_deref()?)?,
    })
}

async fn load_definitions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sql: &str,
    feature_id: Option<&str>,
) -> Result<Vec<FeatureDefinition>, Response> {
    let rows: Result<Vec<FeatureDefinitionRow>, sqlx::Error> = match feature_id {
        Some(feature_id) => {
            sqlx::query_as::<_, FeatureDefinitionRow>(sql)
                .bind(feature_id)
                .fetch_all(&mut **transaction)
                .await
        },
        None => {
            sqlx::query_as::<_, FeatureDefinitionRow>(sql)
                .fetch_all(&mut **transaction)
                .await
        },
    };
    let rows = rows.map_err(|_| unavailable())?;
    let mut definitions = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(definition) = definition_from_row(row) else {
            return Err(unavailable());
        };
        definitions.push(definition);
    }
    Ok(definitions)
}

async fn load_overrides(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<LoadedOverride>, Response> {
    let rows = sqlx::query_as::<_, FeatureOverrideRow>(FEATURE_OVERRIDES_SQL)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| unavailable())?;
    let mut overrides = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(loaded) = override_from_row(row) else {
            return Err(unavailable());
        };
        overrides.push(loaded);
    }
    Ok(overrides)
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

async fn list_families(
    State(state): State<AdminPolicyState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let route = Route::new(
        ACTION_POLICY_LIST,
        RESOURCE_POLICY_FAMILY,
        POLICIES_VIEW_PERMISSION,
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
    let active_rows = match sqlx::query_as::<_, FamilyActiveRow>(FAMILY_ACTIVE_SQL)
        .bind(&state.0.deployment_id.0)
        .bind(&context.customer_id.0)
        .bind(Option::<&str>::None)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let counts = match sqlx::query_as::<_, CountRow>(REVISION_COUNTS_SQL)
        .bind(&state.0.deployment_id.0)
        .bind(&context.customer_id.0)
        .bind(Option::<&str>::None)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows.into_iter().collect::<HashMap<String, i64>>(),
        Err(_) => return unavailable(),
    };
    let families = active_rows
        .iter()
        .map(|row| FamilySummaryResponse {
            family_key: row.0.clone(),
            description: row.1.clone(),
            management_level: row.2.clone(),
            security_floor: row.3,
            revision_count: counts.get(&row.0).copied().unwrap_or(0),
            active_revision: active_revision(row),
        })
        .collect();
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: PolicyListResponse { families },
        }),
    )
        .into_response()
}

async fn get_family(
    State(state): State<AdminPolicyState>,
    Path(family_key): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if family_key.is_empty() || family_key.len() > FAMILY_KEY_MAX_LEN {
        return not_found("Policy family was not found");
    }
    let route = Route::new(
        ACTION_POLICY_DETAIL,
        RESOURCE_POLICY_FAMILY,
        POLICIES_VIEW_PERMISSION,
    )
    .with_resource(family_key.clone());
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) =
        require_family_tier(&state, &context, &headers, &route, &family_key).await
    {
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
    let active_row = match sqlx::query_as::<_, FamilyActiveRow>(FAMILY_ACTIVE_SQL)
        .bind(&state.0.deployment_id.0)
        .bind(&context.customer_id.0)
        .bind(&family_key)
        .fetch_optional(&mut *transaction)
        .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    let Some(active_row) = active_row else {
        return not_found("Policy family was not found");
    };
    let count = match sqlx::query_as::<_, CountRow>(REVISION_COUNTS_SQL)
        .bind(&state.0.deployment_id.0)
        .bind(&context.customer_id.0)
        .bind(&family_key)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(counts) => counts
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .unwrap_or(0),
        Err(_) => return unavailable(),
    };
    let rows = match sqlx::query_as::<_, RevisionRow>(FAMILY_REVISIONS_SQL)
        .bind(&family_key)
        .bind(&state.0.deployment_id.0)
        .bind(&context.customer_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let active_number = active_row.4;
    let mut revisions = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(scope_level) = RevisionScope::parse(&row.3) else {
            return unavailable();
        };
        let rules_count = row
            .6
             .0
            .as_array()
            .map(|rules| rules.len() as i64)
            .unwrap_or(0);
        revisions.push(RevisionDetailResponse {
            revision_number: row.0,
            published_by: row.1,
            published_at: row.2,
            scope_level,
            activated_at: row.4,
            deactivated_at: row.5,
            rules_count,
            rules: if active_number == Some(row.0) {
                Some(row.6 .0)
            } else {
                None
            },
        });
    }
    let summary = active_revision(&active_row);
    let family = FamilySummaryResponse {
        family_key: active_row.0,
        description: active_row.1,
        management_level: active_row.2,
        security_floor: active_row.3,
        revision_count: count,
        active_revision: summary,
    };
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: PolicyDetailResponse { family, revisions },
        }),
    )
        .into_response()
}

async fn publish_family(
    State(state): State<AdminPolicyState>,
    Path(family_key): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<PublishPolicyBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if family_key.is_empty() || family_key.len() > FAMILY_KEY_MAX_LEN {
        return not_found("Policy family was not found");
    }
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    if !valid_rules(&body.rules) {
        return invalid_request();
    }
    let rules = match serde_json::to_value(&body.rules) {
        Ok(Value::Array(rules)) => Value::Array(rules),
        _ => return invalid_request(),
    };
    let rules_count = body.rules.len() as i64;
    let route = Route::new(
        ACTION_POLICY_PUBLISHED,
        RESOURCE_POLICY_FAMILY,
        POLICIES_MANAGE_PERMISSION,
    )
    .with_resource(family_key.clone());
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) =
        require_family_tier(&state, &context, &headers, &route, &family_key).await
    {
        return response;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let scope = match RevisionScope::for_management_level(
        POLICY_FAMILY_MANAGEMENT_LEVELS
            .iter()
            .find(|(key, _)| *key == family_key)
            .map(|(_, management_level)| *management_level)
            .unwrap_or_default(),
    ) {
        Some(scope) => scope,
        None => return not_found("Policy family was not found"),
    };
    let scope_customer = match scope {
        RevisionScope::System => None,
        RevisionScope::Tenant => Some(context.customer_id.0.clone()),
    };
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
    let operation = format!("policy:publish:{family_key}");
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
    let lock_key = format!("{family_key}:{}", scope.as_str());
    if let Err(response) = lock_family_scope(&mut transaction, &lock_key).await {
        return response;
    }
    let revision_number = match sqlx::query_scalar::<_, i64>(PUBLISH_NEXT_SQL)
        .bind(&family_key)
        .bind(scope.as_str())
        .bind(&state.0.deployment_id.0)
        .bind(&scope_customer)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(revision) => revision,
        Err(_) => return unavailable(),
    };
    let revision_id = Uuid::new_v4();
    if let Err(response) = deactivate_previous(
        &mut transaction,
        &family_key,
        scope,
        &state.0.deployment_id.0,
        &scope_customer,
        revision_id,
    )
    .await
    {
        return response;
    }
    let published_at = match sqlx::query_scalar::<_, DateTime<Utc>>(PUBLISH_INSERT_SQL)
        .bind(revision_id)
        .bind(&scope_customer)
        .bind(&state.0.deployment_id.0)
        .bind(&family_key)
        .bind(scope.as_str())
        .bind(revision_number)
        .bind(sqlx::types::Json(rules))
        .bind(context.actor.actor_id.0.to_string())
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(published_at) => published_at,
        Err(_) => return unavailable(),
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_POLICY_PUBLISHED,
            resource_type: RESOURCE_POLICY_FAMILY,
            resource_id: Some(family_key.clone()),
            customer_id: context.customer_id.0.clone(),
            details: json!({
                "family_key": family_key,
                "revision_number": revision_number,
                "scope_level": scope.as_str(),
                "rules_count": rules_count,
            }),
        },
    )
    .await
    {
        return response;
    }
    if let Err(response) = write_outbox(
        &mut transaction,
        EVENT_CONFIG_CHANGED,
        json!({
            "family_key": family_key,
            "scope": scope.as_str(),
            "scope_id": scope_customer
                .as_deref()
                .unwrap_or(&state.0.deployment_id.0),
            "revision_number": revision_number,
        }),
        format!("policy-publish:{key}"),
        &context,
        &state.0.deployment_id,
    )
    .await
    {
        return response;
    }
    let config_scope_id = scope_customer.as_deref().unwrap_or("system");
    if sqlx::query(CONFIG_REVISION_INSERT_SQL)
        .bind(Uuid::new_v4())
        .bind(scope.as_str())
        .bind(config_scope_id)
        .bind(sqlx::types::Json(json!({
            "family_key": family_key,
            "revision_number": revision_number,
            "source": "policy_publish",
        })))
        .bind(context.actor.actor_id.0.to_string())
        .execute(&mut *transaction)
        .await
        .is_err()
    {
        return unavailable();
    }
    let response = PublishResponse {
        family_key: family_key.clone(),
        revision_number,
        published_at,
        rules_count,
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

async fn deactivate_previous(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    family_key: &str,
    scope: RevisionScope,
    deployment_id: &str,
    scope_customer: &Option<String>,
    revision_id: Uuid,
) -> Result<(), Response> {
    sqlx::query(PUBLISH_DEACTIVATE_SQL)
        .bind(family_key)
        .bind(scope.as_str())
        .bind(deployment_id)
        .bind(scope_customer)
        .bind(revision_id)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(|_| unavailable())
}

async fn refresh_family(
    State(state): State<AdminPolicyState>,
    Path(family_key): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if family_key.is_empty() || family_key.len() > FAMILY_KEY_MAX_LEN {
        return not_found("Policy family was not found");
    }
    let route = Route::new(
        ACTION_POLICY_REFRESHED,
        RESOURCE_POLICY_FAMILY,
        POLICIES_MANAGE_PERMISSION,
    )
    .with_resource(family_key.clone());
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) =
        require_family_tier(&state, &context, &headers, &route, &family_key).await
    {
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
    let operation = format!("policy:refresh:{family_key}");
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
    let refresh_requested_at = Utc::now();
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_POLICY_REFRESHED,
            resource_type: RESOURCE_POLICY_FAMILY,
            resource_id: Some(family_key.clone()),
            customer_id: context.customer_id.0.clone(),
            details: json!({ "family_key": family_key }),
        },
    )
    .await
    {
        return response;
    }
    if let Err(response) = write_outbox(
        &mut transaction,
        EVENT_CONFIG_CHANGED,
        json!({ "family_key": family_key, "reason": "manual_refresh" }),
        format!("policy-refresh:{key}"),
        &context,
        &state.0.deployment_id,
    )
    .await
    {
        return response;
    }
    let response = RefreshResponse {
        family_key,
        refresh_requested_at,
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

async fn list_features(
    State(state): State<AdminPolicyState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let route = Route::new(
        ACTION_FEATURE_LIST,
        RESOURCE_FEATURE,
        POLICIES_VIEW_PERMISSION,
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
    let definitions = match load_definitions(&mut transaction, FEATURE_DEFINITIONS_SQL, None).await
    {
        Ok(definitions) => definitions,
        Err(response) => return response,
    };
    let overrides = match load_overrides(&mut transaction).await {
        Ok(overrides) => overrides,
        Err(response) => return response,
    };
    let now = Utc::now();
    let evaluator = FeatureEvaluator::new(definitions.clone());
    let mut features = Vec::with_capacity(definitions.len());
    for definition in &definitions {
        let applicable: Vec<&LoadedOverride> = overrides
            .iter()
            .filter(|loaded| loaded.item.feature_id == definition.feature_id)
            .collect();
        let applicable_overrides = applicable
            .iter()
            .map(|loaded| loaded.item.clone())
            .collect::<Vec<FeatureOverride>>();
        let evaluation = match evaluator.evaluate(
            &definition.feature_id,
            &state.0.deployment_id,
            &context.customer_id,
            &applicable_overrides,
            now,
        ) {
            Ok(evaluation) => evaluation,
            Err(_) => return unavailable(),
        };
        features.push(FeatureResponse {
            feature_id: definition.feature_id.clone(),
            description: definition.description.clone(),
            default_value: encode_feature_value(&definition.default_value),
            mandatory: definition.mandatory,
            kill_switch: definition.kill_switch,
            allowed_scopes: definition.allowed_scopes.clone(),
            effective_value: encode_feature_value(&evaluation.value),
            winning_scope: evaluation.winning_scope,
            overrides: applicable
                .iter()
                .map(|loaded| override_response(loaded))
                .collect(),
        });
    }
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: FeatureListResponse { features },
        }),
    )
        .into_response()
}

async fn write_override(
    State(state): State<AdminPolicyState>,
    Path(feature_id): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<OverrideBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_feature_id(&feature_id) {
        return invalid_request();
    }
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    let Some(value) = parse_feature_value(&body.value) else {
        return invalid_request();
    };
    let reason = body.reason.trim();
    if !valid_reason(reason) {
        return invalid_request();
    }
    if let Some(expires_at) = body.expires_at {
        if expires_at <= Utc::now() {
            return invalid_request();
        }
    }
    let route = Route::new(
        ACTION_FEATURE_OVERRIDE_CHANGED,
        RESOURCE_FEATURE,
        POLICIES_MANAGE_PERMISSION,
    )
    .with_resource(feature_id.clone());
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if !scope_role_allowed(&context, body.scope) {
        return denied(
            &state,
            &context,
            &headers,
            &route,
            &Denial::forbidden(format!(
                "{} scope requires a higher policy role",
                match body.scope {
                    OverrideScope::System => "system",
                    OverrideScope::Deployment => "deployment",
                    OverrideScope::Tenant => "tenant",
                }
            )),
        )
        .await;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let scope_id = scope_id_for(&state, &context, body.scope);
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
    let operation = format!("feature:override:{feature_id}");
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
    let lock_key = format!("{feature_id}:{}:{scope_id}", scope_key(body.scope));
    if let Err(response) = lock_family_scope(&mut transaction, &lock_key).await {
        return response;
    }
    let definitions =
        match load_definitions(&mut transaction, FEATURE_DEFINITION_SQL, Some(&feature_id)).await {
            Ok(definitions) => definitions,
            Err(response) => return response,
        };
    let Some(definition) = definitions.first() else {
        return not_found("Feature was not found");
    };
    if !definition.allowed_scopes.contains(&body.scope) {
        return invalid_request();
    }
    if blocks_mandatory_disable(definition.mandatory, &value) {
        return denied(
            &state,
            &context,
            &headers,
            &route,
            &Denial::forbidden("mandatory security features cannot be disabled"),
        )
        .await;
    }
    let revision = match sqlx::query_scalar::<_, i64>(OVERRIDE_MAX_REVISION_SQL)
        .bind(&feature_id)
        .bind(scope_key(body.scope))
        .bind(&scope_id)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(revision) => revision,
        Err(_) => return unavailable(),
    };
    let override_id = Uuid::new_v4();
    let owner = context.actor.actor_id.0.to_string();
    let encoded = encode_feature_value(&value);
    let (inserted_id, created_at) =
        match sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(OVERRIDE_INSERT_SQL)
            .bind(override_id)
            .bind(&feature_id)
            .bind(scope_key(body.scope))
            .bind(&scope_id)
            .bind(&encoded)
            .bind(&owner)
            .bind(reason)
            .bind(revision)
            .bind(body.expires_at)
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
            action: ACTION_FEATURE_OVERRIDE_CHANGED,
            resource_type: RESOURCE_FEATURE,
            resource_id: Some(feature_id.clone()),
            customer_id: context.customer_id.0.clone(),
            details: json!({
                "feature_id": feature_id,
                "scope": body.scope,
                "value": encoded,
                "revision": revision,
                "expires_at": body.expires_at,
            }),
        },
    )
    .await
    {
        return response;
    }
    if let Err(response) = write_outbox(
        &mut transaction,
        EVENT_FEATURE_CHANGED,
        json!({
            "feature_id": feature_id,
            "scope": body.scope,
            "scope_id": scope_id,
            "revision": revision,
        }),
        format!("feature-override:{key}"),
        &context,
        &state.0.deployment_id,
    )
    .await
    {
        return response;
    }
    let overrides = match load_overrides(&mut transaction).await {
        Ok(overrides) => overrides,
        Err(response) => return response,
    };
    let now = Utc::now();
    let evaluator = FeatureEvaluator::new(vec![definition.clone()]);
    let evaluation = match evaluator.evaluate(
        &definition.feature_id,
        &state.0.deployment_id,
        &context.customer_id,
        &overrides
            .iter()
            .map(|loaded| loaded.item.clone())
            .collect::<Vec<FeatureOverride>>(),
        now,
    ) {
        Ok(evaluation) => evaluation,
        Err(_) => return unavailable(),
    };
    let response = OverrideWriteResponse {
        id: inserted_id,
        scope: body.scope,
        scope_id,
        value: encoded,
        owner,
        reason: reason.to_string(),
        revision,
        created_at,
        expires_at: body.expires_at,
        effective_value: encode_feature_value(&evaluation.value),
        winning_scope: evaluation.winning_scope,
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

fn scope_key(scope: OverrideScope) -> &'static str {
    match scope {
        OverrideScope::System => "system",
        OverrideScope::Deployment => "deployment",
        OverrideScope::Tenant => "tenant",
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        extract::Extension,
        http::{Method, Request},
    };
    use nullapart_mail_contracts::{transaction::CustomerId, ActorId};
    use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::admin_rbac::CUSTOMER_ADMIN_ROLE;

    fn state() -> AdminPolicyState {
        // A short acquire timeout keeps failure paths deterministic: the
        // unreachable pool must fail quickly instead of masking gate order.
        let pool = PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse");
        AdminPolicyState::new(pool, DeploymentId::new("LOCAL-TEST"))
    }

    fn context() -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            region: RegionId::new("local"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "operator@example.test".to_string(),
                roles: vec![SYSTEM_ADMIN_ROLE.to_string()],
                authentication_assurance: AuthenticationAssurance::StepUp,
            },
            impersonation: None,
            customer_id: CustomerId::new("local-customer"),
            customer_internal_key: 1,
            customer_display_name: "Local customer".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions: vec![
                POLICIES_VIEW_PERMISSION.to_string(),
                POLICIES_MANAGE_PERMISSION.to_string(),
            ],
            config_revision: 1,
            trace_id: "policy-admin-test".to_string(),
            correlation_id: "policy-admin-test".to_string(),
            session_id: "policy-admin-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("test request must build")
    }

    fn send(method: Method, uri: &str, key: Option<&str>, body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("x-idempotency-key", key);
        }
        builder
            .body(Body::from(body.to_string()))
            .expect("test request must build")
    }

    fn publish_body(rules: &str) -> String {
        format!("{{\"rules\":[{rules}]}}")
    }

    fn rule(name: &str, priority: i32, reason_code: &str) -> String {
        format!(
            "{{\"id\":\"11111111-1111-1111-1111-111111111111\",\"name\":\"{name}\",\
             \"priority\":{priority},\"condition\":{{\"scope\":\"transaction\"}},\
             \"action\":{{\"disposition\":\"allow\",\"reason_code\":\"{reason_code}\"}},\
             \"enabled\":true}}"
        )
    }

    fn override_body() -> String {
        r#"{"scope":"tenant","value":"enabled","reason":"local policy admin test"}"#.to_string()
    }

    async fn body_value(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test body must read");
        serde_json::from_slice(&bytes).expect("test body must be JSON")
    }

    fn error_body(code: &str, message: &str) -> Value {
        json!({ "code": code, "message": message })
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test body must read");
        String::from_utf8(bytes.to_vec()).expect("test body must be UTF-8")
    }

    /// An external error response is exactly `{code, message}` and never
    /// carries SQL, driver, pool, panic or credential material.
    fn assert_static_error_body(raw: &str) {
        let value: Value = serde_json::from_str(raw).expect("an error response must be JSON");
        let object = value
            .as_object()
            .expect("an error response must be a JSON object");
        assert_eq!(
            object.len(),
            2,
            "an error response must carry only code and message: {raw}"
        );
        assert!(
            object.contains_key("code") && object.contains_key("message"),
            "an error response must carry a code and a message: {raw}"
        );
        let lowered = raw.to_lowercase();
        for marker in [
            "select",
            "insert",
            "update",
            "sqlx",
            "postgres",
            "pgpool",
            "panicked at",
            "stack backtrace",
            "nullapart_",
            "password",
            "secret",
            "token=",
        ] {
            assert!(
                !lowered.contains(marker),
                "an error response must not leak {marker} internals: {raw}"
            );
        }
    }

    async fn snapshot(app: Router, request: Request<Body>) -> (StatusCode, String) {
        let response = app.oneshot(request).await.expect("test response");
        let status = response.status();
        (status, body_text(response).await)
    }

    fn all_route_requests() -> Vec<Request<Body>> {
        vec![
            get("/api/v1/policies"),
            get("/api/v1/policies/attachments"),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("key-publish"),
                &publish_body(&rule("local rule", 0, "ALLOWED")),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/refresh",
                Some("key-refresh"),
                "",
            ),
            get("/api/v1/features"),
            send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("key-override"),
                &override_body(),
            ),
        ]
    }

    #[tokio::test]
    async fn policy_administration_requires_authenticated_context() {
        let app = policy_admin_router(state());
        for request in all_route_requests() {
            let response = app.clone().oneshot(request).await.expect("test response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                body_value(response).await,
                error_body("UNAUTHENTICATED", "Authentication is required")
            );
        }
    }

    #[tokio::test]
    async fn policy_list_requires_view_permission_before_database_access() {
        let mut context = context();
        context.permissions.clear();
        let response = policy_admin_router(state())
            .layer(Extension(context))
            .oneshot(get("/api/v1/policies"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("FORBIDDEN", "Permission is required")
        );
    }

    #[tokio::test]
    async fn publishing_requires_manage_permission_before_database_access() {
        let mut context = context();
        context.permissions = vec![POLICIES_VIEW_PERMISSION.to_string()];
        let response = policy_admin_router(state())
            .layer(Extension(context))
            .oneshot(send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("key-manage"),
                &publish_body(&rule("local rule", 0, "ALLOWED")),
            ))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("FORBIDDEN", "Permission is required")
        );
    }

    #[tokio::test]
    async fn family_tier_gate_runs_before_database_access() {
        let app = policy_admin_router(state());

        let mut customer_admin = context();
        customer_admin.actor.roles = vec![CUSTOMER_ADMIN_ROLE.to_string()];
        let support_family = app
            .clone()
            .layer(Extension(customer_admin))
            .oneshot(get("/api/v1/policies/quarantine"))
            .await
            .expect("test response");
        assert_eq!(support_family.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(support_family).await,
            error_body("FORBIDDEN", "Permission is required")
        );

        let mut support = context();
        support.actor.roles = vec![SUPPORT_ROLE.to_string()];
        let system_family = app
            .clone()
            .layer(Extension(support))
            .oneshot(get("/api/v1/policies/malware"))
            .await
            .expect("test response");
        assert_eq!(system_family.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(system_family).await,
            error_body("FORBIDDEN", "Permission is required")
        );

        let own_tier = app
            .clone()
            .layer(Extension(context()))
            .oneshot(get("/api/v1/policies/attachments"))
            .await
            .expect("test response");
        assert_eq!(own_tier.status(), StatusCode::SERVICE_UNAVAILABLE);

        let system_tier = app
            .layer(Extension(context()))
            .oneshot(get("/api/v1/policies/malware"))
            .await
            .expect("test response");
        assert_eq!(system_tier.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_value(system_tier).await,
            error_body("UNAVAILABLE", "Service is unavailable")
        );
    }

    #[tokio::test]
    async fn unknown_policy_family_is_not_found_before_database_access() {
        let response = policy_admin_router(state())
            .layer(Extension(context()))
            .oneshot(get("/api/v1/policies/not_a_family"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_value(response).await,
            error_body("NOT_FOUND", "Policy family was not found")
        );
    }

    #[tokio::test]
    async fn rule_validation_rejects_bad_requests_before_database_access() {
        let many_rules = vec![rule("local rule", 0, "ALLOWED"); MAX_RULES + 1].join(",");
        let requests = vec![
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v1"),
                r#"{"rules":{}}"#,
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v2"),
                "{}",
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v3"),
                &publish_body(&many_rules),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v4"),
                &publish_body(&rule("local rule", 0, "bad reason code")),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v5"),
                &publish_body(&rule("local rule", 0, "lower_case")),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v6"),
                &publish_body(&rule("", 0, "ALLOWED")),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v7"),
                &publish_body(&rule(&"a".repeat(RULE_NAME_MAX_LEN + 1), 0, "ALLOWED")),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v8"),
                &publish_body(&rule("\\u0007", 0, "ALLOWED")),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v9"),
                &publish_body(&rule("local rule", RULE_PRIORITY_MAX + 1, "ALLOWED")),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v10"),
                &publish_body(&rule("local rule", RULE_PRIORITY_MIN - 1, "ALLOWED")),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v11"),
                &publish_body(r#"{"name":"no id"}"#),
            ),
            send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("v12"),
                &format!(
                    "{{\"rules\":[{}],\"extra\":true}}",
                    rule("local rule", 0, "ALLOWED")
                ),
            ),
            send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("v13"),
                &override_body().replace("\"reason\"", "\"scope_id\":\"other\",\"reason\""),
            ),
            send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("v14"),
                r#"{"scope":"region","value":"enabled","reason":"local policy admin test"}"#,
            ),
            send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("v15"),
                r#"{"scope":"tenant","value":"on","reason":"local policy admin test"}"#,
            ),
            send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("v16"),
                r#"{"scope":"tenant","value":"enabled","reason":"too short"}"#,
            ),
            send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("v17"),
                r#"{"scope":"tenant","value":"enabled","reason":"local policy admin test",
                    "expires_at":"2020-01-01T00:00:00Z"}"#,
            ),
            send(
                Method::PUT,
                "/api/v1/features/bad!id/overrides",
                Some("v18"),
                &override_body(),
            ),
        ];
        let app = policy_admin_router(state()).layer(Extension(context()));
        for request in requests {
            let response = app.clone().oneshot(request).await.expect("test response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                body_value(response).await,
                error_body("INVALID_REQUEST", "Request is invalid")
            );
        }
    }

    #[tokio::test]
    async fn mutations_require_an_idempotency_key() {
        let app = policy_admin_router(state()).layer(Extension(context()));
        let missing = app
            .clone()
            .oneshot(send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                None,
                &publish_body(&rule("local rule", 0, "ALLOWED")),
            ))
            .await
            .expect("test response");
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_value(missing).await,
            error_body("IDEMPOTENCY_REQUIRED", "Idempotency key is required")
        );

        let empty = app
            .oneshot(send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some(""),
                &publish_body(&rule("local rule", 0, "ALLOWED")),
            ))
            .await
            .expect("test response");
        assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_value(empty).await,
            error_body("INVALID_REQUEST", "Request is invalid")
        );
    }

    #[tokio::test]
    async fn mutations_require_fresh_step_up_authentication() {
        let mut context = context();
        context.actor.authentication_assurance = AuthenticationAssurance::Standard;
        let response = policy_admin_router(state())
            .layer(Extension(context))
            .oneshot(send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("key-step-up"),
                &publish_body(&rule("local rule", 0, "ALLOWED")),
            ))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("STEP_UP_REQUIRED", "Step-up authentication is required")
        );
    }

    #[tokio::test]
    async fn tier_and_scope_gates_run_before_the_high_risk_gate() {
        let mut context = context();
        context.actor.authentication_assurance = AuthenticationAssurance::Standard;
        let mut support = context;
        support.actor.roles = vec![SUPPORT_ROLE.to_string()];
        let response = policy_admin_router(state())
            .layer(Extension(support))
            .oneshot(send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("key-scope"),
                r#"{"scope":"system","value":"enabled","reason":"local policy admin test"}"#,
            ))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("FORBIDDEN", "Permission is required")
        );
    }

    #[tokio::test]
    async fn database_failures_return_unavailable() {
        let response = policy_admin_router(state())
            .layer(Extension(context()))
            .oneshot(get("/api/v1/policies"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_value(response).await,
            error_body("UNAVAILABLE", "Service is unavailable")
        );
    }

    #[test]
    fn mandatory_security_floors_cannot_be_disabled() {
        assert!(blocks_mandatory_disable(true, &FeatureValue::Disabled));
        assert!(!blocks_mandatory_disable(true, &FeatureValue::Enabled));
        assert!(!blocks_mandatory_disable(true, &FeatureValue::Inherit));
        assert!(!blocks_mandatory_disable(false, &FeatureValue::Disabled));
    }

    #[test]
    fn feature_value_encoding_roundtrips() {
        for value in [
            FeatureValue::Inherit,
            FeatureValue::Enabled,
            FeatureValue::Disabled,
            FeatureValue::Typed("threshold=42".to_string()),
        ] {
            let encoded = encode_feature_value(&value);
            assert_eq!(parse_feature_value(&encoded), Some(value));
        }
        for invalid in ["", "on", "true", "typed:", "ENABLED", "inherit "] {
            assert!(
                parse_feature_value(invalid).is_none(),
                "{invalid} must be rejected"
            );
        }
        let too_long = format!("{TYPED_PREFIX}{}", "x".repeat(VALUE_MAX_LEN));
        assert!(parse_feature_value(&too_long).is_none());
    }

    #[test]
    fn family_catalog_is_sorted_and_known() {
        let keys: Vec<&str> = POLICY_FAMILY_MANAGEMENT_LEVELS
            .iter()
            .map(|(key, _)| *key)
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
        assert_eq!(
            POLICY_FAMILY_MANAGEMENT_LEVELS.len(),
            24,
            "the catalog must mirror every seeded policy family"
        );
        assert_eq!(family_tier("malware"), Some(2));
        assert_eq!(family_tier("quarantine"), Some(1));
        assert_eq!(family_tier("attachments"), Some(0));
        assert_eq!(family_tier("not_a_family"), None);
    }

    #[tokio::test]
    async fn policy_publish_rejects_injected_security_fields() {
        let app = policy_admin_router(state()).layer(Extension(context()));

        let baseline = app
            .clone()
            .oneshot(send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("mass-assign-publish-baseline"),
                &publish_body(&rule("local rule", 0, "ALLOWED")),
            ))
            .await
            .expect("test response");
        assert_eq!(
            baseline.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an ordinary publish must reach the database so the rejection below is discriminating"
        );

        let before = snapshot(app.clone(), get("/api/v1/policies/attachments")).await;
        let rejected = app
            .clone()
            .oneshot(send(
                Method::POST,
                "/api/v1/policies/attachments/revisions",
                Some("mass-assign-publish"),
                &format!(
                    "{{\"rules\":[{}],\"security_floor\":false,\"management_level\":\"system\"}}",
                    rule("local rule", 0, "ALLOWED")
                ),
            ))
            .await
            .expect("test response");
        assert_eq!(
            rejected.status(),
            StatusCode::BAD_REQUEST,
            "an unexpected field must be rejected by the JSON extractor"
        );
        assert_eq!(
            body_value(rejected).await,
            error_body("INVALID_REQUEST", "Request is invalid")
        );

        let after = snapshot(app, get("/api/v1/policies/attachments")).await;
        assert_eq!(
            before, after,
            "a rejected publish must leave the policy family unchanged"
        );
        assert!(
            !after.1.contains("\"management_level\":\"system\""),
            "an injected management level must never be persisted: {}",
            after.1
        );
    }

    #[tokio::test]
    async fn feature_override_rejects_injected_fields() {
        let app = policy_admin_router(state()).layer(Extension(context()));

        let baseline = app
            .clone()
            .oneshot(send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("mass-assign-override-baseline"),
                &override_body(),
            ))
            .await
            .expect("test response");
        assert_eq!(
            baseline.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an ordinary override must reach the database so the rejection below is discriminating"
        );

        let before = snapshot(app.clone(), get("/api/v1/features")).await;
        let rejected = app
            .clone()
            .oneshot(send(
                Method::PUT,
                "/api/v1/features/local-feature/overrides",
                Some("mass-assign-override"),
                r#"{"scope":"tenant","value":"enabled","reason":"local policy admin test",
                    "scope_id":"OTHER-DEPLOYMENT","mandatory":false,"kill_switch":false}"#,
            ))
            .await
            .expect("test response");
        assert_eq!(
            rejected.status(),
            StatusCode::BAD_REQUEST,
            "an unexpected field must be rejected by the JSON extractor"
        );
        assert_eq!(
            body_value(rejected).await,
            error_body("INVALID_REQUEST", "Request is invalid")
        );

        let after = snapshot(app, get("/api/v1/features")).await;
        assert_eq!(
            before, after,
            "a rejected override must leave the feature list unchanged"
        );
        assert!(
            !after.1.contains("OTHER-DEPLOYMENT"),
            "an injected scope identifier must never be persisted or echoed: {}",
            after.1
        );
    }

    #[tokio::test]
    async fn policy_error_responses_are_static_json_without_internal_leaks() {
        let app = policy_admin_router(state()).layer(Extension(context()));
        let cases = vec![
            (
                get("/api/v1/policies/not_a_family"),
                vec![StatusCode::NOT_FOUND],
            ),
            (
                send(
                    Method::POST,
                    "/api/v1/policies/attachments/revisions",
                    Some("leak-publish"),
                    "{",
                ),
                vec![StatusCode::BAD_REQUEST],
            ),
            (
                send(
                    Method::PUT,
                    "/api/v1/features/local-feature/overrides",
                    Some("leak-override"),
                    r#"{"scope":"tenant","value":"enabled","reason":"short"}"#,
                ),
                vec![StatusCode::BAD_REQUEST],
            ),
        ];
        for (request, expected) in cases {
            let response = app.clone().oneshot(request).await.expect("test response");
            let status = response.status();
            assert!(
                expected.contains(&status),
                "unexpected status {status}, expected one of {expected:?}"
            );
            let raw = body_text(response).await;
            assert_static_error_body(&raw);
        }
    }
}

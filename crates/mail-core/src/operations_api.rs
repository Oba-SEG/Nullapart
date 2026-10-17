//! Authenticated runtime operations projection and audited manual refresh.
//!
//! The read route reports published configuration, registered nodes, durable
//! queue lag, terminal reinjection failures and the scanner fleet for the
//! deployment. The write route records an audited request to reload that
//! configuration at a deployment, tenant or node scope.
//!
//! Both routes are authenticated context first, then permission/lifecycle/
//! deployment authorization, and only then any validation, rate limit or
//! database work: a caller who may not act learns nothing about whether the
//! request body would have validated. The refresh derives its scope from the
//! server-side session — never from a client-supplied customer — writes its
//! audit row and its `config.changed` outbox event in the same transaction,
//! and refuses any node the deployment does not own.
//!
//! The snapshot deliberately reports only counts and recorded state. SMTP
//! commissioning is stated as node rows that exist, never as health or
//! completion the data cannot show.

use std::sync::Arc;

use axum::{
    extract::{rejection::JsonRejection, Extension, State},
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
use crate::idempotency::{claim, complete, ClaimOutcome};

pub const OPERATIONS_VIEW_PERMISSION: &str = "operations:view";
pub const OPERATIONS_MANAGE_PERMISSION: &str = "operations:manage";

const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const NODE_ID_MAX_LEN: usize = 64;

const RUNTIME_PATH: &str = "/api/v1/operations/runtime";
const HARDENING_PATH: &str = "/api/v1/operations/hardening";
const REFRESH_PATH: &str = "/api/v1/operations/refresh";

const ACTION_RUNTIME_VIEW: &str = "runtime_snapshot_view";
const ACTION_HARDENING_VIEW: &str = "operations_hardening_view";
const ACTION_RUNTIME_REFRESH: &str = "runtime_refresh_requested";

const RESOURCE_RUNTIME_CONFIG: &str = "runtime_config";

const EVENT_CONFIG_CHANGED: &str = "config.changed";

const NODES_SQL: &str = "SELECT id, node_type, role, status, hostname, version, \
     config_revision, last_health_check FROM nodes \
     WHERE deployment_id = $1 ORDER BY node_type, id";
const NODE_EXISTS_SQL: &str = "SELECT 1 FROM nodes WHERE id = $1 AND deployment_id = $2";
const CONFIG_SCOPES_SQL: &str = "SELECT DISTINCT ON (scope, scope_id) scope, scope_id, \
     revision_number, published_by, published_at FROM config_revisions \
     WHERE (scope <> 'tenant' OR scope_id = $1) \
     ORDER BY scope, scope_id, revision_number DESC";
const OUTBOX_SQL: &str = "SELECT count(*) FILTER (WHERE published_at IS NULL) \
         AS unpublished_count, \
     (SELECT EXTRACT(EPOCH FROM (now() - min(created_at)))::bigint \
        FROM outbox_events \
       WHERE published_at IS NULL AND deployment_id = $1) \
         AS oldest_unpublished_age_seconds \
     FROM outbox_events WHERE deployment_id = $1";
const DEAD_LETTERS_SQL: &str = "SELECT count(*)::bigint AS count \
     FROM reinjection_dead_letters WHERE deployment_id = $1";
const OUTBOX_INSERT_SQL: &str = "INSERT INTO outbox_events \
     (event_type, event_version, payload, idempotency_key, customer_id, deployment_id, trace_id) \
     VALUES ($1, $2, $3, $4, $5, $6, $7)";
const TIER3_CAPABILITIES_SQL: &str = "SELECT capability_id, display_name, owner, sli, \
     slo_target, error_budget, measurement_source, rto_minutes, rpo_minutes, \
     dependency_map, redundancy_design, degraded_mode, capacity_threshold, runbook, \
     readiness_state, last_exercise_at, updated_at \
     FROM operations_tier3_capabilities WHERE deployment_id = $1 ORDER BY capability_id";
const ALERT_RULES_SQL: &str =
    "SELECT alert_key, capability_id, severity, burn_rate::text AS burn_rate, \
     long_window_minutes, short_window_minutes, threshold_description, owner, runbook, \
     suppression, escalation, enabled, last_tested_at \
     FROM operations_alert_rules WHERE deployment_id = $1 ORDER BY capability_id, alert_key";
const READINESS_CHECKS_SQL: &str = "SELECT check_id, category, title, status, owner, \
     evidence_ref, runbook, last_verified_at, notes \
     FROM operations_readiness_checks WHERE deployment_id = $1 ORDER BY category, check_id";
const AUTOMATION_CATEGORIES_SQL: &str = "SELECT category_id, display_name, destination, \
     severity, owner, minimized_metadata, deduplication_key, aggregation_window_minutes, \
     delivery_mode, blocks_mail_delivery, runbook, readiness_state, updated_at \
     FROM operations_automation_categories WHERE deployment_id = $1 ORDER BY category_id";

#[derive(Clone)]
pub struct OperationsState(Arc<OperationsStateInner>);

struct OperationsStateInner {
    pool: PgPool,
    deployment_id: DeploymentId,
    audit: Arc<dyn AuditStore>,
    high_risk_limiter: std::sync::Mutex<TokenBucket>,
}

impl OperationsState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self(Arc::new(OperationsStateInner {
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

#[derive(Serialize)]
struct ConfigScopeResponse {
    scope: String,
    scope_id: String,
    revision_number: i64,
    published_by: String,
    /// The publisher's human name for the console read model. Additive per
    /// `docs/27`: `published_by` stays the stored actor reference, because a
    /// configuration history has to keep naming the identity, not a label that
    /// can change.
    published_by_name: String,
    published_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct ConfigResponse {
    db_revision: Option<i64>,
    scopes: Vec<ConfigScopeResponse>,
}

#[derive(Serialize)]
struct RuntimeNodeResponse {
    id: String,
    node_type: String,
    role: String,
    status: String,
    hostname: Option<String>,
    version: String,
    config_revision: Option<i64>,
    last_health_check: Option<DateTime<Utc>>,
    stale: Option<bool>,
}

#[derive(Serialize)]
struct OutboxResponse {
    unpublished_count: i64,
    oldest_unpublished_age_seconds: Option<i64>,
}

#[derive(Serialize)]
struct DeadLettersResponse {
    count: i64,
}

#[derive(Serialize)]
struct ScannerFleetResponse {
    total: i64,
    active: i64,
    draining: i64,
    offline: i64,
}

#[derive(Serialize)]
struct SmtpResponse {
    commissioning: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct RuntimeSnapshotResponse {
    deployment_id: String,
    config: ConfigResponse,
    nodes: Vec<RuntimeNodeResponse>,
    outbox: OutboxResponse,
    dead_letters: DeadLettersResponse,
    scanner: ScannerFleetResponse,
    smtp: SmtpResponse,
}

#[derive(Serialize)]
struct OperationsHardeningResponse {
    deployment_id: String,
    generated_at: DateTime<Utc>,
    summary: HardeningSummaryResponse,
    tier3_capabilities: Vec<Tier3CapabilityResponse>,
    alert_rules: Vec<AlertRuleResponse>,
    automation_categories: Vec<AutomationCategoryResponse>,
    readiness_checks: Vec<ReadinessCheckResponse>,
}

#[derive(Serialize, Default)]
struct HardeningSummaryResponse {
    tier3_capabilities: i64,
    capabilities_tested: i64,
    alert_rules: i64,
    enabled_alert_rules: i64,
    automation_categories: i64,
    automation_categories_ready: i64,
    readiness_ready: i64,
    readiness_partial: i64,
    readiness_not_ready: i64,
    readiness_blocked: i64,
}

#[derive(Serialize)]
struct Tier3CapabilityResponse {
    capability_id: String,
    display_name: String,
    owner: String,
    sli: String,
    slo_target: String,
    error_budget: String,
    measurement_source: String,
    rto_minutes: i32,
    rpo_minutes: i32,
    dependency_map: String,
    redundancy_design: String,
    degraded_mode: String,
    capacity_threshold: String,
    runbook: String,
    readiness_state: String,
    last_exercise_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct AlertRuleResponse {
    alert_key: String,
    capability_id: String,
    severity: String,
    burn_rate: String,
    long_window_minutes: i32,
    short_window_minutes: i32,
    threshold_description: String,
    owner: String,
    runbook: String,
    suppression: String,
    escalation: String,
    enabled: bool,
    last_tested_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct AutomationCategoryResponse {
    category_id: String,
    display_name: String,
    destination: String,
    severity: String,
    owner: String,
    minimized_metadata: String,
    deduplication_key: String,
    aggregation_window_minutes: i32,
    delivery_mode: String,
    blocks_mail_delivery: bool,
    runbook: String,
    readiness_state: String,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct ReadinessCheckResponse {
    check_id: String,
    category: String,
    title: String,
    status: String,
    owner: String,
    evidence_ref: String,
    runbook: Option<String>,
    last_verified_at: Option<DateTime<Utc>>,
    notes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RefreshTarget {
    Deployment,
    Tenant,
    Node,
}

impl RefreshTarget {
    fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Tenant => "tenant",
            Self::Node => "node",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshBody {
    target: RefreshTarget,
    node_id: Option<String>,
}

#[derive(Serialize)]
struct RefreshResponse {
    requested_at: DateTime<Utc>,
    target: String,
    scope_id: String,
}

pub fn operations_router(state: OperationsState) -> Router {
    Router::new()
        .route(RUNTIME_PATH, get(get_runtime))
        .route(HARDENING_PATH, get(get_hardening))
        .route(REFRESH_PATH, post(post_refresh))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Authorization helpers
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

/// Audits a denial (observability only; the response is a denial either way,
/// so an audit write failure never changes the outcome) and returns it.
async fn denied(
    state: &OperationsState,
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
        error!(%error, "failed to audit runtime operations denial");
    }
    api_error(denial.status, denial.code, denial.message)
}

/// Permission, lifecycle, deployment — before any body parsing, rate limit,
/// audit or transaction work.
async fn authorize(
    state: &OperationsState,
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

/// Fresh step-up, then the shared fail-closed high-risk budget: permission
/// checks come first, and neither gate ever writes.
async fn require_high_risk(
    state: &OperationsState,
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

/// Writes the audit row in the caller's transaction: the request and its
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
    payload: Value,
    idempotency_key: String,
    context: &TenantContext,
    deployment_id: &DeploymentId,
) -> Result<(), Response> {
    sqlx::query(OUTBOX_INSERT_SQL)
        .bind(EVENT_CONFIG_CHANGED)
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

/// The operation name a refresh key is claimed under. It binds the
/// authenticated deployment and customer plus the resolved scope, so a key
/// already claimed in another session resolves to `OperationMismatch` instead
/// of replaying that session's stored response into this one.
fn refresh_operation(
    target: RefreshTarget,
    deployment_id: &str,
    customer_id: &str,
    scope_id: &str,
) -> String {
    format!(
        "runtime:refresh:{}:{deployment_id}:{customer_id}:{scope_id}",
        target.as_str()
    )
}

// ---------------------------------------------------------------------------
// Projection helpers
// ---------------------------------------------------------------------------

/// Node ids are operator-facing identifiers, so the same restricted charset
/// the refresh endpoint accepts is enforced server-side: `[A-Za-z0-9._-]{1,64}`.
fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= NODE_ID_MAX_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-'
        })
}

/// Config freshness needs both sides of the comparison. A missing database or
/// node revision is *unknown*, never "current": the UI must not present an
/// unverifiable value as verified.
fn stale(config_revision: Option<i64>, db_revision: Option<i64>) -> Option<bool> {
    match (config_revision, db_revision) {
        (Some(loaded), Some(db)) => Some(loaded < db),
        _ => None,
    }
}

/// Reports only the SMTP node rows that exist for this deployment. No
/// commissioning checklist, health or SLO is inferred from them.
fn smtp_summary(mail_nodes: usize) -> SmtpResponse {
    if mail_nodes == 0 {
        return SmtpResponse {
            commissioning: "not_configured",
            detail: "No SMTP mail nodes are recorded for this deployment; SMTP commissioning is \
                     managed outside this environment."
                .to_string(),
        };
    }
    SmtpResponse {
        commissioning: "recorded",
        detail: format!("{mail_nodes} SMTP mail node(s) recorded in the nodes table."),
    }
}

fn scanner_fleet(nodes: &[RuntimeNodeResponse]) -> ScannerFleetResponse {
    let scanner_nodes: Vec<&RuntimeNodeResponse> = nodes
        .iter()
        .filter(|node| node.node_type == "scanner")
        .collect();
    let by_status = |status: &str| -> i64 {
        scanner_nodes
            .iter()
            .filter(|node| node.status == status)
            .count() as i64
    };
    ScannerFleetResponse {
        total: scanner_nodes.len() as i64,
        active: by_status("active"),
        draining: by_status("draining"),
        offline: by_status("offline"),
    }
}

fn hardening_summary(
    capabilities: &[Tier3CapabilityResponse],
    alert_rules: &[AlertRuleResponse],
    automation_categories: &[AutomationCategoryResponse],
    checks: &[ReadinessCheckResponse],
) -> HardeningSummaryResponse {
    let count_checks = |status: &str| -> i64 {
        checks.iter().filter(|check| check.status == status).count() as i64
    };
    HardeningSummaryResponse {
        tier3_capabilities: capabilities.len() as i64,
        capabilities_tested: capabilities
            .iter()
            .filter(|capability| capability.readiness_state == "tested")
            .count() as i64,
        alert_rules: alert_rules.len() as i64,
        enabled_alert_rules: alert_rules.iter().filter(|rule| rule.enabled).count() as i64,
        automation_categories: automation_categories.len() as i64,
        automation_categories_ready: automation_categories
            .iter()
            .filter(|category| category.readiness_state == "ready")
            .count() as i64,
        readiness_ready: count_checks("ready"),
        readiness_partial: count_checks("partial"),
        readiness_not_ready: count_checks("not_ready"),
        readiness_blocked: count_checks("blocked"),
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

async fn get_runtime(
    State(state): State<OperationsState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let route = Route::new(
        ACTION_RUNTIME_VIEW,
        RESOURCE_RUNTIME_CONFIG,
        OPERATIONS_VIEW_PERMISSION,
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

    let scope_rows = match sqlx::query(CONFIG_SCOPES_SQL)
        .bind(&context.customer_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    // Configuration history stores an actor id. The console has to say who
    // published, so the same read model the policy and model surfaces use
    // resolves names here; an identity with no display data degrades to the
    // stored value rather than blanking the row.
    let actor_names = match crate::policy_admin::load_actor_display_names(&mut transaction).await {
        Ok(names) => names,
        Err(response) => return response,
    };
    let mut scopes: Vec<ConfigScopeResponse> = scope_rows
        .iter()
        .map(|row| {
            let published_by: String = row.get("published_by");
            let published_by_name =
                crate::policy_admin::actor_display_name(&actor_names, &published_by);
            ConfigScopeResponse {
                scope: row.get("scope"),
                scope_id: row.get("scope_id"),
                revision_number: row.get("revision_number"),
                published_by,
                published_by_name,
                published_at: row.get("published_at"),
            }
        })
        .collect();
    scopes.sort_by_key(|entry| std::cmp::Reverse(entry.revision_number));
    let db_revision = scopes.iter().map(|entry| entry.revision_number).max();

    let node_rows = match sqlx::query(NODES_SQL)
        .bind(&state.0.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let nodes: Vec<RuntimeNodeResponse> = node_rows
        .iter()
        .map(|row| RuntimeNodeResponse {
            id: row.get("id"),
            node_type: row.get("node_type"),
            role: row.get("role"),
            status: row.get("status"),
            hostname: row.get("hostname"),
            version: row.get("version"),
            config_revision: row.get("config_revision"),
            last_health_check: row.get("last_health_check"),
            stale: stale(row.get::<Option<i64>, _>("config_revision"), db_revision),
        })
        .collect();

    let outbox = match sqlx::query(OUTBOX_SQL)
        .bind(&state.0.deployment_id.0)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(row) => OutboxResponse {
            unpublished_count: row.get("unpublished_count"),
            oldest_unpublished_age_seconds: row
                .get::<Option<i64>, _>("oldest_unpublished_age_seconds")
                .map(|age| age.max(0)),
        },
        Err(_) => return unavailable(),
    };

    let dead_letters = match sqlx::query(DEAD_LETTERS_SQL)
        .bind(&state.0.deployment_id.0)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(row) => DeadLettersResponse {
            count: row.get("count"),
        },
        Err(_) => return unavailable(),
    };

    if transaction.commit().await.is_err() {
        return unavailable();
    }

    let mail_nodes = nodes.iter().filter(|node| node.node_type == "mail").count();
    let snapshot = RuntimeSnapshotResponse {
        deployment_id: state.0.deployment_id.0.clone(),
        config: ConfigResponse {
            db_revision,
            scopes,
        },
        scanner: scanner_fleet(&nodes),
        smtp: smtp_summary(mail_nodes),
        nodes,
        outbox,
        dead_letters,
    };
    (StatusCode::OK, Json(ApiEnvelope { data: snapshot })).into_response()
}

async fn get_hardening(
    State(state): State<OperationsState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let route = Route::new(
        ACTION_HARDENING_VIEW,
        RESOURCE_RUNTIME_CONFIG,
        OPERATIONS_VIEW_PERMISSION,
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

    let capabilities = match sqlx::query(TIER3_CAPABILITIES_SQL)
        .bind(&state.0.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| Tier3CapabilityResponse {
                capability_id: row.get("capability_id"),
                display_name: row.get("display_name"),
                owner: row.get("owner"),
                sli: row.get("sli"),
                slo_target: row.get("slo_target"),
                error_budget: row.get("error_budget"),
                measurement_source: row.get("measurement_source"),
                rto_minutes: row.get("rto_minutes"),
                rpo_minutes: row.get("rpo_minutes"),
                dependency_map: row.get("dependency_map"),
                redundancy_design: row.get("redundancy_design"),
                degraded_mode: row.get("degraded_mode"),
                capacity_threshold: row.get("capacity_threshold"),
                runbook: row.get("runbook"),
                readiness_state: row.get("readiness_state"),
                last_exercise_at: row.get("last_exercise_at"),
                updated_at: row.get("updated_at"),
            })
            .collect::<Vec<_>>(),
        Err(_) => return unavailable(),
    };
    let alert_rules = match sqlx::query(ALERT_RULES_SQL)
        .bind(&state.0.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| AlertRuleResponse {
                alert_key: row.get("alert_key"),
                capability_id: row.get("capability_id"),
                severity: row.get("severity"),
                burn_rate: row.get("burn_rate"),
                long_window_minutes: row.get("long_window_minutes"),
                short_window_minutes: row.get("short_window_minutes"),
                threshold_description: row.get("threshold_description"),
                owner: row.get("owner"),
                runbook: row.get("runbook"),
                suppression: row.get("suppression"),
                escalation: row.get("escalation"),
                enabled: row.get("enabled"),
                last_tested_at: row.get("last_tested_at"),
            })
            .collect::<Vec<_>>(),
        Err(_) => return unavailable(),
    };
    let readiness_checks = match sqlx::query(READINESS_CHECKS_SQL)
        .bind(&state.0.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| ReadinessCheckResponse {
                check_id: row.get("check_id"),
                category: row.get("category"),
                title: row.get("title"),
                status: row.get("status"),
                owner: row.get("owner"),
                evidence_ref: row.get("evidence_ref"),
                runbook: row.get("runbook"),
                last_verified_at: row.get("last_verified_at"),
                notes: row.get("notes"),
            })
            .collect::<Vec<_>>(),
        Err(_) => return unavailable(),
    };
    let automation_categories = match sqlx::query(AUTOMATION_CATEGORIES_SQL)
        .bind(&state.0.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| AutomationCategoryResponse {
                category_id: row.get("category_id"),
                display_name: row.get("display_name"),
                destination: row.get("destination"),
                severity: row.get("severity"),
                owner: row.get("owner"),
                minimized_metadata: row.get("minimized_metadata"),
                deduplication_key: row.get("deduplication_key"),
                aggregation_window_minutes: row.get("aggregation_window_minutes"),
                delivery_mode: row.get("delivery_mode"),
                blocks_mail_delivery: row.get("blocks_mail_delivery"),
                runbook: row.get("runbook"),
                readiness_state: row.get("readiness_state"),
                updated_at: row.get("updated_at"),
            })
            .collect::<Vec<_>>(),
        Err(_) => return unavailable(),
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    let response = OperationsHardeningResponse {
        deployment_id: state.0.deployment_id.0.clone(),
        generated_at: Utc::now(),
        summary: hardening_summary(
            &capabilities,
            &alert_rules,
            &automation_categories,
            &readiness_checks,
        ),
        tier3_capabilities: capabilities,
        alert_rules,
        automation_categories,
        readiness_checks,
    };
    (StatusCode::OK, Json(ApiEnvelope { data: response })).into_response()
}

async fn post_refresh(
    State(state): State<OperationsState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<RefreshBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let route = Route::new(
        ACTION_RUNTIME_REFRESH,
        RESOURCE_RUNTIME_CONFIG,
        OPERATIONS_MANAGE_PERMISSION,
    );
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    let node_id = match (body.target, body.node_id.as_deref()) {
        (RefreshTarget::Node, Some(raw)) if valid_node_id(raw) => Some(raw.to_string()),
        (RefreshTarget::Node, _) => return invalid_request(),
        (_, Some(_)) => return invalid_request(),
        (_, None) => None,
    };
    let scope_id = match body.target {
        RefreshTarget::Deployment => state.0.deployment_id.0.clone(),
        RefreshTarget::Tenant => context.customer_id.0.clone(),
        RefreshTarget::Node => match node_id {
            Some(node_id) => node_id,
            None => return invalid_request(),
        },
    };
    let route = route.with_resource(scope_id.clone());
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
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

    // A node target is resolved against the registration table, so a name the
    // deployment does not own is a denial rather than a silently accepted
    // refresh. The transaction is dropped first: a failed request must not
    // leave a claim or a partial write behind.
    if body.target == RefreshTarget::Node {
        let registered = match sqlx::query_scalar::<_, i32>(NODE_EXISTS_SQL)
            .bind(&scope_id)
            .bind(&state.0.deployment_id.0)
            .fetch_optional(&mut *transaction)
            .await
        {
            Ok(registered) => registered,
            Err(_) => return unavailable(),
        };
        if registered.is_none() {
            drop(transaction);
            return denied(
                &state,
                &context,
                &headers,
                &route,
                &Denial::not_found("Node was not found", "node not found"),
            )
            .await;
        }
    }

    let operation = refresh_operation(
        body.target,
        &state.0.deployment_id.0,
        &context.customer_id.0,
        &scope_id,
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

    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_RUNTIME_REFRESH,
            resource_type: RESOURCE_RUNTIME_CONFIG,
            resource_id: Some(scope_id.clone()),
            customer_id: context.customer_id.0.clone(),
            details: json!({
                "target": body.target.as_str(),
                "scope_id": scope_id,
            }),
        },
    )
    .await
    {
        return response;
    }
    if let Err(response) = write_outbox(
        &mut transaction,
        json!({
            "target": body.target.as_str(),
            "scope_id": scope_id,
            "reason": "manual_refresh",
        }),
        format!("runtime-refresh:{key}"),
        &context,
        &state.0.deployment_id,
    )
    .await
    {
        return response;
    }

    let response = RefreshResponse {
        requested_at: Utc::now(),
        target: body.target.as_str().to_string(),
        scope_id,
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
    use crate::admin_rbac::SYSTEM_ADMIN_ROLE;

    fn state() -> OperationsState {
        // A short acquire timeout keeps failure paths deterministic: the
        // unreachable pool must fail quickly instead of masking gate order.
        let pool = PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse");
        OperationsState::new(pool, DeploymentId::new("LOCAL-TEST"))
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
                OPERATIONS_VIEW_PERMISSION.to_string(),
                OPERATIONS_MANAGE_PERMISSION.to_string(),
            ],
            config_revision: 1,
            trace_id: "operations-api-test".to_string(),
            correlation_id: "operations-api-test".to_string(),
            session_id: "operations-api-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("test request must build")
    }

    fn post(uri: &str, key: Option<&str>, body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("x-idempotency-key", key);
        }
        builder
            .body(Body::from(body.to_string()))
            .expect("test request must build")
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

    fn all_route_requests() -> Vec<Request<Body>> {
        vec![
            get("/api/v1/operations/runtime"),
            get("/api/v1/operations/hardening"),
            post(
                "/api/v1/operations/refresh",
                Some("key-refresh"),
                r#"{"target":"deployment"}"#,
            ),
        ]
    }

    #[tokio::test]
    async fn runtime_operations_require_authenticated_context() {
        let app = operations_router(state());
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
    async fn runtime_snapshot_requires_view_permission_before_database_access() {
        let mut context = context();
        context.permissions.clear();
        let response = operations_router(state())
            .layer(Extension(context))
            .oneshot(get("/api/v1/operations/runtime"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("FORBIDDEN", "Permission is required")
        );
    }

    #[tokio::test]
    async fn hardening_projection_requires_view_permission_before_database_access() {
        let mut context = context();
        context.permissions.clear();
        let response = operations_router(state())
            .layer(Extension(context))
            .oneshot(get("/api/v1/operations/hardening"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("FORBIDDEN", "Permission is required")
        );
    }

    #[tokio::test]
    async fn runtime_refresh_requires_manage_permission_before_database_access() {
        let mut context = context();
        context
            .permissions
            .retain(|permission| permission != OPERATIONS_MANAGE_PERMISSION);
        let response = operations_router(state())
            .layer(Extension(context))
            .oneshot(post(
                "/api/v1/operations/refresh",
                Some("key-no-manage"),
                r#"{"target":"deployment"}"#,
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
    async fn foreign_deployment_context_is_denied_before_database_access() {
        let mut context = context();
        context.deployment_id = DeploymentId::new("OTHER-DEPLOYMENT");
        let response = operations_router(state())
            .layer(Extension(context))
            .oneshot(get("/api/v1/operations/runtime"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("FORBIDDEN", "Permission is required")
        );
    }

    #[tokio::test]
    async fn runtime_refresh_requires_fresh_step_up_authentication() {
        let mut context = context();
        context.actor.authentication_assurance = AuthenticationAssurance::Standard;
        let response = operations_router(state())
            .layer(Extension(context))
            .oneshot(post(
                "/api/v1/operations/refresh",
                Some("key-step-up"),
                r#"{"target":"deployment"}"#,
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
    async fn runtime_refresh_requires_an_idempotency_key() {
        let app = operations_router(state()).layer(Extension(context()));
        let missing = app
            .clone()
            .oneshot(post(
                "/api/v1/operations/refresh",
                None,
                r#"{"target":"deployment"}"#,
            ))
            .await
            .expect("test response");
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_value(missing).await,
            error_body("IDEMPOTENCY_REQUIRED", "Idempotency key is required")
        );

        let empty = app
            .oneshot(post(
                "/api/v1/operations/refresh",
                Some(""),
                r#"{"target":"deployment"}"#,
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
    async fn runtime_refresh_rejects_bad_requests_before_database_access() {
        let requests = vec![
            post(
                "/api/v1/operations/refresh",
                Some("v1"),
                r#"{"target":"deployment","extra":true}"#,
            ),
            post(
                "/api/v1/operations/refresh",
                Some("v2"),
                r#"{"target":"node"}"#,
            ),
            post(
                "/api/v1/operations/refresh",
                Some("v3"),
                r#"{"target":"node","node_id":"mx-1","extra":true}"#,
            ),
            post(
                "/api/v1/operations/refresh",
                Some("v4"),
                r#"{"target":"bogus"}"#,
            ),
            post(
                "/api/v1/operations/refresh",
                Some("v5"),
                r#"{"target":"node","node_id":"bad/id"}"#,
            ),
            post(
                "/api/v1/operations/refresh",
                Some("v6"),
                r#"{"target":"node","node_id":""}"#,
            ),
            post(
                "/api/v1/operations/refresh",
                Some("v7"),
                r#"{"target":"node","node_id":"mx-1-with-a-node-id-longer-than-sixty-four-characters-extra-toolong"}"#,
            ),
            post(
                "/api/v1/operations/refresh",
                Some("v8"),
                r#"{"target":"deployment","node_id":"mx-1"}"#,
            ),
            post("/api/v1/operations/refresh", Some("v9"), "{"),
        ];
        let app = operations_router(state()).layer(Extension(context()));
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
    async fn authorized_refresh_reaches_the_database() {
        let response = operations_router(state())
            .layer(Extension(context()))
            .oneshot(post(
                "/api/v1/operations/refresh",
                Some("key-database"),
                r#"{"target":"tenant"}"#,
            ))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_value(response).await,
            error_body("UNAVAILABLE", "Service is unavailable")
        );
    }

    #[tokio::test]
    async fn high_risk_budget_is_fail_closed() {
        let app = operations_router(state()).layer(Extension(context()));
        let mut statuses = Vec::new();
        let mut last = None;
        for index in 0..6 {
            let key = format!("key-rate-{index}");
            let response = app
                .clone()
                .oneshot(post(
                    "/api/v1/operations/refresh",
                    Some(&key),
                    r#"{"target":"deployment"}"#,
                ))
                .await
                .expect("test response");
            statuses.push(response.status());
            last = Some(response);
        }
        let mut expected = vec![StatusCode::SERVICE_UNAVAILABLE; 5];
        expected.push(StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(statuses, expected);
        let last = last.expect("sixth response");
        assert_eq!(
            last.headers()
                .get("retry-after")
                .map(|value| value.to_str().expect("retry-after header")),
            Some("60")
        );
        assert_eq!(
            body_value(last).await,
            error_body("RATE_LIMITED", "Too many high-risk changes")
        );
    }

    #[test]
    fn smtp_commissioning_reports_only_recorded_node_counts() {
        let none = smtp_summary(0);
        assert_eq!(none.commissioning, "not_configured");
        assert!(none
            .detail
            .contains("No SMTP mail nodes are recorded for this deployment"));

        let recorded = smtp_summary(2);
        assert_eq!(recorded.commissioning, "recorded");
        assert!(recorded
            .detail
            .contains("2 SMTP mail node(s) recorded in the nodes table."));
    }

    #[test]
    fn config_freshness_requires_both_revisions() {
        assert_eq!(stale(Some(5), Some(10)), Some(true));
        assert_eq!(stale(Some(10), Some(5)), Some(false));
        assert_eq!(stale(Some(5), Some(5)), Some(false));
        assert_eq!(stale(None, Some(10)), None);
        assert_eq!(stale(Some(5), None), None);
        assert_eq!(stale(None, None), None);
    }

    #[test]
    fn idempotent_refresh_replays_are_scoped_to_session_and_target() {
        let tenant_a = refresh_operation(RefreshTarget::Tenant, "DEP-A", "cust-a", "cust-a");
        let tenant_b = refresh_operation(RefreshTarget::Tenant, "DEP-A", "cust-b", "cust-b");
        let other_deployment =
            refresh_operation(RefreshTarget::Tenant, "DEP-B", "cust-a", "cust-a");
        let deployment_scope_a =
            refresh_operation(RefreshTarget::Deployment, "DEP-A", "cust-a", "DEP-A");
        let deployment_scope_b =
            refresh_operation(RefreshTarget::Deployment, "DEP-A", "cust-b", "DEP-A");
        let node_a = refresh_operation(RefreshTarget::Node, "DEP-A", "cust-a", "mx-1");
        let node_b = refresh_operation(RefreshTarget::Node, "DEP-A", "cust-a", "mx-2");

        assert_ne!(
            tenant_a, tenant_b,
            "a key claimed by one tenant must not replay another tenant's response"
        );
        assert_ne!(
            tenant_a, other_deployment,
            "a key claimed in one deployment must not replay another deployment's response"
        );
        assert_ne!(
            deployment_scope_a, deployment_scope_b,
            "a key claimed by one customer must not replay another customer's deployment refresh"
        );
        assert_ne!(node_a, node_b, "one key may only cover one node target");
        // The name is stable for the same session and scope so an honest retry
        // still replays its own completed response.
        assert_eq!(
            tenant_a,
            refresh_operation(RefreshTarget::Tenant, "DEP-A", "cust-a", "cust-a")
        );
    }
}

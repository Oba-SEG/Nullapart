//! Customer and domain administration for the local control plane.
//!
//! Every route is authenticated context first, then validation, then the
//! idempotency claim for mutations, then permission/lifecycle/deployment/
//! scope authorization, then role gates, then the shared high-risk gate
//! (step-up, fail-closed budget), and only then a database transaction.

use std::sync::Arc;

use axum::{
    extract::{rejection::JsonRejection, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
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
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::admin_audit::{source_ip_from, AuditEventRecord, AuditStore, PostgresAuditStore};
use crate::admin_capabilities::{Blocker, WriteCapability};
use crate::admin_rbac::{SUPPORT_ROLE, SYSTEM_ADMIN_ROLE};
use crate::dns_txt::DnsTxtResolver;
use crate::idempotency::{claim, complete, ClaimOutcome};

pub const CUSTOMERS_VIEW_PERMISSION: &str = "admin:customers:view";
pub const CUSTOMERS_MANAGE_PERMISSION: &str = "admin:customers:manage";
pub const DOMAINS_MANAGE_PERMISSION: &str = "admin:domains:manage";

const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const CUSTOMER_ID_MAX_LEN: usize = 128;
/// Advisory-lock namespace for regional customer sequence allocation.
const CUSTOMER_ID_LOCK_NAMESPACE: &str = "nullapart:customer-id:";
const DISPLAY_NAME_MAX_LEN: usize = 128;
const GROUP_NAME_MAX_LEN: usize = 128;
const DOMAIN_MAX_LEN: usize = 253;
const DOMAIN_LABEL_MAX_LEN: usize = 63;
const CIDR_MAX_ENTRIES: usize = 64;
const CIDR_MAX_LEN: usize = 64;
const REASON_MIN_LEN: usize = 10;
const REASON_MAX_LEN: usize = 500;

const CUSTOMERS_PATH: &str = "/api/v1/admin/customers";
const CUSTOMER_PATH: &str = "/api/v1/admin/customers/:customer_id";
const CUSTOMER_DOMAINS_PATH: &str = "/api/v1/admin/customers/:customer_id/domains";
const DOMAIN_VERIFY_PATH: &str = "/api/v1/admin/customers/:customer_id/domains/:domain_id/verify";
const SOURCE_IP_GROUPS_PATH: &str = "/api/v1/admin/customers/:customer_id/source-ip-groups";
const SOURCE_IP_GROUP_PATH: &str =
    "/api/v1/admin/customers/:customer_id/source-ip-groups/:group_id";

const ACTION_CUSTOMER_LIST: &str = "customer_list";
const ACTION_CUSTOMER_DETAIL: &str = "customer_detail";
const ACTION_CUSTOMER_CREATED: &str = "customer_created";
const ACTION_CUSTOMER_UPDATED: &str = "customer_updated";
const ACTION_DOMAIN_ADDED: &str = "domain_added";
const ACTION_DOMAIN_VERIFIED: &str = "domain_verified";
const ACTION_DOMAIN_VERIFICATION_FAILED: &str = "domain_verification_failed";
const ACTION_GROUP_LIST: &str = "source_ip_group_list";
const ACTION_GROUP_CREATED: &str = "source_ip_group_created";
const ACTION_GROUP_DELETED: &str = "source_ip_group_deleted";

const RESOURCE_CUSTOMER: &str = "customer";
const RESOURCE_DOMAIN: &str = "domain";
const RESOURCE_GROUP: &str = "source_ip_group";

const LIST_ALL_SQL: &str = "SELECT c.id, c.display_name, c.internal_key, c.lifecycle, \
     c.created_at, c.updated_at, count(d.id)::bigint, c.region_code, c.sequence_no \
     FROM customers c LEFT JOIN domains d ON d.customer_id = c.id \
     WHERE c.deployment_id = $1 GROUP BY c.id ORDER BY c.internal_key LIMIT 200";
const LIST_OWN_SQL: &str = "SELECT c.id, c.display_name, c.internal_key, c.lifecycle, \
     c.created_at, c.updated_at, count(d.id)::bigint, c.region_code, c.sequence_no \
     FROM customers c LEFT JOIN domains d ON d.customer_id = c.id \
     WHERE c.deployment_id = $1 AND c.id = $2 \
     GROUP BY c.id ORDER BY c.internal_key LIMIT 200";
const CUSTOMER_SQL: &str =
    "SELECT id, display_name, internal_key, lifecycle, created_at, updated_at, \
     region_code, sequence_no \
     FROM customers WHERE id = $1 AND deployment_id = $2";
const DOMAIN_COUNT_SQL: &str = "SELECT count(*) FROM domains WHERE customer_id = $1";
const DOMAINS_LIST_SQL: &str = "SELECT id, domain, domain_type, verification_status, \
     verification_method, verification_attempts, verification_expires_at, verified_at, \
     created_at, verification_token FROM domains WHERE customer_id = $1 \
     ORDER BY created_at, id";
const GROUPS_LIST_SQL: &str = "SELECT id, name, cidrs, created_at FROM source_ip_groups \
     WHERE customer_id = $1 AND deployment_id = $2 ORDER BY name, id";
const CUSTOMER_STATE_SQL: &str =
    "SELECT lifecycle FROM customers WHERE id = $1 AND deployment_id = $2";
const CUSTOMER_INSERT_SQL: &str = "INSERT INTO customers \
     (id, deployment_id, display_name, region_code, sequence_no) \
     VALUES ($1, $2, $3, $4, $5) \
     RETURNING internal_key, created_at, updated_at";
const CUSTOMER_REGION_SQL: &str = "SELECT region FROM deployments WHERE id = $1";
const CUSTOMER_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtext($1))";
const CUSTOMER_NEXT_SEQUENCE_SQL: &str =
    "SELECT COALESCE(max(sequence_no), 0) + 1 FROM customers WHERE region_code = $1";
const CUSTOMER_PATCH_SQL: &str = "UPDATE customers SET lifecycle = $3, updated_at = now() \
     WHERE id = $1 AND deployment_id = $2 \
     RETURNING display_name, internal_key, created_at, updated_at, region_code, sequence_no";
const DOMAIN_EXISTS_SQL: &str = "SELECT 1 FROM domains WHERE lower(domain) = $1";
const DOMAIN_INSERT_SQL: &str = "INSERT INTO domains \
     (customer_id, domain, domain_type, verification_status, verification_token) \
     VALUES ($1, $2, $3, 'pending', $4) RETURNING id, created_at";
const DOMAIN_SELECT_SQL: &str = "SELECT d.id, d.domain, d.domain_type, d.verification_status, \
     d.verification_method, d.verification_attempts, d.verification_expires_at, d.verified_at, \
     d.created_at, d.verification_token FROM domains d \
     JOIN customers c ON c.id = d.customer_id \
     WHERE d.id = $1 AND d.customer_id = $2 AND c.deployment_id = $3";
const DOMAIN_VERIFY_OK_SQL: &str = "UPDATE domains SET verification_status = 'verified', \
     verification_method = 'dns_txt', verified_at = now(), \
     verification_attempts = verification_attempts + 1 WHERE id = $1 \
     RETURNING verification_status, verification_method, verification_attempts, \
     verification_expires_at, verified_at";
const DOMAIN_VERIFY_FAILED_SQL: &str = "UPDATE domains SET verification_status = 'failed', \
     verification_attempts = verification_attempts + 1 WHERE id = $1 \
     RETURNING verification_status, verification_method, verification_attempts, \
     verification_expires_at, verified_at";
const GROUP_EXISTS_SQL: &str =
    "SELECT 1 FROM source_ip_groups WHERE customer_id = $1 AND name = $2";
const GROUP_INSERT_SQL: &str = "INSERT INTO source_ip_groups \
     (deployment_id, customer_id, name, cidrs, created_by) \
     VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at";
const GROUP_DELETE_SQL: &str = "DELETE FROM source_ip_groups \
     WHERE id = $1 AND customer_id = $2 AND deployment_id = $3 RETURNING name";

#[derive(Clone)]
pub struct AdminCustomersState(Arc<AdminCustomersStateInner>);

struct AdminCustomersStateInner {
    pool: PgPool,
    deployment_id: DeploymentId,
    audit: Arc<dyn AuditStore>,
    resolver: DnsTxtResolver,
    high_risk_limiter: std::sync::Mutex<TokenBucket>,
}

impl AdminCustomersState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self(Arc::new(AdminCustomersStateInner {
            audit: Arc::new(PostgresAuditStore::new(pool.clone())),
            resolver: DnsTxtResolver::from_env(),
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
struct CustomerSummaryResponse {
    id: String,
    display_name: String,
    internal_key: i64,
    lifecycle: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    domain_count: i64,
    /// Operational placement (migration 018). Nullable because direct
    /// database fixtures may predate the columns; freshly created customers
    /// always carry both.
    region_code: Option<String>,
    sequence_no: Option<i64>,
}

#[derive(Serialize)]
struct CustomerDetailResponse {
    #[serde(flatten)]
    summary: CustomerSummaryResponse,
    domains: Vec<DomainResponse>,
    source_ip_groups: Vec<SourceIpGroupResponse>,
    capabilities: CustomerCapabilities,
}

#[derive(Serialize)]
struct DomainResponse {
    id: Uuid,
    domain: String,
    domain_type: String,
    verification_status: String,
    verification_method: String,
    verification_attempts: i32,
    verification_expires_at: Option<DateTime<Utc>>,
    verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    verification_token: Option<String>,
}

#[derive(Serialize)]
struct SourceIpGroupResponse {
    id: Uuid,
    name: String,
    cidrs: Vec<String>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct DeletedResponse {
    id: Uuid,
    deleted: bool,
}

/// Published with the customer list and detail payloads. Every field is the
/// output of the same predicates the write handlers run, so UI gating and API
/// authorization cannot drift apart.
#[derive(Serialize)]
struct CustomerCapabilities {
    create_customer: WriteCapability,
    change_lifecycle: WriteCapability,
    add_send_only_domain: WriteCapability,
}

#[derive(Serialize)]
struct CustomerListResponse {
    customers: Vec<CustomerSummaryResponse>,
    capabilities: CustomerCapabilities,
}

#[derive(Serialize)]
struct SourceIpGroupListResponse {
    groups: Vec<SourceIpGroupResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCustomerBody {
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateCustomerBody {
    lifecycle: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDomainBody {
    domain: String,
    domain_type: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSourceIpGroupBody {
    name: String,
    cidrs: Vec<String>,
}

pub fn admin_customers_router(state: AdminCustomersState) -> Router {
    Router::new()
        .route(CUSTOMERS_PATH, get(list_customers).post(create_customer))
        .route(CUSTOMER_PATH, get(get_customer).patch(update_customer))
        .route(CUSTOMER_DOMAINS_PATH, post(create_domain))
        .route(DOMAIN_VERIFY_PATH, post(verify_domain))
        .route(
            SOURCE_IP_GROUPS_PATH,
            get(list_source_ip_groups).post(create_source_ip_group),
        )
        .route(SOURCE_IP_GROUP_PATH, delete(delete_source_ip_group))
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
    target: Option<&'a str>,
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

/// A unique-constraint violation (23505) on a guarded insert means the row
/// already exists — including the cross-customer duplicate the RLS-scoped
/// pre-check cannot see. Anything else stays an availability failure so no
/// SQL detail leaks to the caller.
fn unique_violation_or_unavailable(error: &sqlx::Error, message: &'static str) -> Response {
    match error {
        sqlx::Error::Database(database) if database.code().as_deref() == Some("23505") => {
            conflict(message)
        },
        _ => unavailable(),
    }
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

/// Built-in roles that may mint or retire a customer identity. A custom role
/// can be granted `admin:customers:manage` and still manage the customers it is
/// scoped to, while creating a customer or switching one off stays with the
/// platform roles (docs/03-IDENTITY-RBAC-IMPERSONATION.md).
const CUSTOMER_IDENTITY_ROLES: &[&str] = &[SYSTEM_ADMIN_ROLE, SUPPORT_ROLE];

fn may_change_customer_identity(context: &TenantContext) -> bool {
    CUSTOMER_IDENTITY_ROLES
        .iter()
        .any(|role| has_role(context, role))
}

/// Every non-interactive gate a customer write must clear, in the order
/// [`authorize`] applies them. `authorize` and the published capabilities call
/// this one predicate, so the reason the console states is the reason the API
/// applied; a client never re-derives it from role names.
fn session_blocker(
    context: &TenantContext,
    deployment_id: &DeploymentId,
    permission: &str,
    requires_identity_role: bool,
) -> Option<Blocker> {
    if !has_permission(context, permission) {
        return Some(Blocker::Permission);
    }
    if context.customer_lifecycle != CustomerLifecycle::Active {
        return Some(Blocker::Lifecycle);
    }
    if &context.deployment_id != deployment_id {
        return Some(Blocker::Deployment);
    }
    if requires_identity_role && !may_change_customer_identity(context) {
        return Some(Blocker::Role);
    }
    None
}

fn customer_capabilities(
    context: &TenantContext,
    deployment_id: &DeploymentId,
) -> CustomerCapabilities {
    CustomerCapabilities {
        create_customer: WriteCapability::from_blocker(session_blocker(
            context,
            deployment_id,
            CUSTOMERS_MANAGE_PERMISSION,
            true,
        )),
        change_lifecycle: WriteCapability::from_blocker(session_blocker(
            context,
            deployment_id,
            CUSTOMERS_MANAGE_PERMISSION,
            true,
        )),
        add_send_only_domain: WriteCapability::from_blocker(session_blocker(
            context,
            deployment_id,
            DOMAINS_MANAGE_PERMISSION,
            true,
        )),
    }
}

/// Whether `target` sits inside this session's authorized customer scope.
/// Customer entry narrows hard to the entered customer, even for a System
/// Administrator: the actor's permissions stay their own, while the tenant
/// data they operate on is the entered one.
fn in_scope(context: &TenantContext, target: &str) -> bool {
    if let Some(impersonation) = &context.impersonation {
        return impersonation.impersonated_customer.0 == target;
    }
    context.customer_id.0 == target || has_role(context, SYSTEM_ADMIN_ROLE)
}

/// Audits a denial (observability only; the response is a denial either
/// way, so an audit write failure never changes the outcome) and returns
/// the response.
async fn denied(
    state: &AdminCustomersState,
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
        error!(%error, "failed to audit customer administration denial");
    }
    api_error(denial.status, denial.code, denial.message)
}

/// Permission, lifecycle, deployment, then scope — in that order, before
/// any rate limit, audit, or transaction work.
async fn authorize(
    state: &AdminCustomersState,
    context: &TenantContext,
    headers: &HeaderMap,
    route: &Route<'_>,
) -> Result<(), Response> {
    // The role gate is not part of this call: only the routes that mint or
    // retire customer identity carry it, and they run
    // `may_change_customer_identity` explicitly after authorizing.
    let denial = match session_blocker(context, &state.0.deployment_id, route.permission, false) {
        Some(Blocker::Permission) => Some(Denial::missing_permission(route.permission)),
        Some(Blocker::Lifecycle) => Some(Denial::forbidden("customer lifecycle is not active")),
        Some(Blocker::Deployment) => Some(Denial::forbidden("deployment mismatch")),
        Some(Blocker::Role) | None => None,
    };
    if let Some(denial) = denial {
        return Err(denied(state, context, headers, route, &denial).await);
    }
    if let Some(target) = route.target {
        if !in_scope(context, target) {
            return Err(denied(
                state,
                context,
                headers,
                route,
                &Denial::not_found("Customer was not found", "not in scope"),
            )
            .await);
        }
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

/// Fresh step-up, then the shared fail-closed permission-change budget:
/// permission checks come first, and neither gate ever writes.
async fn require_high_risk(
    state: &AdminCustomersState,
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

/// Sets only the deployment tenant GUC, for the pre-mint phase of customer
/// creation where the customer identity does not exist yet but the regional
/// sequence read already touches the FORCE-row-level-secured `customers`
/// table (migration 034). The customer GUC follows once the identity is
/// minted (see `set_scope`).
async fn set_deployment_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
) -> Result<(), Response> {
    sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
        .bind(deployment_id)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(|_| unavailable())
}

/// Claims the idempotency key inside the caller's transaction. Error paths
/// drop the transaction, rolling back both the claim and any partial work,
/// so a failed request never burns its key.
async fn begin_claim(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
    operation: &str,
) -> Result<ClaimOutcome, Response> {
    claim(transaction, key, operation)
        .await
        .map_err(|_| unavailable())
}

/// Mints the next operational customer identity for the deployment's region:
/// `"C" + region code + "-" + sequence` (docs/02-REGIONS-TENANCY-NAMING.md,
/// for example `CZA-1`), returning `(id, region_code, sequence_no)` so the
/// structured fields are stored beside the visible ID.
///
/// The sequence is allocated under a transaction-scoped advisory lock keyed by
/// region, so concurrent creations serialize until commit and two callers can
/// never mint the same identity. A deployment whose region is not a canonical
/// docs/02 code fails closed instead of producing an identity no parser will
/// accept.
///
/// The caller's transaction must already assert
/// `app.current_deployment_id` (see `set_deployment_scope`): the sequence
/// read touches the FORCE-row-level-secured `customers` table (migration
/// 034), and an unscoped transaction matches zero rows, which would mint
/// sequence 1 forever.
pub async fn next_customer_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
) -> Result<(String, String, i64), Response> {
    let region: Option<String> = sqlx::query_scalar(CUSTOMER_REGION_SQL)
        .bind(deployment_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| unavailable())?
        .map(|raw: String| raw.to_ascii_uppercase());
    let Some(region) = region else {
        return Err(unavailable());
    };
    if !valid_region_code(&region) {
        return Err(unavailable());
    }
    sqlx::query(CUSTOMER_LOCK_SQL)
        .bind(format!("{CUSTOMER_ID_LOCK_NAMESPACE}{region}"))
        .execute(&mut **transaction)
        .await
        .map_err(|_| unavailable())?;
    let sequence: i64 = sqlx::query_scalar(CUSTOMER_NEXT_SEQUENCE_SQL)
        .bind(&region)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| unavailable())?;
    Ok((format_customer_id(&region, sequence), region, sequence))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn valid_path_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= CUSTOMER_ID_MAX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Canonical docs/02 region code: two or three uppercase ASCII letters
/// (`ZA`, `ZAB`, `ZAC`, `EU`, `UK`, `US`).
fn valid_region_code(region: &str) -> bool {
    (2..=3).contains(&region.len()) && region.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn format_customer_id(region: &str, sequence: i64) -> String {
    format!("C{region}-{sequence}")
}

fn has_control_characters(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn valid_display_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= DISPLAY_NAME_MAX_LEN && !has_control_characters(value)
}

fn valid_reason(value: &str) -> bool {
    value.len() >= REASON_MIN_LEN && value.len() <= REASON_MAX_LEN
}

fn valid_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > DOMAIN_MAX_LEN || value.ends_with('.') {
        return false;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= DOMAIN_LABEL_MAX_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn valid_group_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= GROUP_NAME_MAX_LEN && !has_control_characters(value)
}

fn valid_cidr(value: &str) -> bool {
    if value.is_empty() || value.len() > CIDR_MAX_LEN {
        return false;
    }
    let (address, prefix) = match value.rsplit_once('/') {
        Some((address, prefix)) => match prefix.parse::<u8>() {
            Ok(prefix) => (address, Some(prefix)),
            Err(_) => return false,
        },
        None => (value, None),
    };
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => match prefix {
            Some(prefix) => prefix <= 32,
            None => true,
        },
        Ok(std::net::IpAddr::V6(_)) => match prefix {
            Some(prefix) => prefix <= 128,
            None => true,
        },
        Err(_) => false,
    }
}

fn transition_allowed(current: &str, target: &str) -> bool {
    match current {
        "active" => matches!(target, "grace" | "suspended" | "terminated"),
        "grace" => matches!(target, "active" | "suspended" | "terminated"),
        "suspended" => matches!(target, "active" | "terminated"),
        "terminated" => target == "active",
        _ => false,
    }
}

type CustomerRow = (
    String,
    String,
    i64,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<String>,
    Option<i64>,
);
type CustomerListRow = (
    String,
    String,
    i64,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    i64,
    Option<String>,
    Option<i64>,
);
type DomainRow = (
    Uuid,
    String,
    String,
    String,
    Option<String>,
    i32,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<String>,
);
type VerificationRow = (
    String,
    Option<String>,
    i32,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);
type GroupRow = (Uuid, String, Vec<String>, DateTime<Utc>);

fn domain_from_row(row: DomainRow) -> DomainResponse {
    DomainResponse {
        id: row.0,
        domain: row.1,
        domain_type: row.2,
        verification_status: row.3,
        verification_method: row.4.unwrap_or_else(|| "unspecified".to_string()),
        verification_attempts: row.5,
        verification_expires_at: row.6,
        verified_at: row.7,
        created_at: row.8,
        verification_token: row.9,
    }
}

fn apply_verification(domain: &mut DomainResponse, row: VerificationRow) {
    domain.verification_status = row.0;
    domain.verification_method = row.1.unwrap_or_else(|| "unspecified".to_string());
    domain.verification_attempts = row.2;
    domain.verification_expires_at = row.3;
    domain.verified_at = row.4;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

async fn list_customers(
    State(state): State<AdminCustomersState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let route = Route {
        action: ACTION_CUSTOMER_LIST,
        resource_type: RESOURCE_CUSTOMER,
        resource_id: None,
        permission: CUSTOMERS_VIEW_PERMISSION,
        target: Some(&context.customer_id.0),
    };
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
    // Customer entry never reduces the actor's own rights: a System Admin
    // keeps the full customer directory while entered.
    let list_all = has_role(&context, SYSTEM_ADMIN_ROLE);
    let rows: Result<Vec<CustomerListRow>, sqlx::Error> = if list_all {
        sqlx::query_as::<_, CustomerListRow>(LIST_ALL_SQL)
            .bind(&state.0.deployment_id.0)
            .fetch_all(&mut *transaction)
            .await
    } else {
        sqlx::query_as::<_, CustomerListRow>(LIST_OWN_SQL)
            .bind(&state.0.deployment_id.0)
            .bind(&context.customer_id.0)
            .fetch_all(&mut *transaction)
            .await
    };
    let rows = match rows {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let customers = rows
        .into_iter()
        .map(
            |(
                id,
                display_name,
                internal_key,
                lifecycle,
                created_at,
                updated_at,
                domain_count,
                region_code,
                sequence_no,
            )| {
                CustomerSummaryResponse {
                    id,
                    display_name,
                    internal_key,
                    lifecycle,
                    created_at,
                    updated_at,
                    domain_count,
                    region_code,
                    sequence_no,
                }
            },
        )
        .collect();
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: CustomerListResponse {
                customers,
                capabilities: customer_capabilities(&context, &state.0.deployment_id),
            },
        }),
    )
        .into_response()
}

async fn create_customer(
    State(state): State<AdminCustomersState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<CreateCustomerBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    let display_name = body.display_name.trim();
    if !valid_display_name(display_name) {
        return invalid_request();
    }
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    // Authorization, the role gate and the high-risk gate all run before the
    // transaction opens, so no pool connection or advisory lock is held on a
    // denied path and the regional sequence lock is only ever taken by a
    // caller that has already proven it may create a customer (module
    // invariant: authorize before any transaction or side effect).
    let route = Route {
        action: ACTION_CUSTOMER_CREATED,
        resource_type: RESOURCE_CUSTOMER,
        resource_id: None,
        permission: CUSTOMERS_MANAGE_PERMISSION,
        target: None,
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if !may_change_customer_identity(&context) {
        return denied(
            &state,
            &context,
            &headers,
            &route,
            &Denial::forbidden("customer creation requires the support or system_admin role"),
        )
        .await;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    // The regional sequence read touches the FORCE-row-level-secured
    // `customers` table (migration 034), so the deployment tenant GUC must be
    // asserted before the mint; the customer GUC follows once the identity
    // exists.
    if let Err(response) = set_deployment_scope(&mut transaction, &state.0.deployment_id.0).await {
        return response;
    }
    // Mint the operational identity inside the caller's transaction: the
    // regional sequence lock is held until commit, so two concurrent creations
    // can never claim the same `C{REGION}-{sequence}` (docs/02).
    let (customer_id, region_code, sequence_no) =
        match next_customer_id(&mut transaction, &state.0.deployment_id.0).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    if let Err(response) = set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
    {
        return response;
    }
    let operation = format!("admin:customer:create:{}", state.0.deployment_id.0);
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
    let row = match sqlx::query_as::<_, (i64, DateTime<Utc>, DateTime<Utc>)>(CUSTOMER_INSERT_SQL)
        .bind(&customer_id)
        .bind(&state.0.deployment_id.0)
        .bind(display_name)
        .bind(&region_code)
        .bind(sequence_no)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    let summary = CustomerSummaryResponse {
        id: customer_id.clone(),
        display_name: display_name.to_string(),
        internal_key: row.0,
        lifecycle: "active".to_string(),
        created_at: row.1,
        updated_at: row.2,
        domain_count: 0,
        region_code: Some(region_code),
        sequence_no: Some(sequence_no),
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_CUSTOMER_CREATED,
            resource_type: RESOURCE_CUSTOMER,
            resource_id: Some(customer_id.clone()),
            customer_id: customer_id.clone(),
            details: json!({
                "customer_id": customer_id,
                "display_name": display_name,
                "lifecycle": "active",
            }),
        },
    )
    .await
    {
        return response;
    }
    let Some(value) = envelope(&summary) else {
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
    (StatusCode::CREATED, Json(ApiEnvelope { data: summary })).into_response()
}

async fn get_customer(
    State(state): State<AdminCustomersState>,
    Path(customer_id): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_path_id(&customer_id) {
        return invalid_request();
    }
    let route = Route {
        action: ACTION_CUSTOMER_DETAIL,
        resource_type: RESOURCE_CUSTOMER,
        resource_id: Some(customer_id.clone()),
        permission: CUSTOMERS_VIEW_PERMISSION,
        target: Some(&customer_id),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
    {
        return response;
    }
    let row = match sqlx::query_as::<_, CustomerRow>(CUSTOMER_SQL)
        .bind(&customer_id)
        .bind(&state.0.deployment_id.0)
        .fetch_optional(&mut *transaction)
        .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    let Some((
        id,
        display_name,
        internal_key,
        lifecycle,
        created_at,
        updated_at,
        region_code,
        sequence_no,
    )) = row
    else {
        return not_found("Customer was not found");
    };
    let domain_count = match sqlx::query_scalar::<_, i64>(DOMAIN_COUNT_SQL)
        .bind(&customer_id)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(count) => count,
        Err(_) => return unavailable(),
    };
    let domains = match sqlx::query_as::<_, DomainRow>(DOMAINS_LIST_SQL)
        .bind(&customer_id)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows.into_iter().map(domain_from_row).collect(),
        Err(_) => return unavailable(),
    };
    let source_ip_groups = match sqlx::query_as::<_, GroupRow>(GROUPS_LIST_SQL)
        .bind(&customer_id)
        .bind(&state.0.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(id, name, cidrs, created_at)| SourceIpGroupResponse {
                id,
                name,
                cidrs,
                created_at,
            })
            .collect(),
        Err(_) => return unavailable(),
    };
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: CustomerDetailResponse {
                summary: CustomerSummaryResponse {
                    id,
                    display_name,
                    internal_key,
                    lifecycle,
                    created_at,
                    updated_at,
                    domain_count,
                    region_code,
                    sequence_no,
                },
                domains,
                source_ip_groups,
                capabilities: customer_capabilities(&context, &state.0.deployment_id),
            },
        }),
    )
        .into_response()
}

async fn update_customer(
    State(state): State<AdminCustomersState>,
    Path(customer_id): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<UpdateCustomerBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_path_id(&customer_id) {
        return invalid_request();
    }
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    if !matches!(
        body.lifecycle.as_str(),
        "active" | "grace" | "suspended" | "terminated"
    ) {
        return invalid_request();
    }
    let reason = body.reason.trim();
    if !valid_reason(reason) {
        return invalid_request();
    }
    let route = Route {
        action: ACTION_CUSTOMER_UPDATED,
        resource_type: RESOURCE_CUSTOMER,
        resource_id: Some(customer_id.clone()),
        permission: CUSTOMERS_MANAGE_PERMISSION,
        target: Some(&customer_id),
    };
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if !may_change_customer_identity(&context) {
        return denied(
            &state,
            &context,
            &headers,
            &route,
            &Denial::forbidden("lifecycle changes require the support or system_admin role"),
        )
        .await;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
    {
        return response;
    }
    let operation = format!("admin:customer:update:{customer_id}");
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
    // The database row, not the session template, is the lifecycle of
    // record: the local template lifecycle is fixed at process start.
    let current = match sqlx::query_scalar::<_, String>(CUSTOMER_STATE_SQL)
        .bind(&customer_id)
        .bind(&state.0.deployment_id.0)
        .fetch_optional(&mut *transaction)
        .await
    {
        Ok(current) => current,
        Err(_) => return unavailable(),
    };
    let Some(current) = current else {
        return not_found("Customer was not found");
    };
    if !transition_allowed(&current, &body.lifecycle) {
        return conflict("Customer lifecycle transition is not allowed");
    }
    let row = match sqlx::query_as::<
        _,
        (
            String,
            i64,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
            Option<i64>,
        ),
    >(CUSTOMER_PATCH_SQL)
    .bind(&customer_id)
    .bind(&state.0.deployment_id.0)
    .bind(&body.lifecycle)
    .fetch_optional(&mut *transaction)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return not_found("Customer was not found"),
        Err(_) => return unavailable(),
    };
    let domain_count = match sqlx::query_scalar::<_, i64>(DOMAIN_COUNT_SQL)
        .bind(&customer_id)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(count) => count,
        Err(_) => return unavailable(),
    };
    let summary = CustomerSummaryResponse {
        id: customer_id.clone(),
        display_name: row.0,
        internal_key: row.1,
        lifecycle: body.lifecycle.clone(),
        created_at: row.2,
        updated_at: row.3,
        domain_count,
        region_code: row.4,
        sequence_no: row.5,
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_CUSTOMER_UPDATED,
            resource_type: RESOURCE_CUSTOMER,
            resource_id: Some(customer_id.clone()),
            customer_id: customer_id.clone(),
            details: json!({ "lifecycle": body.lifecycle, "reason": reason }),
        },
    )
    .await
    {
        return response;
    }
    let Some(value) = envelope(&summary) else {
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
    (StatusCode::OK, Json(ApiEnvelope { data: summary })).into_response()
}

async fn create_domain(
    State(state): State<AdminCustomersState>,
    Path(customer_id): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<CreateDomainBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_path_id(&customer_id) {
        return invalid_request();
    }
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    let domain = body.domain.trim().to_ascii_lowercase();
    if !valid_domain(&domain) {
        return invalid_request();
    }
    if !matches!(body.domain_type.as_str(), "internal" | "send_only") {
        return invalid_request();
    }
    let route = Route {
        action: ACTION_DOMAIN_ADDED,
        resource_type: RESOURCE_DOMAIN,
        resource_id: None,
        permission: DOMAINS_MANAGE_PERMISSION,
        target: Some(&customer_id),
    };
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if body.domain_type == "send_only" && !may_change_customer_identity(&context) {
        return denied(
            &state,
            &context,
            &headers,
            &route,
            &Denial::forbidden("send_only domain type requires the support or system_admin role"),
        )
        .await;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
    {
        return response;
    }
    let operation = format!("admin:domain:add:{customer_id}");
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
    let duplicate = match sqlx::query_scalar::<_, i32>(DOMAIN_EXISTS_SQL)
        .bind(&domain)
        .fetch_optional(&mut *transaction)
        .await
    {
        Ok(duplicate) => duplicate,
        Err(_) => return unavailable(),
    };
    if duplicate.is_some() {
        return conflict("Domain already exists");
    }
    let verification_token = Uuid::new_v4().simple().to_string();
    let row = match sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(DOMAIN_INSERT_SQL)
        .bind(&customer_id)
        .bind(&domain)
        .bind(&body.domain_type)
        .bind(&verification_token)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(row) => row,
        Err(error) => return unique_violation_or_unavailable(&error, "Domain already exists"),
    };
    let created = DomainResponse {
        id: row.0,
        domain: domain.clone(),
        domain_type: body.domain_type.clone(),
        verification_status: "pending".to_string(),
        verification_method: "unspecified".to_string(),
        verification_attempts: 0,
        verification_expires_at: None,
        verified_at: None,
        created_at: row.1,
        verification_token: Some(verification_token),
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_DOMAIN_ADDED,
            resource_type: RESOURCE_DOMAIN,
            resource_id: Some(created.id.to_string()),
            customer_id: customer_id.clone(),
            details: json!({ "domain": domain, "domain_type": body.domain_type }),
        },
    )
    .await
    {
        return response;
    }
    let Some(value) = envelope(&created) else {
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
    (StatusCode::CREATED, Json(ApiEnvelope { data: created })).into_response()
}

async fn verify_domain(
    State(state): State<AdminCustomersState>,
    Path((customer_id, domain_id)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_path_id(&customer_id) {
        return invalid_request();
    }
    let Ok(domain_uuid) = Uuid::parse_str(&domain_id) else {
        return invalid_request();
    };
    let route = Route {
        action: ACTION_DOMAIN_VERIFIED,
        resource_type: RESOURCE_DOMAIN,
        resource_id: Some(domain_id.clone()),
        permission: DOMAINS_MANAGE_PERMISSION,
        target: Some(&customer_id),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    // Phase 1: short read-only transaction. The DNS lookup must never hold a
    // database transaction (and its connection) open across the network call,
    // so this snapshot commits/drops before the resolver is touched.
    let domain = {
        let mut transaction = match state.0.pool.begin().await {
            Ok(transaction) => transaction,
            Err(_) => return unavailable(),
        };
        if let Err(response) =
            set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
        {
            return response;
        }
        let row = match sqlx::query_as::<_, DomainRow>(DOMAIN_SELECT_SQL)
            .bind(domain_uuid)
            .bind(&customer_id)
            .bind(&state.0.deployment_id.0)
            .fetch_optional(&mut *transaction)
            .await
        {
            Ok(row) => row,
            Err(_) => return unavailable(),
        };
        let Some(row) = row else {
            return not_found("Domain was not found");
        };
        let domain = domain_from_row(row);
        if domain.verification_status == "verified" {
            return (StatusCode::OK, Json(ApiEnvelope { data: domain })).into_response();
        }
        if let Some(expires_at) = domain.verification_expires_at {
            if expires_at < Utc::now() {
                return conflict("Domain verification window expired");
            }
        }
        domain
    };
    let name = format!("_nullapart-verify.{}", domain.domain);
    let expected = domain
        .verification_token
        .as_ref()
        .map(|token| format!("nullapart-verify={token}"));
    // Phase 2: DNS lookup outside any database transaction so a slow or hung
    // resolver cannot pin a pool connection or hold row locks.
    match state.0.resolver.lookup(&name).await {
        Ok(records) => {
            let matched = expected.is_some()
                && records
                    .iter()
                    .any(|record| *record == expected.clone().unwrap());
            // Phase 3: fresh mutation transaction re-checks the row so a
            // concurrent verification or expiry between the lookup and the
            // write cannot be silently overwritten.
            let mut transaction = match state.0.pool.begin().await {
                Ok(transaction) => transaction,
                Err(_) => return unavailable(),
            };
            if let Err(response) =
                set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
            {
                return response;
            }
            let row = match sqlx::query_as::<_, DomainRow>(DOMAIN_SELECT_SQL)
                .bind(domain_uuid)
                .bind(&customer_id)
                .bind(&state.0.deployment_id.0)
                .fetch_optional(&mut *transaction)
                .await
            {
                Ok(row) => row,
                Err(_) => return unavailable(),
            };
            let Some(row) = row else {
                return not_found("Domain was not found");
            };
            let mut domain = domain_from_row(row);
            if domain.verification_status == "verified" {
                if transaction.commit().await.is_err() {
                    return unavailable();
                }
                return (StatusCode::OK, Json(ApiEnvelope { data: domain })).into_response();
            }
            if let Some(expires_at) = domain.verification_expires_at {
                if expires_at < Utc::now() {
                    return conflict("Domain verification window expired");
                }
            }
            let sql = if matched {
                DOMAIN_VERIFY_OK_SQL
            } else {
                DOMAIN_VERIFY_FAILED_SQL
            };
            let updated = match sqlx::query_as::<_, VerificationRow>(sql)
                .bind(domain.id)
                .fetch_optional(&mut *transaction)
                .await
            {
                Ok(Some(row)) => row,
                Ok(None) => return unavailable(),
                Err(_) => return unavailable(),
            };
            apply_verification(&mut domain, updated);
            let (result, details) = if matched {
                ("success", json!({ "domain": domain.domain }))
            } else {
                (
                    "failed",
                    json!({ "domain": domain.domain, "reason": "verification record not found" }),
                )
            };
            let action = if matched {
                ACTION_DOMAIN_VERIFIED
            } else {
                ACTION_DOMAIN_VERIFICATION_FAILED
            };
            if let Err(response) = write_event(
                &mut transaction,
                &state.0.deployment_id,
                &context,
                &headers,
                result,
                AuditFields {
                    action,
                    resource_type: RESOURCE_DOMAIN,
                    resource_id: Some(domain.id.to_string()),
                    customer_id: customer_id.clone(),
                    details,
                },
            )
            .await
            {
                return response;
            }
            if transaction.commit().await.is_err() {
                return unavailable();
            }
            (StatusCode::OK, Json(ApiEnvelope { data: domain })).into_response()
        },
        Err(_) => {
            // The resolver failing never rewrites verification state, but
            // the attempt is still audited evidence in its own short
            // transaction (`write_event` re-asserts the tenant GUC itself).
            let mut transaction = match state.0.pool.begin().await {
                Ok(transaction) => transaction,
                Err(_) => return unavailable(),
            };
            if let Err(response) = write_event(
                &mut transaction,
                &state.0.deployment_id,
                &context,
                &headers,
                "failed",
                AuditFields {
                    action: ACTION_DOMAIN_VERIFICATION_FAILED,
                    resource_type: RESOURCE_DOMAIN,
                    resource_id: Some(domain.id.to_string()),
                    customer_id: customer_id.clone(),
                    details: json!({ "domain": domain.domain, "reason": "resolver unavailable" }),
                },
            )
            .await
            {
                return response;
            }
            if transaction.commit().await.is_err() {
                return unavailable();
            }
            unavailable()
        },
    }
}

async fn list_source_ip_groups(
    State(state): State<AdminCustomersState>,
    Path(customer_id): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_path_id(&customer_id) {
        return invalid_request();
    }
    let route = Route {
        action: ACTION_GROUP_LIST,
        resource_type: RESOURCE_GROUP,
        resource_id: None,
        permission: CUSTOMERS_VIEW_PERMISSION,
        target: Some(&customer_id),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
    {
        return response;
    }
    let rows = match sqlx::query_as::<_, GroupRow>(GROUPS_LIST_SQL)
        .bind(&customer_id)
        .bind(&state.0.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let groups = rows
        .into_iter()
        .map(|(id, name, cidrs, created_at)| SourceIpGroupResponse {
            id,
            name,
            cidrs,
            created_at,
        })
        .collect();
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: SourceIpGroupListResponse { groups },
        }),
    )
        .into_response()
}

async fn create_source_ip_group(
    State(state): State<AdminCustomersState>,
    Path(customer_id): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<CreateSourceIpGroupBody>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_path_id(&customer_id) {
        return invalid_request();
    }
    let Ok(Json(body)) = body else {
        return invalid_request();
    };
    let name = body.name.trim();
    if !valid_group_name(name) {
        return invalid_request();
    }
    let cidrs: Vec<String> = body
        .cidrs
        .iter()
        .map(|entry| entry.trim().to_string())
        .collect();
    if cidrs.is_empty()
        || cidrs.len() > CIDR_MAX_ENTRIES
        || cidrs.iter().any(|entry| !valid_cidr(entry))
    {
        return invalid_request();
    }
    let route = Route {
        action: ACTION_GROUP_CREATED,
        resource_type: RESOURCE_GROUP,
        resource_id: None,
        permission: CUSTOMERS_MANAGE_PERMISSION,
        target: Some(&customer_id),
    };
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
    {
        return response;
    }
    let operation = format!("admin:source-ip-group:add:{customer_id}");
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
    let duplicate = match sqlx::query_scalar::<_, i32>(GROUP_EXISTS_SQL)
        .bind(&customer_id)
        .bind(name)
        .fetch_optional(&mut *transaction)
        .await
    {
        Ok(duplicate) => duplicate,
        Err(_) => return unavailable(),
    };
    if duplicate.is_some() {
        return conflict("Source IP group already exists");
    }
    let created_by = context.actor.actor_id.0.to_string();
    let row = match sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(GROUP_INSERT_SQL)
        .bind(&state.0.deployment_id.0)
        .bind(&customer_id)
        .bind(name)
        .bind(&cidrs)
        .bind(created_by)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(row) => row,
        Err(error) => {
            return unique_violation_or_unavailable(&error, "Source IP group already exists")
        },
    };
    let created = SourceIpGroupResponse {
        id: row.0,
        name: name.to_string(),
        cidrs,
        created_at: row.1,
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_GROUP_CREATED,
            resource_type: RESOURCE_GROUP,
            resource_id: Some(created.id.to_string()),
            customer_id: customer_id.clone(),
            details: json!({ "name": created.name, "cidr_count": created.cidrs.len() }),
        },
    )
    .await
    {
        return response;
    }
    let Some(value) = envelope(&created) else {
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
    (StatusCode::CREATED, Json(ApiEnvelope { data: created })).into_response()
}

async fn delete_source_ip_group(
    State(state): State<AdminCustomersState>,
    Path((customer_id, group_id)): Path<(String, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if !valid_path_id(&customer_id) {
        return invalid_request();
    }
    let Ok(group_uuid) = Uuid::parse_str(&group_id) else {
        return invalid_request();
    };
    let route = Route {
        action: ACTION_GROUP_DELETED,
        resource_type: RESOURCE_GROUP,
        resource_id: Some(group_id.clone()),
        permission: CUSTOMERS_MANAGE_PERMISSION,
        target: Some(&customer_id),
    };
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = authorize(&state, &context, &headers, &route).await {
        return response;
    }
    if let Err(response) = require_high_risk(&state, &context, &headers, &route).await {
        return response;
    }
    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if let Err(response) = set_scope(&mut transaction, &state.0.deployment_id.0, &customer_id).await
    {
        return response;
    }
    let operation = format!("admin:source-ip-group:delete:{group_id}");
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
    let deleted = match sqlx::query_scalar::<_, String>(GROUP_DELETE_SQL)
        .bind(group_uuid)
        .bind(&customer_id)
        .bind(&state.0.deployment_id.0)
        .fetch_optional(&mut *transaction)
        .await
    {
        Ok(deleted) => deleted,
        Err(_) => return unavailable(),
    };
    let Some(name) = deleted else {
        return not_found("Source IP group was not found");
    };
    let id = match Uuid::parse_str(&group_id) {
        Ok(id) => id,
        Err(_) => return invalid_request(),
    };
    if let Err(response) = write_event(
        &mut transaction,
        &state.0.deployment_id,
        &context,
        &headers,
        "success",
        AuditFields {
            action: ACTION_GROUP_DELETED,
            resource_type: RESOURCE_GROUP,
            resource_id: Some(group_id.clone()),
            customer_id: customer_id.clone(),
            details: json!({ "name": name }),
        },
    )
    .await
    {
        return response;
    }
    let payload = DeletedResponse { id, deleted: true };
    let Some(value) = envelope(&payload) else {
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
    (StatusCode::OK, Json(ApiEnvelope { data: payload })).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        extract::Extension,
        http::{Method, Request},
    };
    use nullapart_mail_contracts::{transaction::CustomerId, ActorId};
    use nullapart_policy::{AuthenticationAssurance, ContextActor, ImpersonationContext, RegionId};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::admin_rbac::CUSTOMER_ADMIN_ROLE;

    #[test]
    fn operational_region_codes_accept_the_canonical_docs_02_set() {
        for region in ["ZA", "ZAB", "ZAC", "EU", "UK", "US"] {
            assert!(valid_region_code(region), "{region} must be accepted");
        }
        for region in ["local", "LOCAL", "Z", "ZAAA", "zA", "Z1"] {
            assert!(!valid_region_code(region), "{region} must be rejected");
        }
    }

    #[test]
    fn operational_customer_ids_follow_the_docs_02_scheme() {
        assert_eq!(format_customer_id("ZA", 1), "CZA-1");
        assert_eq!(format_customer_id("ZAB", 42), "CZAB-42");
        assert!(valid_path_id(&format_customer_id("EU", 7)));
    }

    fn deployment() -> DeploymentId {
        DeploymentId::new("LOCAL-TEST")
    }

    #[test]
    fn platform_roles_get_every_published_capability() {
        let capabilities = customer_capabilities(&context(), &deployment());
        assert!(capabilities.create_customer.allowed);
        assert!(capabilities.change_lifecycle.allowed);
        assert!(capabilities.add_send_only_domain.allowed);
    }

    #[test]
    fn a_manage_permission_without_a_platform_role_publishes_the_role_blocker() {
        // The defect this closes: a custom role can hold
        // `admin:customers:manage`, so the console offered "New customer",
        // while `create_customer` answered 403. The same predicate now decides
        // both, so the button is replaced by a stated requirement.
        let mut scoped = context();
        scoped.actor.roles = vec![CUSTOMER_ADMIN_ROLE.to_string()];
        let capabilities = customer_capabilities(&scoped, &deployment());
        assert!(!capabilities.create_customer.allowed);
        assert_eq!(capabilities.create_customer.blocker, Some(Blocker::Role));
        assert_eq!(capabilities.change_lifecycle.blocker, Some(Blocker::Role));
        assert_eq!(
            capabilities.add_send_only_domain.blocker,
            Some(Blocker::Role)
        );
    }

    #[test]
    fn capability_blockers_follow_the_authorization_gate_order() {
        let mut no_permission = context();
        no_permission.actor.roles = vec![CUSTOMER_ADMIN_ROLE.to_string()];
        no_permission.permissions = vec![CUSTOMERS_VIEW_PERMISSION.to_string()];
        assert_eq!(
            session_blocker(
                &no_permission,
                &deployment(),
                CUSTOMERS_MANAGE_PERMISSION,
                true,
            ),
            Some(Blocker::Permission)
        );

        // Lifecycle and deployment refusals outrank the role requirement, the
        // same order `authorize` enforces before any handler runs.
        let mut suspended = context();
        suspended.customer_lifecycle = CustomerLifecycle::Suspended;
        assert_eq!(
            session_blocker(&suspended, &deployment(), CUSTOMERS_MANAGE_PERMISSION, true),
            Some(Blocker::Lifecycle)
        );

        let mut other_deployment = context();
        other_deployment.deployment_id = DeploymentId::new("LOCAL-OTHER");
        assert_eq!(
            session_blocker(
                &other_deployment,
                &deployment(),
                CUSTOMERS_MANAGE_PERMISSION,
                true,
            ),
            Some(Blocker::Deployment)
        );

        assert_eq!(
            session_blocker(
                &context(),
                &deployment(),
                CUSTOMERS_MANAGE_PERMISSION,
                false
            ),
            None
        );
    }

    #[test]
    fn capabilities_serialize_to_the_documented_wire_shape() {
        let mut scoped = context();
        scoped.actor.roles = vec![CUSTOMER_ADMIN_ROLE.to_string()];
        let json = serde_json::to_value(customer_capabilities(&scoped, &deployment()))
            .expect("capabilities must serialize");
        assert_eq!(json["create_customer"]["allowed"], false);
        assert_eq!(json["create_customer"]["blocker"], "role");
        assert_eq!(json["add_send_only_domain"]["blocker"], "role");

        let allowed = serde_json::to_value(customer_capabilities(&context(), &deployment()))
            .expect("capabilities must serialize");
        assert_eq!(allowed["change_lifecycle"]["allowed"], true);
        assert!(allowed["change_lifecycle"]["blocker"].is_null());
    }

    fn state() -> AdminCustomersState {
        // A short acquire timeout keeps failure paths deterministic: the
        // unreachable pool must fail quickly instead of masking gate order.
        let pool = PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse");
        AdminCustomersState::new(pool, DeploymentId::new("LOCAL-TEST"))
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
                CUSTOMERS_VIEW_PERMISSION.to_string(),
                CUSTOMERS_MANAGE_PERMISSION.to_string(),
                DOMAINS_MANAGE_PERMISSION.to_string(),
            ],
            config_revision: 1,
            trace_id: "customer-admin-test".to_string(),
            correlation_id: "customer-admin-test".to_string(),
            session_id: "customer-admin-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn impersonating_context() -> TenantContext {
        let mut context = context();
        let real_actor = context.actor.clone();
        context.impersonation = Some(ImpersonationContext {
            real_actor,
            impersonated_subject: None,
            impersonated_customer: CustomerId::new("impersonated-customer"),
            started_at: Utc::now(),
            reason: "investigating a report".to_string(),
            session_id: "impersonation-session".to_string(),
        });
        context
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

    fn patch(uri: &str, key: Option<&str>, body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("x-idempotency-key", key);
        }
        builder
            .body(Body::from(body.to_string()))
            .expect("test request must build")
    }

    fn delete(uri: &str, key: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(Method::DELETE).uri(uri);
        if let Some(key) = key {
            builder = builder.header("x-idempotency-key", key);
        }
        builder
            .body(Body::empty())
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
            get("/api/v1/admin/customers"),
            post(
                "/api/v1/admin/customers",
                Some("key-create"),
                r#"{"display_name":"Acme"}"#,
            ),
            get("/api/v1/admin/customers/local-customer"),
            patch(
                "/api/v1/admin/customers/local-customer",
                Some("key-patch"),
                r#"{"lifecycle":"suspended","reason":"contract test reason"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("key-domain"),
                r#"{"domain":"example.test","domain_type":"internal"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains/11111111-1111-1111-1111-111111111111/verify",
                None,
                "",
            ),
            get("/api/v1/admin/customers/local-customer/source-ip-groups"),
            post(
                "/api/v1/admin/customers/local-customer/source-ip-groups",
                Some("key-group"),
                r#"{"name":"office","cidrs":["10.0.0.0/8"]}"#,
            ),
            delete(
                "/api/v1/admin/customers/local-customer/source-ip-groups/22222222-2222-2222-2222-222222222222",
                Some("key-delete"),
            ),
        ]
    }

    #[tokio::test]
    async fn customer_administration_requires_authenticated_context() {
        let app = admin_customers_router(state());
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
    async fn customer_list_requires_view_permission_before_database_access() {
        let mut context = context();
        context.permissions.clear();
        let response = admin_customers_router(state())
            .layer(Extension(context))
            .oneshot(get("/api/v1/admin/customers"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("FORBIDDEN", "Permission is required")
        );
    }

    #[tokio::test]
    async fn domain_verify_rejects_a_non_uuid_domain_id_before_authorization() {
        let response = admin_customers_router(state())
            .layer(Extension(context()))
            .oneshot(post(
                "/api/v1/admin/customers/local-customer/domains/not-a-uuid/verify",
                Some("domain-verify-invalid-uuid"),
                "{}",
            ))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_value(response).await,
            error_body("INVALID_REQUEST", "Request is invalid")
        );
    }

    #[tokio::test]
    async fn source_ip_group_delete_rejects_a_non_uuid_group_id_before_authorization() {
        let response = admin_customers_router(state())
            .layer(Extension(context()))
            .oneshot(delete(
                "/api/v1/admin/customers/local-customer/source-ip-groups/not-a-uuid",
                Some("group-delete-invalid-uuid"),
            ))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_value(response).await,
            error_body("INVALID_REQUEST", "Request is invalid")
        );
    }

    #[tokio::test]
    async fn foreign_deployment_context_is_denied_before_database_access() {
        let mut context = context();
        context.deployment_id = DeploymentId::new("OTHER-DEPLOYMENT");
        let response = admin_customers_router(state())
            .layer(Extension(context))
            .oneshot(get("/api/v1/admin/customers"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            error_body("FORBIDDEN", "Permission is required")
        );
    }

    #[tokio::test]
    async fn cross_customer_detail_is_denied_without_database_access() {
        let mut context = context();
        context.actor.roles = vec![CUSTOMER_ADMIN_ROLE.to_string()];
        let response = admin_customers_router(state())
            .layer(Extension(context))
            .oneshot(get("/api/v1/admin/customers/other-customer"))
            .await
            .expect("test response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_value(response).await,
            error_body("NOT_FOUND", "Customer was not found")
        );
    }

    /// A Customer Admin now holds `admin:domains:manage`, so the only thing
    /// standing between them and another tenant's domain list is the scope
    /// check. It must refuse before any database work, and refuse as a
    /// missing resource rather than as a permission gap.
    #[tokio::test]
    async fn domain_management_refuses_a_foreign_customer_and_reaches_their_own() {
        let mut context = context();
        context.actor.roles = vec![CUSTOMER_ADMIN_ROLE.to_string()];
        let app = admin_customers_router(state());
        let foreign = app
            .clone()
            .layer(Extension(context.clone()))
            .oneshot(post(
                "/api/v1/admin/customers/other-customer/domains",
                Some("key-foreign-domain"),
                r#"{"domain":"other.example.test","domain_type":"internal"}"#,
            ))
            .await
            .expect("test response");
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_value(foreign).await,
            error_body("NOT_FOUND", "Customer was not found")
        );

        let own = app
            .layer(Extension(context))
            .oneshot(post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("key-own-domain"),
                r#"{"domain":"mail.example.test","domain_type":"internal"}"#,
            ))
            .await
            .expect("test response");
        assert_eq!(own.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn impersonation_narrows_customer_scope() {
        let app = admin_customers_router(state());
        let inside = app
            .clone()
            .layer(Extension(impersonating_context()))
            .oneshot(get("/api/v1/admin/customers/impersonated-customer"))
            .await
            .expect("test response");
        assert_eq!(inside.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_value(inside).await,
            error_body("UNAVAILABLE", "Service is unavailable")
        );

        let outside = app
            .layer(Extension(impersonating_context()))
            .oneshot(get("/api/v1/admin/customers/other-customer"))
            .await
            .expect("test response");
        assert_eq!(outside.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_value(outside).await,
            error_body("NOT_FOUND", "Customer was not found")
        );
    }

    #[tokio::test]
    async fn send_only_domain_creation_requires_platform_role() {
        let mut context = context();
        context.actor.roles = vec![CUSTOMER_ADMIN_ROLE.to_string()];
        let response = admin_customers_router(state())
            .layer(Extension(context))
            .oneshot(post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("key-send-only"),
                r#"{"domain":"outbound.example.test","domain_type":"send_only"}"#,
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
    async fn lifecycle_change_requires_platform_role() {
        let mut context = context();
        context.actor.roles = vec![CUSTOMER_ADMIN_ROLE.to_string()];
        let response = admin_customers_router(state())
            .layer(Extension(context))
            .oneshot(patch(
                "/api/v1/admin/customers/local-customer",
                Some("key-lifecycle"),
                r#"{"lifecycle":"grace","reason":"entering grace period"}"#,
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
    async fn customer_entry_does_not_change_creation_authorization() {
        let response = admin_customers_router(state())
            .layer(Extension(impersonating_context()))
            .oneshot(post(
                "/api/v1/admin/customers",
                Some("key-entered-create"),
                r#"{"display_name":"During entry"}"#,
            ))
            .await
            .expect("test response");
        // The actor's own manage permission passes the authorization gate;
        // entry adds no extra denial. The unreachable test pool then fails
        // fast, exactly like the other gate-order tests.
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn mutations_require_an_idempotency_key() {
        let app = admin_customers_router(state()).layer(Extension(context()));
        let missing = app
            .clone()
            .oneshot(post(
                "/api/v1/admin/customers/local-customer/domains",
                None,
                r#"{"domain":"example.test","domain_type":"internal"}"#,
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
                "/api/v1/admin/customers/local-customer/domains",
                Some(""),
                r#"{"domain":"example.test","domain_type":"internal"}"#,
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
    async fn input_validation_rejects_bad_requests_before_database_access() {
        let long_name = "a".repeat(129);
        let long_reason = "a".repeat(501);
        let long_group_name = "a".repeat(129);
        let long_label = format!("{}.example.test", "a".repeat(64));
        let control_name = format!("{{\"display_name\":\"{}\"}}", "\u{7}");
        let many_cidrs =
            serde_json::to_string(&vec!["10.0.0.0/8".to_string(); 65]).expect("test json");
        let group_body = format!("{{\"name\":\"office\",\"cidrs\":{many_cidrs}}}");
        let long_group_body =
            format!("{{\"name\":\"{long_group_name}\",\"cidrs\":[\"10.0.0.0/8\"]}}");
        let requests = vec![
            post(
                "/api/v1/admin/customers",
                Some("v1"),
                r#"{"display_name":""}"#,
            ),
            post(
                "/api/v1/admin/customers",
                Some("v2"),
                &format!("{{\"display_name\":\"{long_name}\"}}"),
            ),
            post("/api/v1/admin/customers", Some("v3"), &control_name),
            post(
                "/api/v1/admin/customers",
                Some("v4"),
                r#"{"display_name":"ok","extra":true}"#,
            ),
            post("/api/v1/admin/customers", Some("v5"), "{"),
            patch(
                "/api/v1/admin/customers/local-customer",
                Some("v6"),
                r#"{"lifecycle":"bogus","reason":"valid reason text"}"#,
            ),
            patch(
                "/api/v1/admin/customers/local-customer",
                Some("v7"),
                r#"{"lifecycle":"suspended","reason":"short"}"#,
            ),
            patch(
                "/api/v1/admin/customers/local-customer",
                Some("v8"),
                &format!("{{\"lifecycle\":\"suspended\",\"reason\":\"{long_reason}\"}}"),
            ),
            patch(
                "/api/v1/admin/customers/local-customer",
                Some("v9"),
                r#"{"lifecycle":"suspended","reason":"valid reason text","extra":1}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v10"),
                r#"{"domain":"","domain_type":"internal"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v11"),
                r#"{"domain":"nodots","domain_type":"internal"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v12"),
                r#"{"domain":"bad_domain.example","domain_type":"internal"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v13"),
                r#"{"domain":"-bad.example","domain_type":"internal"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v14"),
                r#"{"domain":"bad-.example","domain_type":"internal"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v15"),
                r#"{"domain":"10.0.0.1","domain_type":"internal"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v16"),
                &format!("{{\"domain\":\"{long_label}\",\"domain_type\":\"internal\"}}"),
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v17"),
                r#"{"domain":"example.test.","domain_type":"internal"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("v18"),
                r#"{"domain":"example.test","domain_type":"other"}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/domains/not-a-uuid/verify",
                None,
                "",
            ),
            get("/api/v1/admin/customers/bad!id"),
            post(
                "/api/v1/admin/customers/local-customer/source-ip-groups",
                Some("v19"),
                r#"{"name":"","cidrs":["10.0.0.0/8"]}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/source-ip-groups",
                Some("v20"),
                &long_group_body,
            ),
            post(
                "/api/v1/admin/customers/local-customer/source-ip-groups",
                Some("v21"),
                r#"{"name":"office","cidrs":[]}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/source-ip-groups",
                Some("v22"),
                r#"{"name":"office","cidrs":["not-an-ip"]}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/source-ip-groups",
                Some("v23"),
                r#"{"name":"office","cidrs":["10.0.0.0/33"]}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/source-ip-groups",
                Some("v24"),
                r#"{"name":"office","cidrs":["::1/129"]}"#,
            ),
            post(
                "/api/v1/admin/customers/local-customer/source-ip-groups",
                Some("v25"),
                &group_body,
            ),
        ];
        let app = admin_customers_router(state()).layer(Extension(context()));
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
    async fn mutations_require_fresh_step_up_authentication() {
        let mut context = context();
        context.actor.authentication_assurance = AuthenticationAssurance::Standard;
        let response = admin_customers_router(state())
            .layer(Extension(context))
            .oneshot(post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("key-step-up"),
                r#"{"domain":"example.test","domain_type":"internal"}"#,
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
    async fn database_failures_return_unavailable() {
        let response = admin_customers_router(state())
            .layer(Extension(context()))
            .oneshot(post(
                "/api/v1/admin/customers/local-customer/domains",
                Some("key-database"),
                r#"{"domain":"example.test","domain_type":"internal"}"#,
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
        let app = admin_customers_router(state()).layer(Extension(context()));
        let mut statuses = Vec::new();
        let mut last = None;
        for index in 0..6 {
            let key = format!("key-rate-{index}");
            let response = app
                .clone()
                .oneshot(post(
                    "/api/v1/admin/customers/local-customer/source-ip-groups",
                    Some(&key),
                    r#"{"name":"office","cidrs":["10.0.0.0/8"]}"#,
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

    #[tokio::test]
    async fn customer_create_rejects_injected_privileged_fields() {
        let app = admin_customers_router(state()).layer(Extension(context()));

        let baseline = app
            .clone()
            .oneshot(post(
                "/api/v1/admin/customers",
                Some("mass-assign-create-baseline"),
                r#"{"display_name":"Mass assignment baseline"}"#,
            ))
            .await
            .expect("test response");
        assert_eq!(
            baseline.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an ordinary create must reach the database so the rejection below is discriminating"
        );

        let before = snapshot(app.clone(), get("/api/v1/admin/customers")).await;
        let rejected = app
            .clone()
            .oneshot(post(
                "/api/v1/admin/customers",
                Some("mass-assign-create"),
                r#"{"display_name":"Mass assignment probe","is_superadmin":true,
                    "roles":["system_admin"],"deployment_id":"OTHER-DEPLOYMENT"}"#,
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

        let after = snapshot(app, get("/api/v1/admin/customers")).await;
        assert_eq!(
            before, after,
            "a rejected create must leave the customer list unchanged"
        );
        assert!(
            !after.1.contains("Mass assignment probe"),
            "a rejected create must leave no customer behind: {}",
            after.1
        );
    }

    #[tokio::test]
    async fn customer_update_rejects_injected_fields() {
        let app = admin_customers_router(state()).layer(Extension(context()));

        let baseline = app
            .clone()
            .oneshot(patch(
                "/api/v1/admin/customers/local-customer",
                Some("mass-assign-update-baseline"),
                r#"{"lifecycle":"grace","reason":"mass assignment baseline reason"}"#,
            ))
            .await
            .expect("test response");
        assert_eq!(
            baseline.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an ordinary update must reach the database so the rejection below is discriminating"
        );

        let before = snapshot(app.clone(), get("/api/v1/admin/customers/local-customer")).await;
        let rejected = app
            .clone()
            .oneshot(patch(
                "/api/v1/admin/customers/local-customer",
                Some("mass-assign-update"),
                r#"{"lifecycle":"grace","reason":"mass assignment probe reason",
                    "customer_id":"cust-injected","deployment_id":"OTHER-DEPLOYMENT"}"#,
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

        let after = snapshot(app, get("/api/v1/admin/customers/local-customer")).await;
        assert_eq!(
            before, after,
            "a rejected update must leave the customer unchanged"
        );
        assert!(
            !after.1.contains("cust-injected") && !after.1.contains("OTHER-DEPLOYMENT"),
            "an injected field must never be persisted or echoed: {}",
            after.1
        );
    }

    #[tokio::test]
    async fn customer_error_responses_are_static_json_without_internal_leaks() {
        let app = admin_customers_router(state()).layer(Extension(context()));
        let cases = vec![
            (
                get("/api/v1/admin/customers/11111111-1111-1111-1111-111111111111"),
                vec![StatusCode::NOT_FOUND, StatusCode::SERVICE_UNAVAILABLE],
            ),
            (
                get("/api/v1/admin/customers/bad!id"),
                vec![StatusCode::BAD_REQUEST],
            ),
            (
                post("/api/v1/admin/customers", Some("leak-create"), "{"),
                vec![StatusCode::BAD_REQUEST],
            ),
            (
                patch(
                    "/api/v1/admin/customers/local-customer",
                    Some("leak-reason"),
                    r#"{"lifecycle":"grace","reason":"short"}"#,
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

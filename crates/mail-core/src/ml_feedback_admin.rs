//! ML feedback candidate administration (read-only).
//!
//! Exposes the server-side ML feedback queue (`ml_feedback_candidates`,
//! populated by quarantine releases, user reports and admin adjudications)
//! to privileged console readers. This module is intentionally read-only:
//! candidate curation happens through the audited quarantine/adjudication
//! flows that own those records, so a list endpoint can never become a
//! side channel for changing a message's disposition or a candidate's
//! curation state.
//!
//! Security invariants:
//!
//! - every route requires the `ml_feedback:view` permission, an active
//!   customer lifecycle, and a deployment match, in that order, before any
//!   database work;
//! - the customer scope derives from the authenticated context, never from
//!   a query parameter; the list is additionally scoped by the deployment
//!   GUC through `set_scope`, so PostgreSQL RLS is defense in depth behind
//!   the explicit `WHERE` clause;
//! - denial responses are audited; the fixed error bodies never carry SQL,
//!   driver or pool material;
//! - the result set is bounded, so a large feedback queue cannot become an
//!   unbounded response.

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use nullapart_mail_contracts::transaction::DeploymentId;
use nullapart_policy::{CustomerLifecycle, TenantContext};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use tracing::error;
use uuid::Uuid;

use crate::admin_audit::{source_ip_from, AuditEventRecord, AuditStore, PostgresAuditStore};
use crate::policy_admin::{load_actor_display_names, set_scope};

pub const ML_FEEDBACK_VIEW_PERMISSION: &str = "ml_feedback:view";

const ADMIN_ML_FEEDBACK_CANDIDATES_PATH: &str = "/api/v1/admin/ml-feedback-candidates";

const ACTION_ML_FEEDBACK_LIST: &str = "ml_feedback_list";
const RESOURCE_INLINE_ML_FEEDBACK_CANDIDATE: &str = "inline_ml_feedback_candidate";

const CURATOR_PENDING: &str = "pending";
const CURATOR_ACCEPTED: &str = "accepted";
const CURATOR_REJECTED: &str = "rejected";

/// Bound on one list response. Curators page through the queue from the
/// oldest first-class flows; this endpoint must never return an unbounded
/// result.
const LIST_LIMIT: i64 = 100;

const CANDIDATE_COLUMNS: &str = "id, tenant_message_id, transaction_id, source, \
     proposed_label, curator_state, actor_login, reason, created_at, \
     curated_by, curated_at, curation_note";

const LIST_CANDIDATES_SQL: &str = "SELECT {cols} FROM ml_feedback_candidates \
     WHERE deployment_id = $1 AND customer_id = $2 \
     AND ($3::text IS NULL OR curator_state = $3) \
     ORDER BY created_at DESC, id DESC LIMIT $4";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MlFeedbackAdminState(Arc<MlFeedbackAdminStateInner>);

struct MlFeedbackAdminStateInner {
    pool: PgPool,
    deployment_id: DeploymentId,
    audit: Arc<dyn AuditStore>,
}

impl MlFeedbackAdminState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self(Arc::new(MlFeedbackAdminStateInner {
            audit: Arc::new(PostgresAuditStore::new(pool.clone())),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CuratorState {
    Pending,
    Accepted,
    Rejected,
}

impl CuratorState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => CURATOR_PENDING,
            Self::Accepted => CURATOR_ACCEPTED,
            Self::Rejected => CURATOR_REJECTED,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    /// `pending`, `accepted` or `rejected`; omitted means all candidates.
    state: Option<CuratorState>,
}

#[derive(Debug, Clone)]
struct CandidateRecord {
    id: Uuid,
    tenant_message_id: Option<Uuid>,
    transaction_id: Option<Uuid>,
    source: String,
    proposed_label: String,
    curator_state: String,
    actor_login: String,
    reason: String,
    created_at: DateTime<Utc>,
    curated_by: Option<String>,
    curated_at: Option<DateTime<Utc>>,
    curation_note: Option<String>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for CandidateRecord {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_message_id: row.try_get("tenant_message_id")?,
            transaction_id: row.try_get("transaction_id")?,
            source: row.try_get("source")?,
            proposed_label: row.try_get("proposed_label")?,
            curator_state: row.try_get("curator_state")?,
            actor_login: row.try_get("actor_login")?,
            reason: row.try_get("reason")?,
            created_at: row.try_get("created_at")?,
            curated_by: row.try_get("curated_by")?,
            curated_at: row.try_get("curated_at")?,
            curation_note: row.try_get("curation_note")?,
        })
    }
}

#[derive(Serialize)]
struct CandidateResponse {
    id: Uuid,
    tenant_message_id: Option<Uuid>,
    transaction_id: Option<Uuid>,
    source: String,
    proposed_label: String,
    curator_state: CuratorState,
    actor_login: String,
    reason: String,
    created_at: DateTime<Utc>,
    /// The `curated_by` fields store the acting identity's id, which is what
    /// the record has to keep. `curated_by_name` carries what a person
    /// reading the curation history needs: the name that identity was issued
    /// under, or the stored reference when no account matches it.
    curated_by: Option<String>,
    curated_by_name: Option<String>,
    curated_at: Option<DateTime<Utc>>,
    curation_note: Option<String>,
}

impl CandidateResponse {
    fn from_record(record: CandidateRecord, names: &HashMap<String, String>) -> Option<Self> {
        // The database CHECK constraint bounds the state vocabulary; an
        // unexpected value is a data defect and must fail loud, not render
        // as an invented state.
        let curator_state = match record.curator_state.as_str() {
            CURATOR_PENDING => CuratorState::Pending,
            CURATOR_ACCEPTED => CuratorState::Accepted,
            CURATOR_REJECTED => CuratorState::Rejected,
            _ => return None,
        };
        let curated_by = record.curated_by.clone();
        Some(Self {
            id: record.id,
            tenant_message_id: record.tenant_message_id,
            transaction_id: record.transaction_id,
            source: record.source,
            proposed_label: record.proposed_label,
            curator_state,
            actor_login: record.actor_login,
            reason: record.reason,
            created_at: record.created_at,
            curated_by,
            curated_by_name: record.curated_by.map(|value| {
                names
                    .get(&value)
                    .cloned()
                    .unwrap_or_else(|| "Unknown account".to_string())
            }),
            curated_at: record.curated_at,
            curation_note: record.curation_note,
        })
    }
}

#[derive(Serialize)]
struct CandidateListResponse {
    candidates: Vec<CandidateResponse>,
}

// ---------------------------------------------------------------------------
// Route/denial/authorization helpers
// ---------------------------------------------------------------------------

struct Route {
    action: &'static str,
    resource_type: &'static str,
    permission: &'static str,
}

impl Route {
    fn new(action: &'static str, resource_type: &'static str, permission: &'static str) -> Self {
        Self {
            action,
            resource_type,
            permission,
        }
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
}

fn has_permission(context: &TenantContext, permission: &str) -> bool {
    context
        .permissions
        .iter()
        .any(|granted| granted == permission)
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
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

/// Audits a denial (observability only; the response is a denial either way,
/// so an audit write failure never changes the outcome) and returns it.
async fn denied(
    state: &MlFeedbackAdminState,
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
            resource_id: None,
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
        error!(%error, "failed to audit ML feedback denial");
    }
    api_error(denial.status, denial.code, denial.message)
}

/// Permission, lifecycle, then deployment — in that order, before any
/// transaction work.
async fn authorize(
    state: &MlFeedbackAdminState,
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

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

async fn list_candidates(
    State(state): State<MlFeedbackAdminState>,
    query: Result<Query<ListQuery>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    let query = match query {
        Ok(query) => query.0,
        // A malformed filter list (unknown parameter, bad value shape) is a
        // client error and must stay a static JSON body, not axum's
        // plain-text rejection, which could echo attacker-controlled text.
        Err(_) => return invalid_request(),
    };
    let route = Route::new(
        ACTION_ML_FEEDBACK_LIST,
        RESOURCE_INLINE_ML_FEEDBACK_CANDIDATE,
        ML_FEEDBACK_VIEW_PERMISSION,
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
    let records = match sqlx::query_as::<_, CandidateRecord>(
        LIST_CANDIDATES_SQL
            .replace("{cols}", CANDIDATE_COLUMNS)
            .as_str(),
    )
    .bind(&state.0.deployment_id.0)
    .bind(&context.customer_id.0)
    .bind(query.state.map(|value| value.as_str().to_string()))
    .bind(LIST_LIMIT)
    .fetch_all(&mut *transaction)
    .await
    {
        Ok(records) => records,
        Err(_) => return unavailable(),
    };
    let actor_names = match load_actor_display_names(&mut transaction).await {
        Ok(names) => names,
        Err(response) => return response,
    };
    let mut candidates = Vec::with_capacity(records.len());
    for record in records {
        match CandidateResponse::from_record(record, &actor_names) {
            Some(response) => candidates.push(response),
            // A state outside the contract is a data defect: fail closed
            // instead of serving a row the consumer cannot interpret.
            None => {
                transaction.rollback().await.ok();
                return unavailable();
            },
        }
    }
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: CandidateListResponse { candidates },
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn ml_feedback_admin_router(state: MlFeedbackAdminState) -> Router {
    Router::new()
        .route(ADMIN_ML_FEEDBACK_CANDIDATES_PATH, get(list_candidates))
        .with_state(state)
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

    fn state() -> MlFeedbackAdminState {
        // A short acquire timeout keeps failure paths deterministic: the
        // unreachable pool must fail quickly instead of masking gate order.
        let pool = PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse");
        MlFeedbackAdminState::new(pool, DeploymentId::new("LOCAL-TEST"))
    }

    fn context_with(permissions: Vec<String>, deployment: DeploymentId) -> TenantContext {
        TenantContext {
            deployment_id: deployment,
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
            permissions,
            config_revision: 1,
            trace_id: "ml-feedback-test".to_string(),
            correlation_id: "ml-feedback-test".to_string(),
            session_id: "ml-feedback-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn context(permissions: Vec<String>) -> TenantContext {
        context_with(permissions, DeploymentId::new("LOCAL-TEST"))
    }

    /// The context rides as a router-level Extension layer, matching how
    /// the authentication middleware publishes it in production.
    fn app(context: Option<TenantContext>) -> Router {
        let router = ml_feedback_admin_router(state());
        match context {
            Some(context) => router.layer(Extension(context)),
            None => router,
        }
    }

    async fn get(uri: &str, context: Option<TenantContext>) -> Response {
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .expect("request must build");
        app(context)
            .oneshot(request)
            .await
            .expect("router must answer")
    }

    async fn body_value(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test body must read");
        serde_json::from_slice(&bytes).expect("test body must be JSON")
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test body must read");
        String::from_utf8(bytes.to_vec()).expect("test body must be UTF-8")
    }

    /// An error response is exactly `{code, message}` and never carries SQL,
    /// driver, pool, panic or credential material.
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
        ] {
            assert!(
                !lowered.contains(marker),
                "an error response must not leak {marker}: {raw}"
            );
        }
    }

    #[tokio::test]
    async fn list_requires_authentication() {
        let response = get(ADMIN_ML_FEEDBACK_CANDIDATES_PATH, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_static_error_body(&body_text(response).await);
    }

    #[tokio::test]
    async fn list_requires_view_permission() {
        let response = get(
            ADMIN_ML_FEEDBACK_CANDIDATES_PATH,
            Some(context(vec![
                crate::model_registry::MODELS_VIEW_PERMISSION.to_string()
            ])),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_static_error_body(&body_text(response).await);
    }

    #[tokio::test]
    async fn list_rejects_deployment_mismatch() {
        let context = context_with(
            vec![ML_FEEDBACK_VIEW_PERMISSION.to_string()],
            DeploymentId::new("OTHER-DEPLOYMENT"),
        );
        let response = get(ADMIN_ML_FEEDBACK_CANDIDATES_PATH, Some(context)).await;
        // The context carries another deployment, so the deployment gate
        // fires before any database work and the denial stays forbidden
        // rather than becoming an unavailable or empty answer.
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_static_error_body(&body_text(response).await);
    }

    #[tokio::test]
    async fn list_rejects_bad_state_filter() {
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "{ADMIN_ML_FEEDBACK_CANDIDATES_PATH}?state=approved"
            ))
            .body(Body::empty())
            .expect("request must build");
        let response = app(Some(context(vec![ML_FEEDBACK_VIEW_PERMISSION.to_string()])))
            .oneshot(request)
            .await
            .expect("router must answer");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_static_error_body(&body_text(response).await);
    }

    #[tokio::test]
    async fn list_rejects_unknown_query_parameters() {
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "{ADMIN_ML_FEEDBACK_CANDIDATES_PATH}?customer_id=evil-customer"
            ))
            .body(Body::empty())
            .expect("request must build");
        let response = app(Some(context(vec![ML_FEEDBACK_VIEW_PERMISSION.to_string()])))
            .oneshot(request)
            .await
            .expect("router must answer");
        // `customer_id` is derived from the authenticated context, never
        // from the query string; supplying it as a parameter must be a 400
        // instead of being silently ignored.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_static_error_body(&body_text(response).await);
    }

    #[tokio::test]
    async fn authorized_list_without_database_is_unavailable() {
        let response = get(
            ADMIN_ML_FEEDBACK_CANDIDATES_PATH,
            Some(context(vec![ML_FEEDBACK_VIEW_PERMISSION.to_string()])),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_value(response).await;
        assert_eq!(body["code"], "UNAVAILABLE");
    }
}

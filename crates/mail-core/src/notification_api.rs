//! Authenticated tenant notification controls.
//!
//! `domain_security_notifications` rows are produced by the domain observer and
//! rendered in the console. This module gives the tenant a say in whether those
//! findings are mailed, at what severity, to whom, and how often, and it
//! publishes the delivery ledger so "was it sent" has one answer.
//!
//! Two rules shape every handler here:
//!
//! - scope comes from the authenticated session. No route accepts a customer id
//!   from the client, so a Customer Admin can only ever read or write their own
//!   tenant's settings;
//! - recipients must be addresses inside a domain this tenant has verified.
//!   Otherwise Nullapart would be an open relay pointed at another tenant or an
//!   arbitrary third party, which is why the check is server-side and a refusal
//!   rather than a warning.

use std::sync::{Arc, Mutex};

use axum::{
    extract::{rejection::JsonRejection, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use nullapart_mail_contracts::{
    rate_limit::{AppRateLimits, HighRiskLimits, RateLimitConfig, TokenBucket},
    transaction::DeploymentId,
};
use nullapart_policy::{CustomerLifecycle, TenantContext};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::admin_audit::{source_ip_from, AuditEventRecord, PostgresAuditStore};
use crate::admin_capabilities::{Blocker, WriteCapability};
use crate::admin_rbac::platform_placement;
use crate::idempotency::{claim, complete, ClaimOutcome};

pub const NOTIFICATIONS_VIEW_PERMISSION: &str = "notifications:view";
pub const NOTIFICATIONS_MANAGE_PERMISSION: &str = "notifications:manage";

const NOTIFICATION_SETTINGS_PATH: &str = "/api/v1/notifications/settings";
const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const AUDIT_SETTINGS_UPDATED: &str = "notification_settings_updated";
const AUDIT_RESOURCE_SETTINGS: &str = "tenant_notification_settings";
/// Upper bound enforced by both this module and the database CHECK constraint.
const MAX_RECIPIENTS: usize = 10;
const MAX_DIGEST_WINDOW_MINUTES: i32 = 1440;
const SEVERITY_FLOORS: [&str; 3] = ["info", "warning", "critical"];
const DEFAULT_SEVERITY_FLOOR: &str = "warning";
const DEFAULT_DIGEST_WINDOW_MINUTES: i32 = 60;
const DELIVERY_HISTORY_LIMIT: usize = 20;

#[derive(Clone)]
pub struct NotificationApiState(Arc<NotificationApiStateInner>);

struct NotificationApiStateInner {
    pool: PgPool,
    deployment_id: DeploymentId,
    read_limiter: Mutex<TokenBucket>,
    /// Fail-closed budget for settings writes. Changing recipients changes who
    /// Nullapart will mail on this tenant's behalf, so it is budgeted like the
    /// other Control Plane high-risk mutations.
    mutation_limiter: Mutex<TokenBucket>,
}

impl NotificationApiState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self::build(
            pool,
            deployment_id,
            AppRateLimits::api_read(),
            HighRiskLimits::permission_change(),
        )
    }

    fn build(
        pool: PgPool,
        deployment_id: DeploymentId,
        read_limit: RateLimitConfig,
        mutation_limit: RateLimitConfig,
    ) -> Self {
        Self(Arc::new(NotificationApiStateInner {
            pool,
            deployment_id,
            read_limiter: Mutex::new(TokenBucket::new(&read_limit)),
            mutation_limiter: Mutex::new(TokenBucket::new(&mutation_limit)),
        }))
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

/// No notification action is reserved to a builtin role identity, so this
/// surface never publishes the shared `role` blocker.
#[derive(Debug, Serialize)]
struct NotificationCapabilities {
    update_settings: WriteCapability,
}

#[derive(Debug, Serialize)]
struct NotificationSettingsResponse {
    /// Which installation answered. Published only to a platform seat; the
    /// tenant's own alert settings do not need the machine reference.
    deployment_id: Option<String>,
    generated_at: DateTime<Utc>,
    /// `None` until the tenant has saved a row: the platform default is then
    /// whatever the column defaults say, and the console shows it as such
    /// rather than as a choice somebody made.
    settings: Option<NotificationSettingsView>,
    effective: EffectiveSettings,
    /// Verified domains the tenant may address, so the form cannot offer a
    /// recipient the server will refuse.
    verified_domains: Vec<String>,
    deliveries: Vec<DeliveryView>,
    capabilities: NotificationCapabilities,
}

#[derive(Debug, Serialize)]
struct NotificationSettingsView {
    enabled: bool,
    severity_floor: String,
    recipient_emails: Vec<String>,
    digest_window_minutes: i32,
    updated_by: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct EffectiveSettings {
    enabled: bool,
    severity_floor: String,
    recipient_count: usize,
    digest_window_minutes: i32,
    /// Whether a mail can actually leave: settings alone are not a delivery
    /// promise, because an empty recipient list delivers nothing.
    deliverable: bool,
}

#[derive(Debug, Serialize)]
struct DeliveryView {
    notification_id: String,
    status: String,
    recipient_count: i32,
    attempts: i32,
    reason: Option<String>,
    /// The MTA's queue reference for a delivered notice. Published only to a
    /// platform seat: a tenant sees that their alert mail was delivered, not
    /// which queue on the mail server carried it.
    outbound_transaction_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct UpdateSettingsRequest {
    enabled: Option<bool>,
    severity_floor: Option<String>,
    recipient_emails: Option<Vec<String>>,
    digest_window_minutes: Option<i32>,
}

struct ValidatedSettings {
    enabled: bool,
    severity_floor: String,
    recipient_emails: Vec<String>,
    digest_window_minutes: i32,
}

#[derive(Debug)]
enum RecipientRejection {
    Malformed,
    /// A well-formed address outside the tenant's verified domains.
    Unauthorized,
}

enum IdempotencyRejection {
    Missing,
    Invalid,
}

pub fn notification_router(state: NotificationApiState) -> Router {
    Router::new()
        .route(
            NOTIFICATION_SETTINGS_PATH,
            get(get_notification_settings).put(put_notification_settings),
        )
        .with_state(state)
}

async fn get_notification_settings(
    State(state): State<NotificationApiState>,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if session_blocker(
        &context,
        &state.0.deployment_id,
        NOTIFICATIONS_VIEW_PERMISSION,
    )
    .is_some()
    {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    if !try_consume(&state.0.read_limiter) {
        return rate_limited();
    }

    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    .is_err()
    {
        return unavailable();
    }

    let stored = match sqlx::query(
        "SELECT enabled, severity_floor, recipient_emails, digest_window_minutes, \
                updated_by, updated_at \
         FROM tenant_notification_settings \
         WHERE deployment_id = $1 AND customer_id = $2",
    )
    .bind(&state.0.deployment_id.0)
    .bind(&context.customer_id.0)
    .fetch_optional(&mut *transaction)
    .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    let settings = stored.as_ref().map(|row| NotificationSettingsView {
        enabled: row.get("enabled"),
        severity_floor: row.get("severity_floor"),
        recipient_emails: row.get::<Vec<String>, _>("recipient_emails"),
        digest_window_minutes: row.get("digest_window_minutes"),
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
    });
    let effective = EffectiveSettings {
        enabled: settings.as_ref().is_none_or(|value| value.enabled),
        severity_floor: settings.as_ref().map_or_else(
            || DEFAULT_SEVERITY_FLOOR.to_string(),
            |value| value.severity_floor.clone(),
        ),
        recipient_count: settings
            .as_ref()
            .map_or(0, |value| value.recipient_emails.len()),
        digest_window_minutes: settings
            .as_ref()
            .map_or(DEFAULT_DIGEST_WINDOW_MINUTES, |value| {
                value.digest_window_minutes
            }),
        deliverable: settings
            .as_ref()
            .is_some_and(|value| value.enabled && !value.recipient_emails.is_empty()),
    };

    let verified_domains =
        match verified_domain_list(&mut transaction, &context.customer_id.0).await {
            Ok(domains) => domains,
            Err(response) => return response,
        };
    let deliveries = match load_deliveries(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
        platform_placement(&context),
    )
    .await
    {
        Ok(rows) => rows,
        Err(response) => return response,
    };

    if transaction.commit().await.is_err() {
        return unavailable();
    }

    let response = NotificationSettingsResponse {
        deployment_id: platform_placement(&context).then(|| state.0.deployment_id.0.clone()),
        generated_at: Utc::now(),
        capabilities: NotificationCapabilities {
            update_settings: WriteCapability::from_blocker(session_blocker(
                &context,
                &state.0.deployment_id,
                NOTIFICATIONS_MANAGE_PERMISSION,
            )),
        },
        settings,
        effective,
        verified_domains,
        deliveries,
    };
    (StatusCode::OK, Json(ApiEnvelope { data: response })).into_response()
}

async fn put_notification_settings(
    State(state): State<NotificationApiState>,
    context: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    payload: Result<Json<UpdateSettingsRequest>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if session_blocker(
        &context,
        &state.0.deployment_id,
        NOTIFICATIONS_MANAGE_PERMISSION,
    )
    .is_some()
    {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    if !context.has_step_up() {
        return api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        );
    }
    if !try_consume(&state.0.mutation_limiter) {
        return rate_limited();
    }
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    let Json(body) = match payload {
        Ok(payload) => payload,
        Err(_) => return invalid_request(),
    };

    let mut transaction = match state.0.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    .is_err()
    {
        return unavailable();
    }

    // The current row supplies the fields this PUT omits: the endpoint is a
    // full settings write, not a patch of four independent switches.
    let stored = match sqlx::query(
        "SELECT enabled, severity_floor, recipient_emails, digest_window_minutes \
         FROM tenant_notification_settings \
         WHERE deployment_id = $1 AND customer_id = $2",
    )
    .bind(&state.0.deployment_id.0)
    .bind(&context.customer_id.0)
    .fetch_optional(&mut *transaction)
    .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    let current_enabled = stored.as_ref().is_none_or(|row| row.get("enabled"));
    let current_floor = stored.as_ref().map_or_else(
        || DEFAULT_SEVERITY_FLOOR.to_string(),
        |row| row.get("severity_floor"),
    );
    let current_recipients = stored.as_ref().map_or_else(Vec::new, |row| {
        row.get::<Vec<String>, _>("recipient_emails")
    });
    let current_window = stored
        .as_ref()
        .map_or(DEFAULT_DIGEST_WINDOW_MINUTES, |row| {
            row.get("digest_window_minutes")
        });

    let request = ValidatedSettings {
        enabled: body.enabled.unwrap_or(current_enabled),
        severity_floor: body.severity_floor.unwrap_or(current_floor),
        recipient_emails: body.recipient_emails.unwrap_or(current_recipients),
        digest_window_minutes: body.digest_window_minutes.unwrap_or(current_window),
    };
    if !SEVERITY_FLOORS.contains(&request.severity_floor.as_str())
        || !(0..=MAX_DIGEST_WINDOW_MINUTES).contains(&request.digest_window_minutes)
    {
        return invalid_request();
    }
    let verified = match verified_domain_list(&mut transaction, &context.customer_id.0).await {
        Ok(domains) => domains,
        Err(response) => return response,
    };
    let recipients = match normalize_recipients(&request.recipient_emails, &verified) {
        Ok(recipients) => recipients,
        Err(RecipientRejection::Malformed) => return invalid_request(),
        Err(RecipientRejection::Unauthorized) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "RECIPIENT_DOMAIN_NOT_VERIFIED",
                "Every recipient must be inside a domain this customer has verified",
            )
        },
    };

    let operation = "notifications:settings:update".to_string();
    match claim(&mut transaction, &key, &operation).await {
        Ok(ClaimOutcome::Fresh) => {},
        Ok(ClaimOutcome::Replay(value)) => return replay_response(value),
        Ok(ClaimOutcome::InProgress) => return conflict("Request is already in progress"),
        Ok(ClaimOutcome::OperationMismatch) => return invalid_request(),
        Err(_) => return unavailable(),
    }

    let previous = stored.as_ref().map(|row| {
        json!({
            "enabled": row.get::<bool, _>("enabled"),
            "severity_floor": row.get::<String, _>("severity_floor"),
            "recipient_emails": row.get::<Vec<String>, _>("recipient_emails"),
            "digest_window_minutes": row.get::<i32, _>("digest_window_minutes"),
        })
    });

    let row = match sqlx::query(
        "INSERT INTO tenant_notification_settings (\
             deployment_id, customer_id, enabled, severity_floor, recipient_emails, \
             digest_window_minutes, updated_by\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT (deployment_id, customer_id) DO UPDATE SET \
             enabled = EXCLUDED.enabled, \
             severity_floor = EXCLUDED.severity_floor, \
             recipient_emails = EXCLUDED.recipient_emails, \
             digest_window_minutes = EXCLUDED.digest_window_minutes, \
             updated_by = EXCLUDED.updated_by, \
             updated_at = now() \
         RETURNING enabled, severity_floor, recipient_emails, digest_window_minutes, \
             updated_by, updated_at",
    )
    .bind(&state.0.deployment_id.0)
    .bind(&context.customer_id.0)
    .bind(request.enabled)
    .bind(&request.severity_floor)
    .bind(&recipients)
    .bind(request.digest_window_minutes)
    .bind(&context.actor.login)
    .fetch_one(&mut *transaction)
    .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    let settings = NotificationSettingsView {
        enabled: row.get("enabled"),
        severity_floor: row.get("severity_floor"),
        recipient_emails: row.get("recipient_emails"),
        digest_window_minutes: row.get("digest_window_minutes"),
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
    };

    if write_settings_audit(
        &mut transaction,
        &state.0.deployment_id.0,
        &context,
        &headers,
        previous,
        &settings,
    )
    .await
    .is_err()
    {
        return unavailable();
    }

    let Some(value) = envelope(&settings) else {
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

    (StatusCode::OK, Json(ApiEnvelope { data: settings })).into_response()
}

/// Normalized, deduplicated, lowercased recipients. Every address must sit in
/// one of `verified_domains`; the cap matches the database CHECK constraint so
/// the caller gets a refusal rather than a write failure.
fn normalize_recipients(
    raw: &[String],
    verified_domains: &[String],
) -> Result<Vec<String>, RecipientRejection> {
    let mut seen = Vec::new();
    for address in raw {
        let trimmed = address.trim().to_lowercase();
        if trimmed.is_empty()
            || trimmed.len() > 320
            || !trimmed.contains('@')
            || trimmed.contains(['\r', '\n', '<', '>', ',', ' '])
            || trimmed.split('@').count() != 2
            || trimmed
                .rsplit('@')
                .next()
                .is_none_or(|domain| !domain.contains('.'))
        {
            return Err(RecipientRejection::Malformed);
        }
        let domain = trimmed.rsplit('@').next().unwrap_or_default();
        // Subdomain addresses are not accepted: a verified parent domain does
        // not authorize mailing a host below it that the tenant never proved.
        if !verified_domains.iter().any(|verified| verified == domain) {
            return Err(RecipientRejection::Unauthorized);
        }
        if !seen.contains(&trimmed) {
            seen.push(trimmed);
        }
    }
    if seen.len() > MAX_RECIPIENTS {
        return Err(RecipientRejection::Malformed);
    }
    Ok(seen)
}

async fn verified_domain_list(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    customer_id: &str,
) -> Result<Vec<String>, Response> {
    sqlx::query_scalar::<_, String>(
        "SELECT lower(domain) FROM domains \
         WHERE customer_id = $1 AND verification_status = 'verified' \
         ORDER BY lower(domain)",
    )
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| unavailable())
}

async fn load_deliveries(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    platform: bool,
) -> Result<Vec<DeliveryView>, Response> {
    let rows = sqlx::query(
        "SELECT notification_id::text AS notification_id, status, recipient_count, attempts, \
                reason, outbound_transaction_id, created_at, updated_at \
         FROM notification_deliveries \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY created_at DESC \
         LIMIT $3",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(DELIVERY_HISTORY_LIMIT as i64)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| unavailable())?;
    Ok(rows
        .into_iter()
        .map(|row| DeliveryView {
            notification_id: row.get("notification_id"),
            status: row.get("status"),
            recipient_count: row.get("recipient_count"),
            attempts: row.get("attempts"),
            reason: row.get("reason"),
            outbound_transaction_id: platform
                .then(|| row.get("outbound_transaction_id"))
                .flatten(),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
        .collect())
}

fn session_blocker(
    context: &TenantContext,
    deployment_id: &DeploymentId,
    permission: &str,
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
    None
}

fn has_permission(context: &TenantContext, permission: &str) -> bool {
    context
        .permissions
        .iter()
        .any(|granted| granted == permission)
}

async fn set_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<(), ()> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(|_| ())
}

async fn write_settings_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    context: &TenantContext,
    headers: &HeaderMap,
    previous: Option<Value>,
    settings: &NotificationSettingsView,
) -> Result<(), Response> {
    let (impersonated_subject, impersonated_customer) = match &context.impersonation {
        Some(impersonation) => (
            impersonation.impersonated_subject.clone(),
            Some(impersonation.impersonated_customer.0.clone()),
        ),
        None => (None, None),
    };
    let record = AuditEventRecord {
        id: uuid::Uuid::new_v4(),
        created_at: Utc::now(),
        actor_id: context.actor.actor_id.0.to_string(),
        actor_login: context.actor.login.clone(),
        actor_roles: context.actor.roles.clone(),
        impersonated_subject,
        impersonated_customer,
        customer_id: Some(context.customer_id.0.clone()),
        action: AUDIT_SETTINGS_UPDATED.to_string(),
        resource_type: AUDIT_RESOURCE_SETTINGS.to_string(),
        resource_id: Some(context.customer_id.0.clone()),
        result: "success".to_string(),
        source_ip: source_ip_from(headers),
        session_id: Some(context.session_id.clone()),
        trace_id: context.trace_id.clone(),
        details: json!({
            "previous": previous,
            "enabled": settings.enabled,
            "severity_floor": settings.severity_floor,
            "recipient_count": settings.recipient_emails.len(),
            "recipients": settings.recipient_emails,
            "digest_window_minutes": settings.digest_window_minutes,
        }),
    };
    PostgresAuditStore::insert_record(transaction, deployment_id, &record)
        .await
        .map_err(|_| unavailable())
}

/// The bucket is consumed only while the guard is held, so a poisoned lock
/// denies the request instead of silently allowing it.
fn try_consume(limiter: &Mutex<TokenBucket>) -> bool {
    limiter
        .lock()
        .map(|mut bucket| bucket.try_consume())
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

fn rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, "60")],
        Json(ApiErrorBody {
            code: "RATE_LIMITED",
            message: "Too many notification requests",
        }),
    )
        .into_response()
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        "Notification settings are unavailable",
    )
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, Extension};
    use nullapart_mail_contracts::{rate_limit::RateLimitConfig, transaction::CustomerId, ActorId};
    use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId};
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;
    use tower::ServiceExt;

    use super::*;

    fn fast_failing_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(75))
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse")
    }

    fn state() -> NotificationApiState {
        NotificationApiState::new(fast_failing_pool(), DeploymentId::new("LOCAL-TEST"))
    }

    fn state_with_budget(read_tokens: u64, mutation_tokens: u64) -> NotificationApiState {
        NotificationApiState::build(
            fast_failing_pool(),
            DeploymentId::new("LOCAL-TEST"),
            rate_limit_config(read_tokens),
            rate_limit_config(mutation_tokens),
        )
    }

    fn rate_limit_config(max_tokens: u64) -> RateLimitConfig {
        RateLimitConfig {
            max_tokens,
            refill_rate_per_sec: 0.0,
            ..RateLimitConfig::default()
        }
    }

    fn context(permissions: Vec<String>, assurance: AuthenticationAssurance) -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            region: RegionId::new("local"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "tenant-admin@example.test".to_string(),
                roles: vec!["customer_admin".to_string()],
                authentication_assurance: assurance,
            },
            impersonation: None,
            customer_id: CustomerId::new("CZA-1"),
            customer_internal_key: 1,
            customer_display_name: "Customer test".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions,
            config_revision: 1,
            trace_id: "notification-test".to_string(),
            correlation_id: "notification-test".to_string(),
            session_id: "notification-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn verified() -> Vec<String> {
        vec!["example.test".to_string(), "mail.example.test".to_string()]
    }

    #[test]
    fn recipients_must_be_inside_the_tenants_verified_domains() {
        let outside = ["admin@other-tenant.test".to_string()];
        assert!(matches!(
            normalize_recipients(&outside, &verified()),
            Err(RecipientRejection::Unauthorized)
        ));
    }

    #[test]
    fn an_unverified_subdomain_is_not_covered_by_its_verified_parent() {
        let nested = ["ops@deep.example.test".to_string()];
        assert!(matches!(
            normalize_recipients(&nested, &verified()),
            Err(RecipientRejection::Unauthorized)
        ));
    }

    #[test]
    fn recipients_are_normalized_and_deduplicated() {
        let deduped = normalize_recipients(
            &[
                "ops@example.test".to_string(),
                " OPS@example.test ".to_string(),
                "admin@mail.example.test".to_string(),
            ],
            &verified(),
        )
        .expect("addresses are valid");
        assert_eq!(deduped, vec!["ops@example.test", "admin@mail.example.test"]);
    }

    #[test]
    fn recipient_list_is_capped_at_the_database_limit() {
        let raw: Vec<String> = (0..=(MAX_RECIPIENTS as u32))
            .map(|index| format!("ops{index}@example.test"))
            .collect();
        assert!(matches!(
            normalize_recipients(&raw, &verified()),
            Err(RecipientRejection::Malformed)
        ));
    }

    #[test]
    fn recipient_validation_rejects_command_shaped_input() {
        for address in [
            "ops@example.test\r\nRCPT TO:<x@y.test>".to_string(),
            "ops@example.test,other@example.test".to_string(),
            "not-an-address".to_string(),
            "a@b".to_string(),
            "".to_string(),
        ] {
            assert!(
                matches!(
                    normalize_recipients(&[address], &verified()),
                    Err(RecipientRejection::Malformed)
                ),
                "malformed input must be refused"
            );
        }
    }

    #[test]
    fn a_syntactically_valid_address_still_faces_the_authorization_check() {
        // Two labels that each look like a domain are a legal mailbox, so the
        // rejection has to come from the verified-domain rule, not the parser.
        let odd = ["two@at.example.test.example.test".to_string()];
        assert!(matches!(
            normalize_recipients(&odd, &verified()),
            Err(RecipientRejection::Unauthorized)
        ));
    }

    #[test]
    fn view_permission_gates_the_read_and_manage_gates_the_write() {
        let deployment = DeploymentId::new("LOCAL-TEST");
        let without = context(
            vec![NOTIFICATIONS_VIEW_PERMISSION.to_string()],
            AuthenticationAssurance::StepUp,
        );
        assert_eq!(
            session_blocker(&without, &deployment, NOTIFICATIONS_MANAGE_PERMISSION),
            Some(Blocker::Permission)
        );
        assert!(session_blocker(&without, &deployment, NOTIFICATIONS_VIEW_PERMISSION).is_none());
    }

    #[test]
    fn a_foreign_deployment_session_is_blocked_even_with_the_permission() {
        let mut scoped = context(
            vec![NOTIFICATIONS_MANAGE_PERMISSION.to_string()],
            AuthenticationAssurance::StepUp,
        );
        scoped.deployment_id = DeploymentId::new("OTHER");
        assert_eq!(
            session_blocker(
                &scoped,
                &DeploymentId::new("LOCAL-TEST"),
                NOTIFICATIONS_MANAGE_PERMISSION
            ),
            Some(Blocker::Deployment)
        );
    }

    #[test]
    fn a_suspended_tenant_is_blocked_before_its_own_settings_change() {
        let mut suspended = context(
            vec![NOTIFICATIONS_MANAGE_PERMISSION.to_string()],
            AuthenticationAssurance::StepUp,
        );
        suspended.customer_lifecycle = CustomerLifecycle::Suspended;
        assert_eq!(
            session_blocker(
                &suspended,
                &DeploymentId::new("LOCAL-TEST"),
                NOTIFICATIONS_MANAGE_PERMISSION
            ),
            Some(Blocker::Lifecycle)
        );
    }

    #[tokio::test]
    async fn settings_read_requires_authenticated_context() {
        let response = notification_router(state())
            .oneshot(
                Request::get(NOTIFICATION_SETTINGS_PATH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn settings_read_requires_permission_before_database_access() {
        let response = notification_router(state())
            .layer(Extension(context(vec![], AuthenticationAssurance::StepUp)))
            .oneshot(
                Request::get(NOTIFICATION_SETTINGS_PATH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn settings_write_requires_step_up_before_the_store_is_reached() {
        let response = notification_router(state())
            .layer(Extension(context(
                vec![NOTIFICATIONS_MANAGE_PERMISSION.to_string()],
                AuthenticationAssurance::Standard,
            )))
            .oneshot(
                Request::put(NOTIFICATION_SETTINGS_PATH)
                    .header(IDEMPOTENCY_HEADER, "key-1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn settings_write_requires_an_idempotency_key_before_the_store_is_reached() {
        let response = notification_router(state())
            .layer(Extension(context(
                vec![NOTIFICATIONS_MANAGE_PERMISSION.to_string()],
                AuthenticationAssurance::StepUp,
            )))
            .oneshot(
                Request::put(NOTIFICATION_SETTINGS_PATH)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn settings_write_is_rate_limited_after_its_mutation_budget() {
        let state = state_with_budget(100, 1);
        let app = notification_router(state).layer(Extension(context(
            vec![NOTIFICATIONS_MANAGE_PERMISSION.to_string()],
            AuthenticationAssurance::StepUp,
        )));
        for index in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::put(NOTIFICATION_SETTINGS_PATH)
                        .header(IDEMPOTENCY_HEADER, format!("key-{index}"))
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"enabled":false}"#))
                        .expect("request"),
                )
                .await
                .expect("response");
            if index == 1 {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }
}

//! Authenticated Phase 6 outbound-intelligence Control Plane API.
//!
//! The projection is intentionally content-free: operators see sender/source
//! behaviour, aggregate campaign fingerprints, event state and approval
//! budgets. It never exposes message bodies, raw MIME, full recipient lists or
//! content samples.

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
use uuid::Uuid;

use crate::admin_audit::{source_ip_from, AuditEventRecord, PostgresAuditStore};
use crate::idempotency::{claim, complete, ClaimOutcome};

pub const OUTBOUND_INTELLIGENCE_VIEW_PERMISSION: &str = "outbound-intelligence:view";
pub const OUTBOUND_INTELLIGENCE_MANAGE_PERMISSION: &str = "outbound-intelligence:manage";

const OUTBOUND_INTELLIGENCE_PATH: &str = "/api/v1/outbound-intelligence";
const APPROVED_SENDERS_PATH: &str = "/api/v1/outbound-intelligence/approved-senders";
const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const AUDIT_APPROVED_SENDER_UPSERTED: &str = "outbound_bulk_sender_upserted";
const AUDIT_RESOURCE_APPROVED_SENDER: &str = "approved_bulk_sender";

#[derive(Clone)]
pub struct OutboundIntelligenceApiState(Arc<OutboundIntelligenceApiStateInner>);

struct OutboundIntelligenceApiStateInner {
    pool: PgPool,
    deployment_id: DeploymentId,
    /// Fail-closed shared budget for approved-sender mutations. Approving a
    /// bulk sender raises a tenant's outbound authority, so it is treated as a
    /// high-risk change like the other Control Plane mutation modules.
    high_risk_limiter: std::sync::Mutex<TokenBucket>,
}

impl OutboundIntelligenceApiState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self(Arc::new(OutboundIntelligenceApiStateInner {
            pool,
            deployment_id,
            high_risk_limiter: std::sync::Mutex::new(TokenBucket::new(
                &HighRiskLimits::permission_change(),
            )),
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

#[derive(Debug, Serialize)]
struct OutboundIntelligenceResponse {
    deployment_id: String,
    generated_at: DateTime<Utc>,
    summary: OutboundIntelligenceSummary,
    approved_senders: Vec<ApprovedBulkSenderView>,
    sender_behaviour: Vec<SenderBehaviourView>,
    campaigns: Vec<CampaignView>,
    security_events: Vec<SecurityEventView>,
    policy_history: Vec<PolicyHistoryView>,
}

#[derive(Debug, Serialize, Default)]
struct OutboundIntelligenceSummary {
    messages_1h: i64,
    recipients_1h: i64,
    unique_recipients_1h: i64,
    active_senders_1h: i64,
    campaigns_observed: i64,
    approved_bulk_senders: i64,
    open_security_events: i64,
    critical_security_events: i64,
}

#[derive(Debug, Serialize)]
struct ApprovedBulkSenderView {
    id: Uuid,
    sender_address: String,
    sending_domain: String,
    source_kind: String,
    source_id: String,
    source_ip: Option<String>,
    max_messages_per_minute: i32,
    max_messages_per_hour: i32,
    max_recipients_per_message: i32,
    max_unique_recipients_per_hour: i32,
    active: bool,
    reason: String,
    approved_by: String,
    updated_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct SenderBehaviourView {
    sender_address: String,
    sending_domain: String,
    source_kind: String,
    source_id: String,
    source_ip: Option<String>,
    messages_1h: i64,
    recipients_1h: i64,
    unique_recipients_1h: i64,
    new_recipients_1h: i64,
    bounce_failures_1h: i64,
    malware_observations_1h: i64,
    auth_source_changes_1h: i64,
    unusual_time_observations_1h: i64,
    latest_seen_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct CampaignView {
    fingerprint: String,
    algorithm: String,
    message_count: i32,
    recipient_count: i32,
    disposition: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SecurityEventView {
    id: Uuid,
    event_type: String,
    severity: String,
    outcome: String,
    reason_code: String,
    sender_address: Option<String>,
    source_id: Option<String>,
    campaign_fingerprint: Option<String>,
    status: String,
    message_count: i32,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    cooldown_until: Option<DateTime<Utc>>,
    remediation_runbook: Option<String>,
    remediation_summary: Option<String>,
    credential_rotation_recommended: bool,
}

#[derive(Debug, Serialize)]
struct PolicyHistoryView {
    id: Uuid,
    action: String,
    actor_login: String,
    resource_id: Option<String>,
    result: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct ApprovedBulkSenderRequest {
    sender_address: String,
    sending_domain: String,
    source_kind: SourceKind,
    source_id: String,
    source_ip: Option<String>,
    max_messages_per_minute: i32,
    max_messages_per_hour: i32,
    max_recipients_per_message: i32,
    max_unique_recipients_per_hour: i32,
    active: Option<bool>,
    reason: String,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    SmtpMta,
    InternalApi,
    Webhook,
    Connector,
}

impl SourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::SmtpMta => "smtp_mta",
            Self::InternalApi => "internal_api",
            Self::Webhook => "webhook",
            Self::Connector => "connector",
        }
    }
}

#[derive(Debug, Serialize)]
struct ApprovedBulkSenderResponse {
    id: Uuid,
    sender_address: String,
    source_kind: &'static str,
    source_id: String,
    active: bool,
    changed: bool,
    updated_at: DateTime<Utc>,
}

struct ValidatedApprovedBulkSenderRequest {
    sender_address: String,
    sending_domain: String,
    source_kind: SourceKind,
    source_id: String,
    source_ip: Option<String>,
    max_messages_per_minute: i32,
    max_messages_per_hour: i32,
    max_recipients_per_message: i32,
    max_unique_recipients_per_hour: i32,
    active: bool,
    reason: String,
    expires_at: Option<DateTime<Utc>>,
}

enum IdempotencyRejection {
    Missing,
    Invalid,
}

pub fn outbound_intelligence_router(state: OutboundIntelligenceApiState) -> Router {
    Router::new()
        .route(OUTBOUND_INTELLIGENCE_PATH, get(get_outbound_intelligence))
        .route(APPROVED_SENDERS_PATH, post(post_approved_sender))
        .with_state(state)
}

async fn get_outbound_intelligence(
    State(state): State<OutboundIntelligenceApiState>,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !authorized(&state, &context, OUTBOUND_INTELLIGENCE_VIEW_PERMISSION) {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
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

    let summary = match load_summary(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(summary) => summary,
        Err(response) => return response,
    };
    let approved_senders = match load_approved_senders(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let sender_behaviour = match load_sender_behaviour(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let campaigns = match load_campaigns(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let security_events = match load_security_events(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let policy_history = match load_policy_history(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };

    if transaction.commit().await.is_err() {
        return unavailable();
    }

    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: OutboundIntelligenceResponse {
                deployment_id: state.0.deployment_id.0.clone(),
                generated_at: Utc::now(),
                summary,
                approved_senders,
                sender_behaviour,
                campaigns,
                security_events,
                policy_history,
            },
        }),
    )
        .into_response()
}

async fn post_approved_sender(
    State(state): State<OutboundIntelligenceApiState>,
    context: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    payload: Result<Json<ApprovedBulkSenderRequest>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !authorized(&state, &context, OUTBOUND_INTELLIGENCE_MANAGE_PERMISSION) {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    let key = match require_idempotency_key(&headers) {
        Ok(key) => key,
        Err(rejection) => return idempotency_rejection_response(rejection),
    };
    if let Err(response) = require_high_risk(&state, &context).await {
        return response;
    }
    let Json(body) = match payload {
        Ok(payload) => payload,
        Err(_) => return invalid_request(),
    };
    let request = match validate_approved_sender(body) {
        Ok(request) => request,
        Err(()) => return invalid_request(),
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
    let operation = format!(
        "outbound-intelligence:approved-sender:{}:{}:{}",
        request.sender_address,
        request.source_kind.as_str(),
        request.source_id
    );
    match claim(&mut transaction, &key, &operation).await {
        Ok(ClaimOutcome::Fresh) => {},
        Ok(ClaimOutcome::Replay(value)) => return replay_response(value),
        Ok(ClaimOutcome::InProgress) => return conflict("Request is already in progress"),
        Ok(ClaimOutcome::OperationMismatch) => return invalid_request(),
        Err(_) => return unavailable(),
    }

    // Approval is scoped to the caller's own tenant, so a Customer Admin can
    // only ever raise limits for domains this customer owns. Enforcement would
    // not leak across tenants without this (the runtime lookup is keyed to
    // customer_id), but it would let a tenant record an approval for a domain
    // it does not control.
    let domain_verified = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM domains \
         WHERE customer_id = $1 AND domain = $2 AND verification_status = 'verified')",
    )
    .bind(&context.customer_id.0)
    .bind(&request.sending_domain)
    .fetch_one(&mut *transaction)
    .await;
    match domain_verified {
        Ok(true) => {},
        Ok(false) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "DOMAIN_NOT_VERIFIED",
                "Sender domain is not a verified domain of this customer",
            )
        },
        Err(_) => return unavailable(),
    }

    let previous = match sqlx::query(
        "SELECT active, max_messages_per_minute, max_messages_per_hour, \
                max_recipients_per_message, max_unique_recipients_per_hour, reason, expires_at \
         FROM approved_bulk_senders \
         WHERE deployment_id = $1 AND customer_id = $2 AND sender_address = $3 \
           AND source_kind = $4 AND source_id = $5",
    )
    .bind(&state.0.deployment_id.0)
    .bind(&context.customer_id.0)
    .bind(&request.sender_address)
    .bind(request.source_kind.as_str())
    .bind(&request.source_id)
    .fetch_optional(&mut *transaction)
    .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    let changed = previous.as_ref().is_none_or(|row| {
        row.get::<bool, _>("active") != request.active
            || row.get::<i32, _>("max_messages_per_minute") != request.max_messages_per_minute
            || row.get::<i32, _>("max_messages_per_hour") != request.max_messages_per_hour
            || row.get::<i32, _>("max_recipients_per_message") != request.max_recipients_per_message
            || row.get::<i32, _>("max_unique_recipients_per_hour")
                != request.max_unique_recipients_per_hour
            || row.get::<String, _>("reason") != request.reason
            || row.get::<Option<DateTime<Utc>>, _>("expires_at") != request.expires_at
    });

    let row = match sqlx::query(
        "INSERT INTO approved_bulk_senders (\
             deployment_id, customer_id, sender_address, sending_domain, source_kind, source_id, \
             source_ip, max_messages_per_minute, max_messages_per_hour, \
             max_recipients_per_message, max_unique_recipients_per_hour, active, \
             approved_by, reason, expires_at\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7::inet,$8,$9,$10,$11,$12,$13,$14,$15) \
         ON CONFLICT (deployment_id, customer_id, sender_address, source_kind, source_id) \
         DO UPDATE SET \
             sending_domain = EXCLUDED.sending_domain, \
             source_ip = EXCLUDED.source_ip, \
             max_messages_per_minute = EXCLUDED.max_messages_per_minute, \
             max_messages_per_hour = EXCLUDED.max_messages_per_hour, \
             max_recipients_per_message = EXCLUDED.max_recipients_per_message, \
             max_unique_recipients_per_hour = EXCLUDED.max_unique_recipients_per_hour, \
             active = EXCLUDED.active, \
             approved_by = EXCLUDED.approved_by, \
             reason = EXCLUDED.reason, \
             expires_at = EXCLUDED.expires_at, \
             updated_at = now() \
         RETURNING id, updated_at",
    )
    .bind(&state.0.deployment_id.0)
    .bind(&context.customer_id.0)
    .bind(&request.sender_address)
    .bind(&request.sending_domain)
    .bind(request.source_kind.as_str())
    .bind(&request.source_id)
    .bind(&request.source_ip)
    .bind(request.max_messages_per_minute)
    .bind(request.max_messages_per_hour)
    .bind(request.max_recipients_per_message)
    .bind(request.max_unique_recipients_per_hour)
    .bind(request.active)
    .bind(&context.actor.login)
    .bind(&request.reason)
    .bind(request.expires_at)
    .fetch_one(&mut *transaction)
    .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    if write_approved_sender_audit(
        &mut transaction,
        &state.0.deployment_id.0,
        &context,
        &headers,
        &request,
        changed,
    )
    .await
    .is_err()
    {
        return unavailable();
    }

    let response = ApprovedBulkSenderResponse {
        id: row.get("id"),
        sender_address: request.sender_address,
        source_kind: request.source_kind.as_str(),
        source_id: request.source_id,
        active: request.active,
        changed,
        updated_at: row.get("updated_at"),
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

async fn load_summary(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<OutboundIntelligenceSummary, Response> {
    sqlx::query(
        "WITH rollups AS ( \
             SELECT * FROM outbound_behavior_rollups \
             WHERE deployment_id = $1 AND customer_id = $2 \
               AND window_start >= now() - interval '1 hour' \
               AND recipient_domain IS NULL \
         ), events AS ( \
             SELECT * FROM outbound_security_events \
             WHERE deployment_id = $1 AND customer_id = $2 AND status = 'open' \
         ) \
         SELECT \
             COALESCE((SELECT sum(message_count) FROM rollups), 0)::bigint AS messages_1h, \
             COALESCE((SELECT sum(recipient_count) FROM rollups), 0)::bigint AS recipients_1h, \
             COALESCE((SELECT sum(unique_recipient_count) FROM rollups), 0)::bigint AS unique_recipients_1h, \
             COALESCE((SELECT count(DISTINCT sender_address) FROM rollups), 0)::bigint AS active_senders_1h, \
             COALESCE((SELECT count(*) FROM outbound_campaign_fingerprints \
                WHERE deployment_id = $1 AND customer_id = $2), 0)::bigint AS campaigns_observed, \
             COALESCE((SELECT count(*) FROM approved_bulk_senders \
                WHERE deployment_id = $1 AND customer_id = $2 AND active = true), 0)::bigint AS approved_bulk_senders, \
             COALESCE((SELECT count(*) FROM events), 0)::bigint AS open_security_events, \
             COALESCE((SELECT count(*) FROM events WHERE severity = 'critical'), 0)::bigint AS critical_security_events",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_one(&mut **transaction)
    .await
    .map(|row| OutboundIntelligenceSummary {
        messages_1h: row.get("messages_1h"),
        recipients_1h: row.get("recipients_1h"),
        unique_recipients_1h: row.get("unique_recipients_1h"),
        active_senders_1h: row.get("active_senders_1h"),
        campaigns_observed: row.get("campaigns_observed"),
        approved_bulk_senders: row.get("approved_bulk_senders"),
        open_security_events: row.get("open_security_events"),
        critical_security_events: row.get("critical_security_events"),
    })
    .map_err(|_| unavailable())
}

async fn load_approved_senders(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<ApprovedBulkSenderView>, Response> {
    sqlx::query(
        "SELECT id, sender_address, sending_domain, source_kind, source_id, host(source_ip) AS source_ip, \
                max_messages_per_minute, max_messages_per_hour, max_recipients_per_message, \
                max_unique_recipients_per_hour, active, reason, approved_by, updated_at, expires_at \
         FROM approved_bulk_senders \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY active DESC, updated_at DESC \
         LIMIT 50",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| ApprovedBulkSenderView {
                id: row.get("id"),
                sender_address: row.get("sender_address"),
                sending_domain: row.get("sending_domain"),
                source_kind: row.get("source_kind"),
                source_id: row.get("source_id"),
                source_ip: row.get("source_ip"),
                max_messages_per_minute: row.get("max_messages_per_minute"),
                max_messages_per_hour: row.get("max_messages_per_hour"),
                max_recipients_per_message: row.get("max_recipients_per_message"),
                max_unique_recipients_per_hour: row.get("max_unique_recipients_per_hour"),
                active: row.get("active"),
                reason: row.get("reason"),
                approved_by: row.get("approved_by"),
                updated_at: row.get("updated_at"),
                expires_at: row.get("expires_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_sender_behaviour(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<SenderBehaviourView>, Response> {
    sqlx::query(
        "SELECT sender_address, sending_domain, source_kind, source_id, host(max(source_ip)) AS source_ip, \
                sum(message_count)::bigint AS messages_1h, \
                sum(recipient_count)::bigint AS recipients_1h, \
                sum(unique_recipient_count)::bigint AS unique_recipients_1h, \
                sum(new_recipient_count)::bigint AS new_recipients_1h, \
                sum(bounce_count + failure_count)::bigint AS bounce_failures_1h, \
                sum(malware_count)::bigint AS malware_observations_1h, \
                sum(auth_source_change_count)::bigint AS auth_source_changes_1h, \
                sum(unusual_time_count)::bigint AS unusual_time_observations_1h, \
                max(updated_at) AS latest_seen_at \
         FROM outbound_behavior_rollups \
         WHERE deployment_id = $1 AND customer_id = $2 \
           AND window_start >= now() - interval '1 hour' \
           AND recipient_domain IS NULL \
         GROUP BY sender_address, sending_domain, source_kind, source_id \
         ORDER BY sum(message_count) DESC, max(updated_at) DESC \
         LIMIT 25",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| SenderBehaviourView {
                sender_address: row.get("sender_address"),
                sending_domain: row.get("sending_domain"),
                source_kind: row.get("source_kind"),
                source_id: row.get("source_id"),
                source_ip: row.get("source_ip"),
                messages_1h: row.get("messages_1h"),
                recipients_1h: row.get("recipients_1h"),
                unique_recipients_1h: row.get("unique_recipients_1h"),
                new_recipients_1h: row.get("new_recipients_1h"),
                bounce_failures_1h: row.get("bounce_failures_1h"),
                malware_observations_1h: row.get("malware_observations_1h"),
                auth_source_changes_1h: row.get("auth_source_changes_1h"),
                unusual_time_observations_1h: row.get("unusual_time_observations_1h"),
                latest_seen_at: row.get("latest_seen_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_campaigns(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<CampaignView>, Response> {
    sqlx::query(
        "SELECT fingerprint, algorithm, message_count, recipient_count, disposition, \
                first_seen_at, last_seen_at \
         FROM outbound_campaign_fingerprints \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY last_seen_at DESC \
         LIMIT 25",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| CampaignView {
                fingerprint: row.get("fingerprint"),
                algorithm: row.get("algorithm"),
                message_count: row.get("message_count"),
                recipient_count: row.get("recipient_count"),
                disposition: row.get("disposition"),
                first_seen_at: row.get("first_seen_at"),
                last_seen_at: row.get("last_seen_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_security_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<SecurityEventView>, Response> {
    sqlx::query(
        "SELECT id, event_type, severity, outcome, reason_code, sender_address, source_id, \
                campaign_fingerprint, status, message_count, first_seen_at, last_seen_at, cooldown_until, \
                details->>'remediation_runbook' AS remediation_runbook, \
                details->>'remediation_summary' AS remediation_summary, \
                COALESCE((details->>'credential_rotation_recommended')::boolean, false) \
                    AS credential_rotation_recommended \
         FROM outbound_security_events \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, last_seen_at DESC \
         LIMIT 25",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| SecurityEventView {
                id: row.get("id"),
                event_type: row.get("event_type"),
                severity: row.get("severity"),
                outcome: row.get("outcome"),
                reason_code: row.get("reason_code"),
                sender_address: row.get("sender_address"),
                source_id: row.get("source_id"),
                campaign_fingerprint: row.get("campaign_fingerprint"),
                status: row.get("status"),
                message_count: row.get("message_count"),
                first_seen_at: row.get("first_seen_at"),
                last_seen_at: row.get("last_seen_at"),
                cooldown_until: row.get("cooldown_until"),
                remediation_runbook: row.get("remediation_runbook"),
                remediation_summary: row.get("remediation_summary"),
                credential_rotation_recommended: row.get("credential_rotation_recommended"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_policy_history(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<PolicyHistoryView>, Response> {
    sqlx::query(
        "SELECT id, action, actor_login, resource_id, result, created_at \
         FROM audit_events \
         WHERE deployment_id = $1 AND customer_id = $2 \
           AND resource_type = 'approved_bulk_sender' \
         ORDER BY created_at DESC \
         LIMIT 15",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| PolicyHistoryView {
                id: row.get("id"),
                action: row.get("action"),
                actor_login: row.get("actor_login"),
                resource_id: row.get("resource_id"),
                result: row.get("result"),
                created_at: row.get("created_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn write_approved_sender_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    context: &TenantContext,
    headers: &HeaderMap,
    request: &ValidatedApprovedBulkSenderRequest,
    changed: bool,
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
        action: AUDIT_APPROVED_SENDER_UPSERTED.to_string(),
        resource_type: AUDIT_RESOURCE_APPROVED_SENDER.to_string(),
        resource_id: Some(format!(
            "{}:{}:{}",
            request.sender_address,
            request.source_kind.as_str(),
            request.source_id
        )),
        result: "success".to_string(),
        source_ip: source_ip_from(headers),
        session_id: Some(context.session_id.clone()),
        trace_id: context.trace_id.clone(),
        details: json!({
            "sender_address": request.sender_address,
            "sending_domain": request.sending_domain,
            "source_kind": request.source_kind.as_str(),
            "source_id": request.source_id,
            "active": request.active,
            "changed": changed,
            "max_messages_per_minute": request.max_messages_per_minute,
            "max_messages_per_hour": request.max_messages_per_hour,
            "max_recipients_per_message": request.max_recipients_per_message,
            "max_unique_recipients_per_hour": request.max_unique_recipients_per_hour,
        }),
    };
    PostgresAuditStore::insert_record(transaction, deployment_id, &record)
        .await
        .map_err(|_| unavailable())
}

fn authorized(
    state: &OutboundIntelligenceApiState,
    context: &TenantContext,
    permission: &str,
) -> bool {
    context.customer_lifecycle == CustomerLifecycle::Active
        && context.deployment_id == state.0.deployment_id
        && has_permission(context, permission)
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

fn validate_approved_sender(
    request: ApprovedBulkSenderRequest,
) -> Result<ValidatedApprovedBulkSenderRequest, ()> {
    let sender_address = request.sender_address.trim().to_lowercase();
    let sending_domain = request.sending_domain.trim().to_lowercase();
    let source_id = request.source_id.trim().to_string();
    let source_ip = request.source_ip.map(|value| value.trim().to_string());
    let reason = request.reason.trim().to_string();
    if sender_address.is_empty()
        || sender_address.len() > 320
        || !sender_address.contains('@')
        || sending_domain.is_empty()
        || sending_domain.len() > 253
        || source_id.is_empty()
        || source_id.len() > 160
        || reason.len() < 8
        || reason.len() > 512
        || !sender_address.ends_with(&format!("@{sending_domain}"))
        || request.max_messages_per_minute <= 0
        || request.max_messages_per_hour <= 0
        || request.max_recipients_per_message <= 0
        || request.max_unique_recipients_per_hour <= 0
    {
        return Err(());
    }
    // A malformed address must fail as an invalid request here; otherwise the
    // `$7::inet` cast fails at write time and the caller sees 503 UNAVAILABLE.
    if source_ip
        .as_ref()
        .is_some_and(|value| value.parse::<std::net::IpAddr>().is_err())
    {
        return Err(());
    }
    if request
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        return Err(());
    }
    Ok(ValidatedApprovedBulkSenderRequest {
        sender_address,
        sending_domain,
        source_kind: request.source_kind,
        source_id,
        source_ip,
        max_messages_per_minute: request.max_messages_per_minute,
        max_messages_per_hour: request.max_messages_per_hour,
        max_recipients_per_message: request.max_recipients_per_message,
        max_unique_recipients_per_hour: request.max_unique_recipients_per_hour,
        active: request.active.unwrap_or(true),
        reason,
        expires_at: request.expires_at,
    })
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

/// Fresh step-up, then the shared fail-closed high-risk budget. Permission
/// checks come first, and neither gate ever writes. A poisoned limiter lock
/// is treated as exhausted (deny), never as a bypass.
async fn require_high_risk(
    state: &OutboundIntelligenceApiState,
    context: &TenantContext,
) -> Result<(), Response> {
    if !context.has_step_up() {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        ));
    }
    let allowed = state
        .0
        .high_risk_limiter
        .lock()
        .map(|mut bucket| bucket.try_consume())
        .unwrap_or(false);
    if !allowed {
        return Err(rate_limited());
    }
    Ok(())
}

fn rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, "60")],
        Json(ApiErrorBody {
            code: "RATE_LIMITED",
            message: "Too many high-risk changes",
        }),
    )
        .into_response()
}

fn conflict(message: &'static str) -> Response {
    api_error(StatusCode::CONFLICT, "CONFLICT", message)
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        "Outbound intelligence is unavailable",
    )
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, Extension};
    use nullapart_mail_contracts::ActorId;
    use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;

    fn state() -> OutboundIntelligenceApiState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse");
        OutboundIntelligenceApiState::new(pool, DeploymentId::new("LOCAL-TEST"))
    }

    fn context(permissions: Vec<String>) -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            region: RegionId::new("local"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "operator@example.test".to_string(),
                roles: vec!["operator".to_string()],
                authentication_assurance: AuthenticationAssurance::StepUp,
            },
            impersonation: None,
            customer_id: nullapart_mail_contracts::CustomerId::new("CZA-1"),
            customer_internal_key: 1,
            customer_display_name: "Customer test".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions,
            config_revision: 1,
            trace_id: "outbound-intelligence-test".to_string(),
            correlation_id: "outbound-intelligence-test".to_string(),
            session_id: "outbound-intelligence-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn outbound_intelligence_requires_authenticated_context() {
        let response = outbound_intelligence_router(state())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/outbound-intelligence")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn outbound_intelligence_requires_explicit_permission_before_database_access() {
        let response = outbound_intelligence_router(state())
            .layer(Extension(context(vec![])))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/outbound-intelligence")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn approved_sender_mutation_requires_idempotency_before_database_write() {
        let response = outbound_intelligence_router(state())
            .layer(Extension(context(vec![
                OUTBOUND_INTELLIGENCE_MANAGE_PERMISSION.to_string(),
            ])))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/outbound-intelligence/approved-senders")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "sender_address":"bulk@example.test",
                            "sending_domain":"example.test",
                            "source_kind":"smtp_mta",
                            "source_id":"mx-1",
                            "max_messages_per_minute":10,
                            "max_messages_per_hour":100,
                            "max_recipients_per_message":50,
                            "max_unique_recipients_per_hour":1000,
                            "reason":"approved campaign"
                        }"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn approval_body(source_ip: &str) -> String {
        format!(
            r#"{{
                "sender_address":"bulk@example.test",
                "sending_domain":"example.test",
                "source_kind":"smtp_mta",
                "source_id":"mx-1",
                "source_ip":"{source_ip}",
                "max_messages_per_minute":10,
                "max_messages_per_hour":100,
                "max_recipients_per_message":50,
                "max_unique_recipients_per_hour":1000,
                "reason":"approved campaign"
            }}"#
        )
    }

    fn approval_request(idempotency_key: &str, body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/v1/outbound-intelligence/approved-senders")
            .header("content-type", "application/json")
            .header("x-idempotency-key", idempotency_key)
            .body(Body::from(body))
            .expect("request")
    }

    #[tokio::test]
    async fn approved_sender_mutation_rejects_malformed_source_ip_before_database_access() {
        let response = outbound_intelligence_router(state())
            .layer(Extension(context(vec![
                OUTBOUND_INTELLIGENCE_MANAGE_PERMISSION.to_string(),
            ])))
            .oneshot(approval_request(
                "malformed-ip-key",
                approval_body("not-an-ip-address"),
            ))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a malformed source_ip must be a 4xx validation error, not a 503 from the inet cast"
        );
    }

    #[tokio::test]
    async fn approved_sender_mutation_requires_step_up_before_rate_limit_budget() {
        let mut denied_context = context(vec![OUTBOUND_INTELLIGENCE_MANAGE_PERMISSION.to_string()]);
        denied_context.actor.authentication_assurance = AuthenticationAssurance::Standard;
        let response = outbound_intelligence_router(state())
            .layer(Extension(denied_context))
            .oneshot(approval_request("step-up-key", approval_body("192.0.2.10")))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn approved_sender_mutation_is_rate_limited_after_shared_high_risk_budget() {
        let router = outbound_intelligence_router(state()).layer(Extension(context(vec![
            OUTBOUND_INTELLIGENCE_MANAGE_PERMISSION.to_string(),
        ])));
        // `HighRiskLimits::permission_change()` allows five tokens. The budget
        // is spent by the gate itself, so the payloads below are malformed on
        // purpose: validation rejects them with 400 before any database access,
        // which keeps the drain deterministic (no lazy-pool latency) while each
        // request still consumes exactly one token.
        for attempt in 0..5 {
            let response = router
                .clone()
                .oneshot(approval_request(
                    &format!("rate-limit-key-{attempt}"),
                    approval_body("not-an-ip-address"),
                ))
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "attempt {attempt} must be rejected by validation after consuming a token"
            );
        }
        let response = router
            .clone()
            .oneshot(approval_request(
                "rate-limit-key-exhausted",
                approval_body("not-an-ip-address"),
            ))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the sixth mutation attempt must be denied once the shared high-risk budget is empty"
        );
    }
}

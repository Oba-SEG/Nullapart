//! Phase 8 connector and post-delivery remediation Control Plane API.
//!
//! This module records connector capabilities, directory-sync posture, mailbox
//! search state and remediation intent/outcome state. It does not execute live
//! Microsoft/Google/IMAP provider mutations; provider credentials are represented
//! only by regional encrypted-secret reference hashes and are never projected.

use std::sync::{Arc, Mutex};

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

pub const CONNECTORS_VIEW_PERMISSION: &str = "connectors:view";
pub const CONNECTORS_MANAGE_PERMISSION: &str = "connectors:manage";

const CONNECTORS_PATH: &str = "/api/v1/connectors-remediation";
const CONNECTOR_UPSERT_PATH: &str = "/api/v1/connectors-remediation/connectors";
const REMEDIATION_PATH: &str = "/api/v1/connectors-remediation/remediations";
const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
const AUDIT_CONNECTOR_UPSERTED: &str = "connector_capabilities_upserted";
const AUDIT_REMEDIATION_REQUESTED: &str = "connector_remediation_requested";

#[derive(Clone)]
pub struct ConnectorsRemediationState {
    pool: PgPool,
    deployment_id: DeploymentId,
    /// One shared fail-closed budget for both high-risk mutations (connector
    /// upsert and remediation request). Connector capability changes and
    /// remediation requests are listed high-risk actions in
    /// `docs/security/22-RATE-LIMITING-ABUSE-PROTECTION.md`, so they consume
    /// the same dedicated low bucket as the other Control Plane high-risk
    /// mutations (`operations_api`, `domain_security`). The bucket survives
    /// handler clones because the limiter is behind an `Arc`.
    mutation_limiter: Arc<Mutex<TokenBucket>>,
}

impl ConnectorsRemediationState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self {
            pool,
            deployment_id,
            mutation_limiter: Arc::new(Mutex::new(TokenBucket::new(
                &HighRiskLimits::permission_change(),
            ))),
        }
    }
}

/// Fail-closed limit check: the shared bucket is consumed only while the guard
/// is held, so a poisoned lock denies the mutation instead of bypassing the
/// budget (same contract as `domain_security::try_consume`).
fn try_consume_high_risk(limiter: &Mutex<TokenBucket>) -> bool {
    limiter
        .lock()
        .map(|mut bucket| bucket.try_consume())
        .unwrap_or(false)
}

fn rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, "60")],
        Json(ApiErrorBody {
            code: "RATE_LIMITED",
            message: "Too many connector changes",
        }),
    )
        .into_response()
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
struct ConnectorsRemediationResponse {
    deployment_id: String,
    generated_at: DateTime<Utc>,
    summary: ConnectorsSummary,
    connectors: Vec<ConnectorView>,
    directory_sync_runs: Vec<DirectorySyncRunView>,
    mailbox_searches: Vec<MailboxSearchView>,
    remediation_actions: Vec<RemediationActionView>,
    audit_history: Vec<ConnectorAuditView>,
}

#[derive(Debug, Serialize, Default)]
struct ConnectorsSummary {
    active_connectors: i64,
    degraded_connectors: i64,
    directory_sync_enabled: i64,
    mailbox_search_enabled: i64,
    retro_remediation_enabled: i64,
    pending_remediations: i64,
    manual_action_required: i64,
    failed_operations: i64,
}

#[derive(Debug, Serialize)]
struct ConnectorView {
    id: Uuid,
    provider: String,
    display_name: String,
    external_tenant_id_hash: String,
    status: String,
    auth_state: String,
    token_expires_at: Option<DateTime<Utc>>,
    last_directory_sync_at: Option<DateTime<Utc>>,
    last_directory_sync_status: Option<String>,
    last_mailbox_search_at: Option<DateTime<Utc>>,
    last_remediation_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    capabilities: Vec<CapabilityView>,
}

#[derive(Debug, Serialize, Clone)]
struct CapabilityView {
    capability: String,
    enabled: bool,
    granted_scopes: Vec<String>,
    reason: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct DirectorySyncRunView {
    id: Uuid,
    connector_id: Uuid,
    provider: String,
    display_name: String,
    state: String,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    users_seen: i32,
    groups_seen: i32,
    aliases_seen: i32,
    vip_candidates: i32,
    error_code: Option<String>,
    error_summary: Option<String>,
}

#[derive(Debug, Serialize)]
struct MailboxSearchView {
    id: Uuid,
    connector_id: Uuid,
    provider: String,
    purpose: String,
    state: String,
    match_confirmation: String,
    mailbox_address_hash: String,
    provider_message_id_hash: Option<String>,
    created_at: DateTime<Utc>,
    error_code: Option<String>,
    error_summary: Option<String>,
}

#[derive(Debug, Serialize)]
struct RemediationActionView {
    id: Uuid,
    connector_id: Uuid,
    provider: String,
    action_type: String,
    state: String,
    provider_outcome_code: Option<String>,
    error_summary: Option<String>,
    reason: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ConnectorAuditView {
    id: Uuid,
    action: String,
    actor_login: String,
    resource_id: Option<String>,
    result: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct UpsertConnectorRequest {
    provider: ConnectorProvider,
    display_name: String,
    external_tenant_id_hash: String,
    credential_reference_hash: String,
    status: ConnectorStatus,
    auth_state: AuthState,
    token_expires_at: Option<DateTime<Utc>>,
    capabilities: Vec<CapabilityRequest>,
}

#[derive(Debug, Deserialize)]
struct CapabilityRequest {
    capability: ConnectorCapability,
    enabled: bool,
    granted_scopes: Vec<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct RemediationRequest {
    connector_id: Uuid,
    tenant_message_id: Uuid,
    mailbox_address_hash: String,
    provider_message_id_hash: Option<String>,
    purpose: SearchPurpose,
    action_type: RemediationActionType,
    reason: String,
}

#[derive(Debug, Serialize)]
struct UpsertConnectorResponse {
    id: Uuid,
    provider: &'static str,
    display_name: String,
    changed: bool,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct RemediationResponse {
    remediation_id: Uuid,
    mailbox_search_id: Uuid,
    state: &'static str,
    match_confirmation: &'static str,
    provider_side_effect: &'static str,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConnectorProvider {
    #[serde(rename = "microsoft_365")]
    Microsoft365,
    GoogleWorkspace,
    ImapPop,
}

impl ConnectorProvider {
    fn as_str(self) -> &'static str {
        match self {
            Self::Microsoft365 => "microsoft_365",
            Self::GoogleWorkspace => "google_workspace",
            Self::ImapPop => "imap_pop",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConnectorCapability {
    DirectorySync,
    MailboxSearch,
    RetroRemediation,
}

impl ConnectorCapability {
    fn as_str(self) -> &'static str {
        match self {
            Self::DirectorySync => "directory_sync",
            Self::MailboxSearch => "mailbox_search",
            Self::RetroRemediation => "retro_remediation",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConnectorStatus {
    SetupRequired,
    Active,
    Degraded,
    Disabled,
    Revoked,
}

impl ConnectorStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::SetupRequired => "setup_required",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthState {
    NotConfigured,
    Healthy,
    Expiring,
    Expired,
    Revoked,
    ProviderError,
}

impl AuthState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Healthy => "healthy",
            Self::Expiring => "expiring",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::ProviderError => "provider_error",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SearchPurpose {
    PostDeliveryThreat,
    CustomerReportedPhishing,
    FalseNegativeReview,
    ManualSecurityCase,
}

impl SearchPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::PostDeliveryThreat => "post_delivery_threat",
            Self::CustomerReportedPhishing => "customer_reported_phishing",
            Self::FalseNegativeReview => "false_negative_review",
            Self::ManualSecurityCase => "manual_security_case",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RemediationActionType {
    MoveToQuarantine,
    MoveToJunk,
    Delete,
    ManualReview,
}

impl RemediationActionType {
    fn as_str(self) -> &'static str {
        match self {
            Self::MoveToQuarantine => "move_to_quarantine",
            Self::MoveToJunk => "move_to_junk",
            Self::Delete => "delete",
            Self::ManualReview => "manual_review",
        }
    }
}

struct ValidatedConnector {
    provider: ConnectorProvider,
    display_name: String,
    external_tenant_id_hash: String,
    credential_reference_hash: String,
    status: ConnectorStatus,
    auth_state: AuthState,
    token_expires_at: Option<DateTime<Utc>>,
    capabilities: Vec<ValidatedCapability>,
}

struct ValidatedCapability {
    capability: ConnectorCapability,
    enabled: bool,
    granted_scopes: Vec<String>,
    reason: String,
}

struct ValidatedRemediation {
    connector_id: Uuid,
    tenant_message_id: Uuid,
    mailbox_address_hash: String,
    provider_message_id_hash: Option<String>,
    purpose: SearchPurpose,
    action_type: RemediationActionType,
    reason: String,
}

#[derive(Debug)]
enum IdempotencyRejection {
    Missing,
    Invalid,
}

pub fn connectors_remediation_router(state: ConnectorsRemediationState) -> Router {
    Router::new()
        .route(CONNECTORS_PATH, get(get_connectors))
        .route(CONNECTOR_UPSERT_PATH, post(post_connector))
        .route(REMEDIATION_PATH, post(post_remediation))
        .with_state(state)
}

async fn get_connectors(
    State(state): State<ConnectorsRemediationState>,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !authorized(&state, &context, CONNECTORS_VIEW_PERMISSION) {
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

    let summary = match load_summary(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut connectors = match load_connectors(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let capabilities = match load_capabilities(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    for connector in &mut connectors {
        connector.capabilities = capabilities
            .iter()
            .filter(|(connector_id, _)| *connector_id == connector.id)
            .map(|(_, capability)| capability.clone())
            .collect();
    }
    let directory_sync_runs = match load_directory_sync_runs(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mailbox_searches = match load_mailbox_searches(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let remediation_actions = match load_remediations(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let audit_history = match load_audit_history(
        &mut transaction,
        &state.deployment_id.0,
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
            data: ConnectorsRemediationResponse {
                deployment_id: state.deployment_id.0,
                generated_at: Utc::now(),
                summary,
                connectors,
                directory_sync_runs,
                mailbox_searches,
                remediation_actions,
                audit_history,
            },
        }),
    )
        .into_response()
}

async fn post_connector(
    State(state): State<ConnectorsRemediationState>,
    context: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    payload: Result<Json<UpsertConnectorRequest>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !authorized(&state, &context, CONNECTORS_MANAGE_PERMISSION) {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    if !context.has_step_up() {
        return api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        );
    }
    if !try_consume_high_risk(&state.mutation_limiter) {
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
    let request = match validate_connector(body) {
        Ok(request) => request,
        Err(()) => return invalid_request(),
    };
    let operation = format!(
        "connectors-remediation:connector:{}:{}",
        request.provider.as_str(),
        request.external_tenant_id_hash
    );

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
    match claim(&mut transaction, &key, &operation).await {
        Ok(ClaimOutcome::Fresh) => {},
        Ok(ClaimOutcome::Replay(value)) => return replay_response(value),
        Ok(ClaimOutcome::InProgress) => return conflict("Request is already in progress"),
        Ok(ClaimOutcome::OperationMismatch) => return invalid_request(),
        Err(_) => return unavailable(),
    }

    let changed = match connector_changed(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
        &request,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let row = match sqlx::query(
        "INSERT INTO connector_integrations (\
             deployment_id, customer_id, provider, display_name, external_tenant_id_hash, \
             credential_reference_hash, status, auth_state, token_expires_at, created_by\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
         ON CONFLICT (deployment_id, customer_id, provider, external_tenant_id_hash) \
         DO UPDATE SET display_name = EXCLUDED.display_name, \
             credential_reference_hash = EXCLUDED.credential_reference_hash, \
             status = EXCLUDED.status, auth_state = EXCLUDED.auth_state, \
             token_expires_at = EXCLUDED.token_expires_at, updated_at = now() \
         RETURNING id, updated_at",
    )
    .bind(&state.deployment_id.0)
    .bind(&context.customer_id.0)
    .bind(request.provider.as_str())
    .bind(&request.display_name)
    .bind(&request.external_tenant_id_hash)
    .bind(&request.credential_reference_hash)
    .bind(request.status.as_str())
    .bind(request.auth_state.as_str())
    .bind(request.token_expires_at)
    .bind(&context.actor.login)
    .fetch_one(&mut *transaction)
    .await
    {
        Ok(row) => row,
        Err(_) => return unavailable(),
    };
    let connector_id: Uuid = row.get("id");
    if upsert_capabilities(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
        connector_id,
        &context.actor.login,
        &request.capabilities,
    )
    .await
    .is_err()
    {
        return unavailable();
    }
    if write_audit(
        &mut transaction,
        AuditWrite {
            deployment_id: &state.deployment_id.0,
            context: &context,
            headers: &headers,
            action: AUDIT_CONNECTOR_UPSERTED,
            resource_type: "connector_integration",
            resource_id: Some(connector_id.to_string()),
            details: json!({
            "provider": request.provider.as_str(),
            "display_name": request.display_name,
            "status": request.status.as_str(),
            "auth_state": request.auth_state.as_str(),
            "capabilities": request.capabilities.iter().map(|capability| json!({
                "capability": capability.capability.as_str(),
                "enabled": capability.enabled,
                "granted_scopes": &capability.granted_scopes,
            })).collect::<Vec<_>>(),
            "changed": changed,
            }),
        },
    )
    .await
    .is_err()
    {
        return unavailable();
    }
    let response = UpsertConnectorResponse {
        id: connector_id,
        provider: request.provider.as_str(),
        display_name: request.display_name,
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

async fn post_remediation(
    State(state): State<ConnectorsRemediationState>,
    context: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    payload: Result<Json<RemediationRequest>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !authorized(&state, &context, CONNECTORS_MANAGE_PERMISSION) {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    if !context.has_step_up() {
        return api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        );
    }
    if !try_consume_high_risk(&state.mutation_limiter) {
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
    let request = match validate_remediation(body) {
        Ok(request) => request,
        Err(()) => return invalid_request(),
    };
    let operation = format!(
        "connectors-remediation:remediation:{}:{}",
        request.connector_id, request.tenant_message_id
    );

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
    match claim(&mut transaction, &key, &operation).await {
        Ok(ClaimOutcome::Fresh) => {},
        Ok(ClaimOutcome::Replay(value)) => return replay_response(value),
        Ok(ClaimOutcome::InProgress) => return conflict("Request is already in progress"),
        Ok(ClaimOutcome::OperationMismatch) => return invalid_request(),
        Err(_) => return unavailable(),
    }
    let provider = match validate_connector_for_remediation(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
        &request,
    )
    .await
    {
        Ok(provider) => provider,
        Err(response) => return response,
    };
    match delivered_message_exists(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
        request.tenant_message_id,
    )
    .await
    {
        Ok(true) => {},
        // A delivered message that is not in this tenant's history is a bad
        // request; a database failure stays an outage instead of being
        // rewritten into "invalid request".
        Ok(false) => return invalid_request(),
        Err(_) => return unavailable(),
    }

    let mailbox_search_id = Uuid::new_v4();
    if sqlx::query(
        "INSERT INTO connector_mailbox_searches (\
             id, connector_id, deployment_id, customer_id, tenant_message_id, mailbox_address_hash, \
             provider_message_id_hash, purpose, state, match_confirmation, created_by\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending','not_checked',$9)",
    )
    .bind(mailbox_search_id)
    .bind(request.connector_id)
    .bind(&state.deployment_id.0)
    .bind(&context.customer_id.0)
    .bind(request.tenant_message_id)
    .bind(&request.mailbox_address_hash)
    .bind(&request.provider_message_id_hash)
    .bind(request.purpose.as_str())
    .bind(&context.actor.login)
    .execute(&mut *transaction)
    .await
    .is_err()
    {
        return unavailable();
    }
    let remediation_id = Uuid::new_v4();
    if sqlx::query(
        "INSERT INTO connector_remediation_actions (\
             id, connector_id, mailbox_search_id, deployment_id, customer_id, tenant_message_id, \
             action_type, state, idempotency_key, requested_by, reason\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9,$10)",
    )
    .bind(remediation_id)
    .bind(request.connector_id)
    .bind(mailbox_search_id)
    .bind(&state.deployment_id.0)
    .bind(&context.customer_id.0)
    .bind(request.tenant_message_id)
    .bind(request.action_type.as_str())
    .bind(&key)
    .bind(&context.actor.login)
    .bind(&request.reason)
    .execute(&mut *transaction)
    .await
    .is_err()
    {
        return unavailable();
    }
    if write_audit(
        &mut transaction,
        AuditWrite {
            deployment_id: &state.deployment_id.0,
            context: &context,
            headers: &headers,
            action: AUDIT_REMEDIATION_REQUESTED,
            resource_type: "connector_remediation_action",
            resource_id: Some(remediation_id.to_string()),
            details: json!({
            "connector_id": request.connector_id,
            "provider": provider,
            "tenant_message_id": request.tenant_message_id,
            "purpose": request.purpose.as_str(),
            "action_type": request.action_type.as_str(),
            "state": "pending",
            "provider_side_effect": "not_executed_in_control_plane",
            }),
        },
    )
    .await
    .is_err()
    {
        return unavailable();
    }
    let response = RemediationResponse {
        remediation_id,
        mailbox_search_id,
        state: "pending",
        match_confirmation: "not_checked",
        provider_side_effect: "not_executed_in_control_plane",
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

async fn load_summary(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<ConnectorsSummary, Response> {
    sqlx::query(
        "WITH caps AS ( \
             SELECT capability, count(*) FILTER (WHERE enabled)::bigint AS enabled_count \
             FROM connector_capability_grants \
             WHERE deployment_id = $1 AND customer_id = $2 \
             GROUP BY capability \
         ), rem AS ( \
             SELECT state, count(*)::bigint AS count \
             FROM connector_remediation_actions \
             WHERE deployment_id = $1 AND customer_id = $2 \
             GROUP BY state \
         ), searches AS ( \
             SELECT count(*) FILTER (WHERE state = 'failed')::bigint AS failed_searches \
             FROM connector_mailbox_searches \
             WHERE deployment_id = $1 AND customer_id = $2 \
         ) \
         SELECT \
             COALESCE((SELECT count(*) FROM connector_integrations WHERE deployment_id = $1 AND customer_id = $2 AND status = 'active'), 0)::bigint AS active_connectors, \
             COALESCE((SELECT count(*) FROM connector_integrations WHERE deployment_id = $1 AND customer_id = $2 AND status = 'degraded'), 0)::bigint AS degraded_connectors, \
             COALESCE((SELECT enabled_count FROM caps WHERE capability = 'directory_sync'), 0)::bigint AS directory_sync_enabled, \
             COALESCE((SELECT enabled_count FROM caps WHERE capability = 'mailbox_search'), 0)::bigint AS mailbox_search_enabled, \
             COALESCE((SELECT enabled_count FROM caps WHERE capability = 'retro_remediation'), 0)::bigint AS retro_remediation_enabled, \
             COALESCE((SELECT count FROM rem WHERE state = 'pending'), 0)::bigint AS pending_remediations, \
             COALESCE((SELECT count FROM rem WHERE state = 'manual_action_required'), 0)::bigint AS manual_action_required, \
             COALESCE((SELECT count FROM rem WHERE state = 'failed'), 0)::bigint \
               + COALESCE((SELECT failed_searches FROM searches), 0)::bigint AS failed_operations",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_one(&mut **transaction)
    .await
    .map(|row| ConnectorsSummary {
        active_connectors: row.get("active_connectors"),
        degraded_connectors: row.get("degraded_connectors"),
        directory_sync_enabled: row.get("directory_sync_enabled"),
        mailbox_search_enabled: row.get("mailbox_search_enabled"),
        retro_remediation_enabled: row.get("retro_remediation_enabled"),
        pending_remediations: row.get("pending_remediations"),
        manual_action_required: row.get("manual_action_required"),
        failed_operations: row.get("failed_operations"),
    })
    .map_err(|_| unavailable())
}

async fn load_connectors(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<ConnectorView>, Response> {
    sqlx::query(
        "SELECT id, provider, display_name, external_tenant_id_hash, status, auth_state, \
                token_expires_at, last_directory_sync_at, last_directory_sync_status, \
                last_mailbox_search_at, last_remediation_at, updated_at \
         FROM connector_integrations \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY updated_at DESC \
         LIMIT 50",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| ConnectorView {
                id: row.get("id"),
                provider: row.get("provider"),
                display_name: row.get("display_name"),
                external_tenant_id_hash: row.get("external_tenant_id_hash"),
                status: row.get("status"),
                auth_state: row.get("auth_state"),
                token_expires_at: row.get("token_expires_at"),
                last_directory_sync_at: row.get("last_directory_sync_at"),
                last_directory_sync_status: row.get("last_directory_sync_status"),
                last_mailbox_search_at: row.get("last_mailbox_search_at"),
                last_remediation_at: row.get("last_remediation_at"),
                updated_at: row.get("updated_at"),
                capabilities: Vec::new(),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_capabilities(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<(Uuid, CapabilityView)>, Response> {
    sqlx::query(
        "SELECT connector_id, capability, enabled, granted_scopes, reason, updated_at \
         FROM connector_capability_grants \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY capability",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                (
                    row.get("connector_id"),
                    CapabilityView {
                        capability: row.get("capability"),
                        enabled: row.get("enabled"),
                        granted_scopes: row.get("granted_scopes"),
                        reason: row.get("reason"),
                        updated_at: row.get("updated_at"),
                    },
                )
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_directory_sync_runs(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<DirectorySyncRunView>, Response> {
    sqlx::query(
        "SELECT run.id, run.connector_id, connector.provider, connector.display_name, \
                run.state, run.started_at, run.completed_at, run.users_seen, run.groups_seen, \
                run.aliases_seen, run.vip_candidates, run.error_code, run.error_summary \
         FROM connector_directory_sync_runs run \
         JOIN connector_integrations connector ON connector.id = run.connector_id \
         WHERE run.deployment_id = $1 AND run.customer_id = $2 \
         ORDER BY run.started_at DESC LIMIT 25",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| DirectorySyncRunView {
                id: row.get("id"),
                connector_id: row.get("connector_id"),
                provider: row.get("provider"),
                display_name: row.get("display_name"),
                state: row.get("state"),
                started_at: row.get("started_at"),
                completed_at: row.get("completed_at"),
                users_seen: row.get("users_seen"),
                groups_seen: row.get("groups_seen"),
                aliases_seen: row.get("aliases_seen"),
                vip_candidates: row.get("vip_candidates"),
                error_code: row.get("error_code"),
                error_summary: row.get("error_summary"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_mailbox_searches(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<MailboxSearchView>, Response> {
    sqlx::query(
        "SELECT search.id, search.connector_id, connector.provider, search.purpose, \
                search.state, search.match_confirmation, search.mailbox_address_hash, \
                search.provider_message_id_hash, search.created_at, search.error_code, search.error_summary \
         FROM connector_mailbox_searches search \
         JOIN connector_integrations connector ON connector.id = search.connector_id \
         WHERE search.deployment_id = $1 AND search.customer_id = $2 \
         ORDER BY search.created_at DESC LIMIT 25",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| MailboxSearchView {
                id: row.get("id"),
                connector_id: row.get("connector_id"),
                provider: row.get("provider"),
                purpose: row.get("purpose"),
                state: row.get("state"),
                match_confirmation: row.get("match_confirmation"),
                mailbox_address_hash: row.get("mailbox_address_hash"),
                provider_message_id_hash: row.get("provider_message_id_hash"),
                created_at: row.get("created_at"),
                error_code: row.get("error_code"),
                error_summary: row.get("error_summary"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_remediations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<RemediationActionView>, Response> {
    sqlx::query(
        "SELECT action.id, action.connector_id, connector.provider, action.action_type, \
                action.state, action.provider_outcome_code, action.error_summary, action.reason, \
                action.created_at, action.updated_at \
         FROM connector_remediation_actions action \
         JOIN connector_integrations connector ON connector.id = action.connector_id \
         WHERE action.deployment_id = $1 AND action.customer_id = $2 \
         ORDER BY action.created_at DESC LIMIT 25",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| RemediationActionView {
                id: row.get("id"),
                connector_id: row.get("connector_id"),
                provider: row.get("provider"),
                action_type: row.get("action_type"),
                state: row.get("state"),
                provider_outcome_code: row.get("provider_outcome_code"),
                error_summary: row.get("error_summary"),
                reason: row.get("reason"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_audit_history(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<ConnectorAuditView>, Response> {
    sqlx::query(
        "SELECT id, action, actor_login, resource_id, result, created_at \
         FROM audit_events \
         WHERE deployment_id = $1 AND customer_id = $2 \
           AND resource_type IN ('connector_integration', 'connector_remediation_action') \
         ORDER BY created_at DESC LIMIT 15",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| ConnectorAuditView {
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

async fn connector_changed(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    request: &ValidatedConnector,
) -> Result<bool, Response> {
    let row = sqlx::query(
        "SELECT display_name, credential_reference_hash, status, auth_state, token_expires_at \
         FROM connector_integrations \
         WHERE deployment_id = $1 AND customer_id = $2 AND provider = $3 AND external_tenant_id_hash = $4",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(request.provider.as_str())
    .bind(&request.external_tenant_id_hash)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| unavailable())?;
    Ok(row.as_ref().is_none_or(|row| {
        row.get::<String, _>("display_name") != request.display_name
            || row.get::<String, _>("credential_reference_hash")
                != request.credential_reference_hash
            || row.get::<String, _>("status") != request.status.as_str()
            || row.get::<String, _>("auth_state") != request.auth_state.as_str()
            || row.get::<Option<DateTime<Utc>>, _>("token_expires_at") != request.token_expires_at
    }))
}

async fn upsert_capabilities(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    connector_id: Uuid,
    actor_login: &str,
    capabilities: &[ValidatedCapability],
) -> Result<(), ()> {
    for capability in capabilities {
        sqlx::query(
            "INSERT INTO connector_capability_grants (\
                 connector_id, deployment_id, customer_id, capability, enabled, granted_scopes, approved_by, reason\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
             ON CONFLICT (connector_id, capability) \
             DO UPDATE SET enabled = EXCLUDED.enabled, granted_scopes = EXCLUDED.granted_scopes, \
                 approved_by = EXCLUDED.approved_by, reason = EXCLUDED.reason, updated_at = now()",
        )
        .bind(connector_id)
        .bind(deployment_id)
        .bind(customer_id)
        .bind(capability.capability.as_str())
        .bind(capability.enabled)
        .bind(&capability.granted_scopes)
        .bind(actor_login)
        .bind(&capability.reason)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ())?;
    }
    Ok(())
}

async fn validate_connector_for_remediation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    request: &ValidatedRemediation,
) -> Result<String, Response> {
    let row = sqlx::query(
        "SELECT connector.provider, connector.status, \
                COALESCE(bool_or(cap.capability = 'mailbox_search' AND cap.enabled), false) AS mailbox_search, \
                COALESCE(bool_or(cap.capability = 'retro_remediation' AND cap.enabled), false) AS retro_remediation \
         FROM connector_integrations connector \
         LEFT JOIN connector_capability_grants cap ON cap.connector_id = connector.id \
         WHERE connector.id = $1 AND connector.deployment_id = $2 AND connector.customer_id = $3 \
         GROUP BY connector.provider, connector.status",
    )
    .bind(request.connector_id)
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| unavailable())?;
    let Some(row) = row else {
        return Err(invalid_request());
    };
    if row.get::<String, _>("status") != "active"
        || !row.get::<bool, _>("mailbox_search")
        || (request.action_type != RemediationActionType::ManualReview
            && !row.get::<bool, _>("retro_remediation"))
    {
        return Err(invalid_request());
    }
    Ok(row.get("provider"))
}

async fn delivered_message_exists(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
    tenant_message_id: Uuid,
) -> Result<bool, ()> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
             SELECT 1 \
             FROM tenant_message_instances message \
             JOIN smtp_transactions tx ON tx.id = message.transaction_id \
             WHERE message.id = $1 AND message.customer_id = $2 \
               AND tx.deployment_id = $3 AND message.disposition = 'allow' \
         )",
    )
    .bind(tenant_message_id)
    .bind(customer_id)
    .bind(deployment_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ())
}

struct AuditWrite<'a> {
    deployment_id: &'a str,
    context: &'a TenantContext,
    headers: &'a HeaderMap,
    action: &'a str,
    resource_type: &'a str,
    resource_id: Option<String>,
    details: Value,
}

async fn write_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    audit: AuditWrite<'_>,
) -> Result<(), ()> {
    let context = audit.context;
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
        action: audit.action.to_string(),
        resource_type: audit.resource_type.to_string(),
        resource_id: audit.resource_id,
        result: "success".to_string(),
        source_ip: source_ip_from(audit.headers),
        session_id: Some(context.session_id.clone()),
        trace_id: context.trace_id.clone(),
        details: audit.details,
    };
    PostgresAuditStore::insert_record(transaction, audit.deployment_id, &record)
        .await
        .map(|_| ())
        .map_err(|_| ())
}

fn validate_connector(request: UpsertConnectorRequest) -> Result<ValidatedConnector, ()> {
    let display_name = request.display_name.trim().to_string();
    let external_tenant_id_hash = request.external_tenant_id_hash.trim().to_string();
    let credential_reference_hash = request.credential_reference_hash.trim().to_string();
    // Lengths are counted in characters, not bytes, so the application check
    // matches the `char_length` CHECK constraints in migration 031 and a
    // multi-byte value is rejected as 400 instead of surfacing as a database
    // error (503) after the claim.
    let display_name_chars = display_name.chars().count();
    if !(3..=160).contains(&display_name_chars)
        || !safe_hash(&external_tenant_id_hash)
        || !safe_hash(&credential_reference_hash)
        || request.capabilities.is_empty()
        || request.capabilities.len() > 3
    {
        return Err(());
    }
    if request.provider == ConnectorProvider::ImapPop
        && (request.status == ConnectorStatus::Active
            || request
                .capabilities
                .iter()
                .any(|capability| capability.enabled))
    {
        return Err(());
    }
    let mut seen = Vec::new();
    let mut capabilities = Vec::new();
    for capability in request.capabilities {
        if seen.contains(&capability.capability) {
            return Err(());
        }
        seen.push(capability.capability);
        let reason = capability.reason.trim().to_string();
        let reason_chars = reason.chars().count();
        let scopes = capability
            .granted_scopes
            .into_iter()
            .map(|scope| scope.trim().to_string())
            .collect::<Vec<_>>();
        if !(12..=512).contains(&reason_chars)
            || scopes.len() > 8
            || (capability.enabled && scopes.is_empty())
            || scopes.iter().any(|scope| {
                scope.is_empty()
                    || scope.len() > 160
                    || !scope_allowed(request.provider, capability.capability, scope)
            })
        {
            return Err(());
        }
        capabilities.push(ValidatedCapability {
            capability: capability.capability,
            enabled: capability.enabled,
            granted_scopes: scopes,
            reason,
        });
    }
    Ok(ValidatedConnector {
        provider: request.provider,
        display_name,
        external_tenant_id_hash,
        credential_reference_hash,
        status: request.status,
        auth_state: request.auth_state,
        token_expires_at: request.token_expires_at,
        capabilities,
    })
}

fn validate_remediation(request: RemediationRequest) -> Result<ValidatedRemediation, ()> {
    let mailbox_address_hash = request.mailbox_address_hash.trim().to_string();
    let provider_message_id_hash = request
        .provider_message_id_hash
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let reason = request.reason.trim().to_string();
    let reason_chars = reason.chars().count();
    if !safe_hash(&mailbox_address_hash)
        || provider_message_id_hash
            .as_ref()
            .is_some_and(|value| !safe_hash(value))
        || !(12..=512).contains(&reason_chars)
    {
        return Err(());
    }
    Ok(ValidatedRemediation {
        connector_id: request.connector_id,
        tenant_message_id: request.tenant_message_id,
        mailbox_address_hash,
        provider_message_id_hash,
        purpose: request.purpose,
        action_type: request.action_type,
        reason,
    })
}

fn safe_hash(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '-'))
}

fn scope_allowed(
    provider: ConnectorProvider,
    capability: ConnectorCapability,
    scope: &str,
) -> bool {
    match (provider, capability) {
        (ConnectorProvider::Microsoft365, ConnectorCapability::DirectorySync) => {
            matches!(
                scope,
                "User.Read.All" | "Group.Read.All" | "Directory.Read.All"
            )
        },
        (ConnectorProvider::Microsoft365, ConnectorCapability::MailboxSearch) => {
            matches!(scope, "Mail.ReadBasic.All" | "Mail.Read")
        },
        (ConnectorProvider::Microsoft365, ConnectorCapability::RetroRemediation) => {
            matches!(scope, "Mail.ReadWrite")
        },
        (ConnectorProvider::GoogleWorkspace, ConnectorCapability::DirectorySync) => matches!(
            scope,
            "https://www.googleapis.com/auth/admin.directory.user.readonly"
                | "https://www.googleapis.com/auth/admin.directory.group.readonly"
        ),
        (ConnectorProvider::GoogleWorkspace, ConnectorCapability::MailboxSearch) => matches!(
            scope,
            "https://www.googleapis.com/auth/gmail.readonly"
                | "https://www.googleapis.com/auth/gmail.metadata"
        ),
        (ConnectorProvider::GoogleWorkspace, ConnectorCapability::RetroRemediation) => {
            matches!(scope, "https://www.googleapis.com/auth/gmail.modify")
        },
        (ConnectorProvider::ImapPop, _) => false,
    }
}

fn authorized(
    state: &ConnectorsRemediationState,
    context: &TenantContext,
    permission: &str,
) -> bool {
    context.customer_lifecycle == CustomerLifecycle::Active
        && context.deployment_id == state.deployment_id
        && context
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

fn require_idempotency_key(headers: &HeaderMap) -> Result<String, IdempotencyRejection> {
    let Some(raw) = headers.get(IDEMPOTENCY_HEADER) else {
        return Err(IdempotencyRejection::Missing);
    };
    let Ok(value) = raw.to_str() else {
        return Err(IdempotencyRejection::Invalid);
    };
    // The remediation ledger persists this key under a
    // `char_length BETWEEN 8 AND 128` CHECK (migration 031), so a shorter key
    // is rejected here as 400 instead of failing the insert as 503.
    if value.len() < 8 || value.len() > 128 {
        return Err(IdempotencyRejection::Invalid);
    }
    Ok(value.to_string())
}

fn envelope<T: Serialize>(data: &T) -> Option<Value> {
    serde_json::to_value(ApiEnvelope { data }).ok()
}

fn replay_response(value: Value) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

fn idempotency_rejection_response(rejection: IdempotencyRejection) -> Response {
    match rejection {
        IdempotencyRejection::Missing => api_error(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_REQUIRED",
            "Idempotency key is required",
        ),
        IdempotencyRejection::Invalid => invalid_request(),
    }
}

fn conflict(message: &'static str) -> Response {
    api_error(StatusCode::CONFLICT, "CONFLICT", message)
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

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderValue, Request, StatusCode};
    use nullapart_mail_contracts::{ActorId, CustomerId};
    use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId};
    use tower::ServiceExt;

    use super::*;

    fn state() -> ConnectorsRemediationState {
        ConnectorsRemediationState::new(
            PgPool::connect_lazy("postgres://nullapart:test@127.0.0.1/nullapart")
                .expect("lazy pool"),
            DeploymentId::new("LOCAL-TEST"),
        )
    }

    fn context(assurance: AuthenticationAssurance, permissions: Vec<String>) -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            region: RegionId::new("local"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "operator@example.test".to_string(),
                roles: vec!["operator".to_string()],
                authentication_assurance: assurance,
            },
            impersonation: None,
            customer_id: CustomerId::new("CZA-1"),
            customer_internal_key: 1,
            customer_display_name: "Customer test".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions,
            config_revision: 1,
            trace_id: "connectors-remediation-test".to_string(),
            correlation_id: "connectors-remediation-test".to_string(),
            session_id: "connectors-remediation-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn manage_context(assurance: AuthenticationAssurance) -> TenantContext {
        context(assurance, vec![CONNECTORS_MANAGE_PERMISSION.to_string()])
    }

    fn mutation_request(uri: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(IDEMPOTENCY_HEADER, "phase8-rate-limit-key")
            .body(Body::empty())
            .expect("request")
    }

    #[tokio::test]
    async fn unauthenticated_projection_is_401() {
        let app = connectors_remediation_router(state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/connectors-remediation")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn microsoft_365_provider_uses_canonical_api_spelling() {
        let provider: ConnectorProvider =
            serde_json::from_str("\"microsoft_365\"").expect("canonical provider spelling");

        assert_eq!(provider, ConnectorProvider::Microsoft365);
        assert_eq!(
            serde_json::to_string(&provider).expect("provider serializes"),
            "\"microsoft_365\""
        );
    }

    #[test]
    fn connector_validation_rejects_overscoped_directory_only_grant() {
        let request = UpsertConnectorRequest {
            provider: ConnectorProvider::Microsoft365,
            display_name: "Microsoft 365".to_string(),
            external_tenant_id_hash: "tenant_hash_123456".to_string(),
            credential_reference_hash: "credential_hash_123456".to_string(),
            status: ConnectorStatus::Active,
            auth_state: AuthState::Healthy,
            token_expires_at: None,
            capabilities: vec![CapabilityRequest {
                capability: ConnectorCapability::DirectorySync,
                enabled: true,
                granted_scopes: vec!["Mail.ReadWrite".to_string()],
                reason: "Directory sync should never request mailbox write scope.".to_string(),
            }],
        };
        assert!(validate_connector(request).is_err());
    }

    #[test]
    fn connector_validation_accepts_independent_capabilities_without_tokens() {
        let request = UpsertConnectorRequest {
            provider: ConnectorProvider::GoogleWorkspace,
            display_name: "Google Workspace".to_string(),
            external_tenant_id_hash: "tenant_hash_abcdef".to_string(),
            credential_reference_hash: "credential_hash_abcdef".to_string(),
            status: ConnectorStatus::Active,
            auth_state: AuthState::Healthy,
            token_expires_at: None,
            capabilities: vec![
                CapabilityRequest {
                    capability: ConnectorCapability::DirectorySync,
                    enabled: true,
                    granted_scopes: vec![
                        "https://www.googleapis.com/auth/admin.directory.user.readonly".to_string(),
                    ],
                    reason: "Directory address validation for this tenant.".to_string(),
                },
                CapabilityRequest {
                    capability: ConnectorCapability::MailboxSearch,
                    enabled: false,
                    granted_scopes: vec![],
                    reason: "Mailbox search is not granted for this tenant.".to_string(),
                },
            ],
        };
        let validated = validate_connector(request).expect("connector should validate");
        assert_eq!(validated.provider, ConnectorProvider::GoogleWorkspace);
        assert_eq!(validated.capabilities.len(), 2);
    }

    #[test]
    fn remediation_validation_requires_hashed_mailbox_and_reason() {
        assert!(validate_remediation(RemediationRequest {
            connector_id: Uuid::new_v4(),
            tenant_message_id: Uuid::new_v4(),
            mailbox_address_hash: "too-short".to_string(),
            provider_message_id_hash: None,
            purpose: SearchPurpose::PostDeliveryThreat,
            action_type: RemediationActionType::MoveToQuarantine,
            reason: "short".to_string(),
        })
        .is_err());
    }

    #[test]
    fn validation_rejects_values_that_would_break_db_char_length_checks() {
        // Two characters / four bytes: the byte-length check used to pass while
        // migration 031's `char_length` CHECK rejected the insert as a 503.
        let connector = UpsertConnectorRequest {
            provider: ConnectorProvider::Microsoft365,
            display_name: "éé".to_string(),
            external_tenant_id_hash: "tenant_hash_123456".to_string(),
            credential_reference_hash: "credential_hash_123456".to_string(),
            status: ConnectorStatus::Active,
            auth_state: AuthState::Healthy,
            token_expires_at: None,
            capabilities: vec![CapabilityRequest {
                capability: ConnectorCapability::DirectorySync,
                enabled: true,
                granted_scopes: vec!["User.Read.All".to_string()],
                reason: "Directory sync should never request mailbox write scope.".to_string(),
            }],
        };
        assert!(validate_connector(connector).is_err());

        // Eight characters / twenty-four bytes: shorter than the 12-character
        // remediation reason floor.
        assert!(validate_remediation(RemediationRequest {
            connector_id: Uuid::new_v4(),
            tenant_message_id: Uuid::new_v4(),
            mailbox_address_hash: "mailbox_hash_123456".to_string(),
            provider_message_id_hash: None,
            purpose: SearchPurpose::PostDeliveryThreat,
            action_type: RemediationActionType::MoveToQuarantine,
            reason: "安全原因说明文本".to_string(),
        })
        .is_err());
    }

    #[test]
    fn idempotency_key_must_fit_the_remediation_ledger_check() {
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_HEADER, HeaderValue::from_static("short"));
        assert!(matches!(
            require_idempotency_key(&headers),
            Err(IdempotencyRejection::Invalid)
        ));

        headers.insert(
            IDEMPOTENCY_HEADER,
            HeaderValue::from_static("phase8-key-0001"),
        );
        assert_eq!(
            require_idempotency_key(&headers).expect("valid key"),
            "phase8-key-0001"
        );
    }

    #[tokio::test]
    async fn mutations_are_unauthenticated_before_any_other_gate() {
        let app = connectors_remediation_router(state());
        for uri in [CONNECTOR_UPSERT_PATH, REMEDIATION_PATH] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn connector_mutation_requires_step_up_before_budget_or_idempotency() {
        let app = connectors_remediation_router(state())
            .layer(Extension(manage_context(AuthenticationAssurance::Standard)));
        let response = app
            .oneshot(mutation_request(CONNECTOR_UPSERT_PATH))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), 4_096).await.expect("body");
        assert!(
            String::from_utf8_lossy(&body).contains("STEP_UP_REQUIRED"),
            "step-up failure must surface the dedicated code the UI re-auth prompt keys on"
        );
    }

    #[tokio::test]
    async fn connector_mutations_share_one_fail_closed_budget() {
        let app = connectors_remediation_router(state())
            .layer(Extension(manage_context(AuthenticationAssurance::StepUp)));
        let budget = HighRiskLimits::permission_change().max_tokens;
        let mut denied: Option<Response> = None;
        for _ in 0..budget + 5 {
            let response = app
                .clone()
                .oneshot(mutation_request(CONNECTOR_UPSERT_PATH))
                .await
                .expect("response");
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                denied = Some(response);
                break;
            }
        }
        let denied = denied.expect("the shared high-risk budget must deny with 429");
        assert_eq!(
            denied
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .map(|value| value.to_str().expect("retry-after")),
            Some("60"),
            "429 responses must carry Retry-After"
        );
        let remediation = app
            .clone()
            .oneshot(mutation_request(REMEDIATION_PATH))
            .await
            .expect("response");
        assert_eq!(
            remediation.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "remediation requests must consume the same exhausted budget"
        );
    }

    #[tokio::test]
    async fn mutation_budget_exhausts_then_fails_closed() {
        let state = state();
        let budget = HighRiskLimits::permission_change().max_tokens;
        for _ in 0..budget {
            assert!(try_consume_high_risk(&state.mutation_limiter));
        }
        assert!(!try_consume_high_risk(&state.mutation_limiter));
    }

    #[test]
    fn mutation_budget_fails_closed_when_the_lock_is_poisoned() {
        let limiter = Mutex::new(TokenBucket::new(&HighRiskLimits::permission_change()));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = limiter.lock().expect("lock");
            panic!("poison the limiter lock");
        }));
        assert!(
            !try_consume_high_risk(&limiter),
            "a poisoned limiter lock must fail closed instead of bypassing the budget"
        );
    }
}

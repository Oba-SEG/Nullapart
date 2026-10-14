//! Mail trace search, transaction detail and full-message content.
//!
//! Two surfaces share this module. The workload surface
//! (`POST /api/v1/trace/search`, `GET /api/v1/trace/transaction/:id`,
//! `GET /api/v1/trace/health`) answers bearer-authenticated mail-node callers
//! and reports only what `smtp_transactions`,
//! `smtp_transaction_recipients` and the running process can prove.
//!
//! The session surface (`/api/v1/mail-trace/*`) is merged into the
//! authenticated local plane, so every request carries a server-side
//! `TenantContext`; its customer scope comes from that session and every
//! tenant-scoped statement both sets the row-level-security GUCs and filters
//! `customer_id` directly. Reading a transaction's message content additionally
//! requires `trace:content`, a dedicated fail-closed per-actor budget, an
//! artifact row that is visible to the caller's customer, and a short-lived
//! `ContentReview` artifact grant; every content access audits
//! `trace_content_accessed` as success, denied or failed and never records
//! message bytes.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::Instant,
};

use axum::{
    body::Body,
    extract::{rejection::JsonRejection, Extension, Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use mailparse::{DispositionType, MailHeaderMap};
#[cfg(test)]
use nullapart_mail_contracts::ActorId;
use nullapart_mail_contracts::{
    artifact::ArtifactId,
    rate_limit::{ExceededAction, RateLimitConfig, TokenBucket},
    transaction::DeploymentId,
};
#[cfg(test)]
use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId};
use nullapart_policy::{CustomerLifecycle, TenantContext};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use subtle::ConstantTimeEq;
use tracing::error;
use uuid::Uuid;

use crate::admin_audit::{source_ip_from, AuditEventRecord, AuditStore, PostgresAuditStore};
use crate::admin_rbac::{TRACE_CONTENT_PERMISSION, TRACE_VIEW_PERMISSION};
#[cfg(test)]
use crate::artifact_store::FilesystemArtifactRuntime;
use crate::artifact_store::{
    ArtifactAccessGrant, ArtifactAccessPurpose, ArtifactPermissions, ArtifactScope,
    ArtifactStoreError, FilesystemArtifactStore,
};

const SEARCH_MIN_QUERY_CHARS: usize = 3;
const SEARCH_DEFAULT_LIMIT: i32 = 20;
const SEARCH_MIN_LIMIT: i32 = 1;
const SEARCH_MAX_LIMIT: i32 = 50;
const TRANSACTION_ID_MAX_LEN: usize = 128;
const CONTENT_GRANT_TTL_SECONDS: i64 = 300;
const CONTENT_READ_MAX_TOKENS: u64 = 60;
const CONTENT_READ_REFILL_PER_SEC: f64 = 1.0 / 60.0;
const MAX_TRACKED_CONTENT_ACTORS: usize = 1024;
const CONTENT_RETRY_AFTER_SECONDS: &str = "60";

const MAX_PLAIN_TEXT_CHARS: usize = 512_000;
const MAX_HTML_CHARS: usize = 1_000_000;
const MAX_HEADER_ENTRIES: usize = 100;
const MAX_HEADER_VALUE_CHARS: usize = 8192;
const MAX_ATTACHMENT_ENTRIES: usize = 50;

const ACTION_TRACE_CONTENT: &str = "trace_content_accessed";
const RESOURCE_TRANSACTION: &str = "transaction";

const WORKLOAD_SEARCH_SQL: &str =
    "SELECT t.id AS transaction_id, t.direction, t.envelope_sender, t.message_id, \
     t.received_at, (SELECT count(*) FROM smtp_transaction_recipients AS r \
     WHERE r.transaction_id = t.id)::bigint AS recipient_count \
     FROM smtp_transactions AS t WHERE t.deployment_id = $1 \
     AND (t.id::text = $2 OR t.trace_id ILIKE $2 OR t.message_id ILIKE $2 \
     OR t.envelope_sender ILIKE $2 OR EXISTS (SELECT 1 \
     FROM smtp_transaction_recipients AS r WHERE r.transaction_id = t.id \
     AND r.address ILIKE $2)) ORDER BY t.received_at DESC, t.id LIMIT $3";
const WORKLOAD_SEARCH_COUNT_SQL: &str =
    "SELECT count(*)::bigint FROM smtp_transactions AS t WHERE t.deployment_id = $1 \
     AND (t.id::text = $2 OR t.trace_id ILIKE $2 OR t.message_id ILIKE $2 \
     OR t.envelope_sender ILIKE $2 OR EXISTS (SELECT 1 \
     FROM smtp_transaction_recipients AS r WHERE r.transaction_id = t.id \
     AND r.address ILIKE $2))";
const SESSION_SEARCH_SQL: &str =
    "SELECT t.id AS transaction_id, t.direction, t.envelope_sender, t.message_id, \
     t.received_at FROM smtp_transactions AS t WHERE t.deployment_id = $1 \
     AND EXISTS (SELECT 1 FROM tenant_message_instances AS i \
     WHERE i.transaction_id = t.id AND i.customer_id = $2) \
     AND (t.id::text = $3 OR t.trace_id ILIKE $3 OR t.message_id ILIKE $3 \
     OR t.envelope_sender ILIKE $3 OR EXISTS (SELECT 1 \
     FROM tenant_message_recipients AS r \
     JOIN tenant_message_instances AS ri ON ri.id = r.tenant_message_id \
     WHERE ri.transaction_id = t.id AND ri.customer_id = $2 \
     AND r.address ILIKE $3)) ORDER BY t.received_at DESC, t.id LIMIT $4";
const SESSION_SEARCH_COUNT_SQL: &str =
    "SELECT count(*)::bigint FROM smtp_transactions AS t WHERE t.deployment_id = $1 \
     AND EXISTS (SELECT 1 FROM tenant_message_instances AS i \
     WHERE i.transaction_id = t.id AND i.customer_id = $2) \
     AND (t.id::text = $3 OR t.trace_id ILIKE $3 OR t.message_id ILIKE $3 \
     OR t.envelope_sender ILIKE $3 OR EXISTS (SELECT 1 \
     FROM tenant_message_recipients AS r \
     JOIN tenant_message_instances AS ri ON ri.id = r.tenant_message_id \
     WHERE ri.transaction_id = t.id AND ri.customer_id = $2 \
     AND r.address ILIKE $3))";
const SESSION_SEARCH_RECIPIENTS_SQL: &str =
    "SELECT i.transaction_id, r.address FROM tenant_message_recipients AS r \
     JOIN tenant_message_instances AS i ON i.id = r.tenant_message_id \
     WHERE i.transaction_id = ANY($1) AND i.customer_id = $2 \
     ORDER BY i.transaction_id, r.id";
const SESSION_RECIPIENTS_SQL: &str =
    "SELECT r.address, r.orcpt, r.notify FROM tenant_message_recipients AS r \
     JOIN tenant_message_instances AS i ON i.id = r.tenant_message_id \
     WHERE i.transaction_id = $1 AND i.customer_id = $2 ORDER BY r.id";
const SEARCH_INSTANCES_SQL: &str = "SELECT transaction_id, id AS tenant_message_id, disposition \
     FROM tenant_message_instances WHERE transaction_id = ANY($1) \
     AND customer_id = $2 ORDER BY transaction_id, created_at, id";
const TRANSACTION_SQL: &str =
    "SELECT t.id AS transaction_id, t.trace_id, t.direction, t.deployment_id, \
     t.envelope_sender, t.message_id, t.content_hash, t.received_at \
     FROM smtp_transactions AS t WHERE t.id = $1 AND t.deployment_id = $2";
const SESSION_TRANSACTION_SQL: &str =
    "SELECT t.id AS transaction_id, t.trace_id, t.direction, t.deployment_id, \
     t.envelope_sender, t.message_id, t.content_hash, t.received_at, t.mime_artifact_id, \
     t.spf_result, t.dkim_result, t.dmarc_result, t.arc_result, t.postfix_queue_ids \
     FROM smtp_transactions AS t WHERE t.id = $1 AND t.deployment_id = $2";
const TRANSACTION_RECIPIENTS_SQL: &str =
    "SELECT address, orcpt, notify FROM smtp_transaction_recipients \
     WHERE transaction_id = $1 ORDER BY id";
const OWNED_INSTANCE_COUNT_SQL: &str =
    "SELECT count(*)::bigint FROM tenant_message_instances AS i \
     WHERE i.transaction_id = $1 AND i.customer_id = $2";
const SESSION_INSTANCES_SQL: &str =
    "SELECT i.id AS tenant_message_id, i.disposition, i.remediation_type, \
     i.created_at, i.updated_at FROM tenant_message_instances AS i \
     WHERE i.transaction_id = $1 AND i.customer_id = $2 ORDER BY i.created_at, i.id";
const SESSION_ATTEMPTS_SQL: &str =
    "SELECT a.attempt_number, a.status, a.smtp_code, a.enhanced_code, a.smtp_message, \
     a.scheduled_at, a.completed_at, a.next_retry_at, a.postfix_queue_id \
     FROM delivery_attempts AS a JOIN tenant_message_instances AS i \
     ON i.id = a.tenant_message_id WHERE i.transaction_id = $1 AND i.customer_id = $2 \
     ORDER BY a.scheduled_at, a.attempt_number";
const SESSION_FINDINGS_SQL: &str =
    "SELECT f.id, f.severity, f.category, f.description, f.scanner_type, \
     f.false_positive, f.created_at FROM security_findings AS f \
     WHERE f.transaction_id = $1 AND f.customer_id = $2 ORDER BY f.created_at, f.id";
const ARTIFACT_SQL: &str =
    "SELECT id FROM artifacts AS a WHERE a.id = $1 AND a.deployment_id = $2 \
     AND a.customer_id = $3";

static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Trace workload API configuration.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub deployment_id: DeploymentId,
    pub node_id: String,
    pub node_version: String,
    pub config_revision: Option<String>,
    /// SHA-256 digest of the per-deployment workload bearer token.
    /// Missing configuration fails closed for all non-health endpoints.
    pub workload_token_sha256: Option<[u8; 32]>,
    /// Read connection pool for the workload trace projection.
    pub pool: PgPool,
}

impl TraceConfig {
    pub fn set_workload_token(&mut self, token: &str) {
        self.workload_token_sha256 = Some(Sha256::digest(token.as_bytes()).into());
    }
}

#[derive(Clone)]
pub struct MailTraceState(Arc<MailTraceStateInner>);

struct MailTraceStateInner {
    pool: PgPool,
    deployment_id: DeploymentId,
    artifact_store: FilesystemArtifactStore,
    audit: Arc<dyn AuditStore>,
    content_limiters: Mutex<HashMap<String, TokenBucket>>,
}

impl MailTraceState {
    pub fn new(
        pool: PgPool,
        deployment_id: DeploymentId,
        artifact_store: FilesystemArtifactStore,
    ) -> Self {
        let audit = Arc::new(PostgresAuditStore::new(pool.clone()));
        Self::with_audit(pool, deployment_id, artifact_store, audit)
    }

    fn with_audit(
        pool: PgPool,
        deployment_id: DeploymentId,
        artifact_store: FilesystemArtifactStore,
        audit: Arc<dyn AuditStore>,
    ) -> Self {
        Self(Arc::new(MailTraceStateInner {
            pool,
            deployment_id,
            artifact_store,
            audit,
            content_limiters: Mutex::new(HashMap::new()),
        }))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSearchRequest {
    /// Free-text match over transaction id, trace id, message id, envelope
    /// sender and recipient address.
    pub q: String,
    /// Result page size; clamped to `1..=50`, defaulting to 20.
    pub limit: Option<i32>,
}

#[derive(Debug)]
struct ValidatedSearch {
    pattern: String,
    limit: i64,
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
struct WorkloadSearchResults {
    results: Vec<WorkloadSearchResult>,
    total_count: i64,
    has_more: bool,
}

#[derive(Serialize)]
struct WorkloadSearchResult {
    transaction_id: String,
    direction: String,
    envelope_sender: String,
    message_id: Option<String>,
    received_at: DateTime<Utc>,
    recipient_count: i64,
}

#[derive(Serialize)]
struct MailTraceSearchResults {
    results: Vec<MailTraceSearchResult>,
    total_count: i64,
    has_more: bool,
}

#[derive(Serialize)]
struct MailTraceSearchResult {
    transaction_id: String,
    direction: String,
    envelope_sender: String,
    message_id: Option<String>,
    received_at: DateTime<Utc>,
    recipients: Vec<String>,
    instances: Vec<MailTraceSearchInstance>,
}

#[derive(Serialize)]
struct MailTraceSearchInstance {
    tenant_message_id: String,
    disposition: String,
}

#[derive(Debug, Serialize)]
struct TraceRecipientResponse {
    address: String,
    orcpt: Option<String>,
    notify: Option<String>,
}

#[derive(Serialize)]
struct TraceAuthResults {
    spf_result: Option<Value>,
    dkim_result: Option<Value>,
    dmarc_result: Option<Value>,
    arc_result: Option<Value>,
}

#[derive(Serialize)]
struct TraceInstanceResponse {
    tenant_message_id: String,
    disposition: String,
    remediation_type: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct TraceDeliveryAttemptResponse {
    attempt_number: i32,
    status: String,
    smtp_code: Option<String>,
    enhanced_code: Option<String>,
    smtp_message: Option<String>,
    scheduled_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    next_retry_at: Option<DateTime<Utc>>,
    postfix_queue_id: Option<String>,
}

#[derive(Serialize)]
struct TraceFindingResponse {
    id: Uuid,
    severity: String,
    category: String,
    description: String,
    scanner_type: String,
    false_positive: bool,
    created_at: DateTime<Utc>,
}

impl TraceFindingResponse {
    fn project_customer_safe(
        id: Uuid,
        severity: String,
        category: String,
        description: String,
        scanner_type: String,
        false_positive: bool,
        created_at: DateTime<Utc>,
    ) -> Self {
        let description = customer_safe_finding_description(&severity, &category, &description);
        let scanner_type = customer_safe_finding_source(&scanner_type).to_string();

        Self {
            id,
            severity,
            category,
            description,
            scanner_type,
            false_positive,
            created_at,
        }
    }
}

fn customer_safe_finding_description(severity: &str, category: &str, description: &str) -> String {
    if description_contains_internal_evidence(description) {
        return generic_customer_safe_finding_description(severity, category);
    }

    description.to_string()
}

fn description_contains_internal_evidence(description: &str) -> bool {
    let normalized = description.to_lowercase();
    [
        "clamav",
        "rspamd",
        "urlanalysis",
        "static-rule",
        "static malware rule",
        "static rule",
        "inline ml",
        "inline_ml",
        "model_version",
        "model version",
        "threshold",
        "score",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn customer_safe_finding_source(scanner_type: &str) -> &'static str {
    match scanner_type {
        "attachment" => "attachment_analysis",
        "clamav" => "malware_analysis",
        "deepai" => "advanced_threat_analysis",
        "dkim" | "spf" | "dmarc" | "arc" => "authentication_analysis",
        "inline_ml" => "threat_analysis",
        "rspamd" => "spam_reputation_analysis",
        "urlanalysis" => "link_analysis",
        _ => "security_analysis",
    }
}

fn generic_customer_safe_finding_description(severity: &str, category: &str) -> String {
    format!("{severity} {category} evidence was recorded for this message.")
}

#[derive(Debug, Serialize)]
struct TraceFlowStageResponse {
    stage: &'static str,
    at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct WorkloadTransactionDetail {
    transaction_id: String,
    trace_id: Option<String>,
    direction: String,
    deployment_id: String,
    envelope_sender: String,
    message_id: Option<String>,
    content_hash: String,
    received_at: DateTime<Utc>,
    recipients: Vec<TraceRecipientResponse>,
    flow_stages: Vec<TraceFlowStageResponse>,
}

#[derive(Serialize)]
struct TransactionDetail {
    transaction_id: String,
    trace_id: Option<String>,
    direction: String,
    deployment_id: String,
    envelope_sender: String,
    message_id: Option<String>,
    content_hash: String,
    received_at: DateTime<Utc>,
    recipients: Vec<TraceRecipientResponse>,
    auth: TraceAuthResults,
    postfix_queue_ids: Vec<String>,
    instances: Vec<TraceInstanceResponse>,
    delivery_attempts: Vec<TraceDeliveryAttemptResponse>,
    findings: Vec<TraceFindingResponse>,
    flow_stages: Vec<TraceFlowStageResponse>,
}

#[derive(Serialize)]
struct MessageHeaderResponse {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct MessageAttachmentResponse {
    filename: Option<String>,
    content_type: Option<String>,
    size_bytes: Option<i64>,
}

#[derive(Serialize)]
struct MessageContentResponse {
    transaction_id: String,
    subject: Option<String>,
    from: Option<String>,
    to: Vec<String>,
    date: Option<String>,
    headers: Vec<MessageHeaderResponse>,
    plain_text: Option<String>,
    html: Option<String>,
    truncated: bool,
    attachments: Vec<MessageAttachmentResponse>,
}

#[derive(Serialize)]
struct HealthCheckResponse {
    status: String,
    node_id: String,
    version: String,
    uptime_seconds: u64,
    queue_depth: Option<i64>,
}

struct TransactionBase {
    transaction_id: Uuid,
    trace_id: Option<String>,
    direction: String,
    deployment_id: String,
    envelope_sender: String,
    message_id: Option<String>,
    content_hash: String,
    received_at: DateTime<Utc>,
}

struct SessionTransaction {
    base: TransactionBase,
    mime_artifact_id: String,
    spf_result: Option<Value>,
    dkim_result: Option<Value>,
    dmarc_result: Option<Value>,
    arc_result: Option<Value>,
    postfix_queue_ids: Vec<String>,
}

struct ContentPlan {
    owned: bool,
    artifact_id: Option<Uuid>,
    artifact_visible: bool,
    tenant_message_ids: Vec<String>,
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

    fn not_found(message: &'static str, reason: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NOT_FOUND",
            message,
            reason: reason.into(),
        }
    }

    fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "RATE_LIMITED",
            message: "Too many message content requests",
            reason: "content read budget exhausted".to_string(),
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

fn validation(message: &'static str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "VALIDATION", message)
}

fn not_found(message: &'static str) -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", message)
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        "Service is unavailable",
    )
}

fn rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, CONTENT_RETRY_AFTER_SECONDS)],
        Json(ApiErrorBody {
            code: "RATE_LIMITED",
            message: "Too many message content requests",
        }),
    )
        .into_response()
}

fn has_permission(context: &TenantContext, permission: &str) -> bool {
    context
        .permissions
        .iter()
        .any(|granted| granted == permission)
}

fn authorization_denial(
    state: &MailTraceState,
    context: &TenantContext,
    permission: &str,
) -> Option<Denial> {
    if !has_permission(context, permission) {
        return Some(Denial::missing_permission(permission));
    }
    if context.customer_lifecycle != CustomerLifecycle::Active {
        return Some(Denial::forbidden("customer lifecycle is not active"));
    }
    if context.deployment_id != state.0.deployment_id {
        return Some(Denial::forbidden("deployment mismatch"));
    }
    None
}

fn audit_record(
    context: &TenantContext,
    headers: &HeaderMap,
    result: &str,
    action: &str,
    resource_id: Option<String>,
    details: Value,
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
        customer_id: Some(context.customer_id.0.clone()),
        action: action.to_string(),
        resource_type: RESOURCE_TRANSACTION.to_string(),
        resource_id,
        result: result.to_string(),
        source_ip: source_ip_from(headers),
        session_id: Some(context.session_id.clone()),
        trace_id: context.trace_id.clone(),
        details,
    }
}

async fn record_content_audit(
    state: &MailTraceState,
    context: &TenantContext,
    headers: &HeaderMap,
    transaction_id: &str,
    result: &str,
    details: Value,
) {
    let record = audit_record(
        context,
        headers,
        result,
        ACTION_TRACE_CONTENT,
        Some(transaction_id.to_string()),
        details,
    );
    if let Err(error) = state
        .0
        .audit
        .record_event(&state.0.deployment_id.0, record)
        .await
    {
        error!(%error, "failed to audit mail trace content access");
    }
}

async fn content_denied(
    state: &MailTraceState,
    context: &TenantContext,
    headers: &HeaderMap,
    transaction_id: &str,
    denial: Denial,
) -> Response {
    record_content_audit(
        state,
        context,
        headers,
        transaction_id,
        "denied",
        json!({ "reason": denial.reason }),
    )
    .await;
    if denial.status == StatusCode::TOO_MANY_REQUESTS {
        return rate_limited();
    }
    api_error(denial.status, denial.code, denial.message)
}

async fn content_failed(
    state: &MailTraceState,
    context: &TenantContext,
    headers: &HeaderMap,
    transaction_id: &str,
    reason: &'static str,
) -> Response {
    record_content_audit(
        state,
        context,
        headers,
        transaction_id,
        "failed",
        json!({ "reason": reason }),
    )
    .await;
    unavailable()
}

fn content_read_limits() -> RateLimitConfig {
    RateLimitConfig {
        max_tokens: CONTENT_READ_MAX_TOKENS,
        refill_rate_per_sec: CONTENT_READ_REFILL_PER_SEC,
        window_secs: 60,
        burst_tolerance: 0,
        exceeded_action: ExceededAction::FailClosed,
        reason_code: "MAIL_TRACE_CONTENT_READ".to_string(),
        trust_forwarded_ip: false,
    }
}

fn take_content_token(state: &MailTraceState, actor_id: &str) -> bool {
    let Ok(mut limiters) = state.0.content_limiters.lock() else {
        return false;
    };
    if limiters.len() >= MAX_TRACKED_CONTENT_ACTORS && !limiters.contains_key(actor_id) {
        return false;
    }
    let bucket = limiters
        .entry(actor_id.to_string())
        .or_insert_with(|| TokenBucket::new(&content_read_limits()));
    bucket.try_consume()
}

fn escape_like_pattern(term: &str) -> String {
    term.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn validate_search_request(request: &TraceSearchRequest) -> Result<ValidatedSearch, Box<Response>> {
    let term = request.q.trim();
    if term.chars().count() < SEARCH_MIN_QUERY_CHARS {
        return Err(Box::new(validation(
            "Search query must be at least 3 characters",
        )));
    }
    let limit = request
        .limit
        .unwrap_or(SEARCH_DEFAULT_LIMIT)
        .clamp(SEARCH_MIN_LIMIT, SEARCH_MAX_LIMIT);
    Ok(ValidatedSearch {
        pattern: format!("%{}%", escape_like_pattern(term)),
        limit: i64::from(limit),
    })
}

fn validate_transaction_path_id(id: &str) -> Result<Uuid, Box<Response>> {
    if id.is_empty() || id.len() > TRANSACTION_ID_MAX_LEN {
        return Err(Box::new(validation("Transaction ID is invalid")));
    }
    if !id
        .chars()
        .all(|character| character.is_alphanumeric() || character == '-' || character == '_')
    {
        return Err(Box::new(validation("Transaction ID is invalid")));
    }
    Uuid::parse_str(id).map_err(|_| Box::new(not_found("Transaction was not found")))
}

fn visible_transaction(
    transaction: Option<TransactionBase>,
) -> Result<TransactionBase, Box<Response>> {
    transaction.ok_or_else(|| Box::new(not_found("Transaction was not found")))
}

fn visible_tenant_instance(instance_count: i64) -> Result<(), Box<Response>> {
    if instance_count > 0 {
        Ok(())
    } else {
        Err(Box::new(not_found("Transaction was not found")))
    }
}

fn transaction_base(row: &sqlx::postgres::PgRow) -> TransactionBase {
    TransactionBase {
        transaction_id: row.get("transaction_id"),
        trace_id: row.get("trace_id"),
        direction: row.get("direction"),
        deployment_id: row.get("deployment_id"),
        envelope_sender: row.get("envelope_sender"),
        message_id: row.get("message_id"),
        content_hash: row.get("content_hash"),
        received_at: row.get("received_at"),
    }
}

fn notify_summary(notify: Option<Vec<String>>) -> Option<String> {
    let values = notify?;
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

fn workload_flow_stages(received_at: DateTime<Utc>) -> Vec<TraceFlowStageResponse> {
    vec![TraceFlowStageResponse {
        stage: "received",
        at: received_at,
    }]
}

fn session_flow_stages(
    received_at: DateTime<Utc>,
    instances: &[TraceInstanceResponse],
    attempts: &[TraceDeliveryAttemptResponse],
) -> Vec<TraceFlowStageResponse> {
    let mut stages = workload_flow_stages(received_at);
    for instance in instances {
        stages.push(TraceFlowStageResponse {
            stage: "tenant_message_created",
            at: instance.created_at,
        });
    }
    for attempt in attempts {
        if let Some(scheduled_at) = attempt.scheduled_at {
            stages.push(TraceFlowStageResponse {
                stage: "delivery_scheduled",
                at: scheduled_at,
            });
        }
        if let Some(completed_at) = attempt.completed_at {
            stages.push(TraceFlowStageResponse {
                stage: "delivery_completed",
                at: completed_at,
            });
        }
    }
    stages.sort_by_key(|stage| stage.at);
    stages
}

fn build_workload_detail(
    transaction: Option<TransactionBase>,
    recipients: Vec<TraceRecipientResponse>,
) -> Result<WorkloadTransactionDetail, Box<Response>> {
    let transaction = visible_transaction(transaction)?;
    Ok(WorkloadTransactionDetail {
        flow_stages: workload_flow_stages(transaction.received_at),
        transaction_id: transaction.transaction_id.to_string(),
        trace_id: transaction.trace_id,
        direction: transaction.direction,
        deployment_id: transaction.deployment_id,
        envelope_sender: transaction.envelope_sender,
        message_id: transaction.message_id,
        content_hash: transaction.content_hash,
        received_at: transaction.received_at,
        recipients,
    })
}

fn clip_chars(value: &str, max_chars: usize) -> (String, bool) {
    if value.chars().count() <= max_chars {
        return (value.to_string(), false);
    }
    (value.chars().take(max_chars).collect(), true)
}

fn parse_message_content(transaction_id: &str, bytes: &[u8]) -> Option<MessageContentResponse> {
    let parsed = mailparse::parse_mail(bytes).ok()?;
    let mut truncated = false;
    let mut headers = Vec::new();
    for (index, header) in parsed.headers.iter().enumerate() {
        if index >= MAX_HEADER_ENTRIES {
            truncated = true;
            break;
        }
        let (value, clipped) = clip_chars(&header.get_value(), MAX_HEADER_VALUE_CHARS);
        truncated = truncated || clipped;
        headers.push(MessageHeaderResponse {
            name: header.get_key(),
            value,
        });
    }
    let subject = parsed.headers.get_first_value("Subject");
    let from = parsed.headers.get_first_value("From");
    let date = parsed.headers.get_first_value("Date");
    let to = parsed.headers.get_all_values("To");

    let mut plain_text: Option<String> = None;
    let mut html: Option<String> = None;
    let mut attachments: Vec<MessageAttachmentResponse> = Vec::new();
    for part in parsed.parts() {
        let mimetype = part.ctype.mimetype.to_ascii_lowercase();
        if mimetype == "text/plain" && plain_text.is_none() {
            if let Ok(body) = part.get_body() {
                let (body, clipped) = clip_chars(&body, MAX_PLAIN_TEXT_CHARS);
                truncated = truncated || clipped;
                plain_text = Some(body);
            }
        } else if mimetype == "text/html" && html.is_none() {
            if let Ok(body) = part.get_body() {
                let (body, clipped) = clip_chars(&body, MAX_HTML_CHARS);
                truncated = truncated || clipped;
                html = Some(body);
            }
        }
        let disposition = part.get_content_disposition();
        let filename = disposition
            .params
            .get("filename")
            .cloned()
            .or_else(|| part.ctype.params.get("filename").cloned());
        let is_attachment =
            disposition.disposition == DispositionType::Attachment || filename.is_some();
        if is_attachment {
            if attachments.len() >= MAX_ATTACHMENT_ENTRIES {
                truncated = true;
                continue;
            }
            attachments.push(MessageAttachmentResponse {
                filename,
                content_type: Some(part.ctype.mimetype.clone()),
                size_bytes: part.get_body_raw().ok().map(|body| body.len() as i64),
            });
        }
    }

    Some(MessageContentResponse {
        transaction_id: transaction_id.to_string(),
        subject,
        from,
        to,
        date,
        headers,
        plain_text,
        html,
        truncated,
        attachments,
    })
}

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

async fn workload_transaction_detail(
    pool: &PgPool,
    deployment_id: &str,
    transaction_id: Uuid,
) -> Result<WorkloadTransactionDetail, Response> {
    // smtp_transactions and smtp_transaction_recipients carry FORCE RLS
    // (migration 034); the deployment GUC must be set in the transaction.
    let mut transaction = pool.begin().await.map_err(|_| unavailable())?;
    sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
        .bind(deployment_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    let row = sqlx::query(TRANSACTION_SQL)
        .bind(transaction_id)
        .bind(deployment_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    let transaction_row = row.as_ref().map(transaction_base);
    let recipients = if transaction_row.is_some() {
        let rows = sqlx::query(TRANSACTION_RECIPIENTS_SQL)
            .bind(transaction_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| unavailable())?;
        rows.iter()
            .map(|row| TraceRecipientResponse {
                address: row.get("address"),
                orcpt: row.get("orcpt"),
                notify: notify_summary(row.get("notify")),
            })
            .collect()
    } else {
        Vec::new()
    };
    transaction.commit().await.map_err(|_| unavailable())?;
    build_workload_detail(transaction_row, recipients).map_err(|error| *error)
}

async fn session_transaction_detail(
    state: &MailTraceState,
    context: &TenantContext,
    transaction_id: Uuid,
) -> Result<TransactionDetail, Response> {
    let mut transaction = state.0.pool.begin().await.map_err(|_| unavailable())?;
    set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await?;

    let row = sqlx::query(SESSION_TRANSACTION_SQL)
        .bind(transaction_id)
        .bind(&state.0.deployment_id.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    let session = row.as_ref().map(session_transaction);
    let Some(session) = session else {
        return Err(not_found("Transaction was not found"));
    };

    let instance_count: i64 = sqlx::query_scalar(OWNED_INSTANCE_COUNT_SQL)
        .bind(transaction_id)
        .bind(&context.customer_id.0)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    visible_tenant_instance(instance_count).map_err(|error| *error)?;

    let recipient_rows = sqlx::query(SESSION_RECIPIENTS_SQL)
        .bind(transaction_id)
        .bind(&context.customer_id.0)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    let instance_rows = sqlx::query(SESSION_INSTANCES_SQL)
        .bind(transaction_id)
        .bind(&context.customer_id.0)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    let attempt_rows = sqlx::query(SESSION_ATTEMPTS_SQL)
        .bind(transaction_id)
        .bind(&context.customer_id.0)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    let finding_rows = sqlx::query(SESSION_FINDINGS_SQL)
        .bind(transaction_id)
        .bind(&context.customer_id.0)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    if transaction.commit().await.is_err() {
        return Err(unavailable());
    }

    let recipients: Vec<TraceRecipientResponse> = recipient_rows
        .iter()
        .map(|row| TraceRecipientResponse {
            address: row.get("address"),
            orcpt: row.get("orcpt"),
            notify: notify_summary(row.get("notify")),
        })
        .collect();
    let instances: Vec<TraceInstanceResponse> = instance_rows
        .iter()
        .map(|row| TraceInstanceResponse {
            tenant_message_id: row.get::<Uuid, _>("tenant_message_id").to_string(),
            disposition: row.get("disposition"),
            remediation_type: row.get("remediation_type"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
        .collect();
    let delivery_attempts: Vec<TraceDeliveryAttemptResponse> = attempt_rows
        .iter()
        .map(|row| TraceDeliveryAttemptResponse {
            attempt_number: row.get("attempt_number"),
            status: row.get("status"),
            smtp_code: row
                .get::<Option<i32>, _>("smtp_code")
                .map(|code| code.to_string()),
            enhanced_code: row.get("enhanced_code"),
            smtp_message: row.get("smtp_message"),
            scheduled_at: row.get("scheduled_at"),
            completed_at: row.get("completed_at"),
            next_retry_at: row.get("next_retry_at"),
            postfix_queue_id: row.get("postfix_queue_id"),
        })
        .collect();
    let findings: Vec<TraceFindingResponse> = finding_rows
        .iter()
        .map(|row| {
            TraceFindingResponse::project_customer_safe(
                row.get("id"),
                row.get("severity"),
                row.get("category"),
                row.get("description"),
                row.get("scanner_type"),
                row.get("false_positive"),
                row.get("created_at"),
            )
        })
        .collect();

    let base = session.base;
    Ok(TransactionDetail {
        flow_stages: session_flow_stages(base.received_at, &instances, &delivery_attempts),
        transaction_id: base.transaction_id.to_string(),
        trace_id: base.trace_id,
        direction: base.direction,
        deployment_id: base.deployment_id,
        envelope_sender: base.envelope_sender,
        message_id: base.message_id,
        content_hash: base.content_hash,
        received_at: base.received_at,
        recipients,
        auth: TraceAuthResults {
            spf_result: session.spf_result,
            dkim_result: session.dkim_result,
            dmarc_result: session.dmarc_result,
            arc_result: session.arc_result,
        },
        postfix_queue_ids: session.postfix_queue_ids,
        instances,
        delivery_attempts,
        findings,
    })
}

fn session_transaction(row: &sqlx::postgres::PgRow) -> SessionTransaction {
    SessionTransaction {
        base: TransactionBase {
            transaction_id: row.get("transaction_id"),
            trace_id: row.get("trace_id"),
            direction: row.get("direction"),
            deployment_id: row.get("deployment_id"),
            envelope_sender: row.get("envelope_sender"),
            message_id: row.get("message_id"),
            content_hash: row.get("content_hash"),
            received_at: row.get("received_at"),
        },
        mime_artifact_id: row.get("mime_artifact_id"),
        spf_result: row.get("spf_result"),
        dkim_result: row.get("dkim_result"),
        dmarc_result: row.get("dmarc_result"),
        arc_result: row.get("arc_result"),
        postfix_queue_ids: row.get("postfix_queue_ids"),
    }
}

async fn load_content_plan(
    state: &MailTraceState,
    context: &TenantContext,
    transaction_id: Uuid,
) -> Result<ContentPlan, Response> {
    let mut transaction = state.0.pool.begin().await.map_err(|_| unavailable())?;
    set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await?;

    let row = sqlx::query(SESSION_TRANSACTION_SQL)
        .bind(transaction_id)
        .bind(&state.0.deployment_id.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    let Some(row) = row else {
        return Err(not_found("Transaction was not found"));
    };
    let session = session_transaction(&row);

    let instance_count: i64 = sqlx::query_scalar(OWNED_INSTANCE_COUNT_SQL)
        .bind(transaction_id)
        .bind(&context.customer_id.0)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;

    let artifact_id = Uuid::parse_str(&session.mime_artifact_id).ok();
    let artifact_visible = match artifact_id {
        Some(artifact_id) => sqlx::query_scalar::<_, Uuid>(ARTIFACT_SQL)
            .bind(artifact_id)
            .bind(&state.0.deployment_id.0)
            .bind(&context.customer_id.0)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| unavailable())?
            .is_some(),
        None => false,
    };
    let tenant_message_ids: Vec<String> = sqlx::query(SESSION_INSTANCES_SQL)
        .bind(transaction_id)
        .bind(&context.customer_id.0)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| unavailable())?
        .iter()
        .map(|row| row.get::<Uuid, _>("tenant_message_id").to_string())
        .collect();
    if transaction.commit().await.is_err() {
        return Err(unavailable());
    }

    Ok(ContentPlan {
        owned: instance_count > 0,
        artifact_id,
        artifact_visible,
        tenant_message_ids,
    })
}

fn issue_content_grant(
    state: &MailTraceState,
    context: &TenantContext,
    artifact_id: Uuid,
) -> Option<ArtifactAccessGrant> {
    ArtifactAccessGrant::issue_server_authorized(
        state.0.deployment_id.clone(),
        ArtifactScope::Customer(context.customer_id.clone()),
        context.actor.actor_id.0.to_string(),
        ArtifactPermissions::new(true, false),
        ArtifactAccessPurpose::ContentReview,
        [ArtifactId(artifact_id)],
        Utc::now() + chrono::Duration::seconds(CONTENT_GRANT_TTL_SECONDS),
    )
    .ok()
}

async fn serve_content(
    state: &MailTraceState,
    context: &TenantContext,
    headers: &HeaderMap,
    transaction_id: &str,
    plan: ContentPlan,
) -> Response {
    if !plan.owned {
        return content_denied(
            state,
            context,
            headers,
            transaction_id,
            Denial::not_found("Transaction was not found", "tenant message is not visible"),
        )
        .await;
    }
    let Some(artifact_id) = plan.artifact_id else {
        return content_denied(
            state,
            context,
            headers,
            transaction_id,
            Denial::not_found("Message content was not found", "no stored MIME artifact"),
        )
        .await;
    };
    if !plan.artifact_visible {
        return content_denied(
            state,
            context,
            headers,
            transaction_id,
            Denial::not_found("Message content was not found", "artifact is not visible"),
        )
        .await;
    }
    let Some(grant) = issue_content_grant(state, context, artifact_id) else {
        return content_failed(
            state,
            context,
            headers,
            transaction_id,
            "artifact grant could not be issued",
        )
        .await;
    };
    let artifact = match state
        .0
        .artifact_store
        .get(&grant, &ArtifactId(artifact_id))
        .await
    {
        Ok(artifact) => artifact,
        Err(ArtifactStoreError::NotFound) => {
            return content_denied(
                state,
                context,
                headers,
                transaction_id,
                Denial::not_found(
                    "Message content was not found",
                    "artifact bytes are missing",
                ),
            )
            .await;
        },
        Err(_) => {
            return content_failed(
                state,
                context,
                headers,
                transaction_id,
                "artifact bytes are unavailable",
            )
            .await;
        },
    };
    let Some(content) = parse_message_content(transaction_id, &artifact.bytes) else {
        return content_failed(
            state,
            context,
            headers,
            transaction_id,
            "stored MIME could not be parsed",
        )
        .await;
    };
    record_content_audit(
        state,
        context,
        headers,
        transaction_id,
        "success",
        json!({
            "artifact_id": artifact_id,
            "tenant_message_ids": plan.tenant_message_ids,
        }),
    )
    .await;
    (StatusCode::OK, Json(ApiEnvelope { data: content })).into_response()
}

pub fn trace_router(config: TraceConfig) -> Router {
    Router::new()
        .route("/api/v1/trace/search", post(handle_trace_search))
        .route("/api/v1/trace/transaction/:id", get(handle_get_transaction))
        .route("/api/v1/trace/health", get(handle_health_check))
        .layer(middleware::from_fn(require_workload_auth))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .layer(axum::extract::Extension(config.clone()))
        .with_state(config)
}

pub fn mail_trace_router(state: MailTraceState) -> Router {
    Router::new()
        .route("/api/v1/mail-trace/search", post(handle_mail_trace_search))
        .route(
            "/api/v1/mail-trace/transaction/:id",
            get(handle_mail_trace_transaction),
        )
        .route(
            "/api/v1/mail-trace/transaction/:id/content",
            get(handle_mail_trace_content),
        )
        .with_state(state)
}

async fn require_workload_auth(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    if request.uri().path() == "/api/v1/trace/health" {
        return Ok(next.run(request).await);
    }

    let expected = request
        .extensions()
        .get::<TraceConfig>()
        .and_then(|cfg| cfg.workload_token_sha256);

    let Some(expected) = expected else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            if !val.starts_with("127.") && !val.starts_with("[::1]") && val != "::1" {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let Some(token) = auth_header.and_then(|value| value.strip_prefix("Bearer ")) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if token.is_empty() || token.len() > 4096 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if expected.ct_eq(&actual).unwrap_u8() != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

async fn handle_trace_search(
    State(config): State<TraceConfig>,
    body: Result<Json<TraceSearchRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return invalid_request();
    };
    let validated = match validate_search_request(&request) {
        Ok(validated) => validated,
        Err(response) => return *response,
    };

    // smtp_transactions and smtp_transaction_recipients carry FORCE RLS
    // (migration 034); run the workload search in a deployment-scoped
    // transaction.
    let mut transaction = match config.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
        .bind(&config.deployment_id.0)
        .execute(&mut *transaction)
        .await
        .is_err()
    {
        return unavailable();
    }
    let total_count: i64 = match sqlx::query_scalar(WORKLOAD_SEARCH_COUNT_SQL)
        .bind(&config.deployment_id.0)
        .bind(&validated.pattern)
        .fetch_one(&mut *transaction)
        .await
    {
        Ok(count) => count,
        Err(_) => return unavailable(),
    };
    let rows = match sqlx::query(WORKLOAD_SEARCH_SQL)
        .bind(&config.deployment_id.0)
        .bind(&validated.pattern)
        .bind(validated.limit)
        .fetch_all(&mut *transaction)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    let results: Vec<WorkloadSearchResult> = rows
        .iter()
        .map(|row| WorkloadSearchResult {
            transaction_id: row.get::<Uuid, _>("transaction_id").to_string(),
            direction: row.get("direction"),
            envelope_sender: row.get("envelope_sender"),
            message_id: row.get("message_id"),
            received_at: row.get("received_at"),
            recipient_count: row.get("recipient_count"),
        })
        .collect();
    let has_more = total_count > results.len() as i64;
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: WorkloadSearchResults {
                results,
                total_count,
                has_more,
            },
        }),
    )
        .into_response()
}

async fn handle_get_transaction(
    State(config): State<TraceConfig>,
    Path(transaction_id): Path<String>,
) -> Response {
    let transaction_uuid = match validate_transaction_path_id(&transaction_id) {
        Ok(transaction_uuid) => transaction_uuid,
        Err(response) => return *response,
    };
    match workload_transaction_detail(&config.pool, &config.deployment_id.0, transaction_uuid).await
    {
        Ok(detail) => (StatusCode::OK, Json(ApiEnvelope { data: detail })).into_response(),
        Err(response) => response,
    }
}

async fn handle_health_check(State(config): State<TraceConfig>) -> Response {
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: HealthCheckResponse {
                status: "healthy".to_string(),
                node_id: config.node_id.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_seconds: PROCESS_START.elapsed().as_secs(),
                queue_depth: None,
            },
        }),
    )
        .into_response()
}

async fn handle_mail_trace_search(
    State(state): State<MailTraceState>,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<TraceSearchRequest>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if let Some(denial) = authorization_denial(&state, &context, TRACE_VIEW_PERMISSION) {
        return api_error(denial.status, denial.code, denial.message);
    }
    let Ok(Json(request)) = body else {
        return invalid_request();
    };
    let validated = match validate_search_request(&request) {
        Ok(validated) => validated,
        Err(response) => return *response,
    };
    let results = match session_search(&state, &context, &validated).await {
        Ok(results) => results,
        Err(response) => return response,
    };
    (StatusCode::OK, Json(ApiEnvelope { data: results })).into_response()
}

async fn session_search(
    state: &MailTraceState,
    context: &TenantContext,
    validated: &ValidatedSearch,
) -> Result<MailTraceSearchResults, Response> {
    let mut transaction = state.0.pool.begin().await.map_err(|_| unavailable())?;
    set_scope(
        &mut transaction,
        &state.0.deployment_id.0,
        &context.customer_id.0,
    )
    .await?;

    let total_count: i64 = sqlx::query_scalar(SESSION_SEARCH_COUNT_SQL)
        .bind(&state.0.deployment_id.0)
        .bind(&context.customer_id.0)
        .bind(&validated.pattern)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;
    let rows = sqlx::query(SESSION_SEARCH_SQL)
        .bind(&state.0.deployment_id.0)
        .bind(&context.customer_id.0)
        .bind(&validated.pattern)
        .bind(validated.limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| unavailable())?;

    let mut results: Vec<MailTraceSearchResult> = Vec::with_capacity(rows.len());
    let mut transaction_ids: Vec<Uuid> = Vec::with_capacity(rows.len());
    for row in &rows {
        let transaction_id: Uuid = row.get("transaction_id");
        transaction_ids.push(transaction_id);
        results.push(MailTraceSearchResult {
            transaction_id: transaction_id.to_string(),
            direction: row.get("direction"),
            envelope_sender: row.get("envelope_sender"),
            message_id: row.get("message_id"),
            received_at: row.get("received_at"),
            recipients: Vec::new(),
            instances: Vec::new(),
        });
    }

    if !transaction_ids.is_empty() {
        let recipient_rows = sqlx::query(SESSION_SEARCH_RECIPIENTS_SQL)
            .bind(&transaction_ids)
            .bind(&context.customer_id.0)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| unavailable())?;
        for row in &recipient_rows {
            let transaction_id: Uuid = row.get("transaction_id");
            let address: String = row.get("address");
            if let Some(entry) = results
                .iter_mut()
                .find(|entry| entry.transaction_id == transaction_id.to_string())
            {
                entry.recipients.push(address);
            }
        }
        let instance_rows = sqlx::query(SEARCH_INSTANCES_SQL)
            .bind(&transaction_ids)
            .bind(&context.customer_id.0)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| unavailable())?;
        for row in &instance_rows {
            let transaction_id: Uuid = row.get("transaction_id");
            let instance = MailTraceSearchInstance {
                tenant_message_id: row.get::<Uuid, _>("tenant_message_id").to_string(),
                disposition: row.get("disposition"),
            };
            if let Some(entry) = results
                .iter_mut()
                .find(|entry| entry.transaction_id == transaction_id.to_string())
            {
                entry.instances.push(instance);
            }
        }
    }

    if transaction.commit().await.is_err() {
        return Err(unavailable());
    }

    let has_more = total_count > results.len() as i64;
    Ok(MailTraceSearchResults {
        results,
        total_count,
        has_more,
    })
}

async fn handle_mail_trace_transaction(
    State(state): State<MailTraceState>,
    Path(transaction_id): Path<String>,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if let Some(denial) = authorization_denial(&state, &context, TRACE_VIEW_PERMISSION) {
        return api_error(denial.status, denial.code, denial.message);
    }
    let Ok(transaction_uuid) = Uuid::parse_str(&transaction_id) else {
        return not_found("Transaction was not found");
    };
    match session_transaction_detail(&state, &context, transaction_uuid).await {
        Ok(detail) => (StatusCode::OK, Json(ApiEnvelope { data: detail })).into_response(),
        Err(response) => response,
    }
}

async fn handle_mail_trace_content(
    State(state): State<MailTraceState>,
    Path(transaction_id): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return unauthenticated();
    };
    if let Some(denial) = authorization_denial(&state, &context, TRACE_CONTENT_PERMISSION) {
        return content_denied(&state, &context, &headers, &transaction_id, denial).await;
    }
    if !take_content_token(&state, &context.actor.actor_id.0.to_string()) {
        return content_denied(
            &state,
            &context,
            &headers,
            &transaction_id,
            Denial::rate_limited(),
        )
        .await;
    }
    let Ok(transaction_uuid) = Uuid::parse_str(&transaction_id) else {
        return content_denied(
            &state,
            &context,
            &headers,
            &transaction_id,
            Denial::not_found("Transaction was not found", "transaction id is not a UUID"),
        )
        .await;
    };
    let plan = match load_content_plan(&state, &context, transaction_uuid).await {
        Ok(plan) => plan,
        Err(response) => return response,
    };
    serve_content(&state, &context, &headers, &transaction_id, plan).await
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request},
    };
    use nullapart_mail_contracts::{
        artifact::{
            Artifact, ArtifactHash, ContentType, HashAlgorithm, RetentionClass, StorageBackend,
            StorageLocation,
        },
        transaction::CustomerId,
    };
    use tower::ServiceExt;

    use super::*;
    use crate::admin_audit::InMemoryAuditStore;

    fn unreachable_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse")
    }

    fn test_context(roles: Vec<String>, permissions: Vec<String>) -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            region: RegionId::new("local"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "trace-test@example.test".to_string(),
                roles,
                authentication_assurance: AuthenticationAssurance::StepUp,
            },
            impersonation: None,
            customer_id: CustomerId::new("local-customer"),
            customer_internal_key: 1,
            customer_display_name: "Trace test customer".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions,
            config_revision: 1,
            trace_id: "trace-test".to_string(),
            correlation_id: "trace-test".to_string(),
            session_id: "trace-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn viewer_context() -> TenantContext {
        test_context(
            vec![crate::admin_rbac::SUPPORT_ROLE.to_string()],
            vec![TRACE_VIEW_PERMISSION.to_string()],
        )
    }

    fn content_context() -> TenantContext {
        test_context(
            vec![crate::admin_rbac::SYSTEM_ADMIN_ROLE.to_string()],
            vec![
                TRACE_VIEW_PERMISSION.to_string(),
                TRACE_CONTENT_PERMISSION.to_string(),
            ],
        )
    }

    fn workload_config() -> TraceConfig {
        let mut config = TraceConfig {
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            node_id: "mailcore-local-01".to_string(),
            node_version: "0.0.0".to_string(),
            config_revision: None,
            workload_token_sha256: None,
            pool: unreachable_pool(),
        };
        config.set_workload_token("trace-workload-token");
        config
    }

    async fn content_state(
        audit: Arc<InMemoryAuditStore>,
    ) -> (MailTraceState, FilesystemArtifactStore, PathBuf) {
        let root = std::env::temp_dir().join(format!("nullapart-trace-{}", Uuid::new_v4()));
        let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
            .await
            .expect("the test artifact root must be created");
        let state = MailTraceState::with_audit(
            unreachable_pool(),
            DeploymentId::new("LOCAL-TEST"),
            store.clone(),
            audit,
        );
        (state, store, root)
    }

    fn stored_artifact(deployment_id: &str, customer_id: &str, bytes: &[u8]) -> Artifact {
        let id = ArtifactId::new();
        Artifact {
            id: id.clone(),
            deployment_id: DeploymentId::new(deployment_id),
            customer_id: Some(CustomerId::new(customer_id)),
            content_type: ContentType::new("message/rfc822"),
            size: bytes.len() as u64,
            storage_location: StorageLocation {
                backend: StorageBackend::Filesystem,
                bucket: None,
                key: format!("{}.artifact", id.0),
                region: None,
            },
            hash: ArtifactHash {
                algorithm: HashAlgorithm::Sha256,
                value: hex::encode(Sha256::digest(bytes)),
            },
            retention_class: RetentionClass::Standard,
            created_at: Utc::now(),
            expires_at: None,
            encrypted: false,
            scanner_eligible: true,
        }
    }

    async fn body_value(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body must read");
        serde_json::from_slice(&bytes).expect("the body must be JSON")
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body must read");
        String::from_utf8(bytes.to_vec()).expect("the body must be UTF-8")
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

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("test request must build")
    }

    fn get_workload(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("authorization", "Bearer trace-workload-token")
            .body(Body::empty())
            .expect("test request must build")
    }

    fn post_mail_trace_search(body: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/mail-trace/search")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("test request must build")
    }

    fn post_search(body: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/trace/search")
            .header("content-type", "application/json")
            .header("authorization", "Bearer trace-workload-token")
            .body(Body::from(body.to_string()))
            .expect("test request must build")
    }

    fn post_search_without_credentials(body: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/trace/search")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("test request must build")
    }

    async fn audit_results(audit: &InMemoryAuditStore) -> Vec<String> {
        audit
            .records()
            .into_iter()
            .map(|record| {
                assert_eq!(record.action, ACTION_TRACE_CONTENT);
                assert_eq!(record.resource_type, RESOURCE_TRANSACTION);
                record.result
            })
            .collect()
    }

    #[test]
    fn search_validation_accepts_trimmed_queries_and_clamps_limits() {
        let request = TraceSearchRequest {
            q: "  alice@example.test  ".to_string(),
            limit: None,
        };
        let validated = validate_search_request(&request).expect("a trimmed query must validate");
        assert_eq!(validated.pattern, "%alice@example.test%");
        assert_eq!(validated.limit, 20);

        for (limit, expected) in [(0, 1), (-5, 1), (30, 30), (999, 50)] {
            let request = TraceSearchRequest {
                q: "alice@example.test".to_string(),
                limit: Some(limit),
            };
            let validated =
                validate_search_request(&request).expect("any limit must be clamped, not rejected");
            assert_eq!(validated.limit, i64::from(expected));
        }
    }

    #[test]
    fn inline_ml_findings_are_projected_as_customer_safe_threat_analysis() {
        let finding = TraceFindingResponse::project_customer_safe(
            Uuid::new_v4(),
            "high".to_string(),
            "phishing".to_string(),
            "Inline ML score 0.91 exceeded high threshold 0.90 for model inline-threat-v2"
                .to_string(),
            "inline_ml".to_string(),
            false,
            Utc::now(),
        );

        assert_eq!(finding.scanner_type, "threat_analysis");
        assert_eq!(
            finding.description,
            "high phishing evidence was recorded for this message."
        );
        let body = serde_json::to_string(&finding).expect("finding must serialize");
        assert!(!body.contains("inline_ml"));
        assert!(!body.contains("Inline ML"));
        assert!(!body.contains("0.91"));
        assert!(!body.contains("inline-threat-v2"));
    }

    #[test]
    fn scanner_findings_are_projected_as_customer_safe_evidence_sources() {
        let finding = TraceFindingResponse::project_customer_safe(
            Uuid::new_v4(),
            "high".to_string(),
            "malware".to_string(),
            "clamav static-rule scanner matched urlanalysis signature".to_string(),
            "urlanalysis".to_string(),
            false,
            Utc::now(),
        );

        assert_eq!(finding.scanner_type, "link_analysis");
        assert_eq!(
            finding.description,
            "high malware evidence was recorded for this message."
        );
        let body = serde_json::to_string(&finding).expect("finding must serialize");
        assert!(!body.contains("urlanalysis"));
        assert!(!body.contains("clamav"));
        assert!(!body.contains("static-rule"));

        let static_rule_finding = TraceFindingResponse::project_customer_safe(
            Uuid::new_v4(),
            "critical".to_string(),
            "malware".to_string(),
            "Static malware rule matched".to_string(),
            "custom".to_string(),
            false,
            Utc::now(),
        );

        assert_eq!(static_rule_finding.scanner_type, "security_analysis");
        assert_eq!(
            static_rule_finding.description,
            "critical malware evidence was recorded for this message."
        );
        let body = serde_json::to_string(&static_rule_finding).expect("finding must serialize");
        assert!(!body.contains("Static malware rule"));
    }

    #[test]
    fn search_validation_rejects_short_queries() {
        let request = TraceSearchRequest {
            q: "  ab ".to_string(),
            limit: None,
        };
        let response =
            validate_search_request(&request).expect_err("a two character query must be rejected");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn workload_search_rejects_short_queries_with_validation_error() {
        let app = trace_router(workload_config());
        let response = app
            .oneshot(post_search(r#"{"q":"ab"}"#))
            .await
            .expect("the search must answer");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_value(response).await,
            json!({ "code": "VALIDATION", "message": "Search query must be at least 3 characters" })
        );
    }

    #[tokio::test]
    async fn workload_search_rejects_requests_without_a_bearer_token() {
        let app = trace_router(workload_config());
        let response = app
            .oneshot(post_search_without_credentials(
                r#"{"q":"alice@example.test"}"#,
            ))
            .await
            .expect("the search must answer");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn workload_search_fails_closed_without_a_workload_token() {
        let mut config = workload_config();
        config.workload_token_sha256 = None;
        let response = trace_router(config)
            .oneshot(post_search(r#"{"q":"alice@example.test"}"#))
            .await
            .expect("the search must answer");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn transaction_path_id_accepts_uuids_and_rejects_malformed_identifiers() {
        let uuid = Uuid::new_v4();
        assert_eq!(
            validate_transaction_path_id(&uuid.to_string()).expect("a UUID must validate"),
            uuid
        );
        let malformed = validate_transaction_path_id("../../etc/passwd")
            .expect_err("an out-of-range identifier must be rejected");
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let unknown = validate_transaction_path_id("not-a-uuid")
            .expect_err("a non-UUID identifier must fall through to 404");
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn workload_detail_is_not_found_without_a_recorded_transaction() {
        let response = build_workload_detail(None, Vec::new())
            .expect_err("an unseen transaction must be not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            serde_json::to_value(ApiErrorBody {
                code: "NOT_FOUND",
                message: "Transaction was not found",
            })
            .expect("the error body must serialize"),
            json!({ "code": "NOT_FOUND", "message": "Transaction was not found" })
        );
    }

    #[test]
    fn session_detail_is_not_found_without_a_visible_tenant_instance() {
        let response =
            visible_tenant_instance(0).expect_err("an unseen tenant message must be not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(visible_tenant_instance(1).is_ok());
    }

    #[test]
    fn workload_flow_stages_report_only_the_recorded_receive_time() {
        let received_at = Utc::now();
        let stages = workload_flow_stages(received_at);
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0].stage, "received");
        assert_eq!(stages[0].at, received_at);
    }

    #[test]
    fn session_flow_stages_are_derived_only_from_recorded_timestamps() {
        let received_at = Utc::now() - chrono::Duration::minutes(5);
        let created_at = received_at + chrono::Duration::seconds(2);
        let scheduled_at = received_at + chrono::Duration::seconds(3);
        let completed_at = received_at + chrono::Duration::seconds(4);
        let stages = session_flow_stages(
            received_at,
            &[TraceInstanceResponse {
                tenant_message_id: "tenant-message-1".to_string(),
                disposition: "quarantine".to_string(),
                remediation_type: None,
                created_at,
                updated_at: created_at,
            }],
            &[TraceDeliveryAttemptResponse {
                attempt_number: 1,
                status: "success".to_string(),
                smtp_code: Some("250".to_string()),
                enhanced_code: None,
                smtp_message: None,
                scheduled_at: Some(scheduled_at),
                completed_at: Some(completed_at),
                next_retry_at: None,
                postfix_queue_id: None,
            }],
        );
        let rendered: Vec<(&'static str, DateTime<Utc>)> =
            stages.iter().map(|stage| (stage.stage, stage.at)).collect();
        assert_eq!(
            rendered,
            vec![
                ("received", received_at),
                ("tenant_message_created", created_at),
                ("delivery_scheduled", scheduled_at),
                ("delivery_completed", completed_at),
            ]
        );
        assert!(session_flow_stages(received_at, &[], &[]).len() == 1);
    }

    #[tokio::test]
    async fn health_reports_only_real_node_values() {
        let response = trace_router(workload_config())
            .oneshot(get("/api/v1/trace/health"))
            .await
            .expect("the health check must answer");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["data"]["node_id"], json!("mailcore-local-01"));
        assert_eq!(body["data"]["version"], json!(env!("CARGO_PKG_VERSION")));
        assert!(body["data"]["uptime_seconds"].as_u64().is_some());
        assert!(body["data"]["queue_depth"].is_null());
        let uptime = body["data"]["uptime_seconds"]
            .as_u64()
            .expect("uptime must be reported");
        assert!(uptime < 3600, "uptime must come from this process");
    }

    #[tokio::test]
    async fn session_routes_require_authenticated_context() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, _store, root) = content_state(audit).await;
        let app = mail_trace_router(state);
        for (method, uri) in [
            (Method::POST, "/api/v1/mail-trace/search"),
            (Method::GET, "/api/v1/mail-trace/transaction/anything"),
            (
                Method::GET,
                "/api/v1/mail-trace/transaction/anything/content",
            ),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .expect("test request must build");
            let response = app
                .clone()
                .oneshot(request)
                .await
                .expect("the route must answer");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                body_value(response).await,
                json!({ "code": "UNAUTHENTICATED", "message": "Authentication is required" })
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn content_requires_trace_content_permission_and_audits_the_denial() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, _store, root) = content_state(Arc::clone(&audit)).await;
        let response = mail_trace_router(state)
            .layer(Extension(viewer_context()))
            .oneshot(get(
                "/api/v1/mail-trace/transaction/3b241101-92b4-4f27-9f2a-3d0d4c3a9f01/content",
            ))
            .await
            .expect("the content route must answer");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_value(response).await,
            json!({ "code": "FORBIDDEN", "message": "Permission is required" })
        );
        assert_eq!(audit_results(&audit).await, vec!["denied"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn content_rate_limit_exhaustion_returns_429_and_audits_the_denial() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, _store, root) = content_state(Arc::clone(&audit)).await;
        let app = mail_trace_router(state.clone()).layer(Extension(content_context()));
        let uri = "/api/v1/mail-trace/transaction/3b241101-92b4-4f27-9f2a-3d0d4c3a9f02/content";
        let mut last: Option<Response> = None;
        for _ in 0..(CONTENT_READ_MAX_TOKENS + 1) {
            last = Some(
                app.clone()
                    .oneshot(get(uri))
                    .await
                    .expect("the route must answer"),
            );
        }
        let response = last.expect("the final request must answer");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some(CONTENT_RETRY_AFTER_SECONDS)
        );
        assert_eq!(
            body_value(response).await,
            json!({
                "code": "RATE_LIMITED",
                "message": "Too many message content requests"
            })
        );
        let results = audit_results(&audit).await;
        assert_eq!(results.len(), 1, "only the exhausted request must audit");
        assert_eq!(results[0], "denied");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn content_ownership_denial_returns_404_and_audits_the_denial() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, _store, root) = content_state(Arc::clone(&audit)).await;
        let context = content_context();
        let headers = HeaderMap::new();
        let transaction_id = "3b241101-92b4-4f27-9f2a-3d0d4c3a9f03";
        let response = serve_content(
            &state,
            &context,
            &headers,
            transaction_id,
            ContentPlan {
                owned: false,
                artifact_id: Some(Uuid::new_v4()),
                artifact_visible: true,
                tenant_message_ids: Vec::new(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_value(response).await,
            json!({ "code": "NOT_FOUND", "message": "Transaction was not found" })
        );
        assert_eq!(audit_results(&audit).await, vec!["denied"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn content_invisible_artifact_returns_404_and_audits_the_denial() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, _store, root) = content_state(Arc::clone(&audit)).await;
        let context = content_context();
        let headers = HeaderMap::new();
        let transaction_id = "3b241101-92b4-4f27-9f2a-3d0d4c3a9f04";
        let response = serve_content(
            &state,
            &context,
            &headers,
            transaction_id,
            ContentPlan {
                owned: true,
                artifact_id: Some(Uuid::new_v4()),
                artifact_visible: false,
                tenant_message_ids: Vec::new(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_value(response).await,
            json!({ "code": "NOT_FOUND", "message": "Message content was not found" })
        );
        assert_eq!(audit_results(&audit).await, vec!["denied"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn content_store_miss_returns_404_and_audits_the_denial() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, store, root) = content_state(Arc::clone(&audit)).await;
        let context = content_context();
        let headers = HeaderMap::new();
        let bytes = b"stored but never referenced".to_vec();
        let artifact = stored_artifact("LOCAL-TEST", "local-customer", &bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("the artifact must store");
        let transaction_id = "3b241101-92b4-4f27-9f2a-3d0d4c3a9f05";
        let response = serve_content(
            &state,
            &context,
            &headers,
            transaction_id,
            ContentPlan {
                owned: true,
                artifact_id: Some(Uuid::new_v4()),
                artifact_visible: true,
                tenant_message_ids: vec!["tenant-message-1".to_string()],
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_value(response).await,
            json!({ "code": "NOT_FOUND", "message": "Message content was not found" })
        );
        let results = audit_results(&audit).await;
        assert_eq!(results, vec!["denied"]);
        assert_ne!(
            artifact.id.0,
            Uuid::new_v4(),
            "the stored artifact must exist for the miss to be meaningful"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    const MULTIPART_MESSAGE: &str = "Subject: Trace content test\r\n\
         From: sender@example.test\r\n\
         To: alice@example.test\r\n\
         Date: Wed, 30 Sep 2026 12:00:00 +0000\r\n\
         Content-Type: multipart/alternative; boundary=\"boundary\"\r\n\
         \r\n\
         --boundary\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         Plain body line\r\n\
         --boundary\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         \r\n\
         <p>HTML body</p>\r\n\
         --boundary--\r\n";

    #[tokio::test]
    async fn content_happy_path_parses_a_stored_multipart_alternative_message() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, store, root) = content_state(Arc::clone(&audit)).await;
        let bytes = MULTIPART_MESSAGE.as_bytes().to_vec();
        let artifact = stored_artifact("LOCAL-TEST", "local-customer", &bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("the artifact must store");

        let context = content_context();
        let headers = HeaderMap::new();
        let transaction_id = "3b241101-92b4-4f27-9f2a-3d0d4c3a9f06";
        let response = serve_content(
            &state,
            &context,
            &headers,
            transaction_id,
            ContentPlan {
                owned: true,
                artifact_id: Some(artifact.id.0),
                artifact_visible: true,
                tenant_message_ids: vec!["tenant-message-1".to_string()],
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        let data = &body["data"];
        assert_eq!(data["transaction_id"], json!(transaction_id));
        assert_eq!(data["subject"], json!("Trace content test"));
        assert_eq!(data["from"], json!("sender@example.test"));
        assert_eq!(data["to"], json!(["alice@example.test"]));
        assert_eq!(data["plain_text"], json!("Plain body line"));
        assert_eq!(data["html"], json!("<p>HTML body</p>"));
        assert_eq!(data["truncated"], json!(false));
        assert_eq!(data["attachments"], json!([]));
        assert!(data["headers"]
            .as_array()
            .expect("headers must be a list")
            .iter()
            .any(|header| header["name"] == json!("Subject")));

        let records = audit.records();
        assert_eq!(records.len(), 1, "one success audit row must be written");
        assert_eq!(records[0].result, "success");
        assert_eq!(records[0].resource_id.as_deref(), Some(transaction_id));
        let details = &records[0].details;
        assert_eq!(details["artifact_id"], json!(artifact.id.0));
        assert_eq!(details["tenant_message_ids"], json!(["tenant-message-1"]));
        assert!(
            !details.to_string().contains("Plain body line"),
            "an audit row must never record message content"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn message_parsing_marks_header_and_attachment_caps_as_truncated() {
        let mut message = String::from("Subject: Capped\r\n");
        for index in 0..150 {
            message.push_str(&format!("X-Trace-Header-{index}: value\r\n"));
        }
        message.push_str("\r\nbody\r\n");
        let content = parse_message_content("tx-capped", message.as_bytes())
            .expect("the capped message must parse");
        assert_eq!(content.headers.len(), MAX_HEADER_ENTRIES);
        assert!(content.truncated);
        assert_eq!(content.subject.as_deref(), Some("Capped"));

        let mut attachment_message = String::from("Subject: Attachments\r\n");
        attachment_message.push_str("Content-Type: multipart/mixed; boundary=\"mixed\"\r\n\r\n");
        for index in 0..60 {
            attachment_message.push_str("--mixed\r\n");
            attachment_message.push_str(&format!(
                "Content-Type: application/octet-stream; name=\"part-{index}.bin\"\r\n"
            ));
            attachment_message.push_str(&format!(
                "Content-Disposition: attachment; filename=\"part-{index}.bin\"\r\n\r\n"
            ));
            attachment_message.push_str("payload\r\n");
        }
        attachment_message.push_str("--mixed--\r\n");
        let content = parse_message_content("tx-attachments", attachment_message.as_bytes())
            .expect("the attachment message must parse");
        assert_eq!(content.attachments.len(), MAX_ATTACHMENT_ENTRIES);
        assert!(content.truncated);
        assert_eq!(
            content.attachments[0].filename.as_deref(),
            Some("part-0.bin")
        );
        assert_eq!(
            content.attachments[0].content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert!(content.attachments[0].size_bytes.is_some());
    }

    #[test]
    fn message_parsing_reports_absent_parts_as_null() {
        let content = parse_message_content("tx-bare", b"\r\nNot much of a message")
            .expect("a bare message must parse");
        assert!(content.subject.is_none());
        assert!(content.from.is_none());
        assert!(content.to.is_empty());
        assert!(content.plain_text.is_none() || content.html.is_none());
        assert!(!content.truncated);
        assert!(content.headers.is_empty());
    }

    #[tokio::test]
    async fn session_search_fails_closed_when_the_database_is_unreachable() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, _store, root) = content_state(audit).await;
        let response = mail_trace_router(state)
            .layer(Extension(viewer_context()))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/mail-trace/search")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"q":"alice@example.test"}"#))
                    .expect("test request must build"),
            )
            .await
            .expect("the search must answer");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_value(response).await,
            json!({ "code": "UNAVAILABLE", "message": "Service is unavailable" })
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn workload_trace_search_rejects_injected_fields() {
        let app = trace_router(workload_config());

        let baseline = app
            .clone()
            .oneshot(post_search(r#"{"q":"alice@example.test"}"#))
            .await
            .expect("the search must answer");
        assert_eq!(
            baseline.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an ordinary search must reach the database so the rejection below is discriminating"
        );

        let rejected = app
            .clone()
            .oneshot(post_search(
                r#"{"q":"alice@example.test","deployment_id":"OTHER-DEPLOYMENT",
                    "customer_id":"cust-injected","is_superadmin":true}"#,
            ))
            .await
            .expect("the search must answer");
        assert_eq!(
            rejected.status(),
            StatusCode::BAD_REQUEST,
            "an unexpected field must be rejected by the JSON extractor"
        );
        let raw = body_text(rejected).await;
        let value: Value = serde_json::from_str(&raw).expect("the rejection must be JSON");
        assert_eq!(
            value,
            json!({ "code": "INVALID_REQUEST", "message": "Request is invalid" })
        );
        assert!(
            value.get("data").is_none(),
            "a rejected search must return no results: {raw}"
        );
    }

    #[tokio::test]
    async fn mail_trace_search_rejects_injected_fields() {
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, _store, root) = content_state(audit).await;
        let app = mail_trace_router(state).layer(Extension(viewer_context()));

        let baseline = app
            .clone()
            .oneshot(post_mail_trace_search(r#"{"q":"alice@example.test"}"#))
            .await
            .expect("the search must answer");
        assert_eq!(
            baseline.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an ordinary search must reach the database so the rejection below is discriminating"
        );

        let rejected = app
            .clone()
            .oneshot(post_mail_trace_search(
                r#"{"q":"alice@example.test","deployment_id":"OTHER-DEPLOYMENT",
                    "customer_id":"cust-injected","is_superadmin":true}"#,
            ))
            .await
            .expect("the search must answer");
        assert_eq!(
            rejected.status(),
            StatusCode::BAD_REQUEST,
            "an unexpected field must be rejected by the JSON extractor"
        );
        let raw = body_text(rejected).await;
        let value: Value = serde_json::from_str(&raw).expect("the rejection must be JSON");
        assert_eq!(
            value,
            json!({ "code": "INVALID_REQUEST", "message": "Request is invalid" })
        );
        assert!(
            value.get("data").is_none(),
            "a rejected search must return no results: {raw}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn trace_error_responses_are_static_json_without_internal_leaks() {
        let workload = trace_router(workload_config());
        let audit = Arc::new(InMemoryAuditStore::new());
        let (state, _store, root) = content_state(audit).await;
        let session = mail_trace_router(state).layer(Extension(viewer_context()));

        let cases: Vec<(Router, Request<Body>, Vec<StatusCode>)> = vec![
            (
                workload.clone(),
                get_workload("/api/v1/trace/transaction/11111111-1111-1111-1111-111111111111"),
                vec![StatusCode::NOT_FOUND, StatusCode::SERVICE_UNAVAILABLE],
            ),
            (
                workload.clone(),
                get_workload("/api/v1/trace/transaction/not-a-uuid"),
                vec![StatusCode::NOT_FOUND],
            ),
            (
                workload.clone(),
                get_workload("/api/v1/trace/transaction/bad!id"),
                vec![StatusCode::BAD_REQUEST],
            ),
            (
                workload.clone(),
                post_search("{"),
                vec![StatusCode::BAD_REQUEST],
            ),
            (
                workload,
                post_search(r#"{"q":"ab"}"#),
                vec![StatusCode::BAD_REQUEST],
            ),
            (
                session.clone(),
                get("/api/v1/mail-trace/transaction/not-a-uuid"),
                vec![StatusCode::NOT_FOUND],
            ),
            (
                session.clone(),
                get("/api/v1/mail-trace/transaction/11111111-1111-1111-1111-111111111111"),
                vec![StatusCode::NOT_FOUND, StatusCode::SERVICE_UNAVAILABLE],
            ),
            (
                session.clone(),
                post_mail_trace_search("{"),
                vec![StatusCode::BAD_REQUEST],
            ),
            (
                session,
                post_mail_trace_search(r#"{"q":"ab"}"#),
                vec![StatusCode::BAD_REQUEST],
            ),
        ];
        for (app, request, expected) in cases {
            let response = app.oneshot(request).await.expect("the route must answer");
            let status = response.status();
            assert!(
                expected.contains(&status),
                "unexpected status {status}, expected one of {expected:?}"
            );
            let raw = body_text(response).await;
            assert_static_error_body(&raw);
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}

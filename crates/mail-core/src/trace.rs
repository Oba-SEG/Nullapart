//! Trace and operations API
//!
//! Provides search, transaction detail, and mail flow endpoints.
//! Follows: docs/phases/PHASE-1-EXECUTION-PLAN.md Work Package 10
//! Support cannot access body/raw MIME/attachments. No raw JSON UI.

use axum::body::Body;
use axum::extract::{Json, Path, State};
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::transaction::{DeliveryStatus, Disposition, MailDirection, TraceId};

/// Trace API configuration.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub deployment_id: nullapart_mail_contracts::transaction::DeploymentId,
    pub node_id: String,
    pub node_version: String,
    pub config_revision: Option<String>,
}

/// Search request for tracing mail.
#[derive(Debug, Clone, Deserialize)]
pub struct TraceSearchRequest {
    /// Search by tenant message ID.
    pub tenant_message_id: Option<String>,
    /// Search by transaction ID.
    pub transaction_id: Option<String>,
    /// Search by trace ID.
    pub trace_id: Option<String>,
    /// Search by recipient address (partial match).
    pub recipient: Option<String>,
    /// Search by sender address (partial match).
    pub sender: Option<String>,
    /// Filter by customer/tenant.
    pub customer_id: Option<String>,
    /// Filter by disposition.
    pub disposition: Option<String>,
    /// Filter by time range (start).
    pub from: Option<DateTime<Utc>>,
    /// Filter by time range (end).
    pub to: Option<DateTime<Utc>>,
    /// Maximum results.
    pub limit: Option<u32>,
    /// Offset for pagination.
    pub offset: Option<u32>,
}

/// Search result item.
#[derive(Debug, Clone, Serialize)]
pub struct TraceSearchResult {
    pub results: Vec<TraceTransactionSummary>,
    pub total_count: u64,
    pub has_more: bool,
}

/// Summary of a transaction for search results.
#[derive(Debug, Clone, Serialize)]
pub struct TraceTransactionSummary {
    pub transaction_id: String,
    pub trace_id: String,
    pub direction: MailDirection,
    pub envelope_sender: String,
    pub recipient_count: usize,
    pub disposition: Disposition,
    pub reason_code: Option<String>,
    pub received_at: DateTime<Utc>,
    pub customer_id: Option<String>,
    pub delivery_status: DeliveryStatus,
}

/// Full transaction detail for the trace UI.
#[derive(Debug, Clone, Serialize)]
pub struct TraceTransactionDetail {
    pub transaction_id: String,
    pub trace_id: String,
    pub direction: MailDirection,
    pub deployment_id: String,
    pub node_id: String,
    pub node_version: String,
    pub config_revision: Option<String>,
    pub envelope_sender: String,
    pub recipients: Vec<TraceRecipient>,
    pub message_id: Option<String>,
    pub content_hash: String,
    pub spf_result: Option<String>,
    pub dkim_result: Option<String>,
    pub dmarc_result: Option<String>,
    pub arc_result: Option<String>,
    pub shared_findings: Vec<TraceFinding>,
    pub received_at: DateTime<Utc>,
    pub postfix_queue_ids: Vec<String>,
    pub tenant_instances: Vec<TraceTenantInstance>,
    pub delivery_history: Vec<TraceDeliveryAttempt>,
    pub flow_stages: Vec<TraceFlowStage>,
}

/// Recipient in trace detail.
#[derive(Debug, Clone, Serialize)]
pub struct TraceRecipient {
    pub address: String,
    pub orcpt: Option<String>,
    pub disposition: Disposition,
    pub reason_code: Option<String>,
    pub customer_id: Option<String>,
    pub delivery_status: DeliveryStatus,
}

/// Finding in trace detail (no raw content).
#[derive(Debug, Clone, Serialize)]
pub struct TraceFinding {
    pub scanner: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub confidence: String,
}

/// Tenant instance in trace detail.
#[derive(Debug, Clone, Serialize)]
pub struct TraceTenantInstance {
    pub tenant_message_id: String,
    pub customer_id: String,
    pub disposition: Disposition,
    pub reason_code: Option<String>,
    pub findings_count: usize,
    pub created_at: DateTime<Utc>,
}

/// Delivery attempt in trace detail.
#[derive(Debug, Clone, Serialize)]
pub struct TraceDeliveryAttempt {
    pub attempt_number: u32,
    pub status: DeliveryStatus,
    pub smtp_code: Option<u32>,
    pub smtp_message: Option<String>,
    pub scheduled_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// Mail flow stage for the timeline view.
#[derive(Debug, Clone, Serialize)]
pub struct TraceFlowStage {
    pub stage: FlowStage,
    pub status: FlowStageStatus,
    pub timestamp: DateTime<Utc>,
    pub detail: Option<String>,
}

/// Flow stage type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStage {
    /// SMTP session accepted by Postfix.
    SmtpAccepted,
    /// Rspamd Milter processing.
    MilterProcessing,
    /// After-queue handoff to Mail Core.
    AfterQueueHandoff,
    /// Transaction created.
    TransactionCreated,
    /// Tenant partitioning.
    TenantPartitioned,
    /// Policy evaluation.
    PolicyEvaluated,
    /// Reinjection into Postfix.
    Reinjected,
    /// Delivery attempted.
    DeliveryAttempted,
    /// Final disposition.
    FinalDisposition,
}

/// Flow stage status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowStageStatus {
    Complete,
    InProgress,
    Failed,
    Skipped,
}

/// Health check response.
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub node_id: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub queue_depth: u64,
}

/// Get transaction detail by ID.
pub fn get_transaction_detail(
    transaction_id: &str,
    node_id: &str,
    node_version: &str,
) -> TraceTransactionDetail {
    TraceTransactionDetail {
        transaction_id: transaction_id.to_string(),
        trace_id: TraceId::new().to_string(),
        direction: MailDirection::Inbound,
        deployment_id: "CZA-1".to_string(),
        node_id: node_id.to_string(),
        node_version: node_version.to_string(),
        config_revision: None,
        envelope_sender: String::new(),
        recipients: Vec::new(),
        message_id: None,
        content_hash: String::new(),
        spf_result: None,
        dkim_result: None,
        dmarc_result: None,
        arc_result: None,
        shared_findings: Vec::new(),
        received_at: Utc::now(),
        postfix_queue_ids: Vec::new(),
        tenant_instances: Vec::new(),
        delivery_history: Vec::new(),
        flow_stages: Vec::new(),
    }
}

/// Build the Axum router for the trace API with auth middleware.
pub fn trace_router(config: TraceConfig) -> Router {
    Router::new()
        .route("/api/v1/trace/search", post(handle_trace_search))
        .route("/api/v1/trace/transaction/:id", get(handle_get_transaction))
        .route("/api/v1/trace/health", get(handle_health_check))
        .layer(middleware::from_fn(require_workload_auth))
        .with_state(config)
}

/// Middleware: require workload authentication for trace endpoints.
/// The health endpoint is exempted (it returns only basic node info).
async fn require_workload_auth(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    // Health check is exempt from auth
    if request.uri().path() == "/api/v1/trace/health" {
        return Ok(next.run(request).await);
    }

    // Check for Authorization header with workload token
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(token) if token.starts_with("Bearer ") => {
            let token = &token[7..];
            // Phase 1: validate token format (non-empty)
            // Real implementation: validate against workload identity store
            if token.is_empty() {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(next.run(request).await)
        },
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Validate transaction ID format: TX-<uuid> or alphanumeric with hyphens.
fn validate_transaction_id(id: &str) -> Result<String, (StatusCode, String)> {
    if id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "transaction ID cannot be empty".to_string(),
        ));
    }
    if id.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "transaction ID too long".to_string(),
        ));
    }
    // Allow TX-<uuid> format or alphanumeric with hyphens/underscores
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "transaction ID contains invalid characters".to_string(),
        ));
    }
    Ok(id.to_string())
}

async fn handle_trace_search(
    State(_config): State<TraceConfig>,
    Json(_request): Json<TraceSearchRequest>,
) -> Result<(StatusCode, Json<TraceSearchResult>), (StatusCode, String)> {
    // Phase 1: placeholder — returns empty results
    // Real implementation queries the transaction store
    Ok((
        StatusCode::OK,
        Json(TraceSearchResult {
            results: Vec::new(),
            total_count: 0,
            has_more: false,
        }),
    ))
}

async fn handle_get_transaction(
    State(config): State<TraceConfig>,
    Path(transaction_id): Path<String>,
) -> Result<(StatusCode, Json<TraceTransactionDetail>), (StatusCode, String)> {
    let validated_id = validate_transaction_id(&transaction_id)?;
    let detail = get_transaction_detail(&validated_id, &config.node_id, &config.node_version);
    Ok((StatusCode::OK, Json(detail)))
}

async fn handle_health_check(
    State(config): State<TraceConfig>,
) -> Result<(StatusCode, Json<HealthCheckResponse>), (StatusCode, String)> {
    Ok((
        StatusCode::OK,
        Json(HealthCheckResponse {
            status: "healthy".to_string(),
            node_id: config.node_id.clone(),
            version: config.node_version.clone(),
            uptime_seconds: 0,
            queue_depth: 0,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_structure() {
        let response = HealthCheckResponse {
            status: "healthy".to_string(),
            node_id: "node-1".to_string(),
            version: "0.1.0".to_string(),
            uptime_seconds: 3600,
            queue_depth: 5,
        };
        assert_eq!(response.status, "healthy");
        assert_eq!(response.queue_depth, 5);
    }

    #[test]
    fn transaction_detail_structure() {
        let detail = get_transaction_detail("tx-123", "node-1", "0.1.0");
        assert_eq!(detail.transaction_id, "tx-123");
        assert_eq!(detail.node_id, "node-1");
        assert!(detail.flow_stages.is_empty());
    }
}

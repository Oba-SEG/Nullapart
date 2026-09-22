//! Mail processing pipeline
//!
//! End-to-end pipeline stages: receive → parse → authenticate → scan → policy → deliver.
//! Pipeline stages are defined per `docs/phases/PHASE-1-EXECUTION-PLAN.md` (1.3–1.8).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{
    transaction::{
        AuthResult, ConnectionId, ContentHash, Disposition, EnvelopeSender, MailDirection,
        Recipient, TraceId,
    },
    CustomerId, DeploymentId, SecurityFinding, TransactionId,
};

/// Pipeline stage identifier for tracking and observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    Receive,
    Parse,
    Authenticate,
    Scan,
    Policy,
    Partition,
    Deliver,
    Complete,
    Failed,
}

/// The result of the full pipeline execution for one SMTP transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Transaction ID.
    pub transaction_id: TransactionId,
    /// Current pipeline stage.
    pub stage: PipelineStage,
    /// Overall disposition.
    pub disposition: Disposition,
    /// Stable reason code.
    pub reason_code: String,
    /// Effective policy revision.
    pub policy_revision: i64,
    /// Tenant message instances created.
    pub tenant_instances: Vec<TenantInstanceResult>,
    /// Shared findings from content-intrinsic analysis.
    pub shared_findings: Vec<SecurityFinding>,
    /// When processing started.
    pub started_at: DateTime<Utc>,
    /// When processing completed.
    pub completed_at: DateTime<Utc>,
    /// Total processing duration in milliseconds.
    pub duration_ms: u64,
    /// Error message if pipeline failed.
    pub error: Option<String>,
}

/// Result for one tenant message instance after partitioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantInstanceResult {
    pub tenant_message_id: String,
    pub customer_id: CustomerId,
    pub disposition: Disposition,
    pub reason_code: String,
    pub findings_count: usize,
    pub delivered: bool,
    pub delivery_attempts: u32,
    pub last_smtp_code: Option<u32>,
    pub last_smtp_message: Option<String>,
}

/// SMTP transaction context passed through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpPipelineContext {
    pub transaction_id: TransactionId,
    pub deployment_id: DeploymentId,
    pub direction: MailDirection,
    pub connection_id: ConnectionId,
    pub envelope_sender: EnvelopeSender,
    pub recipients: Vec<Recipient>,
    pub message_id: Option<String>,
    pub spf_result: Option<AuthResult>,
    pub dkim_result: Option<AuthResult>,
    pub dmarc_result: Option<AuthResult>,
    pub content_hash: ContentHash,
    pub mime_artifact_id: String,
    pub received_at: DateTime<Utc>,
    pub postfix_queue_ids: Vec<String>,
    pub trace_id: TraceId,
    /// Trusted Rspamd/milter observations.
    pub milter_observations: Vec<MilterObservation>,
}

/// A single trusted observation from the Rspamd milter stage (pre-queue).
/// This is the per-source observation; the aggregated after-queue version
/// is `MilterObservations` in the handoff module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MilterObservation {
    pub source: String,
    pub score: Option<f64>,
    pub symbols: Vec<String>,
    pub action: Option<String>,
    pub is_spam: bool,
}

/// After-queue handoff input from Postfix to Mail Core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AfterQueueHandoff {
    /// Original Postfix queue ID.
    pub postfix_queue_id: String,
    /// Deployment/node identity.
    pub deployment_id: DeploymentId,
    /// Envelope sender.
    pub envelope_sender: EnvelopeSender,
    /// Accepted recipients.
    pub recipients: Vec<Recipient>,
    /// DSN/envelope metadata.
    pub dsn_status: Option<String>,
    /// Connection/source facts safe to trust.
    pub connection: SmtpPipelineContext,
    /// Raw message artifact reference.
    pub artifact_id: String,
    /// Trace identity.
    pub trace_id: TraceId,
    /// When Postfix accepted the message.
    pub accepted_at: DateTime<Utc>,
}

/// Delivery attempt result for one tenant message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttemptResult {
    pub attempt_id: String,
    pub attempt_number: u32,
    pub success: bool,
    pub smtp_code: Option<u32>,
    pub smtp_message: Option<String>,
    pub enhanced_code: Option<String>,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub completed_at: DateTime<Utc>,
}

/// Postfix reinjection request for an allowed tenant message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinjectionRequest {
    pub tenant_message_id: String,
    pub transaction_id: TransactionId,
    pub customer_id: CustomerId,
    pub envelope_sender: EnvelopeSender,
    pub recipients: Vec<Recipient>,
    pub artifact_id: String,
    pub trace_id: TraceId,
    pub loop_prevention_header: String,
}

/// Pipeline configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub deployment_id: DeploymentId,
    /// Maximum processing timeout for the full pipeline.
    pub pipeline_timeout_ms: u64,
    /// Maximum recipients per transaction.
    pub max_recipients: u32,
    /// Maximum message size in bytes.
    pub max_message_size: u64,
    /// Whether to quarantine on scanner error.
    pub quarantine_on_scanner_error: bool,
    /// Default disposition when policy cannot be evaluated.
    pub default_disposition: Disposition,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            deployment_id: DeploymentId("CZA-1".to_string()),
            pipeline_timeout_ms: 30_000,
            max_recipients: 500,
            max_message_size: 50 * 1024 * 1024, // 50MB
            quarantine_on_scanner_error: true,
            default_disposition: Disposition::Hold,
        }
    }
}

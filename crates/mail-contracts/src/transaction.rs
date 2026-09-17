//! SMTP Transaction and Tenant Message Instance types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ActorId, ArtifactId, PolicyRevisionId, SecurityFinding};

/// Unique transaction ID for an SMTP transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionId(pub Uuid);

impl TransactionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TX-{}", self.0)
    }
}

/// Unique tenant message instance ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantMessageId(pub Uuid);

impl TenantMessageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TenantMessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TenantMessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TM-{}", self.0)
    }
}

/// Unique delivery attempt ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeliveryAttemptId(pub Uuid);

impl DeliveryAttemptId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for DeliveryAttemptId {
    fn default() -> Self {
        Self::new()
    }
}

/// Trace ID for distributed tracing
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(pub Uuid);

impl TraceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TRACE-{}", self.0)
    }
}

/// Direction of mail flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailDirection {
    Inbound,
    Outbound,
}

/// SMTP Transaction - represents the shared SMTP submission and immutable content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpTransaction {
    /// Unique transaction ID
    pub id: TransactionId,

    /// Direction: inbound or outbound
    pub direction: MailDirection,

    /// Region/deployment where this transaction is processed
    pub deployment_id: DeploymentId,

    /// Source connection/session identity
    pub connection_id: ConnectionId,

    /// Envelope sender (MAIL FROM)
    pub envelope_sender: EnvelopeSender,

    /// All originally accepted recipients (RCPT TO)
    pub recipients: Vec<Recipient>,

    /// RFC Message-ID header
    pub message_id: Option<String>,

    /// Trusted SPF result
    pub spf_result: Option<AuthResult>,

    /// Trusted DKIM verification result
    pub dkim_result: Option<AuthResult>,

    /// Trusted DMARC alignment/result
    pub dmarc_result: Option<AuthResult>,

    /// ARC validation state where applicable
    pub arc_result: Option<ArcResult>,

    /// Raw MIME artifact reference
    pub mime_artifact_id: ArtifactId,

    /// Normalized MIME structure hash
    pub content_hash: ContentHash,

    /// Shared scanner findings that are content-intrinsic
    pub shared_findings: Vec<SecurityFinding>,

    /// When the message was received
    pub received_at: DateTime<Utc>,

    /// Original Postfix queue ID(s) where applicable
    pub postfix_queue_ids: Vec<String>,

    /// Trace ID for distributed tracing
    pub trace_id: TraceId,
}

/// Tenant Message Instance - customer-scoped evaluation and disposition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMessageInstance {
    /// Unique tenant message ID
    pub id: TenantMessageId,

    /// Parent transaction ID
    pub transaction_id: TransactionId,

    /// Customer/tenant ID
    pub customer_id: CustomerId,

    /// Customer-scoped recipients
    pub recipients: Vec<Recipient>,

    /// Effective policy revision at time of evaluation
    pub policy_revision: PolicyRevisionId,

    /// Tenant-specific scanner findings
    pub findings: Vec<SecurityFinding>,

    /// Disposition decision
    pub disposition: Disposition,

    /// Quarantine/hold state
    pub quarantine_state: Option<QuarantineState>,

    /// Delivery attempts and downstream SMTP results
    pub delivery_attempts: Vec<DeliveryAttempt>,

    /// Security/remediation state
    pub remediation_state: Option<RemediationState>,
}

/// Connection/source identity from SMTP session
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionId(pub String);

impl ConnectionId {
    pub fn new(id: String) -> Self {
        Self(id)
    }
}

/// Deployment/region identity
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeploymentId(pub String);

impl DeploymentId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

/// Customer/tenant identity
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CustomerId(pub String);

impl CustomerId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

/// Envelope sender (MAIL FROM)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvelopeSender(pub String);

impl EnvelopeSender {
    pub fn new(addr: &str) -> Self {
        Self(addr.to_string())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty() || self.0 == "<>"
    }

    pub fn address(&self) -> &str {
        &self.0
    }
}

/// Recipient (RCPT TO)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Recipient {
    pub address: String,
    pub orcpt: Option<String>,
    pub notify: Option<Vec<NotifyOption>>,
}

/// DSN NOTIFY options
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NotifyOption {
    Success,
    Failure,
    Delay,
}

/// Authentication result (SPF, DKIM, DMARC)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub result: AuthResultType,
    pub detail: Option<String>,
    pub identity: Option<String>,
    pub selector: Option<String>,
    pub domain: Option<String>,
}

/// Authentication result type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthResultType {
    Pass,
    Fail,
    Softfail,
    Neutral,
    None,
    Permerror,
    Temperror,
}

/// ARC result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcResult {
    pub seal: ArcSealStatus,
    pub chain_status: ArcChainStatus,
    pub results: Vec<AuthResult>,
}

/// ARC seal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArcSealStatus {
    Pass,
    Fail,
    None,
}

/// ARC chain status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArcChainStatus {
    Pass,
    Fail,
    BestHeaderPass,
    None,
}

/// Content hash
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub String);

impl ContentHash {
    pub fn new(hash: &str) -> Self {
        Self(hash.to_string())
    }
}

/// Message disposition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Allow,
    Quarantine,
    Reject,
    Hold,
    Defer,
}

/// Quarantine state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineState {
    pub quarantined_at: DateTime<Utc>,
    pub reason: String,
    pub released_at: Option<DateTime<Utc>>,
    pub released_by: Option<ActorId>,
}

/// Remediation state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationState {
    pub state: RemediationType,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub action: Option<String>,
}

/// Remediation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemediationType {
    None,
    Quarantined,
    Deleted,
    Rewritten,
    NotifyAdmin,
}

/// Delivery attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    pub id: DeliveryAttemptId,
    pub attempt_number: u32,
    pub scheduled_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: DeliveryResult,
    pub downstream_smtp_response: Option<String>,
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// Delivery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResult {
    pub status: DeliveryStatus,
    pub code: Option<u32>,
    pub enhanced_code: Option<EnhancedCode>,
    pub message: Option<String>,
}

/// Delivery status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    Pending,
    InProgress,
    Success,
    TransientFailure,
    PermanentFailure,
    Bounced,
}

/// SMTP enhanced status code
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnhancedCode {
    pub class: u8,
    pub subject: u8,
    pub detail: u8,
}

impl std::fmt::Display for EnhancedCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

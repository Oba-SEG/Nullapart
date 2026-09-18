//! Security Finding types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Security finding from scanners
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Unique finding ID
    pub id: FindingId,

    /// Finding scope: transaction, content, tenant, or recipient
    pub scope: FindingScope,

    /// Scanner that produced this finding
    pub scanner: ScannerType,

    /// Scanner-specific status/result
    pub scanner_status: ScannerStatus,

    /// Normalized severity
    pub severity: FindingSeverity,

    /// Confidence level
    pub confidence: Confidence,

    /// Category of finding
    pub category: FindingCategory,

    /// Human-readable description
    pub description: String,

    /// Technical details (JSON)
    pub details: Option<serde_json::Value>,

    /// Symbols/indicators found
    pub indicators: Vec<Indicator>,

    /// When the finding was generated
    pub created_at: DateTime<Utc>,

    /// Whether this is a false positive
    pub false_positive: bool,

    /// Parent transaction ID if scoped to transaction
    pub transaction_id: Option<crate::transaction::TransactionId>,

    /// Tenant message ID if scoped to tenant
    pub tenant_message_id: Option<crate::transaction::TenantMessageId>,
}

/// Finding ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingId(pub Uuid);

impl FindingId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for FindingId {
    fn default() -> Self {
        Self::new()
    }
}

/// Finding scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingScope {
    Transaction,
    Content,
    Tenant,
    Recipient,
}

/// Scanner type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScannerType {
    Clamav,
    Rspamd,
    UrlAnalysis,
    Attachment,
    Dkim,
    Spf,
    Dmarc,
    Arc,
    InlineMl,
    DeepAi,
    Custom,
}

/// Scanner status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScannerStatus {
    Clean,
    Threat,
    Suspicious,
    Unknown,
    Error,
    NotApplicable,
}

/// Finding severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Finding category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Malware,
    Phishing,
    Spam,
    Spoofing,
    BusinessEmailCompromise,
    CredentialHarvest,
    MaliciousUrl,
    MaliciousAttachment,
    SuspiciousContent,
    PolicyViolation,
    AuthFailure,
    Reputation,
    Unknown,
}

/// Indicator found by scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub context: Option<String>,
}

/// Indicator type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Url,
    Domain,
    IpAddress,
    EmailAddress,
    Hash,
    FileName,
    FileType,
    Regex,
    Behavior,
}

/// Failed scanner state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerFailure {
    pub scanner: ScannerType,
    pub failure_type: FailureType,
    pub message: String,
    pub retryable: bool,
    pub failed_at: DateTime<Utc>,
}

/// Failure type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureType {
    Unavailable,
    Timeout,
    Error,
    ResourceLimit,
}

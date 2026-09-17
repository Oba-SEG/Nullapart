//! Scanner SDK types
//!
//! Shared types for scanner integration: scan requests, results, findings, and status.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::trait_defs::ScannerId;

/// Scan request sent to a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Unique request ID for idempotency.
    pub request_id: Uuid,
    /// Transaction ID being scanned.
    pub transaction_id: String,
    /// Tenant message ID if scoped to tenant.
    pub tenant_message_id: Option<String>,
    /// Customer/tenant ID.
    pub customer_id: Option<String>,
    /// Deployment ID.
    pub deployment_id: String,
    /// Artifact reference (MIME content).
    pub artifact_id: String,
    /// Content type of the artifact.
    pub content_type: String,
    /// Content hash for dedup/caching.
    pub content_hash: String,
    /// Maximum time allowed for this scan.
    pub timeout_ms: u64,
    /// When the scan was requested.
    pub requested_at: DateTime<Utc>,
    /// Additional scanner-specific parameters.
    pub params: serde_json::Value,
}

/// Result returned by a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Request ID this result corresponds to.
    pub request_id: Uuid,
    /// Scanner identity.
    pub scanner_id: ScannerId,
    /// Scanner-specific status/result code.
    pub status: ScannerStatus,
    /// Human-readable status message.
    pub message: Option<String>,
    /// Findings produced by this scanner.
    pub findings: Vec<ScannerFinding>,
    /// When the scan completed.
    pub completed_at: DateTime<Utc>,
    /// Scan duration in milliseconds.
    pub duration_ms: u64,
    /// Scanner-specific details (JSON).
    pub details: Option<serde_json::Value>,
}

/// A single finding from a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerFinding {
    /// Unique finding ID.
    pub id: Uuid,
    /// Normalized severity.
    pub severity: FindingSeverity,
    /// Finding category (e.g., "malware", "phishing", "spam").
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Technical details (JSON).
    pub details: Option<serde_json::Value>,
    /// Indicators found (URLs, domains, IPs, hashes).
    pub indicators: Vec<FindingIndicator>,
    /// Whether this is a false positive.
    pub false_positive: bool,
}

/// Normalized finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Clean,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// An indicator found in a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub context: Option<String>,
}

/// Type of indicator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Url,
    Domain,
    Ip,
    Hash,
    Email,
    Certificate,
    Header,
    Raw,
}

/// Scanner capabilities description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerCapabilities {
    /// What content types this scanner can handle.
    pub supported_content_types: Vec<String>,
    /// Maximum content size in bytes.
    pub max_content_size: u64,
    /// Latency class: "fast" (<100ms), "medium" (<1s), "slow" (>1s).
    pub latency_class: LatencyClass,
    /// Whether this scanner requires network access.
    pub requires_network: bool,
    /// Whether this scanner can run in the Milter path (pre-queue).
    pub milter_compatible: bool,
    /// Scanner-specific capabilities (JSON).
    pub extra: serde_json::Value,
}

/// Scanner latency classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    Fast,
    Medium,
    Slow,
}

/// Scanner health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerHealth {
    pub healthy: bool,
    pub message: Option<String>,
    pub checked_at: DateTime<Utc>,
    pub uptime_seconds: Option<u64>,
    pub queue_depth: Option<u32>,
}

/// Scanner operational status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerStatus {
    Clean,
    Threat,
    Suspicious,
    Error,
    Timeout,
    ResourceLimit,
    Unsupported,
}

impl std::fmt::Display for ScannerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::Threat => write!(f, "threat"),
            Self::Suspicious => write!(f, "suspicious"),
            Self::Error => write!(f, "error"),
            Self::Timeout => write!(f, "timeout"),
            Self::ResourceLimit => write!(f, "resource_limit"),
            Self::Unsupported => write!(f, "unsupported"),
        }
    }
}

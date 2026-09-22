//! Scanner SDK types
//!
//! Shared types for scanner integration: scan requests, results, findings, and status.
//! Canonical types live in `nullapart-mail-contracts`; this module re-exports them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Re-export canonical types from mail-contracts
pub use nullapart_mail_contracts::{FindingSeverity, ScannerStatus};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_request_serde_roundtrip() {
        let req = ScanRequest {
            request_id: Uuid::new_v4(),
            transaction_id: "tx-001".to_string(),
            tenant_message_id: Some("msg-001".to_string()),
            customer_id: Some("cust-001".to_string()),
            deployment_id: "CZA-1".to_string(),
            artifact_id: "artifact-001".to_string(),
            content_type: "message/rfc822".to_string(),
            content_hash: "sha256:abc123".to_string(),
            timeout_ms: 5000,
            requested_at: Utc::now(),
            params: serde_json::json!({"max_depth": 3}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ScanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.request_id, back.request_id);
        assert_eq!(req.transaction_id, back.transaction_id);
        assert_eq!(req.deployment_id, back.deployment_id);
    }

    #[test]
    fn scan_result_serde_roundtrip() {
        let result = ScanResult {
            request_id: Uuid::new_v4(),
            scanner_id: ScannerId::new("clamav"),
            status: ScannerStatus::Clean,
            message: None,
            findings: vec![],
            completed_at: Utc::now(),
            duration_ms: 42,
            details: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.request_id, back.request_id);
        assert_eq!(result.status, ScannerStatus::Clean);
    }

    #[test]
    fn scanner_finding_serde_roundtrip() {
        let finding = ScannerFinding {
            id: Uuid::new_v4(),
            severity: FindingSeverity::High,
            category: "malware".to_string(),
            description: "EICAR test file detected".to_string(),
            details: Some(serde_json::json!({"engine": "clamav"})),
            indicators: vec![FindingIndicator {
                indicator_type: IndicatorType::Hash,
                value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                    .to_string(),
                context: None,
            }],
            false_positive: false,
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: ScannerFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding.severity, FindingSeverity::High);
        assert_eq!(back.indicators.len(), 1);
        assert_eq!(back.indicators[0].indicator_type, IndicatorType::Hash);
    }

    #[test]
    fn scanner_capabilities_serde_roundtrip() {
        let caps = ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: 52_428_800,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: true,
            extra: serde_json::json!({}),
        };
        let json = serde_json::to_string(&caps).unwrap();
        let back: ScannerCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(back.latency_class, LatencyClass::Fast);
        assert!(back.milter_compatible);
    }

    #[test]
    fn scanner_health_serde_roundtrip() {
        let health = ScannerHealth {
            healthy: true,
            message: Some("OK".to_string()),
            checked_at: Utc::now(),
            uptime_seconds: Some(86400),
            queue_depth: Some(0),
        };
        let json = serde_json::to_string(&health).unwrap();
        let back: ScannerHealth = serde_json::from_str(&json).unwrap();
        assert!(back.healthy);
        assert_eq!(back.uptime_seconds, Some(86400));
    }

    #[test]
    fn finding_severity_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&FindingSeverity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(
            serde_json::to_string(&FindingSeverity::Info).unwrap(),
            "\"info\""
        );
    }

    #[test]
    fn scanner_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&ScannerStatus::Clean).unwrap(),
            "\"clean\""
        );
        assert_eq!(
            serde_json::to_string(&ScannerStatus::NotApplicable).unwrap(),
            "\"not_applicable\""
        );
    }

    #[test]
    fn indicator_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&IndicatorType::Url).unwrap(),
            "\"url\""
        );
        assert_eq!(
            serde_json::to_string(&IndicatorType::Certificate).unwrap(),
            "\"certificate\""
        );
    }
}

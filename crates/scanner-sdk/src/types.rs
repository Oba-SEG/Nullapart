//! Scanner SDK types
//!
//! Shared types for scanner integration: scan requests, results, findings, and status.
//! Canonical types live in `nullapart-mail-contracts`; this module re-exports them.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use nullapart_mail_contracts::transaction::{
    ContentHash, CustomerId, DeploymentId, TenantMessageId, TransactionId,
};
use nullapart_mail_contracts::{ArtifactId, ContentType};

pub use nullapart_mail_contracts::{FindingSeverity, Indicator, IndicatorType, ScannerStatus};

use crate::contract::{validate_scanner_contract_version, UnsupportedContractVersion};
use crate::trait_defs::ScannerId;

/// Execution class for a scanner (`docs/05-SCANNER-FABRIC.md`).
///
/// REQUIRED scanners participate in required coverage: if an applicable REQUIRED
/// scanner cannot produce a definite result, the fabric outcome is inconclusive
/// and fails safe. OPTIONAL scanners contribute enrichment evidence only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    FastRequired,
    StandardRequired,
    OptionalEnrichment,
    DeepAnalysis,
}

impl ExecutionClass {
    /// Whether this execution class participates in REQUIRED coverage.
    pub fn is_required(self) -> bool {
        matches!(self, Self::FastRequired | Self::StandardRequired)
    }
}

/// Per-scanner resource limits (`docs/phases/PHASE-2-SCANNER-FABRIC.md`).
///
/// Limits are carried on every [`ScanRequest`] so a scanner enforces them at the
/// parser boundary; the fabric additionally enforces the wall-clock deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum input bytes accepted for one scan.
    pub max_input_bytes: u64,
    /// Maximum total expanded/decompressed bytes.
    pub max_expanded_bytes: u64,
    /// Maximum recursion/nesting depth.
    pub max_nesting_depth: u32,
    /// Maximum entry/attachment count.
    pub max_attachment_count: u32,
    /// Maximum memory budget in bytes.
    pub max_memory_bytes: u64,
    /// Maximum temporary disk usage in bytes.
    pub max_temp_disk_bytes: u64,
    /// Maximum OCR page count.
    pub max_ocr_pages: u32,
    /// Maximum OCR pixel count.
    pub max_ocr_pixels: u64,
    /// Maximum URL count inspected.
    pub max_url_count: u32,
    /// Maximum redirect count followed.
    pub max_redirect_count: u32,
}

impl ResourceLimits {
    /// Conservative defaults suitable for bounded in-process analysis.
    pub fn bounded_defaults() -> Self {
        Self {
            max_input_bytes: 50 * 1024 * 1024,
            max_expanded_bytes: 200 * 1024 * 1024,
            max_nesting_depth: 10,
            max_attachment_count: 256,
            max_memory_bytes: 512 * 1024 * 1024,
            max_temp_disk_bytes: 1024 * 1024 * 1024,
            max_ocr_pages: 50,
            max_ocr_pixels: 40_000_000,
            max_url_count: 500,
            max_redirect_count: 10,
        }
    }
}

/// Per-scanner execution profile enforced by the Scanner Fabric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerProfile {
    /// REQUIRED vs OPTIONAL classification.
    pub execution_class: ExecutionClass,
    /// Wall-clock deadline for a single scan (enforced by the fabric).
    pub wall_clock: Duration,
    /// Maximum concurrent scans against this scanner instance.
    pub max_concurrency: u32,
    /// Resource limits handed to the scanner on every request.
    pub limits: ResourceLimits,
}

/// Scan request sent to a scanner.
///
/// The request/result pair is an explicitly versioned SDK contract
/// (`docs/27-API-VERSIONING-FEATURE-FLAGS.md`): [`ScanRequest::contract_version`]
/// must be a supported version or consumers reject the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Deterministic per-scanner request ID derived by the fabric from the
    /// stable scan-operation correlation ID ([`crate::fabric::ScanTarget::request_id`])
    /// plus this scanner's [`ScannerId`]; the result must echo it unchanged.
    ///
    /// This is NOT the scan-operation correlation ID: one fabric scan keeps a
    /// single stable `ScanTarget::request_id` while each registered scanner
    /// receives its own derived `ScanRequest::request_id`.
    pub request_id: Uuid,
    /// Versioned scanner contract schema this request conforms to
    /// (`crate::contract::SCANNER_CONTRACT_VERSION`).
    pub contract_version: u32,
    /// Transaction ID being scanned.
    pub transaction_id: TransactionId,
    /// Tenant message instance if scoped to a tenant evaluation.
    pub tenant_message_id: Option<TenantMessageId>,
    /// Customer/tenant identity (server-derived, never a client-asserted ID).
    pub customer_id: Option<CustomerId>,
    /// Deployment ID.
    pub deployment_id: DeploymentId,
    /// Artifact reference (MIME content).
    pub artifact_id: ArtifactId,
    /// Content type of the artifact.
    pub content_type: ContentType,
    /// Content hash for dedup/caching.
    pub content_hash: ContentHash,
    /// Artifact size in bytes (for input-limit enforcement).
    pub artifact_size_bytes: u64,
    /// Maximum time allowed for this scan (mirrors the profile wall clock).
    pub timeout_ms: u64,
    /// Resource profile limits for this scan.
    pub limits: ResourceLimits,
    /// When the scan was requested.
    pub requested_at: DateTime<Utc>,
    /// Additional scanner-specific parameters.
    pub params: serde_json::Value,
}

/// Scanner runtime provenance carried on every [`ScanResult`] and copied
/// unchanged onto the matching fabric [`crate::fabric::ScannerOutcome`].
///
/// Audit metadata only (`docs/05-SCANNER-FABRIC.md`): records which node,
/// profile, engine and ruleset the scan started under. It is never exposed
/// via a network API or UI and is not persisted by the SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerProvenance {
    /// Stable/logical scanner runtime node ID.
    pub scanner_node_id: Option<String>,
    /// Scanner execution profile identity.
    pub scanner_profile_id: Option<String>,
    /// Version of the scanner profile applied to this scan.
    pub scanner_profile_version: Option<String>,
    /// Scanner engine (implementation) version.
    pub engine_version: Option<String>,
    /// Ruleset version loaded when the scan started.
    pub ruleset_version: Option<String>,
    /// When the scan started on the scanner runtime.
    pub started_at: DateTime<Utc>,
}

/// Result returned by a scanner.
///
/// Carries the same explicit contract version as [`ScanRequest`]; consumers
/// validate it via [`ScanResult::validate_contract`] and reject unsupported
/// versions rather than parsing unknown output optimistically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Per-scanner request ID this result corresponds to (echoed unchanged
    /// from [`ScanRequest::request_id`]).
    pub request_id: Uuid,
    /// Versioned scanner contract schema this result conforms to.
    pub contract_version: u32,
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
    /// Audit provenance of the scanner runtime that produced this result.
    pub provenance: ScannerProvenance,
}

impl ScanRequest {
    /// Validate the contract version carried by this request.
    pub fn validate_contract(&self) -> Result<(), UnsupportedContractVersion> {
        validate_scanner_contract_version(self.contract_version)
    }
}

impl ScanResult {
    /// Validate the contract version carried by this result.
    pub fn validate_contract(&self) -> Result<(), UnsupportedContractVersion> {
        validate_scanner_contract_version(self.contract_version)
    }
}

/// A single finding from a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerFinding {
    /// Unique finding ID.
    pub id: Uuid,
    /// Normalized severity.
    pub severity: FindingSeverity,
    /// Finding category label (e.g., "malware", "phishing", "spam").
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Technical details (JSON).
    pub details: Option<serde_json::Value>,
    /// Indicators found (URLs, domains, IPs, hashes).
    pub indicators: Vec<Indicator>,
    /// Whether this is a false positive.
    pub false_positive: bool,
}

/// Scanner capabilities description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerCapabilities {
    /// What content types this scanner can handle (empty = any; supports `*` and `prefix/*`).
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
    use crate::contract::DEFAULT_SCANNER_CONTRACT_VERSION;

    #[test]
    fn scan_request_serde_roundtrip() {
        let req = ScanRequest {
            request_id: Uuid::new_v4(),
            contract_version: DEFAULT_SCANNER_CONTRACT_VERSION,
            transaction_id: TransactionId::new(),
            tenant_message_id: Some(TenantMessageId::new()),
            customer_id: Some(CustomerId::new("cust-001")),
            deployment_id: DeploymentId::new("CZA-1"),
            artifact_id: ArtifactId::new(),
            content_type: ContentType::new("message/rfc822"),
            content_hash: ContentHash::new("sha256:abc123"),
            artifact_size_bytes: 4096,
            timeout_ms: 5000,
            limits: ResourceLimits::bounded_defaults(),
            requested_at: Utc::now(),
            params: serde_json::json!({"max_depth": 3}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ScanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.request_id, back.request_id);
        assert_eq!(req.contract_version, back.contract_version);
        assert!(back.validate_contract().is_ok());
        assert_eq!(req.transaction_id, back.transaction_id);
        assert_eq!(req.deployment_id, back.deployment_id);
        assert_eq!(req.artifact_id, back.artifact_id);
        assert_eq!(req.limits, back.limits);
    }

    #[test]
    fn scan_result_serde_roundtrip() {
        let result = ScanResult {
            request_id: Uuid::new_v4(),
            contract_version: DEFAULT_SCANNER_CONTRACT_VERSION,
            scanner_id: ScannerId::new("clamav"),
            status: ScannerStatus::Clean,
            message: None,
            findings: vec![],
            completed_at: Utc::now(),
            duration_ms: 42,
            details: None,
            provenance: ScannerProvenance {
                scanner_node_id: Some("node-1".to_string()),
                scanner_profile_id: Some("profile-1".to_string()),
                scanner_profile_version: Some("1.2.3".to_string()),
                engine_version: Some("9.9.9".to_string()),
                ruleset_version: Some("rs-42".to_string()),
                started_at: Utc::now(),
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.request_id, back.request_id);
        assert_eq!(result.contract_version, back.contract_version);
        assert!(back.validate_contract().is_ok());
        assert_eq!(result.status, ScannerStatus::Clean);
        assert_eq!(result.provenance, back.provenance);
    }

    #[test]
    fn scan_result_rejects_unsupported_contract_version() {
        let result = ScanResult {
            request_id: Uuid::new_v4(),
            contract_version: 99,
            scanner_id: ScannerId::new("clamav"),
            status: ScannerStatus::Clean,
            message: None,
            findings: vec![],
            completed_at: Utc::now(),
            duration_ms: 42,
            details: None,
            provenance: ScannerProvenance {
                scanner_node_id: None,
                scanner_profile_id: None,
                scanner_profile_version: None,
                engine_version: None,
                ruleset_version: None,
                started_at: Utc::now(),
            },
        };
        let error = result
            .validate_contract()
            .expect_err("unsupported contract version must be rejected");
        assert_eq!(error.version, 99);
    }

    #[test]
    fn scanner_finding_serde_roundtrip() {
        let finding = ScannerFinding {
            id: Uuid::new_v4(),
            severity: FindingSeverity::High,
            category: "malware".to_string(),
            description: "EICAR test file detected".to_string(),
            details: Some(serde_json::json!({"engine": "clamav"})),
            indicators: vec![Indicator {
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

    #[test]
    fn execution_class_required_mapping() {
        assert!(ExecutionClass::FastRequired.is_required());
        assert!(ExecutionClass::StandardRequired.is_required());
        assert!(!ExecutionClass::OptionalEnrichment.is_required());
        assert!(!ExecutionClass::DeepAnalysis.is_required());
    }
}

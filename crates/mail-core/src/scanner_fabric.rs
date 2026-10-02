//! Bounded post-queue scanner orchestration.
//!
//! Mail Core delegates execution to the SDK fabric
//! [`nullapart_scanner_sdk::fabric::ScannerFabric`]: local registrations and
//! profiles are converted to SDK registrations and profiles, and the SDK
//! [`nullapart_scanner_sdk::fabric::FabricOutcome`] is mapped onto this
//! module's result without re-normalizing untrusted scanner fields. Scanner
//! input is represented only by regional artifact metadata plus an explicit
//! [`ScanContent`] seam; raw MIME never moves through this interface as a
//! transport. `requires_hold` is taken from the SDK fabric's authoritative
//! inconclusive flag, never inferred from the presence of a failure, so an
//! empty or inapplicable required set never becomes a clean result.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use nullapart_mail_contracts::{
    artifact::{ArtifactId, ContentType},
    finding::{ScannerFailure, ScannerType, SecurityFinding},
    transaction::{
        ContentHash, CustomerId, DeploymentId, Disposition, TenantMessageId, TransactionId,
    },
};
use nullapart_scanner_sdk::{
    fabric::{
        FabricConfig, FabricError, ScanTarget, ScannerFabric as SdkScannerFabric, ScannerOutcome,
        ScannerRegistration as SdkScannerRegistration,
    },
    trait_defs::{ScanContent, Scanner, ScannerId},
    types::{ExecutionClass, ResourceLimits, ScannerProfile as SdkScannerProfile},
};
use uuid::Uuid;

/// Immutable regional artifact metadata supplied to post-queue scanners.
///
/// Every identity and artifact-metadata field is server-derived: the caller
/// never assembles it from client-supplied request data.
#[derive(Debug, Clone)]
pub struct ScanArtifact {
    /// Stable scan-operation correlation ID for the whole fabric run.
    pub request_id: Uuid,
    pub transaction_id: TransactionId,
    /// Tenant message instance if this scan is tenant-scoped.
    pub tenant_message_id: Option<TenantMessageId>,
    /// Customer/tenant identity from authenticated server context.
    pub customer_id: Option<CustomerId>,
    pub deployment_id: DeploymentId,
    pub artifact_id: ArtifactId,
    pub content_type: ContentType,
    pub content_hash: ContentHash,
    pub size_bytes: u64,
    /// Scanner-specific parameters handed to every scanner registered for
    /// this run (`Null` for the deterministic pass; structured stage
    /// parameters for the optional inline ML pass).
    pub params: serde_json::Value,
}

/// Whether scanner failure blocks policy/delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerRequirement {
    Required,
    Optional,
}

/// Per-scanner resource and failure profile.
#[derive(Debug, Clone)]
pub struct ScannerProfile {
    pub scanner_id: ScannerId,
    pub scanner_type: ScannerType,
    pub requirement: ScannerRequirement,
    pub max_input_bytes: u64,
    pub timeout: Duration,
    /// Explicit reviewed concurrency ceiling for this scanner, mapped
    /// unchanged onto the SDK profile. It must be nonzero so a registration
    /// can never silently inherit an unbounded per-scanner concurrency.
    pub max_concurrency: u32,
    /// Explicit hostile-content limits enforced by the adapter/isolation
    /// runtime in addition to fabric input and wall-clock limits.
    pub limits: ScannerResourceLimits,
}

/// Reviewed resource envelope for one scanner implementation. A scanner that
/// needs an unbounded parser, decompressor, redirect chain, or OCR workload is
/// invalid at configuration time rather than silently inheriting an unsafe
/// process default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerResourceLimits {
    pub max_expanded_bytes: u64,
    pub max_recursion_depth: u16,
    pub max_entries: u32,
    pub max_cpu_millis: u64,
    pub max_memory_bytes: u64,
    pub max_temp_disk_bytes: u64,
    pub max_ocr_pages: u16,
    pub max_ocr_pixels: u64,
    pub max_url_redirects: u8,
    /// Explicit reviewed ceiling on the number of URLs one scanner run may
    /// inspect, mapped unchanged onto the SDK profile. It must be nonzero so
    /// a registration can never silently inherit an unreviewed default.
    pub max_url_count: u32,
}

impl ScannerResourceLimits {
    pub fn bounded_default(max_input_bytes: u64) -> Self {
        Self {
            max_expanded_bytes: max_input_bytes.saturating_mul(8),
            max_recursion_depth: 8,
            max_entries: 1_000,
            max_cpu_millis: 10_000,
            max_memory_bytes: 512 * 1024 * 1024,
            max_temp_disk_bytes: 512 * 1024 * 1024,
            max_ocr_pages: 20,
            max_ocr_pixels: 100_000_000,
            max_url_redirects: 5,
            max_url_count: 50,
        }
    }

    fn is_valid(&self) -> bool {
        self.max_expanded_bytes > 0
            && self.max_recursion_depth > 0
            && self.max_entries > 0
            && self.max_cpu_millis > 0
            && self.max_memory_bytes > 0
            && self.max_temp_disk_bytes > 0
            && self.max_ocr_pages > 0
            && self.max_ocr_pixels > 0
            && self.max_url_redirects > 0
            && self.max_url_count > 0
    }
}

/// A registered scanner plus its reviewed execution profile.
#[derive(Clone)]
pub struct ScannerRegistration {
    pub scanner: Arc<dyn Scanner>,
    pub profile: ScannerProfile,
}

/// Bounded scanner-fabric configuration.
#[derive(Debug, Clone)]
pub struct ScannerFabricConfig {
    /// Maximum independent scanner executions for one artifact.
    pub max_concurrent_scans: usize,
}

impl Default for ScannerFabricConfig {
    fn default() -> Self {
        Self {
            max_concurrent_scans: 4,
        }
    }
}

/// Configuration error raised before hostile artifacts are dispatched.
#[derive(Debug, thiserror::Error)]
pub enum ScannerFabricConfigError {
    #[error("scanner concurrency must be greater than zero")]
    ZeroConcurrency,
    #[error("scanner profile ID does not match scanner implementation")]
    ScannerIdentityMismatch,
    #[error("scanner timeout must be greater than zero")]
    ZeroTimeout,
    #[error("scanner profile max concurrency must be greater than zero")]
    ZeroScannerMaxConcurrency,
    #[error("scanner resource limits must be explicitly bounded")]
    InvalidResourceLimits,
    #[error("scanner fabric rejected the registration")]
    FabricRejected,
}

/// Reviewed scanner profile fields retained with a result so durable evidence
/// records required/optional semantics without inferring them from status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerResultProfile {
    pub scanner_id: ScannerId,
    pub scanner_type: ScannerType,
    pub required: bool,
}

/// Aggregated scanner result for one artifact.
///
/// `findings`, `failures` and `results` are carried through from the SDK
/// [`nullapart_scanner_sdk::fabric::FabricOutcome`] unchanged: untrusted
/// scanner fields are never re-normalized at this boundary.
#[derive(Debug, Clone)]
pub struct ScannerFabricResult {
    /// Per-scanner outcomes ordered by scanner ID.
    pub results: Vec<ScannerOutcome>,
    pub scanner_profiles: Vec<ScannerResultProfile>,
    /// Normalized shared findings that can safely flow to tenant policy.
    pub findings: Vec<SecurityFinding>,
    /// Explicit scanner failures, clamped by the SDK fabric before delivery.
    pub failures: Vec<ScannerFailure>,
    /// A required scanner could not produce a trustworthy result, or no
    /// required coverage applied at all: the SDK fabric's authoritative
    /// inconclusive flag. The caller must hold/defer the message rather than
    /// treating it as clean.
    pub requires_hold: bool,
}

/// Sanitized operational status for one configured scanner capability.
///
/// `capability` is a product capability label, never an engine, binary,
/// library, version, endpoint, or scanner-specific error string. This makes
/// the projection safe for the authenticated operations UI while the
/// scanner implementation identity remains internal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerOperationStatus {
    pub capability: String,
    pub required: bool,
    pub healthy: bool,
    pub checked_at: chrono::DateTime<Utc>,
    pub queue_depth: Option<u32>,
}

/// Wall-clock deadline for one capability's health probe. A health future
/// that does not settle inside this bound is reported unhealthy with a fresh
/// timestamp: no adapter can extend the operations view's response time, and
/// every probe still runs concurrently so the projection costs at most one
/// deadline rather than one deadline per scanner.
const OPERATION_HEALTH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Clone)]
struct ScannerOperationRegistration {
    scanner: Arc<dyn Scanner>,
    profile: ScannerResultProfile,
}

/// Parallel scanner coordinator delegating to the SDK scanner fabric. This is
/// a module boundary, not a synchronous service chain.
pub struct ScannerFabric {
    fabric: SdkScannerFabric,
    profiles: Vec<ScannerResultProfile>,
    operations: Vec<ScannerOperationRegistration>,
}

impl ScannerFabric {
    pub fn new(
        config: ScannerFabricConfig,
        registrations: Vec<ScannerRegistration>,
    ) -> Result<Self, ScannerFabricConfigError> {
        if config.max_concurrent_scans == 0 {
            return Err(ScannerFabricConfigError::ZeroConcurrency);
        }
        for registration in &registrations {
            if registration.scanner.id() != registration.profile.scanner_id {
                return Err(ScannerFabricConfigError::ScannerIdentityMismatch);
            }
            if registration.profile.timeout.is_zero() {
                return Err(ScannerFabricConfigError::ZeroTimeout);
            }
            if registration.profile.max_concurrency == 0 {
                return Err(ScannerFabricConfigError::ZeroScannerMaxConcurrency);
            }
            if !registration.profile.limits.is_valid() {
                return Err(ScannerFabricConfigError::InvalidResourceLimits);
            }
        }
        let mut fabric = SdkScannerFabric::new(fabric_config(&config, &registrations))
            .map_err(fabric_config_error)?;
        for registration in &registrations {
            fabric
                .register(sdk_registration(registration))
                .map_err(fabric_config_error)?;
        }
        let profiles = registrations
            .iter()
            .map(|registration| ScannerResultProfile {
                scanner_id: registration.profile.scanner_id.clone(),
                scanner_type: registration.profile.scanner_type,
                required: registration.profile.requirement == ScannerRequirement::Required,
            })
            .collect::<Vec<_>>();
        let operations = registrations
            .iter()
            .zip(profiles.iter())
            .map(|(registration, profile)| ScannerOperationRegistration {
                scanner: Arc::clone(&registration.scanner),
                profile: profile.clone(),
            })
            .collect();
        Ok(Self {
            fabric,
            profiles,
            operations,
        })
    }

    /// Delegates one bounded scan to the SDK fabric. `content` must agree
    /// with `artifact` metadata; the SDK fabric acquires, verifies and shares
    /// one immutable snapshot across scanners. The hold requirement is the
    /// SDK fabric's authoritative inconclusive flag: empty or inapplicable
    /// required coverage and inconclusive required runs require a hold;
    /// optional failures alone never set it.
    pub async fn scan(
        &self,
        artifact: ScanArtifact,
        content: Arc<dyn ScanContent>,
    ) -> ScannerFabricResult {
        let outcome = self.fabric.scan(&scan_target(&artifact), content).await;
        let requires_hold = outcome.inconclusive;
        ScannerFabricResult {
            results: outcome.scanner_outcomes,
            scanner_profiles: self.profiles.clone(),
            findings: outcome.findings,
            failures: outcome.failures,
            requires_hold,
        }
    }

    /// Returns a bounded, content-free health projection for the configured
    /// scanner capabilities. Adapter-provided health messages are
    /// deliberately discarded because they may disclose engine versions,
    /// endpoints, or backend failure details.
    pub async fn operation_statuses(&self) -> Vec<ScannerOperationStatus> {
        // Every probe is started first so the whole projection is bounded by
        // one deadline instead of one deadline per scanner. Identity is kept
        // outside the spawned task, so a probe that panics or overruns still
        // reports its own capability as unhealthy rather than disappearing.
        let mut probes = Vec::with_capacity(self.operations.len());
        for registration in &self.operations {
            let scanner = Arc::clone(&registration.scanner);
            let handle = tokio::spawn(async move {
                tokio::time::timeout(OPERATION_HEALTH_DEADLINE, scanner.health()).await
            });
            probes.push((
                scanner_capability_label(&registration.profile.scanner_id).to_string(),
                registration.profile.required,
                handle,
            ));
        }

        let mut statuses = Vec::with_capacity(probes.len());
        for (capability, required, handle) in probes {
            // Adapter health messages are never read here, only the
            // content-free booleans and counters.
            let (healthy, checked_at, queue_depth) = match handle.await {
                Ok(Ok(health)) => (health.healthy, health.checked_at, health.queue_depth),
                Ok(Err(_)) | Err(_) => (false, Utc::now(), None),
            };
            statuses.push(ScannerOperationStatus {
                capability,
                required,
                healthy,
                checked_at,
                queue_depth,
            });
        }
        statuses.sort_by(|left, right| left.capability.cmp(&right.capability));
        statuses
    }
}

pub(crate) fn scanner_capability_label(scanner_id: &ScannerId) -> &'static str {
    match scanner_id.0.as_str() {
        "clamav" => "Malware analysis",
        "static-rule" => "Static content rules",
        "archive" => "Archive safety",
        "image" => "Image safety",
        "document" => "Document safety",
        "url-reputation" => "URL reputation",
        "file-type" => "File type verification",
        // The composite registration covers file-type, archive, PDF, Office,
        // image, OCR and QR analysis under one shared resource envelope, so it
        // needs an explicit label rather than the generic fallback.
        "attachment-analysis" => "Attachment content analysis",
        _ => "Security analysis",
    }
}

/// Converts reviewed local configuration into the SDK fabric configuration.
///
/// The SDK overall deadline covers one full fabric run; it is derived from
/// the per-scanner wall clocks so a scan can never outlive the sum of its
/// reviewed deadlines.
fn fabric_config(
    config: &ScannerFabricConfig,
    registrations: &[ScannerRegistration],
) -> FabricConfig {
    let mut overall_deadline = Duration::ZERO;
    for registration in registrations {
        overall_deadline = overall_deadline.saturating_add(registration.profile.timeout);
    }
    FabricConfig {
        max_parallel_scanners: config.max_concurrent_scans,
        overall_deadline: if overall_deadline.is_zero() {
            FabricConfig::default().overall_deadline
        } else {
            overall_deadline
        },
        on_inconclusive: Disposition::Hold,
        on_threat: Disposition::Quarantine,
        on_suspicious: Disposition::Hold,
    }
}

/// Maps a rejected local registration onto the local configuration error.
fn fabric_config_error(error: FabricError) -> ScannerFabricConfigError {
    match error {
        FabricError::InvalidParallelCeiling => ScannerFabricConfigError::ZeroConcurrency,
        FabricError::InvalidOverallDeadline => ScannerFabricConfigError::ZeroTimeout,
        FabricError::DuplicateScannerId(_)
        | FabricError::InvalidWallClock(_)
        | FabricError::InvalidMaxConcurrency(_)
        | FabricError::UnsafeFailSafeDisposition => ScannerFabricConfigError::FabricRejected,
    }
}

/// Converts one local registration into an SDK registration.
fn sdk_registration(registration: &ScannerRegistration) -> SdkScannerRegistration {
    SdkScannerRegistration {
        scanner: Arc::clone(&registration.scanner),
        scanner_type: registration.profile.scanner_type,
        profile: SdkScannerProfile {
            execution_class: execution_class(registration.profile.requirement),
            wall_clock: registration.profile.timeout,
            max_concurrency: registration.profile.max_concurrency,
            limits: sdk_resource_limits(&registration.profile),
        },
    }
}

fn execution_class(requirement: ScannerRequirement) -> ExecutionClass {
    match requirement {
        ScannerRequirement::Required => ExecutionClass::StandardRequired,
        ScannerRequirement::Optional => ExecutionClass::OptionalEnrichment,
    }
}

fn sdk_resource_limits(profile: &ScannerProfile) -> ResourceLimits {
    ResourceLimits {
        max_input_bytes: profile.max_input_bytes,
        max_expanded_bytes: profile.limits.max_expanded_bytes,
        max_nesting_depth: u32::from(profile.limits.max_recursion_depth),
        max_attachment_count: profile.limits.max_entries,
        max_memory_bytes: profile.limits.max_memory_bytes,
        max_temp_disk_bytes: profile.limits.max_temp_disk_bytes,
        max_ocr_pages: u32::from(profile.limits.max_ocr_pages),
        max_ocr_pixels: profile.limits.max_ocr_pixels,
        max_url_count: profile.limits.max_url_count,
        max_redirect_count: u32::from(profile.limits.max_url_redirects),
    }
}

fn scan_target(artifact: &ScanArtifact) -> ScanTarget {
    ScanTarget {
        request_id: artifact.request_id,
        transaction_id: artifact.transaction_id.clone(),
        tenant_message_id: artifact.tenant_message_id.clone(),
        customer_id: artifact.customer_id.clone(),
        deployment_id: artifact.deployment_id.clone(),
        artifact_id: artifact.artifact_id.clone(),
        content_type: artifact.content_type.clone(),
        content_hash: artifact.content_hash.clone(),
        artifact_size_bytes: artifact.size_bytes,
        requested_at: Utc::now(),
        params: artifact.params.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use nullapart_scanner_sdk::trait_defs::{ScanContentError, ScanError};
    use nullapart_scanner_sdk::types::{
        ScanRequest, ScanResult, ScannerCapabilities, ScannerHealth, ScannerProvenance,
        ScannerStatus,
    };
    use sha2::Digest;

    use super::*;

    const TEST_BYTES: &[u8] = b"nullapart scanner fabric test artifact";

    struct TestScanner {
        id: ScannerId,
        status: ScannerStatus,
        delay: Duration,
        health_delay: Duration,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        supported_content_types: Vec<String>,
    }

    fn test_provenance() -> ScannerProvenance {
        ScannerProvenance {
            scanner_node_id: None,
            scanner_profile_id: None,
            scanner_profile_version: None,
            engine_version: None,
            ruleset_version: None,
            started_at: Utc::now(),
        }
    }

    #[async_trait::async_trait]
    impl Scanner for TestScanner {
        fn id(&self) -> ScannerId {
            self.id.clone()
        }

        fn name(&self) -> &str {
            "test scanner"
        }

        fn version(&self) -> &str {
            "test"
        }

        fn capabilities(&self) -> ScannerCapabilities {
            ScannerCapabilities {
                supported_content_types: self.supported_content_types.clone(),
                max_content_size: 1024,
                latency_class: nullapart_scanner_sdk::types::LatencyClass::Fast,
                requires_network: false,
                milter_compatible: false,
                extra: serde_json::Value::Null,
            }
        }

        async fn scan(
            &self,
            request: ScanRequest,
            _content: Arc<dyn ScanContent>,
        ) -> Result<ScanResult, ScanError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(ScanResult {
                request_id: request.request_id,
                contract_version: request.contract_version,
                scanner_id: self.id(),
                status: self.status,
                message: None,
                findings: Vec::new(),
                completed_at: Utc::now(),
                duration_ms: self.delay.as_millis() as u64,
                details: None,
                provenance: test_provenance(),
            })
        }

        async fn health(&self) -> ScannerHealth {
            if !self.health_delay.is_zero() {
                tokio::time::sleep(self.health_delay).await;
            }
            ScannerHealth {
                healthy: true,
                message: None,
                checked_at: Utc::now(),
                uptime_seconds: None,
                queue_depth: None,
            }
        }
    }

    /// Immutable test content handed to the fabric for one scan.
    struct TestScanContent {
        bytes: Arc<[u8]>,
        content_type: ContentType,
    }

    #[async_trait::async_trait]
    impl ScanContent for TestScanContent {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn content_type(&self) -> &ContentType {
            &self.content_type
        }

        async fn read_all_bounded(&self, max_bytes: u64) -> Result<Arc<[u8]>, ScanContentError> {
            if self.bytes.len() as u64 > max_bytes {
                return Err(ScanContentError::LimitExceeded);
            }
            Ok(Arc::clone(&self.bytes))
        }
    }

    fn hash_of(bytes: &[u8]) -> ContentHash {
        ContentHash::new(&format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(bytes))
        ))
    }

    fn content(bytes: &[u8]) -> Arc<TestScanContent> {
        Arc::new(TestScanContent {
            bytes: Arc::from(bytes),
            content_type: ContentType::new("message/rfc822"),
        })
    }

    fn artifact_for(bytes: &[u8]) -> ScanArtifact {
        ScanArtifact {
            request_id: Uuid::new_v4(),
            transaction_id: TransactionId::new(),
            tenant_message_id: Some(TenantMessageId::new()),
            customer_id: Some(CustomerId::new("customer-test")),
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            artifact_id: ArtifactId::new(),
            content_type: ContentType::new("message/rfc822"),
            content_hash: hash_of(bytes),
            size_bytes: bytes.len() as u64,
            params: serde_json::Value::Null,
        }
    }

    fn registration(
        id: &str,
        requirement: ScannerRequirement,
        status: ScannerStatus,
        delay: Duration,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    ) -> ScannerRegistration {
        registration_for_content_types(
            id,
            requirement,
            status,
            delay,
            active,
            peak,
            vec!["message/rfc822".to_string()],
        )
    }

    fn registration_for_content_types(
        id: &str,
        requirement: ScannerRequirement,
        status: ScannerStatus,
        delay: Duration,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        supported_content_types: Vec<String>,
    ) -> ScannerRegistration {
        let scanner = Arc::new(TestScanner {
            id: ScannerId::new(id),
            status,
            delay,
            health_delay: Duration::ZERO,
            active,
            peak,
            supported_content_types,
        });
        ScannerRegistration {
            profile: ScannerProfile {
                scanner_id: scanner.id(),
                scanner_type: ScannerType::Attachment,
                requirement,
                max_input_bytes: 1024,
                timeout: Duration::from_millis(100),
                max_concurrency: 1,
                limits: ScannerResourceLimits::bounded_default(1024),
            },
            scanner,
        }
    }

    #[tokio::test]
    async fn operation_statuses_map_every_known_capability_to_a_customer_safe_label() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let ids = [
            "clamav",
            "attachment-analysis",
            "static-rule",
            "url-reputation",
            "archive",
            "image",
            "document",
            "file-type",
        ];
        let registrations = ids
            .iter()
            .map(|id| {
                registration(
                    id,
                    ScannerRequirement::Required,
                    ScannerStatus::Clean,
                    Duration::from_millis(1),
                    Arc::clone(&active),
                    Arc::clone(&peak),
                )
            })
            .collect();
        let fabric = ScannerFabric::new(ScannerFabricConfig::default(), registrations).unwrap();

        let statuses = fabric.operation_statuses().await;
        assert_eq!(statuses.len(), ids.len());
        for status in &statuses {
            assert_ne!(
                status.capability, "Security analysis",
                "unmapped scanner id surfaced a generic label"
            );
            for id in ids {
                assert!(
                    !status.capability.contains(id),
                    "scanner id {} leaked into capability label {}",
                    id,
                    status.capability
                );
            }
            assert!(
                status
                    .capability
                    .chars()
                    .next()
                    .is_some_and(char::is_uppercase),
                "label must read as a capability, not an identifier"
            );
        }
    }

    /// A registration whose health probe never settles, used to prove the
    /// operations projection enforces its own deadline.
    fn hanging_health_registration(id: &str) -> ScannerRegistration {
        let scanner = Arc::new(TestScanner {
            id: ScannerId::new(id),
            status: ScannerStatus::Clean,
            delay: Duration::ZERO,
            health_delay: Duration::from_secs(60),
            active: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            supported_content_types: vec!["message/rfc822".to_string()],
        });
        ScannerRegistration {
            profile: ScannerProfile {
                scanner_id: scanner.id(),
                scanner_type: ScannerType::Attachment,
                requirement: ScannerRequirement::Required,
                max_input_bytes: 1024,
                timeout: Duration::from_millis(100),
                max_concurrency: 1,
                limits: ScannerResourceLimits::bounded_default(1024),
            },
            scanner,
        }
    }

    /// Health probes are bounded: a scanner whose health future never
    /// settles is reported unhealthy with a fresh timestamp, the healthy
    /// capability next to it still reports healthy, and the whole projection
    /// costs about one deadline instead of hanging the operations view.
    #[tokio::test]
    async fn operation_statuses_bound_a_health_probe_that_never_settles() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let registrations = vec![
            hanging_health_registration("clamav"),
            registration(
                "static-rule",
                ScannerRequirement::Required,
                ScannerStatus::Clean,
                Duration::from_millis(1),
                active,
                peak,
            ),
        ];
        let fabric = ScannerFabric::new(ScannerFabricConfig::default(), registrations).unwrap();

        let started = std::time::Instant::now();
        let statuses = fabric.operation_statuses().await;
        let elapsed = started.elapsed();

        assert_eq!(statuses.len(), 2, "every capability must stay represented");
        let hanging = statuses
            .iter()
            .find(|status| status.capability == "Malware analysis")
            .expect("the hanging capability must be reported");
        assert!(
            !hanging.healthy,
            "a health probe that overruns the deadline must be unhealthy"
        );
        let responsive = statuses
            .iter()
            .find(|status| status.capability == "Static content rules")
            .expect("the responsive capability must be reported");
        assert!(
            responsive.healthy,
            "a responsive health probe must stay healthy under the same bound"
        );
        assert!(
            elapsed >= Duration::from_secs(2),
            "the deadline must actually have been enforced"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "the projection must not wait for the adapter's own sleep"
        );
        for status in &statuses {
            assert!(
                !status.capability.contains("clamav") && !status.capability.contains("static-rule"),
                "capability labels must never carry scanner ids: {}",
                status.capability
            );
        }
    }

    #[tokio::test]
    async fn scanners_run_in_parallel_without_exceeding_the_global_bound() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let registrations = (0..4)
            .map(|index| {
                registration(
                    &format!("scanner-{index}"),
                    ScannerRequirement::Required,
                    ScannerStatus::Clean,
                    Duration::from_millis(20),
                    Arc::clone(&active),
                    Arc::clone(&peak),
                )
            })
            .collect();
        let fabric = ScannerFabric::new(
            ScannerFabricConfig {
                max_concurrent_scans: 2,
            },
            registrations,
        )
        .unwrap();

        let result = fabric
            .scan(artifact_for(TEST_BYTES), content(TEST_BYTES))
            .await;

        assert_eq!(result.results.len(), 4);
        assert!(!result.requires_hold);
        assert!(peak.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test]
    async fn required_timeout_requires_hold_but_optional_timeout_does_not_when_required_coverage_is_complete(
    ) {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut required = registration(
            "required",
            ScannerRequirement::Required,
            ScannerStatus::Clean,
            Duration::from_millis(20),
            Arc::clone(&active),
            Arc::clone(&peak),
        );
        required.profile.timeout = Duration::from_millis(1);
        let fabric = ScannerFabric::new(ScannerFabricConfig::default(), vec![required]).unwrap();
        assert!(
            fabric
                .scan(artifact_for(TEST_BYTES), content(TEST_BYTES))
                .await
                .requires_hold
        );

        let completing_required = registration(
            "required-complete",
            ScannerRequirement::Required,
            ScannerStatus::Clean,
            Duration::from_millis(20),
            Arc::clone(&active),
            Arc::clone(&peak),
        );
        let mut optional = registration(
            "optional",
            ScannerRequirement::Optional,
            ScannerStatus::Clean,
            Duration::from_millis(20),
            active,
            peak,
        );
        optional.profile.timeout = Duration::from_millis(1);
        let fabric = ScannerFabric::new(
            ScannerFabricConfig::default(),
            vec![completing_required, optional],
        )
        .unwrap();
        let result = fabric
            .scan(artifact_for(TEST_BYTES), content(TEST_BYTES))
            .await;
        assert!(result.failures.iter().any(|failure| failure.retryable));
        assert!(!result.requires_hold);
    }

    #[tokio::test]
    async fn fabric_without_required_registrations_requires_hold() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let fabric = ScannerFabric::new(
            ScannerFabricConfig::default(),
            vec![registration(
                "optional-only",
                ScannerRequirement::Optional,
                ScannerStatus::Clean,
                Duration::from_millis(20),
                active,
                peak,
            )],
        )
        .unwrap();

        let result = fabric
            .scan(artifact_for(TEST_BYTES), content(TEST_BYTES))
            .await;

        assert_eq!(result.results.len(), 1);
        assert!(!result.results[0].required);
        assert!(result.failures.is_empty());
        assert!(result.requires_hold);
    }

    #[tokio::test]
    async fn content_type_inapplicable_required_scanner_requires_hold() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let fabric = ScannerFabric::new(
            ScannerFabricConfig::default(),
            vec![registration_for_content_types(
                "required-text-plain",
                ScannerRequirement::Required,
                ScannerStatus::Clean,
                Duration::from_millis(20),
                active,
                peak,
                vec!["text/plain".to_string()],
            )],
        )
        .unwrap();

        let result = fabric
            .scan(artifact_for(TEST_BYTES), content(TEST_BYTES))
            .await;

        assert_eq!(result.results.len(), 1);
        assert!(result.results[0].required);
        assert!(!result.results[0].applicable);
        assert!(result.failures.is_empty());
        assert!(result.requires_hold);
    }

    #[test]
    fn registration_rejects_a_zero_max_concurrency_profile() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut registration = registration(
            "unbounded-concurrency",
            ScannerRequirement::Required,
            ScannerStatus::Clean,
            Duration::from_secs(1),
            active,
            peak,
        );
        registration.profile.max_concurrency = 0;
        assert!(matches!(
            ScannerFabric::new(ScannerFabricConfig::default(), vec![registration]),
            Err(ScannerFabricConfigError::ZeroScannerMaxConcurrency)
        ));
    }

    #[test]
    fn registration_rejects_an_unbounded_resource_profile() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut registration = registration(
            "unbounded",
            ScannerRequirement::Required,
            ScannerStatus::Clean,
            Duration::ZERO,
            active,
            peak,
        );
        registration.profile.limits.max_expanded_bytes = 0;
        registration.profile.timeout = Duration::from_secs(1);
        assert!(matches!(
            ScannerFabric::new(ScannerFabricConfig::default(), vec![registration]),
            Err(ScannerFabricConfigError::InvalidResourceLimits)
        ));
    }

    #[test]
    fn registration_rejects_a_zero_max_url_count_profile() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut registration = registration(
            "unbounded-urls",
            ScannerRequirement::Required,
            ScannerStatus::Clean,
            Duration::from_secs(1),
            active,
            peak,
        );
        registration.profile.limits.max_url_count = 0;
        assert!(matches!(
            ScannerFabric::new(ScannerFabricConfig::default(), vec![registration]),
            Err(ScannerFabricConfigError::InvalidResourceLimits)
        ));
    }

    #[test]
    fn registration_rejects_a_zero_max_url_redirects_profile() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut registration = registration(
            "unbounded-redirects",
            ScannerRequirement::Required,
            ScannerStatus::Clean,
            Duration::from_secs(1),
            active,
            peak,
        );
        registration.profile.limits.max_url_redirects = 0;
        assert!(matches!(
            ScannerFabric::new(ScannerFabricConfig::default(), vec![registration]),
            Err(ScannerFabricConfigError::InvalidResourceLimits)
        ));
    }

    #[test]
    fn profile_max_url_count_is_preserved_by_the_sdk_conversion() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut registration = registration(
            "bounded-urls",
            ScannerRequirement::Required,
            ScannerStatus::Clean,
            Duration::from_secs(1),
            active,
            peak,
        );
        registration.profile.limits.max_url_count = 7;
        let limits = sdk_resource_limits(&registration.profile);
        assert_eq!(limits.max_url_count, 7);
        assert_eq!(
            registration.profile.limits.max_url_count,
            limits.max_url_count
        );
    }

    #[tokio::test]
    async fn oversized_required_artifact_is_not_dispatched_and_requires_hold() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let fabric = ScannerFabric::new(
            ScannerFabricConfig::default(),
            vec![registration(
                "required",
                ScannerRequirement::Required,
                ScannerStatus::Clean,
                Duration::ZERO,
                Arc::clone(&active),
                Arc::clone(&peak),
            )],
        )
        .unwrap();

        let oversized = vec![0u8; 1025];
        let result = fabric
            .scan(artifact_for(&oversized), content(&oversized))
            .await;

        assert!(result.requires_hold);
        assert_eq!(result.results[0].status, ScannerStatus::Error);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}

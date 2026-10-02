//! Focused Scanner Fabric tests.
//!
//! The adapters in this file are deterministic, in-repo scripted test
//! doubles owned by this repository. They are NOT production scanners and
//! make no production engine claims (no ClamAV/Rspamd/etc. identities);
//! every adapter is registered under `test-*` IDs with `ScannerType::Custom`.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::Barrier;
use uuid::Uuid;

use nullapart_mail_contracts::finding::{
    FailureType, FindingCategory, FindingSeverity, ScannerStatus, ScannerType,
};
use nullapart_mail_contracts::transaction::{
    ContentHash, CustomerId, DeploymentId, Disposition, TenantMessageId, TransactionId,
};
use nullapart_mail_contracts::{ArtifactId, ContentType};

use nullapart_scanner_sdk::contract::SCANNER_CONTRACT_VERSION;
use nullapart_scanner_sdk::fabric::{
    derive_scanner_request_id, sanitize_failure_message, FabricConfig, FabricError, FabricOutcome,
    ScanTarget, ScannerFabric, ScannerRegistration, MAX_PERSISTED_FAILURE_MESSAGE_LEN,
};
use nullapart_scanner_sdk::trait_defs::{
    ScanContent, ScanContentError, ScanError, Scanner, ScannerId,
};
use nullapart_scanner_sdk::types::{
    ExecutionClass, Indicator, IndicatorType, LatencyClass, ResourceLimits, ScanRequest,
    ScanResult, ScannerCapabilities, ScannerFinding, ScannerHealth, ScannerProfile,
    ScannerProvenance,
};

// ---------------------------------------------------------------------------
// Deterministic test adapters
// ---------------------------------------------------------------------------

/// Scripted behaviour for a [`ScriptedTestScanner`].
#[derive(Clone)]
enum Script {
    Clean,
    Threat {
        severity: FindingSeverity,
        description: String,
    },
    Suspicious {
        description: String,
    },
    Status(ScannerStatus),
    Fail(ScanError),
    /// Never completes; only the fabric wall-clock deadline ends the scan.
    Hang,
    Panic(&'static str),
    /// Participate in a shared wave gate (concurrency-ceiling tests).
    Gate,
    SleepThen(Duration, Box<Script>),
    /// Return a Clean result stamped with a foreign contract version.
    ContractVersion(u32),
    /// Return a definite status carrying one prebuilt finding (used by the
    /// bounded finding-text normalization test).
    StatusWithFinding {
        status: ScannerStatus,
        finding: ScannerFinding,
    },
    /// Read bytes through the provided [`ScanContent`] and emit a threat
    /// finding when the expected marker appears in the yielded bytes.
    ContentMarker {
        marker: Vec<u8>,
        description: String,
    },
    /// Read the fabric-supplied content repeatedly and record whether every
    /// read shared one backing allocation (the no-copy guarantee).
    RepeatedReads {
        reads: usize,
    },
}

/// In-repo deterministic test adapter. Test-only: never registered as a
/// production scanner and never claiming a production engine identity.
struct ScriptedTestScanner {
    scanner_id: ScannerId,
    script: Script,
    supported_content_types: Vec<String>,
    max_content_size: u64,
    gate: Option<Arc<WaveGate>>,
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
    /// Total `scan` invocations — proves fabric-side pre-invocation rejection.
    invocations: AtomicUsize,
    /// Per-scanner request IDs this adapter has received, in call order.
    recorded_request_ids: Mutex<Vec<Uuid>>,
    /// Shared-backing outcome recorded by [`Script::RepeatedReads`]:
    /// `Some(true)` when every read aliased one immutable allocation.
    shared_backing: Mutex<Option<bool>>,
    /// Provenance stamped onto every [`ScanResult`] this adapter returns.
    provenance: ScannerProvenance,
}

fn unspecified_provenance() -> ScannerProvenance {
    ScannerProvenance {
        scanner_node_id: None,
        scanner_profile_id: None,
        scanner_profile_version: None,
        engine_version: None,
        ruleset_version: None,
        started_at: Utc::now(),
    }
}

impl ScriptedTestScanner {
    fn new(id: &str, script: Script) -> Self {
        Self {
            scanner_id: ScannerId::new(id),
            script,
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: u64::MAX,
            gate: None,
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
            invocations: AtomicUsize::new(0),
            recorded_request_ids: Mutex::new(Vec::new()),
            shared_backing: Mutex::new(None),
            provenance: unspecified_provenance(),
        }
    }

    fn with_content_types(mut self, content_types: &[&str]) -> Self {
        self.supported_content_types = content_types
            .iter()
            .map(|value| (*value).to_string())
            .collect();
        self
    }

    fn with_max_content_size(mut self, max_content_size: u64) -> Self {
        self.max_content_size = max_content_size;
        self
    }

    fn with_gate(mut self, gate: Arc<WaveGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    fn with_provenance(mut self, provenance: ScannerProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    fn result(
        &self,
        request: &ScanRequest,
        status: ScannerStatus,
        findings: Vec<ScannerFinding>,
        message: Option<String>,
    ) -> ScanResult {
        ScanResult {
            request_id: request.request_id,
            contract_version: request.contract_version,
            scanner_id: self.scanner_id.clone(),
            status,
            message,
            findings,
            completed_at: Utc::now(),
            duration_ms: 0,
            details: None,
            provenance: self.provenance.clone(),
        }
    }

    async fn run(
        &self,
        request: &ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let mut script = &self.script;
        loop {
            match script {
                Script::SleepThen(delay, inner) => {
                    tokio::time::sleep(*delay).await;
                    script = inner.as_ref();
                },
                Script::Clean => {
                    return Ok(self.result(request, ScannerStatus::Clean, Vec::new(), None));
                },
                Script::Threat {
                    severity,
                    description,
                } => {
                    let findings = vec![ScannerFinding {
                        id: Uuid::new_v4(),
                        severity: *severity,
                        category: "malware".to_string(),
                        description: description.clone(),
                        details: None,
                        indicators: Vec::new(),
                        false_positive: false,
                    }];
                    return Ok(self.result(request, ScannerStatus::Threat, findings, None));
                },
                Script::Suspicious { description } => {
                    let findings = vec![ScannerFinding {
                        id: Uuid::new_v4(),
                        severity: FindingSeverity::Medium,
                        category: "suspicious_content".to_string(),
                        description: description.clone(),
                        details: None,
                        indicators: Vec::new(),
                        false_positive: false,
                    }];
                    return Ok(self.result(request, ScannerStatus::Suspicious, findings, None));
                },
                Script::Status(status) => {
                    let message = match status {
                        ScannerStatus::Unknown | ScannerStatus::Error => {
                            Some("scripted test scanner reported non-definite status".to_string())
                        },
                        _ => None,
                    };
                    return Ok(self.result(request, *status, Vec::new(), message));
                },
                Script::Fail(error) => return Err(error.clone()),
                Script::Hang => loop {
                    std::future::pending::<()>().await;
                },
                Script::Panic(message) => panic!("scripted test adapter panic: {message}"),
                Script::Gate => {
                    let clean = self.result(request, ScannerStatus::Clean, Vec::new(), None);
                    return match &self.gate {
                        Some(gate) => Ok(wave_run(gate, async { clean }).await),
                        None => Ok(clean),
                    };
                },
                Script::ContractVersion(version) => {
                    let mut result = self.result(request, ScannerStatus::Clean, Vec::new(), None);
                    result.contract_version = *version;
                    return Ok(result);
                },
                Script::StatusWithFinding { status, finding } => {
                    return Ok(self.result(request, *status, vec![finding.clone()], None));
                },
                Script::ContentMarker {
                    marker,
                    description,
                } => {
                    let bytes = content
                        .read_all_bounded(request.artifact_size_bytes)
                        .await
                        .map_err(map_scan_content_error)?;
                    if bytes
                        .windows(marker.len())
                        .any(|window| window == marker.as_slice())
                    {
                        let findings = vec![ScannerFinding {
                            id: Uuid::new_v4(),
                            severity: FindingSeverity::High,
                            category: "malware".to_string(),
                            description: description.clone(),
                            details: None,
                            indicators: Vec::new(),
                            false_positive: false,
                        }];
                        return Ok(self.result(request, ScannerStatus::Threat, findings, None));
                    }
                    return Ok(self.result(request, ScannerStatus::Clean, Vec::new(), None));
                },
                Script::RepeatedReads { reads } => {
                    let first = content
                        .read_all_bounded(request.artifact_size_bytes)
                        .await
                        .map_err(map_scan_content_error)?;
                    let mut all_shared = true;
                    for _ in 1..*reads {
                        let next = content
                            .read_all_bounded(request.artifact_size_bytes)
                            .await
                            .map_err(map_scan_content_error)?;
                        if !Arc::ptr_eq(&first, &next) || first != next {
                            all_shared = false;
                        }
                    }
                    *self
                        .shared_backing
                        .lock()
                        .expect("shared-backing recorder must not be poisoned") = Some(all_shared);
                    return Ok(self.result(request, ScannerStatus::Clean, Vec::new(), None));
                },
            }
        }
    }
}

/// Map a [`ScanContent`] failure onto the typed [`ScanError`] contract
/// without ever echoing content bytes.
fn map_scan_content_error(error: ScanContentError) -> ScanError {
    match error {
        ScanContentError::LimitExceeded => ScanError::ResourceLimit(error.to_string()),
        ScanContentError::Unavailable => ScanError::Unavailable(error.to_string()),
        ScanContentError::Integrity => ScanError::Failed(error.to_string()),
    }
}

#[async_trait]
impl Scanner for ScriptedTestScanner {
    fn id(&self) -> ScannerId {
        self.scanner_id.clone()
    }

    fn name(&self) -> &str {
        "scripted-test-scanner"
    }

    fn version(&self) -> &str {
        "0.0.0-test-only"
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: self.supported_content_types.clone(),
            max_content_size: self.max_content_size,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: true,
            extra: serde_json::json!({}),
        }
    }

    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.recorded_request_ids
            .lock()
            .expect("request-id recorder must not be poisoned")
            .push(request.request_id);
        let previous = self.in_flight.fetch_add(1, Ordering::SeqCst);
        self.peak_in_flight
            .fetch_max(previous + 1, Ordering::SeqCst);
        let result = self.run(&request, content).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        result
    }

    async fn health(&self) -> ScannerHealth {
        ScannerHealth {
            healthy: true,
            message: None,
            checked_at: Utc::now(),
            uptime_seconds: Some(0),
            queue_depth: None,
        }
    }
}

/// Wave gate: exactly `wave` adapters enter together, do their work, then
/// leave. Deterministically records peak concurrency without wall-clock sleeps.
struct WaveGate {
    barrier: Barrier,
    active: AtomicUsize,
    peak: AtomicUsize,
}

impl WaveGate {
    fn new(wave: usize) -> Arc<Self> {
        Arc::new(Self {
            barrier: Barrier::new(wave),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        })
    }
}

async fn wave_run<T>(gate: &Arc<WaveGate>, work: impl Future<Output = T>) -> T {
    let now_active = gate.active.fetch_add(1, Ordering::SeqCst) + 1;
    gate.peak.fetch_max(now_active, Ordering::SeqCst);
    gate.barrier.wait().await;
    let output = work.await;
    gate.active.fetch_sub(1, Ordering::SeqCst);
    output
}

// ---------------------------------------------------------------------------
// In-memory test ScanContent
// ---------------------------------------------------------------------------

/// Distinctive byte marker embedded in [`default_content_bytes`]: a scanner
/// can only produce the marker-based threat by actually reading the content.
const TEST_THREAT_MARKER: &[u8] = b"NULLAPART-TEST-THREAT-MARKER";

/// Declared artifact length used by [`target`] (and therefore
/// [`default_content_bytes`]).
const DEFAULT_ARTIFACT_LEN: usize = 1024;

/// Deterministic fixture bytes shared by [`target`]'s declared hash and
/// every ordinary fixture provider.
fn default_content_bytes() -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..DEFAULT_ARTIFACT_LEN)
        .map(|index| (index % 251) as u8)
        .collect();
    bytes[..TEST_THREAT_MARKER.len()].copy_from_slice(TEST_THREAT_MARKER);
    bytes
}

/// Lowercase hex SHA-256 of `bytes` — the only hash form the fabric accepts
/// is `sha256:<lowercase hex>`.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Declared content hash shared by [`target`] and ordinary fixture content:
/// the fabric-verified SHA-256 of [`default_content_bytes`].
fn default_content_hash() -> ContentHash {
    ContentHash::new(&format!("sha256:{}", sha256_hex(&default_content_bytes())))
}

/// Deterministic in-memory [`ScanContent`] test double.
///
/// Yields its known bytes only when the caller-supplied bound covers the
/// full length; an oversized read is rejected with
/// [`ScanContentError::LimitExceeded`] before any bytes are returned.
/// Counts every `read_all_bounded` call so tests can prove the fabric
/// acquires the provider exactly once and never reads it again.
struct InMemoryTestContent {
    bytes: Vec<u8>,
    content_type: ContentType,
    reads: AtomicUsize,
    /// When true, `read_all_bounded` never completes; only the fabric
    /// overall deadline can end the acquisition (deadline-before-adapter
    /// test scenario).
    hanging_read: bool,
}

impl InMemoryTestContent {
    fn new(bytes: Vec<u8>, content_type: ContentType) -> Arc<Self> {
        Arc::new(Self {
            bytes,
            content_type,
            reads: AtomicUsize::new(0),
            hanging_read: false,
        })
    }

    /// Fixture content whose length/type match a valid target but whose
    /// bounded read never completes.
    fn hanging_read(bytes: Vec<u8>, content_type: ContentType) -> Arc<Self> {
        Arc::new(Self {
            bytes,
            content_type,
            reads: AtomicUsize::new(0),
            hanging_read: true,
        })
    }
}

#[async_trait]
impl ScanContent for InMemoryTestContent {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn content_type(&self) -> &ContentType {
        &self.content_type
    }

    async fn read_all_bounded(&self, max_bytes: u64) -> Result<Arc<[u8]>, ScanContentError> {
        if self.hanging_read {
            std::future::pending::<()>().await;
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        if max_bytes < self.bytes.len() as u64 {
            return Err(ScanContentError::LimitExceeded);
        }
        Ok(Arc::from(self.bytes.as_slice()))
    }
}

/// Toggling [`ScanContent`] test double proving TOCTOU remediation.
///
/// The first bounded read yields the acquired bytes (matching the target
/// hash); every later read yields a same-length mutation with the threat
/// marker removed. If the fabric or any adapter ever read the provider
/// after acquisition, the marker-based scanners would see the mutated
/// bytes and lose the threat.
struct TogglingTestContent {
    reads: AtomicUsize,
    acquired: Vec<u8>,
    mutated: Vec<u8>,
    content_type: ContentType,
}

impl TogglingTestContent {
    fn new(acquired: Vec<u8>, content_type: ContentType) -> Self {
        assert_eq!(
            acquired.len(),
            DEFAULT_ARTIFACT_LEN,
            "toggling fixture must match the declared artifact length"
        );
        let mut mutated = acquired.clone();
        mutated[..TEST_THREAT_MARKER.len()].fill(0);
        assert!(
            !mutated
                .windows(TEST_THREAT_MARKER.len())
                .any(|window| window == TEST_THREAT_MARKER),
            "mutated fixture must not retain the threat marker"
        );
        Self {
            reads: AtomicUsize::new(0),
            acquired,
            mutated,
            content_type,
        }
    }
}

#[async_trait]
impl ScanContent for TogglingTestContent {
    fn len(&self) -> u64 {
        self.acquired.len() as u64
    }

    fn content_type(&self) -> &ContentType {
        &self.content_type
    }

    async fn read_all_bounded(&self, max_bytes: u64) -> Result<Arc<[u8]>, ScanContentError> {
        let previous_reads = self.reads.fetch_add(1, Ordering::SeqCst);
        let bytes = if previous_reads == 0 {
            &self.acquired
        } else {
            &self.mutated
        };
        if max_bytes < bytes.len() as u64 {
            return Err(ScanContentError::LimitExceeded);
        }
        Ok(Arc::from(bytes.as_slice()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fabric_with(max_parallel_scanners: usize) -> ScannerFabric {
    ScannerFabric::new(FabricConfig {
        max_parallel_scanners,
        ..FabricConfig::default()
    })
    .expect("fabric config must be valid")
}

fn default_profile(execution_class: ExecutionClass) -> ScannerProfile {
    ScannerProfile {
        execution_class,
        wall_clock: Duration::from_secs(10),
        max_concurrency: 4,
        limits: ResourceLimits::bounded_defaults(),
    }
}

fn register(
    fabric: &mut ScannerFabric,
    scanner: Arc<ScriptedTestScanner>,
    execution_class: ExecutionClass,
) {
    fabric
        .register(ScannerRegistration {
            scanner: scanner as Arc<dyn Scanner>,
            scanner_type: ScannerType::Custom,
            profile: default_profile(execution_class),
        })
        .expect("test scanner registration must be valid");
}

fn target() -> ScanTarget {
    ScanTarget {
        request_id: Uuid::new_v4(),
        transaction_id: TransactionId::new(),
        tenant_message_id: Some(TenantMessageId::new()),
        customer_id: Some(CustomerId::new("cust-test")),
        deployment_id: DeploymentId::new("CZA-1"),
        artifact_id: ArtifactId::new(),
        content_type: ContentType::new("message/rfc822"),
        content_hash: default_content_hash(),
        artifact_size_bytes: DEFAULT_ARTIFACT_LEN as u64,
        requested_at: Utc::now(),
        params: serde_json::json!({}),
    }
}

/// Content that matches [`target`]: same declared length and content type,
/// with [`TEST_THREAT_MARKER`] embedded so content-reading scanners can
/// prove they actually received the bytes.
fn default_content_provider() -> Arc<InMemoryTestContent> {
    InMemoryTestContent::new(default_content_bytes(), ContentType::new("message/rfc822"))
}

/// [`default_content_provider`] erased to the [`ScanContent`] seam.
fn default_content() -> Arc<dyn ScanContent> {
    default_content_provider()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_required_clean_yields_clean_and_allow() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new("test-required-a", Script::Clean)),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new("test-required-b", Script::Clean)),
        ExecutionClass::StandardRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_eq!(outcome.status, ScannerStatus::Clean);
    assert!(!outcome.inconclusive);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Allow);
    assert!(outcome.findings.is_empty());
    assert!(outcome.failures.is_empty());
    assert!(outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.scanner_outcomes.len(), 2);
}

#[tokio::test]
async fn bounded_concurrency_ceiling_is_enforced_and_reached() {
    const CEILING: usize = 2;
    const SCANNERS: usize = 6;

    let gate = WaveGate::new(CEILING);
    let mut fabric = fabric_with(CEILING);
    for index in 0..SCANNERS {
        let scanner = Arc::new(
            ScriptedTestScanner::new(&format!("test-parallel-{index:02}"), Script::Gate)
                .with_gate(Arc::clone(&gate)),
        );
        register(&mut fabric, scanner, ExecutionClass::StandardRequired);
    }

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_eq!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.scanner_outcomes.len(), SCANNERS);
    let peak = gate.peak.load(Ordering::SeqCst);
    assert!(
        peak <= CEILING,
        "observed concurrency {peak} must never exceed ceiling {CEILING}"
    );
    assert_eq!(
        peak, CEILING,
        "ceiling must actually be reached to prove parallel execution"
    );
}

#[tokio::test]
async fn per_scanner_concurrency_cap_is_enforced() {
    let mut fabric = fabric_with(8);
    let scanner = Arc::new(ScriptedTestScanner::new(
        "test-capped",
        Script::SleepThen(Duration::from_millis(25), Box::new(Script::Clean)),
    ));
    fabric
        .register(ScannerRegistration {
            scanner: Arc::clone(&scanner) as Arc<dyn Scanner>,
            scanner_type: ScannerType::Custom,
            profile: ScannerProfile {
                execution_class: ExecutionClass::FastRequired,
                wall_clock: Duration::from_secs(10),
                max_concurrency: 1,
                limits: ResourceLimits::bounded_defaults(),
            },
        })
        .expect("registration must be valid");

    let fabric = Arc::new(fabric);
    let first_target = target();
    let second_target = target();
    let first_fabric = Arc::clone(&fabric);
    let second_fabric = Arc::clone(&fabric);
    let first_content = default_content();
    let second_content = default_content();
    let first = tokio::spawn(async move { first_fabric.scan(&first_target, first_content).await });
    let second =
        tokio::spawn(async move { second_fabric.scan(&second_target, second_content).await });

    let first_outcome = first.await.expect("first scan task must not panic");
    let second_outcome = second.await.expect("second scan task must not panic");

    assert_eq!(first_outcome.status, ScannerStatus::Clean);
    assert_eq!(second_outcome.status, ScannerStatus::Clean);
    let peak = scanner.peak_in_flight.load(Ordering::SeqCst);
    assert_eq!(
        peak, 1,
        "per-scanner cap of 1 must serialize scans of the same scanner"
    );
}

#[tokio::test]
async fn required_scanner_failure_never_yields_clean() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-required-fail",
            Script::Fail(ScanError::Failed("engine crashed".to_string())),
        )),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new("test-required-ok", Script::Clean)),
        ExecutionClass::StandardRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Error);
    assert!(outcome.inconclusive);
    assert!(!outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.coverage.required_inconclusive, 1);
    assert_eq!(outcome.coverage.optional_inconclusive, 0);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);

    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(outcome.failures[0].failure_type, FailureType::Error);
    assert!(!outcome.failures[0].retryable);

    assert!(
        outcome.findings.iter().any(|finding| {
            finding.scanner_status == ScannerStatus::Error
                && finding.category == FindingCategory::Unknown
                && !finding.false_positive
        }),
        "required failure must produce explicit non-CLEAN evidence findings"
    );
}

#[tokio::test]
async fn required_scanner_runtime_not_applicable_is_unknown_inconclusive_hold() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-required-runtime-na",
            Script::Status(ScannerStatus::NotApplicable),
        )),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new("test-required-ok", Script::Clean)),
        ExecutionClass::StandardRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    // A selected required scanner that returns runtime NotApplicable is not a
    // definite completion: explicit non-CLEAN unknown evidence, incomplete
    // required coverage, inconclusive, fail-safe Hold — never Clean/Allow.
    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert!(
        outcome.status == ScannerStatus::Unknown || outcome.status == ScannerStatus::Error,
        "expected Unknown or Error, got {:?}",
        outcome.status
    );
    assert!(outcome.inconclusive);
    assert!(!outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.coverage.required_inconclusive, 1);
    assert_eq!(outcome.coverage.optional_inconclusive, 0);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);

    assert_eq!(outcome.failures.len(), 1);
    assert!(
        outcome.findings.iter().any(|finding| {
            matches!(
                finding.scanner_status,
                ScannerStatus::Unknown | ScannerStatus::Error
            ) && finding.category == FindingCategory::Unknown
                && !finding.false_positive
        }),
        "runtime NotApplicable on a required scanner must produce explicit non-CLEAN evidence"
    );
    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.scanner_status != ScannerStatus::Clean),
        "required runtime NotApplicable must never yield clean-status findings"
    );

    let na_outcome = outcome
        .scanner_outcomes
        .iter()
        .find(|entry| entry.scanner_id.0 == "test-required-runtime-na")
        .expect("runtime NotApplicable scanner outcome must be present");
    assert!(na_outcome.failure.is_some());
    assert_ne!(na_outcome.status, ScannerStatus::NotApplicable);
    assert!(
        matches!(
            na_outcome.status,
            ScannerStatus::Unknown | ScannerStatus::Error
        ),
        "required runtime NotApplicable must surface as Unknown/Error, got {:?}",
        na_outcome.status
    );
}

#[tokio::test]
async fn optional_scanner_runtime_not_applicable_stays_nonblocking_clean_allow() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-optional-runtime-na",
            Script::Status(ScannerStatus::NotApplicable),
        )),
        ExecutionClass::OptionalEnrichment,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new("test-required-ok", Script::Clean)),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    // Runtime NotApplicable from an optional/deep scanner remains nonblocking:
    // no synthetic failure, not inconclusive, clean required run still Allows.
    assert_eq!(outcome.status, ScannerStatus::Clean);
    assert!(!outcome.inconclusive);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Allow);
    assert!(outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.coverage.required_inconclusive, 0);
    assert_eq!(outcome.coverage.optional_inconclusive, 0);

    assert!(
        outcome.failures.is_empty(),
        "optional runtime NotApplicable must not create a synthetic failure: {:?}",
        outcome.failures
    );

    let na_outcome = outcome
        .scanner_outcomes
        .iter()
        .find(|entry| entry.scanner_id.0 == "test-optional-runtime-na")
        .expect("optional runtime NotApplicable scanner outcome must be present");
    assert_eq!(na_outcome.status, ScannerStatus::NotApplicable);
    assert!(na_outcome.failure.is_none());
    assert!(!na_outcome.required);
}

#[tokio::test]
async fn optional_and_deep_failure_stay_explicit_but_do_not_block_clean_required_outcome() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-required-clean",
            Script::Clean,
        )),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-optional-unavailable",
            Script::Fail(ScanError::Unavailable("engine down".to_string())),
        )),
        ExecutionClass::OptionalEnrichment,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-deep-failed",
            Script::Fail(ScanError::Failed("deep engine failed".to_string())),
        )),
        ExecutionClass::DeepAnalysis,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    // The clean required run is NOT blocked by optional/deep failures...
    assert!(!outcome.inconclusive);
    assert_eq!(outcome.status, ScannerStatus::Clean);
    assert!(outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.coverage.required_inconclusive, 0);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Allow);

    // ...but the failures remain fully explicit everywhere else.
    assert_eq!(outcome.coverage.optional_applicable, 2);
    assert_eq!(outcome.coverage.optional_inconclusive, 2);
    assert_eq!(outcome.failures.len(), 2);
    assert!(outcome
        .failures
        .iter()
        .any(|failure| failure.failure_type == FailureType::Unavailable));
    assert!(outcome
        .failures
        .iter()
        .any(|failure| failure.failure_type == FailureType::Error));

    let optional_outcome = outcome
        .scanner_outcomes
        .iter()
        .find(|entry| entry.scanner_id.0 == "test-optional-unavailable")
        .expect("optional scanner outcome must be present");
    assert_eq!(optional_outcome.status, ScannerStatus::Unknown);
    assert!(optional_outcome.failure.is_some());
    assert!(!optional_outcome.required);

    assert!(
        outcome.findings.iter().any(|finding| {
            finding.scanner_status == ScannerStatus::Unknown
                && finding.category == FindingCategory::Unknown
        }),
        "optional/deep failures must still produce explicit non-CLEAN evidence findings"
    );
}

#[tokio::test]
async fn threat_from_successful_optional_scanner_overrides_clean_required_outcome() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-required-clean",
            Script::Clean,
        )),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-optional-threat",
            Script::Threat {
                severity: FindingSeverity::High,
                description: "scripted optional threat".to_string(),
            },
        )),
        ExecutionClass::OptionalEnrichment,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert!(!outcome.inconclusive);
    assert!(outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.status, ScannerStatus::Threat);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Quarantine);
}

#[tokio::test]
async fn scanner_timeout_yields_explicit_unknown_evidence() {
    tokio::time::pause();

    let mut fabric = fabric_with(4);
    fabric
        .register(ScannerRegistration {
            scanner: Arc::new(ScriptedTestScanner::new("test-required-hang", Script::Hang))
                as Arc<dyn Scanner>,
            scanner_type: ScannerType::Custom,
            profile: ScannerProfile {
                execution_class: ExecutionClass::FastRequired,
                wall_clock: Duration::from_millis(50),
                max_concurrency: 1,
                limits: ResourceLimits::bounded_defaults(),
            },
        })
        .expect("registration must be valid");

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Unknown);
    assert!(outcome.inconclusive);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert!(!outcome.coverage.required_coverage_complete());

    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(outcome.failures[0].failure_type, FailureType::Timeout);
    assert!(outcome.failures[0].retryable);

    assert!(
        outcome.findings.iter().any(|finding| {
            finding.scanner_status == ScannerStatus::Unknown
                && finding.category == FindingCategory::Unknown
        }),
        "timeout must produce explicit non-CLEAN evidence findings"
    );
    assert!(outcome
        .findings
        .iter()
        .all(|finding| finding.scanner_status != ScannerStatus::Clean));
}

#[tokio::test]
async fn aggregation_is_deterministic_across_runs() {
    tokio::time::pause();

    let mut fabric = fabric_with(8);
    // Completion order (sleeps): d(0) < c(10ms) < b(20ms) < a(30ms).
    // Required finding order is severity-first regardless of completion order.
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-det-a",
            Script::SleepThen(
                Duration::from_millis(30),
                Box::new(Script::Threat {
                    severity: FindingSeverity::High,
                    description: "high severity scripted finding".to_string(),
                }),
            ),
        )),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-det-b",
            Script::SleepThen(
                Duration::from_millis(20),
                Box::new(Script::Threat {
                    severity: FindingSeverity::Critical,
                    description: "critical severity scripted finding".to_string(),
                }),
            ),
        )),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-det-c",
            Script::SleepThen(
                Duration::from_millis(10),
                Box::new(Script::Suspicious {
                    description: "suspicious scripted finding".to_string(),
                }),
            ),
        )),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new("test-det-d", Script::Clean)),
        ExecutionClass::FastRequired,
    );

    let scan_target = target();
    let first = fabric.scan(&scan_target, default_content()).await;
    let second = fabric.scan(&scan_target, default_content()).await;

    let project = |outcome: &FabricOutcome| {
        outcome
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.severity,
                    finding.scanner_status,
                    finding.category,
                    finding.description.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(project(&first), project(&second));
    assert_eq!(
        first
            .scanner_outcomes
            .iter()
            .map(|outcome| outcome.scanner_id.0.clone())
            .collect::<Vec<_>>(),
        second
            .scanner_outcomes
            .iter()
            .map(|outcome| outcome.scanner_id.0.clone())
            .collect::<Vec<_>>(),
        "scanner outcomes must be ordered deterministically by scanner id"
    );

    assert_eq!(first.findings.len(), 3);
    assert_eq!(first.findings[0].severity, FindingSeverity::Critical);
    assert_eq!(first.findings[1].severity, FindingSeverity::High);
    assert_eq!(first.findings[2].severity, FindingSeverity::Medium);
    assert_eq!(first.status, ScannerStatus::Threat);
    assert_eq!(first.fail_safe_disposition, Disposition::Quarantine);
}

#[tokio::test]
async fn fabric_without_scanners_fails_safe_to_hold() {
    let fabric = fabric_with(4);
    let outcome = fabric.scan(&target(), default_content()).await;

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Unknown);
    assert!(outcome.inconclusive);
    assert_eq!(outcome.coverage.required_applicable, 0);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
}

#[tokio::test]
async fn content_inapplicable_required_scanner_fails_safe() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(
            ScriptedTestScanner::new("test-pdf-only", Script::Clean)
                .with_content_types(&["application/pdf"]),
        ),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Unknown);
    assert!(outcome.inconclusive);
    assert_eq!(outcome.coverage.skipped, 1);
    assert_eq!(outcome.coverage.required_applicable, 0);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
}

#[tokio::test]
async fn oversized_artifact_yields_explicit_unscannable_evidence() {
    let mut fabric = fabric_with(4);
    fabric
        .register(ScannerRegistration {
            scanner: Arc::new(
                ScriptedTestScanner::new("test-small-input", Script::Clean)
                    .with_max_content_size(100),
            ) as Arc<dyn Scanner>,
            scanner_type: ScannerType::Custom,
            profile: default_profile(ExecutionClass::FastRequired),
        })
        .expect("registration must be valid");

    // target() carries artifact_size_bytes = 1024 > 100.
    let outcome = fabric.scan(&target(), default_content()).await;

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Error);
    assert!(outcome.inconclusive);
    assert!(!outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert_eq!(outcome.failures[0].failure_type, FailureType::ResourceLimit);
    assert!(outcome
        .findings
        .iter()
        .any(|finding| finding.scanner_status == ScannerStatus::Error));
}

#[tokio::test]
async fn scanner_panic_is_contained_as_error_evidence() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-required-panic",
            Script::Panic("scripted boom"),
        )),
        ExecutionClass::FastRequired,
    );

    // If the panic escaped the task boundary this test would fail rather
    // than hang or abort the process.
    let outcome = fabric.scan(&target(), default_content()).await;

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Error);
    assert!(outcome.inconclusive);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(outcome.failures[0].failure_type, FailureType::Error);
    assert_eq!(outcome.failures[0].message, "scanner task panicked");
    assert!(outcome
        .findings
        .iter()
        .any(|finding| finding.scanner_status == ScannerStatus::Error));
}

#[tokio::test]
async fn suspicious_evidence_fails_safe_to_hold() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-suspicious",
            Script::Suspicious {
                description: "scripted suspicious signal".to_string(),
            },
        )),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    // Suspicious is a definite result, so coverage is complete — but the
    // fail-safe disposition still refuses to allow.
    assert!(!outcome.inconclusive);
    assert!(outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.status, ScannerStatus::Suspicious);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert!(!outcome.findings.is_empty());
}

#[tokio::test]
async fn scanner_reported_unknown_status_is_not_clean() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-reported-unknown",
            Script::Status(ScannerStatus::Unknown),
        )),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Unknown);
    assert!(outcome.inconclusive);
    assert!(!outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert_eq!(outcome.failures.len(), 1);
    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.scanner_status != ScannerStatus::Clean),
        "an unknown scanner verdict must never be silently cleaned"
    );
}

#[test]
fn fabric_rejects_unsafe_fail_safe_config() {
    let error = match ScannerFabric::new(FabricConfig {
        on_inconclusive: Disposition::Allow,
        ..FabricConfig::default()
    }) {
        Err(error) => error,
        Ok(_) => panic!("Allow on inconclusive must be rejected"),
    };
    assert_eq!(error, FabricError::UnsafeFailSafeDisposition);
}

#[test]
fn fabric_rejects_duplicate_scanner_ids() {
    let mut fabric = fabric_with(1);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new("test-duplicate", Script::Clean)),
        ExecutionClass::FastRequired,
    );

    let error = match fabric.register(ScannerRegistration {
        scanner: Arc::new(ScriptedTestScanner::new("test-duplicate", Script::Clean))
            as Arc<dyn Scanner>,
        scanner_type: ScannerType::Custom,
        profile: default_profile(ExecutionClass::FastRequired),
    }) {
        Err(error) => error,
        Ok(_) => panic!("duplicate scanner ids must be rejected"),
    };

    assert!(matches!(error, FabricError::DuplicateScannerId(_)));
}

#[tokio::test]
async fn fabric_rejects_input_above_profile_max_input_bytes_without_invoking_adapter() {
    let scanner = Arc::new(ScriptedTestScanner::new("test-input-limit", Script::Clean));
    let mut fabric = fabric_with(4);
    fabric
        .register(ScannerRegistration {
            scanner: Arc::clone(&scanner) as Arc<dyn Scanner>,
            scanner_type: ScannerType::Custom,
            profile: ScannerProfile {
                execution_class: ExecutionClass::FastRequired,
                wall_clock: Duration::from_secs(10),
                max_concurrency: 1,
                limits: ResourceLimits {
                    // target() carries artifact_size_bytes = 1024 > 100.
                    max_input_bytes: 100,
                    ..ResourceLimits::bounded_defaults()
                },
            },
        })
        .expect("registration must be valid");

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_eq!(
        scanner.invocations.load(Ordering::SeqCst),
        0,
        "adapter must never be invoked for a target above profile max_input_bytes"
    );
    assert!(
        scanner
            .recorded_request_ids
            .lock()
            .expect("recorder must not be poisoned")
            .is_empty(),
        "no per-scanner request may be issued when the fabric rejects the target"
    );

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Error);
    assert!(outcome.inconclusive);
    assert!(!outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(outcome.failures[0].failure_type, FailureType::ResourceLimit);
    assert!(outcome
        .findings
        .iter()
        .any(|finding| finding.scanner_status == ScannerStatus::Error));
}

#[tokio::test]
async fn unsupported_result_contract_version_is_rejected_explicitly() {
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-foreign-contract",
            Script::ContractVersion(SCANNER_CONTRACT_VERSION + 1),
        )),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Error);
    assert!(outcome.inconclusive);
    assert!(!outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(outcome.failures[0].failure_type, FailureType::Error);
    assert!(
        outcome.failures[0].message.contains("contract version"),
        "rejection must name the contract version problem: {}",
        outcome.failures[0].message
    );
    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.scanner_status != ScannerStatus::Clean),
        "an unsupported contract version must never be silently treated as clean"
    );
}

#[tokio::test]
async fn per_scanner_request_ids_are_deterministic_and_unique_while_scan_operation_id_is_retained()
{
    let scanner_a = Arc::new(ScriptedTestScanner::new("test-corr-a", Script::Clean));
    let scanner_b = Arc::new(ScriptedTestScanner::new("test-corr-b", Script::Clean));
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::clone(&scanner_a),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::clone(&scanner_b),
        ExecutionClass::StandardRequired,
    );

    let scan_target = target();
    let first = fabric.scan(&scan_target, default_content()).await;
    let second = fabric.scan(&scan_target, default_content()).await;

    // ScanTarget.request_id remains the stable scan-operation correlation ID.
    assert_eq!(first.request_id, scan_target.request_id);
    assert_eq!(second.request_id, scan_target.request_id);

    let recorded = |scanner: &Arc<ScriptedTestScanner>| -> Vec<Uuid> {
        scanner
            .recorded_request_ids
            .lock()
            .expect("recorder must not be poisoned")
            .clone()
    };
    let a_ids = recorded(&scanner_a);
    let b_ids = recorded(&scanner_b);
    assert_eq!(a_ids.len(), 2);
    assert_eq!(b_ids.len(), 2);

    // Deterministic across repeated fabric scans of the same operation.
    assert_eq!(
        a_ids[0], a_ids[1],
        "same operation + scanner must reuse the derived ID"
    );
    assert_eq!(
        b_ids[0], b_ids[1],
        "same operation + scanner must reuse the derived ID"
    );

    // Unique across scanners within one operation.
    assert_ne!(
        a_ids[0], b_ids[0],
        "distinct scanners must get distinct request IDs"
    );
    assert_ne!(
        a_ids[0], scan_target.request_id,
        "per-scanner IDs must differ from the scan-operation correlation ID"
    );

    // The public derivation helper agrees with what the fabric sent.
    assert_eq!(
        a_ids[0],
        derive_scanner_request_id(&scan_target.request_id, &ScannerId::new("test-corr-a"))
    );
    assert_eq!(
        b_ids[0],
        derive_scanner_request_id(&scan_target.request_id, &ScannerId::new("test-corr-b"))
    );

    // A different scan operation derives different per-scanner IDs.
    let other_target = target();
    fabric.scan(&other_target, default_content()).await;
    let a_after = recorded(&scanner_a);
    assert_eq!(a_after.len(), 3);
    assert_ne!(
        a_after[2], a_ids[0],
        "a new scan operation must derive a new per-scanner ID"
    );
}

#[tokio::test]
async fn raw_engine_failure_text_is_sanitized_in_failures_and_absent_from_findings() {
    const ENGINE_MARKER: &str = "engine-internal-marker-XYZ-98765";
    let raw_message = format!(
        "clamav backend exploded\n\x1b[31m{}\x1b[0m {}",
        ENGINE_MARKER,
        "payload ".repeat(200)
    );
    assert!(raw_message.chars().count() > MAX_PERSISTED_FAILURE_MESSAGE_LEN);

    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-noisy-failure",
            Script::Fail(ScanError::Failed(raw_message.clone())),
        )),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_eq!(outcome.failures.len(), 1);
    let persisted = &outcome.failures[0].message;
    assert!(
        persisted.chars().count() <= MAX_PERSISTED_FAILURE_MESSAGE_LEN,
        "persisted failure message must be clamped: {} chars",
        persisted.chars().count()
    );
    assert!(
        !persisted.chars().any(char::is_control),
        "persisted failure message must not contain control bytes"
    );
    assert_ne!(
        *persisted, raw_message,
        "raw engine text must not be persisted verbatim"
    );

    let outcome_messages: Vec<String> = outcome
        .scanner_outcomes
        .iter()
        .filter_map(|entry| {
            entry
                .failure
                .as_ref()
                .map(|failure| failure.message.clone())
        })
        .collect();
    assert_eq!(outcome_messages.len(), 1);
    assert_eq!(outcome_messages[0], *persisted);
    assert!(!outcome_messages[0].chars().any(char::is_control));

    for finding in &outcome.findings {
        assert!(
            !finding.description.contains(ENGINE_MARKER),
            "normalized findings must never carry raw engine failure text: {}",
            finding.description
        );
        let details = finding
            .details
            .as_ref()
            .map(|value| value.to_string())
            .unwrap_or_default();
        assert!(
            !details.contains(ENGINE_MARKER),
            "normalized finding details must never carry raw engine failure text: {details}"
        );
        assert!(
            !finding.description.contains('\x1b'),
            "normalized findings must never carry control bytes"
        );
    }
    assert!(
        outcome
            .findings
            .iter()
            .any(|finding| finding.scanner_status == ScannerStatus::Error),
        "the sanitized failure must still produce explicit non-CLEAN evidence"
    );

    // The helper itself is exercised directly as the shared utility contract.
    let direct = sanitize_failure_message(&raw_message);
    assert!(!direct.chars().any(char::is_control));
    assert!(direct.chars().count() <= MAX_PERSISTED_FAILURE_MESSAGE_LEN);
}

#[tokio::test]
async fn validated_scan_result_provenance_is_copied_unchanged_to_scanner_outcome() {
    // Deliberately distinctive fixed values: any substitution (now(),
    // completion time, per-field rewrite) fails these assertions.
    let distinctive_started_at = chrono::DateTime::parse_from_rfc3339("2020-01-02T03:04:05Z")
        .expect("fixed provenance timestamp must parse")
        .with_timezone(&Utc);
    let expected = ScannerProvenance {
        scanner_node_id: Some("prov-node-7f3a".to_string()),
        scanner_profile_id: Some("prov-profile-9c2e".to_string()),
        scanner_profile_version: Some("prof-ver-4.5.6-distinct".to_string()),
        engine_version: Some("engine-ver-7.8.9-distinct".to_string()),
        ruleset_version: Some("ruleset-ver-2020-01-02-distinct".to_string()),
        started_at: distinctive_started_at,
    };

    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(
            ScriptedTestScanner::new("test-provenance", Script::Clean)
                .with_provenance(expected.clone()),
        ),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_eq!(outcome.status, ScannerStatus::Clean);
    let scanner_outcome = outcome
        .scanner_outcomes
        .iter()
        .find(|entry| entry.scanner_id.0 == "test-provenance")
        .expect("matching scanner outcome must be present");

    assert_eq!(
        scanner_outcome.provenance.scanner_node_id.as_deref(),
        Some("prov-node-7f3a"),
        "scanner_node_id must be retained unchanged"
    );
    assert_eq!(
        scanner_outcome.provenance.scanner_profile_id.as_deref(),
        Some("prov-profile-9c2e"),
        "scanner_profile_id must be retained unchanged"
    );
    assert_eq!(
        scanner_outcome
            .provenance
            .scanner_profile_version
            .as_deref(),
        Some("prof-ver-4.5.6-distinct"),
        "scanner_profile_version must be retained unchanged"
    );
    assert_eq!(
        scanner_outcome.provenance.engine_version.as_deref(),
        Some("engine-ver-7.8.9-distinct"),
        "engine_version must be retained unchanged"
    );
    assert_eq!(
        scanner_outcome.provenance.ruleset_version.as_deref(),
        Some("ruleset-ver-2020-01-02-distinct"),
        "ruleset_version must be retained unchanged"
    );
    assert_eq!(
        scanner_outcome.provenance.started_at, distinctive_started_at,
        "provenance started_at must not be substituted"
    );
    assert_ne!(
        scanner_outcome.provenance.started_at, scanner_outcome.completed_at,
        "provenance started_at must not be replaced by the outcome completion timestamp"
    );
    assert_eq!(scanner_outcome.provenance, expected);
}

#[tokio::test]
async fn finding_text_normalization_strips_controls_and_clamps_declared_limits() {
    // Mirrors the private limits declared in `fabric.rs` (integration tests
    // cannot reference private items).
    const MAX_FINDING_CATEGORY_LEN: usize = 64;
    const MAX_FINDING_DESCRIPTION_LEN: usize = 512;
    const MAX_INDICATOR_VALUE_LEN: usize = 256;
    const MAX_INDICATOR_CONTEXT_LEN: usize = 256;

    // Over-limit category padded only with ASCII control characters, so after
    // control stripping + trimming the label still maps to Malware — proving
    // category mapping operates on the normalized text, not the raw label.
    let raw_category = format!(
        "{}malware{}",
        "\x07\x00\x1b".repeat(MAX_FINDING_CATEGORY_LEN),
        "\n\t\r\x1b\x00".repeat(MAX_FINDING_CATEGORY_LEN),
    );
    let raw_description = format!(
        "\x07\x1b[31m finding \x07 with controls{}",
        "D".repeat(MAX_FINDING_DESCRIPTION_LEN)
    );
    let raw_value = format!(
        "u{}evil.example\x00\x1b",
        "u".repeat(MAX_INDICATOR_VALUE_LEN)
    );
    let raw_context = format!(
        "ctx\x07 {} with controls\x1b",
        "c".repeat(MAX_INDICATOR_CONTEXT_LEN)
    );
    for raw in [&raw_category, &raw_description, &raw_value, &raw_context] {
        assert!(
            raw.chars().any(char::is_control),
            "test input must contain ASCII control characters"
        );
    }
    assert!(raw_category.chars().count() > MAX_FINDING_CATEGORY_LEN);
    assert!(raw_description.chars().count() > MAX_FINDING_DESCRIPTION_LEN);
    assert!(raw_value.chars().count() > MAX_INDICATOR_VALUE_LEN);
    assert!(raw_context.chars().count() > MAX_INDICATOR_CONTEXT_LEN);

    let finding_id = Uuid::new_v4();
    let scripted = ScannerFinding {
        id: finding_id,
        severity: FindingSeverity::High,
        category: raw_category.clone(),
        description: raw_description.clone(),
        details: None,
        indicators: vec![Indicator {
            indicator_type: IndicatorType::Url,
            value: raw_value.clone(),
            context: Some(raw_context.clone()),
        }],
        false_positive: false,
    };

    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::new(ScriptedTestScanner::new(
            "test-normalized-finding",
            Script::StatusWithFinding {
                status: ScannerStatus::Threat,
                finding: scripted,
            },
        )),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    // The successful scanner's finding is retained in the outcome.
    assert_eq!(outcome.status, ScannerStatus::Threat);
    assert_eq!(outcome.findings.len(), 1);
    let finding = outcome
        .findings
        .iter()
        .find(|finding| finding.id.0 == finding_id)
        .expect("the emitted finding must be retained in the FabricOutcome");

    // Category mapping operated on the normalized text: the raw label (control
    // padded) could never match, so a Malware mapping proves normalization ran
    // before `category_from_label`.
    assert_eq!(finding.category, FindingCategory::Malware);

    assert!(!finding.description.chars().any(char::is_control));
    assert!(
        finding.description.chars().count() <= MAX_FINDING_DESCRIPTION_LEN,
        "description must be at or under the declared limit: {} chars",
        finding.description.chars().count()
    );
    assert_ne!(finding.description, raw_description);

    assert_eq!(finding.indicators.len(), 1);
    let indicator = &finding.indicators[0];
    assert_eq!(indicator.indicator_type, IndicatorType::Url);
    assert!(!indicator.value.chars().any(char::is_control));
    assert!(
        indicator.value.chars().count() <= MAX_INDICATOR_VALUE_LEN,
        "indicator value must be at or under the declared limit: {} chars",
        indicator.value.chars().count()
    );
    assert_ne!(indicator.value, raw_value);

    let context = indicator
        .context
        .as_ref()
        .expect("Some(context) must remain Some after normalization");
    assert!(!context.chars().any(char::is_control));
    assert!(
        context.chars().count() <= MAX_INDICATOR_CONTEXT_LEN,
        "indicator context must be at or under the declared limit: {} chars",
        context.chars().count()
    );
    assert_ne!(*context, raw_context);
}

#[tokio::test]
async fn finding_details_normalization_bounds_invalid_json_and_preserves_safe_json() {
    // (a) Nested object depth 12 exceeds the production depth limit of 8:
    // the root is depth 0 and the innermost object sits at depth 12.
    let mut deep = serde_json::json!({});
    for _ in 0..12 {
        deep = serde_json::json!({ "n": deep });
    }

    // (b) An object with 80 keys exceeds the production entry limit of 64.
    let mut wide_map = serde_json::Map::new();
    for index in 0..80 {
        wide_map.insert(format!("k{index}"), serde_json::json!(index));
    }
    let wide = serde_json::Value::Object(wide_map);

    // (c) A 300-character ASCII string exceeds the production string limit
    // of 256.
    let long_string = serde_json::json!("x".repeat(300));

    // (d) A safe object that fits every production limit must be preserved.
    let safe = serde_json::json!({
        "source": "scanner",
        "score": 7,
        "labels": ["a", "b"],
    });

    let scripted = [
        (Uuid::new_v4(), deep),
        (Uuid::new_v4(), wide),
        (Uuid::new_v4(), long_string),
        (Uuid::new_v4(), safe),
    ];
    let safe_id = scripted[3].0;

    let mut fabric = fabric_with(4);
    for (index, (finding_id, details)) in scripted.iter().enumerate() {
        register(
            &mut fabric,
            Arc::new(ScriptedTestScanner::new(
                &format!("test-details-{index}"),
                Script::StatusWithFinding {
                    status: ScannerStatus::Threat,
                    finding: ScannerFinding {
                        id: *finding_id,
                        severity: FindingSeverity::High,
                        category: "malware".to_string(),
                        description: format!("details bounds case {index}"),
                        details: Some(details.clone()),
                        indicators: Vec::new(),
                        false_positive: false,
                    },
                },
            )),
            ExecutionClass::FastRequired,
        );
    }

    let scan_target = target();
    let outcome = fabric.scan(&scan_target, default_content()).await;

    assert_eq!(outcome.findings.len(), 4);

    let details_of = |finding_id: Uuid| -> Option<serde_json::Value> {
        outcome
            .findings
            .iter()
            .find(|finding| finding.id.0 == finding_id)
            .expect("each scripted finding must be retained in FabricOutcome")
            .details
            .clone()
    };

    let truncated = Some(serde_json::json!({ "truncated": true }));
    for (finding_id, _) in &scripted[..3] {
        assert_eq!(
            details_of(*finding_id),
            truncated,
            "over-limit details must be replaced by the truncated marker"
        );
    }
    assert_eq!(
        details_of(safe_id),
        Some(serde_json::json!({
            "source": "scanner",
            "score": 7,
            "labels": ["a", "b"],
        })),
        "in-bounds details must be preserved exactly"
    );
}

#[tokio::test]
async fn scanner_reads_known_bytes_through_content_and_produces_threat() {
    let scanner = Arc::new(ScriptedTestScanner::new(
        "test-content-reader",
        Script::ContentMarker {
            marker: TEST_THREAT_MARKER.to_vec(),
            description: "threat signature matched in content bytes".to_string(),
        },
    ));
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::clone(&scanner),
        ExecutionClass::FastRequired,
    );

    let outcome = fabric.scan(&target(), default_content()).await;

    assert_eq!(
        scanner.invocations.load(Ordering::SeqCst),
        1,
        "the scanner must be invoked exactly once"
    );
    // The threat can only be produced by actually reading the marker out of
    // the ScanContent bytes — proving the content seam delivered the data.
    assert_eq!(outcome.status, ScannerStatus::Threat);
    assert!(!outcome.inconclusive);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Quarantine);
    assert!(outcome.findings.iter().any(|finding| {
        finding.description == "threat signature matched in content bytes"
            && finding.scanner_status == ScannerStatus::Threat
    }));
}

#[tokio::test]
async fn content_metadata_mismatch_fails_safe_with_zero_scanner_calls() {
    let scanner = Arc::new(ScriptedTestScanner::new(
        "test-integrity-gate",
        Script::Clean,
    ));
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::clone(&scanner),
        ExecutionClass::FastRequired,
    );

    let assert_fail_safe = |outcome: &FabricOutcome, case: &str| {
        assert_eq!(
            scanner.invocations.load(Ordering::SeqCst),
            0,
            "no adapter may be invoked on a metadata/content mismatch ({case})"
        );
        assert!(
            scanner
                .recorded_request_ids
                .lock()
                .expect("recorder must not be poisoned")
                .is_empty(),
            "no per-scanner request may be issued on a mismatch ({case})"
        );
        assert_ne!(outcome.status, ScannerStatus::Clean, "case: {case}");
        assert!(
            matches!(
                outcome.status,
                ScannerStatus::Unknown | ScannerStatus::Error
            ),
            "expected Unknown or Error fail-safe status, got {:?} ({case})",
            outcome.status
        );
        assert!(
            outcome.inconclusive,
            "mismatch must be inconclusive ({case})"
        );
        assert_eq!(
            outcome.fail_safe_disposition,
            Disposition::Hold,
            "mismatch must fail safe to Hold, never Allow ({case})"
        );
        assert_eq!(
            outcome.failures.len(),
            1,
            "exactly one explicit mismatch failure is expected ({case})"
        );
        assert_eq!(
            outcome.failures[0].message, "artifact metadata/content integrity mismatch",
            "the mismatch failure must carry the stable generic message ({case})"
        );
        assert!(
            outcome
                .findings
                .iter()
                .all(|finding| finding.scanner_status != ScannerStatus::Clean),
            "a mismatch must never surface clean evidence ({case})"
        );
    };

    // Length mismatch: content shorter than target.artifact_size_bytes (1024).
    let short_content: Arc<dyn ScanContent> =
        InMemoryTestContent::new(b"short".to_vec(), ContentType::new("message/rfc822"));
    let length_outcome = fabric.scan(&target(), short_content).await;
    assert_fail_safe(&length_outcome, "length mismatch");

    // Content-type mismatch: correct length (1024) but a different type.
    let wrong_type: Arc<dyn ScanContent> = InMemoryTestContent::new(
        vec![0u8; DEFAULT_ARTIFACT_LEN],
        ContentType::new("application/pdf"),
    );
    let type_outcome = fabric.scan(&target(), wrong_type).await;
    assert_fail_safe(&type_outcome, "content-type mismatch");
}

#[tokio::test]
async fn content_hash_integrity_failure_fails_safe_with_zero_scanner_calls() {
    let scanner = Arc::new(ScriptedTestScanner::new(
        "test-hash-integrity",
        Script::Clean,
    ));
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::clone(&scanner),
        ExecutionClass::FastRequired,
    );

    // Length and content type agree with target(), so the preflight failure
    // can only come from the fabric's own SHA-256 verification rejecting
    // acquired bytes that do not hash to target.content_hash.
    let content: Arc<dyn ScanContent> = InMemoryTestContent::new(
        vec![0u8; DEFAULT_ARTIFACT_LEN],
        ContentType::new("message/rfc822"),
    );

    let outcome = fabric.scan(&target(), content).await;

    assert_eq!(
        scanner.invocations.load(Ordering::SeqCst),
        0,
        "no adapter may be invoked when the acquired snapshot fails hash verification"
    );
    assert!(
        scanner
            .recorded_request_ids
            .lock()
            .expect("recorder must not be poisoned")
            .is_empty(),
        "no per-scanner request may be issued when hash verification fails"
    );

    assert_ne!(outcome.status, ScannerStatus::Clean);
    assert_eq!(outcome.status, ScannerStatus::Unknown);
    assert!(outcome.inconclusive);
    assert!(!outcome.coverage.required_coverage_complete());
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert_eq!(
        outcome.failures.len(),
        1,
        "exactly one explicit integrity failure is expected: {:?}",
        outcome.failures
    );
    assert_eq!(
        outcome.failures[0].message, "artifact metadata/content integrity mismatch",
        "the integrity failure must carry the stable generic message, never error detail"
    );
    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.scanner_status != ScannerStatus::Clean),
        "an integrity failure must never surface clean evidence"
    );
}

#[tokio::test]
async fn malformed_or_mismatched_target_sha256_fails_safe_with_zero_scanner_calls() {
    let compatible = Arc::new(ScriptedTestScanner::new("test-hash-gate", Script::Clean));
    let incompatible = Arc::new(
        ScriptedTestScanner::new("test-pdf-only", Script::Clean)
            .with_content_types(&["application/pdf"]),
    );
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::clone(&compatible),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::clone(&incompatible),
        ExecutionClass::OptionalEnrichment,
    );

    let assert_fail_safe = |outcome: &FabricOutcome, case: &str| {
        assert_eq!(
            compatible.invocations.load(Ordering::SeqCst),
            0,
            "no adapter may be invoked on a malformed/mismatched target hash ({case})"
        );
        assert_eq!(
            incompatible.invocations.load(Ordering::SeqCst),
            0,
            "no adapter may be invoked on a malformed/mismatched target hash ({case})"
        );
        assert_ne!(outcome.status, ScannerStatus::Clean, "case: {case}");
        assert_eq!(
            outcome.status,
            ScannerStatus::Unknown,
            "a hash gate failure must surface Unknown ({case})"
        );
        assert!(outcome.inconclusive, "case: {case}");
        assert_eq!(
            outcome.fail_safe_disposition,
            Disposition::Hold,
            "a hash gate failure must fail safe to Hold ({case})"
        );
        assert_eq!(
            outcome.failures.len(),
            1,
            "exactly one generic failure is expected ({case})"
        );
        assert_eq!(
            outcome.failures[0].message, "artifact metadata/content integrity mismatch",
            "hash failures must carry only the stable generic message ({case})"
        );
        assert!(
            outcome
                .findings
                .iter()
                .all(|finding| finding.scanner_status != ScannerStatus::Clean),
            "a hash gate failure must never surface clean evidence ({case})"
        );
        let na = outcome
            .scanner_outcomes
            .iter()
            .find(|entry| entry.scanner_id.0 == "test-pdf-only")
            .expect("the content-type-incompatible outcome must be present");
        assert_eq!(
            na.status,
            ScannerStatus::NotApplicable,
            "incompatible registrations stay NotApplicable under global preflight failure ({case})"
        );
        assert!(!na.applicable, "case: {case}");
        assert!(
            na.failure.is_none(),
            "incompatible registrations carry no failure evidence ({case})"
        );
    };

    // Malformed/unsupported declared hashes fail closed before any byte is
    // ever acquired: wrong hex/length, unsupported algorithm, non-lowercase
    // hex, and short hex.
    let uppercase = sha256_hex(&default_content_bytes()).to_uppercase();
    let malformed_cases = [
        ("non-hex payload", ContentHash::new("sha256:test-content")),
        (
            "unsupported algorithm",
            ContentHash::new(&format!("sha512:{}", "0".repeat(128))),
        ),
        (
            "non-lowercase hex",
            ContentHash::new(&format!("sha256:{uppercase}")),
        ),
        (
            "short hex",
            ContentHash::new(&format!("sha256:{}", "a".repeat(63))),
        ),
    ];
    for (case, content_hash) in malformed_cases {
        let provider = default_content_provider();
        let mut scan_target = target();
        scan_target.content_hash = content_hash;

        let outcome = fabric.scan(&scan_target, provider.clone()).await;

        assert_eq!(
            provider.reads.load(Ordering::SeqCst),
            0,
            "a malformed/unsupported hash must fail closed before any acquisition read ({case})"
        );
        assert_fail_safe(&outcome, case);
    }

    // A well-formed but wrong digest is read exactly once for verification
    // and then rejected before any adapter is scheduled.
    let provider = default_content_provider();
    let mut scan_target = target();
    scan_target.content_hash = ContentHash::new(&format!("sha256:{}", "0".repeat(64)));

    let outcome = fabric.scan(&scan_target, provider.clone()).await;

    assert_eq!(
        provider.reads.load(Ordering::SeqCst),
        1,
        "a mismatched digest must be read exactly once for fabric verification"
    );
    assert_fail_safe(&outcome, "well-formed but mismatched digest");
}

#[tokio::test]
async fn toggling_provider_bytes_cannot_affect_adapters_after_acquisition() {
    // First provider read (the fabric acquisition) yields the marker-carrying
    // bytes that hash to target.content_hash; every later read yields a
    // same-length mutation with the marker removed. If the fabric or any
    // adapter read the provider after acquisition, the marker would vanish
    // and the threat could not be produced.
    let provider = Arc::new(TogglingTestContent::new(
        default_content_bytes(),
        ContentType::new("message/rfc822"),
    ));
    let first_reader = Arc::new(ScriptedTestScanner::new(
        "test-toctou-a",
        Script::ContentMarker {
            marker: TEST_THREAT_MARKER.to_vec(),
            description: "acquired snapshot retained the threat marker".to_string(),
        },
    ));
    let second_reader = Arc::new(ScriptedTestScanner::new(
        "test-toctou-b",
        Script::ContentMarker {
            marker: TEST_THREAT_MARKER.to_vec(),
            description: "acquired snapshot retained the threat marker".to_string(),
        },
    ));
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::clone(&first_reader),
        ExecutionClass::FastRequired,
    );
    register(
        &mut fabric,
        Arc::clone(&second_reader),
        ExecutionClass::StandardRequired,
    );

    let outcome = fabric.scan(&target(), provider.clone()).await;

    assert_eq!(
        provider.reads.load(Ordering::SeqCst),
        1,
        "the provider must be read exactly once for acquisition and never again"
    );
    assert_eq!(first_reader.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(second_reader.invocations.load(Ordering::SeqCst), 1);
    // Both adapters must observe the acquired (marker-carrying) bytes, not
    // the post-acquisition mutation: two marker threats, aggregate Threat.
    assert_eq!(
        outcome
            .findings
            .iter()
            .filter(
                |finding| finding.description == "acquired snapshot retained the threat marker"
                    && finding.scanner_status == ScannerStatus::Threat
            )
            .count(),
        2,
        "every adapter must receive the exact acquired snapshot bytes"
    );
    assert_eq!(outcome.status, ScannerStatus::Threat);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Quarantine);
}

#[tokio::test]
async fn repeated_adapter_reads_share_one_immutable_backing_allocation() {
    let scanner = Arc::new(ScriptedTestScanner::new(
        "test-repeated-read",
        Script::RepeatedReads { reads: 3 },
    ));
    let mut fabric = fabric_with(4);
    register(
        &mut fabric,
        Arc::clone(&scanner),
        ExecutionClass::FastRequired,
    );

    let provider = default_content_provider();
    let outcome = fabric.scan(&target(), provider.clone()).await;

    assert_eq!(outcome.status, ScannerStatus::Clean);
    assert_eq!(scanner.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        *scanner
            .shared_backing
            .lock()
            .expect("shared-backing recorder must not be poisoned"),
        Some(true),
        "every repeated read must alias one shared immutable allocation (no full-artifact copy)"
    );
    assert_eq!(
        provider.reads.load(Ordering::SeqCst),
        1,
        "adapter reads must hit the snapshot; the provider is read only once for acquisition"
    );
}

#[tokio::test]
async fn hanging_content_acquisition_times_out_before_adapter_invocation() {
    let scanner = Arc::new(ScriptedTestScanner::new(
        "test-hanging-acquisition",
        Script::Clean,
    ));
    let mut fabric = ScannerFabric::new(FabricConfig {
        overall_deadline: Duration::from_millis(20),
        ..FabricConfig::default()
    })
    .expect("fabric config must be valid");
    register(
        &mut fabric,
        Arc::clone(&scanner),
        ExecutionClass::FastRequired,
    );

    // Length and content type match target(), so preflight would otherwise
    // reach the adapter; only the bounded acquisition read never completes.
    let content: Arc<dyn ScanContent> = InMemoryTestContent::hanging_read(
        vec![0u8; DEFAULT_ARTIFACT_LEN],
        ContentType::new("message/rfc822"),
    );

    let started = Instant::now();
    let outcome = fabric.scan(&target(), content).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "scan must finish via the fabric deadline, not hang: {elapsed:?}"
    );
    assert_eq!(outcome.status, ScannerStatus::Unknown);
    assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
    assert_eq!(
        scanner.invocations.load(Ordering::SeqCst),
        0,
        "no adapter may be invoked when content acquisition never completes"
    );
}

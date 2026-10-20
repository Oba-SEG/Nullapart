//! Bounded concurrent Scanner Fabric.
//!
//! Orchestrates applicable [`Scanner`] executions per `docs/phases/PHASE-2-SCANNER-FABRIC.md`
//! and `docs/05-SCANNER-FABRIC.md`:
//!
//! - runs applicable scanners concurrently under a global and per-scanner
//!   concurrency ceiling;
//! - enforces per-scanner wall-clock deadlines and carries resource profiles
//!   on every [`ScanRequest`];
//! - rejects targets above `profile.limits.max_input_bytes` before any
//!   adapter is invoked, with explicit `ResourceLimit` evidence;
//! - acquires the supplied [`ScanContent`] exactly once under the remaining
//!   fabric overall deadline, bounded by the largest `max_input_bytes`
//!   among content-type-applicable registrations (the provider is never
//!   read when no scanner applies or the declared input exceeds that
//!   bound), then verifies the acquired bytes against `ScanTarget`
//!   artifact metadata (`length == target.artifact_size_bytes` and
//!   `content_type == target.content_type`) and against the declared
//!   content hash via fabric-owned SHA-256 (`sha256:<lowercase hex>`;
//!   malformed or unsupported hashes fail closed) before any adapter task
//!   is scheduled; a mismatch or verification failure yields an explicit
//!   fail-safe (non-ALLOW) outcome with the stable
//!   [`CONTENT_INTEGRITY_MISMATCH_MESSAGE`] failure text and zero adapter
//!   invocations;
//! - hands every scheduled adapter the same private immutable snapshot
//!   (shared `Arc<[u8]>`) instead of the original provider, and never
//!   reads the provider again after acquisition — post-acquisition
//!   provider mutations cannot change adapter-visible bytes (TOCTOU), and
//!   repeated adapter reads clone the shared allocation rather than the
//!   artifact (no repeated full-artifact copies);
//! - distinguishes REQUIRED vs OPTIONAL execution classes: only missing or
//!   failed applicable `FAST_REQUIRED`/`STANDARD_REQUIRED` analysis makes the
//!   outcome inconclusive (and selects `on_inconclusive`);
//!   `OPTIONAL_ENRICHMENT`/`DEEP_ANALYSIS` failures stay explicit in scanner
//!   outcomes, findings, failures and counters but do not by themselves block
//!   an otherwise clean required outcome — threat evidence from any
//!   successful scanner still overrides;
//! - converts timeout/unavailable/error/panic outcomes into explicit
//!   normalized non-CLEAN evidence;
//! - treats a runtime [`ScannerStatus::NotApplicable`] returned by an
//!   already-selected `FAST_REQUIRED`/`STANDARD_REQUIRED` scanner as explicit
//!   unknown failure evidence (never a definite completion, never retaining
//!   that response's findings), while runtime `NotApplicable` from
//!   `OPTIONAL_ENRICHMENT`/`DEEP_ANALYSIS` scanners stays a nonblocking
//!   definite result — registration-time content-type incompatibility skips
//!   are unaffected;
//! - stamps an explicitly versioned request/result contract
//!   (`crate::contract`) and rejects unsupported contract versions;
//! - derives deterministic per-scanner request IDs from the stable
//!   scan-operation correlation ID ([`ScanTarget::request_id`]) plus scanner ID;
//! - sanitizes/clamps persisted failure messages so raw engine/untrusted
//!   failure text never enters normalized findings or stored failures
//!   unclamped;
//! - bounds scanner-supplied `ScannerFinding.details` JSON at the Fabric
//!   persistence/transport boundary under explicit depth, object-entry,
//!   array-item, string-length and serialized-size limits, replacing only
//!   an over-limit `details` value with `{"truncated": true}` while the
//!   finding itself is retained — this bounds untrusted scanner data; it is
//!   not HTML/UI sanitization;
//! - aggregates findings deterministically;
//! - yields a fail-safe, policy-ready [`FabricOutcome`].
//!
//! Security invariants:
//!
//! - Unknown/failed analysis is never reported as [`ScannerStatus::Clean`]
//!   for the scanner that failed; the aggregate status stays non-CLEAN while
//!   REQUIRED coverage is missing or failed.
//! - A fabric run with no applicable REQUIRED scanners fails safe
//!   (status `Unknown`, inconclusive, hold-class disposition).
//! - Fail-safe dispositions can never be configured as `Allow`.
//! - Threat evidence from any applicable scanner overrides every other
//!   aggregate status/disposition.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio::task::{Id as TaskId, JoinSet};
use uuid::Uuid;

use nullapart_mail_contracts::finding::{
    Confidence, FailureType, FindingCategory, FindingId, FindingScope, FindingSeverity, Indicator,
    ScannerFailure, ScannerStatus, ScannerType, SecurityFinding,
};
use nullapart_mail_contracts::transaction::{
    ContentHash, CustomerId, DeploymentId, Disposition, TenantMessageId, TransactionId,
};
use nullapart_mail_contracts::{ArtifactId, ContentType};

use crate::contract::{validate_scanner_contract_version, DEFAULT_SCANNER_CONTRACT_VERSION};
use crate::trait_defs::{ScanContent, ScanContentError, ScanError, Scanner, ScannerId};
use crate::types::{
    ExecutionClass, ResourceLimits, ScanRequest, ScannerCapabilities, ScannerFinding,
    ScannerProfile, ScannerProvenance,
};

/// Dedicated UUID namespace for deterministic per-scanner request-ID
/// derivation (`nullapart.scanrq`), separate from other Nullapart UUIDv5
/// derivations such as transaction IDs.
const SCANNER_REQUEST_ID_NAMESPACE: Uuid = Uuid::from_u128(0x6e756c6c_61706172_742e7363_616e7271);

/// Stable generic failure message used when the supplied [`ScanContent`]
/// disagrees with [`ScanTarget`] artifact metadata (declared length or
/// content type), when the declared content hash is malformed/unsupported,
/// or when the fabric-acquired snapshot fails SHA-256 verification — all
/// detected before any scanner is selected or invoked.
/// Deliberately generic: never echoes untrusted content details, the raw
/// hash, or any acquired bytes.
const CONTENT_INTEGRITY_MISMATCH_MESSAGE: &str = "artifact metadata/content integrity mismatch";

/// Maximum length (in Unicode scalar values) retained for a persisted
/// scanner failure message.
pub const MAX_PERSISTED_FAILURE_MESSAGE_LEN: usize = 256;

/// Maximum length (in Unicode scalar values) retained for a normalized
/// scanner finding category label before category mapping.
const MAX_FINDING_CATEGORY_LEN: usize = 64;

/// Maximum length (in Unicode scalar values) retained for a normalized
/// scanner finding description.
const MAX_FINDING_DESCRIPTION_LEN: usize = 512;

/// Maximum length (in Unicode scalar values) retained for a normalized
/// [`Indicator::value`].
const MAX_INDICATOR_VALUE_LEN: usize = 256;

/// Maximum length (in Unicode scalar values) retained for a normalized
/// optional [`Indicator::context`].
const MAX_INDICATOR_CONTEXT_LEN: usize = 256;

/// Maximum nesting depth accepted for a scanner-supplied
/// [`ScannerFinding::details`] JSON value (the root value is depth 0; any
/// value inside more than this many enclosing containers is over-limit).
const MAX_DETAILS_JSON_DEPTH: usize = 8;

/// Maximum number of entries accepted in any single scanner-supplied
/// `details` JSON object.
const MAX_DETAILS_OBJECT_ENTRIES: usize = 64;

/// Maximum number of items accepted in any single scanner-supplied
/// `details` JSON array.
const MAX_DETAILS_ARRAY_ITEMS: usize = 64;

/// Maximum length (in Unicode scalar values) accepted for any
/// scanner-supplied `details` JSON string, including object keys.
const MAX_DETAILS_STRING_CHARS: usize = 256;

/// Maximum serialized size in bytes accepted for one normalized
/// scanner-supplied `details` value.
const MAX_DETAILS_SERIALIZED_BYTES: usize = 8 * 1024;

/// Derive the deterministic per-scanner request ID for one scan operation.
///
/// [`ScanTarget::request_id`] is the stable scan-operation correlation ID for
/// the whole fabric run; each registered scanner instead receives a UUIDv5
/// derived from that correlation ID plus its [`ScannerId`]. The same
/// scan-operation + scanner always reproduces the same per-scanner request ID
/// (retry/log correlation), while distinct scanners on the same operation get
/// distinct IDs (no cross-attribution).
pub fn derive_scanner_request_id(scan_request_id: &Uuid, scanner_id: &ScannerId) -> Uuid {
    let material = format!(
        "nullapart.scanner-request.v1|{scan_request_id}|{}",
        scanner_id.0
    );
    Uuid::new_v5(&SCANNER_REQUEST_ID_NAMESPACE, material.as_bytes())
}

/// Clamp and sanitize an untrusted failure message before it is persisted.
///
/// Scanner/engine error text is untrusted: it may contain control bytes
/// (including terminal escape sequences) or unbounded engine output. This
/// helper strips control characters, trims surrounding whitespace and clamps
/// to [`MAX_PERSISTED_FAILURE_MESSAGE_LEN`] (with a `...` ellipsis when
/// truncated) so persisted [`OutcomeFailure`]/`ScannerFailure` messages stay
/// safe for storage, logs and UI. Normalized [`SecurityFinding`] failure
/// evidence never carries raw engine text at all — synthesized failure
/// findings use the stable [`failure_description`] copy instead.
pub fn sanitize_failure_message(raw: &str) -> String {
    const ELLIPSIS: &str = "...";
    let mut cleaned: Vec<char> =
        Vec::with_capacity(raw.len().min(MAX_PERSISTED_FAILURE_MESSAGE_LEN));
    let mut truncated = false;
    for ch in raw.chars() {
        if cleaned.len() >= MAX_PERSISTED_FAILURE_MESSAGE_LEN {
            truncated = true;
            break;
        }
        cleaned.push(if ch.is_control() { ' ' } else { ch });
    }
    if truncated {
        while cleaned.len() > MAX_PERSISTED_FAILURE_MESSAGE_LEN.saturating_sub(ELLIPSIS.len()) {
            cleaned.pop();
        }
        cleaned.extend(ELLIPSIS.chars());
    }
    cleaned.into_iter().collect::<String>().trim().to_string()
}

/// Fabric-level configuration for one [`ScannerFabric`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricConfig {
    /// Global ceiling on concurrently executing scanners, shared by all
    /// `scan` invocations on this fabric.
    pub max_parallel_scanners: usize,
    /// Overall deadline for one fabric scan invocation.
    pub overall_deadline: Duration,
    /// Fail-safe disposition when analysis is inconclusive.
    pub on_inconclusive: Disposition,
    /// Fail-safe disposition when threat evidence exists.
    pub on_threat: Disposition,
    /// Fail-safe disposition when suspicious evidence exists.
    pub on_suspicious: Disposition,
}

impl Default for FabricConfig {
    fn default() -> Self {
        Self {
            max_parallel_scanners: 4,
            overall_deadline: Duration::from_secs(30),
            on_inconclusive: Disposition::Hold,
            on_threat: Disposition::Quarantine,
            on_suspicious: Disposition::Hold,
        }
    }
}

/// Fabric construction/registration error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FabricError {
    #[error("max_parallel_scanners must be >= 1")]
    InvalidParallelCeiling,

    #[error("overall_deadline must be greater than zero")]
    InvalidOverallDeadline,

    #[error("fail-safe dispositions must not be Allow")]
    UnsafeFailSafeDisposition,

    #[error("duplicate scanner id: {0:?}")]
    DuplicateScannerId(ScannerId),

    #[error("scanner wall_clock must be greater than zero for {0:?}")]
    InvalidWallClock(ScannerId),

    #[error("scanner max_concurrency must be >= 1 for {0:?}")]
    InvalidMaxConcurrency(ScannerId),
}

/// A scanner registered with the fabric together with its execution profile.
pub struct ScannerRegistration {
    pub scanner: Arc<dyn Scanner>,
    /// Contract scanner type used when normalizing findings for policy.
    pub scanner_type: ScannerType,
    pub profile: ScannerProfile,
}

/// One bounded scan invocation against a single immutable artifact reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    /// Stable scan-operation correlation ID for the entire fabric run: one
    /// value per [`ScannerFabric::scan`] invocation, echoed unchanged on
    /// [`FabricOutcome::request_id`] and used to derive deterministic
    /// per-scanner [`ScanRequest::request_id`]s (see
    /// [`derive_scanner_request_id`]). This is NOT a per-scanner request ID.
    pub request_id: Uuid,
    pub transaction_id: TransactionId,
    pub tenant_message_id: Option<TenantMessageId>,
    /// Customer/tenant identity from authenticated server context — never a
    /// client-asserted raw ID.
    pub customer_id: Option<CustomerId>,
    pub deployment_id: DeploymentId,
    pub artifact_id: ArtifactId,
    pub content_type: ContentType,
    pub content_hash: ContentHash,
    pub artifact_size_bytes: u64,
    pub requested_at: DateTime<Utc>,
    pub params: serde_json::Value,
}

/// Explicit inconclusive-failure evidence for one scanner outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeFailure {
    pub failure_type: FailureType,
    pub message: String,
    pub retryable: bool,
    /// Effective non-CLEAN status produced for this failure (`Unknown` or `Error`).
    pub status: ScannerStatus,
}

/// Deterministic per-scanner outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerOutcome {
    pub scanner_id: ScannerId,
    pub scanner_type: ScannerType,
    pub execution_class: ExecutionClass,
    pub required: bool,
    pub applicable: bool,
    pub status: ScannerStatus,
    pub duration_ms: u64,
    pub finding_count: usize,
    pub failure: Option<OutcomeFailure>,
    pub completed_at: DateTime<Utc>,
    /// Audit provenance copied unchanged from the validated [`ScanResult`]
    /// (or fabric-synthesized when no validated result was received).
    pub provenance: ScannerProvenance,
}

/// Coverage counters for REQUIRED vs OPTIONAL analysis.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricCoverage {
    /// Applicable scanners (including those that failed inconclusively).
    pub applicable: usize,
    /// Registered scanners skipped as not applicable to this target.
    pub skipped: usize,
    /// Applicable scanners with a definite result (`Clean`/`Threat`/`Suspicious`,
    /// plus runtime `NotApplicable` from optional/deep scanners).
    pub completed: usize,
    /// Applicable scanners without a definite result.
    pub inconclusive: usize,
    pub required_applicable: usize,
    pub required_inconclusive: usize,
    pub optional_applicable: usize,
    pub optional_inconclusive: usize,
}

impl FabricCoverage {
    /// True when at least one REQUIRED scanner was applicable and every
    /// applicable REQUIRED scanner produced a definite result.
    pub fn required_coverage_complete(&self) -> bool {
        self.required_applicable > 0 && self.required_inconclusive == 0
    }
}

/// Policy-ready outcome of one fabric scan.
///
/// `findings` is ready to drop into `PolicyEvaluationRequest.findings`;
/// `fail_safe_disposition` is the fail-safe fallback when policy has no
/// explicit matching rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricOutcome {
    pub request_id: Uuid,
    pub transaction_id: TransactionId,
    /// Overall status. Never `Clean` while REQUIRED coverage is missing or
    /// any applicable REQUIRED scanner is inconclusive; optional/deep
    /// enrichment failures alone do not prevent an otherwise clean aggregate.
    pub status: ScannerStatus,
    pub coverage: FabricCoverage,
    /// True when REQUIRED coverage is empty or any applicable REQUIRED
    /// scanner is inconclusive. OPTIONAL_ENRICHMENT/DEEP_ANALYSIS failures
    /// are counted in `coverage.optional_inconclusive` but do not set this
    /// flag by themselves.
    pub inconclusive: bool,
    /// Deterministically ordered normalized findings.
    pub findings: Vec<SecurityFinding>,
    /// Deterministically ordered explicit scanner failures.
    pub failures: Vec<ScannerFailure>,
    /// Per-scanner outcomes ordered by scanner ID.
    pub scanner_outcomes: Vec<ScannerOutcome>,
    pub fail_safe_disposition: Disposition,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Immutable content snapshot and fabric-owned verification
// ---------------------------------------------------------------------------

/// Fabric-private immutable content snapshot handed to every scheduled
/// adapter for one scan operation.
///
/// Built once from the fabric-acquired, SHA-256-verified bytes; the
/// original [`ScanContent`] provider is never read again after acquisition,
/// so post-acquisition provider mutations (TOCTOU) cannot change what
/// adapters observe. Reads clone the shared `Arc<[u8]>` allocation instead
/// of copying artifact bytes, so repeated per-adapter reads stay bounded
/// and never produce repeated full-artifact copies.
struct FabricContentSnapshot {
    bytes: Arc<[u8]>,
    content_type: ContentType,
}

#[async_trait]
impl ScanContent for FabricContentSnapshot {
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

/// Decode one ASCII character as a lowercase hexadecimal nibble.
///
/// Uppercase and non-hex characters are rejected so only the exact
/// `sha256:<lowercase hex>` form is accepted.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Parse a declared target content hash of the exact form
/// `sha256:<64 lowercase hex characters>` into its 32 raw digest bytes.
///
/// Returns `None` for any other algorithm, length or character class so
/// unsupported/malformed hashes fail closed before any byte is acquired.
/// The hash value is never logged and never enters failure evidence.
fn parse_expected_sha256(content_hash: &ContentHash) -> Option<[u8; 32]> {
    let hex = content_hash.0.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(digest)
}

/// SHA-256 `bytes` and compare against the already-parsed expected digest.
///
/// Pure CPU comparison of public digest values; neither the digest nor the
/// bytes are logged or returned on mismatch.
fn sha256_matches(bytes: &[u8], expected_digest: &[u8; 32]) -> bool {
    let actual = Sha256::digest(bytes);
    actual[..] == expected_digest[..]
}

/// Acquire the provider bytes exactly once and verify the acquired
/// snapshot against `target.artifact_size_bytes` and the already-parsed
/// expected SHA-256 digest.
///
/// The entire acquisition + verification runs under one `tokio::time::timeout`
/// bounded by the remaining fabric overall deadline; `None` is returned for
/// an exhausted deadline, a timeout, a provider read error, a length
/// disagreement or a hash mismatch. Never logs the hash or the bytes.
async fn acquire_verified_snapshot(
    content: &dyn ScanContent,
    target: &ScanTarget,
    acquisition_bound: u64,
    expected_digest: &[u8; 32],
    overall_deadline: Duration,
    fabric_started: Instant,
) -> Option<Arc<dyn ScanContent>> {
    let remaining = overall_deadline.checked_sub(fabric_started.elapsed())?;
    tokio::time::timeout(remaining, async {
        let bytes = content.read_all_bounded(acquisition_bound).await.ok()?;
        let acquired_len = bytes.len() as u64;
        if acquired_len != target.artifact_size_bytes || acquired_len > acquisition_bound {
            return None;
        }
        if !sha256_matches(&bytes, expected_digest) {
            return None;
        }
        let snapshot: Arc<dyn ScanContent> = Arc::new(FabricContentSnapshot {
            bytes,
            content_type: target.content_type.clone(),
        });
        Some(snapshot)
    })
    .await
    .ok()
    .flatten()
}

// ---------------------------------------------------------------------------
// Fabric
// ---------------------------------------------------------------------------

/// Reusable bounded concurrent Scanner Fabric.
pub struct ScannerFabric {
    config: FabricConfig,
    registrations: Vec<ScannerRegistration>,
    global_permits: Arc<Semaphore>,
    per_scanner_permits: HashMap<ScannerId, Arc<Semaphore>>,
}

impl ScannerFabric {
    /// Create a fabric with a validated configuration.
    pub fn new(config: FabricConfig) -> Result<Self, FabricError> {
        if config.max_parallel_scanners < 1 {
            return Err(FabricError::InvalidParallelCeiling);
        }
        if config.overall_deadline.is_zero() {
            return Err(FabricError::InvalidOverallDeadline);
        }
        for disposition in [
            config.on_inconclusive,
            config.on_threat,
            config.on_suspicious,
        ] {
            if disposition == Disposition::Allow {
                return Err(FabricError::UnsafeFailSafeDisposition);
            }
        }
        Ok(Self {
            global_permits: Arc::new(Semaphore::new(config.max_parallel_scanners)),
            config,
            registrations: Vec::new(),
            per_scanner_permits: HashMap::new(),
        })
    }

    /// Register a scanner with its execution profile.
    pub fn register(&mut self, registration: ScannerRegistration) -> Result<(), FabricError> {
        let scanner_id = registration.scanner.id();
        if registration.profile.wall_clock.is_zero() {
            return Err(FabricError::InvalidWallClock(scanner_id));
        }
        if registration.profile.max_concurrency < 1 {
            return Err(FabricError::InvalidMaxConcurrency(scanner_id));
        }
        if self
            .registrations
            .iter()
            .any(|r| r.scanner.id() == scanner_id)
        {
            return Err(FabricError::DuplicateScannerId(scanner_id));
        }
        self.per_scanner_permits.insert(
            scanner_id,
            Arc::new(Semaphore::new(
                registration.profile.max_concurrency as usize,
            )),
        );
        self.registrations.push(registration);
        Ok(())
    }

    /// Execute all applicable registered scanners and aggregate a
    /// deterministic, fail-safe, policy-ready outcome.
    ///
    /// `content` must agree with `target` artifact metadata (declared length
    /// and content type). The fabric then acquires the bytes exactly once
    /// under the remaining overall deadline — bounded by the largest
    /// `max_input_bytes` among content-type-applicable registrations, and
    /// not at all when no scanner applies or the declared input exceeds
    /// that bound — and verifies the acquired snapshot against
    /// `target.content_hash` with fabric-owned SHA-256
    /// (`sha256:<lowercase hex>`; malformed/unsupported hashes fail closed)
    /// before any scanner is scheduled. On success every adapter receives
    /// the same private immutable snapshot and the provider is never read
    /// again; on any preflight/acquisition/hash failure the run fails safe
    /// with [`CONTENT_INTEGRITY_MISMATCH_MESSAGE`] evidence and zero
    /// adapter invocations (content-type-incompatible registrations stay
    /// `NotApplicable`).
    ///
    /// Never returns `ScannerStatus::Clean` when analysis is inconclusive.
    pub async fn scan(&self, target: &ScanTarget, content: Arc<dyn ScanContent>) -> FabricOutcome {
        let fabric_started = Instant::now();
        let target = Arc::new(target.clone());

        // Preflight metadata gate: the supplied ScanContent must agree with
        // the declared artifact metadata BEFORE any byte is acquired. Any
        // disagreement is explicit fail-safe evidence — stable generic
        // message, never Allow, never a silent skip, zero adapter calls.
        let mut preflight_failed = content.len() != target.artifact_size_bytes
            || content.content_type() != &target.content_type;

        // Acquisition bound: the largest profile `max_input_bytes` among
        // content-type-applicable registrations. Taking the maximum keeps a
        // smaller optional profile from blocking a larger required profile;
        // every per-scanner limit is still enforced again per scanner below.
        // `None` means no scanner applies to this content type, so the
        // provider is never read.
        let acquisition_bound = self
            .registrations
            .iter()
            .filter(|registration| {
                content_type_supported(&registration.scanner.capabilities(), &target.content_type)
            })
            .map(|registration| registration.profile.limits.max_input_bytes)
            .max();

        // One-shot acquisition + fabric-owned SHA-256 verification, bounded
        // by the remaining single fabric overall deadline. The provider is
        // read at most once here and never again afterwards; adapters only
        // ever receive the immutable snapshot produced below.
        let mut snapshot: Option<Arc<dyn ScanContent>> = None;
        if !preflight_failed {
            match (
                acquisition_bound,
                parse_expected_sha256(&target.content_hash),
            ) {
                (Some(bound), Some(expected)) => {
                    if target.artifact_size_bytes <= bound {
                        snapshot = acquire_verified_snapshot(
                            content.as_ref(),
                            &target,
                            bound,
                            &expected,
                            self.config.overall_deadline,
                            fabric_started,
                        )
                        .await;
                        if snapshot.is_none() {
                            preflight_failed = true;
                        }
                    }
                    // Declared input above the acquisition bound: no read,
                    // no large allocation. Every applicable scanner below
                    // rejects the target at its own profile gate first, so
                    // the per-scanner ResourceLimit evidence is preserved
                    // unchanged.
                },
                _ => preflight_failed = true,
            }
        }

        if preflight_failed {
            let collected: Vec<Collected> = self
                .registrations
                .iter()
                .map(|registration| {
                    let meta = ScannerMeta {
                        scanner_id: registration.scanner.id(),
                        scanner_type: registration.scanner_type,
                        execution_class: registration.profile.execution_class,
                        required: registration.profile.execution_class.is_required(),
                    };
                    if !content_type_supported(
                        &registration.scanner.capabilities(),
                        &target.content_type,
                    ) {
                        Collected::not_applicable(&meta)
                    } else {
                        Collected::inconclusive(
                            &meta,
                            &target,
                            OutcomeFailure {
                                // Content-integrity/hash preflight failure is
                                // an integrity error, not a resource limit.
                                failure_type: FailureType::Error,
                                message: CONTENT_INTEGRITY_MISMATCH_MESSAGE.to_string(),
                                retryable: false,
                                status: ScannerStatus::Unknown,
                            },
                            Vec::new(),
                            0,
                        )
                    }
                })
                .collect();
            return assemble_outcome(target, collected, &self.config, fabric_started);
        }

        let mut collected: Vec<Collected> = Vec::new();
        let mut work: Vec<(WorkItem, Arc<Semaphore>, Arc<dyn ScanContent>)> = Vec::new();

        for registration in &self.registrations {
            let meta = ScannerMeta {
                scanner_id: registration.scanner.id(),
                scanner_type: registration.scanner_type,
                execution_class: registration.profile.execution_class,
                required: registration.profile.execution_class.is_required(),
            };
            let caps = registration.scanner.capabilities();

            if !content_type_supported(&caps, &target.content_type) {
                collected.push(Collected::not_applicable(&meta));
                continue;
            }

            // Fabric-owned resource gate: reject oversized targets for every
            // applicable scanner BEFORE the adapter is ever invoked, with
            // explicit ResourceLimit evidence (never a silent skip).
            if target.artifact_size_bytes > registration.profile.limits.max_input_bytes {
                collected.push(Collected::inconclusive(
                    &meta,
                    &target,
                    OutcomeFailure {
                        failure_type: FailureType::ResourceLimit,
                        message: "artifact exceeds scanner profile max_input_bytes".to_string(),
                        retryable: false,
                        status: ScannerStatus::Error,
                    },
                    Vec::new(),
                    0,
                ));
                continue;
            }

            if target.artifact_size_bytes > caps.max_content_size {
                // Unscannable oversized input is explicit evidence, never a silent skip.
                collected.push(Collected::inconclusive(
                    &meta,
                    &target,
                    OutcomeFailure {
                        failure_type: FailureType::ResourceLimit,
                        message: "artifact exceeds scanner maximum input size".to_string(),
                        retryable: false,
                        status: ScannerStatus::Error,
                    },
                    Vec::new(),
                    0,
                ));
                continue;
            }

            // Adapters only ever receive the fabric-acquired immutable
            // snapshot — never the original provider — so no provider read
            // can happen after acquisition (TOCTOU).
            match (
                self.per_scanner_permits.get(&meta.scanner_id),
                snapshot.as_ref(),
            ) {
                (Some(local), Some(snapshot)) => work.push((
                    WorkItem {
                        scanner: Arc::clone(&registration.scanner),
                        meta,
                        profile: registration.profile.clone(),
                        spawned_at: Instant::now(),
                    },
                    Arc::clone(local),
                    Arc::clone(snapshot),
                )),
                (None, _) => collected.push(Collected::inconclusive(
                    &meta,
                    &target,
                    OutcomeFailure {
                        failure_type: FailureType::Error,
                        message: "internal: missing scanner concurrency profile".to_string(),
                        retryable: false,
                        status: ScannerStatus::Error,
                    },
                    Vec::new(),
                    0,
                )),
                // Unreachable in normal control flow: a missing snapshot
                // only occurs when the declared input exceeded the
                // acquisition bound, and every applicable scanner then
                // fails its profile gate above before reaching this arm.
                (Some(_), None) => collected.push(Collected::inconclusive(
                    &meta,
                    &target,
                    OutcomeFailure {
                        failure_type: FailureType::Error,
                        message: "internal: missing immutable content snapshot".to_string(),
                        retryable: false,
                        status: ScannerStatus::Error,
                    },
                    Vec::new(),
                    0,
                )),
            }
        }

        let mut join_set: JoinSet<Collected> = JoinSet::new();
        let mut pending: HashMap<TaskId, FailureMeta> = HashMap::new();

        for (item, local, snapshot) in work {
            let meta = FailureMeta {
                scanner: item.meta.clone(),
                spawned_at: item.spawned_at,
            };
            let wall_clock = item.profile.wall_clock.min(self.config.overall_deadline);
            let limits = item.profile.limits.clone();
            let global = Arc::clone(&self.global_permits);
            let target_for_task = Arc::clone(&target);
            let snapshot_for_task = snapshot;

            let handle = join_set.spawn(async move {
                run_scanner(
                    item,
                    target_for_task,
                    snapshot_for_task,
                    global,
                    local,
                    wall_clock,
                    limits,
                )
                .await
            });
            pending.insert(handle.id(), meta);
        }

        let timed_out = {
            let collect_all = async {
                while let Some(joined) = join_set.join_next_with_id().await {
                    match joined {
                        Ok((task_id, result)) => {
                            pending.remove(&task_id);
                            collected.push(result);
                        },
                        Err(join_err) => {
                            let meta = pending.remove(&join_err.id());
                            collected.push(join_failure(&meta, join_err, &target));
                        },
                    }
                }
            };

            match self
                .config
                .overall_deadline
                .checked_sub(fabric_started.elapsed())
            {
                Some(remaining) => tokio::time::timeout(remaining, collect_all).await.is_err(),
                None => true,
            }
        };
        if timed_out {
            join_set.abort_all();
            while let Some(joined) = join_set.join_next_with_id().await {
                match joined {
                    Ok((task_id, result)) => {
                        pending.remove(&task_id);
                        collected.push(result);
                    },
                    Err(join_err) => {
                        let meta = pending.remove(&join_err.id());
                        collected.push(join_failure(&meta, join_err, &target));
                    },
                }
            }
        }

        // Fail-safe completeness sweep: every applicable work item must have evidence.
        for meta in pending.values() {
            collected.push(Collected::inconclusive(
                &meta.scanner,
                &target,
                OutcomeFailure {
                    failure_type: FailureType::Timeout,
                    message: "fabric overall deadline exceeded".to_string(),
                    retryable: true,
                    status: ScannerStatus::Unknown,
                },
                Vec::new(),
                meta.spawned_at.elapsed().as_millis() as u64,
            ));
        }

        assemble_outcome(target, collected, &self.config, fabric_started)
    }
}

// ---------------------------------------------------------------------------
// Applicability
// ---------------------------------------------------------------------------

fn content_type_supported(caps: &ScannerCapabilities, content_type: &ContentType) -> bool {
    if caps.supported_content_types.is_empty() {
        return true;
    }
    caps.supported_content_types
        .iter()
        .any(|pattern| content_type_matches(pattern, &content_type.0))
}

fn content_type_matches(pattern: &str, content_type: &str) -> bool {
    if pattern == "*" || pattern == content_type {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return content_type.starts_with(prefix) && content_type[prefix.len()..].starts_with('/');
    }
    false
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

struct WorkItem {
    scanner: Arc<dyn Scanner>,
    meta: ScannerMeta,
    profile: ScannerProfile,
    spawned_at: Instant,
}

/// Identity metadata shared by in-process results and attributed failures.
#[derive(Clone)]
struct ScannerMeta {
    scanner_id: ScannerId,
    scanner_type: ScannerType,
    execution_class: ExecutionClass,
    required: bool,
}

/// Metadata retained so a panicked/cancelled task can still be attributed.
#[derive(Clone)]
struct FailureMeta {
    scanner: ScannerMeta,
    spawned_at: Instant,
}

async fn run_scanner(
    item: WorkItem,
    target: Arc<ScanTarget>,
    snapshot: Arc<dyn ScanContent>,
    global: Arc<Semaphore>,
    local: Arc<Semaphore>,
    wall_clock: Duration,
    limits: ResourceLimits,
) -> Collected {
    let global_permit = match global.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return Collected::inconclusive(
                &item.meta,
                &target,
                OutcomeFailure {
                    failure_type: FailureType::Error,
                    message: "fabric concurrency limiter unavailable".to_string(),
                    retryable: true,
                    status: ScannerStatus::Error,
                },
                Vec::new(),
                0,
            );
        },
    };
    let local_permit = match local.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return Collected::inconclusive(
                &item.meta,
                &target,
                OutcomeFailure {
                    failure_type: FailureType::Error,
                    message: "scanner concurrency limiter unavailable".to_string(),
                    retryable: true,
                    status: ScannerStatus::Error,
                },
                Vec::new(),
                0,
            );
        },
    };

    let started = Instant::now();
    // Deterministic per-scanner request ID derived from the stable
    // scan-operation correlation ID + scanner identity (never a fresh random
    // ID), so retries of the same scan-operation correlate per scanner.
    let request_id = derive_scanner_request_id(&target.request_id, &item.meta.scanner_id);
    let request = ScanRequest {
        request_id,
        contract_version: DEFAULT_SCANNER_CONTRACT_VERSION,
        transaction_id: target.transaction_id.clone(),
        tenant_message_id: target.tenant_message_id.clone(),
        customer_id: target.customer_id.clone(),
        deployment_id: target.deployment_id.clone(),
        artifact_id: target.artifact_id.clone(),
        content_type: target.content_type.clone(),
        content_hash: target.content_hash.clone(),
        artifact_size_bytes: target.artifact_size_bytes,
        timeout_ms: wall_clock.as_millis() as u64,
        limits,
        requested_at: target.requested_at,
        params: target.params.clone(),
    };

    let scanned = tokio::time::timeout(wall_clock, item.scanner.scan(request, snapshot)).await;
    let duration_ms = started.elapsed().as_millis() as u64;

    // Keep permits alive until the scan (and result handling) completes.
    drop(global_permit);
    drop(local_permit);

    let classify = |failure: OutcomeFailure, partial: Vec<SecurityFinding>| {
        Collected::inconclusive(&item.meta, &target, failure, partial, duration_ms)
    };

    match scanned {
        Err(_) => classify(
            OutcomeFailure {
                failure_type: FailureType::Timeout,
                message: "wall-clock deadline exceeded".to_string(),
                retryable: true,
                status: ScannerStatus::Unknown,
            },
            Vec::new(),
        ),
        Ok(Err(ScanError::Unavailable(message))) => classify(
            OutcomeFailure {
                failure_type: FailureType::Unavailable,
                message,
                retryable: true,
                status: ScannerStatus::Unknown,
            },
            Vec::new(),
        ),
        Ok(Err(ScanError::Failed(message))) => classify(
            OutcomeFailure {
                failure_type: FailureType::Error,
                message,
                retryable: false,
                status: ScannerStatus::Error,
            },
            Vec::new(),
        ),
        Ok(Err(ScanError::ResourceLimit(message))) => classify(
            OutcomeFailure {
                failure_type: FailureType::ResourceLimit,
                message,
                retryable: false,
                status: ScannerStatus::Error,
            },
            Vec::new(),
        ),
        Ok(Ok(result)) => {
            // Contract gate first: an unsupported contract version is an
            // explicit failure — never parsed optimistically, and any payload
            // it carried is dropped with the result.
            if let Err(unsupported) = validate_scanner_contract_version(result.contract_version) {
                return classify(
                    OutcomeFailure {
                        failure_type: FailureType::Error,
                        message: unsupported.to_string(),
                        retryable: false,
                        status: ScannerStatus::Error,
                    },
                    Vec::new(),
                );
            }
            if result.request_id != request_id || result.scanner_id != item.meta.scanner_id {
                // An identity mismatch is untrusted; drop any payload it carried.
                return classify(
                    OutcomeFailure {
                        failure_type: FailureType::Error,
                        message: "scanner result identity mismatch".to_string(),
                        retryable: false,
                        status: ScannerStatus::Error,
                    },
                    Vec::new(),
                );
            }
            // From here the result is validated: its audit provenance is
            // carried through to the outcome unchanged (never substituted).
            let provenance = result.provenance.clone();
            match result.status {
                ScannerStatus::NotApplicable if item.meta.required => {
                    // Runtime NotApplicable after the scanner was selected as
                    // applicable is NOT a definite completion for REQUIRED
                    // analysis: required coverage must stay incomplete and the
                    // outcome inconclusive (never Clean/Allow). Explicit
                    // non-CLEAN unknown evidence via the failure path, and the
                    // scanner's own findings from this response are dropped.
                    let mut collected = classify(
                        OutcomeFailure {
                            failure_type: FailureType::Error,
                            message: "required scanner reported NotApplicable after selection"
                                .to_string(),
                            retryable: true,
                            status: ScannerStatus::Unknown,
                        },
                        Vec::new(),
                    );
                    collected.provenance = provenance;
                    collected
                },
                ScannerStatus::Clean
                | ScannerStatus::Threat
                | ScannerStatus::Suspicious
                | ScannerStatus::NotApplicable => {
                    let findings = normalize_findings(
                        item.meta.scanner_type,
                        &target,
                        result.status,
                        &result.findings,
                    );
                    let status = escalate_definite_status(result.status, &findings);
                    Collected {
                        scanner_id: item.meta.scanner_id.clone(),
                        scanner_type: item.meta.scanner_type,
                        execution_class: item.meta.execution_class,
                        required: item.meta.required,
                        applicable: true,
                        status,
                        duration_ms,
                        findings,
                        failure: None,
                        completed_at: Utc::now(),
                        provenance,
                    }
                },
                ScannerStatus::Unknown => {
                    let partial = normalize_findings(
                        item.meta.scanner_type,
                        &target,
                        result.status,
                        &result.findings,
                    );
                    let mut collected = classify(
                        OutcomeFailure {
                            failure_type: FailureType::Error,
                            message: result
                                .message
                                .unwrap_or_else(|| "scanner reported unknown result".to_string()),
                            retryable: true,
                            status: ScannerStatus::Unknown,
                        },
                        partial,
                    );
                    collected.provenance = provenance;
                    collected
                },
                ScannerStatus::Error => {
                    let partial = normalize_findings(
                        item.meta.scanner_type,
                        &target,
                        result.status,
                        &result.findings,
                    );
                    let mut collected = classify(
                        OutcomeFailure {
                            failure_type: FailureType::Error,
                            message: result
                                .message
                                .unwrap_or_else(|| "scanner reported error".to_string()),
                            retryable: false,
                            status: ScannerStatus::Error,
                        },
                        partial,
                    );
                    collected.provenance = provenance;
                    collected
                },
            }
        },
    }
}

fn join_failure(
    meta: &Option<FailureMeta>,
    join_err: tokio::task::JoinError,
    target: &Arc<ScanTarget>,
) -> Collected {
    match meta {
        Some(meta) => {
            let failure = if join_err.is_panic() {
                // Panic payloads are deliberately not propagated: they may echo
                // untrusted content. The stable message is the evidence.
                OutcomeFailure {
                    failure_type: FailureType::Error,
                    message: "scanner task panicked".to_string(),
                    retryable: false,
                    status: ScannerStatus::Error,
                }
            } else if join_err.is_cancelled() {
                OutcomeFailure {
                    failure_type: FailureType::Timeout,
                    message: "scanner task cancelled by fabric deadline".to_string(),
                    retryable: true,
                    status: ScannerStatus::Unknown,
                }
            } else {
                OutcomeFailure {
                    failure_type: FailureType::Error,
                    message: "scanner task failed".to_string(),
                    retryable: false,
                    status: ScannerStatus::Error,
                }
            };
            Collected::inconclusive(
                &meta.scanner,
                target,
                failure,
                Vec::new(),
                meta.spawned_at.elapsed().as_millis() as u64,
            )
        },
        None => Collected {
            scanner_id: ScannerId::new("untracked"),
            scanner_type: ScannerType::Custom,
            execution_class: ExecutionClass::StandardRequired,
            // An unattributed internal task failure cannot be safely treated
            // as optional enrichment: treat it as REQUIRED so it drives the
            // inconclusive/fail-safe path rather than a clean aggregate.
            required: true,
            applicable: true,
            status: ScannerStatus::Error,
            duration_ms: 0,
            findings: Vec::new(),
            failure: Some(OutcomeFailure {
                failure_type: FailureType::Error,
                message: "untracked scanner task failed".to_string(),
                retryable: false,
                status: ScannerStatus::Error,
            }),
            completed_at: Utc::now(),
            provenance: unspecified_provenance(),
        },
    }
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Strip ASCII control characters, trim leading/trailing whitespace and
/// truncate to `max_chars` Unicode scalar values.
///
/// Pure, deterministic and panic-free: scanner-supplied finding text is
/// untrusted and must never carry terminal escapes/control bytes or grow
/// without bound into storage, logs or UI. Applied by [`normalize_findings`]
/// to the category label (before category mapping), the description, each
/// indicator value/context, and — via [`normalize_finding_details`] — every
/// string inside a fitting `details` value.
fn normalize_bounded_finding_text(raw: &str, max_chars: usize) -> String {
    let stripped: String = raw.chars().filter(|ch| !ch.is_ascii_control()).collect();
    stripped.trim().chars().take(max_chars).collect()
}

/// The exact replacement written to `SecurityFinding.details` when the
/// scanner-supplied value exceeds any details bound or cannot be safely
/// represented. Only the `details` field is replaced; the finding and every
/// other normalized field are retained.
fn details_truncated_marker() -> serde_json::Value {
    serde_json::json!({ "truncated": true })
}

/// Recursively normalize one scanner-supplied `details` value under the
/// private depth/entry/item/string bounds.
///
/// Returns `None` when the value (or any child) exceeds a bound, carries a
/// non-finite number, or cannot be safely represented (for example two
/// distinct object keys that collide after control stripping). Pure,
/// deterministic and panic-free; used only by [`normalize_finding_details`].
fn normalize_details_value(value: &serde_json::Value, depth: usize) -> Option<serde_json::Value> {
    if depth > MAX_DETAILS_JSON_DEPTH {
        return None;
    }
    match value {
        serde_json::Value::Null => Some(serde_json::Value::Null),
        serde_json::Value::Bool(flag) => Some(serde_json::Value::Bool(*flag)),
        serde_json::Value::Number(number) => {
            // Non-finite numbers cannot be represented in JSON and are
            // rejected rather than coerced.
            if number.as_f64().is_some_and(|float| float.is_finite()) {
                Some(serde_json::Value::Number(number.clone()))
            } else {
                None
            }
        },
        serde_json::Value::String(raw) => {
            if raw.chars().count() > MAX_DETAILS_STRING_CHARS {
                return None;
            }
            Some(serde_json::Value::String(normalize_bounded_finding_text(
                raw,
                MAX_DETAILS_STRING_CHARS,
            )))
        },
        serde_json::Value::Array(items) => {
            if items.len() > MAX_DETAILS_ARRAY_ITEMS {
                return None;
            }
            let mut normalized = Vec::with_capacity(items.len());
            for item in items {
                normalized.push(normalize_details_value(item, depth + 1)?);
            }
            Some(serde_json::Value::Array(normalized))
        },
        serde_json::Value::Object(entries) => {
            if entries.len() > MAX_DETAILS_OBJECT_ENTRIES {
                return None;
            }
            let mut normalized = serde_json::Map::with_capacity(entries.len());
            for (raw_key, child) in entries {
                if raw_key.chars().count() > MAX_DETAILS_STRING_CHARS {
                    return None;
                }
                let key = normalize_bounded_finding_text(raw_key, MAX_DETAILS_STRING_CHARS);
                let value = normalize_details_value(child, depth + 1)?;
                // Distinct raw keys can collide after control stripping;
                // silently overwriting would drop data, so the value is not
                // safely representable in that case.
                if normalized.contains_key(&key) {
                    return None;
                }
                normalized.insert(key, value);
            }
            Some(serde_json::Value::Object(normalized))
        },
    }
}

/// Normalize a scanner-supplied [`ScannerFinding::details`] value before it
/// is placed on the persisted/transported [`SecurityFinding`].
///
/// `None` input stays `None`. A fitting value is returned with child strings
/// control-stripped/trimmed/clamped. Any input that exceeds
/// [`MAX_DETAILS_JSON_DEPTH`], [`MAX_DETAILS_OBJECT_ENTRIES`],
/// [`MAX_DETAILS_ARRAY_ITEMS`] or [`MAX_DETAILS_STRING_CHARS`], carries a
/// non-finite number, serializes above [`MAX_DETAILS_SERIALIZED_BYTES`], or
/// otherwise cannot be safely represented is replaced by
/// [`details_truncated_marker`] — only `details` changes; the finding and all
/// non-details behavior are retained. Pure, deterministic and panic-free.
///
/// This bounds scanner-provided data at the Fabric persistence/transport
/// boundary; it is not HTML/UI sanitization.
fn normalize_finding_details(details: Option<&serde_json::Value>) -> Option<serde_json::Value> {
    let value = details?;
    let normalized = match normalize_details_value(value, 0) {
        Some(normalized) => normalized,
        None => return Some(details_truncated_marker()),
    };
    match serde_json::to_string(&normalized) {
        Ok(serialized) if serialized.len() <= MAX_DETAILS_SERIALIZED_BYTES => Some(normalized),
        Ok(_) | Err(_) => Some(details_truncated_marker()),
    }
}

fn normalize_findings(
    scanner_type: ScannerType,
    target: &ScanTarget,
    result_status: ScannerStatus,
    scanner_findings: &[ScannerFinding],
) -> Vec<SecurityFinding> {
    let base = if matches!(
        result_status,
        ScannerStatus::Clean
            | ScannerStatus::Threat
            | ScannerStatus::Suspicious
            | ScannerStatus::NotApplicable
    ) {
        result_status
    } else {
        ScannerStatus::Unknown
    };

    scanner_findings
        .iter()
        .map(|finding| {
            let scanner_status = match finding.severity {
                FindingSeverity::Critical | FindingSeverity::High => ScannerStatus::Threat,
                FindingSeverity::Medium => ScannerStatus::Suspicious,
                FindingSeverity::Low | FindingSeverity::Info => base,
            };
            let category_label =
                normalize_bounded_finding_text(&finding.category, MAX_FINDING_CATEGORY_LEN);
            let description =
                normalize_bounded_finding_text(&finding.description, MAX_FINDING_DESCRIPTION_LEN);
            let indicators = finding
                .indicators
                .iter()
                .map(|indicator| Indicator {
                    indicator_type: indicator.indicator_type,
                    value: normalize_bounded_finding_text(
                        &indicator.value,
                        MAX_INDICATOR_VALUE_LEN,
                    ),
                    context: indicator.context.as_ref().map(|context| {
                        normalize_bounded_finding_text(context, MAX_INDICATOR_CONTEXT_LEN)
                    }),
                })
                .collect();
            SecurityFinding {
                id: FindingId(finding.id),
                scope: FindingScope::Transaction,
                scanner: scanner_type,
                scanner_status,
                severity: finding.severity,
                confidence: Confidence::Medium,
                category: category_from_label(&category_label),
                description,
                details: normalize_finding_details(finding.details.as_ref()),
                indicators,
                created_at: Utc::now(),
                false_positive: finding.false_positive,
                transaction_id: Some(target.transaction_id.clone()),
                tenant_message_id: target.tenant_message_id.clone(),
            }
        })
        .collect()
}

fn category_from_label(label: &str) -> FindingCategory {
    match label.to_ascii_lowercase().as_str() {
        "malware" => FindingCategory::Malware,
        "phishing" => FindingCategory::Phishing,
        "spam" => FindingCategory::Spam,
        "spoofing" => FindingCategory::Spoofing,
        "business_email_compromise" => FindingCategory::BusinessEmailCompromise,
        "credential_harvest" => FindingCategory::CredentialHarvest,
        "malicious_url" => FindingCategory::MaliciousUrl,
        "malicious_attachment" => FindingCategory::MaliciousAttachment,
        "suspicious_content" => FindingCategory::SuspiciousContent,
        "policy_violation" => FindingCategory::PolicyViolation,
        "auth_failure" => FindingCategory::AuthFailure,
        "reputation" => FindingCategory::Reputation,
        _ => FindingCategory::Unknown,
    }
}

fn escalate_definite_status(base: ScannerStatus, findings: &[SecurityFinding]) -> ScannerStatus {
    let rank = |status: ScannerStatus| match status {
        ScannerStatus::Threat => 0,
        ScannerStatus::Suspicious => 1,
        _ => 3,
    };
    let mut worst = rank(base);
    for finding in findings.iter().filter(|f| !f.false_positive) {
        worst = worst.min(rank(finding.scanner_status));
    }
    match worst {
        0 => ScannerStatus::Threat,
        1 => ScannerStatus::Suspicious,
        _ => base,
    }
}

fn failure_description(failure_type: FailureType) -> &'static str {
    match failure_type {
        FailureType::Timeout => "Scanner wall-clock deadline exceeded; analysis result unknown",
        FailureType::Unavailable => "Scanner unavailable; analysis was not completed",
        FailureType::Error => "Scanner failed; analysis result unknown",
        FailureType::ResourceLimit => "Scanner resource limit exceeded; analysis incomplete",
    }
}

fn failure_finding(
    scanner_type: ScannerType,
    target: &ScanTarget,
    failure: &OutcomeFailure,
    created_at: DateTime<Utc>,
) -> SecurityFinding {
    SecurityFinding {
        id: FindingId::new(),
        scope: FindingScope::Transaction,
        scanner: scanner_type,
        scanner_status: failure.status,
        severity: FindingSeverity::Medium,
        confidence: Confidence::High,
        category: FindingCategory::Unknown,
        description: failure_description(failure.failure_type).to_string(),
        details: Some(serde_json::json!({
            "failure_type": failure.failure_type,
            "retryable": failure.retryable,
        })),
        indicators: Vec::new(),
        created_at,
        false_positive: false,
        transaction_id: Some(target.transaction_id.clone()),
        tenant_message_id: target.tenant_message_id.clone(),
    }
}

// ---------------------------------------------------------------------------
// Collection and assembly
// ---------------------------------------------------------------------------

struct Collected {
    scanner_id: ScannerId,
    scanner_type: ScannerType,
    execution_class: ExecutionClass,
    required: bool,
    applicable: bool,
    status: ScannerStatus,
    duration_ms: u64,
    findings: Vec<SecurityFinding>,
    failure: Option<OutcomeFailure>,
    completed_at: DateTime<Utc>,
    provenance: ScannerProvenance,
}

/// Fabric-synthesized provenance for outcomes that never carried a validated
/// [`ScanResult`] (pre-invocation rejections, not-applicable skips, timeouts,
/// adapter errors, panics). Audit metadata only: every optional
/// identity/version field is absent.
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

impl Collected {
    fn inconclusive(
        meta: &ScannerMeta,
        target: &ScanTarget,
        failure: OutcomeFailure,
        mut partial: Vec<SecurityFinding>,
        duration_ms: u64,
    ) -> Self {
        let completed_at = Utc::now();
        partial.push(failure_finding(
            meta.scanner_type,
            target,
            &failure,
            completed_at,
        ));
        Self {
            scanner_id: meta.scanner_id.clone(),
            scanner_type: meta.scanner_type,
            execution_class: meta.execution_class,
            required: meta.required,
            applicable: true,
            status: failure.status,
            duration_ms,
            findings: partial,
            failure: Some(failure),
            completed_at,
            provenance: unspecified_provenance(),
        }
    }

    fn not_applicable(meta: &ScannerMeta) -> Self {
        Self {
            scanner_id: meta.scanner_id.clone(),
            scanner_type: meta.scanner_type,
            execution_class: meta.execution_class,
            required: meta.required,
            applicable: false,
            status: ScannerStatus::NotApplicable,
            duration_ms: 0,
            findings: Vec::new(),
            failure: None,
            completed_at: Utc::now(),
            provenance: unspecified_provenance(),
        }
    }
}

fn severity_rank(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
        FindingSeverity::Info => 4,
    }
}

fn category_rank(category: FindingCategory) -> u8 {
    match category {
        FindingCategory::Malware => 0,
        FindingCategory::Phishing => 1,
        FindingCategory::Spam => 2,
        FindingCategory::Spoofing => 3,
        FindingCategory::BusinessEmailCompromise => 4,
        FindingCategory::CredentialHarvest => 5,
        FindingCategory::MaliciousUrl => 6,
        FindingCategory::MaliciousAttachment => 7,
        FindingCategory::SuspiciousContent => 8,
        FindingCategory::PolicyViolation => 9,
        FindingCategory::AuthFailure => 10,
        FindingCategory::Reputation => 11,
        FindingCategory::Unknown => 12,
    }
}

fn assemble_outcome(
    target: Arc<ScanTarget>,
    mut collected: Vec<Collected>,
    config: &FabricConfig,
    fabric_started: Instant,
) -> FabricOutcome {
    collected.sort_by(|a, b| a.scanner_id.0.cmp(&b.scanner_id.0));

    let mut coverage = FabricCoverage::default();
    for entry in &collected {
        if !entry.applicable {
            coverage.skipped += 1;
            continue;
        }
        coverage.applicable += 1;
        if entry.required {
            coverage.required_applicable += 1;
        } else {
            coverage.optional_applicable += 1;
        }
        if entry.failure.is_some() {
            coverage.inconclusive += 1;
            if entry.required {
                coverage.required_inconclusive += 1;
            } else {
                coverage.optional_inconclusive += 1;
            }
        } else {
            coverage.completed += 1;
        }
    }

    // Only missing or failed applicable REQUIRED analysis makes the outcome
    // inconclusive (and selects `on_inconclusive`). OPTIONAL_ENRICHMENT /
    // DEEP_ANALYSIS failures stay explicit in `coverage.optional_inconclusive`,
    // per-scanner outcomes, findings and failures, but do not by themselves
    // block an otherwise clean required outcome.
    let inconclusive = coverage.required_applicable == 0 || coverage.required_inconclusive > 0;

    // Threat/suspicious evidence is collected from EVERY applicable scanner
    // (successful or not) so threat evidence always overrides; unknown/error
    // escalation of the aggregate status only applies to REQUIRED scanners —
    // optional/deep failures are recorded but do not make a complete required
    // run non-clean.
    let mut threat_evidence = false;
    let mut suspicious_evidence = false;
    let mut required_error = false;
    let mut required_unknown = false;
    for entry in &collected {
        if !entry.applicable {
            continue;
        }
        for status in std::iter::once(entry.status).chain(
            entry
                .findings
                .iter()
                .filter(|f| !f.false_positive)
                .map(|f| f.scanner_status),
        ) {
            match status {
                ScannerStatus::Threat => threat_evidence = true,
                ScannerStatus::Suspicious => suspicious_evidence = true,
                ScannerStatus::Error if entry.required => required_error = true,
                ScannerStatus::Unknown if entry.required => required_unknown = true,
                ScannerStatus::Error | ScannerStatus::Unknown => {},
                _ => {},
            }
        }
    }

    // Coverage problems dominate: missing/failed REQUIRED analysis
    // outranks suspicious signals because the evidence set may be incomplete.
    // Threat evidence from any successful scanner overrides everything.
    let status = if threat_evidence {
        ScannerStatus::Threat
    } else if required_error {
        ScannerStatus::Error
    } else if required_unknown || coverage.required_applicable == 0 {
        ScannerStatus::Unknown
    } else if suspicious_evidence {
        ScannerStatus::Suspicious
    } else {
        ScannerStatus::Clean
    };

    let fail_safe_disposition = if threat_evidence {
        config.on_threat
    } else if inconclusive {
        config.on_inconclusive
    } else if suspicious_evidence {
        config.on_suspicious
    } else {
        Disposition::Allow
    };

    debug_assert!(
        !(status == ScannerStatus::Clean
            && (inconclusive
                || threat_evidence
                || suspicious_evidence
                || required_unknown
                || required_error)),
        "clean status must never coexist with inconclusive REQUIRED coverage, threat/suspicious evidence, or REQUIRED unknown/error"
    );
    debug_assert!(
        !(inconclusive && fail_safe_disposition == Disposition::Allow),
        "inconclusive analysis must never fail open to Allow"
    );

    let mut findings: Vec<(u8, String, u8, String, Uuid, SecurityFinding)> = Vec::new();
    let mut failures: Vec<(String, ScannerFailure)> = Vec::new();
    let mut scanner_outcomes: Vec<ScannerOutcome> = Vec::new();

    for entry in &collected {
        // Persisted failure text is clamped/sanitized at the single write
        // point so raw engine/untrusted failure messages never reach
        // outcomes or stored failures unclamped (normalized findings never
        // carry raw failure text at all — see `failure_finding`).
        let sanitized_failure = entry.failure.as_ref().map(|failure| OutcomeFailure {
            message: sanitize_failure_message(&failure.message),
            ..failure.clone()
        });

        scanner_outcomes.push(ScannerOutcome {
            scanner_id: entry.scanner_id.clone(),
            scanner_type: entry.scanner_type,
            execution_class: entry.execution_class,
            required: entry.required,
            applicable: entry.applicable,
            status: entry.status,
            duration_ms: entry.duration_ms,
            finding_count: entry.findings.len(),
            failure: sanitized_failure.clone(),
            completed_at: entry.completed_at,
            provenance: entry.provenance.clone(),
        });

        if let Some(failure) = &sanitized_failure {
            failures.push((
                entry.scanner_id.0.clone(),
                ScannerFailure {
                    scanner: entry.scanner_type,
                    failure_type: failure.failure_type,
                    message: failure.message.clone(),
                    retryable: failure.retryable,
                    failed_at: entry.completed_at,
                },
            ));
        }

        for finding in &entry.findings {
            findings.push((
                severity_rank(finding.severity),
                entry.scanner_id.0.clone(),
                category_rank(finding.category),
                finding.description.clone(),
                finding.id.0,
                finding.clone(),
            ));
        }
    }

    findings.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.3.cmp(&b.3))
            .then_with(|| a.4.cmp(&b.4))
    });
    failures.sort_by(|a, b| a.0.cmp(&b.0));

    FabricOutcome {
        request_id: target.request_id,
        transaction_id: target.transaction_id.clone(),
        status,
        coverage,
        inconclusive,
        findings: findings.into_iter().map(|entry| entry.5).collect(),
        failures: failures.into_iter().map(|entry| entry.1).collect(),
        scanner_outcomes,
        fail_safe_disposition,
        completed_at: Utc::now(),
        duration_ms: fabric_started.elapsed().as_millis() as u64,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_failure_message_strips_control_characters() {
        let raw = "engine failed: \x1b[31mred\x1b[0m\x00tail\n";
        let sanitized = sanitize_failure_message(raw);
        assert!(!sanitized.chars().any(char::is_control));
        assert!(sanitized.contains("engine failed:"));
        assert!(sanitized.contains("red"));
        assert!(sanitized.contains("tail"));
    }

    #[test]
    fn sanitize_failure_message_clamps_length_with_ellipsis() {
        let raw = "A".repeat(MAX_PERSISTED_FAILURE_MESSAGE_LEN * 4);
        let sanitized = sanitize_failure_message(&raw);
        assert!(
            sanitized.chars().count() <= MAX_PERSISTED_FAILURE_MESSAGE_LEN,
            "clamped message must not exceed the limit"
        );
        assert!(sanitized.ends_with("..."));
        assert!(sanitized.starts_with("A"));
    }

    #[test]
    fn sanitize_failure_message_trims_and_keeps_short_text() {
        assert_eq!(sanitize_failure_message("  timed out  "), "timed out");
        assert_eq!(sanitize_failure_message(""), "");
        assert_eq!(sanitize_failure_message("\n\t"), "");
    }

    #[test]
    fn sanitize_failure_message_is_idempotent() {
        let raw = format!("{}{}", "\x1b[2Jboom", "B".repeat(1000));
        let once = sanitize_failure_message(&raw);
        let twice = sanitize_failure_message(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn derive_scanner_request_id_is_deterministic() {
        let scan_request_id = Uuid::new_v4();
        let scanner_id = ScannerId::new("test-a");
        let first = derive_scanner_request_id(&scan_request_id, &scanner_id);
        let second = derive_scanner_request_id(&scan_request_id, &scanner_id);
        assert_eq!(
            first, second,
            "same scan operation + scanner must derive the same ID"
        );
    }

    #[test]
    fn derive_scanner_request_id_is_unique_across_scanners_and_operations() {
        let scan_request_id = Uuid::new_v4();
        let other_scan_request_id = Uuid::new_v4();
        let a = derive_scanner_request_id(&scan_request_id, &ScannerId::new("test-a"));
        let b = derive_scanner_request_id(&scan_request_id, &ScannerId::new("test-b"));
        let a_other = derive_scanner_request_id(&other_scan_request_id, &ScannerId::new("test-a"));
        assert_ne!(
            a, b,
            "distinct scanners on one operation must get distinct IDs"
        );
        assert_ne!(a, a_other, "distinct operations must get distinct IDs");
        assert_ne!(
            a, scan_request_id,
            "derived ID is never the operation correlation ID"
        );
    }

    #[test]
    fn content_type_matches_wildcard_and_prefix() {
        assert!(content_type_matches("*", "message/rfc822"));
        assert!(content_type_matches("*", "application/pdf"));
        assert!(content_type_matches("*", "anything/at-all"));

        assert!(content_type_matches("message/*", "message/rfc822"));
        assert!(content_type_matches("message/*", "message/global"));
        assert!(!content_type_matches("message/*", "application/pdf"));
        assert!(!content_type_matches("message/*", "messagex/rfc822"));
        assert!(!content_type_matches("message/*", "message"));

        assert!(content_type_matches("application/*", "application/pdf"));
        assert!(content_type_matches(
            "application/*",
            "application/octet-stream"
        ));
        assert!(!content_type_matches("application/*", "text/plain"));
    }

    #[test]
    fn content_type_matches_exact_and_mismatch() {
        assert!(content_type_matches("message/rfc822", "message/rfc822"));
        assert!(!content_type_matches("message/rfc822", "message/global"));
        assert!(!content_type_matches("message/rfc822", "MESSAGE/RFC822"));
        assert!(!content_type_matches("message/rfc822", "message/rfc822x"));
        assert!(!content_type_matches("", "message/rfc822"));
    }
}

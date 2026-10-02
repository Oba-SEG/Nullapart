//! Internal Phase 2 Mail Core-to-ScannerFabric composition boundary.
//!
//! This module is never a network endpoint, never a browser API, and never a
//! raw storage location/bytes API.
//!
//! [`MailCoreScannerPipeline::scan`] issues a crate-private artifact access
//! grant, reads the authorized artifact through [`InMemoryArtifactStore`],
//! builds a scanner-sdk [`ScanTarget`] strictly from server-derived identity
//! plus store-authorized content metadata, and returns a compact
//! [`MailCoreScanOutcome`] intended only for internal policy handoff.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use nullapart_mail_contracts::artifact::{
    Artifact, ContentType, RetentionClass, StorageBackend, StorageLocation,
};
use nullapart_mail_contracts::policy::ReasonCode;
use nullapart_mail_contracts::transaction::{
    ContentHash, CustomerId, DeploymentId, Disposition, TenantMessageId, TraceId, TransactionId,
};
use nullapart_mail_contracts::{
    ArtifactHash, ArtifactId, HashAlgorithm, ScannerFailure, ScannerStatus, SecurityFinding,
};
use nullapart_scanner_sdk::fabric::{FabricCoverage, ScanTarget, ScannerFabric};
use nullapart_scanner_sdk::trait_defs::{ScanContent, ScanContentError};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::PgPool;
use uuid::Uuid;

use crate::artifact_store::{
    ArtifactAccessGrant, ArtifactAccessPurpose, ArtifactPermissions, ArtifactScope,
    ArtifactStoreError, AuthorizedArtifactMetadata, FilesystemArtifactStore, InMemoryArtifactStore,
};
use crate::phase2_persistence::{
    Phase2PersistenceError, Phase2PersistenceInput, PostgresPhase2Persistence,
};
use crate::policy::PolicyEvaluationResult;
use crate::scanner_fabric::{ScanArtifact, ScannerFabricResult};

/// Stable server-side actor identity bound into pipeline-issued grants.
const SCANNER_PIPELINE_ACTOR_ID: &str = "mail-core-scanner-pipeline";

/// Lifetime of a pipeline-issued scanner grant, in seconds.
const SCANNER_GRANT_TTL_SECONDS: i64 = 60;

/// Maximum authorized scanner input accepted by the preflight gate, in bytes
/// (50 MiB). An artifact whose declared size exceeds this never has its bytes
/// read and never reaches the fabric.
const MAX_SCANNER_INPUT_BYTES: u64 = 50 * 1024 * 1024;

/// Stable failure code returned when the artifact grant could not be issued
/// or the authorized artifact could not be read. It never encodes backend
/// error detail or cross-scope existence.
const ARTIFACT_UNAVAILABLE: &str = "ARTIFACT_UNAVAILABLE";

/// Stable fail-safe code returned when the stored artifact is declared
/// not scanner-eligible; bytes are never read and the fabric is never
/// invoked.
const ARTIFACT_NOT_SCANNER_ELIGIBLE: &str = "ARTIFACT_NOT_SCANNER_ELIGIBLE";

/// Stable fail-safe code returned when the declared artifact size exceeds
/// [`MAX_SCANNER_INPUT_BYTES`]; bytes are never read and the fabric is never
/// invoked.
const ARTIFACT_INPUT_LIMIT_EXCEEDED: &str = "ARTIFACT_INPUT_LIMIT_EXCEEDED";

/// Stable fail-safe code returned when the authorized byte length does not
/// exactly equal the preflight metadata size; the fabric is never invoked.
const ARTIFACT_METADATA_MISMATCH: &str = "ARTIFACT_METADATA_MISMATCH";

/// Private in-memory [`ScanContent`] over store-authorized artifact bytes.
///
/// Bytes are shared immutable storage (`Arc<[u8]>`): a bounded read clones
/// the allocation rather than copying the artifact. The fabric acquires
/// these bytes exactly once, verifies them against the declared content
/// hash itself, and never reads this provider again — adapters only ever
/// see the fabric's immutable snapshot.
struct InMemoryScanContent {
    bytes: Arc<[u8]>,
    content_type: ContentType,
}

impl ScanContent for InMemoryScanContent {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn content_type(&self) -> &ContentType {
        &self.content_type
    }

    fn read_all_bounded<'life0, 'async_trait>(
        &'life0 self,
        max: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<[u8]>, ScanContentError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if self.bytes.len() as u64 > max {
                return Err(ScanContentError::LimitExceeded);
            }
            Ok(Arc::clone(&self.bytes))
        })
    }
}

/// Errors for the Mail Core-to-ScannerFabric composition boundary.
///
/// Retained as a public error shape for the composition boundary; [`scan`]
/// never returns it and never uses it to surface raw backend existence.
///
/// [`scan`]: MailCoreScannerPipeline::scan
#[derive(Debug)]
pub enum ScannerPipelineError {
    /// A required artifact is not available for processing.
    ArtifactUnavailable,
    /// The provided input is invalid.
    InvalidInput,
}

/// Server-derived scan request.
///
/// Built only from authenticated/internal server context. Content hash,
/// content type, byte size, artifact bytes, storage location and any
/// caller-selected scope or permission bits are deliberately absent: all of
/// those derive from the [`InMemoryArtifactStore`] under a server-issued
/// grant at execution time.
#[derive(Debug, Clone)]
pub struct ServerDerivedScanRequest {
    /// Transaction being scanned.
    pub transaction_id: TransactionId,
    /// Deployment that owns the artifact.
    pub deployment_id: DeploymentId,
    /// Customer/tenant identity from server context; `None` selects
    /// System scope for grant issuance.
    pub customer_id: Option<CustomerId>,
    /// Tenant message instance if this scan is tenant-scoped.
    pub tenant_message_id: Option<TenantMessageId>,
    /// Artifact reference to scan.
    pub artifact_id: ArtifactId,
    /// When the scan was requested.
    pub requested_at: DateTime<Utc>,
    /// Distributed trace identity for correlation.
    pub trace_id: TraceId,
    /// Scanner-specific parameters (server-assembled).
    pub params: serde_json::Value,
}

/// Server-derived identity for one tenant-scoped scan.
///
/// This is the shared context between [`MailCoreScannerPipeline`] and the
/// durable scanner evidence repository. It carries the tenant message,
/// transaction, deployment, customer and trace identity, plus only the
/// trusted SMTP envelope metadata (MAIL FROM / RCPT TO) already derived by
/// the server-side recipient partitioner.
///
/// It deliberately carries no artifact reference, no artifact scope or
/// permission bits, no content hash, no storage location and no raw MIME or
/// header bytes: callers can never choose what the pipeline may read or what
/// scope evidence is written under. Tenant scope always derives from
/// `customer_id`, which the evidence repository sets as the RLS
/// `app.current_customer_id` before any insert.
///
/// The type has no `Deserialize` implementation and no browser-facing
/// constructor, so it cannot be assembled from browser request JSON.
#[derive(Debug, Clone)]
pub struct TenantScanContext {
    /// Tenant message instance this scan belongs to.
    pub tenant_message_id: TenantMessageId,
    /// Parent SMTP transaction.
    pub transaction_id: TransactionId,
    /// Deployment that owns the transaction and its artifacts.
    pub deployment_id: DeploymentId,
    /// Customer/tenant identity from server context. It is the sole source
    /// of the evidence repository's tenant RLS scope.
    pub customer_id: CustomerId,
    /// Distributed trace identity for correlation.
    pub trace_id: TraceId,
    /// Stable server-observed acceptance timestamp. It is reused as immutable
    /// artifact metadata so an after-queue retry publishes the exact same
    /// artifact instead of conflicting on a newly sampled clock value.
    pub accepted_at: DateTime<Utc>,
    /// Trusted envelope sender (MAIL FROM) from server-side partitioning;
    /// never parsed from caller-supplied request JSON.
    pub envelope_sender: String,
    /// Trusted envelope recipients (RCPT TO) from server-side partitioning.
    pub recipients: Vec<String>,
}

impl TenantScanContext {
    /// Derives the pipeline scan request for one artifact of this tenant
    /// message. Artifact scope is derived from the server-derived
    /// `customer_id` (Customer scope, never caller-selected), and the
    /// artifact reference is an explicit argument rather than context state.
    pub fn scan_request(
        &self,
        artifact_id: ArtifactId,
        requested_at: DateTime<Utc>,
        params: serde_json::Value,
    ) -> ServerDerivedScanRequest {
        ServerDerivedScanRequest {
            transaction_id: self.transaction_id.clone(),
            deployment_id: self.deployment_id.clone(),
            customer_id: Some(self.customer_id.clone()),
            tenant_message_id: Some(self.tenant_message_id.clone()),
            artifact_id,
            requested_at,
            trace_id: self.trace_id.clone(),
            params,
        }
    }
}

/// Compact pipeline-level failure carried on a [`MailCoreScanOutcome`].
///
/// Only stable machine-readable codes; never a raw backend error string and
/// never an existence signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailCoreScanFailure {
    /// Stable machine-readable failure code.
    pub code: String,
}

impl MailCoreScanFailure {
    /// The fail-safe code used when the artifact grant could not be issued or
    /// the authorized artifact could not be read.
    pub fn artifact_unavailable() -> Self {
        Self {
            code: ARTIFACT_UNAVAILABLE.to_string(),
        }
    }
}

/// Compact result of one Mail Core scan invocation.
///
/// This output is an internal policy handoff only — not a UI response, not an
/// API response, and never a raw storage location/bytes API. It carries the
/// fabric findings, scanner failures, aggregate status, coverage and
/// fail-safe disposition (plus an optional stable pipeline failure code), and
/// never carries artifact bytes, storage data, a grant, scanner provenance or
/// raw backend error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailCoreScanOutcome {
    /// Aggregate scanner status; fail-safe `Unknown` when the artifact was
    /// unavailable — never silently `Clean`.
    pub status: ScannerStatus,
    /// Fail-safe disposition for policy fallback when no explicit rule
    /// matches.
    pub fail_safe_disposition: Disposition,
    /// REQUIRED vs OPTIONAL coverage counters (all zero when the artifact
    /// was unavailable and the fabric was never invoked).
    pub coverage: FabricCoverage,
    /// Normalized findings ready for policy evaluation.
    pub findings: Vec<SecurityFinding>,
    /// Explicit scanner failures from the fabric run.
    pub failures: Vec<ScannerFailure>,
    /// Pipeline-level fail-safe failure, if any.
    pub failure: Option<MailCoreScanFailure>,
}

impl MailCoreScanOutcome {
    /// Fail-safe outcome used when the artifact grant could not be issued or
    /// the authorized artifact could not be read. The fabric is not invoked;
    /// no bytes, storage data, grant or raw error are exposed.
    fn artifact_unavailable() -> Self {
        Self {
            status: ScannerStatus::Unknown,
            fail_safe_disposition: Disposition::Hold,
            coverage: FabricCoverage::default(),
            findings: Vec::new(),
            failures: Vec::new(),
            failure: Some(MailCoreScanFailure::artifact_unavailable()),
        }
    }

    /// Fail-safe outcome for a preflight rejection (`Unknown` + `Hold` with
    /// only the given stable generic code). The fabric is not invoked and no
    /// bytes, storage data, grant or raw error are exposed.
    fn preflight_failure(code: &str) -> Self {
        Self {
            status: ScannerStatus::Unknown,
            fail_safe_disposition: Disposition::Hold,
            coverage: FabricCoverage::default(),
            findings: Vec::new(),
            failures: Vec::new(),
            failure: Some(MailCoreScanFailure {
                code: code.to_string(),
            }),
        }
    }
}

/// Mail Core composition boundary around an [`InMemoryArtifactStore`] and a
/// [`ScannerFabric`], both supplied at construction.
pub struct MailCoreScannerPipeline {
    store: InMemoryArtifactStore,
    fabric: ScannerFabric,
}

impl MailCoreScannerPipeline {
    /// Builds a pipeline over the supplied store and fabric.
    pub fn new(store: InMemoryArtifactStore, fabric: ScannerFabric) -> Self {
        Self { store, fabric }
    }

    /// Executes one bounded scanner-fabric pass for `request`.
    ///
    /// Issues a crate-private [`ArtifactAccessGrant`] with Customer scope when
    /// `customer_id` is `Some` and System scope otherwise — Scanner purpose,
    /// exactly `[artifact_id]`, read-only, expiring `Utc::now() + 60s` — then
    /// obtains preflight metadata through [`InMemoryArtifactStore::get_metadata`]
    /// under that same grant before any bytes are read. Preflight fails safe
    /// without calling `get` or the fabric when the artifact is not
    /// scanner-eligible (stable code `ARTIFACT_NOT_SCANNER_ELIGIBLE`) or its
    /// declared size exceeds [`MAX_SCANNER_INPUT_BYTES`] (stable code
    /// `ARTIFACT_INPUT_LIMIT_EXCEEDED`). Only then does it read the artifact
    /// through the store; if the authorized byte length does not exactly equal
    /// the preflight size, it fails safe with stable code
    /// `ARTIFACT_METADATA_MISMATCH` without invoking the fabric. Content type,
    /// hash and byte size on the [`ScanTarget`] come only from that authorized
    /// read, and the operation `request_id` is the only identifier generated
    /// internally.
    ///
    /// On grant issuance or store-read failure the fabric is never invoked
    /// and a fail-safe outcome (`Disposition::Hold`, stable code
    /// `ARTIFACT_UNAVAILABLE`) is returned with no bytes, storage data, grant
    /// or raw error. All preflight rejections likewise return
    /// `Disposition::Hold` with only their stable generic code. The returned
    /// [`MailCoreScanOutcome`] is an internal policy handoff — not a UI/API
    /// response — and omits scanner provenance, per-scanner outcomes and raw
    /// error detail.
    pub async fn scan(&self, request: ServerDerivedScanRequest) -> MailCoreScanOutcome {
        let scope = match &request.customer_id {
            Some(customer_id) => ArtifactScope::Customer(customer_id.clone()),
            None => ArtifactScope::System,
        };
        let grant = match ArtifactAccessGrant::issue_server_authorized(
            request.deployment_id.clone(),
            scope,
            SCANNER_PIPELINE_ACTOR_ID.to_string(),
            ArtifactPermissions::content_read_only(),
            ArtifactAccessPurpose::Scanner,
            std::iter::once(request.artifact_id.clone()),
            Utc::now() + chrono::Duration::seconds(SCANNER_GRANT_TTL_SECONDS),
        ) {
            Ok(grant) => grant,
            Err(_) => return MailCoreScanOutcome::artifact_unavailable(),
        };
        let metadata = match self.store.get_metadata(&grant, &request.artifact_id).await {
            Ok(metadata) => metadata,
            Err(_) => return MailCoreScanOutcome::artifact_unavailable(),
        };
        if let Some(code) = preflight_rejection(&metadata) {
            return MailCoreScanOutcome::preflight_failure(code);
        }
        let authorized = match self.store.get(&grant, &request.artifact_id).await {
            Ok(authorized) => authorized,
            Err(_) => return MailCoreScanOutcome::artifact_unavailable(),
        };
        if authorized_size_mismatch(metadata.size_bytes, authorized.bytes.len()) {
            return MailCoreScanOutcome::preflight_failure(ARTIFACT_METADATA_MISMATCH);
        }
        let target = ScanTarget {
            request_id: Uuid::new_v4(),
            transaction_id: request.transaction_id.clone(),
            tenant_message_id: request.tenant_message_id.clone(),
            customer_id: request.customer_id.clone(),
            deployment_id: request.deployment_id.clone(),
            artifact_id: authorized.id.clone(),
            content_type: authorized.content_type.clone(),
            content_hash: content_hash_of(&authorized.hash),
            artifact_size_bytes: authorized.bytes.len() as u64,
            requested_at: request.requested_at,
            params: request.params,
        };
        let content = Arc::new(InMemoryScanContent {
            bytes: Arc::from(authorized.bytes),
            content_type: authorized.content_type.clone(),
        });
        let fabric_outcome = self.fabric.scan(&target, content).await;
        MailCoreScanOutcome {
            status: fabric_outcome.status,
            fail_safe_disposition: fabric_outcome.fail_safe_disposition,
            coverage: fabric_outcome.coverage,
            findings: fabric_outcome.findings,
            failures: fabric_outcome.failures,
            failure: None,
        }
    }
}

/// Derives the fabric [`ContentHash`] from the store-authorized artifact
/// hash; the hash itself never comes from the caller.
fn content_hash_of(hash: &ArtifactHash) -> ContentHash {
    let algorithm = match hash.algorithm {
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha512 => "sha512",
        HashAlgorithm::Md5 => "md5",
    };
    ContentHash::new(&format!("{algorithm}:{}", hash.value))
}

/// Preflight gate over grant-authorized metadata, evaluated before any
/// artifact bytes are read. Returns the stable fail-safe code the caller
/// must return — without calling `get` or the fabric — or `None` when the
/// artifact may proceed to the authorized byte read.
fn preflight_rejection(metadata: &AuthorizedArtifactMetadata) -> Option<&'static str> {
    if !metadata.scanner_eligible {
        return Some(ARTIFACT_NOT_SCANNER_ELIGIBLE);
    }
    if metadata.size_bytes > MAX_SCANNER_INPUT_BYTES {
        return Some(ARTIFACT_INPUT_LIMIT_EXCEEDED);
    }
    None
}

/// True when the authorized byte length does not exactly equal the
/// preflight metadata size; such a mismatch fails safe without invoking the
/// fabric.
fn authorized_size_mismatch(preflight_size_bytes: u64, authorized_len: usize) -> bool {
    authorized_len as u64 != preflight_size_bytes
}

/// Stable failures for the durable Phase 2 mail-processing coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DurableScannerPipelineError {
    #[error("phase 2 mail-processing input is invalid")]
    InvalidInput,
    #[error("phase 2 artifact conflicts with existing immutable state")]
    ArtifactConflict,
    #[error("phase 2 artifact storage is unavailable")]
    ArtifactUnavailable,
    #[error("phase 2 durable state conflicts with existing state")]
    PersistenceConflict,
    #[error("phase 2 durable state is unavailable")]
    PersistenceUnavailable,
}

/// Minimal outcome from the durable artifact-to-quarantine workflow.
///
/// It deliberately excludes raw MIME, storage paths, grants, and database
/// details. Scanner evidence remains the normalized internal contract used by
/// policy and durable evidence persistence.
#[derive(Debug, Clone)]
pub struct DurableScanOutcome {
    pub artifact_id: ArtifactId,
    pub disposition: Disposition,
    pub reason_code: ReasonCode,
    pub scan_result: ScannerFabricResult,
    pub quarantine_created: bool,
}

/// Local/development Phase 2 coordinator.
///
/// The immutable filesystem publication necessarily occurs before the single
/// PostgreSQL transaction. If database persistence fails, the already
/// published file can remain as an inaccessible immutable orphan for a
/// reconciler; no partial PostgreSQL workflow is committed.
pub struct DurableScannerPipeline {
    store: FilesystemArtifactStore,
    fabric: Arc<crate::scanner_fabric::ScannerFabric>,
    persistence: PostgresPhase2Persistence,
    inline_ml: Option<Arc<crate::inline_ml::stage::InlineMlStage>>,
}

impl DurableScannerPipeline {
    pub fn new(
        store: FilesystemArtifactStore,
        fabric: crate::scanner_fabric::ScannerFabric,
        pool: PgPool,
    ) -> Self {
        Self::new_shared(store, Arc::new(fabric), pool)
    }

    pub fn new_shared(
        store: FilesystemArtifactStore,
        fabric: Arc<crate::scanner_fabric::ScannerFabric>,
        pool: PgPool,
    ) -> Self {
        Self {
            store,
            fabric,
            persistence: PostgresPhase2Persistence::new(pool),
            inline_ml: None,
        }
    }

    /// Attach the optional pass-2 inline ML stage. `None` keeps the
    /// deterministic single-pass behaviour (stage not provisioned).
    pub fn with_inline_ml(
        mut self,
        stage: Option<Arc<crate::inline_ml::stage::InlineMlStage>>,
    ) -> Self {
        self.inline_ml = stage;
        self
    }

    /// Stores, authorizes, scans, applies the scanner fail-safe floor, and
    /// atomically persists one tenant message projection.
    pub async fn process(
        &self,
        context: TenantScanContext,
        accepted_mime: Vec<u8>,
        content_type: ContentType,
        policy_result: PolicyEvaluationResult,
    ) -> Result<DurableScanOutcome, DurableScannerPipelineError> {
        self.process_with_policy(context, accepted_mime, content_type, move |_| policy_result)
            .await
    }

    /// Runs the scanners first and then evaluates policy against the complete
    /// normalized aggregate. The evaluator is local and synchronous by design:
    /// it receives no raw content, storage grant, path, network or tool access.
    pub async fn process_with_policy<F>(
        &self,
        context: TenantScanContext,
        accepted_mime: Vec<u8>,
        content_type: ContentType,
        evaluate_policy: F,
    ) -> Result<DurableScanOutcome, DurableScannerPipelineError>
    where
        F: FnOnce(&ScannerFabricResult) -> PolicyEvaluationResult,
    {
        validate_durable_input(&context, &accepted_mime, &content_type)?;

        // One tenant message has exactly one primary MIME artifact. Reusing
        // its server-issued UUID makes retries hit the immutable conflict
        // boundary instead of publishing a second unrelated artifact.
        let artifact_id = ArtifactId(context.tenant_message_id.0);
        let hash_value = hex::encode(sha2::Sha256::digest(&accepted_mime));
        let artifact = Artifact {
            id: artifact_id.clone(),
            deployment_id: context.deployment_id.clone(),
            customer_id: Some(context.customer_id.clone()),
            content_type: content_type.clone(),
            size: accepted_mime.len() as u64,
            storage_location: StorageLocation {
                backend: StorageBackend::Filesystem,
                bucket: None,
                key: format!("{}.artifact", artifact_id.0),
                region: None,
            },
            hash: ArtifactHash {
                algorithm: HashAlgorithm::Sha256,
                value: hash_value,
            },
            retention_class: RetentionClass::Standard,
            // PostgreSQL stores TIMESTAMPTZ at microsecond precision. Keep
            // the in-process Artifact record on that same precision so the
            // release worker can reconstruct identical metadata immediately,
            // not only after a process restart has discarded local state.
            created_at: postgres_timestamp(context.accepted_at)
                .ok_or(DurableScannerPipelineError::InvalidInput)?,
            expires_at: None,
            encrypted: false,
            scanner_eligible: true,
        };
        self.store
            .put(artifact.clone(), accepted_mime)
            .await
            .map_err(|error| {
                tracing::error!(stage = "publish", "phase 2 artifact stage failed");
                map_artifact_store_error(error)
            })?;

        let grant = ArtifactAccessGrant::issue_server_authorized(
            context.deployment_id.clone(),
            ArtifactScope::Customer(context.customer_id.clone()),
            SCANNER_PIPELINE_ACTOR_ID.to_string(),
            ArtifactPermissions::content_read_only(),
            ArtifactAccessPurpose::Scanner,
            std::iter::once(artifact_id.clone()),
            Utc::now() + chrono::Duration::seconds(SCANNER_GRANT_TTL_SECONDS),
        )
        .map_err(|_| DurableScannerPipelineError::ArtifactUnavailable)?;
        let metadata = self
            .store
            .get_metadata(&grant, &artifact_id)
            .await
            .map_err(|error| {
                tracing::error!(stage = "metadata", "phase 2 artifact stage failed");
                map_artifact_store_error(error)
            })?;
        if preflight_rejection(&metadata).is_some() {
            return Err(DurableScannerPipelineError::InvalidInput);
        }
        let authorized = self
            .store
            .get(&grant, &artifact_id)
            .await
            .map_err(|error| {
                tracing::error!(stage = "authorized_read", "phase 2 artifact stage failed");
                map_artifact_store_error(error)
            })?;
        if authorized_size_mismatch(metadata.size_bytes, authorized.bytes.len())
            || metadata.hash != authorized.hash
            || metadata.content_type != authorized.content_type
        {
            return Err(DurableScannerPipelineError::ArtifactUnavailable);
        }

        let scan_artifact = ScanArtifact {
            request_id: Uuid::new_v4(),
            transaction_id: context.transaction_id.clone(),
            tenant_message_id: Some(context.tenant_message_id.clone()),
            customer_id: Some(context.customer_id.clone()),
            deployment_id: context.deployment_id.clone(),
            artifact_id: artifact_id.clone(),
            content_type: authorized.content_type.clone(),
            content_hash: content_hash_of(&authorized.hash),
            size_bytes: authorized.bytes.len() as u64,
            params: serde_json::Value::Null,
        };
        let content = Arc::new(InMemoryScanContent {
            bytes: Arc::from(authorized.bytes),
            content_type: authorized.content_type,
        });
        let scan_result = self
            .fabric
            .scan(
                scan_artifact.clone(),
                Arc::clone(&content) as Arc<dyn ScanContent>,
            )
            .await;
        let scan_result = match &self.inline_ml {
            Some(stage) => {
                let pass2 = stage
                    .run(
                        &context,
                        &scan_artifact,
                        &scan_result,
                        content.clone() as Arc<dyn ScanContent>,
                    )
                    .await;
                match pass2 {
                    Some(pass2) => crate::inline_ml::stage::merge_pass2(scan_result, pass2),
                    None => scan_result,
                }
            },
            None => scan_result,
        };
        tracing::info!(
            scanner_outcomes = scan_result.results.len(),
            findings = scan_result.findings.len(),
            failures = scan_result.failures.len(),
            requires_hold = scan_result.requires_hold,
            total_scanner_duration_ms = scan_result
                .results
                .iter()
                .map(|outcome| outcome.duration_ms)
                .sum::<u64>(),
            "phase 2 scanner fabric completed"
        );
        let policy_result = evaluate_policy(&scan_result);
        let (disposition, reason_code) = final_policy_decision(&scan_result, &policy_result);
        let persistence = self
            .persistence
            .persist(Phase2PersistenceInput {
                context: &context,
                artifact: &artifact,
                scan_result: &scan_result,
                disposition,
                reason_code: &reason_code,
                policy_revision_id: policy_result.policy_revision.0,
            })
            .await
            .map_err(map_persistence_error)?;

        Ok(DurableScanOutcome {
            artifact_id,
            disposition,
            reason_code,
            scan_result,
            quarantine_created: persistence.quarantine_created,
        })
    }
}

fn validate_durable_input(
    context: &TenantScanContext,
    accepted_mime: &[u8],
    content_type: &ContentType,
) -> Result<(), DurableScannerPipelineError> {
    if accepted_mime.is_empty()
        || accepted_mime.len() as u64 > MAX_SCANNER_INPUT_BYTES
        || !content_type.is_email()
        || context.envelope_sender.is_empty()
        || context.envelope_sender.len() > 320
        || context.recipients.is_empty()
        || context.recipients.len() > 500
        || context
            .recipients
            .iter()
            .any(|recipient| recipient.is_empty() || recipient.len() > 320)
    {
        return Err(DurableScannerPipelineError::InvalidInput);
    }
    Ok(())
}

fn postgres_timestamp(value: DateTime<Utc>) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp_micros(value.timestamp_micros())
}

fn final_policy_decision(
    scan_result: &ScannerFabricResult,
    policy_result: &PolicyEvaluationResult,
) -> (Disposition, ReasonCode) {
    if scan_result.requires_hold {
        (Disposition::Hold, ReasonCode::hold_pending())
    } else {
        (policy_result.disposition, policy_result.reason_code.clone())
    }
}

fn map_artifact_store_error(error: ArtifactStoreError) -> DurableScannerPipelineError {
    match error {
        ArtifactStoreError::ImmutableConflict => DurableScannerPipelineError::ArtifactConflict,
        ArtifactStoreError::HashMismatch
        | ArtifactStoreError::SizeMismatch
        | ArtifactStoreError::SizeLimitExceeded
        | ArtifactStoreError::RetentionViolation => DurableScannerPipelineError::InvalidInput,
        ArtifactStoreError::NotFound
        | ArtifactStoreError::StorageUnavailable
        | ArtifactStoreError::EnvironmentRejected => {
            DurableScannerPipelineError::ArtifactUnavailable
        },
    }
}

fn map_persistence_error(error: Phase2PersistenceError) -> DurableScannerPipelineError {
    match error {
        Phase2PersistenceError::InvalidInput => DurableScannerPipelineError::InvalidInput,
        Phase2PersistenceError::Conflict => DurableScannerPipelineError::PersistenceConflict,
        Phase2PersistenceError::Unavailable => DurableScannerPipelineError::PersistenceUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use nullapart_mail_contracts::artifact::{
        Artifact, ContentType, RetentionClass, StorageBackend, StorageLocation,
    };
    use nullapart_mail_contracts::finding::ScannerType;
    use nullapart_scanner_sdk::fabric::{FabricConfig, ScannerRegistration};
    use nullapart_scanner_sdk::trait_defs::{ScanError, Scanner, ScannerId};
    use nullapart_scanner_sdk::types::{
        ExecutionClass, LatencyClass, ResourceLimits, ScanRequest, ScanResult, ScannerCapabilities,
        ScannerHealth, ScannerProfile, ScannerProvenance,
    };
    use sha2::Digest;

    use super::*;

    /// Minimal deterministic fake scanner: records the exact [`ScanRequest`]
    /// it receives plus the shared bytes it reads through [`ScanContent`],
    /// and always returns `Clean` with echoed identity fields.
    #[derive(Default)]
    struct RecordingFakeScanner {
        invocations: AtomicUsize,
        seen: Mutex<Option<ScanRequest>>,
        seen_bytes: Mutex<Option<Arc<[u8]>>>,
    }

    impl Scanner for RecordingFakeScanner {
        fn id(&self) -> ScannerId {
            ScannerId::new("test-pipeline-fake")
        }

        fn name(&self) -> &str {
            "test-pipeline-fake"
        }

        fn version(&self) -> &str {
            "0.0.0-test-only"
        }

        fn capabilities(&self) -> ScannerCapabilities {
            ScannerCapabilities {
                supported_content_types: vec!["message/rfc822".to_string()],
                max_content_size: u64::MAX,
                latency_class: LatencyClass::Fast,
                requires_network: false,
                milter_compatible: true,
                extra: serde_json::json!({}),
            }
        }

        fn scan<'life0, 'async_trait>(
            &'life0 self,
            request: ScanRequest,
            content: Arc<dyn ScanContent>,
        ) -> Pin<Box<dyn Future<Output = Result<ScanResult, ScanError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            let result = ScanResult {
                request_id: request.request_id,
                contract_version: request.contract_version,
                scanner_id: self.id(),
                status: ScannerStatus::Clean,
                message: None,
                findings: Vec::new(),
                completed_at: Utc::now(),
                duration_ms: 0,
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
            *self
                .seen
                .lock()
                .expect("fake scanner request recorder must not be poisoned") = Some(request);
            Box::pin(async move {
                let bytes = content
                    .read_all_bounded(1024)
                    .await
                    .expect("fake scanner fixture read must stay within its bound");
                *self
                    .seen_bytes
                    .lock()
                    .expect("fake scanner bytes recorder must not be poisoned") = Some(bytes);
                Ok(result)
            })
        }

        fn health<'life0, 'async_trait>(
            &'life0 self,
        ) -> Pin<Box<dyn Future<Output = ScannerHealth> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                ScannerHealth {
                    healthy: true,
                    message: None,
                    checked_at: Utc::now(),
                    uptime_seconds: Some(0),
                    queue_depth: None,
                }
            })
        }
    }

    #[tokio::test]
    async fn scan_passes_stored_artifact_identity_to_required_fake_scanner() {
        let bytes = b"scanner-pipeline-body".to_vec();
        let hash_hex = hex::encode(sha2::Sha256::digest(&bytes));
        let expected_content_hash = ContentHash::new(&format!("sha256:{hash_hex}"));
        let artifact_id = ArtifactId::new();
        let deployment_id = DeploymentId::new("deployment-alpha");
        let customer_id = CustomerId::new("customer-one");

        let store = InMemoryArtifactStore::new();
        store
            .put(
                Artifact {
                    id: artifact_id.clone(),
                    deployment_id: deployment_id.clone(),
                    customer_id: Some(customer_id.clone()),
                    content_type: ContentType::new("message/rfc822"),
                    size: bytes.len() as u64,
                    storage_location: StorageLocation {
                        backend: StorageBackend::Memory,
                        bucket: None,
                        key: format!("memory/artifacts/{}", artifact_id.0),
                        region: None,
                    },
                    hash: ArtifactHash {
                        algorithm: HashAlgorithm::Sha256,
                        value: hash_hex,
                    },
                    retention_class: RetentionClass::Standard,
                    created_at: Utc::now(),
                    expires_at: None,
                    encrypted: false,
                    scanner_eligible: true,
                },
                bytes.clone(),
            )
            .await
            .expect("valid customer-owned Memory artifact must put");

        let fake = Arc::new(RecordingFakeScanner::default());
        let mut fabric = ScannerFabric::new(FabricConfig::default())
            .expect("default fabric config must be valid");
        fabric
            .register(ScannerRegistration {
                scanner: fake.clone(),
                scanner_type: ScannerType::Custom,
                profile: ScannerProfile {
                    execution_class: ExecutionClass::FastRequired,
                    wall_clock: Duration::from_secs(5),
                    max_concurrency: 1,
                    limits: ResourceLimits::bounded_defaults(),
                },
            })
            .expect("fake required scanner registration must be valid");

        let pipeline = MailCoreScannerPipeline::new(store, fabric);
        let outcome = pipeline
            .scan(ServerDerivedScanRequest {
                transaction_id: TransactionId::new(),
                deployment_id,
                customer_id: Some(customer_id),
                tenant_message_id: Some(TenantMessageId::new()),
                artifact_id: artifact_id.clone(),
                requested_at: Utc::now(),
                trace_id: TraceId::new(),
                params: serde_json::json!({}),
            })
            .await;

        assert_eq!(outcome.status, ScannerStatus::Clean);
        assert!(outcome.failure.is_none());

        assert_eq!(
            fake.invocations.load(Ordering::SeqCst),
            1,
            "required fake scanner must be called exactly once"
        );
        let seen = fake
            .seen
            .lock()
            .expect("fake scanner request recorder must not be poisoned")
            .clone()
            .expect("fake scanner must have received a ScanRequest");
        assert_eq!(seen.artifact_id, artifact_id);
        assert_eq!(seen.content_type, ContentType::new("message/rfc822"));
        assert_eq!(seen.content_hash, expected_content_hash);
        assert_eq!(seen.artifact_size_bytes, bytes.len() as u64);

        let seen_bytes = fake
            .seen_bytes
            .lock()
            .expect("fake scanner bytes recorder must not be poisoned")
            .clone()
            .expect("fake scanner must have recorded ScanContent bytes");
        assert_eq!(
            seen_bytes.as_ref(),
            bytes.as_slice(),
            "the exact fixture bytes must pass through the ScanContent contract"
        );
    }

    #[tokio::test]
    async fn scan_preflight_rejects_ineligible_artifact_without_invoking_fake() {
        let bytes = b"scanner-pipeline-ineligible".to_vec();
        let hash_hex = hex::encode(sha2::Sha256::digest(&bytes));
        let artifact_id = ArtifactId::new();
        let deployment_id = DeploymentId::new("deployment-alpha");
        let customer_id = CustomerId::new("customer-one");

        let store = InMemoryArtifactStore::new();
        store
            .put(
                Artifact {
                    id: artifact_id.clone(),
                    deployment_id: deployment_id.clone(),
                    customer_id: Some(customer_id.clone()),
                    content_type: ContentType::new("message/rfc822"),
                    size: bytes.len() as u64,
                    storage_location: StorageLocation {
                        backend: StorageBackend::Memory,
                        bucket: None,
                        key: format!("memory/artifacts/{}", artifact_id.0),
                        region: None,
                    },
                    hash: ArtifactHash {
                        algorithm: HashAlgorithm::Sha256,
                        value: hash_hex,
                    },
                    retention_class: RetentionClass::Standard,
                    created_at: Utc::now(),
                    expires_at: None,
                    encrypted: false,
                    scanner_eligible: false,
                },
                bytes,
            )
            .await
            .expect("valid customer-owned Memory artifact must put");

        let fake = Arc::new(RecordingFakeScanner::default());
        let mut fabric = ScannerFabric::new(FabricConfig::default())
            .expect("default fabric config must be valid");
        fabric
            .register(ScannerRegistration {
                scanner: fake.clone(),
                scanner_type: ScannerType::Custom,
                profile: ScannerProfile {
                    execution_class: ExecutionClass::FastRequired,
                    wall_clock: Duration::from_secs(5),
                    max_concurrency: 1,
                    limits: ResourceLimits::bounded_defaults(),
                },
            })
            .expect("fake required scanner registration must be valid");

        let pipeline = MailCoreScannerPipeline::new(store, fabric);
        let outcome = pipeline
            .scan(ServerDerivedScanRequest {
                transaction_id: TransactionId::new(),
                deployment_id,
                customer_id: Some(customer_id),
                tenant_message_id: Some(TenantMessageId::new()),
                artifact_id,
                requested_at: Utc::now(),
                trace_id: TraceId::new(),
                params: serde_json::json!({}),
            })
            .await;

        assert_eq!(outcome.status, ScannerStatus::Unknown);
        assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
        assert_eq!(
            outcome
                .failure
                .as_ref()
                .map(|failure| failure.code.as_str()),
            Some(ARTIFACT_NOT_SCANNER_ELIGIBLE)
        );
        assert_eq!(outcome.coverage, FabricCoverage::default());
        assert!(outcome.findings.is_empty());
        assert!(outcome.failures.is_empty());
        assert_eq!(
            fake.invocations.load(Ordering::SeqCst),
            0,
            "an ineligible artifact must never reach the fake scanner"
        );
    }

    #[test]
    fn preflight_limit_rejects_declared_size_above_max_without_payload() {
        let metadata = AuthorizedArtifactMetadata {
            id: ArtifactId::new(),
            content_type: ContentType::new("message/rfc822"),
            hash: ArtifactHash {
                algorithm: HashAlgorithm::Sha256,
                value: "0".repeat(64),
            },
            size_bytes: MAX_SCANNER_INPUT_BYTES + 1,
            scanner_eligible: true,
        };

        assert_eq!(
            preflight_rejection(&metadata),
            Some(ARTIFACT_INPUT_LIMIT_EXCEEDED),
            "a declared size above the Mail Core max must fail preflight before get/fabric"
        );

        let at_limit = AuthorizedArtifactMetadata {
            id: ArtifactId::new(),
            content_type: ContentType::new("message/rfc822"),
            hash: ArtifactHash {
                algorithm: HashAlgorithm::Sha256,
                value: "0".repeat(64),
            },
            size_bytes: MAX_SCANNER_INPUT_BYTES,
            scanner_eligible: true,
        };
        assert_eq!(
            preflight_rejection(&at_limit),
            None,
            "a declared size exactly at the max must pass preflight"
        );

        let outcome = MailCoreScanOutcome::preflight_failure(ARTIFACT_INPUT_LIMIT_EXCEEDED);
        assert_eq!(outcome.status, ScannerStatus::Unknown);
        assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
        assert_eq!(
            outcome
                .failure
                .as_ref()
                .map(|failure| failure.code.as_str()),
            Some(ARTIFACT_INPUT_LIMIT_EXCEEDED)
        );
        assert_eq!(outcome.coverage, FabricCoverage::default());
        assert!(outcome.findings.is_empty());
        assert!(outcome.failures.is_empty());
    }

    #[test]
    fn authorized_size_mismatch_fails_safe_with_generic_code_without_fabric() {
        assert!(
            authorized_size_mismatch(16, 15),
            "a byte length differing from the preflight size must be treated as a mismatch"
        );
        assert!(
            !authorized_size_mismatch(16, 16),
            "an exactly matching byte length must not be treated as a mismatch"
        );

        let outcome = MailCoreScanOutcome::preflight_failure(ARTIFACT_METADATA_MISMATCH);
        assert_eq!(outcome.status, ScannerStatus::Unknown);
        assert_eq!(outcome.fail_safe_disposition, Disposition::Hold);
        assert_eq!(
            outcome
                .failure
                .as_ref()
                .map(|failure| failure.code.as_str()),
            Some(ARTIFACT_METADATA_MISMATCH),
            "mismatch must surface only the stable generic code"
        );
        assert_eq!(outcome.coverage, FabricCoverage::default());
        assert!(outcome.findings.is_empty());
        assert!(outcome.failures.is_empty());
    }

    #[tokio::test]
    async fn fabric_rejects_tampered_store_bytes_without_invoking_fake() {
        let original_bytes = b"content-integrity-original".to_vec();
        let stored_bytes = b"content-integrity-tampered".to_vec();
        assert_eq!(
            stored_bytes.len(),
            original_bytes.len(),
            "fixture requires a same-length tampered body"
        );
        assert_ne!(
            stored_bytes, original_bytes,
            "fixture requires a stored body different from the declared original"
        );
        let declared_hash_hex = hex::encode(sha2::Sha256::digest(&original_bytes));

        let fake = Arc::new(RecordingFakeScanner::default());
        let mut fabric = ScannerFabric::new(FabricConfig::default())
            .expect("default fabric config must be valid");
        fabric
            .register(ScannerRegistration {
                scanner: fake.clone(),
                scanner_type: ScannerType::Custom,
                profile: ScannerProfile {
                    execution_class: ExecutionClass::FastRequired,
                    wall_clock: Duration::from_secs(5),
                    max_concurrency: 1,
                    limits: ResourceLimits::bounded_defaults(),
                },
            })
            .expect("fake required scanner registration must be valid");

        // The target declares the hash of the original body while the
        // private provider carries the same-length tampered store bytes:
        // the fabric's own SHA-256 verification of the acquired snapshot
        // must reject them before any adapter is scheduled.
        let scan_target = ScanTarget {
            request_id: Uuid::new_v4(),
            transaction_id: TransactionId::new(),
            tenant_message_id: None,
            customer_id: Some(CustomerId::new("cust-test")),
            deployment_id: DeploymentId::new("CZA-1"),
            artifact_id: ArtifactId::new(),
            content_type: ContentType::new("message/rfc822"),
            content_hash: ContentHash::new(&format!("sha256:{declared_hash_hex}")),
            artifact_size_bytes: stored_bytes.len() as u64,
            requested_at: Utc::now(),
            params: serde_json::json!({}),
        };
        let content = Arc::new(InMemoryScanContent {
            bytes: Arc::from(stored_bytes),
            content_type: ContentType::new("message/rfc822"),
        });

        let outcome = fabric.scan(&scan_target, content).await;

        assert_ne!(outcome.status, ScannerStatus::Clean);
        assert_eq!(
            outcome.status,
            ScannerStatus::Unknown,
            "a tampered body must surface Unknown, never Clean"
        );
        assert_eq!(
            outcome.fail_safe_disposition,
            Disposition::Hold,
            "a tampered body must fail safe to Hold"
        );
        assert!(outcome.inconclusive);
        assert_eq!(
            outcome.failures.len(),
            1,
            "exactly one generic failure is expected: {:?}",
            outcome.failures
        );
        assert_eq!(
            outcome.failures[0].message, "artifact metadata/content integrity mismatch",
            "the rejection must carry only the stable generic message"
        );
        assert_eq!(
            fake.invocations.load(Ordering::SeqCst),
            0,
            "a tampered body must never reach the fake scanner"
        );
    }

    fn durable_scan_result(requires_hold: bool) -> ScannerFabricResult {
        ScannerFabricResult {
            results: Vec::new(),
            scanner_profiles: Vec::new(),
            findings: Vec::new(),
            failures: Vec::new(),
            requires_hold,
        }
    }

    fn policy_result(disposition: Disposition, reason_code: ReasonCode) -> PolicyEvaluationResult {
        PolicyEvaluationResult {
            disposition,
            reason_code,
            policy_revision: nullapart_mail_contracts::policy::PolicyRevisionId::new(),
            explanation: "test policy decision".to_string(),
            findings_applied: Vec::new(),
            evaluated_at: Utc::now(),
        }
    }

    #[test]
    fn required_scanner_hold_overrides_permissive_and_quarantine_policy() {
        let scan_result = durable_scan_result(true);
        for policy_disposition in [Disposition::Allow, Disposition::Quarantine] {
            let policy = policy_result(policy_disposition, ReasonCode::quarantine_malware());
            assert_eq!(
                final_policy_decision(&scan_result, &policy),
                (Disposition::Hold, ReasonCode::hold_pending())
            );
        }
    }

    #[test]
    fn complete_required_coverage_preserves_explicit_policy_decision() {
        let scan_result = durable_scan_result(false);
        let policy = policy_result(Disposition::Reject, ReasonCode::reject_policy());
        assert_eq!(
            final_policy_decision(&scan_result, &policy),
            (Disposition::Reject, ReasonCode::reject_policy())
        );
    }

    #[test]
    fn artifact_timestamp_is_normalized_to_postgres_precision() {
        let accepted_at = chrono::DateTime::parse_from_rfc3339("2026-09-28T03:20:21.777776999Z")
            .expect("fixture timestamp must parse")
            .with_timezone(&Utc);

        let normalized = postgres_timestamp(accepted_at).expect("timestamp must remain in range");

        assert_eq!(
            normalized.timestamp_micros(),
            accepted_at.timestamp_micros()
        );
        assert_eq!(normalized.timestamp_subsec_nanos() % 1_000, 0);
        assert_eq!(
            normalized.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            "2026-09-28T03:20:21.777776000Z"
        );
    }
}

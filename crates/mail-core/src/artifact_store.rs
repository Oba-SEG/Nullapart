//! Phase 2 ArtifactStore seam.
//!
//! Application code stores and retrieves artifact bytes through this contract
//! instead of embedding backend-specific calls. Caller-supplied storage
//! locations (bucket/key/URL) are never used as authorization inputs, and
//! error variants never expose backend keys or existence across scopes.
//! Access is gated by a server-issued [`ArtifactAccessGrant`] carrying
//! explicit permission bits, actor identity, a closed purpose, an explicit
//! non-empty set of authorized [`ArtifactId`]s and an expiration deadline.
//! Grant fields are private and only the server-side issuance path can
//! create one. A grant is a short-lived, artifact-bound internal workload
//! capability for scanner/quarantine/retention jobs — never a browser
//! credential and never user authentication. Successful reads return a
//! minimal [`AuthorizedArtifact`], or — through
//! [`InMemoryArtifactStore::get_metadata`] or
//! [`FilesystemArtifactStore::get_metadata`] — an even narrower
//! [`AuthorizedArtifactMetadata`] that also omits the bytes themselves.
//! Neither result includes storage location, encryption or retention
//! metadata.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use cap_fs_ext::OsMetadataExt as _;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
#[cfg(unix)]
use cap_std::fs::OpenOptionsExt;
use cap_std::fs::{Dir, OpenOptions};
use chrono::{DateTime, Utc};
use nullapart_mail_contracts::artifact::{
    Artifact, ArtifactHash, ArtifactId, ContentType, HashAlgorithm, RetentionClass, StorageBackend,
    StorageLocation,
};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use sha2::Digest;
use tokio::sync::RwLock;

/// Closed set of server-side purposes for an artifact access grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAccessPurpose {
    Scanner,
    QuarantineRelease,
    DmarcReportIngestion,
    RetentionWorker,
    /// Session-authenticated rendering of one message's stored MIME to an
    /// operator with `trace:content`.
    ContentReview,
}

/// Server-side authorization scope bound into an [`ArtifactAccessGrant`].
///
/// Crate-internal only: it is `pub(crate)` so the `pub(crate)` issuer can name
/// it, and it is never re-exported outside this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArtifactScope {
    Customer(CustomerId),
    System,
}

/// Failure returned when a grant cannot be issued.
///
/// The message stays generic: issuance failures never echo artifact content,
/// identifiers or storage metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid artifact access grant")]
pub(crate) enum ArtifactGrantIssueError {
    /// A grant must bind at least one explicit [`ArtifactId`]. Empty sets are
    /// rejected with this error rather than issued or panicked on: there is
    /// no empty and no wildcard artifact capability.
    EmptyAuthorizedIds,
}

/// Server-issued, artifact-bound access grant for artifact read/delete
/// operations.
///
/// A grant is a short-lived internal workload capability — not a browser
/// credential and not user authentication. It names an explicit non-empty
/// set of [`ArtifactId`]s, expires at a fixed [`DateTime<Utc>`] deadline and
/// is limited to a closed server-side purpose. It authorizes only the exact
/// resources bound at issuance, never a tenant-wide or wildcard artifact set.
///
/// All fields are private. Production code must construct this type only via
/// [`ArtifactAccessGrant::issue_server_authorized`] after server-side
/// authorization has decided the actor, scope, permission bits, exact
/// artifact ID set and expiration. This in-memory seam is not an identity
/// provider: issuing a grant locally never authenticates anyone, and callers
/// must not forge grants from client-supplied input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactAccessGrant {
    deployment_id: DeploymentId,
    scope: ArtifactScope,
    actor_id: String,
    can_read_content: bool,
    can_delete: bool,
    purpose: ArtifactAccessPurpose,
    /// Exact artifact resources this grant can touch; never empty.
    authorized_ids: HashSet<ArtifactId>,
    /// Hard deadline after which the grant is expired; equality counts as
    /// expired.
    expires_at: DateTime<Utc>,
}

/// Permission bits an authorization decision attaches to a server-issued
/// [`ArtifactAccessGrant`].
///
/// Grouping the two bits into one typed argument keeps grant issuance at a
/// single, readable call site: callers state *what* the decision authorized
/// instead of passing two positional booleans whose order is easy to swap.
/// The bits are private and only ever read through [`ArtifactAccessGrant`],
/// so no caller can observe permission state without presenting a live grant
/// to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactPermissions {
    can_read_content: bool,
    can_delete: bool,
}

impl ArtifactPermissions {
    /// Read access to artifact content; no delete access.
    pub const fn content_read_only() -> Self {
        Self {
            can_read_content: true,
            can_delete: false,
        }
    }

    /// Explicit bit combination for decisions that vary exactly one bit at a
    /// time — used by server-side issuance paths and their tests.
    pub const fn new(can_read_content: bool, can_delete: bool) -> Self {
        Self {
            can_read_content,
            can_delete,
        }
    }
}

impl ArtifactAccessGrant {
    /// Issues a server-authorized grant for `deployment` and `scope` after
    /// authorization has resolved `actor_id`, the `permissions` decision, the
    /// closed `purpose`, the exact `authorized_ids` set and the `expires_at`
    /// deadline.
    ///
    /// The resulting capability is short-lived and bound to precisely the
    /// listed [`ArtifactId`]s: an empty `authorized_ids` iterable is
    /// rejected with [`ArtifactGrantIssueError::EmptyAuthorizedIds`] instead
    /// of being issued, and there is no wildcard alternative. There is no
    /// public constructor and no public fields; this is the only way to
    /// create a grant, and it must only be called from server-side
    /// authorization paths.
    pub(crate) fn issue_server_authorized(
        deployment: DeploymentId,
        scope: ArtifactScope,
        actor_id: String,
        permissions: ArtifactPermissions,
        purpose: ArtifactAccessPurpose,
        authorized_ids: impl IntoIterator<Item = ArtifactId>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ArtifactGrantIssueError> {
        let authorized_ids: HashSet<ArtifactId> = authorized_ids.into_iter().collect();
        if authorized_ids.is_empty() {
            return Err(ArtifactGrantIssueError::EmptyAuthorizedIds);
        }
        Ok(Self {
            deployment_id: deployment,
            scope,
            actor_id,
            can_read_content: permissions.can_read_content,
            can_delete: permissions.can_delete,
            purpose,
            authorized_ids,
            expires_at,
        })
    }
}

/// Artifact bytes authorized for delivery to a caller that presented a
/// matching [`ArtifactAccessGrant`].
///
/// Deliberately minimal: it never exposes [`StorageLocation`], encryption
/// state or retention metadata.
#[derive(Debug, Clone)]
pub struct AuthorizedArtifact {
    pub id: ArtifactId,
    pub content_type: ContentType,
    pub hash: ArtifactHash,
    pub bytes: Vec<u8>,
}

/// Artifact metadata authorized for delivery to a caller that presented a
/// matching [`ArtifactAccessGrant`].
///
/// Deliberately minimal: exactly id, content type, hash, declared size and
/// scanner eligibility. It never exposes stored bytes, [`StorageLocation`],
/// encryption state, retention metadata, customer/deployment scope or grant
/// internals. It is produced only by [`InMemoryArtifactStore::get_metadata`]
/// and [`FilesystemArtifactStore::get_metadata`] after the same live
/// read-capability checks as [`InMemoryArtifactStore::get`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedArtifactMetadata {
    pub id: ArtifactId,
    pub content_type: ContentType,
    pub hash: ArtifactHash,
    pub size_bytes: u64,
    pub scanner_eligible: bool,
}

/// An artifact record together with its stored bytes (internal only).
#[derive(Debug, Clone)]
struct StoredArtifact {
    artifact: Artifact,
    bytes: Vec<u8>,
}

/// Stable ArtifactStore error variants.
///
/// Messages are intentionally generic: they must not reveal backend keys,
/// buckets, or whether an artifact exists in another scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactStoreError {
    #[error("artifact not found")]
    NotFound,
    #[error("artifact content hash mismatch")]
    HashMismatch,
    #[error("artifact already exists with different content")]
    ImmutableConflict,
    #[error("artifact size mismatch")]
    SizeMismatch,
    #[error("artifact exceeds the maximum accepted size")]
    SizeLimitExceeded,
    #[error("artifact retention class does not permit deletion")]
    RetentionViolation,
    #[error("artifact storage unavailable")]
    StorageUnavailable,
    #[error("filesystem artifact store is unavailable in this environment")]
    EnvironmentRejected,
}

/// Combined mutable store state guarded by a single lock so artifact
/// records and tombstones change atomically.
#[derive(Debug, Default)]
struct ArtifactState {
    artifacts: HashMap<ArtifactId, StoredArtifact>,
    tombstones: HashSet<ArtifactId>,
}

/// In-memory ArtifactStore used for development and tests.
#[derive(Debug, Clone)]
pub struct InMemoryArtifactStore {
    state: Arc<RwLock<ArtifactState>>,
}

impl Default for InMemoryArtifactStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryArtifactStore {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ArtifactState::default())),
        }
    }

    /// Stores `bytes` under `artifact.id` after verifying the declared hash
    /// and declared size.
    ///
    /// A tombstoned ID is rejected as `ImmutableConflict`; a declared size
    /// that differs from `bytes.len()` is rejected as `SizeMismatch`. The
    /// SHA-256 check is unchanged: re-putting the same ID with identical
    /// metadata and bytes succeeds idempotently; any different record for
    /// the same ID is rejected.
    pub async fn put(&self, artifact: Artifact, bytes: Vec<u8>) -> Result<(), ArtifactStoreError> {
        let mut state = self.state.write().await;
        if state.tombstones.contains(&artifact.id) {
            return Err(ArtifactStoreError::ImmutableConflict);
        }
        if !hash_matches(&artifact.hash, &bytes) {
            return Err(ArtifactStoreError::HashMismatch);
        }
        if artifact.size != bytes.len() as u64 {
            return Err(ArtifactStoreError::SizeMismatch);
        }
        match state.artifacts.get(&artifact.id) {
            Some(existing) => {
                if same_metadata(&existing.artifact, &artifact) && existing.bytes == bytes {
                    Ok(())
                } else {
                    Err(ArtifactStoreError::ImmutableConflict)
                }
            },
            None => {
                state
                    .artifacts
                    .insert(artifact.id.clone(), StoredArtifact { artifact, bytes });
                Ok(())
            },
        }
    }

    /// Returns an [`AuthorizedArtifact`] when `grant` is a live, read
    /// capability bound to this exact artifact.
    ///
    /// All capability checks run before any store state is read, and every
    /// capability failure is the generic `NotFound` so neither permission
    /// state nor existence is revealed. `can_read_content` must be true; the
    /// purpose must be `Scanner`, `QuarantineRelease`, `DmarcReportIngestion`
    /// or `ContentReview` (`RetentionWorker` cannot read content); the grant
    /// must not be expired (`Utc::now() < expires_at`, so equality counts as
    /// expired); and `id` must be present in the grant's authorized ID set.
    /// After the capability passes,
    /// deployment must match: a `Customer` grant scope matches only an
    /// artifact whose customer is exactly equal; a `System` grant scope
    /// matches only customerless artifacts. The result carries only id,
    /// content type, hash and bytes — never storage location, encryption or
    /// retention metadata.
    ///
    /// These checks run through the shared [`Self::authorized_read`] helper
    /// together with [`Self::get_metadata`], so the two read paths cannot
    /// diverge.
    pub async fn get(
        &self,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
    ) -> Result<AuthorizedArtifact, ArtifactStoreError> {
        self.authorized_read(grant, id, |stored| AuthorizedArtifact {
            id: stored.artifact.id.clone(),
            content_type: stored.artifact.content_type.clone(),
            hash: stored.artifact.hash.clone(),
            bytes: stored.bytes.clone(),
        })
        .await
    }

    /// Returns an [`AuthorizedArtifactMetadata`] when `grant` is a live,
    /// read capability bound to this exact artifact.
    ///
    /// The capability, expiry, exact-binding and scope/non-enumeration checks
    /// are exactly those of [`Self::get`] — both paths share the single
    /// [`Self::authorized_read`] helper so they cannot diverge — but the
    /// result carries only id, content type, hash, declared size and declared
    /// scanner eligibility. It never includes stored bytes (nothing is cloned
    /// from the stored payload), storage location, encryption state,
    /// retention metadata, customer/deployment scope or grant internals.
    /// `size_bytes` and `scanner_eligible` are the declared values from the
    /// stored artifact record (declared size validated against the bytes at
    /// `put` time).
    pub async fn get_metadata(
        &self,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
    ) -> Result<AuthorizedArtifactMetadata, ArtifactStoreError> {
        self.authorized_read(grant, id, |stored| AuthorizedArtifactMetadata {
            id: stored.artifact.id.clone(),
            content_type: stored.artifact.content_type.clone(),
            hash: stored.artifact.hash.clone(),
            size_bytes: stored.artifact.size,
            scanner_eligible: stored.artifact.scanner_eligible,
        })
        .await
    }

    /// Shared live read-capability gate for [`Self::get`] and
    /// [`Self::get_metadata`]; applies `project` to the authorized stored
    /// record while its read lock is held.
    ///
    /// Capability checks run before any store state is read: every failure —
    /// `can_read_content` false, purpose other than `Scanner` /
    /// `QuarantineRelease` / `DmarcReportIngestion` / `ContentReview`,
    /// expired grant (`Utc::now() >= expires_at`, so equality counts as
    /// expired), `id` missing from the authorized ID set, artifact absent, or
    /// deployment/customer scope
    /// mismatch — is the generic `NotFound`, so neither permission state nor
    /// existence is revealed. Because both read paths call this one function,
    /// they cannot diverge: any future check added here binds both.
    async fn authorized_read<T>(
        &self,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
        project: impl FnOnce(&StoredArtifact) -> T,
    ) -> Result<T, ArtifactStoreError> {
        if !grant.can_read_content {
            return Err(ArtifactStoreError::NotFound);
        }
        if !matches!(
            grant.purpose,
            ArtifactAccessPurpose::Scanner
                | ArtifactAccessPurpose::QuarantineRelease
                | ArtifactAccessPurpose::DmarcReportIngestion
                | ArtifactAccessPurpose::ContentReview
        ) {
            return Err(ArtifactStoreError::NotFound);
        }
        if Utc::now() >= grant.expires_at {
            return Err(ArtifactStoreError::NotFound);
        }
        if !grant.authorized_ids.contains(id) {
            return Err(ArtifactStoreError::NotFound);
        }
        let state = self.state.read().await;
        let stored = state
            .artifacts
            .get(id)
            .ok_or(ArtifactStoreError::NotFound)?;
        if !scope_matches(grant, stored) {
            return Err(ArtifactStoreError::NotFound);
        }
        Ok(project(stored))
    }

    /// Removes the artifact only once `grant` is a live retention capability
    /// bound to this exact artifact.
    ///
    /// Capability checks run before any store state is read: `can_delete`
    /// and the `RetentionWorker` purpose are both required, the grant must
    /// not be expired (`Utc::now() < expires_at`, so equality counts as
    /// expired), and `id` must be present in the grant's authorized ID set.
    /// Every capability, permission or scope failure is reported as
    /// `NotFound` before any retention state is revealed. After the
    /// capability passes, the stored scope must match, `retention_class` must
    /// be `Deleted`, and `expires_at` must be `Some(deadline)` with
    /// `deadline <= now`, otherwise `RetentionViolation`. On success only
    /// the ID is tombstoned — no bytes or metadata are retained — under the
    /// single state lock, so the removal and tombstone insert are atomic.
    pub async fn delete_after_retention(
        &self,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
    ) -> Result<(), ArtifactStoreError> {
        if !grant.can_delete || grant.purpose != ArtifactAccessPurpose::RetentionWorker {
            return Err(ArtifactStoreError::NotFound);
        }
        if Utc::now() >= grant.expires_at {
            return Err(ArtifactStoreError::NotFound);
        }
        if !grant.authorized_ids.contains(id) {
            return Err(ArtifactStoreError::NotFound);
        }
        let mut state = self.state.write().await;
        let stored = state
            .artifacts
            .get(id)
            .ok_or(ArtifactStoreError::NotFound)?;
        if !scope_matches(grant, stored) {
            return Err(ArtifactStoreError::NotFound);
        }
        if stored.artifact.retention_class != RetentionClass::Deleted {
            return Err(ArtifactStoreError::RetentionViolation);
        }
        match stored.artifact.expires_at {
            Some(deadline) if deadline <= Utc::now() => {},
            _ => return Err(ArtifactStoreError::RetentionViolation),
        }
        state.artifacts.remove(id);
        state.tombstones.insert(id.clone());
        Ok(())
    }
}

/// Deployment must always equal the stored deployment. A `Customer` grant
/// scope matches only an artifact whose stored customer is exactly equal to
/// the grant's customer; a `System` grant scope matches only artifacts with
/// no stored customer. Any other combination does not match.
fn scope_matches_artifact(grant: &ArtifactAccessGrant, artifact: &Artifact) -> bool {
    if artifact.deployment_id != grant.deployment_id {
        return false;
    }
    match (&grant.scope, &artifact.customer_id) {
        (ArtifactScope::Customer(grant_customer), Some(stored_customer)) => {
            grant_customer == stored_customer
        },
        (ArtifactScope::System, None) => true,
        _ => false,
    }
}

/// Deployment/scope matching over a stored record, delegated unchanged to
/// [`scope_matches_artifact`] so the two read paths cannot diverge.
fn scope_matches(grant: &ArtifactAccessGrant, stored: &StoredArtifact) -> bool {
    scope_matches_artifact(grant, &stored.artifact)
}

fn hash_matches(hash: &ArtifactHash, bytes: &[u8]) -> bool {
    hash.algorithm == HashAlgorithm::Sha256
        && hash.value == hex::encode(sha2::Sha256::digest(bytes))
}

fn same_metadata(a: &Artifact, b: &Artifact) -> bool {
    a.id == b.id
        && a.deployment_id == b.deployment_id
        && a.customer_id == b.customer_id
        && a.content_type == b.content_type
        && a.size == b.size
        && same_storage_location(&a.storage_location, &b.storage_location)
        && a.hash == b.hash
        && a.retention_class == b.retention_class
        && a.created_at == b.created_at
        && a.expires_at == b.expires_at
        && a.encrypted == b.encrypted
        && a.scanner_eligible == b.scanner_eligible
}

fn same_storage_location(a: &StorageLocation, b: &StorageLocation) -> bool {
    a.backend == b.backend && a.bucket == b.bucket && a.key == b.key && a.region == b.region
}

/// Closed runtime selection for the filesystem artifact backend.
///
/// The filesystem backend exists only for local development and tests;
/// [`FilesystemArtifactRuntime::Production`] is rejected at construction
/// and creates nothing on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemArtifactRuntime {
    LocalDevelopment,
    Test,
    Production,
}

/// Maximum artifact size accepted by the local filesystem store, in bytes
/// (50 MiB). It matches the mail/scanner ceiling so a candidate is rejected
/// with [`ArtifactStoreError::SizeLimitExceeded`] before any size
/// comparison or hashing work happens.
const MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES: u64 = 50 * 1024 * 1024;

/// Mutable filesystem store state guarded by a single lock so the metadata
/// decision and the immutable publication stay atomic.
///
/// It holds only artifact metadata and tombstoned IDs: the raw bytes are
/// published to disk by [`FilesystemArtifactStore::publish_immutable`] and
/// are never retained in memory here.
#[derive(Debug, Default)]
struct FilesystemArtifactState {
    artifacts: HashMap<ArtifactId, Artifact>,
    tombstones: HashSet<ArtifactId>,
}

/// Local-development/test-only filesystem artifact store.
///
/// Storage locations are always derived server-side from the
/// [`ArtifactId`]: no caller ever supplies a path, key, bucket or URL, and
/// no public API exposes the configured root or a stored file path.
///
/// The store keeps both the accepted root [`PathBuf`] — the canonicalized
/// parent joined with the root's final component, never a canonicalization
/// of the root itself — and a directory capability (`Arc<Dir>`) opened from
/// that parent capability with a no-follow open of exactly that final
/// component. The capability is validated at construction against the `std`
/// metadata captured immediately before the no-follow open (device and inode
/// on Unix), so both fields describe one and the same directory.
#[derive(Debug, Clone)]
pub struct FilesystemArtifactStore {
    /// Accepted root retained for test-only path assertions
    /// ([`Self::final_path`]). Production code never reads it: every
    /// filesystem operation resolves through [`Self::capability`] and a
    /// server-derived relative name, so the ambient root path has no
    /// production consumer and the field would otherwise be dead weight in a
    /// non-test build.
    #[cfg(test)]
    root: PathBuf,
    capability: Arc<Dir>,
    state: Arc<RwLock<FilesystemArtifactState>>,
}

impl FilesystemArtifactStore {
    /// Builds a filesystem store rooted at `root`.
    ///
    /// [`FilesystemArtifactRuntime::Production`] fails with
    /// [`ArtifactStoreError::EnvironmentRejected`] before any directory is
    /// created. [`FilesystemArtifactRuntime::LocalDevelopment`] and
    /// [`FilesystemArtifactRuntime::Test`] run the filesystem work through
    /// the blocking pool, never on the async executor: an existing root must
    /// be a non-symlink directory, a missing root is created as a directory
    /// tree, and any other initial failure is the generic
    /// [`ArtifactStoreError::StorageUnavailable`].
    ///
    /// The configured root is then split into its parent and its final
    /// component: a path with no final component is rejected, an empty
    /// relative parent is treated as `.`, and only that parent is
    /// canonicalized — the root itself is never canonicalized and is never
    /// chmod'ed through its ambient path. That canonical parent is opened as
    /// a [`Dir`] capability with [`ambient_authority`], then the `std`
    /// symlink metadata of `canonical_parent.join(file_name)` must report a
    /// non-symlink directory, and exactly that final component is opened
    /// from the parent capability with [`DirExt::open_dir_nofollow`]. The
    /// no-follow open therefore never resolves a final-component symlink,
    /// even one inserted after the initial root check. The opened
    /// capability must itself report a directory, and on Unix its
    /// device/inode identity must equal the `std` metadata captured
    /// immediately before that open, which closes a replacement of the
    /// final component between the capture and the open. On Unix the
    /// accepted directory is then set to mode `0700` through the accepted
    /// directory handle itself
    /// (`capability.try_clone().into_std_file().set_permissions(..)`), never
    /// through an ambient path, and the refreshed capability metadata must
    /// report a mode masked with `0o777` equal to `0o700`. Every filesystem
    /// failure is the generic [`ArtifactStoreError::StorageUnavailable`].
    pub async fn try_new(
        root: impl Into<PathBuf>,
        runtime: FilesystemArtifactRuntime,
    ) -> Result<Self, ArtifactStoreError> {
        if runtime == FilesystemArtifactRuntime::Production {
            return Err(ArtifactStoreError::EnvironmentRejected);
        }
        let directory = root.into();
        let (accepted_root, capability) =
            tokio::task::spawn_blocking(move || -> Result<(PathBuf, Dir), ArtifactStoreError> {
                match std::fs::symlink_metadata(&directory) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(ArtifactStoreError::StorageUnavailable);
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::fs::create_dir_all(&directory)
                            .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                    },
                    Err(_) => return Err(ArtifactStoreError::StorageUnavailable),
                }

                let file_name = directory
                    .file_name()
                    .ok_or(ArtifactStoreError::StorageUnavailable)?;
                let configured_parent = directory.parent().unwrap_or(std::path::Path::new(""));
                let configured_parent = if configured_parent.as_os_str().is_empty() {
                    std::path::Path::new(".")
                } else {
                    configured_parent
                };
                let canonical_parent = std::fs::canonicalize(configured_parent)
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                let parent_capability =
                    Dir::open_ambient_dir(&canonical_parent, ambient_authority())
                        .map_err(|_| ArtifactStoreError::StorageUnavailable)?;

                let accepted_path = canonical_parent.join(file_name);
                let pre_open_metadata = std::fs::symlink_metadata(&accepted_path)
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                if pre_open_metadata.file_type().is_symlink() || !pre_open_metadata.is_dir() {
                    return Err(ArtifactStoreError::StorageUnavailable);
                }

                // Identity of the final component captured immediately before the
                // no-follow open, so the comparison below cannot observe a
                // replacement of that component between the capture and the open.
                #[cfg(unix)]
                let (expected_dev, expected_ino) = {
                    use std::os::unix::fs::MetadataExt;
                    (pre_open_metadata.dev(), pre_open_metadata.ino())
                };

                let capability = parent_capability
                    .open_dir_nofollow(file_name)
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                let capability_metadata = capability
                    .dir_metadata()
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                if !capability_metadata.is_dir() {
                    return Err(ArtifactStoreError::StorageUnavailable);
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;

                    if capability_metadata.dev() != expected_dev
                        || capability_metadata.ino() != expected_ino
                    {
                        return Err(ArtifactStoreError::StorageUnavailable);
                    }
                    if capability_metadata.mode() & 0o777 != 0o700 {
                        capability
                            .try_clone()
                            .and_then(|directory| {
                                directory
                                    .into_std_file()
                                    .set_permissions(std::fs::Permissions::from_mode(0o700))
                            })
                            .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                    }
                    let refreshed_metadata = capability
                        .dir_metadata()
                        .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                    if refreshed_metadata.mode() & 0o777 != 0o700 {
                        return Err(ArtifactStoreError::StorageUnavailable);
                    }
                }

                Ok((accepted_path, capability))
            })
            .await
            .map_err(|_| ArtifactStoreError::StorageUnavailable)??;
        // `accepted_root` is the constructor's proof that the capability and
        // the configured path describe the same directory; only test builds
        // keep a copy of it (see the field's documentation).
        #[cfg(not(test))]
        let _accepted_root = accepted_root;
        Ok(Self {
            #[cfg(test)]
            root: accepted_root,
            capability: Arc::new(capability),
            state: Arc::new(RwLock::new(FilesystemArtifactState::default())),
        })
    }

    /// Publishes `bytes` as the immutable artifact `artifact` under its
    /// server-derived final path and records its metadata.
    ///
    /// [`Self::validate_put`] runs first, before any lock or filesystem
    /// work, so a rejected candidate never reaches the disk. The state write
    /// lock is then held for the whole ID decision and publication: a
    /// tombstoned ID and an existing record whose metadata differs from
    /// `artifact` (per [`same_metadata`]) are rejected as
    /// [`ArtifactStoreError::ImmutableConflict`] before any publication.
    /// [`Self::publish_immutable`] publishes the bytes for the ID — an
    /// already published byte-identical file succeeds — and only after that
    /// success is the metadata inserted, and only when the ID is still
    /// absent. A crash/retry over an already published identical file
    /// therefore recovers by inserting the metadata. The bytes move into the
    /// publication and are never stored in the state; only metadata and
    /// tombstones are.
    pub async fn put(&self, artifact: Artifact, bytes: Vec<u8>) -> Result<(), ArtifactStoreError> {
        self.validate_put(&artifact, &bytes).await?;
        let mut state = self.state.write().await;
        if state.tombstones.contains(&artifact.id) {
            return Err(ArtifactStoreError::ImmutableConflict);
        }
        if let Some(existing) = state.artifacts.get(&artifact.id) {
            if !same_metadata(existing, &artifact) {
                return Err(ArtifactStoreError::ImmutableConflict);
            }
        }
        self.publish_immutable(&artifact.id, bytes).await?;
        state
            .artifacts
            .entry(artifact.id.clone())
            .or_insert(artifact);
        Ok(())
    }

    /// Rehydrates trusted database metadata for an already-published local
    /// artifact after a process restart. The file is opened through the
    /// directory capability with no symlink following, bounded by the local
    /// size ceiling, and its size and SHA-256 digest must exactly match the
    /// supplied server-derived record before that record enters process
    /// state. No caller-supplied path is accepted.
    pub(crate) async fn recover_existing(
        &self,
        artifact: Artifact,
    ) -> Result<(), ArtifactStoreError> {
        let expected_name = self.final_name(&artifact.id);
        if artifact.storage_location.backend != StorageBackend::Filesystem
            || artifact.storage_location.bucket.is_some()
            || artifact.storage_location.region.is_some()
            || artifact.storage_location.key != expected_name
            || artifact.size > MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES
            || artifact.hash.algorithm != HashAlgorithm::Sha256
        {
            return Err(ArtifactStoreError::ImmutableConflict);
        }

        let mut state = self.state.write().await;
        if state.tombstones.contains(&artifact.id) {
            return Err(ArtifactStoreError::ImmutableConflict);
        }
        if let Some(existing) = state.artifacts.get(&artifact.id) {
            return if same_metadata(existing, &artifact) {
                Ok(())
            } else {
                Err(ArtifactStoreError::ImmutableConflict)
            };
        }

        let capability = Arc::clone(&self.capability);
        let declared_size = artifact.size;
        let expected_hash = artifact.hash.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ArtifactStoreError> {
            use std::io::Read;

            let mut options = OpenOptions::new();
            options.read(true);
            options.follow(FollowSymlinks::No);
            let mut handle = capability
                .open_with(&expected_name, &options)
                .map_err(|_| ArtifactStoreError::NotFound)?;
            let metadata = handle
                .metadata()
                .map_err(|_| ArtifactStoreError::NotFound)?;
            if !metadata.is_file() || metadata.len() != declared_size {
                return Err(ArtifactStoreError::SizeMismatch);
            }
            let mut bytes = Vec::new();
            handle
                .by_ref()
                .take(MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
            if bytes.len() as u64 > MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES {
                return Err(ArtifactStoreError::SizeLimitExceeded);
            }
            if bytes.len() as u64 != declared_size {
                return Err(ArtifactStoreError::SizeMismatch);
            }
            if !hash_matches(&expected_hash, &bytes) {
                return Err(ArtifactStoreError::HashMismatch);
            }
            Ok(())
        })
        .await
        .map_err(|_| ArtifactStoreError::StorageUnavailable)??;

        state.artifacts.insert(artifact.id.clone(), artifact);
        Ok(())
    }

    /// Server-derived production storage name for `id`: exactly
    /// `<uuid>.artifact`.
    ///
    /// The [`ArtifactId`] UUID is the only input; there is no key, path or
    /// URL parameter, so no caller-controlled component can reach the
    /// filesystem. The result is a single relative filename by construction:
    /// one fixed ASCII suffix appended to the UUID's hyphenated hex form
    /// never contains a separator, a prefix or a parent component, so it is
    /// always resolved directly inside the stored [`Self::capability`]
    /// directory and can never escape it.
    fn final_name(&self, id: &ArtifactId) -> String {
        format!("{}.artifact", id.0)
    }

    /// Server-derived final location for `id`: `<root>/<uuid>.artifact`.
    ///
    /// Test-only: it exists so existing assertions can inspect the exact
    /// path the store derives, and it is simply [`Self::root`] joined with
    /// [`Self::final_name`]. No production method may call it — production
    /// code uses [`Self::final_name`] as a capability-relative name instead.
    ///
    /// The [`ArtifactId`] UUID is the only input; there is no key, path or
    /// URL parameter, so no caller-controlled component can reach the
    /// filesystem.
    #[cfg(test)]
    fn final_path(&self, id: &ArtifactId) -> PathBuf {
        self.root.join(self.final_name(id))
    }

    /// Returns the stored artifact bytes when `grant` is a live, read
    /// capability bound to this exact artifact.
    ///
    /// [`Self::authorized_metadata`] runs first, so every permission,
    /// purpose, expiry, exact-binding, missing-ID and deployment/customer
    /// scope failure is the generic [`ArtifactStoreError::NotFound`] before
    /// any filesystem work happens — the filesystem name therefore cannot
    /// diverge from the capability gate used by [`Self::get_metadata`]. The
    /// server-derived [`Self::final_name`] for the authorized ID is then
    /// read entirely inside one blocking-pool closure, never on the async
    /// executor, and never through the ambient [`Self::root`] path: the
    /// closure receives a clone of the stored [`Self::capability`]
    /// directory handle plus that single relative filename, and opens it
    /// exactly once with `read(true)` and [`FollowSymlinks::No`]. A failed
    /// open — including a symlinked final component, which the no-follow
    /// option refuses to resolve — is `NotFound`, so is any handle that does
    /// not report a regular file (anything else — missing, symlinked, or a
    /// directory — is `NotFound`, so no path or storage metadata is ever
    /// revealed). That one opened handle then supplies both the metadata and
    /// the bytes: its length above [`MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES`] is
    /// `SizeLimitExceeded`; its length differing from the declared size is
    /// `SizeMismatch`, both checked before any byte is read; the read
    /// through that same handle is capped at
    /// [`MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES`] + 1 bytes, so concurrent
    /// growth cannot allocate beyond that bound, and the bytes read are
    /// re-checked against the same ceiling and declared size; and only then
    /// does the existing SHA-256
    /// [`hash_matches`] check decide, failing as `HashMismatch`. An
    /// unexpected metadata or read failure is likewise reported without any
    /// path detail as `NotFound`, and a failed blocking-pool join is
    /// `StorageUnavailable`. The result carries only id, content type, hash
    /// and bytes — never the path, storage location, encryption state or
    /// retention metadata.
    pub async fn get(
        &self,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
    ) -> Result<AuthorizedArtifact, ArtifactStoreError> {
        let artifact = self.authorized_metadata(grant, id).await?;
        let capability = Arc::clone(&self.capability);
        let final_name = self.final_name(id);
        let declared_size = artifact.size;
        let hash = artifact.hash.clone();
        let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, ArtifactStoreError> {
            use std::io::Read;

            let mut options = OpenOptions::new();
            options.read(true);
            options.follow(FollowSymlinks::No);
            let mut handle = capability
                .open_with(&final_name, &options)
                .map_err(|_| ArtifactStoreError::NotFound)?;
            let metadata = handle
                .metadata()
                .map_err(|_| ArtifactStoreError::NotFound)?;
            if !metadata.is_file() {
                return Err(ArtifactStoreError::NotFound);
            }
            if metadata.len() > MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES {
                return Err(ArtifactStoreError::SizeLimitExceeded);
            }
            if metadata.len() != declared_size {
                return Err(ArtifactStoreError::SizeMismatch);
            }
            let mut bytes = Vec::new();
            handle
                .by_ref()
                .take(MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ArtifactStoreError::NotFound)?;
            if bytes.len() as u64 > MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES {
                return Err(ArtifactStoreError::SizeLimitExceeded);
            }
            if bytes.len() as u64 != declared_size {
                return Err(ArtifactStoreError::SizeMismatch);
            }
            if !hash_matches(&hash, &bytes) {
                return Err(ArtifactStoreError::HashMismatch);
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| ArtifactStoreError::StorageUnavailable)??;
        Ok(AuthorizedArtifact {
            id: artifact.id,
            content_type: artifact.content_type,
            hash: artifact.hash,
            bytes,
        })
    }

    /// Returns an [`AuthorizedArtifactMetadata`] when `grant` is a live,
    /// read capability bound to this exact artifact.
    ///
    /// The result carries only id, content type, hash, declared size and
    /// declared scanner eligibility — never stored bytes (no file is read),
    /// storage location, encryption state, retention metadata,
    /// customer/deployment scope or grant internals. It runs the same live
    /// checks as [`Self::authorized_metadata`], so the filesystem metadata
    /// path cannot diverge from the capability gate.
    pub async fn get_metadata(
        &self,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
    ) -> Result<AuthorizedArtifactMetadata, ArtifactStoreError> {
        let artifact = self.authorized_metadata(grant, id).await?;
        Ok(AuthorizedArtifactMetadata {
            id: artifact.id,
            content_type: artifact.content_type,
            hash: artifact.hash,
            size_bytes: artifact.size,
            scanner_eligible: artifact.scanner_eligible,
        })
    }

    /// Returns the exact stored [`Artifact`] metadata record for `id` when
    /// `grant` is a live, read capability bound to this artifact.
    ///
    /// All capability checks run before any store state is read: the
    /// `can_read_content` bit must be true; the purpose must be `Scanner`,
    /// `QuarantineRelease`, `DmarcReportIngestion` or `ContentReview`
    /// (`RetentionWorker` cannot read content); the grant must not be expired
    /// (`Utc::now() < expires_at`, so equality counts as expired); and `id`
    /// must be present in the grant's authorized ID set. After the capability
    /// passes, the stored record's deployment/customer scope must match the
    /// grant per
    /// [`scope_matches_artifact`]. Only then is the exact stored metadata
    /// cloned out of the state — no file is ever read. Every failed
    /// permission, purpose, expiry, binding, missing ID or scope check is the
    /// generic [`ArtifactStoreError::NotFound`], so neither permission state
    /// nor existence is revealed.
    async fn authorized_metadata(
        &self,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
    ) -> Result<Artifact, ArtifactStoreError> {
        if !grant.can_read_content {
            return Err(ArtifactStoreError::NotFound);
        }
        if !matches!(
            grant.purpose,
            ArtifactAccessPurpose::Scanner
                | ArtifactAccessPurpose::QuarantineRelease
                | ArtifactAccessPurpose::DmarcReportIngestion
                | ArtifactAccessPurpose::ContentReview
        ) {
            return Err(ArtifactStoreError::NotFound);
        }
        if Utc::now() >= grant.expires_at {
            return Err(ArtifactStoreError::NotFound);
        }
        if !grant.authorized_ids.contains(id) {
            return Err(ArtifactStoreError::NotFound);
        }
        let state = self.state.read().await;
        let stored = state
            .artifacts
            .get(id)
            .ok_or(ArtifactStoreError::NotFound)?;
        if !scope_matches_artifact(grant, stored) {
            return Err(ArtifactStoreError::NotFound);
        }
        Ok(stored.clone())
    }

    /// Validates a candidate `put` before any filesystem work happens.
    ///
    /// Storage-location rules: the backend must be
    /// [`StorageBackend::Filesystem`], `bucket` and `region` must be `None`,
    /// and `key` must equal exactly the server-derived filename produced by
    /// [`Self::final_name`] for `artifact.id` — any other value (including
    /// traversal shapes such as `../`) is rejected as
    /// [`ArtifactStoreError::ImmutableConflict`] without revealing the
    /// expected key or any path. Next, a declared size or byte length above
    /// [`MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES`] is rejected as
    /// [`ArtifactStoreError::SizeLimitExceeded`] before any size comparison
    /// or hashing. Declared size must then equal `bytes.len()`
    /// ([`ArtifactStoreError::SizeMismatch`]), and the SHA-256 check —
    /// which never runs on the async executor — must be accepted
    /// ([`ArtifactStoreError::HashMismatch`]); a failed blocking-pool join
    /// is [`ArtifactStoreError::StorageUnavailable`]. This function never
    /// touches the disk, so a rejected candidate always leaves the root
    /// empty.
    async fn validate_put(
        &self,
        artifact: &Artifact,
        bytes: &[u8],
    ) -> Result<(), ArtifactStoreError> {
        let derived_file_name = self.final_name(&artifact.id);
        if artifact.storage_location.backend != StorageBackend::Filesystem
            || artifact.storage_location.bucket.is_some()
            || artifact.storage_location.region.is_some()
            || artifact.storage_location.key != derived_file_name
        {
            return Err(ArtifactStoreError::ImmutableConflict);
        }
        if artifact.size > MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES
            || bytes.len() as u64 > MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES
        {
            return Err(ArtifactStoreError::SizeLimitExceeded);
        }
        if artifact.size != bytes.len() as u64 {
            return Err(ArtifactStoreError::SizeMismatch);
        }
        let hash = artifact.hash.clone();
        let owned_bytes = bytes.to_vec();
        let matched = tokio::task::spawn_blocking(move || hash_matches(&hash, &owned_bytes))
            .await
            .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
        if !matched {
            return Err(ArtifactStoreError::HashMismatch);
        }
        Ok(())
    }

    /// Publishes `bytes` for `id` at the server-derived final name without
    /// ever replacing existing content.
    ///
    /// The target comes only from [`Self::final_name`] — a single relative
    /// filename — and every filesystem operation runs inside one
    /// blocking-pool closure — never on the async executor — exclusively
    /// through the stored [`Self::capability`] directory using relative
    /// names: no line of this method joins [`Self::root`], builds a
    /// [`PathBuf`], reopens the directory by ambient path or calls `std::fs`
    /// on the artifact. Existing-final validation first asks the capability
    /// for `symlink_metadata(final_name)`: an absent name continues to
    /// publication, a symlink or any other non-regular shape is
    /// [`ArtifactStoreError::ImmutableConflict`], and a regular candidate is
    /// opened exactly once with `read(true)` and [`FollowSymlinks::No`].
    /// That single handle must itself report a regular file, and that same
    /// handle alone supplies a bounded read through
    /// `take(MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES + 1)`, so at most one byte
    /// above [`MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES`] is ever buffered even
    /// if the file grows concurrently; only byte-identical content is
    /// accepted, while oversized or different content is
    /// [`ArtifactStoreError::ImmutableConflict`] and any unexpected
    /// metadata/open/read failure is [`ArtifactStoreError::StorageUnavailable`]
    /// — always without a path.
    ///
    /// When the final name is absent, a fresh-UUID temp name of the form
    /// `.<uuid>.tmp` — also a single relative filename — is created through
    /// the capability with `create_new(true)`, `write(true)`,
    /// [`FollowSymlinks::No`] and Unix mode `0600`, then `write_all`ed and
    /// `sync_all`ed. Publication uses only
    /// `capability.hard_link(temp, capability, final)` — never `rename` and
    /// never an overwrite — so an already published artifact is never
    /// replaced. A lost `AlreadyExists` link race first removes the temp
    /// file and only then revalidates the final name with the exact same
    /// no-follow, single-handle rule. Once the temp file has been created it
    /// is attempted to be removed on **every** return path; if that cleanup
    /// itself fails the result is [`ArtifactStoreError::StorageUnavailable`]
    /// (on the `AlreadyExists` path the cleanup failure is returned before
    /// revalidation). After a newly created link and a successful temp
    /// cleanup, `.` is reopened through the accepted directory capability
    /// and that ordinary directory handle is synced. Reopening through the
    /// capability is required because a cloned `cap_std::fs::Dir` may retain
    /// Linux `O_PATH` semantics on container volumes, for which `fsync(2)`
    /// fails even though a normal directory handle is syncable. Every other
    /// filesystem failure — or a failed blocking-pool join — is the generic
    /// [`ArtifactStoreError::StorageUnavailable`] with no path or backend
    /// detail.
    async fn publish_immutable(
        &self,
        id: &ArtifactId,
        bytes: Vec<u8>,
    ) -> Result<(), ArtifactStoreError> {
        let capability = Arc::clone(&self.capability);
        let final_name = self.final_name(id);
        let temp_name = format!(".{}.tmp", uuid::Uuid::new_v4());
        tokio::task::spawn_blocking(move || -> Result<(), ArtifactStoreError> {
            use std::io::Write;

            /// Same no-follow, single-handle regular/non-symlink/identical
            /// bytes rule for an already-present final name, resolved only
            /// through the directory capability.
            fn existing_matches(
                capability: &Dir,
                final_name: &str,
                bytes: &[u8],
            ) -> Result<(), ArtifactStoreError> {
                use std::io::Read;

                let metadata = capability
                    .symlink_metadata(final_name)
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                if metadata.is_symlink() || !metadata.is_file() {
                    return Err(ArtifactStoreError::ImmutableConflict);
                }

                let mut options = OpenOptions::new();
                options.read(true);
                options.follow(FollowSymlinks::No);
                let mut handle = capability
                    .open_with(final_name, &options)
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                let handle_metadata = handle
                    .metadata()
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                if !handle_metadata.is_file() {
                    return Err(ArtifactStoreError::ImmutableConflict);
                }

                let mut stored = Vec::new();
                Read::by_ref(&mut handle)
                    .take(MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES + 1)
                    .read_to_end(&mut stored)
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                if stored.len() as u64 > MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES
                    || stored.as_slice() != bytes
                {
                    return Err(ArtifactStoreError::ImmutableConflict);
                }
                Ok(())
            }

            match capability.symlink_metadata(&final_name) {
                Ok(_) => return existing_matches(&capability, &final_name, &bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                Err(_) => return Err(ArtifactStoreError::StorageUnavailable),
            }

            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            options.follow(FollowSymlinks::No);
            #[cfg(unix)]
            options.mode(0o600);
            let mut temp = match capability.open_with(&temp_name, &options) {
                Ok(file) => file,
                Err(_) => return Err(ArtifactStoreError::StorageUnavailable),
            };
            if temp
                .write_all(&bytes)
                .and_then(|()| temp.sync_all())
                .is_err()
            {
                capability
                    .remove_file(&temp_name)
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                return Err(ArtifactStoreError::StorageUnavailable);
            }
            drop(temp);

            let link_result = capability.hard_link(&temp_name, capability.as_ref(), &final_name);
            capability
                .remove_file(&temp_name)
                .map_err(|_| ArtifactStoreError::StorageUnavailable)?;

            match link_result {
                Ok(()) => {},
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return existing_matches(&capability, &final_name, &bytes);
                },
                Err(_) => return Err(ArtifactStoreError::StorageUnavailable),
            }

            let mut directory_options = OpenOptions::new();
            directory_options.read(true);
            directory_options.follow(FollowSymlinks::No);
            capability
                .open_with(".", &directory_options)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
            Ok(())
        })
        .await
        .map_err(|_| ArtifactStoreError::StorageUnavailable)?
    }

    /// Removes the published final file for `id` and tombstones the ID, but
    /// only once `grant` is a live retention capability bound to this exact
    /// artifact.
    ///
    /// Capability checks run first, before any store state is read and before
    /// any filesystem work: `can_delete` must be true, the purpose must be
    /// exactly [`ArtifactAccessPurpose::RetentionWorker`], the grant must be
    /// live (`Utc::now() < expires_at`, so equality counts as expired) and
    /// `id` must be present in the grant's exact authorized ID set. Every
    /// capability failure is the generic [`ArtifactStoreError::NotFound`], so
    /// a rejected caller learns nothing about permission state, storage
    /// layout or existence.
    ///
    /// The state write lock is then held across the metadata/retention
    /// decision, the filesystem deletion and the state transition, so while a
    /// deletion runs it excludes in-process [`Self::put`] and any new
    /// [`Self::authorized_metadata`] / [`Self::get_metadata`] authorization
    /// read: a reader that has not yet passed authorization when the
    /// deletion takes the write lock blocks, then finds the record gone and
    /// observes `NotFound`. This exclusion is narrower than "no read can
    /// interleave": a [`Self::get`] that already completed authorization and
    /// opened its file handle before the directory entry was removed may
    /// still finish reading that already-open file afterwards. No claim is
    /// made that all [`Self::get`] calls are excluded, and none is made of
    /// disk/memory crash atomicity across a process or machine failure.
    ///
    /// Under that lock the metadata record must exist and the stored
    /// deployment/customer scope must match the grant per
    /// [`scope_matches_artifact`] (missing record or scope mismatch is
    /// `NotFound`); `retention_class` must be [`RetentionClass::Deleted`] and
    /// `expires_at` must be `Some(deadline)` with `deadline <= now`, otherwise
    /// [`ArtifactStoreError::RetentionViolation`]. A single `now` is captured
    /// at entry and used for both the grant-liveness check and this retention
    /// decision, so one timestamp decides the whole operation and no artifact
    /// can ever be removed before its deadline.
    ///
    /// The deletion target is derived only from [`Self::final_name`] — a
    /// single server-derived relative filename — and every filesystem
    /// operation runs inside one blocking-pool closure, never on the async
    /// executor and never through the ambient [`Self::root`] path: the
    /// closure receives a clone of the stored [`Self::capability`] directory
    /// plus that one relative name, and no line of this method joins
    /// [`Self::root`], builds a [`PathBuf`], calls `std::fs` on the artifact
    /// or reopens the directory by ambient path. The final name is opened
    /// exactly once with `read(true)` and [`FollowSymlinks::No`], and that
    /// one handle must itself report a regular file. An absent final name, a
    /// symlinked final component (the no-follow open refuses to resolve it),
    /// a directory or any other non-regular shape, and any other no-follow
    /// open failure are the generic `NotFound` returned *before*
    /// `remove_file`, so nothing is touched: a symlink target is never
    /// followed, read or unlinked. The verified handle is deliberately kept
    /// open until after `remove_file` has returned, and removal is only
    /// `capability.remove_file(final_name)` — the capability-relative unlink
    /// of that single directory entry, never an ambient path — so no
    /// directory, sibling artifact or temp file is removed. After the
    /// removal the open directory is synced through a cloned capability
    /// handle (`try_clone().into_std_file().sync_all()`).
    ///
    /// State-transition rules, all applied under the same write lock:
    /// - file removal fails: `StorageUnavailable` with metadata and
    ///   tombstones unchanged;
    /// - the open-directory sync fails *after* the file was removed: the
    ///   metadata record is still replaced by the permanent tombstone and
    ///   only then is `StorageUnavailable` returned, because the deletion
    ///   did happen and the ID must never be reused;
    /// - a failed blocking-pool join: `StorageUnavailable` with state
    ///   unchanged — the honest caveat is that the on-disk outcome is then
    ///   unknown, and this store never tombstones a deletion it did not
    ///   confirm.
    ///
    /// Only after a confirmed removal are the metadata record removed and the
    /// permanent tombstone inserted, so a repeat call for a tombstoned ID is
    /// `NotFound` (its metadata no longer exists) and [`Self::put`] for that
    /// ID keeps returning [`ArtifactStoreError::ImmutableConflict`]. Returned
    /// errors never carry a path, storage location, encryption state,
    /// retention detail or existence information.
    pub async fn delete_after_retention(
        &self,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
    ) -> Result<(), ArtifactStoreError> {
        if !grant.can_delete || grant.purpose != ArtifactAccessPurpose::RetentionWorker {
            return Err(ArtifactStoreError::NotFound);
        }
        let now = Utc::now();
        if now >= grant.expires_at {
            return Err(ArtifactStoreError::NotFound);
        }
        if !grant.authorized_ids.contains(id) {
            return Err(ArtifactStoreError::NotFound);
        }

        /// Outcome of the retention deletion step on the filesystem, kept
        /// distinct from failure so the state-transition rules below stay
        /// explicit. The file removal never reports success inside an error
        /// variant: once the final file is gone the ID must be tombstoned
        /// even when the follow-up directory sync fails.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum RetentionFileOutcome {
            /// The final file was removed and the open capability directory
            /// synced.
            Removed,
            /// The final file was removed but the open-directory sync
            /// failed: the ID must still be tombstoned and only then
            /// may [`ArtifactStoreError::StorageUnavailable`] be returned.
            RemovedRootSyncFailed,
        }

        let mut state = self.state.write().await;
        {
            let stored = state
                .artifacts
                .get(id)
                .ok_or(ArtifactStoreError::NotFound)?;
            if !scope_matches_artifact(grant, stored) {
                return Err(ArtifactStoreError::NotFound);
            }
            if stored.retention_class != RetentionClass::Deleted {
                return Err(ArtifactStoreError::RetentionViolation);
            }
            match stored.expires_at {
                Some(deadline) if deadline <= now => {},
                _ => return Err(ArtifactStoreError::RetentionViolation),
            }
        }

        let final_name = self.final_name(id);
        let capability = Arc::clone(&self.capability);
        let outcome = tokio::task::spawn_blocking(
            move || -> Result<RetentionFileOutcome, ArtifactStoreError> {
                let mut options = OpenOptions::new();
                options.read(true);
                options.follow(FollowSymlinks::No);
                let handle = capability
                    .open_with(&final_name, &options)
                    .map_err(|_| ArtifactStoreError::NotFound)?;
                let handle_metadata = handle
                    .metadata()
                    .map_err(|_| ArtifactStoreError::NotFound)?;
                if !handle_metadata.is_file() {
                    return Err(ArtifactStoreError::NotFound);
                }
                capability
                    .remove_file(&final_name)
                    .map_err(|_| ArtifactStoreError::StorageUnavailable)?;
                drop(handle);
                if capability
                    .try_clone()
                    .and_then(|directory| directory.into_std_file().sync_all())
                    .is_err()
                {
                    return Ok(RetentionFileOutcome::RemovedRootSyncFailed);
                }
                Ok(RetentionFileOutcome::Removed)
            },
        )
        .await
        .map_err(|_| ArtifactStoreError::StorageUnavailable)??;

        state.artifacts.remove(id);
        state.tombstones.insert(id.clone());

        match outcome {
            RetentionFileOutcome::Removed => Ok(()),
            RetentionFileOutcome::RemovedRootSyncFailed => {
                Err(ArtifactStoreError::StorageUnavailable)
            },
        }
    }
}

#[cfg(test)]
mod filesystem_store_tests {
    //! Contract tests for [`FilesystemArtifactStore`]: construction
    //! (environment rejection and server-derived paths), the validation and
    //! immutable-publication primitives, the wired `put` operation, the
    //! grant-gated read paths and grant-gated retention deletion.

    use super::*;
    use std::path::Path;

    fn unique_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nullapart-filesystem-store-{label}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    #[tokio::test]
    async fn production_runtime_is_rejected_and_creates_no_directory() {
        let root = unique_root("production");
        let result =
            FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Production)
                .await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::EnvironmentRejected),
            "Production must be rejected with the environment error"
        );
        assert!(
            !root.exists(),
            "Production rejection must create no directory"
        );
    }

    #[tokio::test]
    async fn test_runtime_creates_root_and_final_path_stays_under_it() {
        let root = unique_root("test");
        let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
            .await
            .expect("Test runtime must create the root and return the store");
        assert!(root.is_dir(), "Test runtime must create the root directory");

        let canonical_root = std::fs::canonicalize(&root)
            .expect("the created root must be canonicalizable for comparison");
        let id = ArtifactId::new();
        let path = store.final_path(&id);
        assert_eq!(
            path.parent(),
            Some(canonical_root.as_path()),
            "final path must stay directly under the canonicalized root the constructor stored"
        );
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(format!("{}.artifact", id.0).as_str()),
            "final filename must be exactly the artifact UUID plus the fixed suffix"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn local_development_runtime_constructs_and_stores_paths_under_canonical_root() {
        let root = unique_root("local-development");
        let store = FilesystemArtifactStore::try_new(
            root.clone(),
            FilesystemArtifactRuntime::LocalDevelopment,
        )
        .await
        .expect("LocalDevelopment runtime must construct the store");
        assert!(
            root.is_dir(),
            "LocalDevelopment runtime must create the root directory"
        );

        let canonical_root = std::fs::canonicalize(&root)
            .expect("the created root must be canonicalizable for comparison");
        let id = ArtifactId::new();
        let path = store.final_path(&id);
        assert_eq!(
            path.parent(),
            Some(canonical_root.as_path()),
            "LocalDevelopment final paths must stay directly under the canonical root"
        );
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(format!("{}.artifact", id.0).as_str()),
            "final filename must be exactly the artifact UUID plus the fixed suffix"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The stored directory capability identifies exactly the accepted
    /// canonical root: its own metadata must report a directory whose device
    /// and inode equal the `std` metadata of that root.
    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_capability_dir_metadata_matches_std_metadata_for_accepted_root() {
        use cap_fs_ext::OsMetadataExt as _;
        use std::os::unix::fs::MetadataExt as _;

        let root = unique_root("capability-identity");
        let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
            .await
            .expect("Test runtime must construct the store with a directory capability");

        let canonical_root = std::fs::canonicalize(&root)
            .expect("the accepted root must be canonicalizable for comparison");
        let std_metadata = std::fs::metadata(&canonical_root)
            .expect("the accepted root must be readable for its identity");
        let capability_metadata = store
            .capability
            .dir_metadata()
            .expect("the stored capability must report its own metadata");

        assert!(
            capability_metadata.is_dir(),
            "the stored capability must report a directory"
        );
        assert_eq!(
            (capability_metadata.dev(), capability_metadata.ino()),
            (std_metadata.dev(), std_metadata.ino()),
            "the accepted capability must identify the same device and inode as the \
             std metadata of the accepted root"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Builds a unique existing directory under the system temp directory so
    /// tests can nest further paths (targets, symlinks) inside one tree and
    /// remove that single tree afterwards.
    #[cfg(unix)]
    fn unique_temp_dir(label: &str) -> PathBuf {
        let directory = unique_root(label);
        std::fs::create_dir_all(&directory).expect("the unique temp directory must be creatable");
        directory
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_root_permissions_masked_with_0o777_are_0o700() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_root("mode");
        std::fs::create_dir_all(&root).expect("the root directory must be creatable");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777))
            .expect("the pre-construction root must accept a relaxed mode");

        let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
            .await
            .expect("Test runtime must accept the existing root directory");

        let canonical_root =
            std::fs::canonicalize(&root).expect("the accepted root must be canonicalizable");
        let mode = std::fs::metadata(&canonical_root)
            .expect("the accepted root must remain readable")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "the accepted root permissions masked with 0o777 must equal 0o700"
        );

        let id = ArtifactId::new();
        assert_eq!(
            store.final_path(&id).parent(),
            Some(canonical_root.as_path()),
            "final paths must stay under the accepted root"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_root_is_rejected_and_the_target_directory_is_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let parent = unique_temp_dir("symlink");
        let target = parent.join("target");
        std::fs::create_dir(&target).expect("the symlink target directory must be creatable");
        let marker = target.join("marker.txt");
        std::fs::write(&marker, b"target contents must survive rejection")
            .expect("the target marker file must be writable");
        let target_mode_before = std::fs::metadata(&target)
            .expect("the target directory must be readable")
            .permissions()
            .mode();

        let link = parent.join("link");
        std::os::unix::fs::symlink(&target, &link)
            .expect("the symlink to the target directory must be creatable");

        let result =
            FilesystemArtifactStore::try_new(link.clone(), FilesystemArtifactRuntime::Test).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::StorageUnavailable),
            "a symlink root must be rejected as storage unavailable"
        );

        let target_metadata = std::fs::symlink_metadata(&target)
            .expect("the symlink target must still exist after rejection");
        assert!(
            target_metadata.file_type().is_dir(),
            "the symlink target must still be a directory"
        );
        assert_eq!(
            target_metadata.permissions().mode(),
            target_mode_before,
            "the symlink target permissions must be unchanged"
        );
        let marker_contents = std::fs::read(&marker)
            .expect("the target marker file must still be readable after rejection");
        assert_eq!(
            marker_contents.as_slice(),
            b"target contents must survive rejection".as_slice(),
            "the symlink target contents must be unchanged"
        );

        let _ = std::fs::remove_dir_all(&parent);
    }

    /// Builds a fully valid filesystem-backed artifact whose storage key is
    /// exactly the server-derived `<uuid>.artifact` for its own ID.
    fn valid_filesystem_artifact(bytes: &[u8]) -> Artifact {
        let id = ArtifactId::new();
        Artifact {
            id: id.clone(),
            deployment_id: DeploymentId::new("deployment-alpha"),
            customer_id: Some(CustomerId::new("customer-one")),
            content_type: ContentType::new("message/rfc822"),
            size: bytes.len() as u64,
            storage_location: StorageLocation {
                backend: StorageBackend::Filesystem,
                bucket: None,
                key: format!("{}.artifact", id.0),
                region: None,
            },
            hash: ArtifactHash {
                algorithm: HashAlgorithm::Sha256,
                value: hex::encode(sha2::Sha256::digest(bytes)),
            },
            retention_class: RetentionClass::Standard,
            created_at: Utc::now(),
            expires_at: None,
            encrypted: false,
            scanner_eligible: true,
        }
    }

    async fn store_for(label: &str) -> (FilesystemArtifactStore, PathBuf) {
        let root = unique_root(label);
        let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
            .await
            .expect("Test runtime must create the root and return the store");
        (store, root)
    }

    fn assert_root_empty(root: &PathBuf, case: &str) {
        let entries = std::fs::read_dir(root)
            .expect(case)
            .inspect(|entry| {
                entry.as_ref().expect(case);
            })
            .count();
        assert_eq!(entries, 0, "{case} must leave the root empty");
    }

    #[tokio::test]
    async fn validate_put_accepts_a_valid_filesystem_artifact() {
        let (store, root) = store_for("validate-valid").await;
        let bytes = b"valid filesystem artifact payload".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);

        assert_eq!(
            store.validate_put(&artifact, &bytes).await,
            Ok(()),
            "a Filesystem-backend artifact with the exact server-derived key, \
             size and SHA-256 must validate"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn validate_put_rejects_storage_location_variants_and_leaves_root_empty() {
        let (store, root) = store_for("validate-location").await;
        let bytes = b"storage location rejection payload".to_vec();

        let mut wrong_backend = valid_filesystem_artifact(&bytes);
        wrong_backend.storage_location.backend = StorageBackend::S3;
        assert_eq!(
            store.validate_put(&wrong_backend, &bytes).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a non-Filesystem backend must be rejected"
        );
        assert_root_empty(&root, "a non-Filesystem backend rejection");

        let mut wrong_bucket = valid_filesystem_artifact(&bytes);
        wrong_bucket.storage_location.bucket = Some("caller-bucket".to_string());
        assert_eq!(
            store.validate_put(&wrong_bucket, &bytes).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a caller-supplied bucket must be rejected"
        );
        assert_root_empty(&root, "a caller-supplied bucket rejection");

        let mut wrong_region = valid_filesystem_artifact(&bytes);
        wrong_region.storage_location.region = Some("us-east-1".to_string());
        assert_eq!(
            store.validate_put(&wrong_region, &bytes).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a caller-supplied region must be rejected"
        );
        assert_root_empty(&root, "a caller-supplied region rejection");

        let mut wrong_key = valid_filesystem_artifact(&bytes);
        wrong_key.storage_location.key = "attacker-chosen-key".to_string();
        assert_eq!(
            store.validate_put(&wrong_key, &bytes).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a caller-chosen key must be rejected"
        );
        assert_root_empty(&root, "a caller-chosen key rejection");

        let mut traversal_key = valid_filesystem_artifact(&bytes);
        traversal_key.storage_location.key = "../../escape.artifact".to_string();
        assert_eq!(
            store.validate_put(&traversal_key, &bytes).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a traversal-shaped key must be rejected"
        );
        assert_root_empty(&root, "a traversal-shaped key rejection");

        let mut other_id_key = valid_filesystem_artifact(&bytes);
        other_id_key.storage_location.key = format!("{}.artifact", uuid::Uuid::new_v4());
        assert_eq!(
            store.validate_put(&other_id_key, &bytes).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a key derived from a different UUID must be rejected"
        );
        assert_root_empty(&root, "a key derived from a different UUID rejection");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn validate_put_rejects_wrong_size_and_wrong_hash() {
        let (store, root) = store_for("validate-integrity").await;
        let bytes = b"integrity validation payload".to_vec();

        let mut wrong_size = valid_filesystem_artifact(&bytes);
        wrong_size.size += 1;
        assert_eq!(
            store.validate_put(&wrong_size, &bytes).await,
            Err(ArtifactStoreError::SizeMismatch),
            "a declared size differing from the byte length must be rejected"
        );
        assert_root_empty(&root, "a size rejection");

        let mut wrong_hash = valid_filesystem_artifact(&bytes);
        wrong_hash.hash.value = hex::encode(sha2::Sha256::digest(b"different bytes"));
        assert_eq!(
            store.validate_put(&wrong_hash, &bytes).await,
            Err(ArtifactStoreError::HashMismatch),
            "a declared hash that does not match the bytes must be rejected"
        );
        assert_root_empty(&root, "a hash rejection");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An over-limit declared size is rejected with `SizeLimitExceeded`
    /// before the size comparison could report `SizeMismatch`: the small
    /// byte slice would otherwise mismatch the declared size, and no
    /// over-limit buffer is ever allocated.
    #[tokio::test]
    async fn validate_put_rejects_over_limit_declared_size_before_size_mismatch() {
        let (store, root) = store_for("validate-size-limit").await;
        let bytes = b"small payload".to_vec();

        let mut over_limit = valid_filesystem_artifact(&bytes);
        over_limit.size = MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES + 1;

        assert_eq!(
            store.validate_put(&over_limit, &bytes).await,
            Err(ArtifactStoreError::SizeLimitExceeded),
            "a declared size above the filesystem ceiling must be rejected as \
             SizeLimitExceeded before any SizeMismatch comparison"
        );
        assert_root_empty(&root, "an over-limit declared size rejection");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Strict `read_dir` sweep over `root`: the directory read itself and
    /// every individual entry must succeed (no ignored errors), and no
    /// surviving filename may be an internal `.tmp` staging file left behind
    /// by [`FilesystemArtifactStore::publish_immutable`].
    fn assert_no_temp_files(root: &PathBuf, case: &str) {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) => panic!("{case}: the root must be readable: {error}"),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => panic!("{case}: every directory entry must be readable: {error}"),
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.ends_with(".tmp"),
                "{case} must leave no `.tmp` temp file behind, found `{name}`"
            );
        }
    }

    #[tokio::test]
    async fn publish_immutable_writes_exact_bytes_with_owner_only_permissions() {
        let (store, root) = store_for("publish-new").await;
        let id = ArtifactId::new();
        let bytes = b"freshly published artifact payload".to_vec();

        store
            .publish_immutable(&id, bytes.clone())
            .await
            .expect("publishing a brand-new artifact must succeed");

        let final_path = store.final_path(&id);
        assert_eq!(
            std::fs::read(&final_path).expect("the published final path must be readable"),
            bytes,
            "the final path must hold exactly the published bytes"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&final_path)
                .expect("the published artifact must be readable for its mode")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the published artifact permissions masked with 0o777 must equal 0o600"
            );
        }
        assert_no_temp_files(&root, "a successful publish");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn publish_immutable_twice_with_identical_bytes_is_ok() {
        let (store, root) = store_for("publish-identical").await;
        let id = ArtifactId::new();
        let bytes = b"identical bytes published twice".to_vec();

        store
            .publish_immutable(&id, bytes.clone())
            .await
            .expect("the first publish must succeed");
        store
            .publish_immutable(&id, bytes.clone())
            .await
            .expect("republishing byte-identical content for the same id must be Ok");
        assert_eq!(
            std::fs::read(store.final_path(&id))
                .expect("the final path must remain readable after an identical re-publish"),
            bytes,
            "an identical re-publish must leave the bytes unchanged"
        );
        assert_no_temp_files(&root, "an identical re-publish");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn publish_immutable_rejects_changed_bytes_and_keeps_the_original() {
        let (store, root) = store_for("publish-conflict").await;
        let id = ArtifactId::new();
        let original = b"the original published payload".to_vec();
        let changed = b"different payload for the same id".to_vec();

        store
            .publish_immutable(&id, original.clone())
            .await
            .expect("the initial publish must succeed");
        let result = store.publish_immutable(&id, changed.clone()).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::ImmutableConflict),
            "publishing changed bytes for an existing id must be ImmutableConflict"
        );
        assert_eq!(
            std::fs::read(store.final_path(&id))
                .expect("the original artifact must remain readable after the conflict"),
            original,
            "the originally published bytes must survive the rejected publish"
        );
        assert_no_temp_files(&root, "a conflicting publish");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn publish_immutable_rejects_a_symlinked_final_path_without_touching_the_target() {
        let (store, root) = store_for("publish-symlink").await;
        let target_parent = unique_temp_dir("publish-symlink-target");
        let target = target_parent.join("target.bin");
        std::fs::write(&target, b"target contents must survive rejection")
            .expect("the symlink target file must be writable");

        let id = ArtifactId::new();
        let final_path = store.final_path(&id);
        std::os::unix::fs::symlink(&target, &final_path)
            .expect("the final path must accept a pre-created symlink for the test");

        let result = store
            .publish_immutable(&id, b"candidate payload that must not publish".to_vec())
            .await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::ImmutableConflict),
            "a symlinked final path must be rejected as ImmutableConflict"
        );
        assert_eq!(
            std::fs::read(&target).expect("the symlink target must remain readable"),
            b"target contents must survive rejection".as_slice(),
            "the symlink target bytes must be unchanged"
        );

        let link_metadata = std::fs::symlink_metadata(&final_path)
            .expect("the final path must still exist after the rejection");
        assert!(
            link_metadata.file_type().is_symlink(),
            "only the pre-created symlink may exist at the final path"
        );
        std::fs::remove_file(&final_path)
            .expect("cleanup must remove only the symlink at the final path");
        assert!(
            !final_path.exists(),
            "the symlink must be gone after cleanup"
        );
        assert!(
            target.exists(),
            "removing the symlink must leave the separate target file in place"
        );
        assert_no_temp_files(&root, "a symlinked final path rejection");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&target_parent);
    }

    #[tokio::test]
    async fn publish_immutable_leaves_no_temp_files_after_success_and_conflict() {
        let (store, root) = store_for("publish-no-temp").await;
        let id = ArtifactId::new();
        let original = b"first payload for the temp sweep".to_vec();

        store
            .publish_immutable(&id, original.clone())
            .await
            .expect("the initial publish must succeed");
        assert_no_temp_files(&root, "after a successful publish");

        let result = store
            .publish_immutable(&id, b"second payload for the temp sweep".to_vec())
            .await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::ImmutableConflict),
            "a changed-byte publish must conflict"
        );
        assert_no_temp_files(&root, "after a conflicting publish");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Type-level proof that the filesystem state carries metadata only:
    /// the parameter type is exactly the value type of
    /// [`FilesystemArtifactState::artifacts`], and [`Artifact`] has no
    /// payload member, so no stored bytes can be read from the state at all.
    fn assert_metadata_only(record: &Artifact) -> &Artifact {
        record
    }

    /// A valid `put` publishes the exact final bytes, records the artifact
    /// metadata under its ID, and keeps the payload bytes exclusively on
    /// disk — never inside the state type.
    #[tokio::test]
    async fn put_publishes_exact_final_bytes_and_records_metadata_without_bytes() {
        let (store, root) = store_for("put-valid").await;
        let bytes = b"FS-PUT-PAYLOAD-MUST-STAY-ON-DISK-ONLY".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a valid artifact and byte payload must put successfully");

        assert_eq!(
            std::fs::read(store.final_path(&artifact.id))
                .expect("the published final path must be readable"),
            bytes,
            "the final file must contain exactly the submitted bytes"
        );

        {
            let state = store.state.read().await;
            assert_eq!(
                state.artifacts.len(),
                1,
                "a first successful put must record exactly one metadata entry"
            );
            let stored = state
                .artifacts
                .get(&artifact.id)
                .expect("the state must contain the artifact id after a successful put");
            assert!(
                same_metadata(stored, &artifact),
                "the recorded metadata must be identical to the submitted artifact"
            );
            assert_metadata_only(stored);
            let rendered = format!("{:?}", *state);
            assert!(
                !rendered.contains("FS-PUT-PAYLOAD"),
                "the state type must never retain artifact bytes"
            );
            assert!(
                !rendered.contains("bytes"),
                "the state type must expose no bytes member at all"
            );
        }

        assert_no_temp_files(&root, "a successful put");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Re-putting the exact same artifact record and bytes succeeds and
    /// leaves exactly one metadata record plus unchanged published bytes.
    #[tokio::test]
    async fn exact_duplicate_put_succeeds_and_keeps_one_metadata_record() {
        let (store, root) = store_for("put-duplicate").await;
        let bytes = b"exact duplicate filesystem put payload".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        let duplicate = artifact.clone();

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("the first put must succeed");
        store
            .put(duplicate, bytes.clone())
            .await
            .expect("an exact duplicate artifact and byte payload must put successfully");

        {
            let state = store.state.read().await;
            assert_eq!(
                state.artifacts.len(),
                1,
                "an exact duplicate must leave exactly one metadata record"
            );
            let stored = state
                .artifacts
                .get(&artifact.id)
                .expect("the single metadata record must be keyed by the artifact id");
            assert!(
                same_metadata(stored, &artifact),
                "the surviving record must keep the identical metadata"
            );
        }

        assert_eq!(
            std::fs::read(store.final_path(&artifact.id))
                .expect("the published final path must remain readable"),
            bytes,
            "an idempotent duplicate put must leave the published bytes unchanged"
        );
        assert_no_temp_files(&root, "an idempotent duplicate put");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Same bytes with one changed metadata field (`scanner_eligible`) is an
    /// immutable conflict that preserves the original file and metadata.
    #[tokio::test]
    async fn changed_metadata_for_same_id_is_immutable_conflict_and_preserves_original() {
        let (store, root) = store_for("put-metadata-conflict").await;
        let bytes = b"immutable filesystem put payload".to_vec();
        let original = valid_filesystem_artifact(&bytes);
        assert!(
            original.scanner_eligible,
            "the helper must default the artifact to scanner eligible"
        );

        store
            .put(original.clone(), bytes.clone())
            .await
            .expect("the original put must succeed");

        let mut changed = original.clone();
        changed.scanner_eligible = false;
        let result = store.put(changed, bytes.clone()).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::ImmutableConflict),
            "identical bytes with one changed metadata field must be rejected"
        );

        assert_eq!(
            std::fs::read(store.final_path(&original.id))
                .expect("the original final path must remain readable"),
            bytes,
            "the original file bytes must survive the rejected put"
        );

        {
            let state = store.state.read().await;
            assert_eq!(
                state.artifacts.len(),
                1,
                "a rejected conflicting put must leave the single original record"
            );
            let stored = state
                .artifacts
                .get(&original.id)
                .expect("the original record must survive the conflict");
            assert!(
                same_metadata(stored, &original),
                "the original metadata must be preserved unchanged"
            );
            assert!(
                stored.scanner_eligible,
                "the original scanner_eligible value must survive the conflict"
            );
        }

        assert_no_temp_files(&root, "a metadata conflict");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A hash-invalid artifact is rejected before publication: no final file
    /// is created and no metadata is added.
    #[tokio::test]
    async fn hash_invalid_put_creates_no_file_and_adds_no_metadata() {
        let (store, root) = store_for("put-hash-invalid").await;
        let bytes = b"payload whose declared sha256 will be wrong".to_vec();
        let mut artifact = valid_filesystem_artifact(&bytes);
        artifact.hash.value = hex::encode(sha2::Sha256::digest(b"a completely different payload"));

        let result = store.put(artifact.clone(), bytes).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::HashMismatch),
            "an artifact whose declared hash does not match the bytes must be rejected"
        );

        assert!(
            !store.final_path(&artifact.id).exists(),
            "a hash-invalid put must create no final file"
        );
        assert_root_empty(&root, "a hash-invalid put");
        {
            let state = store.state.read().await;
            assert!(
                state.artifacts.is_empty(),
                "a hash-invalid put must add no metadata"
            );
            assert!(
                state.tombstones.is_empty(),
                "a hash-invalid put must tombstone nothing"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A tombstoned ID is rejected as an immutable conflict before any
    /// publication: no final file is created and no metadata is added.
    #[tokio::test]
    async fn tombstoned_id_put_is_immutable_conflict_with_no_file_and_no_metadata() {
        let (store, root) = store_for("put-tombstoned").await;
        let bytes = b"payload for an already tombstoned artifact id".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);

        store
            .state
            .write()
            .await
            .tombstones
            .insert(artifact.id.clone());

        let result = store.put(artifact.clone(), bytes).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::ImmutableConflict),
            "a put for a tombstoned id must be rejected as an immutable conflict"
        );

        assert!(
            !store.final_path(&artifact.id).exists(),
            "a tombstoned put must create no final file"
        );
        assert_root_empty(&root, "a tombstoned put");
        {
            let state = store.state.read().await;
            assert!(
                state.artifacts.is_empty(),
                "a tombstoned put must add no metadata"
            );
            assert!(
                state.tombstones.contains(&artifact.id),
                "the tombstone must remain in place"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // Authorized reads over the filesystem store
    // -----------------------------------------------------------------------

    const DEPLOYMENT_A: &str = "deployment-alpha";
    const DEPLOYMENT_B: &str = "deployment-beta";
    const CUSTOMER_ONE: &str = "customer-one";
    const CUSTOMER_TWO: &str = "customer-two";

    /// Deadline comfortably in the future so every helper-issued grant stays
    /// live for the whole run without sleeping.
    fn future_deadline() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::hours(1)
    }

    /// Deadline strictly in the past so a helper-issued grant is already
    /// expired without sleeping.
    fn expired_deadline() -> DateTime<Utc> {
        Utc::now() - chrono::Duration::hours(1)
    }

    /// The only grant-issuance path used by these filesystem tests: grants go
    /// through [`ArtifactAccessGrant::issue_server_authorized`] with an
    /// explicit deployment, an explicit customer scope, the exact artifact
    /// ID set, a closed purpose, explicit permission bits and an explicit
    /// deadline — never as a struct literal.
    fn issue_read_grant(
        deployment: &str,
        customer: &str,
        purpose: ArtifactAccessPurpose,
        can_read_content: bool,
        authorized_ids: Vec<ArtifactId>,
        expires_at: DateTime<Utc>,
    ) -> ArtifactAccessGrant {
        ArtifactAccessGrant::issue_server_authorized(
            DeploymentId::new(deployment),
            ArtifactScope::Customer(CustomerId::new(customer)),
            "filesystem-store-test-actor".to_string(),
            ArtifactPermissions::new(can_read_content, false),
            purpose,
            authorized_ids,
            expires_at,
        )
        .expect("a grant bound to an explicit non-empty artifact id set must issue")
    }

    /// Matching-scope, read-permitted `Scanner` grant bound to exactly
    /// `authorized_ids` with a future deadline: the baseline live read
    /// capability for these tests.
    fn scanner_read_grant(
        deployment: &str,
        customer: &str,
        authorized_ids: Vec<ArtifactId>,
    ) -> ArtifactAccessGrant {
        issue_read_grant(
            deployment,
            customer,
            ArtifactAccessPurpose::Scanner,
            true,
            authorized_ids,
            future_deadline(),
        )
    }

    /// Asserts that both authorized read paths report the generic
    /// [`ArtifactStoreError::NotFound`] for `grant`/`id`, so neither
    /// permission state nor existence is revealed.
    async fn assert_both_reads_not_found(
        store: &FilesystemArtifactStore,
        grant: &ArtifactAccessGrant,
        id: &ArtifactId,
        case: &str,
    ) {
        assert_eq!(
            store.get(grant, id).await.err(),
            Some(ArtifactStoreError::NotFound),
            "{case}: get must return the generic NotFound"
        );
        assert_eq!(
            store.get_metadata(grant, id).await.err(),
            Some(ArtifactStoreError::NotFound),
            "{case}: get_metadata must return the generic NotFound"
        );
    }

    /// A valid `put` plus a matching-scope `Scanner` grant makes `get`
    /// return exactly the stored bytes, id, content type and hash, and
    /// `get_metadata` return only the expected metadata projection — never
    /// the payload itself.
    #[tokio::test]
    async fn valid_put_with_scanner_grant_returns_exact_bytes_and_metadata_projection() {
        let (store, root) = store_for("read-valid").await;
        let bytes = b"FS-READ-VALID-PAYLOAD-ROUND-TRIP".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a valid artifact and byte payload must put successfully");
        assert_no_temp_files(&root, "a valid read put");

        let grant = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);

        let stored = store
            .get(&grant, &artifact.id)
            .await
            .expect("a matching-scope Scanner grant must read the artifact");
        assert_eq!(
            stored.id, artifact.id,
            "get must return the exact artifact id"
        );
        assert_eq!(
            stored.content_type, artifact.content_type,
            "get must return the exact content type"
        );
        assert_eq!(stored.hash, artifact.hash, "get must return the exact hash");
        assert_eq!(
            stored.hash.value,
            hex::encode(sha2::Sha256::digest(&bytes)),
            "the returned hash must be the lowercase SHA-256 of the returned bytes"
        );
        assert_eq!(
            stored.bytes, bytes,
            "get must return the exact stored bytes"
        );

        let metadata = store
            .get_metadata(&grant, &artifact.id)
            .await
            .expect("a matching-scope Scanner grant must read the metadata");
        assert_eq!(
            metadata,
            AuthorizedArtifactMetadata {
                id: artifact.id.clone(),
                content_type: artifact.content_type.clone(),
                hash: artifact.hash.clone(),
                size_bytes: artifact.size,
                scanner_eligible: artifact.scanner_eligible,
            },
            "get_metadata must return exactly the expected metadata projection"
        );
        let rendered = format!("{:?}", metadata);
        assert!(
            !rendered.contains("FS-READ-VALID-PAYLOAD"),
            "the metadata projection must never carry artifact bytes"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A grant scoped to a different customer must observe the generic
    /// `NotFound` on both read paths, never cross-tenant existence.
    #[tokio::test]
    async fn read_with_different_customer_is_not_found() {
        let (store, root) = store_for("read-wrong-customer").await;
        let bytes = b"FS-READ-SCOPE-CUSTOMER-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let wrong_customer =
            scanner_read_grant(DEPLOYMENT_A, CUSTOMER_TWO, vec![artifact.id.clone()]);
        assert_both_reads_not_found(&store, &wrong_customer, &artifact.id, "different customer")
            .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A grant scoped to a different deployment must observe the generic
    /// `NotFound` on both read paths, never cross-deployment existence.
    #[tokio::test]
    async fn read_with_different_deployment_is_not_found() {
        let (store, root) = store_for("read-wrong-deployment").await;
        let bytes = b"FS-READ-SCOPE-DEPLOYMENT-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let wrong_deployment =
            scanner_read_grant(DEPLOYMENT_B, CUSTOMER_ONE, vec![artifact.id.clone()]);
        assert_both_reads_not_found(
            &store,
            &wrong_deployment,
            &artifact.id,
            "different deployment",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A valid grant bound only to another artifact ID must observe the
    /// generic `NotFound` for this exact ID on both read paths.
    #[tokio::test]
    async fn read_with_grant_bound_to_other_id_is_not_found() {
        let (store, root) = store_for("read-other-id").await;
        let bytes = b"FS-READ-BINDING-OTHER-ID-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let other_bound = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![ArtifactId::new()]);
        assert_both_reads_not_found(
            &store,
            &other_bound,
            &artifact.id,
            "grant bound to another id",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An expired grant must observe the generic `NotFound` on both read
    /// paths even though its scope, binding and permissions all match.
    #[tokio::test]
    async fn read_with_expired_grant_is_not_found() {
        let (store, root) = store_for("read-expired").await;
        let bytes = b"FS-READ-EXPIRED-GRANT-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let expired = issue_read_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::Scanner,
            true,
            vec![artifact.id.clone()],
            expired_deadline(),
        );
        assert_both_reads_not_found(&store, &expired, &artifact.id, "expired grant").await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A matching-scope grant without the read permission bit must observe
    /// the generic `NotFound` on both read paths.
    #[tokio::test]
    async fn read_without_read_permission_is_not_found() {
        let (store, root) = store_for("read-no-permission").await;
        let bytes = b"FS-READ-NO-PERMISSION-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let denied = issue_read_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::Scanner,
            false,
            vec![artifact.id.clone()],
            future_deadline(),
        );
        assert_both_reads_not_found(&store, &denied, &artifact.id, "no-read permission").await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A live `RetentionWorker`-purpose grant cannot read content: both
    /// read paths must observe the generic `NotFound`.
    #[tokio::test]
    async fn read_with_retention_worker_purpose_is_not_found() {
        let (store, root) = store_for("read-retention-purpose").await;
        let bytes = b"FS-READ-RETENTION-PURPOSE-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let retention = issue_read_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::RetentionWorker,
            true,
            vec![artifact.id.clone()],
            future_deadline(),
        );
        assert_both_reads_not_found(&store, &retention, &artifact.id, "RetentionWorker purpose")
            .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A live `ContentReview`-purpose grant is a normal read capability: both
    /// read paths return the stored bytes and the metadata projection for the
    /// one artifact the grant is bound to.
    #[tokio::test]
    async fn read_with_content_review_purpose_returns_bytes_and_metadata() {
        let (store, root) = store_for("read-content-review-purpose").await;
        let bytes = b"FS-READ-CONTENT-REVIEW-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a valid put must succeed");
        assert_no_temp_files(&root, "a content-review read put");

        let review = issue_read_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::ContentReview,
            true,
            vec![artifact.id.clone()],
            future_deadline(),
        );
        let authorized = store
            .get(&review, &artifact.id)
            .await
            .expect("a ContentReview grant must read the bound artifact");
        assert_eq!(
            authorized.id, artifact.id,
            "the read must name the artifact"
        );
        assert_eq!(
            authorized.bytes, bytes,
            "the read must return exactly the stored bytes"
        );

        let metadata = store
            .get_metadata(&review, &artifact.id)
            .await
            .expect("a ContentReview grant must read the bound artifact metadata");
        assert_eq!(
            metadata.size_bytes,
            bytes.len() as u64,
            "the metadata must report the declared size"
        );

        let other = ArtifactId::new();
        assert_both_reads_not_found(&store, &review, &other, "unbound ContentReview artifact")
            .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// After a valid `put`, replacing the final file's bytes in place with
    /// different bytes of the same length makes `get` fail the on-disk
    /// SHA-256 check with `HashMismatch`.
    #[tokio::test]
    async fn overwritten_final_file_with_same_length_bytes_returns_hash_mismatch() {
        let (store, root) = store_for("read-tampered").await;
        let bytes = b"FS-READ-TAMPER-PAYLOAD-ORIGINAL".to_vec();
        let tampered = b"FS-READ-TAMPER-PAYLOAD-ATTACKED".to_vec();
        assert_eq!(
            bytes.len(),
            tampered.len(),
            "the tampered bytes must be exactly the same length as the original"
        );

        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let final_path = store.final_path(&artifact.id);
        std::fs::write(&final_path, &tampered)
            .expect("the final file must accept an in-place overwrite for the test");
        assert_eq!(
            std::fs::read(&final_path).expect("the overwritten final file must be readable"),
            tampered,
            "the setup must have replaced the final file with the tampered bytes"
        );

        let grant = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let result = store.get(&grant, &artifact.id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::HashMismatch),
            "same-length bytes whose SHA-256 differs from the declared hash must be HashMismatch"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Removing the final file makes `get` return the generic `NotFound`
    /// while an authorized `get_metadata` read still succeeds: metadata
    /// lives in the state record, not on disk.
    #[tokio::test]
    async fn removed_final_file_returns_not_found_but_authorized_metadata_remains() {
        let (store, root) = store_for("read-missing-file").await;
        let bytes = b"FS-READ-MISSING-FILE-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let grant = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);

        std::fs::remove_file(store.final_path(&artifact.id))
            .expect("the final file must be removable for the test");
        let get_result = store.get(&grant, &artifact.id).await;
        assert_eq!(
            get_result.err(),
            Some(ArtifactStoreError::NotFound),
            "a missing final file must return the generic NotFound"
        );

        let metadata = store
            .get_metadata(&grant, &artifact.id)
            .await
            .expect("authorized metadata must remain available without the final file");
        assert_eq!(
            metadata,
            AuthorizedArtifactMetadata {
                id: artifact.id,
                content_type: artifact.content_type,
                hash: artifact.hash,
                size_bytes: artifact.size,
                scanner_eligible: artifact.scanner_eligible,
            },
            "the metadata projection must be unchanged by the missing file"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Replacing the final file with a symlink makes `get` return the
    /// generic `NotFound` without reading the target: the target's length
    /// deliberately differs from the declared size, so an implementation
    /// that followed the link would report `SizeMismatch`/`HashMismatch`
    /// instead. The symlink and the target both survive untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_final_file_returns_not_found_without_reading_its_target() {
        let (store, root) = store_for("read-symlink").await;
        let target_parent = unique_temp_dir("read-symlink-target");
        let target = target_parent.join("target.bin");
        let target_bytes =
            b"symlink target contents far longer than the declared artifact size".to_vec();

        let bytes = b"FS-READ-SYMLINK-PAYLOAD".to_vec();
        assert_ne!(
            target_bytes.len(),
            bytes.len(),
            "the target must differ in length from the declared size so a followed \
             link could not pass the size check"
        );

        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("a valid put must succeed");

        let final_path = store.final_path(&artifact.id);
        std::fs::remove_file(&final_path).expect("the final file must be removable for the test");
        std::fs::write(&target, &target_bytes).expect("the symlink target file must be writable");
        std::os::unix::fs::symlink(&target, &final_path)
            .expect("the final path must accept a symlink for the test");

        let grant = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let result = store.get(&grant, &artifact.id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "a symlinked final file must return the generic NotFound without following it"
        );

        let link_metadata = std::fs::symlink_metadata(&final_path)
            .expect("the symlink must still exist after the rejected read");
        assert!(
            link_metadata.file_type().is_symlink(),
            "the read must not have dereferenced or replaced the symlink"
        );
        assert_eq!(
            std::fs::read(&target).expect("the symlink target must remain readable"),
            target_bytes,
            "the symlink target bytes must be unchanged by the rejected read"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&target_parent);
    }

    /// The pinned directory capability survives a replacement of the root
    /// pathname: after the accepted root directory is renamed away and the
    /// original pathname is occupied by a symlink to an attacker directory,
    /// `put`, an authorized `get` and `delete_after_retention` all still
    /// resolve exclusively through the capability, so the exact bytes land
    /// under the moved directory, the due `Deleted` artifact's final file is
    /// removed from that same moved directory, and the attacker directory
    /// stays untouched and empty. The capability's own `dev`/`ino` identity
    /// must equal the `std` metadata of the moved directory, and no `.tmp`
    /// staging file may survive either path.
    #[cfg(unix)]
    #[tokio::test]
    async fn pinned_capability_survives_root_pathname_replacement() {
        use cap_fs_ext::OsMetadataExt as _;
        use std::os::unix::fs::MetadataExt as _;

        let parent = unique_temp_dir("pinned-capability");
        let root = parent.join("root");
        let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
            .await
            .expect("Test runtime must construct the store with a directory capability");

        let moved_root = parent.join("moved-root");
        std::fs::rename(&root, &moved_root)
            .expect("the accepted root directory must be movable to a distinct path");

        let attacker = parent.join("attacker");
        std::fs::create_dir(&attacker).expect("the attacker directory must be creatable");
        std::os::unix::fs::symlink(&attacker, &root)
            .expect("the original root pathname must accept a symlink to the attacker directory");

        let bytes = b"FS-PINNED-CAPABILITY-ROOT-PATHNAME-REPLACED".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a valid put must publish through the pinned capability");

        let grant = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let stored = store
            .get(&grant, &artifact.id)
            .await
            .expect("an authorized read must resolve through the pinned capability");

        assert_eq!(
            stored.id, artifact.id,
            "get must return the exact artifact id"
        );
        assert_eq!(
            stored.bytes, bytes,
            "get must return the exact stored bytes"
        );
        assert_eq!(
            std::fs::read(moved_root.join(store.final_name(&artifact.id)))
                .expect("the moved root must hold the published final file"),
            bytes,
            "the exact final bytes must exist under the moved root directory"
        );

        let attacker_entries = std::fs::read_dir(&attacker)
            .expect("the attacker directory must be readable")
            .inspect(|entry| {
                entry
                    .as_ref()
                    .expect("every attacker directory entry must be readable");
            })
            .count();
        assert_eq!(
            attacker_entries, 0,
            "the attacker directory reached through the replaced root pathname must stay empty"
        );

        let deleted_bytes = b"FS-PINNED-CAPABILITY-RETENTION-DELETE-PAYLOAD".to_vec();
        let deleted = deleted_filesystem_artifact(&deleted_bytes, due_retention_deadline());
        assert_ne!(
            deleted.id, artifact.id,
            "the retention-deletion artifact must be distinct from the Standard artifact"
        );
        store
            .put(deleted.clone(), deleted_bytes.clone())
            .await
            .expect(
                "a due Deleted-class artifact must publish through the pinned capability while \
                 the original root pathname is still the attacker symlink",
            );

        let deleted_final = moved_root.join(store.final_name(&deleted.id));
        assert_eq!(
            std::fs::read(&deleted_final)
                .expect("the moved root must hold the due Deleted artifact's final file"),
            deleted_bytes,
            "the exact final bytes of the due Deleted artifact must exist under the moved root \
             directory"
        );

        let delete_grant =
            retention_delete_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![deleted.id.clone()]);
        store
            .delete_after_retention(&delete_grant, &deleted.id)
            .await
            .expect("a due Deleted-class artifact must be removable through the pinned capability");

        assert!(
            !deleted_final.exists(),
            "the moved root final file of the deleted artifact must be gone"
        );

        let attacker_entries_after_delete = std::fs::read_dir(&attacker)
            .expect("the attacker directory must remain readable")
            .inspect(|entry| {
                entry
                    .as_ref()
                    .expect("every attacker directory entry must be readable");
            })
            .count();
        assert_eq!(
            attacker_entries_after_delete, 0,
            "the attacker directory must remain empty after the retention delete"
        );

        {
            let state = store.state.read().await;
            assert!(
                !state.artifacts.contains_key(&deleted.id),
                "the deleted artifact's metadata record must be absent"
            );
            assert!(
                state.tombstones.contains(&deleted.id),
                "the deleted artifact's ID must carry a permanent tombstone"
            );
            let stored = state
                .artifacts
                .get(&artifact.id)
                .expect("the original Standard artifact's metadata must remain present");
            assert!(
                same_metadata(stored, &artifact),
                "the original Standard artifact's metadata must be unchanged by the retention \
                 delete"
            );
        }
        assert_eq!(
            std::fs::read(moved_root.join(store.final_name(&artifact.id)))
                .expect("the original Standard artifact's final file must remain readable"),
            bytes,
            "the original Standard artifact's final file must be unchanged by the retention \
             delete"
        );

        assert_no_temp_files(&moved_root, "a root pathname replacement");

        let capability_metadata = store
            .capability
            .dir_metadata()
            .expect("the stored capability must report its own metadata");
        let moved_metadata = std::fs::metadata(&moved_root)
            .expect("the moved root directory must be readable for its identity");
        assert!(
            capability_metadata.is_dir(),
            "the stored capability must still report a directory"
        );
        assert_eq!(
            (capability_metadata.dev(), capability_metadata.ino()),
            (moved_metadata.dev(), moved_metadata.ino()),
            "the pinned capability must identify the same device and inode as the \
             std metadata of the moved root directory"
        );

        std::fs::remove_file(&root)
            .expect("cleanup must remove only the symlink at the original root pathname");
        std::fs::remove_dir_all(&moved_root)
            .expect("cleanup must remove the moved root directory tree");
        std::fs::remove_dir_all(&attacker)
            .expect("cleanup must remove the attacker directory tree");
        std::fs::remove_dir_all(&parent).expect("cleanup must remove the parent directory tree");
    }

    // -----------------------------------------------------------------------
    // Retention deletion over the filesystem store
    // -----------------------------------------------------------------------

    /// Retention deadline strictly in the past, so a `Deleted` artifact
    /// carrying it is already due for retention deletion without sleeping.
    fn due_retention_deadline() -> DateTime<Utc> {
        Utc::now() - chrono::Duration::hours(1)
    }

    /// Retention deadline comfortably in the future, so a `Deleted` artifact
    /// carrying it is not yet due for retention deletion without sleeping.
    fn pending_retention_deadline() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::hours(1)
    }

    /// A deletable filesystem artifact: identical to
    /// [`valid_filesystem_artifact`] (server-derived storage key, declared
    /// size and SHA-256 over `bytes`) except that the retention class is
    /// `Deleted` and the retention `deadline` is explicit.
    fn deleted_filesystem_artifact(bytes: &[u8], deadline: DateTime<Utc>) -> Artifact {
        let mut artifact = valid_filesystem_artifact(bytes);
        artifact.retention_class = RetentionClass::Deleted;
        artifact.expires_at = Some(deadline);
        artifact
    }

    /// The deletion-side counterpart to [`issue_read_grant`]: the same
    /// server-authorized issuance path with an explicit `can_delete` bit, an
    /// explicit purpose and an explicit deadline — never a struct literal —
    /// so a delete test can vary exactly one capability field at a time.
    fn issue_delete_grant(
        deployment: &str,
        customer: &str,
        purpose: ArtifactAccessPurpose,
        can_delete: bool,
        authorized_ids: Vec<ArtifactId>,
        expires_at: DateTime<Utc>,
    ) -> ArtifactAccessGrant {
        ArtifactAccessGrant::issue_server_authorized(
            DeploymentId::new(deployment),
            ArtifactScope::Customer(CustomerId::new(customer)),
            "filesystem-store-test-actor".to_string(),
            ArtifactPermissions::new(true, can_delete),
            purpose,
            authorized_ids,
            expires_at,
        )
        .expect("a grant bound to an explicit non-empty artifact id set must issue")
    }

    /// Baseline live retention capability: both permission bits set, the
    /// exact `RetentionWorker` purpose, matching deployment/customer scope,
    /// bound to exactly `authorized_ids` with a future deadline. The read bit
    /// is set deliberately so a `NotFound` from a rejected delete can never
    /// be explained by a missing read permission.
    fn retention_delete_grant(
        deployment: &str,
        customer: &str,
        authorized_ids: Vec<ArtifactId>,
    ) -> ArtifactAccessGrant {
        issue_delete_grant(
            deployment,
            customer,
            ArtifactAccessPurpose::RetentionWorker,
            true,
            authorized_ids,
            future_deadline(),
        )
    }

    /// Asserts that a rejected retention delete left everything in place: the
    /// final file still holds exactly `bytes`, the metadata record is
    /// unchanged, no tombstone exists for the ID, and no `.tmp` staging file
    /// was left behind.
    async fn assert_retention_rejected_preserves_artifact(
        store: &FilesystemArtifactStore,
        root: &PathBuf,
        artifact: &Artifact,
        bytes: &[u8],
        case: &str,
    ) {
        assert_eq!(
            std::fs::read(store.final_path(&artifact.id)).unwrap_or_else(|error| {
                panic!("{case}: the final file must remain readable: {error}")
            }),
            bytes,
            "{case}: the final file bytes must be unchanged"
        );
        {
            let state = store.state.read().await;
            let stored = state
                .artifacts
                .get(&artifact.id)
                .unwrap_or_else(|| panic!("{case}: the metadata record must be preserved"));
            assert!(
                same_metadata(stored, artifact),
                "{case}: the stored metadata must be unchanged"
            );
            assert!(
                !state.tombstones.contains(&artifact.id),
                "{case}: a rejected retention delete must insert no tombstone"
            );
        }
        assert_no_temp_files(root, case);
    }

    /// Runs one refused retention delete: `grant` must be answered with the
    /// generic [`ArtifactStoreError::NotFound`] and the artifact — file,
    /// metadata and tombstone set — must be untouched.
    async fn assert_delete_not_found_preserves_artifact(
        store: &FilesystemArtifactStore,
        root: &PathBuf,
        artifact: &Artifact,
        bytes: &[u8],
        grant: &ArtifactAccessGrant,
        case: &str,
    ) {
        let result = store.delete_after_retention(grant, &artifact.id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::NotFound),
            "{case}: a refused retention delete must be the generic NotFound"
        );
        assert_retention_rejected_preserves_artifact(store, root, artifact, bytes, case).await;
    }

    /// A due `Deleted` artifact is deleted for a live retention grant bound
    /// to that exact ID and scope: the final file is removed, the metadata
    /// record is replaced by a permanent tombstone, a repeat delete stays
    /// `NotFound`, and the same ID can never be put again.
    #[tokio::test]
    async fn expired_deleted_artifact_is_deleted_tombstoned_and_never_reusable() {
        let (store, root) = store_for("retention-delete").await;
        let bytes = b"FS-RETENTION-DELETE-EXPIRED-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");
        assert!(
            store.final_path(&artifact.id).exists(),
            "setup must publish the final file"
        );

        let grant = retention_delete_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        store
            .delete_after_retention(&grant, &artifact.id)
            .await
            .expect("an expired Deleted-class artifact must be removable");

        assert!(
            !store.final_path(&artifact.id).exists(),
            "the final file must be removed"
        );
        {
            let state = store.state.read().await;
            assert!(
                state.artifacts.is_empty(),
                "the metadata record must be removed"
            );
            assert!(
                state.tombstones.contains(&artifact.id),
                "the ID must carry a permanent tombstone"
            );
        }
        assert_no_temp_files(&root, "a successful retention delete");

        let repeat = store.delete_after_retention(&grant, &artifact.id).await;
        assert_eq!(
            repeat,
            Err(ArtifactStoreError::NotFound),
            "a repeat delete for an already tombstoned ID must stay NotFound"
        );

        let reinsert = store.put(artifact.clone(), bytes.clone()).await;
        assert_eq!(
            reinsert,
            Err(ArtifactStoreError::ImmutableConflict),
            "a tombstoned ID must never be reusable"
        );
        assert!(
            !store.final_path(&artifact.id).exists(),
            "the refused re-put must not recreate the final file"
        );
        assert_no_temp_files(&root, "a refused re-put of a tombstoned ID");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `RetentionClass::Standard` is never deletable, however expired the
    /// caller's grant is: `RetentionViolation`, with file, metadata and
    /// tombstone set untouched.
    #[tokio::test]
    async fn standard_retention_delete_is_retention_violation_and_preserves_artifact() {
        let (store, root) = store_for("retention-standard").await;
        let bytes = b"FS-RETENTION-STANDARD-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        assert_eq!(
            artifact.retention_class,
            RetentionClass::Standard,
            "the helper must build a Standard-retention artifact"
        );

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a Standard-retention artifact must put");

        let grant = retention_delete_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let result = store.delete_after_retention(&grant, &artifact.id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::RetentionViolation),
            "a Standard-retention artifact must reject deletion"
        );
        assert_retention_rejected_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            "Standard retention",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `Deleted` artifact whose own retention deadline is still in the
    /// future is not deletable yet: `RetentionViolation`, with file, metadata
    /// and tombstone set untouched.
    #[tokio::test]
    async fn future_deleted_expiry_delete_is_retention_violation_and_preserves_artifact() {
        let (store, root) = store_for("retention-future").await;
        let bytes = b"FS-RETENTION-FUTURE-DEADLINE-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, pending_retention_deadline());

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a Deleted-class artifact with a future deadline must put");

        let grant = retention_delete_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let result = store.delete_after_retention(&grant, &artifact.id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::RetentionViolation),
            "a future retention deadline must reject deletion"
        );
        assert_retention_rejected_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            "future retention deadline",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A grant whose purpose is not exactly `RetentionWorker` observes the
    /// generic `NotFound` even with the delete permission bit set, and
    /// nothing about the artifact changes.
    #[tokio::test]
    async fn delete_with_non_retention_purpose_is_not_found() {
        let (store, root) = store_for("retention-wrong-purpose").await;
        let bytes = b"FS-RETENTION-WRONG-PURPOSE-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");

        let scanner = issue_delete_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::Scanner,
            true,
            vec![artifact.id.clone()],
            future_deadline(),
        );
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &scanner,
            "Scanner purpose",
        )
        .await;

        let release = issue_delete_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::QuarantineRelease,
            true,
            vec![artifact.id.clone()],
            future_deadline(),
        );
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &release,
            "QuarantineRelease purpose",
        )
        .await;

        let dmarc = issue_delete_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::DmarcReportIngestion,
            true,
            vec![artifact.id.clone()],
            future_deadline(),
        );
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &dmarc,
            "DmarcReportIngestion purpose",
        )
        .await;

        let review = issue_delete_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::ContentReview,
            true,
            vec![artifact.id.clone()],
            future_deadline(),
        );
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &review,
            "ContentReview purpose",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `RetentionWorker` grant without `can_delete` observes the generic
    /// `NotFound`, and nothing about the artifact changes.
    #[tokio::test]
    async fn delete_without_delete_permission_is_not_found() {
        let (store, root) = store_for("retention-no-permission").await;
        let bytes = b"FS-RETENTION-NO-DELETE-PERMISSION-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");

        let denied = issue_delete_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::RetentionWorker,
            false,
            vec![artifact.id.clone()],
            future_deadline(),
        );
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &denied,
            "can_delete=false",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An expired retention grant observes the generic `NotFound` even though
    /// its purpose, permission bits, binding and scope all match, and nothing
    /// about the artifact changes.
    #[tokio::test]
    async fn delete_with_expired_grant_is_not_found() {
        let (store, root) = store_for("retention-expired-grant").await;
        let bytes = b"FS-RETENTION-EXPIRED-GRANT-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");

        let expired = issue_delete_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            ArtifactAccessPurpose::RetentionWorker,
            true,
            vec![artifact.id.clone()],
            expired_deadline(),
        );
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &expired,
            "expired grant",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A full-permission retention grant bound only to another artifact ID
    /// observes the generic `NotFound` for this exact ID, and nothing about
    /// the artifact changes.
    #[tokio::test]
    async fn delete_with_grant_bound_to_other_id_is_not_found() {
        let (store, root) = store_for("retention-other-id").await;
        let bytes = b"FS-RETENTION-BINDING-OTHER-ID-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");

        let other_bound =
            retention_delete_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![ArtifactId::new()]);
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &other_bound,
            "grant bound to another id",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A full-permission retention grant from another deployment observes the
    /// generic `NotFound`, never cross-deployment existence, and nothing
    /// about the artifact changes.
    #[tokio::test]
    async fn delete_with_different_deployment_is_not_found() {
        let (store, root) = store_for("retention-wrong-deployment").await;
        let bytes = b"FS-RETENTION-SCOPE-DEPLOYMENT-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");

        let wrong_deployment =
            retention_delete_grant(DEPLOYMENT_B, CUSTOMER_ONE, vec![artifact.id.clone()]);
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &wrong_deployment,
            "different deployment",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A full-permission retention grant for another customer observes the
    /// generic `NotFound`, never cross-tenant existence, and nothing about
    /// the artifact changes.
    #[tokio::test]
    async fn delete_with_different_customer_is_not_found() {
        let (store, root) = store_for("retention-wrong-customer").await;
        let bytes = b"FS-RETENTION-SCOPE-CUSTOMER-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");

        let wrong_customer =
            retention_delete_grant(DEPLOYMENT_A, CUSTOMER_TWO, vec![artifact.id.clone()]);
        assert_delete_not_found_preserves_artifact(
            &store,
            &root,
            &artifact,
            &bytes,
            &wrong_customer,
            "different customer",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A due `Deleted` artifact whose final file has vanished must not
    /// succeed: the delete is the generic `NotFound`, and the metadata record
    /// and tombstone set stay exactly as they were.
    #[tokio::test]
    async fn missing_final_file_returns_not_found_and_preserves_metadata() {
        let (store, root) = store_for("retention-missing-file").await;
        let bytes = b"FS-RETENTION-MISSING-FILE-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");

        std::fs::remove_file(store.final_path(&artifact.id))
            .expect("the final file must be removable for the test");

        let grant = retention_delete_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let result = store.delete_after_retention(&grant, &artifact.id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::NotFound),
            "a missing final file must be the generic NotFound"
        );

        {
            let state = store.state.read().await;
            let stored = state
                .artifacts
                .get(&artifact.id)
                .expect("the metadata record must survive a missing final file");
            assert!(
                same_metadata(stored, &artifact),
                "the stored metadata must be unchanged by the missing file"
            );
            assert!(
                !state.tombstones.contains(&artifact.id),
                "a missing final file must insert no tombstone"
            );
        }
        assert_no_temp_files(&root, "a missing final file");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlink at the final path is refused as the generic `NotFound`
    /// without ever following it: the link itself and the separate target
    /// file both survive with unchanged contents, and neither metadata nor
    /// the tombstone set changes.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_final_file_returns_not_found_without_touching_the_target() {
        let (store, root) = store_for("retention-symlink").await;
        let target_parent = unique_temp_dir("retention-symlink-target");
        let target = target_parent.join("target.bin");
        let target_bytes = b"retention symlink target contents that must survive".to_vec();
        std::fs::write(&target, &target_bytes).expect("the symlink target file must be writable");

        let bytes = b"FS-RETENTION-SYMLINK-PAYLOAD".to_vec();
        let artifact = deleted_filesystem_artifact(&bytes, due_retention_deadline());
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("a due Deleted-class artifact must put");

        let final_path = store.final_path(&artifact.id);
        std::fs::remove_file(&final_path).expect("the final file must be removable for the test");
        std::os::unix::fs::symlink(&target, &final_path)
            .expect("the final path must accept a symlink for the test");

        let grant = retention_delete_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let result = store.delete_after_retention(&grant, &artifact.id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::NotFound),
            "a symlinked final file must be the generic NotFound without following it"
        );

        let link_metadata = std::fs::symlink_metadata(&final_path)
            .expect("the symlink must still exist after the refused delete");
        assert!(
            link_metadata.file_type().is_symlink(),
            "the refused delete must not dereference, replace or unlink the symlink"
        );
        assert_eq!(
            std::fs::read(&target).expect("the symlink target must remain readable"),
            target_bytes,
            "the symlink target bytes must be unchanged by the refused delete"
        );
        {
            let state = store.state.read().await;
            let stored = state
                .artifacts
                .get(&artifact.id)
                .expect("the metadata record must survive a symlinked final file");
            assert!(
                same_metadata(stored, &artifact),
                "the stored metadata must be unchanged by the symlinked final file"
            );
            assert!(
                !state.tombstones.contains(&artifact.id),
                "a symlinked final file must insert no tombstone"
            );
        }
        assert_no_temp_files(&root, "a symlinked final file");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&target_parent);
    }

    /// Deleting one artifact touches only that artifact: the other artifact's
    /// final file and metadata stay intact, the deleted artifact's file is
    /// gone, and the root holds no temp or leftover files.
    #[tokio::test]
    async fn retention_delete_leaves_no_temp_files_and_affects_only_its_own_artifact() {
        let (store, root) = store_for("retention-neighbour").await;
        let deleted_bytes = b"FS-RETENTION-NEIGHBOUR-DELETED-PAYLOAD".to_vec();
        let deleted_artifact =
            deleted_filesystem_artifact(&deleted_bytes, due_retention_deadline());
        let kept_bytes = b"FS-RETENTION-NEIGHBOUR-KEPT-PAYLOAD".to_vec();
        let kept_artifact = valid_filesystem_artifact(&kept_bytes);

        store
            .put(deleted_artifact.clone(), deleted_bytes.clone())
            .await
            .expect("the due Deleted-class artifact must put");
        store
            .put(kept_artifact.clone(), kept_bytes.clone())
            .await
            .expect("the neighbouring artifact must put");

        let grant = retention_delete_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            vec![deleted_artifact.id.clone()],
        );
        store
            .delete_after_retention(&grant, &deleted_artifact.id)
            .await
            .expect("the due Deleted-class artifact must be removable");

        assert!(
            !store.final_path(&deleted_artifact.id).exists(),
            "the deleted artifact's final file must be gone"
        );
        assert_eq!(
            std::fs::read(store.final_path(&kept_artifact.id))
                .expect("the neighbouring final file must remain readable"),
            kept_bytes,
            "the neighbouring final file bytes must be unchanged"
        );

        let mut remaining: Vec<String> = std::fs::read_dir(&root)
            .expect("the root must be readable")
            .map(|entry| {
                entry
                    .expect("every root entry must be readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        remaining.sort();
        assert_eq!(
            remaining,
            vec![format!("{}.artifact", kept_artifact.id.0)],
            "only the neighbouring artifact's final file may remain, with no temp files"
        );

        {
            let state = store.state.read().await;
            assert!(
                !state.artifacts.contains_key(&deleted_artifact.id),
                "the deleted artifact's metadata must be gone"
            );
            assert!(
                state.tombstones.contains(&deleted_artifact.id),
                "the deleted artifact's ID must be tombstoned"
            );
            let kept = state
                .artifacts
                .get(&kept_artifact.id)
                .expect("the neighbouring metadata record must survive");
            assert!(
                same_metadata(kept, &kept_artifact),
                "the neighbouring metadata must be unchanged"
            );
            assert!(
                !state.tombstones.contains(&kept_artifact.id),
                "the neighbouring artifact must not be tombstoned"
            );
        }

        let observer =
            scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![kept_artifact.id.clone()]);
        let read_back = store
            .get(&observer, &kept_artifact.id)
            .await
            .expect("the neighbouring artifact must stay readable after the delete");
        assert_eq!(read_back.bytes, kept_bytes);

        let _ = std::fs::remove_dir_all(&root);
    }
    // -----------------------------------------------------------------------
    // Trusted rehydration after a process restart
    // -----------------------------------------------------------------------

    /// Reopens a second store over the same root: a fresh process state with
    /// the published bytes already on disk but no in-memory metadata.
    async fn reopened_store(root: &Path) -> FilesystemArtifactStore {
        FilesystemArtifactStore::try_new(root.to_path_buf(), FilesystemArtifactRuntime::Test)
            .await
            .expect("a second store over an existing root must construct")
    }

    /// Recovery is the only path that re-enters process state after a
    /// restart: a byte-identical published artifact is rehydrated, recovery
    /// is idempotent, and the recovered record is readable and metadata
    /// readable through a matching-scope grant.
    #[tokio::test]
    async fn recover_existing_after_restart_rehydrates_published_artifact() {
        let (store, root) = store_for("recover-restart").await;
        let bytes = b"FS-RECOVER-RESTART-PAYLOAD-ROUND-TRIP".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("the initial put must publish the artifact");

        let reopened = reopened_store(&root).await;
        {
            let state = reopened.state.read().await;
            assert!(
                state.artifacts.is_empty(),
                "a fresh process must start with no metadata record"
            );
        }

        reopened
            .recover_existing(artifact.clone())
            .await
            .expect("recovery of a byte-identical published artifact must succeed");
        reopened
            .recover_existing(artifact.clone())
            .await
            .expect("recovery must be idempotent for an already rehydrated record");

        let grant = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let read_back = reopened
            .get(&grant, &artifact.id)
            .await
            .expect("a recovered artifact must be readable under a matching-scope grant");
        assert_eq!(read_back.bytes, bytes, "recovery must preserve exact bytes");
        let metadata = reopened
            .get_metadata(&grant, &artifact.id)
            .await
            .expect("recovery must rehydrate the metadata projection");
        assert_eq!(
            metadata.size_bytes,
            bytes.len() as u64,
            "the recovered record must carry the declared size"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Recovery never widens authority: a rehydrated record is still denied
    /// to another customer, another deployment, an unrelated artifact id and
    /// a retention delete grant from the wrong scope.
    #[tokio::test]
    async fn recovered_artifact_stays_denied_outside_its_scope() {
        let (store, root) = store_for("recover-cross-scope").await;
        let bytes = b"FS-RECOVER-CROSS-SCOPE-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("the initial put must publish the artifact");

        let reopened = reopened_store(&root).await;
        reopened
            .recover_existing(artifact.clone())
            .await
            .expect("recovery must succeed before the scope assertions");

        let other_customer =
            scanner_read_grant(DEPLOYMENT_A, CUSTOMER_TWO, vec![artifact.id.clone()]);
        assert_both_reads_not_found(
            &reopened,
            &other_customer,
            &artifact.id,
            "recovered artifact read from another customer",
        )
        .await;

        let other_deployment =
            scanner_read_grant(DEPLOYMENT_B, CUSTOMER_ONE, vec![artifact.id.clone()]);
        assert_both_reads_not_found(
            &reopened,
            &other_deployment,
            &artifact.id,
            "recovered artifact read from another deployment",
        )
        .await;

        let unrelated_id = ArtifactId::new();
        let wrong_id = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![unrelated_id]);
        assert_both_reads_not_found(
            &reopened,
            &wrong_id,
            &artifact.id,
            "recovered artifact read under an unrelated authorized id",
        )
        .await;

        let foreign_delete =
            retention_delete_grant(DEPLOYMENT_A, CUSTOMER_TWO, vec![artifact.id.clone()]);
        assert_eq!(
            reopened
                .delete_after_retention(&foreign_delete, &artifact.id)
                .await
                .err(),
            Some(ArtifactStoreError::NotFound),
            "a foreign-scope retention grant must not delete a recovered artifact"
        );
        assert!(
            reopened.final_path(&artifact.id).exists(),
            "the denied delete must leave the published bytes in place"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Same-length tampering of the published bytes makes recovery fail with
    /// `HashMismatch`, and the record never enters process state: a later
    /// authorized read observes the generic `NotFound`.
    #[tokio::test]
    async fn recover_existing_rejects_same_length_tampered_bytes() {
        let (store, root) = store_for("recover-tampered").await;
        let bytes = b"FS-RECOVER-TAMPER-PAYLOAD-ORIGINAL".to_vec();
        let tampered = b"FS-RECOVER-TAMPER-PAYLOAD-ATTACKED".to_vec();
        assert_eq!(
            bytes.len(),
            tampered.len(),
            "the tampered bytes must be exactly the same length as the original"
        );
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("the initial put must publish the artifact");

        std::fs::write(store.final_path(&artifact.id), &tampered)
            .expect("the final file must accept an in-place overwrite for the test");

        let reopened = reopened_store(&root).await;
        assert_eq!(
            reopened.recover_existing(artifact.clone()).await,
            Err(ArtifactStoreError::HashMismatch),
            "recovery must verify SHA-256 over the published bytes"
        );
        {
            let state = reopened.state.read().await;
            assert!(
                state.artifacts.is_empty(),
                "a failed recovery must add no metadata record"
            );
        }

        let grant = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        assert_both_reads_not_found(
            &reopened,
            &grant,
            &artifact.id,
            "read after a failed recovery",
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A published file whose on-disk length no longer matches the trusted
    /// record is rejected with `SizeMismatch` before any digest work.
    #[tokio::test]
    async fn recover_existing_rejects_size_mismatch() {
        let (store, root) = store_for("recover-size").await;
        let bytes = b"FS-RECOVER-SIZE-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("the initial put must publish the artifact");

        let final_path = store.final_path(&artifact.id);
        std::fs::write(&final_path, b"FS-RECOVER-SIZE").expect("the file must accept truncation");

        let reopened = reopened_store(&root).await;
        assert_eq!(
            reopened.recover_existing(artifact.clone()).await,
            Err(ArtifactStoreError::SizeMismatch),
            "a length that differs from the declared size must be a SizeMismatch"
        );
        {
            let state = reopened.state.read().await;
            assert!(
                state.artifacts.is_empty(),
                "a size-mismatched recovery must add no metadata record"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A missing published file reports the generic `NotFound`, never a
    /// path or storage-location detail.
    #[tokio::test]
    async fn recover_existing_rejects_missing_file() {
        let (store, root) = store_for("recover-missing").await;
        let bytes = b"FS-RECOVER-MISSING-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("the initial put must publish the artifact");
        std::fs::remove_file(store.final_path(&artifact.id))
            .expect("the published file must be removable for the test");

        let reopened = reopened_store(&root).await;
        assert_eq!(
            reopened.recover_existing(artifact.clone()).await,
            Err(ArtifactStoreError::NotFound),
            "a missing published file must be the generic NotFound"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlink planted at the final name is never followed: recovery opens
    /// with symlink following disabled and reports `NotFound`.
    #[cfg(unix)]
    #[tokio::test]
    async fn recover_existing_rejects_symlinked_final_path() {
        let (store, root) = store_for("recover-symlink").await;
        let bytes = b"FS-RECOVER-SYMLINK-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("the initial put must publish the artifact");

        let final_path = store.final_path(&artifact.id);
        std::fs::remove_file(&final_path).expect("the published file must be removable");
        let outside = root.join("outside-target.txt");
        std::fs::write(&outside, b"FS-RECOVER-SYMLINK-TARGET").expect("the target must be written");
        std::os::unix::fs::symlink(&outside, &final_path).expect("the symlink must be created");

        let reopened = reopened_store(&root).await;
        assert_eq!(
            reopened.recover_existing(artifact.clone()).await,
            Err(ArtifactStoreError::NotFound),
            "a symlinked final path must never be followed by recovery"
        );
        assert_eq!(
            std::fs::read(&outside).expect("the symlink target must stay readable"),
            b"FS-RECOVER-SYMLINK-TARGET",
            "recovery must not touch the symlink target"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A candidate whose storage location is not the server-derived
    /// filesystem name is rejected before any state or filesystem work.
    #[tokio::test]
    async fn recover_existing_rejects_foreign_storage_location() {
        let (store, root) = store_for("recover-location").await;
        let bytes = b"FS-RECOVER-LOCATION-PAYLOAD".to_vec();
        let mut artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes)
            .await
            .expect("the initial put must publish the artifact");

        artifact.storage_location.bucket = Some("foreign-bucket".to_string());
        let reopened = reopened_store(&root).await;
        assert_eq!(
            reopened.recover_existing(artifact.clone()).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a bucket-bearing storage location must be an immutable conflict"
        );

        let mut regional = valid_filesystem_artifact(b"FS-RECOVER-REGION".as_ref());
        regional.storage_location.region = Some("eu-west-1".to_string());
        assert_eq!(
            reopened.recover_existing(regional).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a region-bearing storage location must be an immutable conflict"
        );

        let mut renamed = valid_filesystem_artifact(b"FS-RECOVER-RENAMED".as_ref());
        renamed.storage_location.key = "not-a-server-derived-name".to_string();
        assert_eq!(
            reopened.recover_existing(renamed).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a key that is not the server-derived final name must be a conflict"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Declared size above the local ceiling and a non-SHA-256 digest are
    /// rejected up front, without opening any file.
    #[tokio::test]
    async fn recover_existing_rejects_over_limit_and_non_sha256_records() {
        let (_store, root) = store_for("recover-bounds").await;
        let reopened = reopened_store(&root).await;

        let bytes = b"FS-RECOVER-BOUNDS-PAYLOAD".to_vec();
        let mut oversized = valid_filesystem_artifact(&bytes);
        oversized.size = MAX_LOCAL_FILESYSTEM_ARTIFACT_BYTES + 1;
        assert_eq!(
            reopened.recover_existing(oversized).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a record above the local ceiling must be an immutable conflict"
        );

        let mut foreign_hash = valid_filesystem_artifact(&bytes);
        foreign_hash.hash.algorithm = HashAlgorithm::Sha512;
        assert_eq!(
            reopened.recover_existing(foreign_hash).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a record whose digest algorithm is not SHA-256 must be a conflict"
        );

        assert_root_empty(&root, "a rejected recovery");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A tombstoned id and an already-rehydrated id with conflicting
    /// metadata are both immutable conflicts, and the original record
    /// survives untouched.
    #[tokio::test]
    async fn recover_existing_rejects_tombstoned_and_conflicting_records() {
        let (store, root) = store_for("recover-conflict").await;
        let bytes = b"FS-RECOVER-CONFLICT-PAYLOAD".to_vec();
        let artifact = valid_filesystem_artifact(&bytes);
        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("the initial put must publish the artifact");

        let reopened = reopened_store(&root).await;
        reopened
            .recover_existing(artifact.clone())
            .await
            .expect("the first recovery must succeed");

        let mut conflicting = artifact.clone();
        conflicting.content_type = ContentType::new("text/plain");
        assert_eq!(
            reopened.recover_existing(conflicting).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "recovery with metadata that differs from the record must conflict"
        );

        reopened
            .state
            .write()
            .await
            .tombstones
            .insert(ArtifactId::new());
        let mut tombstoned = artifact.clone();
        tombstoned.id = reopened
            .state
            .read()
            .await
            .tombstones
            .iter()
            .next()
            .expect("the tombstone must exist")
            .clone();
        tombstoned.storage_location.key = format!("{}.artifact", tombstoned.id.0);
        assert_eq!(
            reopened.recover_existing(tombstoned).await,
            Err(ArtifactStoreError::ImmutableConflict),
            "a tombstoned id must be an immutable conflict"
        );

        let grant = scanner_read_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![artifact.id.clone()]);
        let read_back = reopened
            .get(&grant, &artifact.id)
            .await
            .expect("the original record must stay readable after the conflicts");
        assert_eq!(
            read_back.bytes, bytes,
            "the original bytes must be unchanged"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod tests {
    //! In-module contract tests for [`InMemoryArtifactStore`].
    //!
    //! These tests live here (rather than as an integration test) because they
    //! exercise `pub(crate)` APIs (`put`, `issue_server_authorized`) and the
    //! private [`ArtifactScope`]. Assertions cover only what the opaque API
    //! actually returns: [`AuthorizedArtifact`] (id, content type, hash,
    //! bytes) and [`AuthorizedArtifactMetadata`] (id, content type, hash,
    //! declared size, declared scanner eligibility). Storage location,
    //! encryption state and retention metadata are internal to the store and
    //! are never asserted from `get` or `get_metadata`.

    use chrono::{DateTime, Utc};
    use nullapart_mail_contracts::artifact::StorageBackend;
    use uuid::Uuid;

    use super::*;

    const DEPLOYMENT_A: &str = "deployment-alpha";
    const DEPLOYMENT_B: &str = "deployment-beta";
    const CUSTOMER_ONE: &str = "customer-one";
    const CUSTOMER_TWO: &str = "customer-two";

    const FIXED_TIMESTAMP_SECONDS: i64 = 1_700_000_000;

    // -----------------------------------------------------------------------
    // Deterministic helpers
    // -----------------------------------------------------------------------

    fn sha256_lower(bytes: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(bytes))
    }

    fn artifact_id(n: u128) -> ArtifactId {
        ArtifactId(Uuid::from_u128(n))
    }

    fn fixed_created_at() -> DateTime<Utc> {
        DateTime::from_timestamp(FIXED_TIMESTAMP_SECONDS, 0)
            .expect("fixed test timestamp must be a valid UTC datetime")
    }

    /// Expiration safely in the future: every helper-issued test grant stays
    /// valid for the whole run without sleeping.
    fn future_expires_at() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::hours(1)
    }

    /// Expiration strictly in the past: a fixed 2023 timestamp that is
    /// always expired relative to `Utc::now()` without sleeping.
    fn expired_expires_at() -> DateTime<Utc> {
        fixed_created_at()
    }

    /// Builds a Memory-backend artifact whose declared hash is the correctly
    /// computed lowercase SHA-256 of `bytes`.
    fn memory_artifact(
        id: ArtifactId,
        deployment_id: &str,
        customer_id: Option<&str>,
        bytes: &[u8],
        retention_class: RetentionClass,
    ) -> Artifact {
        let key = format!("memory/artifacts/{}", id.0);
        Artifact {
            id,
            deployment_id: DeploymentId::new(deployment_id),
            customer_id: customer_id.map(CustomerId::new),
            content_type: ContentType::new("message/rfc822"),
            size: bytes.len() as u64,
            storage_location: StorageLocation {
                backend: StorageBackend::Memory,
                bucket: None,
                key,
                region: None,
            },
            hash: ArtifactHash {
                algorithm: HashAlgorithm::Sha256,
                value: sha256_lower(bytes),
            },
            retention_class,
            created_at: fixed_created_at(),
            expires_at: None,
            encrypted: false,
            scanner_eligible: true,
        }
    }

    /// The only grant-issuance path used anywhere, tests included: grants go
    /// through `issue_server_authorized` and are never written as struct
    /// literals (fields and constructors are not public).
    fn issue_grant(
        deployment_id: &str,
        scope: ArtifactScope,
        can_read_content: bool,
        can_delete: bool,
        purpose: ArtifactAccessPurpose,
        authorized_ids: Vec<ArtifactId>,
        expires_at: DateTime<Utc>,
    ) -> Result<ArtifactAccessGrant, ArtifactGrantIssueError> {
        ArtifactAccessGrant::issue_server_authorized(
            DeploymentId::new(deployment_id),
            scope,
            "test-actor".to_string(),
            ArtifactPermissions::new(can_read_content, can_delete),
            purpose,
            authorized_ids,
            expires_at,
        )
    }

    /// Full-permission customer-scope grant (Scanner purpose) bound to
    /// `authorized_ids` and unexpired.
    fn grant(
        deployment_id: &str,
        customer_id: &str,
        authorized_ids: Vec<ArtifactId>,
    ) -> ArtifactAccessGrant {
        issue_grant(
            deployment_id,
            ArtifactScope::Customer(CustomerId::new(customer_id)),
            true,
            true,
            ArtifactAccessPurpose::Scanner,
            authorized_ids,
            future_expires_at(),
        )
        .expect("scanner grant with a non-empty authorized ID set must issue")
    }

    /// Full-permission customer-scope grant with the RetentionWorker purpose,
    /// bound to `authorized_ids` and unexpired.
    fn retention_grant(
        deployment_id: &str,
        customer_id: &str,
        authorized_ids: Vec<ArtifactId>,
    ) -> ArtifactAccessGrant {
        issue_grant(
            deployment_id,
            ArtifactScope::Customer(CustomerId::new(customer_id)),
            true,
            true,
            ArtifactAccessPurpose::RetentionWorker,
            authorized_ids,
            future_expires_at(),
        )
        .expect("retention grant with a non-empty authorized ID set must issue")
    }

    /// Full-permission system-scope grant for customerless artifacts, bound
    /// to `authorized_ids` and unexpired.
    fn system_grant(deployment_id: &str, authorized_ids: Vec<ArtifactId>) -> ArtifactAccessGrant {
        issue_grant(
            deployment_id,
            ArtifactScope::System,
            true,
            true,
            ArtifactAccessPurpose::RetentionWorker,
            authorized_ids,
            future_expires_at(),
        )
        .expect("system grant with a non-empty authorized ID set must issue")
    }

    /// Full-permission system-scope grant with the Scanner purpose (reads
    /// only; `RetentionWorker` cannot read), bound to `authorized_ids`.
    fn system_scanner_grant(
        deployment_id: &str,
        authorized_ids: Vec<ArtifactId>,
    ) -> ArtifactAccessGrant {
        issue_grant(
            deployment_id,
            ArtifactScope::System,
            true,
            false,
            ArtifactAccessPurpose::Scanner,
            authorized_ids,
            future_expires_at(),
        )
        .expect("system scanner grant with a non-empty authorized ID set must issue")
    }

    fn sample_bytes() -> Vec<u8> {
        b"nullapart artifact store contract payload".to_vec()
    }

    // -----------------------------------------------------------------------
    // Grant construction is server-authorized only
    // -----------------------------------------------------------------------

    /// Grants are issued through the internal server-authorized function —
    /// there is no public constructor or public field to form a struct
    /// literal, in production code or in tests.
    #[test]
    fn grants_are_issued_only_via_server_authorized_function() {
        let id = artifact_id(0);
        let grant = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        assert_eq!(grant.deployment_id, DeploymentId::new(DEPLOYMENT_A));
        assert_eq!(
            grant.scope,
            ArtifactScope::Customer(CustomerId::new(CUSTOMER_ONE))
        );
        assert_eq!(grant.actor_id, "test-actor");
        assert!(grant.can_read_content);
        assert!(grant.can_delete);
        assert_eq!(grant.purpose, ArtifactAccessPurpose::Scanner);

        let system = system_grant(DEPLOYMENT_A, vec![id.clone()]);
        assert_eq!(system.scope, ArtifactScope::System);
    }

    /// There is no empty and no wildcard artifact capability: an empty
    /// authorized ID set is rejected at issuance with the explicit error.
    #[test]
    fn issuing_grant_with_empty_artifact_scope_is_rejected() {
        let result = ArtifactAccessGrant::issue_server_authorized(
            DeploymentId::new(DEPLOYMENT_A),
            ArtifactScope::Customer(CustomerId::new(CUSTOMER_ONE)),
            "test-actor".to_string(),
            ArtifactPermissions::new(true, true),
            ArtifactAccessPurpose::Scanner,
            Vec::new(),
            future_expires_at(),
        );
        assert_eq!(
            result,
            Err(ArtifactGrantIssueError::EmptyAuthorizedIds),
            "an empty authorized artifact scope must be rejected at issuance"
        );
    }

    // -----------------------------------------------------------------------
    // 1. Round-trip under matching deployment/customer
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn round_trip_bytes_under_matching_scope() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(1);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("put under matching scope must succeed");

        let grant = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let stored = store
            .get(&grant, &id)
            .await
            .expect("get under matching scope must succeed");

        // AuthorizedArtifact exposes id/content_type/hash/bytes only —
        // never storage location, encryption or retention metadata.
        assert_eq!(stored.id, artifact.id);
        assert_eq!(stored.content_type, artifact.content_type);
        assert_eq!(stored.hash, artifact.hash);
        assert_eq!(stored.bytes, bytes, "stored bytes must round-trip");
        assert_eq!(
            stored.hash.value,
            sha256_lower(&bytes),
            "hash must be lowercase SHA-256 of the stored bytes"
        );
        assert_eq!(
            stored.hash.value,
            stored.hash.value.to_lowercase(),
            "hash value must be lowercase hex"
        );
    }

    // -----------------------------------------------------------------------
    // 2. SHA-256 mismatch -> HashMismatch
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn put_rejects_sha256_hash_mismatch() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(2);
        let declared_bytes = sample_bytes();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &declared_bytes,
            RetentionClass::Standard,
        );

        let tampered_bytes = b"tampered payload that does not match the declared hash".to_vec();
        artifact.hash.value = sha256_lower(&declared_bytes);

        let result = store.put(artifact, tampered_bytes).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::HashMismatch),
            "bytes whose SHA-256 differs from the declared hash must be rejected"
        );

        let grant = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let get_result = store.get(&grant, &id).await;
        assert_eq!(
            get_result.err(),
            Some(ArtifactStoreError::NotFound),
            "a rejected put must not store the artifact"
        );
    }

    // -----------------------------------------------------------------------
    // 3. Exact duplicate same ID/metadata/bytes -> Ok
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn exact_duplicate_put_with_same_id_and_content_is_ok() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(3);
        let bytes = sample_bytes();
        let first = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );
        let duplicate = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(first, bytes.clone())
            .await
            .expect("initial put must succeed");

        let duplicate_result = store.put(duplicate, bytes.clone()).await;
        assert_eq!(
            duplicate_result,
            Ok(()),
            "identical re-put of the same ID/metadata/bytes must be idempotent"
        );

        let grant = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let stored = store
            .get(&grant, &id)
            .await
            .expect("artifact must remain retrievable after idempotent put");
        assert_eq!(stored.bytes, bytes);
    }

    // -----------------------------------------------------------------------
    // 4. Changed duplicate same ID -> ImmutableConflict
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn changed_duplicate_same_id_is_immutable_conflict() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(4);
        let original_bytes = sample_bytes();
        let original = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &original_bytes,
            RetentionClass::Standard,
        );

        store
            .put(original, original_bytes.clone())
            .await
            .expect("initial put must succeed");

        let changed_bytes = b"a different payload under the same artifact id".to_vec();
        let changed = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &changed_bytes,
            RetentionClass::Standard,
        );

        let result = store.put(changed, changed_bytes).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::ImmutableConflict),
            "same ID with different content must be rejected as immutable"
        );

        let grant = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let stored = store
            .get(&grant, &id)
            .await
            .expect("original artifact must survive the rejected put");
        assert_eq!(
            stored.bytes, original_bytes,
            "original bytes must remain unchanged after conflict"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Different deployment get -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_with_different_deployment_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(5);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes)
            .await
            .expect("initial put must succeed");

        let wrong_deployment = grant(DEPLOYMENT_B, CUSTOMER_ONE, vec![id.clone()]);
        let result = store.get(&wrong_deployment, &id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "a different deployment must observe NotFound, not cross-scope existence"
        );
    }

    // -----------------------------------------------------------------------
    // 6. Different customer get -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_with_different_customer_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(6);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes)
            .await
            .expect("initial put must succeed");

        let wrong_customer = grant(DEPLOYMENT_A, CUSTOMER_TWO, vec![id.clone()]);
        let result = store.get(&wrong_customer, &id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "a different customer must observe NotFound, not cross-tenant existence"
        );
    }

    // -----------------------------------------------------------------------
    // 7. delete_after_retention: RetentionViolation then success for Deleted
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_after_retention_requires_deleted_retention_class() {
        let store = InMemoryArtifactStore::new();
        let retained_id = artifact_id(7);
        let deletable_id = artifact_id(8);
        let retained_bytes = sample_bytes();
        let retained = memory_artifact(
            retained_id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &retained_bytes,
            RetentionClass::Standard,
        );

        store
            .put(retained, retained_bytes.clone())
            .await
            .expect("initial put must succeed");

        let retention = retention_grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            vec![retained_id.clone(), deletable_id.clone()],
        );
        let observer = grant(
            DEPLOYMENT_A,
            CUSTOMER_ONE,
            vec![retained_id.clone(), deletable_id.clone()],
        );
        let violation = store.delete_after_retention(&retention, &retained_id).await;
        assert_eq!(
            violation,
            Err(ArtifactStoreError::RetentionViolation),
            "non-Deleted retention class must reject deletion"
        );

        let still_present = store
            .get(&observer, &retained_id)
            .await
            .expect("artifact must remain after rejected delete");
        assert_eq!(still_present.bytes, retained_bytes);

        let deletable_bytes = b"expired payload pending retention deletion".to_vec();
        let mut deletable = memory_artifact(
            deletable_id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &deletable_bytes,
            RetentionClass::Deleted,
        );
        deletable.expires_at = Some(fixed_created_at());
        store
            .put(deletable, deletable_bytes)
            .await
            .expect("Deleted-class artifact put must succeed");

        store
            .delete_after_retention(&retention, &deletable_id)
            .await
            .expect("Deleted retention class with expired deadline must permit deletion");

        let gone = store.get(&observer, &deletable_id).await;
        assert_eq!(
            gone.err(),
            Some(ArtifactStoreError::NotFound),
            "deleted artifact must no longer be retrievable"
        );
    }

    // -----------------------------------------------------------------------
    // 8. Grant without can_read_content -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_without_read_permission_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(9);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes)
            .await
            .expect("initial put must succeed");

        let denied = issue_grant(
            DEPLOYMENT_A,
            ArtifactScope::Customer(CustomerId::new(CUSTOMER_ONE)),
            false,
            true,
            ArtifactAccessPurpose::Scanner,
            vec![id.clone()],
            future_expires_at(),
        )
        .expect("permission-denied scanner grant with a non-empty authorized ID set must issue");
        let result = store.get(&denied, &id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "a matching-scope grant without can_read_content must observe NotFound"
        );
    }

    // -----------------------------------------------------------------------
    // ContentReview purpose reads like any other live read capability
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_with_content_review_purpose_returns_the_stored_bytes() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(91);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes.clone())
            .await
            .expect("initial put must succeed");

        let review = issue_grant(
            DEPLOYMENT_A,
            ArtifactScope::Customer(CustomerId::new(CUSTOMER_ONE)),
            true,
            false,
            ArtifactAccessPurpose::ContentReview,
            vec![id.clone()],
            future_expires_at(),
        )
        .expect("content-review grant with a non-empty authorized ID set must issue");
        let authorized = store
            .get(&review, &id)
            .await
            .expect("a ContentReview grant must read the bound artifact");
        assert_eq!(
            authorized.bytes, bytes,
            "the read must return exactly the stored bytes"
        );

        let metadata = store
            .get_metadata(&review, &id)
            .await
            .expect("a ContentReview grant must read the bound artifact metadata");
        assert_eq!(
            metadata.size_bytes,
            bytes.len() as u64,
            "the metadata must report the declared size"
        );
    }

    #[tokio::test]
    async fn get_with_dmarc_ingestion_purpose_returns_the_stored_bytes() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(92);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes.clone())
            .await
            .expect("initial put must succeed");

        let dmarc = issue_grant(
            DEPLOYMENT_A,
            ArtifactScope::Customer(CustomerId::new(CUSTOMER_ONE)),
            true,
            false,
            ArtifactAccessPurpose::DmarcReportIngestion,
            vec![id.clone()],
            future_expires_at(),
        )
        .expect("dmarc-ingestion grant with a non-empty authorized ID set must issue");
        let authorized = store
            .get(&dmarc, &id)
            .await
            .expect("a DmarcReportIngestion grant must read the bound artifact");
        assert_eq!(
            authorized.bytes, bytes,
            "the read must return exactly the stored bytes"
        );
    }

    // -----------------------------------------------------------------------
    // 9. Grant without can_delete -> NotFound (artifact survives)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_without_delete_permission_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(10);
        let bytes = b"expired payload protected from undeleter grant".to_vec();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Deleted,
        );

        store
            .put(artifact, bytes.clone())
            .await
            .expect("Deleted-class artifact put must succeed");

        let denied = issue_grant(
            DEPLOYMENT_A,
            ArtifactScope::Customer(CustomerId::new(CUSTOMER_ONE)),
            true,
            false,
            ArtifactAccessPurpose::RetentionWorker,
            vec![id.clone()],
            future_expires_at(),
        )
        .expect("permission-denied retention grant with a non-empty authorized ID set must issue");
        let result = store.delete_after_retention(&denied, &id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::NotFound),
            "a matching-scope grant without can_delete must observe NotFound"
        );

        let full = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let still_present = store
            .get(&full, &id)
            .await
            .expect("artifact must survive a permission-denied delete");
        assert_eq!(still_present.bytes, bytes);
    }

    // -----------------------------------------------------------------------
    // 10. Delete grant for wrong customer -> NotFound (artifact survives)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_with_wrong_customer_scope_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(11);
        let bytes = b"expired payload protected from cross-tenant delete".to_vec();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Deleted,
        );

        store
            .put(artifact, bytes.clone())
            .await
            .expect("Deleted-class artifact put must succeed");

        let wrong_customer = retention_grant(DEPLOYMENT_A, CUSTOMER_TWO, vec![id.clone()]);
        let result = store.delete_after_retention(&wrong_customer, &id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::NotFound),
            "a full-permission grant for the wrong customer must observe NotFound"
        );

        let owner = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let still_present = store
            .get(&owner, &id)
            .await
            .expect("artifact must survive a wrong-customer delete attempt");
        assert_eq!(still_present.bytes, bytes);
    }

    // -----------------------------------------------------------------------
    // 11. Declared size mismatch -> SizeMismatch
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn put_rejects_declared_size_mismatch() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(12);
        let bytes = sample_bytes();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );
        artifact.size = bytes.len() as u64 + 1;

        let result = store.put(artifact, bytes).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::SizeMismatch),
            "declared size differing from bytes.len() must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // 12. Scanner-purpose delete -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_with_scanner_purpose_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(13);
        let bytes = b"expired payload protected from non-retention purpose".to_vec();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Deleted,
        );
        artifact.expires_at = Some(fixed_created_at());

        store
            .put(artifact, bytes.clone())
            .await
            .expect("Deleted-class artifact put must succeed");

        let scanner = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        assert_eq!(scanner.purpose, ArtifactAccessPurpose::Scanner);
        let result = store.delete_after_retention(&scanner, &id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::NotFound),
            "a Scanner-purpose grant must observe NotFound on delete"
        );

        let still_present = store
            .get(&scanner, &id)
            .await
            .expect("artifact must survive a scanner-purpose delete attempt");
        assert_eq!(still_present.bytes, bytes);
    }

    // -----------------------------------------------------------------------
    // 13. Future expires_at deadline -> RetentionViolation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_with_future_deadline_is_retention_violation() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(14);
        let bytes = b"payload still under unexpired retention".to_vec();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Deleted,
        );
        artifact.expires_at = Some(chrono::Utc::now() + chrono::Duration::hours(1));

        store
            .put(artifact, bytes.clone())
            .await
            .expect("Deleted-class artifact with future deadline must put");

        let retention = retention_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let result = store.delete_after_retention(&retention, &id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::RetentionViolation),
            "a future expires_at deadline must reject deletion"
        );
    }

    // -----------------------------------------------------------------------
    // 14. Deleted (tombstoned) ID cannot be inserted again
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn deleted_id_cannot_be_inserted_again() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(15);
        let bytes = b"payload deleted then reinserted".to_vec();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Deleted,
        );
        artifact.expires_at = Some(fixed_created_at());

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("initial put must succeed");

        let retention = retention_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        store
            .delete_after_retention(&retention, &id)
            .await
            .expect("expired Deleted-class artifact must be removable");

        let reinsert = store.put(artifact, bytes).await;
        assert_eq!(
            reinsert,
            Err(ArtifactStoreError::ImmutableConflict),
            "a tombstoned ID must be rejected as ImmutableConflict on re-put"
        );
    }

    // -----------------------------------------------------------------------
    // 15. Customer grants cannot reach customerless artifacts; same-deployment
    //     System grant can
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn customer_grant_cannot_get_or_delete_customerless_artifact() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(16);
        let bytes = b"system-scope payload".to_vec();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            None,
            &bytes,
            RetentionClass::Deleted,
        );
        artifact.expires_at = Some(fixed_created_at());

        store
            .put(artifact, bytes.clone())
            .await
            .expect("customerless artifact put must succeed");

        let customer = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let get_result = store.get(&customer, &id).await;
        assert_eq!(
            get_result.err(),
            Some(ArtifactStoreError::NotFound),
            "a Customer-scope grant must not get a customerless artifact"
        );

        let customer_retention = retention_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let delete_result = store.delete_after_retention(&customer_retention, &id).await;
        assert_eq!(
            delete_result,
            Err(ArtifactStoreError::NotFound),
            "a Customer-scope grant must not retention-delete a customerless artifact"
        );

        let system = system_scanner_grant(DEPLOYMENT_A, vec![id.clone()]);
        let survivor = store
            .get(&system, &id)
            .await
            .expect("customerless artifact must survive a customer-scope delete attempt");
        assert_eq!(survivor.bytes, bytes);
    }

    #[tokio::test]
    async fn system_grant_same_deployment_gets_and_retention_deletes_customerless_artifact() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(17);
        let bytes = b"system-scope payload pending retention".to_vec();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            None,
            &bytes,
            RetentionClass::Deleted,
        );
        artifact.expires_at = Some(fixed_created_at());

        store
            .put(artifact, bytes.clone())
            .await
            .expect("customerless artifact put must succeed");

        let system_scanner = system_scanner_grant(DEPLOYMENT_A, vec![id.clone()]);
        let stored = store
            .get(&system_scanner, &id)
            .await
            .expect("same-deployment System grant must get a customerless artifact");
        assert_eq!(stored.id, id);
        assert_eq!(stored.bytes, bytes);

        let system = system_grant(DEPLOYMENT_A, vec![id.clone()]);
        store
            .delete_after_retention(&system, &id)
            .await
            .expect("same-deployment System grant must retention-delete a customerless artifact");

        let gone = store.get(&system_scanner, &id).await;
        assert_eq!(
            gone.err(),
            Some(ArtifactStoreError::NotFound),
            "customerless artifact must be gone after System retention delete"
        );
    }

    // -----------------------------------------------------------------------
    // 16. Valid Scanner grant bound only to a different artifact -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_with_grant_bound_to_different_artifact_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(18);
        let other_id = artifact_id(19);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes)
            .await
            .expect("initial put must succeed");

        let other_bound = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![other_id]);
        let result = store.get(&other_bound, &id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "a grant bound only to a different artifact must observe NotFound"
        );
    }

    // -----------------------------------------------------------------------
    // 17. Expired Scanner grant bound to the artifact -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_with_expired_scanner_grant_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(20);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes)
            .await
            .expect("initial put must succeed");

        let expired = issue_grant(
            DEPLOYMENT_A,
            ArtifactScope::Customer(CustomerId::new(CUSTOMER_ONE)),
            true,
            true,
            ArtifactAccessPurpose::Scanner,
            vec![id.clone()],
            expired_expires_at(),
        )
        .expect("expired scanner grant with a non-empty authorized ID set must issue");
        let result = store.get(&expired, &id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "an expired grant must observe NotFound"
        );
    }

    // -----------------------------------------------------------------------
    // 18. RetentionWorker-purpose grant cannot read content -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_with_retention_worker_purpose_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(21);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes)
            .await
            .expect("initial put must succeed");

        let retention = retention_grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        assert_eq!(retention.purpose, ArtifactAccessPurpose::RetentionWorker);
        let result = store.get(&retention, &id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "a RetentionWorker-purpose grant must observe NotFound on get"
        );
    }

    // -----------------------------------------------------------------------
    // 19. Expired RetentionWorker grant cannot delete; artifact survives
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn expired_retention_grant_cannot_delete_but_artifact_stays_readable() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(22);
        let bytes = b"expired payload protected from an expired retention grant".to_vec();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Deleted,
        );
        artifact.expires_at = Some(fixed_created_at());

        store
            .put(artifact, bytes.clone())
            .await
            .expect("Deleted-class artifact with due retention deadline must put");

        let expired_retention = issue_grant(
            DEPLOYMENT_A,
            ArtifactScope::Customer(CustomerId::new(CUSTOMER_ONE)),
            true,
            true,
            ArtifactAccessPurpose::RetentionWorker,
            vec![id.clone()],
            expired_expires_at(),
        )
        .expect("expired retention grant with a non-empty authorized ID set must issue");
        let result = store.delete_after_retention(&expired_retention, &id).await;
        assert_eq!(
            result,
            Err(ArtifactStoreError::NotFound),
            "an expired retention grant must observe NotFound on delete"
        );

        let observer = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let still_present = store
            .get(&observer, &id)
            .await
            .expect("artifact must remain readable after an expired delete attempt");
        assert_eq!(still_present.bytes, bytes);
    }

    // -----------------------------------------------------------------------
    // 20. get_metadata returns declared size/eligible for authorized read
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_metadata_returns_declared_size_and_eligibility_for_authorized_read() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(23);
        let bytes = sample_bytes();
        let mut artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );
        // Declare the flag explicitly (not the helper default) so the test
        // proves the metadata carries the stored declared value.
        artifact.scanner_eligible = false;

        store
            .put(artifact.clone(), bytes.clone())
            .await
            .expect("put under matching scope must succeed");

        let grant = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let metadata = store
            .get_metadata(&grant, &id)
            .await
            .expect("get_metadata under matching scope must succeed");

        assert_eq!(metadata.id, artifact.id);
        assert_eq!(metadata.content_type, artifact.content_type);
        assert_eq!(metadata.hash, artifact.hash);
        assert_eq!(
            metadata.size_bytes, artifact.size,
            "size_bytes must be the declared size from the stored record"
        );
        assert_eq!(
            metadata.size_bytes,
            bytes.len() as u64,
            "declared size was validated against the bytes at put time"
        );
        assert_eq!(
            metadata.scanner_eligible, artifact.scanner_eligible,
            "scanner_eligible must be the declared flag from the stored record"
        );
        assert!(
            !metadata.scanner_eligible,
            "the explicitly declared false flag must round-trip"
        );
    }

    // -----------------------------------------------------------------------
    // 21. get_metadata with grant bound to a different artifact -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_metadata_with_grant_bound_to_different_artifact_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(24);
        let other_id = artifact_id(25);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes)
            .await
            .expect("initial put must succeed");

        let other_bound = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![other_id]);
        let result = store.get_metadata(&other_bound, &id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "a grant bound only to a different artifact must observe NotFound on get_metadata"
        );
    }

    // -----------------------------------------------------------------------
    // 22. get_metadata for wrong customer -> NotFound
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_metadata_with_different_customer_is_not_found() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(26);
        let bytes = sample_bytes();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes)
            .await
            .expect("initial put must succeed");

        let wrong_customer = grant(DEPLOYMENT_A, CUSTOMER_TWO, vec![id.clone()]);
        let result = store.get_metadata(&wrong_customer, &id).await;
        assert_eq!(
            result.err(),
            Some(ArtifactStoreError::NotFound),
            "a different customer must observe NotFound on get_metadata, not cross-tenant existence"
        );
    }

    // -----------------------------------------------------------------------
    // 23. AuthorizedArtifactMetadata API exposes no bytes (design contract)
    // -----------------------------------------------------------------------

    /// API design test: [`AuthorizedArtifactMetadata`] has exactly five
    /// public fields — `id`, `content_type`, `hash`, `size_bytes` and
    /// `scanner_eligible` — and deliberately no `bytes` field and no storage
    /// location, encryption, retention, customer/deployment or grant field,
    /// so artifact content cannot be carried through this type at all (any
    /// attempt to read a non-existent field fails to compile). This test
    /// documents that contract at the value level: for an artifact whose
    /// payload is a distinctive byte string, the returned metadata renders
    /// only the declared metadata and never the stored payload.
    #[tokio::test]
    async fn get_metadata_exposes_no_artifact_bytes() {
        let store = InMemoryArtifactStore::new();
        let id = artifact_id(27);
        let bytes = b"SECRET-PAYLOAD-THAT-MUST-NOT-BE-RETURNED".to_vec();
        let artifact = memory_artifact(
            id.clone(),
            DEPLOYMENT_A,
            Some(CUSTOMER_ONE),
            &bytes,
            RetentionClass::Standard,
        );

        store
            .put(artifact, bytes.clone())
            .await
            .expect("initial put must succeed");

        let grant = grant(DEPLOYMENT_A, CUSTOMER_ONE, vec![id.clone()]);
        let metadata = store
            .get_metadata(&grant, &id)
            .await
            .expect("authorized get_metadata must succeed");

        // `format!("{:?}", bytes)` is exactly how a `Vec<u8>` payload would
        // render if the type ever gained a bytes field; it must never appear.
        let rendered = format!("{:?}", metadata);
        let byte_debug = format!("{:?}", bytes);
        assert!(
            !rendered.contains(&byte_debug),
            "AuthorizedArtifactMetadata must never render stored artifact bytes"
        );
        assert!(
            !rendered.contains("SECRET-PAYLOAD"),
            "AuthorizedArtifactMetadata must never render stored artifact content"
        );
        // The only content-bearing accessor is the declared size.
        assert_eq!(metadata.size_bytes, bytes.len() as u64);
    }
}

//! Scanner trait definitions
//!
//! Core traits that all scanner plugins must implement.
//! Scanners are bounded, synchronous milter-path components or async
//! post-queue analysis components.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::ContentType;

use crate::types::{ScanRequest, ScanResult, ScannerCapabilities, ScannerHealth};

/// Unique scanner identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScannerId(pub String);

impl ScannerId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

/// Typed failure returned by a [`Scanner`] implementation.
///
/// Failures are explicit: a scanner must never convert an engine failure,
/// timeout or resource-limit condition into a `Clean` [`ScanResult`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// The scanner/engine could not run (down, not reachable, not initialised).
    #[error("scanner unavailable: {0}")]
    Unavailable(String),

    /// The scanner/engine ran and failed.
    #[error("scanner failed: {0}")]
    Failed(String),

    /// The scanner hit an explicit resource limit while analysing the input.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
}

/// Typed failure returned by a [`ScanContent`] implementation.
///
/// Error text must stay non-sensitive: no message bodies, attachment
/// contents, credentials, URLs, or other transport details.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanContentError {
    /// The requested read exceeds the caller-supplied byte bound.
    #[error("content limit exceeded")]
    LimitExceeded,

    /// The content source could not be read (closed, not ready, backend down).
    #[error("content unavailable")]
    Unavailable,

    /// The content failed an integrity check while being read.
    #[error("content integrity failure")]
    Integrity,
}

/// Scanner-local bounded content seam.
///
/// Implementations reject reads above `max_bytes` before yielding any bytes.
/// A successful read yields shared immutable bytes (`Arc<[u8]>`) so repeated
/// bounded reads never clone the whole artifact. Implementations may use
/// bounded temporary storage, but must never expose a URL or base64
/// transport; this is only a scanner-local data seam.
///
/// The fabric — not the provider — owns integrity verification: it acquires
/// the bytes exactly once, verifies them against the declared
/// `ScanTarget.content_hash`, and hands every scanner adapter a private
/// immutable snapshot. The provider is never read again after that
/// acquisition, so there is no provider read/verify window for TOCTOU.
#[async_trait]
pub trait ScanContent: Send + Sync {
    /// Total content length in bytes.
    fn len(&self) -> u64;

    /// Whether there is no content to read.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Content type of the underlying data.
    fn content_type(&self) -> &ContentType;

    /// Read at most `max_bytes` as shared immutable bytes, rejecting
    /// oversized reads up front.
    async fn read_all_bounded(&self, max_bytes: u64) -> Result<Arc<[u8]>, ScanContentError>;
}

/// Scanner plugin trait.
///
/// Each scanner implements this trait to integrate with the Scanner Fabric.
/// Scanners must be idempotent and bounded in time/resource usage.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Return the scanner's unique identity.
    fn id(&self) -> ScannerId;

    /// Return human-readable scanner name.
    fn name(&self) -> &str;

    /// Return scanner version.
    fn version(&self) -> &str;

    /// Return scanner capabilities (what it can scan, latency class, etc.).
    fn capabilities(&self) -> ScannerCapabilities;

    /// Perform a scan within the wall-clock deadline carried in the request,
    /// reading artifact bytes through the fabric-supplied [`ScanContent`]
    /// snapshot (acquired and hash-verified once by the fabric before any
    /// adapter was scheduled).
    ///
    /// The fabric enforces the deadline externally as well; returning an error
    /// is the explicit signal for unavailable/failed/resource-limited analysis.
    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError>;

    /// Check scanner health/readiness.
    async fn health(&self) -> ScannerHealth;

    /// Optional: prepare for shutdown (flush buffers, close connections).
    async fn shutdown(&self) {}
}

/// Scanner factory for creating scanner instances.
#[async_trait]
pub trait ScannerFactory: Send + Sync {
    /// Create a new scanner instance from configuration.
    async fn create(&self, config: &ScannerConfig) -> Result<Box<dyn Scanner>, ScannerCreateError>;
}

/// Configuration for scanner instantiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub scanner_id: ScannerId,
    pub endpoint: Option<String>,
    pub timeout_ms: u64,
    pub max_concurrent: u32,
    pub extra: serde_json::Value,
}

/// Error creating a scanner.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ScannerCreateError {
    #[error("scanner configuration invalid: {0}")]
    ConfigInvalid(String),

    #[error("scanner dependency unavailable: {0}")]
    DependencyUnavailable(String),

    #[error("scanner initialization failed: {0}")]
    InitializationFailed(String),
}

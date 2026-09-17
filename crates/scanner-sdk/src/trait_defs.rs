//! Scanner trait definitions
//!
//! Core traits that all scanner plugins must implement.
//! Scanners are bounded, synchronous milter-path components or async
//! post-queue analysis components.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::types::{ScanRequest, ScanResult, ScannerCapabilities, ScannerHealth};

/// Unique scanner identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScannerId(pub String);

impl ScannerId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
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

    /// Perform a scan. Must complete within the timeout specified in the request.
    async fn scan(&self, request: ScanRequest) -> ScanResult;

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

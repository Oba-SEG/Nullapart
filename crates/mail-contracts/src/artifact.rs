//! Artifact types for message content storage

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Artifact representing stored message content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: ArtifactId,
    pub deployment_id: crate::transaction::DeploymentId,
    pub customer_id: Option<crate::transaction::CustomerId>,
    pub content_type: ContentType,
    pub size: u64,
    pub storage_location: StorageLocation,
    pub hash: ArtifactHash,
    pub retention_class: RetentionClass,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub encrypted: bool,
    pub scanner_eligible: bool,
}

/// Artifact ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub Uuid);

impl ArtifactId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ArtifactId {
    fn default() -> Self {
        Self::new()
    }
}

/// Content type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentType(pub String);

impl ContentType {
    pub fn new(ct: &str) -> Self {
        Self(ct.to_string())
    }

    pub fn is_email(&self) -> bool {
        self.0.starts_with("message/") || self.0 == "application/x-email"
    }

    pub fn is_attachment(&self) -> bool {
        !self.is_email()
    }
}

/// Artifact hash
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactHash {
    pub algorithm: HashAlgorithm,
    pub value: String,
}

/// Hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    /// Legacy-only — kept for backward-compatibility scanning of old artifacts.
    /// Do not use for new content; prefer SHA-256 or SHA-512.
    Md5,
}

/// Storage location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLocation {
    pub backend: StorageBackend,
    pub bucket: Option<String>,
    pub key: String,
    pub region: Option<String>,
}

/// Storage backend
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    S3,
    Filesystem,
    Memory,
}

/// Retention class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RetentionClass {
    ShortTerm,
    Standard,
    LongTerm,
    Litigation,
    Deleted,
}

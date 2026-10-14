//! Scanner evidence persistence seam.
//!
//! The durable Postgres write path for scanner evidence lives in
//! [`crate::phase2_persistence`] (`PostgresPhase2Persistence`); this module
//! retains only the trait seam and a no-op implementation for unit tests
//! that exercise orchestration in isolation.

use async_trait::async_trait;

use crate::{scanner_fabric::ScannerFabricResult, scanner_pipeline::TenantScanContext};
use nullapart_mail_contracts::ArtifactId;

#[derive(Debug, thiserror::Error)]
pub enum ScannerEvidenceError {
    #[error("scanner evidence persistence is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait ScannerEvidenceRepository: Send + Sync {
    async fn persist(
        &self,
        context: &TenantScanContext,
        artifact_id: &ArtifactId,
        result: &ScannerFabricResult,
    ) -> Result<(), ScannerEvidenceError>;
}

/// Appropriate only for unit tests that exercise orchestration in isolation.
#[derive(Default)]
pub struct NoopScannerEvidenceRepository;

#[async_trait]
impl ScannerEvidenceRepository for NoopScannerEvidenceRepository {
    async fn persist(
        &self,
        _context: &TenantScanContext,
        _artifact_id: &ArtifactId,
        _result: &ScannerFabricResult,
    ) -> Result<(), ScannerEvidenceError> {
        Ok(())
    }
}

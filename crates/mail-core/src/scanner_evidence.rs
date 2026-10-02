//! Durable, tenant-scoped normalized scanner evidence.

use async_trait::async_trait;
use sqlx::PgPool;

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

#[derive(Clone)]
pub struct PostgresScannerEvidenceRepository {
    pool: PgPool,
}

impl PostgresScannerEvidenceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScannerEvidenceRepository for PostgresScannerEvidenceRepository {
    async fn persist(
        &self,
        context: &TenantScanContext,
        artifact_id: &ArtifactId,
        result: &ScannerFabricResult,
    ) -> Result<(), ScannerEvidenceError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ScannerEvidenceError::Unavailable)?;
        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&context.customer_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ScannerEvidenceError::Unavailable)?;
        for scan in &result.results {
            let profile = result
                .scanner_profiles
                .iter()
                .find(|profile| profile.scanner_id == scan.scanner_id);
            sqlx::query(
                "INSERT INTO scanner_results (tenant_message_id, transaction_id, artifact_id, deployment_id, customer_id, scanner_id, scanner_type, status, required, duration_ms, completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(context.tenant_message_id.0)
            .bind(context.transaction_id.0)
            .bind(artifact_id.0)
            .bind(&context.deployment_id.0)
            .bind(&context.customer_id.0)
            .bind(&scan.scanner_id.0)
            .bind(
                profile
                    .map(|item| format!("{:?}", item.scanner_type).to_lowercase())
                    .unwrap_or_else(|| "custom".to_string()),
            )
            .bind(format!("{:?}", scan.status).to_lowercase())
            .bind(profile.is_some_and(|item| item.required))
            .bind(i64::try_from(scan.duration_ms).unwrap_or(i64::MAX))
            .bind(scan.completed_at)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ScannerEvidenceError::Unavailable)?;
        }
        for finding in &result.findings {
            sqlx::query(
                "INSERT INTO security_findings (id, tenant_message_id, transaction_id, artifact_id, deployment_id, customer_id, scanner_type, scanner_status, severity, category, description, details, false_positive, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            )
            .bind(finding.id.0)
            .bind(context.tenant_message_id.0)
            .bind(context.transaction_id.0)
            .bind(artifact_id.0)
            .bind(&context.deployment_id.0)
            .bind(&context.customer_id.0)
            .bind(format!("{:?}", finding.scanner).to_lowercase())
            .bind(format!("{:?}", finding.scanner_status).to_lowercase())
            .bind(format!("{:?}", finding.severity).to_lowercase())
            .bind(format!("{:?}", finding.category).to_lowercase())
            .bind(&finding.description)
            .bind(&finding.details)
            .bind(finding.false_positive)
            .bind(finding.created_at)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ScannerEvidenceError::Unavailable)?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| ScannerEvidenceError::Unavailable)
    }
}

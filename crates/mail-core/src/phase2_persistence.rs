//! Atomic PostgreSQL persistence for the Phase 2 mail-security workflow.
//!
//! Artifact bytes are published to `ArtifactStore` before this boundary. This
//! module atomically commits only the PostgreSQL projection: artifact metadata,
//! scanner evidence, final tenant disposition, and (for hold/quarantine) the
//! private reinjection envelope. A database failure can therefore leave an
//! immutable filesystem orphan; it never leaves a partially committed database
//! workflow and never copies raw MIME into PostgreSQL.

use nullapart_mail_contracts::artifact::{Artifact, HashAlgorithm, RetentionClass, StorageBackend};
use nullapart_mail_contracts::finding::{
    FindingCategory, FindingSeverity, ScannerStatus, ScannerType,
};
use nullapart_mail_contracts::policy::ReasonCode;
use nullapart_mail_contracts::transaction::Disposition;
use sqlx::PgPool;
use uuid::Uuid;

use crate::scanner_fabric::ScannerFabricResult;
use crate::scanner_pipeline::TenantScanContext;

/// Stable, content-free failures for the durable Phase 2 projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Phase2PersistenceError {
    #[error("phase 2 persistence input is invalid")]
    InvalidInput,
    #[error("phase 2 persistence conflicts with existing state")]
    Conflict,
    #[error("phase 2 persistence is unavailable")]
    Unavailable,
}

/// Server-derived data committed by one Phase 2 database transaction.
pub struct Phase2PersistenceInput<'a> {
    pub context: &'a TenantScanContext,
    pub artifact: &'a Artifact,
    pub scan_result: &'a ScannerFabricResult,
    pub disposition: Disposition,
    pub reason_code: &'a ReasonCode,
    pub policy_revision_id: Uuid,
}

/// Minimal result that reveals no content or storage location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase2PersistenceOutcome {
    pub quarantine_created: bool,
}

/// PostgreSQL implementation of the Phase 2 durable projection.
#[derive(Clone)]
pub struct PostgresPhase2Persistence {
    pool: PgPool,
}

impl PostgresPhase2Persistence {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Commits all tenant-scoped Phase 2 database records in one transaction.
    pub async fn persist(
        &self,
        input: Phase2PersistenceInput<'_>,
    ) -> Result<Phase2PersistenceOutcome, Phase2PersistenceError> {
        validate_input(&input)?;

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| Phase2PersistenceError::Unavailable)?;
        // smtp_transactions and related tables carry FORCE RLS (migration
        // 034); both GUCs must be set before any join/insert/update below.
        sqlx::query(
            "SELECT set_config('app.current_deployment_id', $1, true), \
                    set_config('app.current_customer_id', $2, true)",
        )
        .bind(&input.context.deployment_id.0)
        .bind(&input.context.customer_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| Phase2PersistenceError::Unavailable)?;

        let owned_message = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM tenant_message_instances AS message \
             JOIN smtp_transactions AS transaction ON transaction.id = message.transaction_id \
             WHERE message.id = $1 AND message.transaction_id = $2 \
               AND message.customer_id = $3 AND transaction.deployment_id = $4 \
             FOR UPDATE OF message",
        )
        .bind(input.context.tenant_message_id.0)
        .bind(input.context.transaction_id.0)
        .bind(&input.context.customer_id.0)
        .bind(&input.context.deployment_id.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Phase2PersistenceError::Unavailable)?;
        if owned_message.is_none() {
            return Err(Phase2PersistenceError::Conflict);
        }

        let existing_evidence = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM scanner_results WHERE tenant_message_id = $1) \
                 OR EXISTS (SELECT 1 FROM security_findings WHERE tenant_message_id = $1)",
        )
        .bind(input.context.tenant_message_id.0)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| Phase2PersistenceError::Unavailable)?;
        if existing_evidence {
            return Err(Phase2PersistenceError::Conflict);
        }

        let size_bytes =
            i64::try_from(input.artifact.size).map_err(|_| Phase2PersistenceError::InvalidInput)?;
        let artifact_insert = sqlx::query(
            "INSERT INTO artifacts \
                (id, deployment_id, customer_id, content_type, size_bytes, content_hash, \
                 storage_backend, storage_path, retention_class, encryption_enabled, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(input.artifact.id.0)
        .bind(&input.context.deployment_id.0)
        .bind(&input.context.customer_id.0)
        .bind(&input.artifact.content_type.0)
        .bind(size_bytes)
        .bind(content_hash(input.artifact))
        .bind("filesystem")
        .bind(&input.artifact.storage_location.key)
        .bind(retention_class(input.artifact.retention_class))
        .bind(input.artifact.encrypted)
        .bind(input.artifact.created_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| Phase2PersistenceError::Unavailable)?;
        if artifact_insert.rows_affected() != 1 {
            return Err(Phase2PersistenceError::Conflict);
        }

        let transaction_update = sqlx::query(
            "UPDATE smtp_transactions SET mime_artifact_id = $1, content_hash = $2 \
             WHERE id = $3 AND deployment_id = $4",
        )
        .bind(input.artifact.id.0.to_string())
        .bind(content_hash(input.artifact))
        .bind(input.context.transaction_id.0)
        .bind(&input.context.deployment_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| Phase2PersistenceError::Unavailable)?;
        if transaction_update.rows_affected() != 1 {
            return Err(Phase2PersistenceError::Conflict);
        }

        for result in &input.scan_result.results {
            let duration_ms = i64::try_from(result.duration_ms).unwrap_or(i64::MAX);
            sqlx::query(
                "INSERT INTO scanner_results \
                    (tenant_message_id, transaction_id, artifact_id, deployment_id, customer_id, \
                     scanner_id, scanner_type, status, required, duration_ms, completed_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(input.context.tenant_message_id.0)
            .bind(input.context.transaction_id.0)
            .bind(input.artifact.id.0)
            .bind(&input.context.deployment_id.0)
            .bind(&input.context.customer_id.0)
            .bind(&result.scanner_id.0)
            .bind(scanner_type(result.scanner_type))
            .bind(scanner_status(result.status))
            .bind(result.required)
            .bind(duration_ms)
            .bind(result.completed_at)
            .execute(&mut *transaction)
            .await
            .map_err(|_| Phase2PersistenceError::Unavailable)?;
        }

        for finding in &input.scan_result.findings {
            sqlx::query(
                "INSERT INTO security_findings \
                    (id, tenant_message_id, transaction_id, artifact_id, deployment_id, customer_id, \
                     scanner_type, scanner_status, severity, category, description, details, \
                     false_positive, created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            )
            .bind(finding.id.0)
            .bind(input.context.tenant_message_id.0)
            .bind(input.context.transaction_id.0)
            .bind(input.artifact.id.0)
            .bind(&input.context.deployment_id.0)
            .bind(&input.context.customer_id.0)
            .bind(scanner_type(finding.scanner))
            .bind(scanner_status(finding.scanner_status))
            .bind(finding_severity(finding.severity))
            .bind(finding_category(finding.category))
            .bind(&finding.description)
            .bind(&finding.details)
            .bind(finding.false_positive)
            .bind(finding.created_at)
            .execute(&mut *transaction)
            .await
            .map_err(|_| Phase2PersistenceError::Unavailable)?;
        }

        let message_update = sqlx::query(
            "UPDATE tenant_message_instances \
             SET disposition = $1, policy_revision_id = $2, updated_at = now() \
             WHERE id = $3 AND customer_id = $4 AND transaction_id = $5",
        )
        .bind(disposition(input.disposition))
        .bind(input.policy_revision_id)
        .bind(input.context.tenant_message_id.0)
        .bind(&input.context.customer_id.0)
        .bind(input.context.transaction_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| Phase2PersistenceError::Unavailable)?;
        if message_update.rows_affected() != 1 {
            return Err(Phase2PersistenceError::Conflict);
        }

        let quarantine_created = matches!(
            input.disposition,
            Disposition::Hold | Disposition::Quarantine
        );
        if quarantine_created {
            let quarantine_insert = sqlx::query(
                "INSERT INTO quarantine_cases \
                    (tenant_message_id, transaction_id, deployment_id, customer_id, artifact_id, reason_code) \
                 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_message_id) DO NOTHING",
            )
            .bind(input.context.tenant_message_id.0)
            .bind(input.context.transaction_id.0)
            .bind(&input.context.deployment_id.0)
            .bind(&input.context.customer_id.0)
            .bind(input.artifact.id.0)
            .bind(&input.reason_code.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| Phase2PersistenceError::Unavailable)?;
            if quarantine_insert.rows_affected() != 1 {
                return Err(Phase2PersistenceError::Conflict);
            }

            sqlx::query(
                "INSERT INTO quarantine_reinjection_envelopes \
                    (tenant_message_id, transaction_id, deployment_id, customer_id, envelope_sender, recipients) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(input.context.tenant_message_id.0)
            .bind(input.context.transaction_id.0)
            .bind(&input.context.deployment_id.0)
            .bind(&input.context.customer_id.0)
            .bind(&input.context.envelope_sender)
            .bind(serde_json::json!(input.context.recipients))
            .execute(&mut *transaction)
            .await
            .map_err(|_| Phase2PersistenceError::Unavailable)?;
        }

        transaction
            .commit()
            .await
            .map_err(|_| Phase2PersistenceError::Unavailable)?;
        Ok(Phase2PersistenceOutcome { quarantine_created })
    }
}

fn validate_input(input: &Phase2PersistenceInput<'_>) -> Result<(), Phase2PersistenceError> {
    if input.artifact.deployment_id != input.context.deployment_id
        || input.artifact.customer_id.as_ref() != Some(&input.context.customer_id)
        || input.artifact.content_type.0.trim().is_empty()
        || input.artifact.storage_location.backend != StorageBackend::Filesystem
        || input.artifact.storage_location.bucket.is_some()
        || input.artifact.storage_location.region.is_some()
        || input.artifact.storage_location.key != format!("{}.artifact", input.artifact.id.0)
        || input.artifact.hash.algorithm != HashAlgorithm::Sha256
        || input.artifact.hash.value.len() != 64
        || input.artifact.retention_class != RetentionClass::Standard
        || input.artifact.expires_at.is_some()
        || input.context.envelope_sender.is_empty()
        || input.context.envelope_sender.len() > 320
        || input.context.recipients.is_empty()
        || input.context.recipients.len() > 500
        || input
            .context
            .recipients
            .iter()
            .any(|recipient| recipient.is_empty() || recipient.len() > 320)
        || input.reason_code.0.trim().is_empty()
        || input.reason_code.0.len() > 128
    {
        return Err(Phase2PersistenceError::InvalidInput);
    }
    Ok(())
}

fn content_hash(artifact: &Artifact) -> String {
    format!("sha256:{}", artifact.hash.value)
}

fn disposition(value: Disposition) -> &'static str {
    match value {
        Disposition::Allow => "allow",
        Disposition::Quarantine => "quarantine",
        Disposition::Reject => "reject",
        Disposition::Hold => "hold",
        Disposition::Defer => "defer",
    }
}

fn retention_class(value: RetentionClass) -> &'static str {
    match value {
        RetentionClass::ShortTerm => "short_term",
        RetentionClass::Standard => "standard",
        RetentionClass::LongTerm => "long_term",
        RetentionClass::Litigation => "litigation",
        RetentionClass::Deleted => "deleted",
    }
}

fn scanner_type(value: ScannerType) -> &'static str {
    match value {
        ScannerType::Clamav => "clamav",
        ScannerType::Rspamd => "rspamd",
        ScannerType::UrlAnalysis => "url_analysis",
        ScannerType::Attachment => "attachment",
        ScannerType::Dkim => "dkim",
        ScannerType::Spf => "spf",
        ScannerType::Dmarc => "dmarc",
        ScannerType::Arc => "arc",
        ScannerType::InlineMl => "inline_ml",
        ScannerType::DeepAi => "deep_ai",
        ScannerType::Custom => "custom",
    }
}

fn scanner_status(value: ScannerStatus) -> &'static str {
    match value {
        ScannerStatus::Clean => "clean",
        ScannerStatus::Threat => "threat",
        ScannerStatus::Suspicious => "suspicious",
        ScannerStatus::Unknown => "unknown",
        ScannerStatus::Error => "error",
        ScannerStatus::NotApplicable => "not_applicable",
    }
}

fn finding_severity(value: FindingSeverity) -> &'static str {
    match value {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    }
}

fn finding_category(value: FindingCategory) -> &'static str {
    match value {
        FindingCategory::Malware => "malware",
        FindingCategory::Phishing => "phishing",
        FindingCategory::Spam => "spam",
        FindingCategory::Spoofing => "spoofing",
        FindingCategory::BusinessEmailCompromise => "business_email_compromise",
        FindingCategory::CredentialHarvest => "credential_harvest",
        FindingCategory::MaliciousUrl => "malicious_url",
        FindingCategory::MaliciousAttachment => "malicious_attachment",
        FindingCategory::SuspiciousContent => "suspicious_content",
        FindingCategory::PolicyViolation => "policy_violation",
        FindingCategory::AuthFailure => "auth_failure",
        FindingCategory::Reputation => "reputation",
        FindingCategory::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use nullapart_mail_contracts::artifact::{
        ArtifactHash, ArtifactId, ContentType, StorageLocation,
    };
    use nullapart_mail_contracts::transaction::{
        CustomerId, DeploymentId, TenantMessageId, TraceId, TransactionId,
    };

    use super::*;

    fn input_fixture() -> (TenantScanContext, Artifact, ScannerFabricResult, ReasonCode) {
        let artifact_id = ArtifactId::new();
        let deployment_id = DeploymentId::new("LOCAL-TEST");
        let customer_id = CustomerId::new("customer-one");
        let context = TenantScanContext {
            tenant_message_id: TenantMessageId::new(),
            transaction_id: TransactionId::new(),
            deployment_id: deployment_id.clone(),
            customer_id: customer_id.clone(),
            trace_id: TraceId::new(),
            accepted_at: Utc::now(),
            envelope_sender: "sender@example.test".to_string(),
            recipients: vec!["recipient@example.test".to_string()],
        };
        let artifact = Artifact {
            id: artifact_id.clone(),
            deployment_id,
            customer_id: Some(customer_id),
            content_type: ContentType::new("message/rfc822"),
            size: 1,
            storage_location: StorageLocation {
                backend: StorageBackend::Filesystem,
                bucket: None,
                key: format!("{}.artifact", artifact_id.0),
                region: None,
            },
            hash: ArtifactHash {
                algorithm: HashAlgorithm::Sha256,
                value: "0".repeat(64),
            },
            retention_class: RetentionClass::Standard,
            created_at: Utc::now(),
            expires_at: None,
            encrypted: false,
            scanner_eligible: true,
        };
        let scan_result = ScannerFabricResult {
            results: Vec::new(),
            scanner_profiles: Vec::new(),
            findings: Vec::new(),
            failures: Vec::new(),
            requires_hold: true,
        };
        (context, artifact, scan_result, ReasonCode::hold_pending())
    }

    #[test]
    fn validation_accepts_server_derived_scoped_input() {
        let (context, artifact, scan_result, reason_code) = input_fixture();
        let input = Phase2PersistenceInput {
            context: &context,
            artifact: &artifact,
            scan_result: &scan_result,
            disposition: Disposition::Hold,
            reason_code: &reason_code,
            policy_revision_id: Uuid::new_v4(),
        };
        assert_eq!(validate_input(&input), Ok(()));
    }

    #[test]
    fn validation_rejects_scope_and_path_mismatch() {
        let (context, mut artifact, scan_result, reason_code) = input_fixture();
        artifact.storage_location.key = "../caller-selected".to_string();
        let input = Phase2PersistenceInput {
            context: &context,
            artifact: &artifact,
            scan_result: &scan_result,
            disposition: Disposition::Hold,
            reason_code: &reason_code,
            policy_revision_id: Uuid::new_v4(),
        };
        assert_eq!(
            validate_input(&input),
            Err(Phase2PersistenceError::InvalidInput)
        );
    }
}

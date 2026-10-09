//! Local Phase 5 DMARC report mailbox ingestion hook.
//!
//! This is not a broad mailbox connector. It runs inside the already
//! authenticated/durable handoff path, inspects the accepted MIME message for
//! bounded DMARC report parts, stores those parts as customer-scoped report
//! artifacts, and enqueues them for [`crate::dmarc_ingress`]. Raw report bytes
//! remain in ArtifactStore and are not exposed to the control-plane UI.

use chrono::Utc;
use mailparse::{DispositionType, ParsedMail};
use nullapart_mail_contracts::artifact::{
    Artifact, ContentType, RetentionClass, StorageBackend, StorageLocation,
};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId, TenantMessageId};
use nullapart_mail_contracts::{ArtifactHash, ArtifactId, HashAlgorithm};
use sha2::Digest;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::artifact_store::{ArtifactStoreError, FilesystemArtifactStore};
use crate::dmarc_ingress::{enqueue_dmarc_report_artifact, DmarcReportIngressError};

const MAX_REPORT_PARTS: usize = 16;
const MAX_REPORT_PART_BYTES: usize = 2 * 1024 * 1024;
const REPORT_MAILBOX_ACTOR: &str = "dmarc-report-mailbox";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmarcMailboxIngestOutcome {
    pub queued: usize,
    pub skipped_oversize: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DmarcMailboxIngestError {
    #[error("dmarc mailbox report parsing failed")]
    InvalidMime,
    #[error("dmarc mailbox artifact storage failed")]
    ArtifactUnavailable,
    #[error("dmarc mailbox durable state is unavailable")]
    PersistenceUnavailable,
}

pub async fn ingest_dmarc_report_mailbox_message(
    pool: &PgPool,
    store: &FilesystemArtifactStore,
    deployment_id: &DeploymentId,
    customer_id: &CustomerId,
    tenant_message_id: &TenantMessageId,
    raw_mime: &[u8],
) -> Result<DmarcMailboxIngestOutcome, DmarcMailboxIngestError> {
    let parsed =
        mailparse::parse_mail(raw_mime).map_err(|_| DmarcMailboxIngestError::InvalidMime)?;
    let mut candidates = Vec::new();
    collect_report_parts(&parsed, &mut candidates);
    let mut outcome = DmarcMailboxIngestOutcome {
        queued: 0,
        skipped_oversize: 0,
    };

    for (index, candidate) in candidates.into_iter().take(MAX_REPORT_PARTS).enumerate() {
        if candidate.bytes.len() > MAX_REPORT_PART_BYTES {
            outcome.skipped_oversize += 1;
            continue;
        }
        let artifact_id = deterministic_report_artifact_id(tenant_message_id, index, &candidate);
        store_report_artifact(
            pool,
            store,
            deployment_id,
            customer_id,
            &artifact_id,
            &candidate,
        )
        .await?;
        let idempotency_key = format!(
            "{REPORT_MAILBOX_ACTOR}:{}:{}:{}",
            tenant_message_id.0, index, candidate.hash
        );
        enqueue_dmarc_report_artifact(
            pool,
            deployment_id,
            customer_id,
            &artifact_id,
            &idempotency_key,
        )
        .await
        .map_err(map_enqueue_error)?;
        outcome.queued += 1;
    }
    Ok(outcome)
}

#[derive(Debug, Clone)]
struct ReportPartCandidate {
    bytes: Vec<u8>,
    content_type: ContentType,
    hash: String,
}

fn collect_report_parts(part: &ParsedMail<'_>, candidates: &mut Vec<ReportPartCandidate>) {
    if candidates.len() >= MAX_REPORT_PARTS {
        return;
    }
    if part.subparts.is_empty() && is_dmarc_report_part(part) {
        if let Ok(bytes) = part.get_body_raw() {
            let hash = hex::encode(sha2::Sha256::digest(&bytes));
            candidates.push(ReportPartCandidate {
                bytes,
                content_type: ContentType::new(&part.ctype.mimetype),
                hash,
            });
        }
        return;
    }
    for child in &part.subparts {
        collect_report_parts(child, candidates);
        if candidates.len() >= MAX_REPORT_PARTS {
            break;
        }
    }
}

fn is_dmarc_report_part(part: &ParsedMail<'_>) -> bool {
    let mimetype = part.ctype.mimetype.to_ascii_lowercase();
    if matches!(
        mimetype.as_str(),
        "application/gzip"
            | "application/x-gzip"
            | "application/zip"
            | "application/xml"
            | "text/xml"
            | "message/feedback-report"
            | "application/feedback-report"
    ) {
        return true;
    }
    let disposition = part.get_content_disposition();
    let filename = disposition
        .params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("filename").cloned())
        .map(|value| value.to_ascii_lowercase());
    let looks_like_report_attachment = disposition.disposition == DispositionType::Attachment
        && filename.as_deref().is_some_and(|name| {
            name.ends_with(".xml")
                || name.ends_with(".xml.gz")
                || name.ends_with(".gz")
                || name.ends_with(".zip")
                || name.ends_with(".arf")
        });
    looks_like_report_attachment
}

fn deterministic_report_artifact_id(
    tenant_message_id: &TenantMessageId,
    index: usize,
    candidate: &ReportPartCandidate,
) -> ArtifactId {
    ArtifactId(Uuid::new_v5(
        &tenant_message_id.0,
        format!("{REPORT_MAILBOX_ACTOR}:{index}:{}", candidate.hash).as_bytes(),
    ))
}

async fn store_report_artifact(
    pool: &PgPool,
    store: &FilesystemArtifactStore,
    deployment_id: &DeploymentId,
    customer_id: &CustomerId,
    artifact_id: &ArtifactId,
    candidate: &ReportPartCandidate,
) -> Result<(), DmarcMailboxIngestError> {
    let now = Utc::now();
    let artifact = Artifact {
        id: artifact_id.clone(),
        deployment_id: deployment_id.clone(),
        customer_id: Some(customer_id.clone()),
        content_type: candidate.content_type.clone(),
        size: candidate.bytes.len() as u64,
        storage_location: StorageLocation {
            backend: StorageBackend::Filesystem,
            bucket: None,
            key: format!("{}.artifact", artifact_id.0),
            region: None,
        },
        hash: ArtifactHash {
            algorithm: HashAlgorithm::Sha256,
            value: candidate.hash.clone(),
        },
        retention_class: RetentionClass::Standard,
        created_at: now,
        expires_at: None,
        encrypted: false,
        scanner_eligible: false,
    };
    match store.put(artifact.clone(), candidate.bytes.clone()).await {
        Ok(()) | Err(ArtifactStoreError::ImmutableConflict) => {},
        Err(_) => return Err(DmarcMailboxIngestError::ArtifactUnavailable),
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| DmarcMailboxIngestError::PersistenceUnavailable)?;
    set_customer_scope(&mut transaction, deployment_id, customer_id).await?;
    sqlx::query(
        "INSERT INTO artifacts \
            (id, deployment_id, customer_id, content_type, size_bytes, content_hash, \
             storage_backend, storage_path, retention_class, encryption_enabled, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,'filesystem',$7,'standard',false,$8) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(artifact_id.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(&artifact.content_type.0)
    .bind(artifact.size as i64)
    .bind(format!("sha256:{}", candidate.hash))
    .bind(&artifact.storage_location.key)
    .bind(artifact.created_at)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DmarcMailboxIngestError::PersistenceUnavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| DmarcMailboxIngestError::PersistenceUnavailable)?;
    Ok(())
}

async fn set_customer_scope(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &DeploymentId,
    customer_id: &CustomerId,
) -> Result<(), DmarcMailboxIngestError> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DmarcMailboxIngestError::PersistenceUnavailable)?;
    Ok(())
}

fn map_enqueue_error(error: DmarcReportIngressError) -> DmarcMailboxIngestError {
    match error {
        DmarcReportIngressError::InvalidJob => DmarcMailboxIngestError::PersistenceUnavailable,
        DmarcReportIngressError::Persistence(_) => DmarcMailboxIngestError::PersistenceUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aggregate_and_failure_report_parts_without_html() {
        let raw = b"Content-Type: multipart/mixed; boundary=x\r\n\r\n\
            --x\r\nContent-Type: text/html\r\n\r\n<html>not a report</html>\r\n\
            --x\r\nContent-Type: application/gzip\r\nContent-Disposition: attachment; filename=\"report.xml.gz\"\r\n\r\nabc\r\n\
            --x\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\n\
            --x--\r\n";
        let parsed = mailparse::parse_mail(raw).expect("mime parses");
        let mut candidates = Vec::new();
        collect_report_parts(&parsed, &mut candidates);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].content_type.0, "application/gzip");
        assert_eq!(candidates[1].content_type.0, "message/feedback-report");
    }
}

//! Phase 5 regional DMARC aggregate-report ingress worker.
//!
//! The parser/ingestor in [`crate::dmarc_aggregate`] is intentionally pure
//! enough to test directly. This worker is the durable boundary that turns a
//! stored, tenant-scoped report artifact into one parser invocation, records
//! terminal state for every claimed job, and never exposes raw report bytes to
//! the control-plane UI.

use std::time::Duration;

use chrono::Utc;
use nullapart_mail_contracts::artifact::ArtifactId;
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use nullapart_mail_contracts::FeatureId;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::artifact_store::{
    ArtifactAccessGrant, ArtifactAccessPurpose, ArtifactPermissions, ArtifactScope,
    FilesystemArtifactStore,
};
use crate::dmarc_aggregate::{
    DmarcAggregateIngestError, DmarcAggregateIngestStatus, DmarcAggregateLimits,
    DmarcAggregateSource, DmarcReportCompression, PostgresDmarcAggregateIngestor,
};
use crate::inline_ml::switch::FeatureSwitchResolver;

const WORKER_ACTOR: &str = "dmarc-aggregate-ingress-worker";
const GRANT_TTL_SECONDS: i64 = 60;
const MAX_REPORT_CLASSIFICATION_BYTES: usize = 512 * 1024;
pub const DMARC_FAILURE_REPORTS_FEATURE_ID: &str = "dmarc_failure_reports";

#[derive(Debug, Clone)]
pub struct DmarcReportIngressConfig {
    pub limits: DmarcAggregateLimits,
    pub poll_interval: Duration,
    pub max_attempts: i64,
}

impl Default for DmarcReportIngressConfig {
    fn default() -> Self {
        Self {
            limits: DmarcAggregateLimits::default(),
            poll_interval: Duration::from_secs(10),
            max_attempts: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcReportIngressRunOutcome {
    Idle,
    Inserted {
        job_id: Uuid,
        report_row_id: Uuid,
        records_inserted: usize,
    },
    Duplicate {
        job_id: Uuid,
        report_row_id: Option<Uuid>,
    },
    Quarantined {
        job_id: Uuid,
    },
    Failed {
        job_id: Uuid,
        code: &'static str,
    },
    DeadLettered {
        job_id: Uuid,
        code: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DmarcReportIngressError {
    #[error("dmarc report ingress persistence is unavailable: {0}")]
    Persistence(&'static str),
    #[error("dmarc report ingress job is invalid")]
    InvalidJob,
}

#[derive(Debug, Clone)]
struct ClaimedJob {
    id: Uuid,
    source_artifact_id: Uuid,
    source_customer_id: String,
    attempts: i64,
}

#[derive(Clone)]
pub struct DmarcReportIngressWorker {
    pool: PgPool,
    store: FilesystemArtifactStore,
    ingestor: PostgresDmarcAggregateIngestor,
    switches: FeatureSwitchResolver,
    deployment_id: DeploymentId,
    config: DmarcReportIngressConfig,
}

impl DmarcReportIngressWorker {
    pub fn new(
        pool: PgPool,
        store: FilesystemArtifactStore,
        deployment_id: DeploymentId,
        config: DmarcReportIngressConfig,
    ) -> Self {
        Self {
            ingestor: PostgresDmarcAggregateIngestor::new(pool.clone(), deployment_id.clone()),
            switches: FeatureSwitchResolver::new(pool.clone()),
            pool,
            store,
            deployment_id,
            config,
        }
    }

    pub async fn run(self) {
        loop {
            match self.run_once().await {
                Ok(DmarcReportIngressRunOutcome::Inserted {
                    job_id,
                    records_inserted,
                    ..
                }) => {
                    tracing::info!(%job_id, records_inserted, "dmarc aggregate report ingested");
                },
                Ok(DmarcReportIngressRunOutcome::Duplicate { job_id, .. }) => {
                    tracing::info!(%job_id, "duplicate dmarc aggregate report replayed");
                },
                Ok(DmarcReportIngressRunOutcome::Quarantined { job_id }) => {
                    tracing::warn!(%job_id, "dmarc aggregate report quarantined");
                },
                Ok(DmarcReportIngressRunOutcome::Failed { job_id, code }) => {
                    tracing::warn!(%job_id, failure_code = code, "dmarc report ingress attempt failed");
                },
                Ok(DmarcReportIngressRunOutcome::DeadLettered { job_id, code }) => {
                    tracing::error!(%job_id, failure_code = code, "dmarc report ingress job dead-lettered");
                },
                Err(error) => {
                    tracing::error!(error = %error, "dmarc report ingress worker failed");
                },
                _ => {},
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    pub async fn run_once(&self) -> Result<DmarcReportIngressRunOutcome, DmarcReportIngressError> {
        let Some(job) = self.claim_next_job().await? else {
            return Ok(DmarcReportIngressRunOutcome::Idle);
        };

        let artifact_id = ArtifactId(job.source_artifact_id);
        let grant = ArtifactAccessGrant::issue_server_authorized(
            self.deployment_id.clone(),
            ArtifactScope::Customer(CustomerId::new(&job.source_customer_id)),
            WORKER_ACTOR.to_string(),
            ArtifactPermissions::content_read_only(),
            ArtifactAccessPurpose::DmarcReportIngestion,
            [artifact_id.clone()],
            Utc::now() + chrono::Duration::seconds(GRANT_TTL_SECONDS),
        )
        .map_err(|_| DmarcReportIngressError::InvalidJob)?;

        let authorized = match self.store.get(&grant, &artifact_id).await {
            Ok(artifact) => artifact,
            Err(_) => {
                return self.record_failure(job, "ARTIFACT_UNAVAILABLE", None).await;
            },
        };
        if is_likely_dmarc_failure_report(&authorized.bytes) {
            let feature_enabled = self
                .switches
                .is_enabled(
                    &FeatureId::new(DMARC_FAILURE_REPORTS_FEATURE_ID),
                    &self.deployment_id,
                    &CustomerId::new(&job.source_customer_id),
                )
                .await;
            let reason_code = if feature_enabled {
                "FAILURE_REPORT_HANDLER_UNAVAILABLE"
            } else {
                "FAILURE_REPORT_FEATURE_DISABLED"
            };
            return self
                .record_failure_report_quarantine(
                    job,
                    &authorized.hash.value,
                    authorized.bytes.len() as u64,
                    reason_code,
                )
                .await;
        }
        let source = DmarcAggregateSource {
            artifact_id: Some(job.source_artifact_id),
            artifact_hash: Some(authorized.hash.value.clone()),
            compressed_size_bytes: authorized.bytes.len() as u64,
        };

        match self
            .ingestor
            .ingest_bytes(
                &authorized.bytes,
                DmarcReportCompression::Auto,
                &self.config.limits,
                source,
            )
            .await
        {
            Ok(outcome) => self.record_success(job.id, outcome).await,
            Err(DmarcAggregateIngestError::InvalidInput) => {
                self.record_failure(job, "INVALID_INPUT", None).await
            },
            Err(DmarcAggregateIngestError::Unavailable) => {
                self.record_failure(job, "INGEST_UNAVAILABLE", None).await
            },
        }
    }

    async fn claim_next_job(&self) -> Result<Option<ClaimedJob>, DmarcReportIngressError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DmarcReportIngressError::Persistence("begin claim"))?;
        set_deployment_scope(&mut transaction, &self.deployment_id).await?;
        let row = sqlx::query(
            "UPDATE dmarc_report_ingress_jobs \
             SET status = 'processing', attempts = attempts + 1, locked_at = now(), \
                 updated_at = now(), last_error_code = NULL, last_error_detail = NULL \
             WHERE id = ( \
                 SELECT id FROM dmarc_report_ingress_jobs \
                 WHERE deployment_id = $1 \
                   AND status IN ('pending', 'failed') \
                   AND attempts < $2 \
                 ORDER BY created_at, id \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT 1 \
             ) \
             RETURNING id, source_artifact_id, source_customer_id, attempts::bigint AS attempts",
        )
        .bind(&self.deployment_id.0)
        .bind(self.config.max_attempts)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| DmarcReportIngressError::Persistence("claim job"))?;
        transaction
            .commit()
            .await
            .map_err(|_| DmarcReportIngressError::Persistence("commit claim"))?;

        row.map(|row| {
            let source_customer_id = row
                .try_get::<String, _>("source_customer_id")
                .map_err(|_| DmarcReportIngressError::Persistence("job customer"))?;
            if source_customer_id.trim().is_empty() {
                return Err(DmarcReportIngressError::InvalidJob);
            }
            Ok(ClaimedJob {
                id: row
                    .try_get("id")
                    .map_err(|_| DmarcReportIngressError::Persistence("job id"))?,
                source_artifact_id: row
                    .try_get("source_artifact_id")
                    .map_err(|_| DmarcReportIngressError::Persistence("job artifact"))?,
                source_customer_id,
                attempts: row
                    .try_get("attempts")
                    .map_err(|_| DmarcReportIngressError::Persistence("job attempts"))?,
            })
        })
        .transpose()
    }

    async fn record_success(
        &self,
        job_id: Uuid,
        outcome: crate::dmarc_aggregate::DmarcAggregateIngestOutcome,
    ) -> Result<DmarcReportIngressRunOutcome, DmarcReportIngressError> {
        let (status, run_outcome) = match outcome.status {
            DmarcAggregateIngestStatus::Inserted => {
                let report_row_id = outcome
                    .report_row_id
                    .ok_or(DmarcReportIngressError::Persistence("missing report id"))?;
                (
                    "succeeded",
                    DmarcReportIngressRunOutcome::Inserted {
                        job_id,
                        report_row_id,
                        records_inserted: outcome.records_inserted,
                    },
                )
            },
            DmarcAggregateIngestStatus::Duplicate => (
                "duplicate",
                DmarcReportIngressRunOutcome::Duplicate {
                    job_id,
                    report_row_id: outcome.report_row_id,
                },
            ),
            DmarcAggregateIngestStatus::Quarantined => (
                "quarantined",
                DmarcReportIngressRunOutcome::Quarantined { job_id },
            ),
        };

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DmarcReportIngressError::Persistence("begin success"))?;
        set_deployment_scope(&mut transaction, &self.deployment_id).await?;
        sqlx::query(
            "UPDATE dmarc_report_ingress_jobs \
             SET status = $2, completed_at = now(), updated_at = now(), \
                 report_row_id = $3, records_inserted = $4, \
                 last_error_code = NULL, last_error_detail = NULL \
             WHERE id = $1 AND deployment_id = $5",
        )
        .bind(job_id)
        .bind(status)
        .bind(outcome.report_row_id)
        .bind(i64::try_from(outcome.records_inserted).unwrap_or(i64::MAX))
        .bind(&self.deployment_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DmarcReportIngressError::Persistence("update success"))?;
        transaction
            .commit()
            .await
            .map_err(|_| DmarcReportIngressError::Persistence("commit success"))?;
        Ok(run_outcome)
    }

    async fn record_failure(
        &self,
        job: ClaimedJob,
        code: &'static str,
        detail: Option<&str>,
    ) -> Result<DmarcReportIngressRunOutcome, DmarcReportIngressError> {
        let terminal = job.attempts >= self.config.max_attempts;
        let status = if terminal { "dead_lettered" } else { "failed" };
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DmarcReportIngressError::Persistence("begin failure"))?;
        set_deployment_scope(&mut transaction, &self.deployment_id).await?;
        sqlx::query(
            "UPDATE dmarc_report_ingress_jobs \
             SET status = $2, updated_at = now(), completed_at = CASE WHEN $3 THEN now() ELSE completed_at END, \
                 last_error_code = $4, last_error_detail = $5 \
             WHERE id = $1 AND deployment_id = $6",
        )
        .bind(job.id)
        .bind(status)
        .bind(terminal)
        .bind(code)
        .bind(detail.map(truncate_error_detail))
        .bind(&self.deployment_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DmarcReportIngressError::Persistence("update failure"))?;
        transaction
            .commit()
            .await
            .map_err(|_| DmarcReportIngressError::Persistence("commit failure"))?;
        if terminal {
            Ok(DmarcReportIngressRunOutcome::DeadLettered {
                job_id: job.id,
                code,
            })
        } else {
            Ok(DmarcReportIngressRunOutcome::Failed {
                job_id: job.id,
                code,
            })
        }
    }

    async fn record_failure_report_quarantine(
        &self,
        job: ClaimedJob,
        artifact_hash: &str,
        compressed_size_bytes: u64,
        reason_code: &'static str,
    ) -> Result<DmarcReportIngressRunOutcome, DmarcReportIngressError> {
        let detail = match reason_code {
            "FAILURE_REPORT_FEATURE_DISABLED" => {
                "DMARC failure report detected. Failure-report content handling is disabled for this customer."
            },
            _ => {
                "DMARC failure report detected, but the restricted failure-report handler is not available."
            },
        };
        let mut transaction =
            self.pool.begin().await.map_err(|_| {
                DmarcReportIngressError::Persistence("begin failure report quarantine")
            })?;
        set_customer_scope(
            &mut transaction,
            &self.deployment_id,
            &CustomerId::new(&job.source_customer_id),
        )
        .await?;
        sqlx::query(
            "INSERT INTO dmarc_failure_report_quarantine (\
                 deployment_id, customer_id, source_artifact_id, artifact_hash, \
                 compressed_size_bytes, reason_code, detail\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7) \
             ON CONFLICT (deployment_id, source_artifact_id, reason_code) DO NOTHING",
        )
        .bind(&self.deployment_id.0)
        .bind(&job.source_customer_id)
        .bind(job.source_artifact_id)
        .bind(artifact_hash.chars().take(128).collect::<String>())
        .bind(i64::try_from(compressed_size_bytes).unwrap_or(i64::MAX))
        .bind(reason_code)
        .bind(detail)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DmarcReportIngressError::Persistence("insert failure report quarantine"))?;
        sqlx::query(
            "UPDATE dmarc_report_ingress_jobs \
             SET status = 'quarantined', completed_at = now(), updated_at = now(), \
                 last_error_code = $2, last_error_detail = $3 \
             WHERE id = $1 AND deployment_id = $4",
        )
        .bind(job.id)
        .bind(reason_code)
        .bind(detail)
        .bind(&self.deployment_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DmarcReportIngressError::Persistence("update failure report job"))?;
        transaction.commit().await.map_err(|_| {
            DmarcReportIngressError::Persistence("commit failure report quarantine")
        })?;
        Ok(DmarcReportIngressRunOutcome::Quarantined { job_id: job.id })
    }
}

pub async fn enqueue_dmarc_report_artifact(
    pool: &PgPool,
    deployment_id: &DeploymentId,
    source_customer_id: &CustomerId,
    source_artifact_id: &ArtifactId,
    idempotency_key: &str,
) -> Result<Uuid, DmarcReportIngressError> {
    if idempotency_key.trim().is_empty() || idempotency_key.len() > 256 {
        return Err(DmarcReportIngressError::InvalidJob);
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| DmarcReportIngressError::Persistence("begin enqueue"))?;
    set_deployment_scope(&mut transaction, deployment_id).await?;
    let job_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO dmarc_report_ingress_jobs \
            (deployment_id, source_customer_id, source_artifact_id, idempotency_key) \
         VALUES ($1,$2,$3,$4) \
         ON CONFLICT (deployment_id, idempotency_key) DO UPDATE \
             SET updated_at = dmarc_report_ingress_jobs.updated_at \
         RETURNING id",
    )
    .bind(&deployment_id.0)
    .bind(&source_customer_id.0)
    .bind(source_artifact_id.0)
    .bind(idempotency_key)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| DmarcReportIngressError::Persistence("enqueue job"))?;
    transaction
        .commit()
        .await
        .map_err(|_| DmarcReportIngressError::Persistence("commit enqueue"))?;
    Ok(job_id)
}

async fn set_deployment_scope(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &DeploymentId,
) -> Result<(), DmarcReportIngressError> {
    sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
        .bind(&deployment_id.0)
        .execute(&mut **transaction)
        .await
        .map_err(|_| DmarcReportIngressError::Persistence("set deployment scope"))?;
    Ok(())
}

async fn set_customer_scope(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &DeploymentId,
    customer_id: &CustomerId,
) -> Result<(), DmarcReportIngressError> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DmarcReportIngressError::Persistence("set customer scope"))?;
    Ok(())
}

fn truncate_error_detail(value: &str) -> String {
    value.chars().take(512).collect()
}

fn is_likely_dmarc_failure_report(bytes: &[u8]) -> bool {
    let sample =
        String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_REPORT_CLASSIFICATION_BYTES)]);
    let unfolded = unfold_header_lines(&sample);
    let compact = unfolded
        .iter()
        .flat_map(|line| line.chars())
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();

    let has_feedback_report_content_type = unfolded.iter().any(|line| {
        let Some(value) = header_value(line, "content-type") else {
            return false;
        };
        value.contains("message/feedback-report")
            || (value.contains("multipart/report")
                && value.contains("report-type")
                && value.contains("feedback-report"))
    }) || compact.contains("message/feedback-report")
        || compact.contains("report-type=feedback-report");

    let has_auth_failure_feedback = unfolded.iter().any(|line| {
        let Some(value) = header_value(line, "feedback-type") else {
            return false;
        };
        value.contains("auth-failure") || value.contains("authentication-failure")
    });
    let has_dmarc_failure_signal = unfolded.iter().any(|line| {
        header_value(line, "reported-domain").is_some()
            || header_value(line, "original-mail-from").is_some()
            || header_value(line, "original-rcpt-to").is_some()
            || header_value(line, "auth-failure").is_some_and(|value| value.contains("dmarc"))
    }) || compact.contains("feedback-type:auth-failure")
        || compact.contains("feedback-type:authentication-failure")
        || compact.contains("auth-failure:dmarc")
        || compact.contains("reported-domain:");

    let looks_like_mime_report = unfolded.iter().any(|line| {
        let Some(value) = header_value(line, "content-type") else {
            return false;
        };
        value.contains("multipart/report") || value.contains("message/feedback-report")
    });

    (has_feedback_report_content_type && (has_auth_failure_feedback || has_dmarc_failure_signal))
        || (looks_like_mime_report && has_auth_failure_feedback)
        || (has_feedback_report_content_type && looks_like_mime_report)
}

fn unfold_header_lines(input: &str) -> Vec<String> {
    let normalized = input.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = Vec::new();
    for raw_line in normalized.lines() {
        if raw_line.is_empty() {
            continue;
        }
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            if let Some(previous) = lines.last_mut() {
                previous.push(' ');
                previous.push_str(raw_line.trim());
            }
            continue;
        }
        lines.push(raw_line.trim().to_ascii_lowercase());
    }
    lines
}

fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.strip_prefix(name)
        .and_then(|remaining| remaining.strip_prefix(':'))
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::is_likely_dmarc_failure_report;

    #[test]
    fn failure_report_detection_requires_feedback_auth_failure_shape() {
        let failure = b"Content-Type: multipart/report; report-type=feedback-report\r\n\
            \r\nContent-Type: message/feedback-report\r\nFeedback-Type: auth-failure\r\n\
            Reported-Domain: example.test\r\n";
        assert!(is_likely_dmarc_failure_report(failure));

        let aggregate = br#"<feedback><report_metadata><org_name>Reporter</org_name></report_metadata></feedback>"#;
        assert!(!is_likely_dmarc_failure_report(aggregate));

        let restricted_feedback_report =
            b"Content-Type: message/feedback-report\r\nFeedback-Type: abuse\r\n";
        assert!(is_likely_dmarc_failure_report(restricted_feedback_report));

        let unrelated = b"Feedback-Type: abuse\r\n";
        assert!(!is_likely_dmarc_failure_report(unrelated));
    }

    #[test]
    fn failure_report_detection_unfolds_mime_headers() {
        let folded = b"Content-Type: multipart/report;\r\n\
            \treport-type = feedback-report\r\n\
            \r\nContent-Type: message/feedback-report\r\nFeedback-Type:\r\n\
            \tauth-failure\r\nAuth-Failure: dmarc\r\n";
        assert!(is_likely_dmarc_failure_report(folded));
    }

    #[test]
    fn failure_report_detection_handles_late_feedback_part() {
        let mut report =
            b"Content-Type: multipart/report; report-type=feedback-report\r\n\r\n".to_vec();
        report.extend(std::iter::repeat_n(b'a', 96 * 1024));
        report.extend(
            b"\r\nContent-Type: message/feedback-report\r\nFeedback-Type: auth-failure\r\n".iter(),
        );
        assert!(is_likely_dmarc_failure_report(&report));
    }
}

//! Tenant notification delivery worker.
//!
//! The domain observer writes `domain_security_notifications` rows, the console
//! renders them, and the tenant controls in [`crate::notification_api`] decide
//! whether they are also mailed. This module is the part that mails them, so it
//! owns the three rules that make that safe:
//!
//! - **Fail closed on signing.** Mail leaves Nullapart from one of a tenant's own
//!   verified domains only when that domain has a provisioned DKIM signer. A
//!   tenant with no provisioned signer is skipped without a ledger write: a
//!   `suppressed` row would burn the notification's one-time idempotency key and
//!   permanently prevent delivery after the domain is provisioned later.
//! - **Never mail outside the tenant.** Recipients come from the tenant's saved
//!   settings, which the API already constrained to that tenant's verified
//!   domains, and are re-checked here for address shape only. The envelope sender
//!   is a verified domain of the same customer, which
//!   [`crate::outbound::validate_outbound_with_signing_config`] enforces again.
//! - **Report the truth.** Every attempt ends in exactly one
//!   `notification_deliveries` row whose final state is `sent`, `suppressed` or
//!   `dead_lettered`. Nothing is recorded as sent without a Postfix queue
//!   acceptance, and an ambiguous failure is resolved through the durable outbound
//!   submission ledger rather than re-sent blindly.
//!
//! The worker is a background task, not an operator action, so it writes no
//! `audit_events` rows: the delivery ledger is its audit trail.

use std::{collections::BTreeMap, time::Duration};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId, EnvelopeSender, Recipient};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::notification_stationery::{render_html, render_text, ServiceNotice};
use crate::outbound::{
    ConnectorType, DomainAuthorization, DomainValidation, DomainValidationSource,
    OutboundConnector, OutboundIntakeRequest, OutboundSigningConfig, ProvisionedDkimSigner,
};
use crate::outbound_submission::{
    authorize_outbound_submission, submit_authorized_outbound, PostgresOutboundSubmissionLedger,
    PrivateOutboundSmtpConfig,
};

const DEFAULT_POLL_INTERVAL_SECS: u64 = 300;
const DEFAULT_SMTP_TIMEOUT_SECS: u64 = 30;
const DEFAULT_SMTP_ENDPOINT: &str = "postfix:10027";
const DEFAULT_HELO_IDENTITY: &str = "mail.nullapart.com";
const DEFAULT_SENDER_LOCAL_PART: &str = "notifications";
const DEFAULT_CONNECTOR_IP: &str = "127.0.0.1";
const DEFAULT_MAX_ATTEMPTS: i32 = 3;
const DEFAULT_BATCH_LIMIT: i64 = 20;
const MAX_REASON_LENGTH: usize = 512;
const NOTIFICATION_CATEGORY: &str = "Domain security";
const REASON_PRIOR_NOTICE: &str = "digest_window";
const REASON_COALESCED: &str = "coalesced_into_digest";
const REASON_CONTENT_CHANGED: &str = "content_changed_before_retry";
const SEVERITY_FLOORS: [&str; 3] = ["info", "warning", "critical"];

/// How notices are mailed and how often the worker polls. DKIM provisioning is
/// part of this configuration because signing availability, not the sender
/// domain alone, decides whether a tenant can be mailed at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationDeliveryConfig {
    pub poll_interval: Duration,
    pub smtp_endpoint: String,
    pub smtp_timeout: Duration,
    pub helo_identity: String,
    pub node_id: String,
    pub connector_ip: String,
    pub sender_local_part: String,
    /// Trusted provisioning: which sending domains have a real key-backed DKIM
    /// signer on the private outbound path. The private key never enters Mail
    /// Core, so this is metadata only and its absence fails closed.
    pub dkim_identities: Vec<ProvisionedDkimSigner>,
    pub max_attempts: i32,
    pub batch_limit: i64,
}

impl NotificationDeliveryConfig {
    /// Read worker configuration from the environment. The DKIM identity list is
    /// mandatory: a deployment that enables the worker without naming any
    /// provisioned signer has configured a mailer that can only ever skip, which
    /// is a startup error rather than a silently inert worker.
    pub fn from_env(node_id: &str) -> Result<Self, NotificationDeliveryError> {
        let raw_identities =
            std::env::var("NULLAPART_OUTBOUND_DKIM_IDENTITIES").unwrap_or_default();
        let dkim_identities = parse_dkim_identities(&raw_identities).ok_or_else(|| {
            tracing::error!(
                "NULLAPART_OUTBOUND_DKIM_IDENTITIES must list domain:selector pairs for \
                 every domain allowed to send service notices"
            );
            NotificationDeliveryError::Configuration
        })?;
        Ok(Self {
            poll_interval: Duration::from_secs(env_u64(
                "NULLAPART_NOTIFICATION_DELIVERY_INTERVAL_SECS",
                DEFAULT_POLL_INTERVAL_SECS,
            )),
            smtp_endpoint: std::env::var("NULLAPART_PRIVATE_OUTBOUND_ENDPOINT")
                .unwrap_or_else(|_| DEFAULT_SMTP_ENDPOINT.to_string()),
            smtp_timeout: Duration::from_secs(env_u64(
                "NULLAPART_PRIVATE_OUTBOUND_TIMEOUT_SECS",
                DEFAULT_SMTP_TIMEOUT_SECS,
            )),
            helo_identity: std::env::var("NULLAPART_OUTBOUND_HELO_IDENTITY")
                .unwrap_or_else(|_| DEFAULT_HELO_IDENTITY.to_string()),
            node_id: node_id.to_string(),
            connector_ip: std::env::var("NULLAPART_MAILCORE_SOURCE_ADDRESS")
                .unwrap_or_else(|_| DEFAULT_CONNECTOR_IP.to_string()),
            sender_local_part: std::env::var("NULLAPART_NOTIFICATION_SENDER_LOCAL_PART")
                .unwrap_or_else(|_| DEFAULT_SENDER_LOCAL_PART.to_string()),
            dkim_identities,
            max_attempts: env_i32(
                "NULLAPART_NOTIFICATION_DELIVERY_MAX_ATTEMPTS",
                DEFAULT_MAX_ATTEMPTS,
            ),
            batch_limit: env_i64(
                "NULLAPART_NOTIFICATION_DELIVERY_BATCH_LIMIT",
                DEFAULT_BATCH_LIMIT,
            ),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NotificationDeliveryError {
    #[error("notification delivery persistence is unavailable")]
    Persistence,
    #[error("notification delivery configuration is invalid")]
    Configuration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotificationDeliveryOutcome {
    pub tenants_examined: usize,
    pub tenants_skipped: usize,
    /// Notices handed to the private outbound path this poll, one per
    /// notification type and domain after coalescing.
    pub notices_attempted: usize,
    /// Findings written to the ledger as `suppressed` without a submission.
    pub findings_suppressed: usize,
    pub messages_sent: usize,
    pub messages_dead_lettered: usize,
}

/// One open finding eligible for mailing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    notification_id: Uuid,
    notification_type: String,
    severity: String,
    title: String,
    detail: String,
    domain: String,
    observed_at: DateTime<Utc>,
}

impl Finding {
    fn group_key(&self) -> (String, String) {
        (self.notification_type.clone(), self.domain.clone())
    }

    fn idempotency_key(&self) -> String {
        format!("notification:{}", self.notification_id)
    }
}

#[derive(Clone)]
pub struct NotificationDeliveryWorker {
    pool: PgPool,
    deployment_id: DeploymentId,
    smtp: PrivateOutboundSmtpConfig,
    node_id: String,
    connector_ip: String,
    helo_identity: String,
    sender_local_part: String,
    dkim_by_domain: BTreeMap<String, ProvisionedDkimSigner>,
    max_attempts: i32,
    batch_limit: i64,
    poll_interval: Duration,
}

impl NotificationDeliveryWorker {
    pub fn new(
        pool: PgPool,
        deployment_id: DeploymentId,
        config: NotificationDeliveryConfig,
    ) -> Result<Self, NotificationDeliveryError> {
        let smtp = PrivateOutboundSmtpConfig::new(
            config.smtp_endpoint.clone(),
            config.smtp_timeout,
            config.helo_identity.clone(),
        )
        .map_err(|_| NotificationDeliveryError::Configuration)?;
        if config.poll_interval.is_zero()
            || config.max_attempts < 1
            || config.batch_limit < 1
            || !is_local_part(&config.sender_local_part)
            || config.connector_ip.parse::<std::net::IpAddr>().is_err()
        {
            return Err(NotificationDeliveryError::Configuration);
        }
        let dkim_by_domain = config
            .dkim_identities
            .iter()
            .cloned()
            .map(|signer| (signer.domain.trim().to_lowercase(), signer))
            .collect::<BTreeMap<_, _>>();
        if dkim_by_domain.is_empty() {
            return Err(NotificationDeliveryError::Configuration);
        }
        Ok(Self {
            pool,
            deployment_id,
            smtp,
            node_id: config.node_id,
            connector_ip: config.connector_ip,
            helo_identity: config.helo_identity,
            sender_local_part: config.sender_local_part,
            dkim_by_domain,
            max_attempts: config.max_attempts,
            batch_limit: config.batch_limit,
            poll_interval: config.poll_interval,
        })
    }

    pub async fn run(self) {
        loop {
            match self.run_once().await {
                Ok(outcome) => tracing::info!(
                    tenants_examined = outcome.tenants_examined,
                    tenants_skipped = outcome.tenants_skipped,
                    notices_attempted = outcome.notices_attempted,
                    findings_suppressed = outcome.findings_suppressed,
                    messages_sent = outcome.messages_sent,
                    messages_dead_lettered = outcome.messages_dead_lettered,
                    "notification delivery worker completed"
                ),
                Err(error) => {
                    tracing::error!(error = %error, "notification delivery worker failed");
                },
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    pub async fn run_once(&self) -> Result<NotificationDeliveryOutcome, NotificationDeliveryError> {
        let customers = self.load_active_customers().await?;
        let mut outcome = NotificationDeliveryOutcome::default();
        for customer in customers {
            outcome.tenants_examined += 1;
            let tenant = CustomerId::new(&customer);
            match self.deliver_for_tenant(&tenant).await? {
                TenantRun::Skipped => outcome.tenants_skipped += 1,
                TenantRun::Work {
                    attempted,
                    suppressed,
                    sent,
                    dead_lettered,
                } => {
                    outcome.notices_attempted += attempted;
                    outcome.findings_suppressed += suppressed;
                    outcome.messages_sent += sent;
                    outcome.messages_dead_lettered += dead_lettered;
                },
            }
        }
        Ok(outcome)
    }

    /// Bootstrap read over `customers`, which carries the deployment-scoped RLS
    /// policy from migration 034. Like the domain observer, this must set the
    /// deployment GUC in its own transaction, or a non-`BYPASSRLS` role sees
    /// nothing.
    async fn load_active_customers(&self) -> Result<Vec<String>, NotificationDeliveryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)?;
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(&self.deployment_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)?;
        let rows = sqlx::query(
            "SELECT id AS customer_id FROM customers \
             WHERE deployment_id = $1 AND lifecycle = 'active' \
             ORDER BY id",
        )
        .bind(&self.deployment_id.0)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| NotificationDeliveryError::Persistence)?;
        transaction
            .commit()
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)?;
        rows.into_iter()
            .map(|row| {
                row.try_get("customer_id")
                    .map_err(|_| NotificationDeliveryError::Persistence)
            })
            .collect()
    }

    async fn deliver_for_tenant(
        &self,
        customer_id: &CustomerId,
    ) -> Result<TenantRun, NotificationDeliveryError> {
        let Some(prep) = self.prepare_tenant(customer_id).await? else {
            return Ok(TenantRun::Skipped);
        };

        let mut attempts = Vec::new();
        let mut suppressed = 0usize;
        for group in &prep.groups {
            if group.suppressed_by_prior_notice {
                for finding in &group.findings {
                    let sha256 = compose_notice_sha256(finding, &prep.sender, &prep.recipients);
                    let written = self
                        .claim(
                            customer_id,
                            finding,
                            "suppressed",
                            Some(REASON_PRIOR_NOTICE),
                            0,
                            &sha256,
                        )
                        .await?
                        .is_some();
                    suppressed += usize::from(written);
                }
                continue;
            }
            let Some((representative, siblings)) = group.findings.split_first() else {
                continue;
            };
            let sha256 = compose_notice_sha256(representative, &prep.sender, &prep.recipients);
            let Some(claim) = self
                .claim(
                    customer_id,
                    representative,
                    "queued",
                    None,
                    prep.recipients.len(),
                    &sha256,
                )
                .await?
            else {
                continue;
            };
            if claim.content_sha256 != sha256 {
                // Retrying would mail different bytes than the attempt that may
                // already have reached Postfix, so this stops as a dead letter
                // rather than risk a duplicate or a mismatched alert.
                self.finalize(
                    customer_id,
                    claim.delivery_id,
                    "dead_lettered",
                    Some(REASON_CONTENT_CHANGED),
                    None,
                )
                .await?;
                suppressed += 1;
                continue;
            }
            for sibling in siblings {
                let sha256 = compose_notice_sha256(sibling, &prep.sender, &prep.recipients);
                let written = self
                    .claim(
                        customer_id,
                        sibling,
                        "suppressed",
                        Some(REASON_COALESCED),
                        0,
                        &sha256,
                    )
                    .await?
                    .is_some();
                suppressed += usize::from(written);
            }
            attempts.push(DeliveryAttempt {
                delivery_id: claim.delivery_id,
                finding: representative.clone(),
                prior_attempts: claim.attempts,
            });
        }

        let mut sent = 0usize;
        let mut dead_lettered = 0usize;
        for attempt in &attempts {
            match self.send(&prep, customer_id, &attempt.finding).await {
                Ok(transaction_id) => {
                    self.finalize(
                        customer_id,
                        attempt.delivery_id,
                        "sent",
                        None,
                        Some(&transaction_id),
                    )
                    .await?;
                    sent += 1;
                },
                Err(failure) => {
                    let tried = attempt.prior_attempts + 1;
                    let exhausted = !failure.retryable || tried >= self.max_attempts;
                    let status = if exhausted {
                        dead_lettered += 1;
                        "dead_lettered"
                    } else {
                        "queued"
                    };
                    self.finalize(
                        customer_id,
                        attempt.delivery_id,
                        status,
                        Some(&failure.reason),
                        None,
                    )
                    .await?;
                },
            }
        }
        Ok(TenantRun::Work {
            attempted: attempts.len(),
            suppressed,
            sent,
            dead_lettered,
        })
    }

    /// Resolve the tenant's settings, sender, recipients and the notices due this
    /// poll. `None` means there is nothing this tenant can be mailed about, which
    /// is the normal case rather than an error.
    async fn prepare_tenant(
        &self,
        customer_id: &CustomerId,
    ) -> Result<Option<TenantPreparation>, NotificationDeliveryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)?;
        set_scope(&mut transaction, &self.deployment_id.0, &customer_id.0).await?;

        let settings = sqlx::query(
            "SELECT enabled, severity_floor, recipient_emails, digest_window_minutes \
             FROM tenant_notification_settings \
             WHERE deployment_id = $1 AND customer_id = $2",
        )
        .bind(&self.deployment_id.0)
        .bind(&customer_id.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| NotificationDeliveryError::Persistence)?;
        // With no saved row the platform defaults apply, and the default
        // recipient list is empty, so nothing is mailed until the tenant opts in.
        let Some(row) = settings else {
            return Ok(None);
        };
        let enabled = row.try_get::<bool, _>("enabled").persist()?;
        let severity_floor = row.try_get::<String, _>("severity_floor").persist()?;
        let configured_recipients = row
            .try_get::<Vec<String>, _>("recipient_emails")
            .persist()?;
        let digest_window_minutes = row.try_get::<i32, _>("digest_window_minutes").persist()?;
        if !enabled {
            return Ok(None);
        }

        let recipients = configured_recipients
            .iter()
            .map(|address| address.trim().to_lowercase())
            .filter(|address| is_mailable_address(address))
            .collect::<Vec<_>>();
        if recipients.is_empty() {
            tracing::warn!(
                customer_id = %customer_id.0,
                "skipping notification delivery: the tenant has no usable recipient"
            );
            return Ok(None);
        }
        let verified_domains = sqlx::query_scalar::<_, String>(
            "SELECT lower(domain) FROM domains \
             WHERE customer_id = $1 AND verification_status = 'verified' \
             ORDER BY lower(domain)",
        )
        .bind(&customer_id.0)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| NotificationDeliveryError::Persistence)?;
        let Some((sender_domain, signer)) =
            pick_signed_sender(&verified_domains, &self.dkim_by_domain)
        else {
            tracing::warn!(
                customer_id = %customer_id.0,
                "skipping notification delivery: no verified domain has a provisioned DKIM signer"
            );
            return Ok(None);
        };
        let sender = format!("{}@{}", self.sender_local_part, sender_domain);

        let rows = sqlx::query(
            "SELECT n.id AS notification_id, n.notification_type, n.severity, n.title, n.detail, \
                    n.created_at, COALESCE(lower(d.domain), '') AS domain \
             FROM domain_security_notifications n \
             LEFT JOIN domains d ON d.id = n.domain_id \
             WHERE n.deployment_id = $1 AND n.customer_id = $2 \
               AND n.status = 'open' AND n.severity = ANY($3) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM notification_deliveries l \
                   WHERE l.notification_id = n.id \
                     AND NOT (l.status = 'queued' AND l.attempts < $4) \
               ) \
             ORDER BY n.notification_type, COALESCE(lower(d.domain), ''), n.created_at, n.id \
             LIMIT $5 \
             FOR UPDATE OF n SKIP LOCKED",
        )
        .bind(&self.deployment_id.0)
        .bind(&customer_id.0)
        .bind(severity_reach(&severity_floor))
        .bind(self.max_attempts)
        .bind(self.batch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| NotificationDeliveryError::Persistence)?;

        let mut findings = Vec::with_capacity(rows.len());
        for row in rows {
            findings.push(Finding {
                notification_id: row.try_get("notification_id").persist()?,
                notification_type: row.try_get("notification_type").persist()?,
                severity: row.try_get("severity").persist()?,
                title: row.try_get("title").persist()?,
                detail: row.try_get("detail").persist()?,
                domain: row.try_get("domain").persist()?,
                observed_at: row.try_get("created_at").persist()?,
            });
        }
        if findings.is_empty() {
            return Ok(None);
        }
        let mut groups: Vec<NoticeGroup> = Vec::new();
        let mut index: BTreeMap<(String, String), usize> = BTreeMap::new();
        for finding in findings {
            let key = finding.group_key();
            match index.get(&key) {
                Some(position) => groups[*position].findings.push(finding),
                None => {
                    index.insert(key, groups.len());
                    groups.push(NoticeGroup {
                        findings: vec![finding],
                        suppressed_by_prior_notice: false,
                    });
                },
            }
        }
        if digest_window_minutes > 0 {
            for group in &mut groups {
                let (notification_type, domain) = group.findings[0].group_key();
                let prior = sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) \
                     FROM notification_deliveries l \
                     JOIN domain_security_notifications p ON p.id = l.notification_id \
                     LEFT JOIN domains pd ON pd.id = p.domain_id \
                     WHERE l.deployment_id = $1 AND l.customer_id = $2 AND l.status = 'sent' \
                       AND p.notification_type = $3 \
                       AND COALESCE(lower(pd.domain), '') = $4 \
                       AND l.updated_at > now() - make_interval(mins => $5)",
                )
                .bind(&self.deployment_id.0)
                .bind(&customer_id.0)
                .bind(notification_type)
                .bind(domain)
                .bind(digest_window_minutes)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| NotificationDeliveryError::Persistence)?;
                group.suppressed_by_prior_notice = prior > 0;
            }
        }

        let allowed_domains = verified_domains
            .into_iter()
            .map(|domain| DomainValidation {
                domain,
                customer_id: customer_id.clone(),
                validated: true,
                validation_source: DomainValidationSource::DnsTxt,
                validated_at: Utc::now(),
            })
            .collect();
        transaction
            .commit()
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)?;
        Ok(Some(TenantPreparation {
            sender,
            recipients,
            signer,
            groups,
            allowed_domains,
        }))
    }

    /// Claim one delivery row in its own transaction, committed before the SMTP
    /// side effect so a crash cannot lose the fact that this notification was
    /// already worked on. Returns `None` when another claim already holds the key
    /// terminally, or when a queued claim has exhausted its attempts.
    async fn claim(
        &self,
        customer_id: &CustomerId,
        finding: &Finding,
        status: &str,
        reason: Option<&str>,
        recipient_count: usize,
        content_sha256: &str,
    ) -> Result<Option<ClaimedDelivery>, NotificationDeliveryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)?;
        set_scope(&mut transaction, &self.deployment_id.0, &customer_id.0).await?;
        let row = sqlx::query(
            "INSERT INTO notification_deliveries AS l \
                 (deployment_id, customer_id, notification_id, idempotency_key, status, \
                  recipient_count, reason, content_sha256) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (idempotency_key) DO UPDATE \
                 SET recipient_count = EXCLUDED.recipient_count, \
                     updated_at = now() \
                 WHERE l.status = 'queued' AND l.attempts < $9 \
             RETURNING l.id AS delivery_id, l.attempts, l.content_sha256",
        )
        .bind(&self.deployment_id.0)
        .bind(&customer_id.0)
        .bind(finding.notification_id)
        .bind(finding.idempotency_key())
        .bind(status)
        .bind(i64::try_from(recipient_count).unwrap_or(i64::MAX))
        .bind(reason.map(truncate_reason))
        .bind(content_sha256)
        .bind(self.max_attempts)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| NotificationDeliveryError::Persistence)?;
        transaction
            .commit()
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(ClaimedDelivery {
            delivery_id: row.try_get("delivery_id").persist()?,
            attempts: row.try_get("attempts").persist()?,
            content_sha256: row.try_get("content_sha256").persist()?,
        }))
    }

    async fn finalize(
        &self,
        customer_id: &CustomerId,
        delivery_id: Uuid,
        status: &str,
        reason: Option<&str>,
        outbound_transaction_id: Option<&str>,
    ) -> Result<(), NotificationDeliveryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)?;
        set_scope(&mut transaction, &self.deployment_id.0, &customer_id.0).await?;
        sqlx::query(
            "UPDATE notification_deliveries \
             SET status = $3, attempts = attempts + 1, reason = $4, \
                 outbound_transaction_id = $5, updated_at = now() \
             WHERE id = $1 AND customer_id = $2",
        )
        .bind(delivery_id)
        .bind(&customer_id.0)
        .bind(status)
        .bind(reason.map(truncate_reason))
        .bind(outbound_transaction_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| NotificationDeliveryError::Persistence)?;
        transaction
            .commit()
            .await
            .map_err(|_| NotificationDeliveryError::Persistence)
    }

    /// Compose, authorize and submit one notice.
    ///
    /// The failure reason is ledger-safe: it never contains a recipient address,
    /// notification text, or message content.
    async fn send(
        &self,
        prep: &TenantPreparation,
        customer_id: &CustomerId,
        finding: &Finding,
    ) -> Result<String, SendFailure> {
        let raw_mime = compose_notice_mime(finding, &prep.sender, &prep.recipients);
        let request = OutboundIntakeRequest {
            connector: OutboundConnector {
                connector_id: "notification-delivery".to_string(),
                customer_id: customer_id.clone(),
                deployment_id: self.deployment_id.clone(),
                ip_address: self.connector_ip.clone(),
                authenticated_as: Some(self.node_id.clone()),
                connector_type: ConnectorType::InternalApi,
            },
            envelope_sender: EnvelopeSender::new(&prep.sender),
            recipients: prep
                .recipients
                .iter()
                .map(|address| Recipient {
                    address: address.clone(),
                    orcpt: None,
                    notify: None,
                })
                .collect(),
            message_id: Some(format!(
                "<{}@{}>",
                finding.notification_id,
                domain_of(&prep.sender)
            )),
            content_hash: hex::encode(Sha256::digest(&raw_mime)),
        };
        let signing = OutboundSigningConfig {
            dkim: Some(prep.signer.clone()),
            helo_identity: Some(self.helo_identity.clone()),
        };
        let submission = authorize_outbound_submission(
            &request,
            &prep.allowed_domains,
            &DomainAuthorization::Internal,
            &signing,
            raw_mime,
        )
        .map_err(|error| SendFailure {
            reason: format!("not submitted: {error}"),
            retryable: false,
        })?;
        let ledger = PostgresOutboundSubmissionLedger::new(
            self.pool.clone(),
            self.deployment_id.clone(),
            customer_id.clone(),
        );
        submit_authorized_outbound(&self.smtp, &ledger, submission)
            .await
            .map(|receipt| receipt.transaction_id)
            .map_err(|error| SendFailure {
                reason: format!("delivery state unresolved: {error}"),
                retryable: true,
            })
    }
}

enum TenantRun {
    /// Nothing to mail: no saved settings, delivery disabled, no usable
    /// recipient, no verified domain with a provisioned signer, or no eligible
    /// open finding.
    Skipped,
    Work {
        attempted: usize,
        suppressed: usize,
        sent: usize,
        dead_lettered: usize,
    },
}

struct TenantPreparation {
    sender: String,
    recipients: Vec<String>,
    signer: ProvisionedDkimSigner,
    groups: Vec<NoticeGroup>,
    allowed_domains: Vec<DomainValidation>,
}

struct NoticeGroup {
    findings: Vec<Finding>,
    suppressed_by_prior_notice: bool,
}

struct ClaimedDelivery {
    delivery_id: Uuid,
    attempts: i32,
    content_sha256: String,
}

struct DeliveryAttempt {
    delivery_id: Uuid,
    finding: Finding,
    prior_attempts: i32,
}

/// A submission that failed. `retryable` is true only when the durable outbound
/// ledger can resolve the next attempt: a failure before or during submission
/// leaves a claim that a retry answers with `AlreadySubmitted` rather than a
/// second message, so the retry can never duplicate customer mail.
struct SendFailure {
    reason: String,
    retryable: bool,
}

async fn set_scope(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<(), NotificationDeliveryError> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| NotificationDeliveryError::Persistence)?;
    Ok(())
}

trait Persist<T> {
    fn persist(self) -> Result<T, NotificationDeliveryError>;
}

impl<T> Persist<T> for Result<T, sqlx::Error> {
    fn persist(self) -> Result<T, NotificationDeliveryError> {
        self.map_err(|_| NotificationDeliveryError::Persistence)
    }
}

/// Pick the domain a notice is mailed from: the tenant's lowest-sorted verified
/// domain that also has a provisioned signer. A tenant whose verified domains are
/// all unprovisioned gets `None`, which is a skip rather than an unsigned send.
fn pick_signed_sender(
    verified_domains: &[String],
    dkim_by_domain: &BTreeMap<String, ProvisionedDkimSigner>,
) -> Option<(String, ProvisionedDkimSigner)> {
    verified_domains.iter().find_map(|domain| {
        dkim_by_domain
            .get(domain)
            .cloned()
            .map(|signer| (domain.clone(), signer))
    })
}

/// Severities at or above the tenant's floor. An unrecognized floor selects
/// everything rather than nothing, so schema drift cannot silence alerts.
fn severity_reach(floor: &str) -> &'static [&'static str] {
    match SEVERITY_FLOORS
        .iter()
        .position(|candidate| *candidate == floor)
    {
        Some(0) | None => &SEVERITY_FLOORS,
        Some(1) => &SEVERITY_FLOORS[1..],
        _ => &SEVERITY_FLOORS[2..],
    }
}

/// Parse a `domain:selector[,domain:selector...]` provisioning list. A malformed
/// entry rejects the whole list instead of being dropped, because a silently
/// dropped domain changes which tenants can be mailed.
fn parse_dkim_identities(raw: &str) -> Option<Vec<ProvisionedDkimSigner>> {
    let mut signers = Vec::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (domain, selector) = entry.split_once(':')?;
        let domain = domain.trim().to_lowercase();
        let selector = selector.trim().to_lowercase();
        if !domain.contains('.')
            || domain.contains(['@', ' ', '/'])
            || selector.is_empty()
            || selector.contains(['@', ':', ' ', '/'])
        {
            return None;
        }
        signers.push(ProvisionedDkimSigner { domain, selector });
    }
    (!signers.is_empty()).then_some(signers)
}

fn is_local_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn is_mailable_address(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn domain_of(address: &str) -> &str {
    address.rsplit('@').next().unwrap_or("")
}

fn truncate_reason(reason: &str) -> String {
    let mut value = reason.to_string();
    if value.len() > MAX_REASON_LENGTH {
        value.truncate(MAX_REASON_LENGTH);
    }
    value
}

/// Compose the RFC 2046 `multipart/alternative` notice for one finding.
///
/// The output is a pure function of the finding, the sender and the recipient
/// list: `Date` is the finding's observation time rather than the current clock,
/// and `Message-ID` comes from the notification identifier, so a retry after a
/// transient submission failure reproduces byte-identical mail. That is what
/// lets the durable outbound submission ledger deduplicate a retry instead of
/// sending a tenant the same alert twice.
fn compose_notice_mime(finding: &Finding, sender: &str, recipients: &[String]) -> Vec<u8> {
    let reference = finding.notification_id.to_string();
    let preview = format!("{} ({})", finding.severity, finding.notification_type);
    let notice = ServiceNotice {
        category: NOTIFICATION_CATEGORY,
        title: finding.title.as_str(),
        preview: &preview,
        summary: finding.detail.as_str(),
        reference: Some(&reference),
    };
    let subject = match finding.severity.as_str() {
        "critical" => format!("Critical notice: {}", finding.title),
        _ => format!("Notice: {}", finding.title),
    };
    let boundary = format!("nullapart-{}", finding.notification_id);

    let mut mime = String::new();
    mime.push_str(&format!(
        "From: Nullapart Service Notices <{sender}>\r\n\
         To: {}\r\n\
         Subject: {}\r\n\
         Date: {}\r\n\
         Message-ID: <{}@{}>\r\n\
         MIME-Version: 1.0\r\n\
         Auto-Submitted: auto-generated\r\n\
         X-Nullapart-Notice: domain-security\r\n\
         Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n",
        recipients.join(", "),
        encode_word(&subject),
        finding.observed_at.to_rfc2822(),
        finding.notification_id,
        domain_of(sender),
    ));
    for (media_type, body) in [
        ("text/plain", render_text(&notice)),
        ("text/html", render_html(&notice)),
    ] {
        mime.push_str(&format!("--{boundary}\r\n"));
        mime.push_str(&format!(
            "Content-Type: {media_type}; charset=\"utf-8\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n"
        ));
        mime.push_str(&base64_body(&body));
        mime.push_str("\r\n");
    }
    mime.push_str(&format!("--{boundary}--\r\n"));
    mime.into_bytes()
}

fn compose_notice_sha256(finding: &Finding, sender: &str, recipients: &[String]) -> String {
    hex::encode(Sha256::digest(compose_notice_mime(
        finding, sender, recipients,
    )))
}

fn encode_word(value: &str) -> String {
    format!("=?UTF-8?B?{}?=", BASE64.encode(value.as_bytes()))
}

fn base64_body(value: &str) -> String {
    let encoded = BASE64.encode(value.as_bytes());
    let mut lines = String::with_capacity(encoded.len() + encoded.len() / 38);
    for chunk in encoded.as_bytes().chunks(76) {
        lines.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        lines.push_str("\r\n");
    }
    lines
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_i32(key: &str, default: i32) -> i32 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<i32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_i64(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailparse::MailHeaderMap;

    fn finding() -> Finding {
        Finding {
            notification_id: Uuid::parse_str("3f2504e0-4f89-41d3-9a0c-0305e82c3301").expect("uuid"),
            notification_type: "dmarc_failure_spike".to_string(),
            severity: "warning".to_string(),
            title: "DMARC failures rose for example.test".to_string(),
            detail: "Three sources failed alignment in the last hour.".to_string(),
            domain: "example.test".to_string(),
            observed_at: DateTime::parse_from_rfc3339("2026-10-19T08:30:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
        }
    }

    fn config() -> NotificationDeliveryConfig {
        NotificationDeliveryConfig {
            poll_interval: Duration::from_secs(60),
            smtp_endpoint: DEFAULT_SMTP_ENDPOINT.to_string(),
            smtp_timeout: Duration::from_secs(10),
            helo_identity: DEFAULT_HELO_IDENTITY.to_string(),
            node_id: "node-a".to_string(),
            connector_ip: DEFAULT_CONNECTOR_IP.to_string(),
            sender_local_part: DEFAULT_SENDER_LOCAL_PART.to_string(),
            dkim_identities: parse_dkim_identities("example.test:default").expect("identities"),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            batch_limit: DEFAULT_BATCH_LIMIT,
        }
    }

    fn lazy_pool() -> PgPool {
        // Never connects: configuration validation happens before any query,
        // and an unresolvable host keeps a mis-written test from hanging.
        PgPool::connect_lazy("postgres://invalid.invalid/notification-delivery")
            .expect("lazily-connectable pool")
    }

    fn refused(mutate: impl FnOnce(&mut NotificationDeliveryConfig)) -> NotificationDeliveryError {
        let mut candidate = config();
        mutate(&mut candidate);
        NotificationDeliveryWorker::new(lazy_pool(), DeploymentId::new("LOCAL-TEST"), candidate)
            .err()
            .expect("configuration must be refused")
    }

    fn intake(sender: &str, recipients: &[String], raw_mime: Vec<u8>) -> OutboundIntakeRequest {
        OutboundIntakeRequest {
            connector: OutboundConnector {
                connector_id: "notification-delivery".to_string(),
                customer_id: CustomerId::new("customer-a"),
                deployment_id: DeploymentId::new("LOCAL-TEST"),
                ip_address: DEFAULT_CONNECTOR_IP.to_string(),
                authenticated_as: Some("node-a".to_string()),
                connector_type: ConnectorType::InternalApi,
            },
            envelope_sender: EnvelopeSender::new(sender),
            recipients: recipients
                .iter()
                .map(|address| Recipient {
                    address: address.clone(),
                    orcpt: None,
                    notify: None,
                })
                .collect(),
            message_id: None,
            content_hash: hex::encode(Sha256::digest(&raw_mime)),
        }
    }

    fn validation(domain: &str) -> DomainValidation {
        DomainValidation {
            domain: domain.to_string(),
            customer_id: CustomerId::new("customer-a"),
            validated: true,
            validation_source: DomainValidationSource::DnsTxt,
            validated_at: Utc::now(),
        }
    }

    #[test]
    fn dkim_provisioning_accepts_only_complete_identities() {
        let signers = parse_dkim_identities("Example.TEST:default, other.test:sel1").expect("list");
        assert_eq!(signers.len(), 2);
        assert_eq!(signers[0].domain, "example.test");
        assert_eq!(signers[0].selector, "default");
        assert_eq!(signers[1].domain, "other.test");
    }

    #[test]
    fn dkim_provisioning_rejects_a_malformed_list_entirely() {
        for raw in [
            "",
            "example.test",
            "example.test:",
            ":default",
            "example.test:default:extra",
            "example test:default",
            "nodot:default",
            "example.test:default,bad",
        ] {
            assert!(
                parse_dkim_identities(raw).is_none(),
                "{raw:?} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn a_complete_configuration_constructs_a_worker() {
        assert!(NotificationDeliveryWorker::new(
            lazy_pool(),
            DeploymentId::new("LOCAL-TEST"),
            config()
        )
        .is_ok());
    }

    #[tokio::test]
    async fn an_empty_signer_list_refuses_startup_rather_than_running_inert() {
        assert_eq!(
            refused(|candidate| candidate.dkim_identities.clear()),
            NotificationDeliveryError::Configuration
        );
    }

    #[tokio::test]
    async fn the_worker_only_targets_the_private_signed_outbound_listener() {
        for endpoint in [
            "mail.example.com:10027",
            "8.8.8.8:25",
            "postfix:10026",
            "relay:2525",
        ] {
            assert_eq!(
                refused(|candidate| candidate.smtp_endpoint = endpoint.to_string()),
                NotificationDeliveryError::Configuration,
                "{endpoint} must be refused"
            );
        }
        let mut allowed = config();
        allowed.smtp_endpoint = "192.168.8.4:10027".to_string();
        assert!(NotificationDeliveryWorker::new(
            lazy_pool(),
            DeploymentId::new("LOCAL-TEST"),
            allowed,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn unusable_worker_settings_are_refused_rather_than_loosened() {
        assert_eq!(
            refused(|candidate| candidate.helo_identity = "not an atom".to_string()),
            NotificationDeliveryError::Configuration
        );
        assert_eq!(
            refused(|candidate| candidate.max_attempts = 0),
            NotificationDeliveryError::Configuration
        );
        assert_eq!(
            refused(|candidate| candidate.batch_limit = 0),
            NotificationDeliveryError::Configuration
        );
        assert_eq!(
            refused(|candidate| candidate.sender_local_part = "bad local".to_string()),
            NotificationDeliveryError::Configuration
        );
        assert_eq!(
            refused(|candidate| candidate.connector_ip = "not-an-address".to_string()),
            NotificationDeliveryError::Configuration
        );
        assert_eq!(
            refused(|candidate| candidate.poll_interval = Duration::ZERO),
            NotificationDeliveryError::Configuration
        );
    }

    #[test]
    fn the_sender_is_a_verified_domain_that_is_also_provisioned() {
        let signers = BTreeMap::from_iter(
            parse_dkim_identities("provisioned.test:default, other.test:sel1")
                .expect("identities")
                .into_iter()
                .map(|signer| (signer.domain.clone(), signer)),
        );
        let verified = vec![
            "only-verified.test".to_string(),
            "provisioned.test".to_string(),
        ];
        let (domain, signer) = pick_signed_sender(&verified, &signers).expect("a signed domain");
        assert_eq!(domain, "provisioned.test");
        assert_eq!(signer.selector, "default");
        assert!(
            pick_signed_sender(&["only-verified.test".to_string()], &signers).is_none(),
            "an unprovisioned tenant must be skipped rather than mailed unsigned"
        );
    }

    #[test]
    fn severity_floor_selects_itself_and_everything_above() {
        assert_eq!(severity_reach("info").len(), 3);
        assert_eq!(severity_reach("warning"), ["warning", "critical"]);
        assert_eq!(severity_reach("critical"), ["critical"]);
        assert_eq!(severity_reach("nonsense").len(), 3);
    }

    #[test]
    fn notice_composition_is_byte_stable_so_a_retry_deduplicates() {
        let recipients = vec!["admin@example.test".to_string()];
        let first = compose_notice_mime(&finding(), "notifications@example.test", &recipients);
        let retry = compose_notice_mime(&finding(), "notifications@example.test", &recipients);
        assert_eq!(first, retry);
        assert_eq!(
            compose_notice_sha256(&finding(), "notifications@example.test", &recipients),
            hex::encode(Sha256::digest(&first))
        );

        let changed_recipient = vec!["other@example.test".to_string()];
        assert_ne!(
            compose_notice_mime(&finding(), "notifications@example.test", &changed_recipient),
            first
        );
    }

    #[test]
    fn notice_mime_is_a_decodable_alternative_message_with_one_aligned_from() {
        let recipients = vec![
            "admin@example.test".to_string(),
            "second@example.test".to_string(),
        ];
        let raw = compose_notice_mime(&finding(), "notifications@example.test", &recipients);
        let mail = mailparse::parse_mail(&raw).expect("parses as mail");
        assert_eq!(mail.headers.get_all_headers("From").len(), 1);
        let addresses = mailparse::addrparse_header(mail.headers.get_all_headers("From")[0])
            .expect("From parses");
        let [mailparse::MailAddr::Single(from)] = addresses.as_slice() else {
            panic!("the notice must have exactly one From address");
        };
        assert_eq!(from.addr, "notifications@example.test");
        assert_eq!(
            mail.headers.get_first_value("Subject").expect("subject"),
            "Notice: DMARC failures rose for example.test"
        );
        assert_eq!(
            mail.headers
                .get_first_value("Auto-Submitted")
                .expect("auto-submitted"),
            "auto-generated"
        );
        assert_eq!(mail.subparts.len(), 2);
        let text = mail.subparts[0].get_body().expect("utf-8 text part");
        assert!(text.contains("Three sources failed alignment"));
        assert!(text.contains("3f2504e0-4f89-41d3-9a0c-0305e82c3301"));
        let html = mail.subparts[1].get_body().expect("utf-8 html part");
        assert!(html.contains("NULLAPART"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://") && !html.contains("https://"));
    }

    #[test]
    fn finding_text_cannot_escape_the_stationery() {
        let mut finding = finding();
        finding.title = "<script>alert(1)</script>".to_string();
        finding.detail = "Ref <b>bold</b>".to_string();
        let raw = compose_notice_mime(&finding, "notifications@example.test", &[]);
        let mail = mailparse::parse_mail(&raw).expect("parses as mail");
        let html = mail.subparts[1].get_body().expect("utf-8 html part");
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn critical_findings_are_named_as_critical_in_the_subject() {
        let mut finding = finding();
        finding.severity = "critical".to_string();
        let raw = compose_notice_mime(&finding, "notifications@example.test", &[]);
        let mail = mailparse::parse_mail(&raw).expect("parses as mail");
        assert_eq!(
            mail.headers.get_first_value("Subject").expect("subject"),
            "Critical notice: DMARC failures rose for example.test"
        );
    }

    #[test]
    fn mailable_addresses_reject_shapes_smtp_would_refuse() {
        for address in [
            "no-at-sign.example.test",
            "@example.test",
            "admin@",
            "admin@nodot",
            "admin@ example.test",
            "admin\nX@example.test",
            "admin@two@test.test",
        ] {
            assert!(!is_mailable_address(address), "{address:?} must be refused");
        }
        assert!(is_mailable_address("admin@example.test"));
        assert!(is_mailable_address("a.b+c@sub.example.test"));
    }

    #[test]
    fn sender_local_part_rejects_shapes_that_could_inject_headers() {
        assert!(is_local_part("notifications"));
        assert!(is_local_part("a.b_c-d+e"));
        for value in [
            "",
            "no@sign",
            "with space",
            "cr\nlf",
            "x".repeat(65).as_str(),
        ] {
            assert!(!is_local_part(value), "{value:?} must be refused");
        }
    }

    #[test]
    fn reasons_are_capped_at_the_column_limit() {
        let long = "x".repeat(1000);
        assert_eq!(truncate_reason(&long).len(), MAX_REASON_LENGTH);
    }

    #[test]
    fn a_notice_for_a_domain_the_tenant_does_not_own_is_refused_by_the_outbound_contract() {
        // The worker derives its sender from the tenant's verified domains, but
        // the shared authorization boundary is what actually guarantees it, so a
        // foreign sender must fail there rather than in worker-side bookkeeping.
        let raw = compose_notice_mime(&finding(), "notifications@someone-else.test", &[]);
        let request = intake(
            "notifications@someone-else.test",
            &["admin@example.test".to_string()],
            raw.clone(),
        );
        let signing = OutboundSigningConfig {
            dkim: Some(ProvisionedDkimSigner {
                domain: "someone-else.test".to_string(),
                selector: "default".to_string(),
            }),
            helo_identity: Some(DEFAULT_HELO_IDENTITY.to_string()),
        };
        assert!(authorize_outbound_submission(
            &request,
            &[validation("example.test")],
            &DomainAuthorization::Internal,
            &signing,
            raw,
        )
        .is_err());
    }

    #[test]
    fn a_verified_and_provisioned_tenant_domain_authorizes_for_submission() {
        let recipients = vec!["admin@example.test".to_string()];
        let raw = compose_notice_mime(&finding(), "notifications@example.test", &recipients);
        let request = intake("notifications@example.test", &recipients, raw.clone());
        let signing = OutboundSigningConfig {
            dkim: Some(ProvisionedDkimSigner {
                domain: "example.test".to_string(),
                selector: "default".to_string(),
            }),
            helo_identity: Some(DEFAULT_HELO_IDENTITY.to_string()),
        };
        let submission = authorize_outbound_submission(
            &request,
            &[validation("example.test")],
            &DomainAuthorization::Internal,
            &signing,
            raw,
        )
        .expect("a verified, provisioned tenant domain must authorize");
        assert!(!submission.transaction_id().is_empty());
    }

    #[test]
    fn an_unprovisioned_sender_domain_never_reaches_the_signing_listener() {
        let recipients = vec!["admin@example.test".to_string()];
        let raw = compose_notice_mime(&finding(), "notifications@example.test", &recipients);
        let request = intake("notifications@example.test", &recipients, raw.clone());
        let signing = OutboundSigningConfig {
            dkim: None,
            helo_identity: Some(DEFAULT_HELO_IDENTITY.to_string()),
        };
        assert!(authorize_outbound_submission(
            &request,
            &[validation("example.test")],
            &DomainAuthorization::Internal,
            &signing,
            raw,
        )
        .is_err());
    }
}

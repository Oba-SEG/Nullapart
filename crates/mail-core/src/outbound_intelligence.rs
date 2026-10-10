//! Phase 6 outbound intelligence evaluator.
//!
//! The evaluator is deliberately pure: callers provide tenant-scoped approved
//! sender configuration, rolling metrics and scanner/authentication signals.
//! It returns a content-free policy decision and optional event aggregation key
//! without storing raw message content, recipient lists or bodies.

use chrono::{DateTime, Duration, Utc};
use nullapart_mail_contracts::{
    policy::ReasonCode,
    transaction::{CustomerId, DeploymentId},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

const UNAPPROVED_MESSAGES_PER_MINUTE: u32 = 25;
const UNAPPROVED_MESSAGES_PER_HOUR: u32 = 100;
const UNAPPROVED_RECIPIENTS_PER_MESSAGE: u32 = 50;
const UNAPPROVED_UNIQUE_RECIPIENTS_PER_HOUR: u32 = 250;
const ROTATING_RECIPIENT_NEW_PERCENT: f32 = 0.80;
const CAMPAIGN_MIN_MESSAGES_PER_HOUR: u32 = 40;
const EVENT_COOLDOWN_MINUTES: i64 = 30;

/// Trusted outbound source kind used by Phase 6 policy and persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundSourceKind {
    SmtpMta,
    InternalApi,
    Webhook,
    Connector,
}

/// Server-derived outbound source facts. Callers must not populate this from
/// client-supplied tenant/customer identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundSourceContext {
    pub deployment_id: DeploymentId,
    pub customer_id: CustomerId,
    pub source_kind: OutboundSourceKind,
    pub source_id: String,
    pub source_ip: Option<String>,
}

/// Explicit bulk sender approval. Approval scopes a sender to one tenant,
/// source and bounded sending budget; it is not a malware/content bypass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedBulkSender {
    pub deployment_id: DeploymentId,
    pub customer_id: CustomerId,
    pub sender_address: String,
    pub source_kind: OutboundSourceKind,
    pub source_id: String,
    pub source_ip: Option<String>,
    pub max_messages_per_minute: u32,
    pub max_messages_per_hour: u32,
    pub max_recipients_per_message: u32,
    pub max_unique_recipients_per_hour: u32,
    pub active: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Rolling sender/source/campaign metrics for one outbound decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OutboundBehaviorMetrics {
    pub messages_last_minute: u32,
    pub messages_last_hour: u32,
    pub recipients_this_message: u32,
    pub unique_recipients_last_hour: u32,
    pub new_recipients_last_hour: u32,
    pub recipient_domain_count_last_hour: u32,
    pub campaign_messages_last_hour: u32,
    pub bounce_failures_last_hour: u32,
}

impl OutboundBehaviorMetrics {
    fn new_recipient_ratio(self) -> f32 {
        if self.unique_recipients_last_hour == 0 {
            return 0.0;
        }
        self.new_recipients_last_hour as f32 / self.unique_recipients_last_hour as f32
    }
}

/// Content/authentication/security signals already derived by trusted stages.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutboundThreatSignals {
    pub malware_detected: bool,
    pub malicious_url_detected: bool,
    pub source_spoofing_detected: bool,
    pub unusual_sending_time: bool,
    pub auth_source_changed: bool,
    pub campaign_fingerprint: Option<String>,
}

/// Input to one outbound intelligence decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundIntelligenceInput {
    pub source: OutboundSourceContext,
    pub sender_address: String,
    pub sending_domain: String,
    pub metrics: OutboundBehaviorMetrics,
    pub signals: OutboundThreatSignals,
    pub approved_senders: Vec<ApprovedBulkSender>,
    pub now: DateTime<Utc>,
    pub existing_event: Option<ExistingOutboundEvent>,
}

/// Existing open event for cooldown/dedup aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExistingOutboundEvent {
    pub event_key: String,
    pub cooldown_until: DateTime<Utc>,
}

/// Phase 6 action vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundDecisionOutcome {
    Allow,
    Warn,
    Throttle,
    Defer,
    Hold,
    BlockSender,
    SuspendOutbound,
}

/// Logical security event category emitted by the evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundSecurityEventType {
    UnauthorizedBulk,
    CompromisedSender,
    SourceSpoofing,
    MalwareFromBulkSender,
    CampaignOutbreak,
    DeliveryFailureSpike,
}

/// Decision returned to outbound policy and event writers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundIntelligenceDecision {
    pub outcome: OutboundDecisionOutcome,
    pub reason_code: ReasonCode,
    pub event_type: Option<OutboundSecurityEventType>,
    pub event_key: Option<String>,
    pub aggregate_into_existing_event: bool,
    pub approval_used: bool,
    pub customer_id: CustomerId,
    pub deployment_id: DeploymentId,
}

/// PostgreSQL persistence failure for Phase 6 outbound intelligence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OutboundIntelligenceStoreError {
    #[error("outbound intelligence persistence is unavailable")]
    Unavailable,
    #[error("outbound intelligence persistence is unavailable during {0}")]
    Stage(&'static str),
}

/// Postgres-backed Phase 6 store.
#[derive(Debug, Clone)]
pub struct PostgresOutboundIntelligenceStore {
    pool: PgPool,
}

impl PostgresOutboundIntelligenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Loads active approved bulk senders for one server-derived tenant/source
    /// context and normalized sender. RLS is scoped transaction-locally.
    pub async fn load_approved_senders(
        &self,
        source: &OutboundSourceContext,
        sender_address: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ApprovedBulkSender>, OutboundIntelligenceStoreError> {
        let mut transaction = begin_scoped(&self.pool, source).await?;
        let rows = sqlx::query(
            "SELECT deployment_id, customer_id, sender_address, source_kind, source_id, \
                    host(source_ip) AS source_ip, max_messages_per_minute, max_messages_per_hour, \
                    max_recipients_per_message, max_unique_recipients_per_hour, active, expires_at \
             FROM approved_bulk_senders \
             WHERE deployment_id = $1 \
               AND customer_id = $2 \
               AND sender_address = lower($3) \
               AND source_kind = $4 \
               AND source_id = $5 \
               AND active = true \
               AND (expires_at IS NULL OR expires_at > $6) \
             ORDER BY updated_at DESC",
        )
        .bind(&source.deployment_id.0)
        .bind(&source.customer_id.0)
        .bind(sender_address.trim())
        .bind(source.source_kind.as_str())
        .bind(&source.source_id)
        .bind(now)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;

        rows.into_iter()
            .map(|row| {
                let source_kind: String = row
                    .try_get("source_kind")
                    .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
                Ok(ApprovedBulkSender {
                    deployment_id: DeploymentId::new(
                        row.try_get::<String, _>("deployment_id")
                            .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?
                            .as_str(),
                    ),
                    customer_id: CustomerId::new(
                        row.try_get::<String, _>("customer_id")
                            .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?
                            .as_str(),
                    ),
                    sender_address: row
                        .try_get("sender_address")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?,
                    source_kind: OutboundSourceKind::try_from(source_kind.as_str())?,
                    source_id: row
                        .try_get("source_id")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?,
                    source_ip: row
                        .try_get("source_ip")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?,
                    max_messages_per_minute: row
                        .try_get::<i32, _>("max_messages_per_minute")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?
                        as u32,
                    max_messages_per_hour: row
                        .try_get::<i32, _>("max_messages_per_hour")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?
                        as u32,
                    max_recipients_per_message: row
                        .try_get::<i32, _>("max_recipients_per_message")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?
                        as u32,
                    max_unique_recipients_per_hour: row
                        .try_get::<i32, _>("max_unique_recipients_per_hour")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?
                        as u32,
                    active: row
                        .try_get("active")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?,
                    expires_at: row
                        .try_get("expires_at")
                        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?,
                })
            })
            .collect()
    }

    /// Persists the content-free rollup/campaign/event projection for one
    /// decision. This never writes raw content or full recipient addresses.
    pub async fn persist_decision(
        &self,
        input: &OutboundIntelligenceInput,
        decision: &OutboundIntelligenceDecision,
    ) -> Result<(), OutboundIntelligenceStoreError> {
        let mut transaction = begin_scoped(&self.pool, &input.source).await?;
        upsert_rollup(&mut transaction, input)
            .await
            .map_err(|_| OutboundIntelligenceStoreError::Stage("rollup"))?;
        if input.signals.campaign_fingerprint.is_some() {
            upsert_campaign(&mut transaction, input, decision)
                .await
                .map_err(|_| OutboundIntelligenceStoreError::Stage("campaign"))?;
        }
        if let Some(event_key) = decision.event_key.as_deref() {
            upsert_security_event(&mut transaction, input, decision, event_key)
                .await
                .map_err(|_| OutboundIntelligenceStoreError::Stage("event"))?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| OutboundIntelligenceStoreError::Stage("commit"))?;
        Ok(())
    }
}

/// Evaluate outbound abuse, bulk and compromised-sender behaviour.
pub fn evaluate_outbound_intelligence(
    input: &OutboundIntelligenceInput,
) -> OutboundIntelligenceDecision {
    let approval = matching_approval(input);

    if input.signals.source_spoofing_detected {
        return decision(
            input,
            OutboundDecisionOutcome::BlockSender,
            ReasonCode::reject_spoofing(),
            Some(OutboundSecurityEventType::SourceSpoofing),
            "source-spoofing",
            approval.is_some(),
        );
    }

    if input.signals.malware_detected || input.signals.malicious_url_detected {
        let event_type = if approval.is_some() {
            Some(OutboundSecurityEventType::MalwareFromBulkSender)
        } else {
            Some(OutboundSecurityEventType::CompromisedSender)
        };
        return decision(
            input,
            OutboundDecisionOutcome::Hold,
            ReasonCode::quarantine_malware(),
            event_type,
            "malware-or-malicious-content",
            approval.is_some(),
        );
    }

    if let Some(approval) = approval {
        return evaluate_approved_bulk(input, approval);
    }

    evaluate_unapproved_sender(input)
}

fn evaluate_approved_bulk(
    input: &OutboundIntelligenceInput,
    approval: &ApprovedBulkSender,
) -> OutboundIntelligenceDecision {
    if input.metrics.recipients_this_message > approval.max_recipients_per_message
        || input.metrics.messages_last_minute > approval.max_messages_per_minute
    {
        return decision(
            input,
            OutboundDecisionOutcome::Throttle,
            ReasonCode::defer_rate_limit(),
            Some(OutboundSecurityEventType::UnauthorizedBulk),
            "approved-bulk-over-minute-budget",
            true,
        );
    }

    if input.metrics.messages_last_hour > approval.max_messages_per_hour
        || input.metrics.unique_recipients_last_hour > approval.max_unique_recipients_per_hour
    {
        return decision(
            input,
            OutboundDecisionOutcome::Defer,
            ReasonCode::defer_rate_limit(),
            Some(OutboundSecurityEventType::UnauthorizedBulk),
            "approved-bulk-over-hour-budget",
            true,
        );
    }

    if input.signals.auth_source_changed || input.signals.unusual_sending_time {
        return decision(
            input,
            OutboundDecisionOutcome::Warn,
            ReasonCode::new("OUTBOUND_BULK_ANOMALY"),
            Some(OutboundSecurityEventType::CompromisedSender),
            "approved-bulk-anomaly",
            true,
        );
    }

    OutboundIntelligenceDecision {
        outcome: OutboundDecisionOutcome::Allow,
        reason_code: ReasonCode::allowed(),
        event_type: None,
        event_key: None,
        aggregate_into_existing_event: false,
        approval_used: true,
        customer_id: input.source.customer_id.clone(),
        deployment_id: input.source.deployment_id.clone(),
    }
}

fn evaluate_unapproved_sender(input: &OutboundIntelligenceInput) -> OutboundIntelligenceDecision {
    if input.metrics.messages_last_minute > UNAPPROVED_MESSAGES_PER_MINUTE
        || input.metrics.recipients_this_message > UNAPPROVED_RECIPIENTS_PER_MESSAGE
    {
        return decision(
            input,
            OutboundDecisionOutcome::Hold,
            ReasonCode::new("OUTBOUND_UNAUTHORIZED_BULK"),
            Some(OutboundSecurityEventType::UnauthorizedBulk),
            "unapproved-bulk-burst",
            false,
        );
    }

    if input.metrics.messages_last_hour > UNAPPROVED_MESSAGES_PER_HOUR
        || input.metrics.unique_recipients_last_hour > UNAPPROVED_UNIQUE_RECIPIENTS_PER_HOUR
    {
        return decision(
            input,
            OutboundDecisionOutcome::Throttle,
            ReasonCode::defer_rate_limit(),
            Some(OutboundSecurityEventType::UnauthorizedBulk),
            "unapproved-bulk-hour-budget",
            false,
        );
    }

    if input.metrics.unique_recipients_last_hour >= 50
        && input.metrics.new_recipient_ratio() >= ROTATING_RECIPIENT_NEW_PERCENT
    {
        return decision(
            input,
            OutboundDecisionOutcome::Warn,
            ReasonCode::new("OUTBOUND_ROTATING_RECIPIENTS"),
            Some(OutboundSecurityEventType::CompromisedSender),
            "rotating-recipients",
            false,
        );
    }

    if input.metrics.campaign_messages_last_hour >= CAMPAIGN_MIN_MESSAGES_PER_HOUR
        && input.signals.campaign_fingerprint.is_some()
    {
        return decision(
            input,
            OutboundDecisionOutcome::Warn,
            ReasonCode::new("OUTBOUND_CAMPAIGN_CLUSTER"),
            Some(OutboundSecurityEventType::CampaignOutbreak),
            "campaign-outbreak",
            false,
        );
    }

    if input.metrics.bounce_failures_last_hour >= 25 {
        return decision(
            input,
            OutboundDecisionOutcome::Defer,
            ReasonCode::new("OUTBOUND_FAILURE_SPIKE"),
            Some(OutboundSecurityEventType::DeliveryFailureSpike),
            "delivery-failure-spike",
            false,
        );
    }

    OutboundIntelligenceDecision {
        outcome: OutboundDecisionOutcome::Allow,
        reason_code: ReasonCode::allowed(),
        event_type: None,
        event_key: None,
        aggregate_into_existing_event: false,
        approval_used: false,
        customer_id: input.source.customer_id.clone(),
        deployment_id: input.source.deployment_id.clone(),
    }
}

fn matching_approval(input: &OutboundIntelligenceInput) -> Option<&ApprovedBulkSender> {
    let sender_address = input.sender_address.trim().to_lowercase();
    input.approved_senders.iter().find(|approval| {
        approval.active
            && approval.deployment_id == input.source.deployment_id
            && approval.customer_id == input.source.customer_id
            && approval.sender_address == sender_address
            && approval.source_kind == input.source.source_kind
            && approval.source_id == input.source.source_id
            && approval
                .source_ip
                .as_deref()
                .is_none_or(|ip| input.source.source_ip.as_deref() == Some(ip))
            && approval
                .expires_at
                .is_none_or(|expires_at| expires_at > input.now)
    })
}

fn decision(
    input: &OutboundIntelligenceInput,
    outcome: OutboundDecisionOutcome,
    reason_code: ReasonCode,
    event_type: Option<OutboundSecurityEventType>,
    event_suffix: &str,
    approval_used: bool,
) -> OutboundIntelligenceDecision {
    let event_key = event_type.map(|event_type| event_key(input, event_type, event_suffix));
    let aggregate_into_existing_event = matches!((&event_key, &input.existing_event), (Some(key), Some(existing))
            if existing.event_key == *key && existing.cooldown_until > input.now);

    OutboundIntelligenceDecision {
        outcome,
        reason_code,
        event_type,
        event_key,
        aggregate_into_existing_event,
        approval_used,
        customer_id: input.source.customer_id.clone(),
        deployment_id: input.source.deployment_id.clone(),
    }
}

fn event_key(
    input: &OutboundIntelligenceInput,
    event_type: OutboundSecurityEventType,
    event_suffix: &str,
) -> String {
    let campaign = input
        .signals
        .campaign_fingerprint
        .as_deref()
        .unwrap_or("no-campaign");
    let mut hasher = Sha256::new();
    hasher.update(normalize_token(&input.sender_address));
    hasher.update(b":");
    hasher.update(normalize_token(campaign));
    hasher.update(b":");
    hasher.update(event_suffix);
    let digest = hex::encode(hasher.finalize());
    format!(
        "{}:{}:{}:{}",
        input.source.deployment_id.0,
        input.source.customer_id.0,
        event_type.as_str(),
        &digest[..24]
    )
}

fn normalize_token(value: &str) -> String {
    value.trim().to_lowercase().replace([' ', '\t', '\n'], "-")
}

impl OutboundSecurityEventType {
    fn as_str(self) -> &'static str {
        match self {
            Self::UnauthorizedBulk => "unauthorized-bulk",
            Self::CompromisedSender => "compromised-sender",
            Self::SourceSpoofing => "source-spoofing",
            Self::MalwareFromBulkSender => "malware-from-bulk-sender",
            Self::CampaignOutbreak => "campaign-outbreak",
            Self::DeliveryFailureSpike => "delivery-failure-spike",
        }
    }
}

impl OutboundSourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::SmtpMta => "smtp_mta",
            Self::InternalApi => "internal_api",
            Self::Webhook => "webhook",
            Self::Connector => "connector",
        }
    }
}

impl TryFrom<&str> for OutboundSourceKind {
    type Error = OutboundIntelligenceStoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "smtp_mta" => Ok(Self::SmtpMta),
            "internal_api" => Ok(Self::InternalApi),
            "webhook" => Ok(Self::Webhook),
            "connector" => Ok(Self::Connector),
            _ => Err(OutboundIntelligenceStoreError::Unavailable),
        }
    }
}

impl OutboundDecisionOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Throttle => "throttle",
            Self::Defer => "defer",
            Self::Hold => "hold",
            Self::BlockSender => "block_sender",
            Self::SuspendOutbound => "suspend_outbound",
        }
    }
}

async fn begin_scoped<'a>(
    pool: &'a PgPool,
    source: &OutboundSourceContext,
) -> Result<Transaction<'a, Postgres>, OutboundIntelligenceStoreError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
    set_scope(&mut transaction, source).await?;
    Ok(transaction)
}

async fn set_scope(
    transaction: &mut Transaction<'_, Postgres>,
    source: &OutboundSourceContext,
) -> Result<(), OutboundIntelligenceStoreError> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(&source.deployment_id.0)
    .bind(&source.customer_id.0)
    .execute(&mut **transaction)
    .await
    .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
    Ok(())
}

async fn upsert_rollup(
    transaction: &mut Transaction<'_, Postgres>,
    input: &OutboundIntelligenceInput,
) -> Result<(), OutboundIntelligenceStoreError> {
    sqlx::query(
        "INSERT INTO outbound_behavior_rollups (\
            deployment_id, customer_id, source_kind, source_id, source_ip, sender_address, \
            sending_domain, campaign_fingerprint, recipient_domain, window_start, window_seconds, \
            message_count, recipient_count, unique_recipient_count, new_recipient_count, \
            bounce_count, failure_count, malware_count, auth_source_change_count, unusual_time_count\
         ) VALUES (\
            $1,$2,$3,$4,$5::inet,lower($6),lower($7),$8,NULL,$9,60,$10,$11,$12,$13,$14,$14,$15,$16,$17\
         ) ON CONFLICT (\
            deployment_id, customer_id, source_kind, source_id, sender_address, \
            (COALESCE(campaign_fingerprint, '')), (COALESCE(recipient_domain, '')), window_start, window_seconds\
         ) DO UPDATE SET \
            source_ip = EXCLUDED.source_ip, \
            message_count = GREATEST(outbound_behavior_rollups.message_count, EXCLUDED.message_count), \
            recipient_count = GREATEST(outbound_behavior_rollups.recipient_count, EXCLUDED.recipient_count), \
            unique_recipient_count = GREATEST(outbound_behavior_rollups.unique_recipient_count, EXCLUDED.unique_recipient_count), \
            new_recipient_count = GREATEST(outbound_behavior_rollups.new_recipient_count, EXCLUDED.new_recipient_count), \
            bounce_count = GREATEST(outbound_behavior_rollups.bounce_count, EXCLUDED.bounce_count), \
            failure_count = GREATEST(outbound_behavior_rollups.failure_count, EXCLUDED.failure_count), \
            malware_count = GREATEST(outbound_behavior_rollups.malware_count, EXCLUDED.malware_count), \
            auth_source_change_count = GREATEST(outbound_behavior_rollups.auth_source_change_count, EXCLUDED.auth_source_change_count), \
            unusual_time_count = GREATEST(outbound_behavior_rollups.unusual_time_count, EXCLUDED.unusual_time_count), \
            updated_at = now()",
    )
    .bind(&input.source.deployment_id.0)
    .bind(&input.source.customer_id.0)
    .bind(input.source.source_kind.as_str())
    .bind(&input.source.source_id)
    .bind(input.source.source_ip.as_deref())
    .bind(input.sender_address.trim())
    .bind(input.sending_domain.trim())
    .bind(input.signals.campaign_fingerprint.as_deref())
    .bind(window_start(input.now, 60))
    .bind(input.metrics.messages_last_minute as i32)
    .bind(input.metrics.recipients_this_message as i32)
    .bind(input.metrics.unique_recipients_last_hour as i32)
    .bind(input.metrics.new_recipients_last_hour as i32)
    .bind(input.metrics.bounce_failures_last_hour as i32)
    .bind(i32::from(input.signals.malware_detected || input.signals.malicious_url_detected))
    .bind(i32::from(input.signals.auth_source_changed))
    .bind(i32::from(input.signals.unusual_sending_time))
    .execute(&mut **transaction)
    .await
    .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
    Ok(())
}

async fn upsert_campaign(
    transaction: &mut Transaction<'_, Postgres>,
    input: &OutboundIntelligenceInput,
    decision: &OutboundIntelligenceDecision,
) -> Result<(), OutboundIntelligenceStoreError> {
    sqlx::query(
        "INSERT INTO outbound_campaign_fingerprints (\
            deployment_id, customer_id, fingerprint, algorithm, message_count, recipient_count, disposition\
         ) VALUES ($1,$2,$3,'nullapart_v1',$4,$5,$6) \
         ON CONFLICT (deployment_id, customer_id, fingerprint, algorithm) DO UPDATE SET \
            last_seen_at = now(), \
            message_count = GREATEST(outbound_campaign_fingerprints.message_count, EXCLUDED.message_count), \
            recipient_count = GREATEST(outbound_campaign_fingerprints.recipient_count, EXCLUDED.recipient_count), \
            disposition = EXCLUDED.disposition",
    )
    .bind(&input.source.deployment_id.0)
    .bind(&input.source.customer_id.0)
    .bind(input.signals.campaign_fingerprint.as_deref())
    .bind(input.metrics.campaign_messages_last_hour as i32)
    .bind(input.metrics.unique_recipients_last_hour as i32)
    .bind(campaign_disposition(decision.outcome))
    .execute(&mut **transaction)
    .await
    .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
    Ok(())
}

async fn upsert_security_event(
    transaction: &mut Transaction<'_, Postgres>,
    input: &OutboundIntelligenceInput,
    decision: &OutboundIntelligenceDecision,
    event_key: &str,
) -> Result<(), OutboundIntelligenceStoreError> {
    let Some(event_type) = decision.event_type else {
        return Ok(());
    };
    let cooldown_until = default_event_cooldown(input.now);
    let severity = event_severity(decision.outcome);
    let details = serde_json::json!({
        "messages_last_minute": input.metrics.messages_last_minute,
        "messages_last_hour": input.metrics.messages_last_hour,
        "recipients_this_message": input.metrics.recipients_this_message,
        "unique_recipients_last_hour": input.metrics.unique_recipients_last_hour,
        "new_recipients_last_hour": input.metrics.new_recipients_last_hour,
        "approval_used": decision.approval_used
    });
    sqlx::query(
        "INSERT INTO outbound_security_events (\
            deployment_id, customer_id, event_key, event_type, severity, outcome, reason_code, \
            sender_address, source_id, campaign_fingerprint, first_seen_at, last_seen_at, \
            message_count, cooldown_until, details\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,lower($8),$9,$10,$11,$11,1,$12,$13) \
         ON CONFLICT (deployment_id, customer_id, event_key) DO UPDATE SET \
            last_seen_at = EXCLUDED.last_seen_at, \
            message_count = outbound_security_events.message_count + 1, \
            cooldown_until = EXCLUDED.cooldown_until, \
            outcome = EXCLUDED.outcome, \
            reason_code = EXCLUDED.reason_code, \
            severity = EXCLUDED.severity, \
            details = EXCLUDED.details, \
            updated_at = now()",
    )
    .bind(&input.source.deployment_id.0)
    .bind(&input.source.customer_id.0)
    .bind(event_key)
    .bind(event_type.as_str().replace('-', "_"))
    .bind(severity)
    .bind(decision.outcome.as_str())
    .bind(&decision.reason_code.0)
    .bind(input.sender_address.trim())
    .bind(&input.source.source_id)
    .bind(input.signals.campaign_fingerprint.as_deref())
    .bind(input.now)
    .bind(cooldown_until)
    .bind(sqlx::types::Json(details))
    .execute(&mut **transaction)
    .await
    .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
    Ok(())
}

fn window_start(now: DateTime<Utc>, window_seconds: i64) -> DateTime<Utc> {
    let timestamp = now.timestamp();
    let start = timestamp - timestamp.rem_euclid(window_seconds);
    DateTime::<Utc>::from_timestamp(start, 0).unwrap_or(now)
}

fn campaign_disposition(outcome: OutboundDecisionOutcome) -> &'static str {
    match outcome {
        OutboundDecisionOutcome::Allow => "allowed",
        OutboundDecisionOutcome::Warn => "warned",
        OutboundDecisionOutcome::Throttle => "throttled",
        OutboundDecisionOutcome::Defer | OutboundDecisionOutcome::Hold => "held",
        OutboundDecisionOutcome::BlockSender | OutboundDecisionOutcome::SuspendOutbound => {
            "blocked"
        },
    }
}

fn event_severity(outcome: OutboundDecisionOutcome) -> &'static str {
    match outcome {
        OutboundDecisionOutcome::Allow => "info",
        OutboundDecisionOutcome::Warn
        | OutboundDecisionOutcome::Throttle
        | OutboundDecisionOutcome::Defer => "warning",
        OutboundDecisionOutcome::Hold
        | OutboundDecisionOutcome::BlockSender
        | OutboundDecisionOutcome::SuspendOutbound => "critical",
    }
}

/// Default cooldown used by event writers for Phase 6 event deduplication.
pub fn default_event_cooldown(now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::minutes(EVENT_COOLDOWN_MINUTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> OutboundSourceContext {
        OutboundSourceContext {
            deployment_id: DeploymentId::new("CZA-1"),
            customer_id: CustomerId::new("cust-a"),
            source_kind: OutboundSourceKind::SmtpMta,
            source_id: "mta-a".to_string(),
            source_ip: Some("10.0.0.10".to_string()),
        }
    }

    fn approval(now: DateTime<Utc>) -> ApprovedBulkSender {
        ApprovedBulkSender {
            deployment_id: DeploymentId::new("CZA-1"),
            customer_id: CustomerId::new("cust-a"),
            sender_address: "bulk@example.test".to_string(),
            source_kind: OutboundSourceKind::SmtpMta,
            source_id: "mta-a".to_string(),
            source_ip: Some("10.0.0.10".to_string()),
            max_messages_per_minute: 20,
            max_messages_per_hour: 800,
            max_recipients_per_message: 100,
            max_unique_recipients_per_hour: 5000,
            active: true,
            expires_at: Some(now + Duration::days(1)),
        }
    }

    fn metrics() -> OutboundBehaviorMetrics {
        OutboundBehaviorMetrics {
            messages_last_minute: 1,
            messages_last_hour: 10,
            recipients_this_message: 5,
            unique_recipients_last_hour: 20,
            new_recipients_last_hour: 2,
            recipient_domain_count_last_hour: 3,
            campaign_messages_last_hour: 10,
            bounce_failures_last_hour: 0,
        }
    }

    fn input(now: DateTime<Utc>) -> OutboundIntelligenceInput {
        OutboundIntelligenceInput {
            source: source(),
            sender_address: "bulk@example.test".to_string(),
            sending_domain: "example.test".to_string(),
            metrics: metrics(),
            signals: OutboundThreatSignals::default(),
            approved_senders: vec![approval(now)],
            now,
            existing_event: None,
        }
    }

    #[test]
    fn approved_bulk_within_limits_is_allowed() {
        let now = Utc::now();
        let decision = evaluate_outbound_intelligence(&input(now));

        assert_eq!(decision.outcome, OutboundDecisionOutcome::Allow);
        assert_eq!(decision.reason_code, ReasonCode::allowed());
        assert!(decision.approval_used);
        assert!(decision.event_key.is_none());
    }

    #[test]
    fn unauthorized_bulk_burst_is_held_and_aggregated() {
        let now = Utc::now();
        let mut request = input(now);
        request.approved_senders.clear();
        request.metrics.messages_last_minute = UNAPPROVED_MESSAGES_PER_MINUTE + 1;

        let decision = evaluate_outbound_intelligence(&request);

        assert_eq!(decision.outcome, OutboundDecisionOutcome::Hold);
        assert_eq!(
            decision.event_type,
            Some(OutboundSecurityEventType::UnauthorizedBulk)
        );
        assert_eq!(
            decision.reason_code,
            ReasonCode::new("OUTBOUND_UNAUTHORIZED_BULK")
        );
        assert!(!decision.approval_used);
    }

    #[test]
    fn approved_bulk_never_bypasses_malware() {
        let now = Utc::now();
        let mut request = input(now);
        request.signals.malware_detected = true;

        let decision = evaluate_outbound_intelligence(&request);

        assert_eq!(decision.outcome, OutboundDecisionOutcome::Hold);
        assert_eq!(decision.reason_code, ReasonCode::quarantine_malware());
        assert_eq!(
            decision.event_type,
            Some(OutboundSecurityEventType::MalwareFromBulkSender)
        );
        assert!(decision.approval_used);
    }

    #[test]
    fn source_spoofing_blocks_sender_before_volume_checks() {
        let now = Utc::now();
        let mut request = input(now);
        request.signals.source_spoofing_detected = true;
        request.metrics.messages_last_minute = UNAPPROVED_MESSAGES_PER_MINUTE + 10;

        let decision = evaluate_outbound_intelligence(&request);

        assert_eq!(decision.outcome, OutboundDecisionOutcome::BlockSender);
        assert_eq!(decision.reason_code, ReasonCode::reject_spoofing());
        assert_eq!(
            decision.event_type,
            Some(OutboundSecurityEventType::SourceSpoofing)
        );
    }

    #[test]
    fn rotating_recipient_low_and_slow_pattern_warns() {
        let now = Utc::now();
        let mut request = input(now);
        request.approved_senders.clear();
        request.metrics.unique_recipients_last_hour = 80;
        request.metrics.new_recipients_last_hour = 70;

        let decision = evaluate_outbound_intelligence(&request);

        assert_eq!(decision.outcome, OutboundDecisionOutcome::Warn);
        assert_eq!(
            decision.reason_code,
            ReasonCode::new("OUTBOUND_ROTATING_RECIPIENTS")
        );
        assert_eq!(
            decision.event_type,
            Some(OutboundSecurityEventType::CompromisedSender)
        );
    }

    #[test]
    fn matching_event_within_cooldown_deduplicates() {
        let now = Utc::now();
        let mut request = input(now);
        request.approved_senders.clear();
        request.metrics.messages_last_minute = UNAPPROVED_MESSAGES_PER_MINUTE + 1;

        let first = evaluate_outbound_intelligence(&request);
        request.existing_event = Some(ExistingOutboundEvent {
            event_key: first.event_key.clone().expect("event key"),
            cooldown_until: default_event_cooldown(now),
        });

        let repeated = evaluate_outbound_intelligence(&request);

        assert_eq!(repeated.outcome, first.outcome);
        assert!(repeated.aggregate_into_existing_event);
        assert_eq!(repeated.event_key, first.event_key);
    }
}

//! Phase 6 outbound intelligence evaluator.
//!
//! The evaluator is deliberately pure: callers provide tenant-scoped approved
//! sender configuration, rolling metrics and scanner/authentication signals.
//! It returns a content-free policy decision and optional event aggregation key
//! without storing raw message content, recipient lists or bodies.

use chrono::{DateTime, Duration, Utc};
use nullapart_mail_contracts::{
    policy::{PolicyRule, ReasonCode},
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
pub const BULK_SENDING_POLICY_FAMILY: &str = "bulk_sending";
pub const OUTBOUND_ABUSE_POLICY_FAMILY: &str = "outbound_abuse";
pub const SENDER_REPUTATION_POLICY_FAMILY: &str = "sender_reputation";

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

/// Tenant-safe aggregate for one recipient domain. Stores only the domain and
/// counts, never full recipient addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundRecipientDomainMetrics {
    pub recipient_domain: String,
    pub recipient_count: u32,
    pub unique_recipient_count: u32,
    pub new_recipient_count: u32,
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

/// Phase 6 policy thresholds loaded from policy administration metadata.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OutboundPolicyThresholds {
    pub unauthorized_messages_per_minute: u32,
    pub unauthorized_messages_per_hour: u32,
    pub unauthorized_recipients_per_message: u32,
    pub unauthorized_unique_recipients_per_hour: u32,
    pub rotating_recipient_new_ratio: f32,
    pub campaign_min_messages_per_hour: u32,
    pub bounce_failures_per_hour: u32,
    pub event_cooldown_minutes: i64,
}

impl Default for OutboundPolicyThresholds {
    fn default() -> Self {
        Self {
            unauthorized_messages_per_minute: UNAPPROVED_MESSAGES_PER_MINUTE,
            unauthorized_messages_per_hour: UNAPPROVED_MESSAGES_PER_HOUR,
            unauthorized_recipients_per_message: UNAPPROVED_RECIPIENTS_PER_MESSAGE,
            unauthorized_unique_recipients_per_hour: UNAPPROVED_UNIQUE_RECIPIENTS_PER_HOUR,
            rotating_recipient_new_ratio: ROTATING_RECIPIENT_NEW_PERCENT,
            campaign_min_messages_per_hour: CAMPAIGN_MIN_MESSAGES_PER_HOUR,
            bounce_failures_per_hour: 25,
            event_cooldown_minutes: EVENT_COOLDOWN_MINUTES,
        }
    }
}

/// Input to one outbound intelligence decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundIntelligenceInput {
    pub source: OutboundSourceContext,
    pub sender_address: String,
    pub sending_domain: String,
    pub metrics: OutboundBehaviorMetrics,
    pub recipient_domain_metrics: Vec<OutboundRecipientDomainMetrics>,
    pub signals: OutboundThreatSignals,
    pub policy_thresholds: OutboundPolicyThresholds,
    pub approved_senders: Vec<ApprovedBulkSender>,
    pub now: DateTime<Utc>,
    pub existing_event: Option<ExistingOutboundEvent>,
}

/// Content-free lookup key for persisted rolling outbound behaviour metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundBehaviorMetricsLookup {
    pub source: OutboundSourceContext,
    pub sender_address: String,
    pub sending_domain: String,
    pub campaign_fingerprint: Option<String>,
    pub now: DateTime<Utc>,
    pub current_recipient_count: u32,
    pub current_recipient_domain_count: u32,
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

    /// Loads active Phase 6 policy thresholds from tenant policy revisions.
    /// Missing metadata falls back to safe built-in defaults.
    pub async fn load_policy_thresholds(
        &self,
        source: &OutboundSourceContext,
    ) -> Result<OutboundPolicyThresholds, OutboundIntelligenceStoreError> {
        let mut transaction = begin_scoped(&self.pool, source).await?;
        let rows = sqlx::query(
            "SELECT family_id, rules \
             FROM policy_revisions \
             WHERE deployment_id = $1 \
               AND customer_id = $2 \
               AND scope_level = 'tenant' \
               AND deactivated_at IS NULL \
               AND family_id IN ('bulk_sending', 'outbound_abuse', 'sender_reputation')",
        )
        .bind(&source.deployment_id.0)
        .bind(&source.customer_id.0)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;

        let mut thresholds = OutboundPolicyThresholds::default();
        for row in rows {
            let family_id: String = row
                .try_get("family_id")
                .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
            let rules = row
                .try_get::<sqlx::types::Json<serde_json::Value>, _>("rules")
                .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?
                .0;
            let rules: Vec<PolicyRule> = serde_json::from_value(rules)
                .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
            apply_policy_threshold_rules(&mut thresholds, &family_id, &rules);
        }
        Ok(thresholds)
    }

    /// Loads the persisted rolling behaviour projection for the current
    /// sender/source and adds the in-flight message counts. Callers may still
    /// merge in richer trusted runtime snapshots; this database projection
    /// prevents the outbound path from depending only on caller-populated
    /// counters.
    pub async fn load_behavior_metrics(
        &self,
        lookup: &OutboundBehaviorMetricsLookup,
    ) -> Result<OutboundBehaviorMetrics, OutboundIntelligenceStoreError> {
        let mut transaction = begin_scoped(&self.pool, &lookup.source).await?;
        let minute_start = lookup.now - Duration::minutes(1);
        let hour_start = lookup.now - Duration::hours(1);
        let row = sqlx::query(
            "SELECT \
                COALESCE(MAX(message_count) FILTER (WHERE recipient_domain IS NULL AND window_start >= $7), 0)::bigint AS messages_last_minute, \
                COALESCE(MAX(message_count) FILTER (WHERE recipient_domain IS NULL), 0)::bigint AS messages_last_hour, \
                COALESCE(MAX(unique_recipient_count) FILTER (WHERE recipient_domain IS NULL), 0)::bigint AS unique_recipients_last_hour, \
                COALESCE(MAX(new_recipient_count) FILTER (WHERE recipient_domain IS NULL), 0)::bigint AS new_recipients_last_hour, \
                COALESCE(COUNT(DISTINCT recipient_domain) FILTER (WHERE recipient_domain IS NOT NULL), 0)::bigint AS recipient_domain_count_last_hour, \
                COALESCE(MAX(message_count) FILTER (WHERE recipient_domain IS NULL AND campaign_fingerprint = $8), 0)::bigint AS campaign_messages_last_hour, \
                COALESCE(MAX(failure_count) FILTER (WHERE recipient_domain IS NULL), 0)::bigint AS bounce_failures_last_hour \
             FROM outbound_behavior_rollups \
             WHERE deployment_id = $1 \
               AND customer_id = $2 \
               AND source_kind = $3 \
               AND source_id = $4 \
               AND sender_address = lower($5) \
               AND sending_domain = lower($6) \
               AND window_start >= $9",
        )
        .bind(&lookup.source.deployment_id.0)
        .bind(&lookup.source.customer_id.0)
        .bind(lookup.source.source_kind.as_str())
        .bind(&lookup.source.source_id)
        .bind(lookup.sender_address.trim())
        .bind(lookup.sending_domain.trim())
        .bind(minute_start)
        .bind(lookup.campaign_fingerprint.as_deref())
        .bind(hour_start)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;

        Ok(OutboundBehaviorMetrics {
            messages_last_minute: i64_to_u32(row.get::<i64, _>("messages_last_minute"))
                .saturating_add(1),
            messages_last_hour: i64_to_u32(row.get::<i64, _>("messages_last_hour"))
                .saturating_add(1),
            recipients_this_message: lookup.current_recipient_count,
            unique_recipients_last_hour: i64_to_u32(
                row.get::<i64, _>("unique_recipients_last_hour"),
            )
            .max(lookup.current_recipient_count),
            new_recipients_last_hour: i64_to_u32(row.get::<i64, _>("new_recipients_last_hour")),
            recipient_domain_count_last_hour: i64_to_u32(
                row.get::<i64, _>("recipient_domain_count_last_hour"),
            )
            .max(lookup.current_recipient_domain_count),
            campaign_messages_last_hour: if lookup.campaign_fingerprint.is_some() {
                i64_to_u32(row.get::<i64, _>("campaign_messages_last_hour")).saturating_add(1)
            } else {
                0
            },
            bounce_failures_last_hour: i64_to_u32(row.get::<i64, _>("bounce_failures_last_hour")),
        })
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

/// Publish-time validation for Phase 6 threshold policy metadata.
pub fn validate_outbound_policy_rules(family_key: &str, rules: &[PolicyRule]) -> bool {
    if !matches!(
        family_key,
        BULK_SENDING_POLICY_FAMILY | OUTBOUND_ABUSE_POLICY_FAMILY | SENDER_REPUTATION_POLICY_FAMILY
    ) {
        return true;
    }
    rules.iter().all(|rule| {
        let Some(metadata) = rule.action.metadata.as_ref() else {
            return true;
        };
        match family_key {
            BULK_SENDING_POLICY_FAMILY => valid_bulk_sending_metadata(metadata),
            OUTBOUND_ABUSE_POLICY_FAMILY => valid_outbound_abuse_metadata(metadata),
            SENDER_REPUTATION_POLICY_FAMILY => valid_sender_reputation_metadata(metadata),
            _ => true,
        }
    })
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
    let thresholds = input.policy_thresholds;
    if input.metrics.messages_last_minute > thresholds.unauthorized_messages_per_minute
        || input.metrics.recipients_this_message > thresholds.unauthorized_recipients_per_message
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

    if input.metrics.messages_last_hour > thresholds.unauthorized_messages_per_hour
        || input.metrics.unique_recipients_last_hour
            > thresholds.unauthorized_unique_recipients_per_hour
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
        && input.metrics.new_recipient_ratio() >= thresholds.rotating_recipient_new_ratio
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

    if input.metrics.campaign_messages_last_hour >= thresholds.campaign_min_messages_per_hour
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

    if input.metrics.bounce_failures_last_hour >= thresholds.bounce_failures_per_hour {
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
    upsert_rollup_row(transaction, input, None).await?;
    for domain in &input.recipient_domain_metrics {
        upsert_rollup_row(transaction, input, Some(domain)).await?;
    }
    Ok(())
}

async fn upsert_rollup_row(
    transaction: &mut Transaction<'_, Postgres>,
    input: &OutboundIntelligenceInput,
    recipient_domain: Option<&OutboundRecipientDomainMetrics>,
) -> Result<(), OutboundIntelligenceStoreError> {
    let recipient_count = recipient_domain
        .map(|metric| metric.recipient_count)
        .unwrap_or(input.metrics.recipients_this_message);
    let unique_recipient_count = recipient_domain
        .map(|metric| metric.unique_recipient_count)
        .unwrap_or(input.metrics.unique_recipients_last_hour);
    let new_recipient_count = recipient_domain
        .map(|metric| metric.new_recipient_count)
        .unwrap_or(input.metrics.new_recipients_last_hour);
    sqlx::query(
        "INSERT INTO outbound_behavior_rollups (\
            deployment_id, customer_id, source_kind, source_id, source_ip, sender_address, \
            sending_domain, campaign_fingerprint, recipient_domain, window_start, window_seconds, \
            message_count, recipient_count, unique_recipient_count, new_recipient_count, \
            bounce_count, failure_count, malware_count, auth_source_change_count, unusual_time_count\
         ) VALUES (\
            $1,$2,$3,$4,$5::inet,lower($6),lower($7),$8,lower($9),$10,60,$11,$12,$13,$14,$15,$15,$16,$17,$18\
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
    .bind(recipient_domain.map(|metric| metric.recipient_domain.trim()))
    .bind(window_start(input.now, 60))
    .bind(input.metrics.messages_last_minute as i32)
    .bind(recipient_count as i32)
    .bind(unique_recipient_count as i32)
    .bind(new_recipient_count as i32)
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
    let cooldown_until =
        input.now + Duration::minutes(input.policy_thresholds.event_cooldown_minutes);
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
    .bind(sqlx::types::Json(details.clone()))
    .execute(&mut **transaction)
    .await
    .map_err(|_| OutboundIntelligenceStoreError::Unavailable)?;
    enqueue_outbound_security_notification(
        transaction,
        OutboundSecurityNotification {
            input,
            decision,
            event_key,
            event_type,
            severity,
            cooldown_until,
            details,
        },
    )
    .await?;
    Ok(())
}

struct OutboundSecurityNotification<'a> {
    input: &'a OutboundIntelligenceInput,
    decision: &'a OutboundIntelligenceDecision,
    event_key: &'a str,
    event_type: OutboundSecurityEventType,
    severity: &'a str,
    cooldown_until: DateTime<Utc>,
    details: serde_json::Value,
}

async fn enqueue_outbound_security_notification(
    transaction: &mut Transaction<'_, Postgres>,
    notification: OutboundSecurityNotification<'_>,
) -> Result<(), OutboundIntelligenceStoreError> {
    if notification.severity == "info" {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO outbox_events \
         (event_type, event_version, payload, idempotency_key, customer_id, deployment_id, trace_id) \
         VALUES ('outbound.security_event', 1, $1, $2, $3, $4, $5) \
         ON CONFLICT (idempotency_key) DO NOTHING",
    )
    .bind(sqlx::types::Json(serde_json::json!({
        "event_key": notification.event_key,
        "event_type": notification.event_type.as_str().replace('-', "_"),
        "severity": notification.severity,
        "outcome": notification.decision.outcome.as_str(),
        "reason_code": notification.decision.reason_code.0,
        "sender_address": notification.input.sender_address,
        "source_id": notification.input.source.source_id,
        "campaign_fingerprint": notification.input.signals.campaign_fingerprint,
        "cooldown_until": notification.cooldown_until,
        "details": notification.details,
    })))
    .bind(format!(
        "outbound-security:{}:{}:{}",
        notification.input.source.deployment_id.0,
        notification.input.source.customer_id.0,
        notification.event_key
    ))
    .bind(&notification.input.source.customer_id.0)
    .bind(&notification.input.source.deployment_id.0)
    .bind(notification.event_key)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(|_| OutboundIntelligenceStoreError::Unavailable)
}

fn apply_policy_threshold_rules(
    thresholds: &mut OutboundPolicyThresholds,
    family_id: &str,
    rules: &[PolicyRule],
) {
    for rule in rules.iter().filter(|rule| rule.enabled) {
        let Some(metadata) = rule.action.metadata.as_ref() else {
            continue;
        };
        match family_id {
            "bulk_sending" => {
                if let Some(value) = positive_u32(metadata, "max_messages_per_minute") {
                    thresholds.unauthorized_messages_per_minute = value;
                }
                if let Some(value) = positive_u32(metadata, "max_messages_per_hour") {
                    thresholds.unauthorized_messages_per_hour = value;
                }
                if let Some(value) = positive_u32(metadata, "max_recipients_per_message") {
                    thresholds.unauthorized_recipients_per_message = value;
                }
                if let Some(value) = positive_u32(metadata, "max_unique_recipients_per_hour") {
                    thresholds.unauthorized_unique_recipients_per_hour = value;
                }
            },
            "outbound_abuse" => {
                if let Some(value) = positive_u32(metadata, "campaign_min_messages_per_hour") {
                    thresholds.campaign_min_messages_per_hour = value;
                }
                if let Some(value) = bounded_ratio(metadata, "rotating_recipient_new_ratio") {
                    thresholds.rotating_recipient_new_ratio = value;
                }
                if let Some(value) = positive_i64(metadata, "event_cooldown_minutes") {
                    thresholds.event_cooldown_minutes = value;
                }
            },
            "sender_reputation" => {
                if let Some(value) = positive_u32(metadata, "bounce_failures_per_hour") {
                    thresholds.bounce_failures_per_hour = value;
                }
            },
            _ => {},
        }
    }
}

fn positive_u32(metadata: &serde_json::Value, key: &str) -> Option<u32> {
    let value = metadata.get(key)?.as_u64()?;
    u32::try_from(value).ok().filter(|value| *value > 0)
}

fn i64_to_u32(value: i64) -> u32 {
    u32::try_from(value.max(0)).unwrap_or(u32::MAX)
}

fn positive_i64(metadata: &serde_json::Value, key: &str) -> Option<i64> {
    let value = metadata.get(key)?.as_i64()?;
    (value > 0).then_some(value)
}

fn bounded_ratio(metadata: &serde_json::Value, key: &str) -> Option<f32> {
    let value = metadata.get(key)?.as_f64()?;
    (value > 0.0 && value <= 1.0).then_some(value as f32)
}

fn valid_bulk_sending_metadata(metadata: &serde_json::Value) -> bool {
    has_exact_keys(
        metadata,
        &[
            "max_messages_per_minute",
            "max_messages_per_hour",
            "max_recipients_per_message",
            "max_unique_recipients_per_hour",
        ],
    ) && positive_u32(metadata, "max_messages_per_minute").is_some()
        && positive_u32(metadata, "max_messages_per_hour").is_some()
        && positive_u32(metadata, "max_recipients_per_message").is_some()
        && positive_u32(metadata, "max_unique_recipients_per_hour").is_some()
}

fn valid_outbound_abuse_metadata(metadata: &serde_json::Value) -> bool {
    has_exact_keys(
        metadata,
        &[
            "campaign_min_messages_per_hour",
            "rotating_recipient_new_ratio",
            "event_cooldown_minutes",
        ],
    ) && positive_u32(metadata, "campaign_min_messages_per_hour").is_some()
        && bounded_ratio(metadata, "rotating_recipient_new_ratio").is_some()
        && positive_i64(metadata, "event_cooldown_minutes").is_some()
}

fn valid_sender_reputation_metadata(metadata: &serde_json::Value) -> bool {
    has_exact_keys(metadata, &["bounce_failures_per_hour"])
        && positive_u32(metadata, "bounce_failures_per_hour").is_some()
}

fn has_exact_keys(metadata: &serde_json::Value, expected: &[&str]) -> bool {
    let Some(object) = metadata.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
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
    use uuid::Uuid;

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
            recipient_domain_metrics: vec![OutboundRecipientDomainMetrics {
                recipient_domain: "recipient.test".to_string(),
                recipient_count: 5,
                unique_recipient_count: 5,
                new_recipient_count: 1,
            }],
            signals: OutboundThreatSignals::default(),
            policy_thresholds: OutboundPolicyThresholds::default(),
            approved_senders: vec![approval(now)],
            now,
            existing_event: None,
        }
    }

    fn rule_with_metadata(metadata: serde_json::Value) -> PolicyRule {
        serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "name": "phase 6 thresholds",
            "priority": 1,
            "enabled": true,
            "condition": {
                "sender": null,
                "recipient": null,
                "auth": null,
                "content": null,
                "finding": null,
                "scope": "transaction"
            },
            "action": {
                "disposition": "hold",
                "reason_code": "OUTBOUND_POLICY",
                "notify": null,
                "metadata": metadata
            }
        }))
        .expect("test policy rule must deserialize")
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

    #[test]
    fn outbound_policy_thresholds_are_validated_and_applied() {
        let rules = vec![rule_with_metadata(serde_json::json!({
            "max_messages_per_minute": 2,
            "max_messages_per_hour": 5,
            "max_recipients_per_message": 8,
            "max_unique_recipients_per_hour": 13
        }))];
        assert!(validate_outbound_policy_rules(
            BULK_SENDING_POLICY_FAMILY,
            &rules
        ));

        let mut thresholds = OutboundPolicyThresholds::default();
        apply_policy_threshold_rules(&mut thresholds, BULK_SENDING_POLICY_FAMILY, &rules);
        assert_eq!(thresholds.unauthorized_messages_per_minute, 2);
        assert_eq!(thresholds.unauthorized_unique_recipients_per_hour, 13);
    }

    #[test]
    fn outbound_policy_thresholds_reject_unknown_or_invalid_metadata() {
        let invalid = vec![rule_with_metadata(serde_json::json!({
            "max_messages_per_minute": 0,
            "max_messages_per_hour": 5,
            "max_recipients_per_message": 8,
            "max_unique_recipients_per_hour": 13
        }))];
        assert!(!validate_outbound_policy_rules(
            BULK_SENDING_POLICY_FAMILY,
            &invalid
        ));

        let extra_key = vec![rule_with_metadata(serde_json::json!({
            "bounce_failures_per_hour": 25,
            "surprise": true
        }))];
        assert!(!validate_outbound_policy_rules(
            SENDER_REPUTATION_POLICY_FAMILY,
            &extra_key
        ));
    }
}

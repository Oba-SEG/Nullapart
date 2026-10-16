//! Outbound intake — trusted outbound mail routing and signing.
//!
//! Receives authenticated outbound mail from internal connectors/MTAs,
//! validates domain ownership, and routes to delivery (direct MX or smart-host).
//!
//! Signing claims are truthful and fail closed: Mail Core reports DKIM as
//! available only when the caller supplies trusted signing configuration that
//! matches the validated sender domain. Private key material never enters this
//! crate; actual signing happens on the trusted private outbound path
//! (Postfix/Rspamd) with per-domain keys provisioned outside Git through the
//! approved secrets boundary. With no provisioned signer the intake result
//! reports signing unavailable rather than claiming `dkim_enabled`.
//! Follows: docs/phases/PHASE-1-EXECUTION-PLAN.md Work Package 9

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{
    policy::ReasonCode,
    transaction::{DeploymentId, EnvelopeSender, Recipient},
    CustomerId,
};

use crate::outbound_intelligence::{
    evaluate_outbound_intelligence, OutboundBehaviorMetrics, OutboundBehaviorMetricsLookup,
    OutboundDecisionOutcome, OutboundIntelligenceDecision, OutboundIntelligenceInput,
    OutboundRecipientDomainMetrics, OutboundSourceContext, OutboundSourceKind,
    OutboundThreatSignals, PostgresOutboundIntelligenceStore,
};

/// Connector/MTA identity that submitted outbound mail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConnector {
    pub connector_id: String,
    pub customer_id: CustomerId,
    pub deployment_id: DeploymentId,
    pub ip_address: String,
    pub authenticated_as: Option<String>,
    pub connector_type: ConnectorType,
}

/// Type of outbound connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorType {
    /// Internal API submission (e.g., from the Trace UI).
    InternalApi,
    /// SMTP submission from a trusted MTA.
    SmtpMta,
    /// Webhook callback from an integration.
    Webhook,
}

/// Domain validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainValidation {
    pub domain: String,
    pub customer_id: CustomerId,
    pub validated: bool,
    pub validation_source: DomainValidationSource,
    pub validated_at: DateTime<Utc>,
}

/// Source of domain validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainValidationSource {
    /// Domain ownership verified via DNS TXT record.
    DnsTxt,
    /// Domain ownership verified via API confirmation.
    ApiConfirmation,
    /// Domain pre-configured in customer setup.
    PreConfigured,
}

/// Domain authorization type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DomainAuthorization {
    /// Verified customer domain authorized for inbound and outbound mail.
    Internal,
    /// Send-only — can send but cannot receive.
    SendOnly,
}

/// Outbound intake request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundIntakeRequest {
    pub connector: OutboundConnector,
    pub envelope_sender: EnvelopeSender,
    pub recipients: Vec<Recipient>,
    pub message_id: Option<String>,
    pub content_hash: String,
}

/// Outbound intake result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundIntakeResult {
    pub transaction_id: String,
    pub disposition: OutboundDisposition,
    pub reason_code: ReasonCode,
    pub routing: OutboundRouting,
    pub signing: OutboundSigning,
    pub validated_at: DateTime<Utc>,
}

/// Outbound disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundDisposition {
    /// Message accepted for delivery.
    Accepted,
    /// Message rejected (policy or validation failure).
    Rejected,
    /// Message deferred (temporary failure).
    Deferred,
}

/// Routing decision for outbound delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundRouting {
    pub method: RoutingMethod,
    pub target: String,
    pub port: u16,
    pub use_tls: bool,
}

/// Routing method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMethod {
    /// Direct MX lookup and delivery.
    DirectMx,
    /// Via smart-host (e.g., SES, Mailgun).
    SmartHost,
    /// Internal routing (loopback).
    Internal,
}

/// Trusted outbound signing state for a validated intake.
///
/// Reported truthfully from [`OutboundSigningConfig`]; never derived from
/// untrusted message headers or from the mere existence of a sender domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundSigning {
    pub dkim_enabled: bool,
    pub dkim_status: DkimSigningStatus,
    pub dkim_domain: Option<String>,
    pub dkim_selector: Option<String>,
    pub spf_helo: Option<String>,
}

/// Whether a trusted outbound DKIM signer is configured and available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkimSigningStatus {
    /// A trusted, key-backed signer for this sending domain is provisioned on
    /// the private outbound path.
    Available,
    /// No trusted signer is provisioned; outbound DKIM signing fails closed
    /// and must surface as unavailable.
    Unavailable,
}

/// Trusted outbound signing configuration supplied by the authenticated
/// server stage that calls [`validate_outbound`].
///
/// Nullapart never derives signing claims from untrusted message headers or
/// from the mere existence of an envelope sender domain. Real per-domain key
/// material is provisioned outside Git through the approved secrets boundary
/// and mounted into the trusted private outbound path (Rspamd/Postfix). This
/// pure structure only reports whether that trusted provisioning exists. The
/// default configuration reports signing unavailable, so outbound signing
/// fails closed instead of silently claiming `dkim_enabled = true`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundSigningConfig {
    /// Trusted provisioned DKIM signer, when a real key-backed signer exists
    /// for the sending domain on the private outbound path.
    pub dkim: Option<ProvisionedDkimSigner>,
    /// Commissioned HELO identity for outbound SMTP, when separately
    /// provisioned. Never derived from envelope/header sender data.
    pub helo_identity: Option<String>,
}

/// A DKIM signing identity that a trusted deployment stage has confirmed is
/// available for one sending domain.
///
/// Metadata only: the private key never enters this structure or Mail Core;
/// it stays with the outbound signer behind the secrets boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionedDkimSigner {
    /// Sending domain the provisioned key is valid for.
    pub domain: String,
    /// Published selector for the provisioned key.
    pub selector: String,
}

/// Derive the outbound signing report from trusted deployment provisioning.
///
/// Pure and deterministic: signing is available only when a provisioned
/// signer's domain matches the validated sender domain. A missing or
/// mismatched signer fails closed as unavailable.
pub fn outbound_signing(sender_domain: &str, config: &OutboundSigningConfig) -> OutboundSigning {
    let sender = sender_domain.trim();
    let matched = config.dkim.as_ref().filter(|signer| {
        !signer.selector.trim().is_empty() && signer.domain.trim().eq_ignore_ascii_case(sender)
    });
    let spf_helo = config
        .helo_identity
        .as_deref()
        .map(str::trim)
        .filter(|identity| !identity.is_empty())
        .map(str::to_string);
    match matched {
        Some(signer) => OutboundSigning {
            dkim_enabled: true,
            dkim_status: DkimSigningStatus::Available,
            dkim_domain: Some(signer.domain.trim().to_string()),
            dkim_selector: Some(signer.selector.trim().to_string()),
            spf_helo,
        },
        None => OutboundSigning {
            dkim_enabled: false,
            dkim_status: DkimSigningStatus::Unavailable,
            dkim_domain: None,
            dkim_selector: None,
            spf_helo,
        },
    }
}

/// Phase 6 behaviour/threat snapshot supplied by trusted server stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundIntelligenceSnapshot {
    pub metrics: OutboundBehaviorMetrics,
    pub signals: OutboundThreatSignals,
    pub observed_at: DateTime<Utc>,
}

/// Outbound validation plus the Phase 6 intelligence decision used to contain
/// bulk abuse or compromised senders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundIntakeWithIntelligence {
    pub intake: OutboundIntakeResult,
    pub intelligence: OutboundIntelligenceDecision,
}

/// Validate an outbound intake request against trusted domain authorization.
///
/// The general admission boundary has no key-backed signer attached, so it
/// reports signing unavailable. The private delivery stage must use
/// [`validate_outbound_with_signing_config`] only after it has selected an
/// actual provisioned signer.
pub fn validate_outbound(
    request: &OutboundIntakeRequest,
    allowed_domains: &[DomainValidation],
    authorization: &DomainAuthorization,
) -> Result<OutboundIntakeResult, OutboundError> {
    validate_outbound_with_signing_config(
        request,
        allowed_domains,
        authorization,
        &OutboundSigningConfig::default(),
    )
}

/// Validate an outbound intake request using trusted signing provisioning.
///
/// `signing_config` must originate in authenticated server configuration that
/// reflects actual key provisioning on the private outbound path. It is never
/// populated from connector or message data.
pub fn validate_outbound_with_signing_config(
    request: &OutboundIntakeRequest,
    allowed_domains: &[DomainValidation],
    authorization: &DomainAuthorization,
    signing_config: &OutboundSigningConfig,
) -> Result<OutboundIntakeResult, OutboundError> {
    if request.connector.connector_id.trim().is_empty()
        || request
            .connector
            .authenticated_as
            .as_deref()
            .map(str::trim)
            .filter(|identity| !identity.is_empty())
            .is_none()
    {
        return Err(OutboundError::NotAuthenticated);
    }

    if request
        .connector
        .ip_address
        .parse::<std::net::IpAddr>()
        .is_err()
    {
        return Err(OutboundError::InvalidSourceAddress);
    }

    if request.connector.deployment_id.0.trim().is_empty() {
        return Err(OutboundError::DeploymentNotAuthorized);
    }

    // Extract sender domain
    let sender_addr = request.envelope_sender.address().to_lowercase();
    let sender_domain = sender_addr.rsplit('@').next().unwrap_or("");

    // Validate domain ownership
    let domain_valid = allowed_domains.iter().find(|d| {
        d.domain.to_lowercase() == sender_domain
            && d.validated
            && d.customer_id == request.connector.customer_id
    });

    let _domain = match domain_valid {
        Some(d) => d,
        None => {
            return Err(OutboundError::DomainNotAuthorized(
                sender_domain.to_string(),
            ));
        },
    };

    // Validate domain authorization
    match authorization {
        // Both documented domain types are permitted to originate outbound
        // mail. Their inbound behavior is enforced by the recipient-domain
        // path, not by this external-delivery admission boundary.
        DomainAuthorization::Internal | DomainAuthorization::SendOnly => {},
    }

    // Validate recipients exist and are syntactically routable.
    if request.recipients.is_empty() {
        return Err(OutboundError::NoRecipients);
    }
    if request.recipients.iter().any(|recipient| {
        let address = recipient.address.trim();
        let mut parts = address.rsplitn(2, '@');
        let domain = parts.next().unwrap_or("");
        let local = parts.next().unwrap_or("");
        local.is_empty() || domain.is_empty() || !domain.contains('.')
    }) {
        return Err(OutboundError::InvalidRecipient);
    }

    // Determine routing
    let routing = OutboundRouting {
        method: RoutingMethod::DirectMx,
        target: request.recipients[0]
            .address
            .rsplit('@')
            .next()
            .unwrap_or("")
            .to_string(),
        port: 25,
        use_tls: true,
    };

    // Signing is reported truthfully from trusted provisioning only. Mail
    // Core never fabricates a DKIM-enabled claim from the sender domain; a
    // missing provisioned signer fails closed as unavailable.
    let signing = outbound_signing(sender_domain, signing_config);

    Ok(OutboundIntakeResult {
        transaction_id: uuid::Uuid::new_v4().to_string(),
        disposition: OutboundDisposition::Accepted,
        reason_code: ReasonCode::allowed(),
        routing,
        signing,
        validated_at: Utc::now(),
    })
}

/// Validate outbound intake and apply Phase 6 intelligence after the trusted
/// connector/source/domain checks have passed.
pub async fn validate_outbound_with_intelligence(
    request: &OutboundIntakeRequest,
    allowed_domains: &[DomainValidation],
    authorization: &DomainAuthorization,
    signing_config: &OutboundSigningConfig,
    snapshot: OutboundIntelligenceSnapshot,
    store: &PostgresOutboundIntelligenceStore,
) -> Result<OutboundIntakeWithIntelligence, OutboundError> {
    let intake = validate_outbound_with_signing_config(
        request,
        allowed_domains,
        authorization,
        signing_config,
    )?;
    let source = OutboundSourceContext {
        deployment_id: request.connector.deployment_id.clone(),
        customer_id: request.connector.customer_id.clone(),
        source_kind: OutboundSourceKind::from(request.connector.connector_type),
        source_id: request.connector.connector_id.clone(),
        source_ip: Some(request.connector.ip_address.clone()),
    };
    let sender_address = request.envelope_sender.address().to_string();
    let sending_domain = sender_address.rsplit('@').next().unwrap_or("").to_string();
    let recipient_domain_metrics = recipient_domain_metrics(&request.recipients);
    let approved_senders = store
        .load_approved_senders(&source, &sender_address, snapshot.observed_at)
        .await
        .map_err(|_| OutboundError::Internal("outbound intelligence unavailable".to_string()))?;
    let policy_thresholds = store
        .load_policy_thresholds(&source)
        .await
        .map_err(|_| OutboundError::Internal("outbound intelligence unavailable".to_string()))?;
    let persisted_metrics = store
        .load_behavior_metrics(&OutboundBehaviorMetricsLookup {
            source: source.clone(),
            sender_address: sender_address.clone(),
            sending_domain: sending_domain.clone(),
            campaign_fingerprint: snapshot.signals.campaign_fingerprint.clone(),
            now: snapshot.observed_at,
            current_recipient_count: request.recipients.len() as u32,
            current_recipient_domain_count: recipient_domain_metrics.len() as u32,
        })
        .await
        .map_err(|_| OutboundError::Internal("outbound intelligence unavailable".to_string()))?;
    let mut input = OutboundIntelligenceInput {
        source,
        sender_address,
        sending_domain,
        metrics: merge_behavior_metrics(snapshot.metrics, persisted_metrics),
        recipient_domain_metrics,
        signals: snapshot.signals,
        policy_thresholds,
        approved_senders,
        now: snapshot.observed_at,
        existing_event: None,
    };
    let mut intelligence = evaluate_outbound_intelligence(&input);
    if let Some(event_key) = intelligence.event_key.clone() {
        if let Some(existing_event) = store
            .load_existing_event(&input.source, &event_key, input.now)
            .await
            .map_err(|_| OutboundError::Internal("outbound intelligence unavailable".to_string()))?
        {
            input.existing_event = Some(existing_event);
            intelligence = evaluate_outbound_intelligence(&input);
        }
    }
    store
        .persist_decision(&input, &intelligence)
        .await
        .map_err(|_| OutboundError::Internal("outbound intelligence unavailable".to_string()))?;

    Ok(OutboundIntakeWithIntelligence {
        intake: apply_intelligence_disposition(intake, &intelligence),
        intelligence,
    })
}

fn recipient_domain_metrics(recipients: &[Recipient]) -> Vec<OutboundRecipientDomainMetrics> {
    let mut counts = BTreeMap::<String, u32>::new();
    for recipient in recipients {
        let Some((_, domain)) = recipient.address.rsplit_once('@') else {
            continue;
        };
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() || domain.len() > 253 {
            continue;
        }
        *counts.entry(domain).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(recipient_domain, count)| OutboundRecipientDomainMetrics {
            recipient_domain,
            recipient_count: count,
            unique_recipient_count: count,
            new_recipient_count: 0,
        })
        .collect()
}

fn merge_behavior_metrics(
    snapshot: OutboundBehaviorMetrics,
    persisted: OutboundBehaviorMetrics,
) -> OutboundBehaviorMetrics {
    OutboundBehaviorMetrics {
        messages_last_minute: snapshot
            .messages_last_minute
            .max(persisted.messages_last_minute),
        messages_last_hour: snapshot
            .messages_last_hour
            .max(persisted.messages_last_hour),
        recipients_this_message: snapshot
            .recipients_this_message
            .max(persisted.recipients_this_message),
        unique_recipients_last_hour: snapshot
            .unique_recipients_last_hour
            .max(persisted.unique_recipients_last_hour),
        new_recipients_last_hour: snapshot
            .new_recipients_last_hour
            .max(persisted.new_recipients_last_hour),
        recipient_domain_count_last_hour: snapshot
            .recipient_domain_count_last_hour
            .max(persisted.recipient_domain_count_last_hour),
        campaign_messages_last_hour: snapshot
            .campaign_messages_last_hour
            .max(persisted.campaign_messages_last_hour),
        bounce_failures_last_hour: snapshot
            .bounce_failures_last_hour
            .max(persisted.bounce_failures_last_hour),
    }
}

fn apply_intelligence_disposition(
    mut intake: OutboundIntakeResult,
    intelligence: &OutboundIntelligenceDecision,
) -> OutboundIntakeResult {
    match intelligence.outcome {
        OutboundDecisionOutcome::Allow | OutboundDecisionOutcome::Warn => {},
        OutboundDecisionOutcome::Throttle | OutboundDecisionOutcome::Defer => {
            intake.disposition = OutboundDisposition::Deferred;
            intake.reason_code = intelligence.reason_code.clone();
        },
        OutboundDecisionOutcome::Hold
        | OutboundDecisionOutcome::BlockSender
        | OutboundDecisionOutcome::SuspendOutbound => {
            intake.disposition = OutboundDisposition::Rejected;
            intake.reason_code = intelligence.reason_code.clone();
        },
    }
    intake
}

impl From<ConnectorType> for OutboundSourceKind {
    fn from(value: ConnectorType) -> Self {
        match value {
            ConnectorType::InternalApi => Self::InternalApi,
            ConnectorType::SmtpMta => Self::SmtpMta,
            ConnectorType::Webhook => Self::Webhook,
        }
    }
}

/// Outbound error types.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OutboundError {
    #[error("domain not authorized: {0}")]
    DomainNotAuthorized(String),

    #[error("no valid recipients")]
    NoRecipients,

    #[error("connector not authenticated")]
    NotAuthenticated,

    #[error("invalid connector source address")]
    InvalidSourceAddress,

    #[error("connector deployment is not authorized")]
    DeploymentNotAuthorized,

    #[error("invalid outbound recipient")]
    InvalidRecipient,

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connector() -> OutboundConnector {
        OutboundConnector {
            connector_id: "conn-1".to_string(),
            customer_id: CustomerId::new("cust-a"),
            deployment_id: DeploymentId::new("CZA-1"),
            ip_address: "10.0.0.1".to_string(),
            authenticated_as: Some("api-key-123".to_string()),
            connector_type: ConnectorType::InternalApi,
        }
    }

    fn test_domains() -> Vec<DomainValidation> {
        vec![DomainValidation {
            domain: "customer-a.com".to_string(),
            customer_id: CustomerId::new("cust-a"),
            validated: true,
            validation_source: DomainValidationSource::DnsTxt,
            validated_at: Utc::now(),
        }]
    }

    #[test]
    fn valid_outbound_accepted() {
        let request = OutboundIntakeRequest {
            connector: test_connector(),
            envelope_sender: EnvelopeSender::new("sender@customer-a.com"),
            recipients: vec![Recipient {
                address: "user@external.com".to_string(),
                orcpt: None,
                notify: None,
            }],
            message_id: None,
            content_hash: "abc".to_string(),
        };
        let result = validate_outbound(&request, &test_domains(), &DomainAuthorization::Internal);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.disposition, OutboundDisposition::Accepted);
        assert!(!result.signing.dkim_enabled);
        assert_eq!(result.signing.dkim_status, DkimSigningStatus::Unavailable);
        assert_eq!(result.signing.dkim_domain, None);
        assert_eq!(result.signing.dkim_selector, None);
        assert_eq!(result.signing.spf_helo, None);
    }

    #[test]
    fn signing_is_available_only_for_a_matching_trusted_provisioned_domain() {
        let config = OutboundSigningConfig {
            dkim: Some(ProvisionedDkimSigner {
                domain: "customer-a.com".to_string(),
                selector: "s2026".to_string(),
            }),
            helo_identity: Some("mxout-za-a-01.nullapart.com".to_string()),
        };

        let signing = outbound_signing("customer-a.com", &config);

        assert!(signing.dkim_enabled);
        assert_eq!(signing.dkim_status, DkimSigningStatus::Available);
        assert_eq!(signing.dkim_domain.as_deref(), Some("customer-a.com"));
        assert_eq!(signing.dkim_selector.as_deref(), Some("s2026"));
        assert_eq!(
            signing.spf_helo.as_deref(),
            Some("mxout-za-a-01.nullapart.com")
        );
    }

    #[test]
    fn signing_fails_closed_when_the_provisioned_domain_does_not_match() {
        let config = OutboundSigningConfig {
            dkim: Some(ProvisionedDkimSigner {
                domain: "other-customer.com".to_string(),
                selector: "s2026".to_string(),
            }),
            helo_identity: None,
        };

        let signing = outbound_signing("customer-a.com", &config);

        assert!(!signing.dkim_enabled);
        assert_eq!(signing.dkim_status, DkimSigningStatus::Unavailable);
        assert_eq!(signing.dkim_domain, None);
        assert_eq!(signing.dkim_selector, None);
    }

    #[test]
    fn unauthenticated_connector_rejected() {
        let mut connector = test_connector();
        connector.authenticated_as = None;
        let request = OutboundIntakeRequest {
            connector,
            envelope_sender: EnvelopeSender::new("sender@customer-a.com"),
            recipients: vec![Recipient {
                address: "user@external.com".to_string(),
                orcpt: None,
                notify: None,
            }],
            message_id: None,
            content_hash: "abc".to_string(),
        };
        let result = validate_outbound(&request, &test_domains(), &DomainAuthorization::Internal);
        assert!(matches!(result, Err(OutboundError::NotAuthenticated)));
    }

    #[test]
    fn unauthorized_domain_rejected() {
        let request = OutboundIntakeRequest {
            connector: test_connector(),
            envelope_sender: EnvelopeSender::new("sender@evil.com"),
            recipients: vec![Recipient {
                address: "user@external.com".to_string(),
                orcpt: None,
                notify: None,
            }],
            message_id: None,
            content_hash: "abc".to_string(),
        };
        let result = validate_outbound(&request, &test_domains(), &DomainAuthorization::Internal);
        assert!(matches!(result, Err(OutboundError::DomainNotAuthorized(_))));
    }

    #[test]
    fn internal_domain_is_allowed_for_external_delivery() {
        let request = OutboundIntakeRequest {
            connector: test_connector(),
            envelope_sender: EnvelopeSender::new("sender@customer-a.com"),
            recipients: vec![Recipient {
                address: "user@external.com".to_string(),
                orcpt: None,
                notify: None,
            }],
            message_id: None,
            content_hash: "abc".to_string(),
        };
        let result = validate_outbound(&request, &test_domains(), &DomainAuthorization::Internal);
        assert!(result.is_ok());
    }

    #[test]
    fn no_recipients_rejected() {
        let request = OutboundIntakeRequest {
            connector: test_connector(),
            envelope_sender: EnvelopeSender::new("sender@customer-a.com"),
            recipients: vec![],
            message_id: None,
            content_hash: "abc".to_string(),
        };
        let result = validate_outbound(&request, &test_domains(), &DomainAuthorization::Internal);
        assert!(matches!(result, Err(OutboundError::NoRecipients)));
    }

    #[test]
    fn intelligence_decision_updates_transport_disposition() {
        let request = OutboundIntakeRequest {
            connector: test_connector(),
            envelope_sender: EnvelopeSender::new("sender@customer-a.com"),
            recipients: vec![Recipient {
                address: "user@external.com".to_string(),
                orcpt: None,
                notify: None,
            }],
            message_id: None,
            content_hash: "abc".to_string(),
        };
        let intake = validate_outbound(&request, &test_domains(), &DomainAuthorization::Internal)
            .expect("base validation must pass");
        let intelligence = OutboundIntelligenceDecision {
            outcome: OutboundDecisionOutcome::Hold,
            reason_code: ReasonCode::new("OUTBOUND_UNAUTHORIZED_BULK"),
            event_type: None,
            event_key: None,
            aggregate_into_existing_event: false,
            approval_used: false,
            customer_id: CustomerId::new("cust-a"),
            deployment_id: DeploymentId::new("CZA-1"),
        };

        let updated = apply_intelligence_disposition(intake, &intelligence);

        assert_eq!(updated.disposition, OutboundDisposition::Rejected);
        assert_eq!(
            updated.reason_code,
            ReasonCode::new("OUTBOUND_UNAUTHORIZED_BULK")
        );
    }

    #[test]
    fn recipient_domain_metrics_store_domains_not_addresses() {
        let metrics = recipient_domain_metrics(&[
            Recipient {
                address: "one@Example.COM".to_string(),
                orcpt: None,
                notify: None,
            },
            Recipient {
                address: "two@example.com".to_string(),
                orcpt: None,
                notify: None,
            },
            Recipient {
                address: "missing-at-sign".to_string(),
                orcpt: None,
                notify: None,
            },
        ]);

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].recipient_domain, "example.com");
        assert_eq!(metrics[0].recipient_count, 2);
        assert_eq!(metrics[0].unique_recipient_count, 2);
        assert_eq!(metrics[0].new_recipient_count, 0);
    }

    #[test]
    fn behavior_metrics_merge_uses_strongest_trusted_count() {
        let snapshot = OutboundBehaviorMetrics {
            messages_last_minute: 3,
            messages_last_hour: 30,
            recipients_this_message: 2,
            unique_recipients_last_hour: 20,
            new_recipients_last_hour: 15,
            recipient_domain_count_last_hour: 4,
            campaign_messages_last_hour: 9,
            bounce_failures_last_hour: 1,
        };
        let persisted = OutboundBehaviorMetrics {
            messages_last_minute: 8,
            messages_last_hour: 28,
            recipients_this_message: 2,
            unique_recipients_last_hour: 25,
            new_recipients_last_hour: 10,
            recipient_domain_count_last_hour: 6,
            campaign_messages_last_hour: 7,
            bounce_failures_last_hour: 3,
        };

        let merged = merge_behavior_metrics(snapshot, persisted);

        assert_eq!(merged.messages_last_minute, 8);
        assert_eq!(merged.messages_last_hour, 30);
        assert_eq!(merged.unique_recipients_last_hour, 25);
        assert_eq!(merged.new_recipients_last_hour, 15);
        assert_eq!(merged.recipient_domain_count_last_hour, 6);
        assert_eq!(merged.campaign_messages_last_hour, 9);
        assert_eq!(merged.bounce_failures_last_hour, 3);
    }
}

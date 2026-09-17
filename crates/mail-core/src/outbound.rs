//! Outbound intake — trusted outbound mail routing and signing.
//!
//! Receives authenticated outbound mail from internal connectors/MTAs,
//! validates domain ownership, and routes to delivery (direct MX or smart-host).
//! Follows: docs/phases/PHASE-1-EXECUTION-PLAN.md Work Package 9

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{
    policy::ReasonCode,
    transaction::{DeploymentId, EnvelopeSender, Recipient},
    CustomerId,
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
    /// Internal-only — cannot be used for external delivery.
    Internal,
    /// Send-only — can send but cannot receive.
    SendOnly,
    /// Full send and receive.
    Full,
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

/// Signing configuration for outbound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundSigning {
    pub dkim_enabled: bool,
    pub dkim_domain: Option<String>,
    pub dkim_selector: Option<String>,
    pub spf_helo: Option<String>,
}

/// Validate an outbound intake request.
pub fn validate_outbound(
    request: &OutboundIntakeRequest,
    allowed_domains: &[DomainValidation],
    authorization: &DomainAuthorization,
) -> Result<OutboundIntakeResult, OutboundError> {
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
        DomainAuthorization::Internal => {
            return Err(OutboundError::DomainNotAuthorized(
                "Internal-only domain cannot send externally".to_string(),
            ));
        },
        DomainAuthorization::SendOnly => {
            // Send-only is allowed for outbound
        },
        DomainAuthorization::Full => {
            // Full access
        },
    }

    // Validate recipients exist
    if request.recipients.is_empty() {
        return Err(OutboundError::NoRecipients);
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

    // Signing configuration
    let signing = OutboundSigning {
        dkim_enabled: true,
        dkim_domain: Some(sender_domain.to_string()),
        dkim_selector: Some("nullapart".to_string()),
        spf_helo: Some(sender_domain.to_string()),
    };

    Ok(OutboundIntakeResult {
        transaction_id: uuid::Uuid::new_v4().to_string(),
        disposition: OutboundDisposition::Accepted,
        reason_code: ReasonCode::allowed(),
        routing,
        signing,
        validated_at: Utc::now(),
    })
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
        let result = validate_outbound(&request, &test_domains(), &DomainAuthorization::Full);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.disposition, OutboundDisposition::Accepted);
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
        let result = validate_outbound(&request, &test_domains(), &DomainAuthorization::Full);
        assert!(matches!(result, Err(OutboundError::DomainNotAuthorized(_))));
    }

    #[test]
    fn internal_only_rejected_for_external() {
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
        assert!(matches!(result, Err(OutboundError::DomainNotAuthorized(_))));
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
        let result = validate_outbound(&request, &test_domains(), &DomainAuthorization::Full);
        assert!(matches!(result, Err(OutboundError::NoRecipients)));
    }
}

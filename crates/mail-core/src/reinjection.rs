//! Reinjection and loop prevention
//!
//! Handles trusted reinjection of processed messages back into Postfix.
//! Ensures reinjection cannot loop or be publicly abused.
//! Follows: docs/phases/PHASE-1-EXECUTION-PLAN.md Work Packages 3, 8

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{
    transaction::{CustomerId, DeliveryAttemptId, TransactionId},
    DeploymentId,
};

/// Loop prevention header value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopPreventionHeader {
    /// The header name (e.g., "X-Nullapart-Loop").
    pub name: String,
    /// The header value containing the deployment + transaction ID.
    pub value: String,
    /// When the header was added.
    pub added_at: DateTime<Utc>,
}

impl LoopPreventionHeader {
    /// Create a new loop prevention header.
    pub fn new(deployment_id: &DeploymentId, transaction_id: &TransactionId) -> Self {
        Self {
            name: "X-Nullapart-Loop".to_string(),
            value: format!("{};{}", deployment_id.0, transaction_id.0),
            added_at: Utc::now(),
        }
    }

    /// Parse the header value to extract deployment and transaction IDs.
    pub fn parse(value: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = value.splitn(2, ';').collect();
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }

    /// Check if this header indicates a loop for the given deployment.
    pub fn is_loop(&self, deployment_id: &DeploymentId) -> bool {
        Self::parse(&self.value)
            .map(|(dep, _)| dep == deployment_id.0)
            .unwrap_or(false)
    }
}

/// Reinjection request to Postfix trusted listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinjectionEnvelope {
    /// Transaction ID.
    pub transaction_id: TransactionId,
    /// Tenant message ID.
    pub tenant_message_id: String,
    /// Customer ID.
    pub customer_id: CustomerId,
    /// Deployment ID.
    pub deployment_id: DeploymentId,
    /// Envelope sender.
    pub envelope_sender: String,
    /// Recipients.
    pub recipients: Vec<String>,
    /// Loop prevention header.
    pub loop_prevention: LoopPreventionHeader,
    /// Artifact ID (MIME content reference).
    pub artifact_id: String,
    /// Trace ID.
    pub trace_id: String,
    /// When reinjection was initiated.
    pub initiated_at: DateTime<Utc>,
}

/// Reinjection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinjectionOutcome {
    /// Whether reinjection succeeded.
    pub success: bool,
    /// Postfix queue ID assigned on reinjection.
    pub postfix_queue_id: Option<String>,
    /// Error message if failed.
    pub error: Option<String>,
    /// When reinjection completed.
    pub completed_at: DateTime<Utc>,
    /// Delivery attempt ID.
    pub delivery_attempt_id: DeliveryAttemptId,
}

/// Reinjection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinjectionConfig {
    /// Reinjection endpoint (private, trusted).
    pub endpoint: String,
    /// Loop prevention header name.
    pub loop_prevention_header: String,
    /// Maximum reinjection attempts before deferring.
    pub max_reinjection_attempts: u32,
    /// Timeout for reinjection request in seconds.
    pub reinjection_timeout_secs: u64,
}

impl Default for ReinjectionConfig {
    fn default() -> Self {
        Self {
            endpoint: "127.0.0.1:10026".to_string(),
            loop_prevention_header: "X-Nullapart-Loop".to_string(),
            max_reinjection_attempts: 3,
            reinjection_timeout_secs: 30,
        }
    }
}

/// Validate that a reinjection request is safe (no loop).
pub fn validate_reinjection(
    envelope: &ReinjectionEnvelope,
    deployment_id: &DeploymentId,
) -> Result<(), ReinjectionError> {
    // Check for loop
    if envelope.loop_prevention.is_loop(deployment_id) {
        return Err(ReinjectionError::LoopDetected);
    }

    // Validate sender is not empty
    if envelope.envelope_sender.is_empty() {
        return Err(ReinjectionError::InvalidEnvelope(
            "empty envelope sender".to_string(),
        ));
    }

    // Validate at least one recipient
    if envelope.recipients.is_empty() {
        return Err(ReinjectionError::InvalidEnvelope(
            "no recipients".to_string(),
        ));
    }

    // Validate deployment matches
    if envelope.deployment_id != *deployment_id {
        return Err(ReinjectionError::DeploymentMismatch {
            expected: deployment_id.0.clone(),
            actual: envelope.deployment_id.0.clone(),
        });
    }

    Ok(())
}

/// Reinjection error types.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReinjectionError {
    #[error("reinjection loop detected")]
    LoopDetected,

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("deployment mismatch: expected {expected}, got {actual}")]
    DeploymentMismatch { expected: String, actual: String },

    #[error("reinjection endpoint unavailable: {0}")]
    EndpointUnavailable(String),

    #[error("reinjection timeout after {0}ms")]
    Timeout(u64),

    #[error("max reinjection attempts exceeded: {0}")]
    MaxAttemptsExceeded(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_prevention_header_create_and_parse() {
        let dep = DeploymentId::new("CZA-1");
        let txn = TransactionId::new();
        let header = LoopPreventionHeader::new(&dep, &txn);

        let parsed = LoopPreventionHeader::parse(&header.value).unwrap();
        assert_eq!(parsed.0, "CZA-1");
        assert_eq!(parsed.1, txn.0.to_string());
    }

    #[test]
    fn loop_detection_works() {
        let dep = DeploymentId::new("CZA-1");
        let txn = TransactionId::new();
        let header = LoopPreventionHeader::new(&dep, &txn);

        assert!(header.is_loop(&dep));
        assert!(!header.is_loop(&DeploymentId::new("EU-WEST-1")));
    }

    #[test]
    fn validate_reinjection_rejects_loop() {
        let dep = DeploymentId::new("CZA-1");
        let txn = TransactionId::new();
        let envelope = ReinjectionEnvelope {
            transaction_id: txn.clone(),
            tenant_message_id: "tm-001".to_string(),
            customer_id: nullapart_mail_contracts::CustomerId::new("cust-1"),
            deployment_id: dep.clone(),
            envelope_sender: "sender@example.com".to_string(),
            recipients: vec!["recipient@example.com".to_string()],
            loop_prevention: LoopPreventionHeader::new(&dep, &txn),
            artifact_id: "art-001".to_string(),
            trace_id: "trace-001".to_string(),
            initiated_at: Utc::now(),
        };

        assert!(validate_reinjection(&envelope, &dep).is_err());
    }

    #[test]
    fn validate_reinjection_accepts_valid() {
        let dep = DeploymentId::new("CZA-1");
        let txn = TransactionId::new();
        let envelope = ReinjectionEnvelope {
            transaction_id: txn,
            tenant_message_id: "tm-001".to_string(),
            customer_id: nullapart_mail_contracts::CustomerId::new("cust-1"),
            deployment_id: dep.clone(),
            envelope_sender: "sender@example.com".to_string(),
            recipients: vec!["recipient@example.com".to_string()],
            loop_prevention: LoopPreventionHeader::new(
                &DeploymentId::new("EU-WEST-1"),
                &TransactionId::new(),
            ),
            artifact_id: "art-001".to_string(),
            trace_id: "trace-001".to_string(),
            initiated_at: Utc::now(),
        };

        assert!(validate_reinjection(&envelope, &dep).is_ok());
    }

    #[test]
    fn validate_reinjection_rejects_empty_sender() {
        let dep = DeploymentId::new("CZA-1");
        let txn = TransactionId::new();
        let envelope = ReinjectionEnvelope {
            transaction_id: txn,
            tenant_message_id: "tm-001".to_string(),
            customer_id: nullapart_mail_contracts::CustomerId::new("cust-1"),
            deployment_id: dep.clone(),
            envelope_sender: String::new(),
            recipients: vec!["recipient@example.com".to_string()],
            loop_prevention: LoopPreventionHeader::new(
                &DeploymentId::new("EU-WEST-1"),
                &TransactionId::new(),
            ),
            artifact_id: "art-001".to_string(),
            trace_id: "trace-001".to_string(),
            initiated_at: Utc::now(),
        };

        assert!(validate_reinjection(&envelope, &dep).is_err());
    }

    #[test]
    fn validate_reinjection_rejects_no_recipients() {
        let dep = DeploymentId::new("CZA-1");
        let txn = TransactionId::new();
        let envelope = ReinjectionEnvelope {
            transaction_id: txn,
            tenant_message_id: "tm-001".to_string(),
            customer_id: nullapart_mail_contracts::CustomerId::new("cust-1"),
            deployment_id: dep.clone(),
            envelope_sender: "sender@example.com".to_string(),
            recipients: vec![],
            loop_prevention: LoopPreventionHeader::new(
                &DeploymentId::new("EU-WEST-1"),
                &TransactionId::new(),
            ),
            artifact_id: "art-001".to_string(),
            trace_id: "trace-001".to_string(),
            initiated_at: Utc::now(),
        };

        assert!(validate_reinjection(&envelope, &dep).is_err());
    }
}

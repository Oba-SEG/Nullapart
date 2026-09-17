//! Delivery orchestration
//!
//! Manages delivery attempts, retries, bounce handling, and downstream SMTP response mapping.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{
    transaction::{DeliveryStatus, Disposition, EnhancedCode},
    CustomerId, DeploymentId, TenantMessageId, TransactionId,
};

/// Delivery orchestration result for one tenant message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryOrchestrationResult {
    pub tenant_message_id: TenantMessageId,
    pub transaction_id: TransactionId,
    pub customer_id: CustomerId,
    pub disposition: Disposition,
    pub reason_code: String,
    pub delivery_attempts: Vec<DeliveryAttemptSummary>,
    pub final_status: DeliveryStatus,
    pub final_smtp_code: Option<u32>,
    pub final_smtp_message: Option<String>,
    pub completed_at: DateTime<Utc>,
}

/// Summary of a single delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttemptSummary {
    pub attempt_number: u32,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: DeliveryStatus,
    pub smtp_code: Option<u32>,
    pub smtp_message: Option<String>,
    pub enhanced_code: Option<EnhancedCode>,
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// Reinjection result after Mail Core processes a tenant message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinjectionResult {
    pub success: bool,
    pub postfix_queue_id: Option<String>,
    pub error: Option<String>,
    pub reinjected_at: DateTime<Utc>,
}

/// Delivery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryConfig {
    pub deployment_id: DeploymentId,
    /// Maximum delivery attempts before bounce.
    pub max_delivery_attempts: u32,
    /// Base retry interval in seconds.
    pub base_retry_interval_secs: u64,
    /// Maximum retry interval in seconds.
    pub max_retry_interval_secs: u64,
    /// Retry backoff multiplier.
    pub retry_backoff_multiplier: f64,
    /// Timeout for downstream SMTP delivery in seconds.
    pub smtp_delivery_timeout_secs: u64,
    /// Reinjection endpoint (private, trusted).
    pub reinjection_endpoint: String,
    /// Loop prevention header name.
    pub loop_prevention_header: String,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            deployment_id: DeploymentId("CZA-1".to_string()),
            max_delivery_attempts: 5,
            base_retry_interval_secs: 300,  // 5 minutes
            max_retry_interval_secs: 14400, // 4 hours
            retry_backoff_multiplier: 2.0,
            smtp_delivery_timeout_secs: 60,
            reinjection_endpoint: "127.0.0.1:10026".to_string(),
            loop_prevention_header: "X-Nullapart-Loop".to_string(),
        }
    }
}

/// Calculate next retry delay based on attempt number and config.
pub fn calculate_retry_delay(attempt_number: u32, config: &DeliveryConfig) -> u64 {
    let delay = config.base_retry_interval_secs as f64
        * config
            .retry_backoff_multiplier
            .powi(attempt_number as i32 - 1);
    (delay as u64).min(config.max_retry_interval_secs)
}

/// Map a downstream SMTP response to a delivery status.
pub fn classify_smtp_response(code: u32) -> DeliveryStatus {
    match code {
        200..=299 => DeliveryStatus::Success,
        400..=499 => DeliveryStatus::TransientFailure,
        500..=599 => DeliveryStatus::PermanentFailure,
        _ => DeliveryStatus::TransientFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_backoff() {
        let config = DeliveryConfig::default();
        assert_eq!(calculate_retry_delay(1, &config), 300);
        assert_eq!(calculate_retry_delay(2, &config), 600);
        assert_eq!(calculate_retry_delay(3, &config), 1200);
        assert_eq!(calculate_retry_delay(4, &config), 2400);
        // Capped at max
        assert_eq!(
            calculate_retry_delay(10, &config),
            config.max_retry_interval_secs
        );
    }

    #[test]
    fn smtp_response_classification() {
        assert_eq!(classify_smtp_response(250), DeliveryStatus::Success);
        assert_eq!(
            classify_smtp_response(452),
            DeliveryStatus::TransientFailure
        );
        assert_eq!(
            classify_smtp_response(550),
            DeliveryStatus::PermanentFailure
        );
    }
}

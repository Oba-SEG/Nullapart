//! Observability and SLI telemetry conventions.
//!
//! Establishes the telemetry contracts required for later Tier-3 SLO activation.
//! Phase 0 does not prove production Tier-3 SLOs but sets the foundation.
//!
//! Application telemetry (docs/11): this crate implements the
//! Sentry-compatible instrumentation layer that emits scrubbed envelopes
//! to the regional SegLumberjack backend — scrub gate, envelope builder,
//! best-effort emitter, capture glue and the local receiver.

use serde::{Deserialize, Serialize};

pub mod capture;
pub mod emitter;
pub mod envelope;
pub mod scrub;

/// Standard service/capability identifier for metrics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceId(pub String);

/// SLI metric type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SliType {
    /// Availability: ratio of successful requests to total requests.
    Availability,
    /// Latency: distribution of request durations.
    Latency,
    /// Throughput: requests per unit time.
    Throughput,
    /// Error rate: ratio of errors to total requests.
    ErrorRate,
    /// Durability: data loss events per time window.
    Durability,
}

/// A single SLI metric data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliMetric {
    pub service: ServiceId,
    pub metric_type: SliType,
    pub value: f64,
    pub unit: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub labels: std::collections::HashMap<String, String>,
}

/// Dependency outcome tag for metric labeling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyOutcome {
    Success,
    Failure,
    Timeout,
    Degraded,
}

/// Standard metric labels for Nullapart services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricLabels {
    pub deployment_id: String,
    pub region: String,
    pub node_id: Option<String>,
    pub release_version: Option<String>,
    pub config_revision: Option<String>,
    pub customer_id: Option<String>,
}

impl MetricLabels {
    pub fn to_hashmap(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        map.insert("deployment_id".to_string(), self.deployment_id.clone());
        map.insert("region".to_string(), self.region.clone());
        if let Some(ref node) = self.node_id {
            map.insert("node_id".to_string(), node.clone());
        }
        if let Some(ref ver) = self.release_version {
            map.insert("release_version".to_string(), ver.clone());
        }
        if let Some(ref rev) = self.config_revision {
            map.insert("config_revision".to_string(), rev.clone());
        }
        if let Some(ref cust) = self.customer_id {
            map.insert("customer_id".to_string(), cust.clone());
        }
        map
    }
}

/// Mail-specific SLI definitions for Phase 1.
pub mod mail_sli {
    use super::*;

    /// Mail pipeline SLI definitions.
    pub const PIPELINE_ACCEPTED: &str = "mail_pipeline_accepted_total";
    pub const PIPELINE_DELIVERED: &str = "mail_pipeline_delivered_total";
    pub const PIPELINE_REJECTED: &str = "mail_pipeline_rejected_total";
    pub const PIPELINE_DEFERRED: &str = "mail_pipeline_deferred_total";
    pub const PIPELINE_QUARANTINED: &str = "mail_pipeline_quarantined_total";

    pub const PIPELINE_LATENCY: &str = "mail_pipeline_latency_ms";
    pub const SCANNER_LATENCY: &str = "mail_scanner_latency_ms";
    pub const POLICY_LATENCY: &str = "mail_policy_latency_ms";

    pub const QUEUE_DEPTH: &str = "mail_queue_depth";
    pub const QUEUE_OLDEST_AGE: &str = "mail_queue_oldest_age_seconds";

    pub const DELIVERY_ATTEMPT_SUCCESS: &str = "mail_delivery_attempt_success_total";
    pub const DELIVERY_ATTEMPT_FAILURE: &str = "mail_delivery_attempt_failure_total";

    /// Dependency metric labels for mail pipeline.
    pub fn dependency_labels(outcome: DependencyOutcome) -> (&'static str, String) {
        (
            "dependency_outcome",
            format!("{:?}", outcome).to_lowercase(),
        )
    }
}

/// Alert threshold convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThreshold {
    pub metric_name: String,
    pub threshold: f64,
    pub window_seconds: u64,
    pub severity: AlertSeverity,
    pub runbook_url: Option<String>,
}

/// Alert severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_labels_to_hashmap() {
        let labels = MetricLabels {
            deployment_id: "CZA-1".to_string(),
            region: "af-south-1".to_string(),
            node_id: Some("mail-1".to_string()),
            release_version: Some("0.1.0".to_string()),
            config_revision: Some("42".to_string()),
            customer_id: None,
        };
        let map = labels.to_hashmap();
        assert_eq!(map.get("deployment_id").unwrap(), "CZA-1");
        assert_eq!(map.get("region").unwrap(), "af-south-1");
        assert_eq!(map.get("node_id").unwrap(), "mail-1");
        assert!(!map.contains_key("customer_id"));
    }
}

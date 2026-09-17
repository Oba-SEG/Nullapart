//! Mail-node runtime contract
//!
//! Defines the deployment contract for a mail node.
//! Follows: docs/phases/PHASE-1-EXECUTION-PLAN.md Work Package 1

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Stable node identity format.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node-{}", self.0)
    }
}

/// Node role: inbound, outbound, or combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Inbound,
    Outbound,
    Combined,
}

/// Node runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailNodeConfig {
    /// Node identity.
    pub node_id: NodeId,
    /// Node role.
    pub role: NodeRole,
    /// Deployment/region identity.
    pub deployment_id: String,
    /// Region.
    pub region: String,
    /// EIP for outbound SMTP identity.
    pub eip_address: Option<String>,
    /// PTR record for EIP.
    pub ptr_record: Option<String>,
    /// HELO identity.
    pub helo_identity: String,
    /// Queue/spool volume mount path.
    pub queue_path: String,
    /// SMTP ports (public).
    pub smtp_ports: Vec<u16>,
    /// Reinjection port (private).
    pub reinjection_port: u16,
    /// Outbound delivery port (private).
    pub outbound_port: u16,
    /// Health check endpoint.
    pub health_endpoint: String,
    /// Release version.
    pub release_version: String,
    /// Config revision.
    pub config_revision: i64,
}

impl Default for MailNodeConfig {
    fn default() -> Self {
        Self {
            node_id: NodeId::new("mail-1"),
            role: NodeRole::Combined,
            deployment_id: "CZA-1".to_string(),
            region: "af-south-1".to_string(),
            eip_address: None,
            ptr_record: None,
            helo_identity: "mail.nullapart.com".to_string(),
            queue_path: "/var/spool/nullapart".to_string(),
            smtp_ports: vec![25, 465, 587],
            reinjection_port: 10026,
            outbound_port: 10027,
            health_endpoint: "/health".to_string(),
            release_version: "0.1.0".to_string(),
            config_revision: 1,
        }
    }
}

/// Node health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealth {
    pub healthy: bool,
    pub node_id: NodeId,
    pub queue_depth: u64,
    pub oldest_queue_age_secs: Option<u64>,
    pub uptime_secs: u64,
    pub config_revision: i64,
    pub checked_at: DateTime<Utc>,
}

/// Node metrics for observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub node_id: NodeId,
    pub smtp_connections_total: u64,
    pub smtp_messages_received: u64,
    pub smtp_messages_delivered: u64,
    pub smtp_messages_deferred: u64,
    pub smtp_messages_bounced: u64,
    pub queue_depth: u64,
    pub queue_oldest_age_secs: Option<u64>,
    pub reinjection_attempts: u64,
    pub reinjection_failures: u64,
    pub mail_core_handoff_success: u64,
    pub mail_core_handoff_failure: u64,
    pub scanner_latency_ms_p99: Option<f64>,
    pub policy_latency_ms_p99: Option<f64>,
    pub measured_at: DateTime<Utc>,
}

/// Port list for the authoritative port configuration.
pub struct PortList;

impl PortList {
    /// Public SMTP ports.
    pub const SMTP_PUBLIC: &'static [u16] = &[25];
    pub const SMTP_SUBMISSION: &'static [u16] = &[587];
    pub const SMTPS: &'static [u16] = &[465];

    /// Private ports (not exposed to internet).
    pub const REINJECTION: u16 = 10026;
    pub const OUTBOUND: u16 = 10027;
    pub const HEALTH: u16 = 8080;
    pub const METRICS: u16 = 9090;

    /// All ports that should be open on a mail node security group.
    pub fn all_public() -> Vec<u16> {
        let mut ports = Vec::new();
        ports.extend(Self::SMTP_PUBLIC);
        ports.extend(Self::SMTP_SUBMISSION);
        ports.extend(Self::SMTPS);
        ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_display() {
        let id = NodeId::new("mail-1");
        assert_eq!(id.to_string(), "node-mail-1");
    }

    #[test]
    fn default_config_is_valid() {
        let config = MailNodeConfig::default();
        assert!(!config.node_id.0.is_empty());
        assert!(!config.helo_identity.is_empty());
        assert!(!config.queue_path.is_empty());
    }

    #[test]
    fn port_list_no_public_reinjection() {
        let public = PortList::all_public();
        assert!(!public.contains(&PortList::REINJECTION));
        assert!(!public.contains(&PortList::OUTBOUND));
    }
}

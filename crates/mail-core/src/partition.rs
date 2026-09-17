//! Tenant message partitioning
//!
//! Per-tenant logical message instances derived from a single inbound transaction.
//! One SMTP DATA transaction may span multiple customers — shared MIME/auth
//! evidence is reused safely while tenant policy/disposition remains isolated.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{
    transaction::{Disposition, Recipient},
    CustomerId, DeploymentId, SecurityFinding, TenantMessageId, TransactionId,
};

/// Result of partitioning one SMTP transaction into tenant message instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionResult {
    /// Original transaction ID.
    pub transaction_id: TransactionId,
    /// Tenant message instances created.
    pub instances: Vec<TenantMessagePartition>,
    /// Recipients that could not be mapped to any tenant.
    pub unmapped_recipients: Vec<Recipient>,
    /// Partition completed at.
    pub partitioned_at: DateTime<Utc>,
}

/// One tenant message instance within a partitioned transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMessagePartition {
    /// Unique tenant message ID.
    pub tenant_message_id: TenantMessageId,
    /// Parent transaction ID.
    pub transaction_id: TransactionId,
    /// Customer/tenant this instance belongs to.
    pub customer_id: CustomerId,
    /// Customer-scoped recipients only.
    pub recipients: Vec<Recipient>,
    /// Shared findings that are content-intrinsic (safe across tenants).
    pub shared_findings: Vec<SecurityFinding>,
    /// Tenant-specific findings (added during per-tenant processing).
    pub tenant_findings: Vec<SecurityFinding>,
    /// Initial disposition (subject to per-tenant policy).
    pub disposition: Disposition,
    /// Tenant-specific policy revision.
    pub policy_revision: Option<i64>,
    /// When partitioned.
    pub created_at: DateTime<Utc>,
}

/// Tenant/recipient mapping resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientMapping {
    pub recipient: Recipient,
    pub customer_id: Option<CustomerId>,
    pub domain: String,
    pub mapped: bool,
    pub mapping_source: MappingSource,
}

/// Source of recipient-to-tenant mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingSource {
    /// Domain is directly owned by a customer.
    DomainOwnership,
    /// Recipient email matches a known customer alias.
    RecipientAlias,
    /// Default tenant for unclassified mail.
    DefaultTenant,
    /// No mapping found.
    Unmapped,
}

/// Partition configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionConfig {
    pub deployment_id: DeploymentId,
    /// Default customer ID for unmapped recipients.
    pub default_customer_id: Option<CustomerId>,
    /// Whether to reject/unmap recipients that cannot be resolved.
    pub reject_unmapped: bool,
    /// Maximum tenants per transaction.
    pub max_tenants_per_transaction: u32,
}

impl Default for PartitionConfig {
    fn default() -> Self {
        Self {
            deployment_id: DeploymentId("CZA-1".to_string()),
            default_customer_id: None,
            reject_unmapped: false,
            max_tenants_per_transaction: 50,
        }
    }
}

/// Partition error types.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PartitionError {
    #[error("no valid recipients after partitioning")]
    NoValidRecipients,

    #[error("too many tenants: {0} exceeds maximum {1}")]
    TooManyTenants(u32, u32),

    #[error("recipient mapping failed: {0}")]
    MappingFailed(String),

    #[error("customer not found for domain: {0}")]
    CustomerNotFound(String),

    #[error("transaction not found: {0}")]
    TransactionNotFound(String),
}

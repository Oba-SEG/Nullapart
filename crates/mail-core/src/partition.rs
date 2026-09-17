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

/// Domain-to-customer mapping record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainMapping {
    pub domain: String,
    pub customer_id: CustomerId,
    pub mapping_source: MappingSource,
}

/// Tenant resolver: maps recipients to tenants.
pub struct TenantResolver {
    domain_mappings: Vec<DomainMapping>,
    alias_mappings: Vec<(String, CustomerId)>,
    config: PartitionConfig,
}

impl TenantResolver {
    pub fn new(
        domain_mappings: Vec<DomainMapping>,
        alias_mappings: Vec<(String, CustomerId)>,
        config: PartitionConfig,
    ) -> Self {
        Self {
            domain_mappings,
            alias_mappings,
            config,
        }
    }

    /// Extract domain from email address.
    pub fn extract_domain(email: &str) -> Option<String> {
        if email.contains('@') {
            email.rsplit('@').next().map(|d| d.to_lowercase())
        } else {
            None
        }
    }

    /// Map a recipient to a tenant.
    pub fn resolve_recipient(&self, recipient: &Recipient) -> RecipientMapping {
        let domain = Self::extract_domain(&recipient.address).unwrap_or_default();

        // 1. Check domain ownership
        if let Some(mapping) = self.domain_mappings.iter().find(|m| m.domain == domain) {
            return RecipientMapping {
                recipient: recipient.clone(),
                customer_id: Some(mapping.customer_id.clone()),
                domain: domain.clone(),
                mapped: true,
                mapping_source: MappingSource::DomainOwnership,
            };
        }

        // 2. Check recipient alias
        let addr_lower = recipient.address.to_lowercase();
        if let Some((_, customer_id)) = self
            .alias_mappings
            .iter()
            .find(|(alias, _)| alias.to_lowercase() == addr_lower)
        {
            return RecipientMapping {
                recipient: recipient.clone(),
                customer_id: Some(customer_id.clone()),
                domain,
                mapped: true,
                mapping_source: MappingSource::RecipientAlias,
            };
        }

        // 3. Default tenant
        if let Some(ref default) = self.config.default_customer_id {
            return RecipientMapping {
                recipient: recipient.clone(),
                customer_id: Some(default.clone()),
                domain,
                mapped: true,
                mapping_source: MappingSource::DefaultTenant,
            };
        }

        // 4. Unmapped
        RecipientMapping {
            recipient: recipient.clone(),
            customer_id: None,
            domain,
            mapped: false,
            mapping_source: MappingSource::Unmapped,
        }
    }

    /// Partition a list of recipients into tenant groups.
    pub fn partition_recipients(
        &self,
        recipients: &[Recipient],
    ) -> Result<PartitionResult, PartitionError> {
        let transaction_id = TransactionId::new();
        let mappings: Vec<RecipientMapping> = recipients
            .iter()
            .map(|r| self.resolve_recipient(r))
            .collect();

        // Group by customer_id
        let mut groups: std::collections::HashMap<String, Vec<Recipient>> =
            std::collections::HashMap::new();
        let mut unmapped = Vec::new();

        for mapping in &mappings {
            match &mapping.customer_id {
                Some(cid) => {
                    groups
                        .entry(cid.0.clone())
                        .or_default()
                        .push(mapping.recipient.clone());
                },
                None => {
                    unmapped.push(mapping.recipient.clone());
                },
            }
        }

        // Check tenant count limit
        if groups.len() as u32 > self.config.max_tenants_per_transaction {
            return Err(PartitionError::TooManyTenants(
                groups.len() as u32,
                self.config.max_tenants_per_transaction,
            ));
        }

        // Check if we have any valid recipients
        if groups.is_empty() && (unmapped.is_empty() || self.config.reject_unmapped) {
            return Err(PartitionError::NoValidRecipients);
        }

        // Create tenant message instances
        let instances: Vec<TenantMessagePartition> = groups
            .into_iter()
            .map(|(customer_id, rcpts)| TenantMessagePartition {
                tenant_message_id: TenantMessageId::new(),
                transaction_id: transaction_id.clone(),
                customer_id: CustomerId::new(&customer_id),
                recipients: rcpts,
                shared_findings: Vec::new(),
                tenant_findings: Vec::new(),
                disposition: Disposition::Allow,
                policy_revision: None,
                created_at: Utc::now(),
            })
            .collect();

        Ok(PartitionResult {
            transaction_id,
            instances,
            unmapped_recipients: unmapped,
            partitioned_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_resolver() -> TenantResolver {
        let domains = vec![
            DomainMapping {
                domain: "customer-a.com".to_string(),
                customer_id: CustomerId::new("cust-a"),
                mapping_source: MappingSource::DomainOwnership,
            },
            DomainMapping {
                domain: "customer-b.com".to_string(),
                customer_id: CustomerId::new("cust-b"),
                mapping_source: MappingSource::DomainOwnership,
            },
        ];
        let aliases = vec![("special@other.com".to_string(), CustomerId::new("cust-a"))];
        TenantResolver::new(domains, aliases, PartitionConfig::default())
    }

    #[test]
    fn domain_extraction() {
        assert_eq!(
            TenantResolver::extract_domain("user@example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(TenantResolver::extract_domain("invalid"), None);
    }

    #[test]
    fn resolve_by_domain() {
        let resolver = test_resolver();
        let rcpt = Recipient {
            address: "user@customer-a.com".to_string(),
            orcpt: None,
            notify: None,
        };
        let mapping = resolver.resolve_recipient(&rcpt);
        assert!(mapping.mapped);
        assert_eq!(mapping.customer_id.unwrap().0, "cust-a");
        assert_eq!(mapping.mapping_source, MappingSource::DomainOwnership);
    }

    #[test]
    fn resolve_by_alias() {
        let resolver = test_resolver();
        let rcpt = Recipient {
            address: "special@other.com".to_string(),
            orcpt: None,
            notify: None,
        };
        let mapping = resolver.resolve_recipient(&rcpt);
        assert!(mapping.mapped);
        assert_eq!(mapping.customer_id.unwrap().0, "cust-a");
        assert_eq!(mapping.mapping_source, MappingSource::RecipientAlias);
    }

    #[test]
    fn unmapped_recipient() {
        let resolver = test_resolver();
        let rcpt = Recipient {
            address: "user@unknown.com".to_string(),
            orcpt: None,
            notify: None,
        };
        let mapping = resolver.resolve_recipient(&rcpt);
        assert!(!mapping.mapped);
        assert!(mapping.customer_id.is_none());
        assert_eq!(mapping.mapping_source, MappingSource::Unmapped);
    }

    #[test]
    fn partition_multi_tenant() {
        let resolver = test_resolver();
        let recipients = vec![
            Recipient {
                address: "a@customer-a.com".to_string(),
                orcpt: None,
                notify: None,
            },
            Recipient {
                address: "b@customer-b.com".to_string(),
                orcpt: None,
                notify: None,
            },
            Recipient {
                address: "c@customer-a.com".to_string(),
                orcpt: None,
                notify: None,
            },
        ];
        let result = resolver.partition_recipients(&recipients).unwrap();
        assert_eq!(result.instances.len(), 2);
        assert!(result.unmapped_recipients.is_empty());

        // Find cust-a instance
        let cust_a = result
            .instances
            .iter()
            .find(|i| i.customer_id.0 == "cust-a")
            .unwrap();
        assert_eq!(cust_a.recipients.len(), 2);

        // Find cust-b instance
        let cust_b = result
            .instances
            .iter()
            .find(|i| i.customer_id.0 == "cust-b")
            .unwrap();
        assert_eq!(cust_b.recipients.len(), 1);
    }

    #[test]
    fn partition_rejects_unmapped_when_configured() {
        let domains = vec![];
        let aliases = vec![];
        let config = PartitionConfig {
            reject_unmapped: true,
            ..Default::default()
        };
        let resolver = TenantResolver::new(domains, aliases, config);
        let recipients = vec![Recipient {
            address: "user@unknown.com".to_string(),
            orcpt: None,
            notify: None,
        }];
        assert!(resolver.partition_recipients(&recipients).is_err());
    }

    #[test]
    fn partition_too_many_tenants() {
        let recipients: Vec<Recipient> = (0..5)
            .map(|i| Recipient {
                address: format!("user@tenant-{}.com", i),
                orcpt: None,
                notify: None,
            })
            .collect();
        // This won't fail because unmapped go to default, but if we add domains:
        let domains: Vec<DomainMapping> = (0..5)
            .map(|i| DomainMapping {
                domain: format!("tenant-{}.com", i),
                customer_id: CustomerId::new(&format!("cust-{}", i)),
                mapping_source: MappingSource::DomainOwnership,
            })
            .collect();
        let resolver = TenantResolver::new(
            domains,
            vec![],
            PartitionConfig {
                max_tenants_per_transaction: 2,
                ..Default::default()
            },
        );
        assert!(resolver.partition_recipients(&recipients).is_err());
    }
}

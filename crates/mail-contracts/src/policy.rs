//! Policy and Configuration types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Policy revision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRevision {
    pub id: PolicyRevisionId,
    pub deployment_id: crate::transaction::DeploymentId,
    pub customer_id: Option<crate::transaction::CustomerId>,
    pub version: u32,
    pub rules: Vec<PolicyRule>,
    pub created_at: DateTime<Utc>,
    pub created_by: crate::ActorId,
    pub effective_from: DateTime<Utc>,
    pub effective_to: Option<DateTime<Utc>>,
    pub is_default: bool,
}

/// Policy revision ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyRevisionId(pub Uuid);

impl PolicyRevisionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PolicyRevisionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: PolicyRuleId,
    pub name: String,
    pub priority: i32,
    pub condition: PolicyCondition,
    pub action: PolicyAction,
    pub enabled: bool,
}

/// Policy rule ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyRuleId(pub Uuid);

impl PolicyRuleId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PolicyRuleId {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub sender: Option<SenderCondition>,
    pub recipient: Option<RecipientCondition>,
    pub auth: Option<AuthCondition>,
    pub content: Option<ContentCondition>,
    pub finding: Option<FindingCondition>,
    pub scope: ConditionScope,
}

/// Condition scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionScope {
    Transaction,
    Tenant,
    Recipient,
}

/// Sender condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderCondition {
    pub domain: Option<Vec<String>>,
    pub address: Option<Vec<String>>,
    pub internal: Option<bool>,
    pub authenticated: Option<bool>,
}

/// Recipient condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientCondition {
    pub domain: Option<Vec<String>>,
    pub address: Option<Vec<String>>,
    pub internal: Option<bool>,
}

/// Auth condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCondition {
    pub spf: Option<Vec<crate::transaction::AuthResultType>>,
    pub dkim: Option<Vec<crate::transaction::AuthResultType>>,
    pub dmarc: Option<Vec<crate::transaction::AuthResultType>>,
}

/// Content condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentCondition {
    pub has_attachment: Option<bool>,
    pub attachment_types: Option<Vec<String>>,
    pub size_gt: Option<u64>,
    pub has_url: Option<bool>,
}

/// Finding condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCondition {
    pub scanner: Option<Vec<crate::finding::ScannerType>>,
    pub severity: Option<Vec<crate::finding::FindingSeverity>>,
    pub category: Option<Vec<crate::finding::FindingCategory>>,
    pub false_positive: Option<bool>,
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAction {
    pub disposition: crate::transaction::Disposition,
    pub reason_code: ReasonCode,
    pub notify: Option<Vec<NotifyAction>>,
    pub metadata: Option<serde_json::Value>,
}

/// Notify action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyAction {
    Admin,
    Sender,
    Recipient,
}

/// Reason code for decisions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReasonCode(pub String);

impl ReasonCode {
    pub fn new(code: &str) -> Self {
        Self(code.to_string())
    }

    // Standard reason codes
    pub fn allowed() -> Self {
        Self(String::from("ALLOWED"))
    }
    pub fn quarantine_malware() -> Self {
        Self(String::from("QUARANTINE_MALWARE"))
    }
    pub fn quarantine_phishing() -> Self {
        Self(String::from("QUARANTINE_PHISHING"))
    }
    pub fn quarantine_spam() -> Self {
        Self(String::from("QUARANTINE_SPAM"))
    }
    pub fn reject_spf_fail() -> Self {
        Self(String::from("REJECT_SPF_FAIL"))
    }
    pub fn reject_dkim_fail() -> Self {
        Self(String::from("REJECT_DKIM_FAIL"))
    }
    pub fn reject_dmarc_fail() -> Self {
        Self(String::from("REJECT_DMARC_FAIL"))
    }
    pub fn reject_spoofing() -> Self {
        Self(String::from("REJECT_SPOOFING"))
    }
    pub fn reject_policy() -> Self {
        Self(String::from("REJECT_POLICY"))
    }
    pub fn defer_rate_limit() -> Self {
        Self(String::from("DEFER_RATE_LIMIT"))
    }
    pub fn defer_temporary() -> Self {
        Self(String::from("DEFER_TEMPORARY"))
    }
    pub fn hold_pending() -> Self {
        Self(String::from("HOLD_PENDING"))
    }
}

/// Feature switch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSwitch {
    pub id: FeatureId,
    pub name: String,
    pub description: String,
    pub default_value: FeatureValue,
    pub scope: FeatureScope,
    pub scope_id: Option<String>,
    pub override_value: Option<FeatureValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Feature ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FeatureId(pub String);

impl FeatureId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

/// Feature value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeatureValue {
    Boolean(bool),
    String(String),
    Number(i64),
    Inherit,
}

impl FeatureValue {
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Boolean(true))
    }

    pub fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

/// Feature scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeatureScope {
    System,
    Deployment,
    Tenant,
}

/// Configuration revision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigRevision {
    pub id: ConfigRevisionId,
    pub deployment_id: crate::transaction::DeploymentId,
    pub version: u32,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub created_by: crate::ActorId,
    pub is_last_known_good: bool,
}

/// Configuration revision ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigRevisionId(pub Uuid);

impl ConfigRevisionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ConfigRevisionId {
    fn default() -> Self {
        Self::new()
    }
}

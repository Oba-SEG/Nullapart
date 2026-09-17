//! Audit types for administrative actions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Audit event for administrative actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub timestamp: DateTime<Utc>,
    pub real_actor: Actor,
    pub impersonated_subject: Option<Actor>,
    pub customer_id: Option<crate::transaction::CustomerId>,
    pub deployment_id: crate::transaction::DeploymentId,
    pub action: AuditAction,
    pub resource: AuditResource,
    pub result: AuditResult,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<SessionId>,
    pub trace_id: Option<crate::transaction::TraceId>,
    pub correlation_id: Option<CorrelationId>,
}

/// Audit event ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditEventId(pub Uuid);

impl AuditEventId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for AuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

/// Actor (user or system)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub id: ActorId,
    pub r#type: ActorType,
    pub name: String,
    pub email: Option<String>,
}

/// Actor ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId(pub Uuid);

impl ActorId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ActorId {
    fn default() -> Self {
        Self::new()
    }
}

/// Actor type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    User,
    System,
    ApiKey,
    ServiceAccount,
}

/// Audit action
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditAction(pub String);

impl AuditAction {
    pub fn new(a: &str) -> Self {
        Self(a.to_string())
    }

    // Standard actions
    pub fn create() -> Self {
        Self(String::from("create"))
    }
    pub fn read() -> Self {
        Self(String::from("read"))
    }
    pub fn update() -> Self {
        Self(String::from("update"))
    }
    pub fn delete() -> Self {
        Self(String::from("delete"))
    }
    pub fn login() -> Self {
        Self(String::from("login"))
    }
    pub fn logout() -> Self {
        Self(String::from("logout"))
    }
    pub fn impersonate() -> Self {
        Self(String::from("impersonate"))
    }
    pub fn quarantine() -> Self {
        Self(String::from("quarantine"))
    }
    pub fn release() -> Self {
        Self(String::from("release"))
    }
    pub fn config_change() -> Self {
        Self(String::from("config_change"))
    }
    pub fn policy_change() -> Self {
        Self(String::from("policy_change"))
    }
    pub fn feature_change() -> Self {
        Self(String::from("feature_change"))
    }
    pub fn access_message() -> Self {
        Self(String::from("access_message"))
    }
}

/// Audit resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResource {
    pub resource_type: ResourceType,
    pub resource_id: String,
    pub owner_customer_id: Option<crate::transaction::CustomerId>,
}

/// Resource type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Tenant,
    User,
    Policy,
    Config,
    Feature,
    Message,
    TenantMessage,
    Transaction,
    Domain,
    Connector,
    Quarantine,
}

/// Audit result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    Success,
    Denied,
    Error,
}

/// Session ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Correlation ID for request chains
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(pub String);

impl CorrelationId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

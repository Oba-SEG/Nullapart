//! Event types for durable async processing

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Nullapart event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub event_type: EventType,
    pub version: EventVersion,
    pub deployment_id: crate::transaction::DeploymentId,
    pub customer_id: Option<crate::transaction::CustomerId>,
    pub trace_id: Option<crate::transaction::TraceId>,
    pub transaction_id: Option<crate::transaction::TransactionId>,
    pub tenant_message_id: Option<crate::transaction::TenantMessageId>,
    pub idempotency_key: IdempotencyKey,
    pub data_classification: DataClassification,
    pub payload: EventPayload,
    pub safe_payload: EventSafePayload,
    pub created_at: DateTime<Utc>,
}

/// Event ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub Uuid);

impl EventId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

/// Event type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventType(pub String);

impl EventType {
    pub fn new(t: &str) -> Self {
        Self(t.to_string())
    }

    // Standard event types
    pub fn message_received() -> Self {
        Self(String::from("message.received"))
    }
    pub fn message_accepted() -> Self {
        Self(String::from("message.accepted"))
    }
    pub fn message_quarantined() -> Self {
        Self(String::from("message.quarantined"))
    }
    pub fn message_delivered() -> Self {
        Self(String::from("message.delivered"))
    }
    pub fn message_failed() -> Self {
        Self(String::from("message.failed"))
    }
    pub fn finding_created() -> Self {
        Self(String::from("finding.created"))
    }
    pub fn policy_evaluated() -> Self {
        Self(String::from("policy.evaluated"))
    }
    pub fn config_changed() -> Self {
        Self(String::from("config.changed"))
    }
    pub fn feature_changed() -> Self {
        Self(String::from("feature.changed"))
    }
    pub fn scan_complete() -> Self {
        Self(String::from("scan.complete"))
    }
}

/// Event version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventVersion(pub u32);

impl EventVersion {
    pub fn new(v: u32) -> Self {
        Self(v)
    }

    pub const V1: Self = Self(1);
}

/// Idempotency key
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey(pub String);

impl IdempotencyKey {
    pub fn new(k: &str) -> Self {
        Self(k.to_string())
    }
}

/// Data classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Event payload (contains actual event data)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventPayload {
    MessageReceived(MessageReceivedPayload),
    MessageAccepted(MessageAcceptedPayload),
    MessageQuarantined(MessageQuarantinedPayload),
    MessageDelivered(MessageDeliveredPayload),
    MessageFailed(MessageFailedPayload),
    FindingCreated(FindingCreatedPayload),
    PolicyEvaluated(PolicyEvaluatedPayload),
    ScanComplete(ScanCompletePayload),
    Custom(serde_json::Value),
}

/// Safe payload (for customer-facing/event history)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventSafePayload {
    MessageReceivedSafe(MessageReceivedSafePayload),
    MessageAcceptedSafe(MessageAcceptedSafePayload),
    MessageQuarantinedSafe(MessageQuarantinedSafePayload),
    MessageDeliveredSafe(MessageDeliveredSafePayload),
    MessageFailedSafe(MessageFailedSafePayload),
    FindingCreatedSafe(FindingCreatedSafePayload),
    PolicyEvaluatedSafe(PolicyEvaluatedSafePayload),
    ScanCompleteSafe(ScanCompleteSafePayload),
    None,
}

// Payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReceivedPayload {
    pub transaction_id: crate::transaction::TransactionId,
    pub envelope_sender: crate::transaction::EnvelopeSender,
    pub recipient_count: usize,
    pub direction: crate::transaction::MailDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReceivedSafePayload {
    pub transaction_id: String,
    pub direction: crate::transaction::MailDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAcceptedPayload {
    pub transaction_id: crate::transaction::TransactionId,
    pub tenant_instances: Vec<crate::transaction::TenantMessageId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAcceptedSafePayload {
    pub transaction_id: String,
    pub instance_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageQuarantinedPayload {
    pub tenant_message_id: crate::transaction::TenantMessageId,
    pub transaction_id: crate::transaction::TransactionId,
    pub reason: crate::policy::ReasonCode,
    pub finding_ids: Vec<crate::finding::FindingId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageQuarantinedSafePayload {
    pub tenant_message_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDeliveredPayload {
    pub tenant_message_id: crate::transaction::TenantMessageId,
    pub transaction_id: crate::transaction::TransactionId,
    pub delivery_attempt_id: crate::transaction::DeliveryAttemptId,
    pub smtp_response: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDeliveredSafePayload {
    pub tenant_message_id: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFailedPayload {
    pub tenant_message_id: crate::transaction::TenantMessageId,
    pub transaction_id: crate::transaction::TransactionId,
    pub delivery_attempt_id: crate::transaction::DeliveryAttemptId,
    pub smtp_response: Option<String>,
    pub permanent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFailedSafePayload {
    pub tenant_message_id: String,
    pub permanent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCreatedPayload {
    pub finding: crate::finding::SecurityFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCreatedSafePayload {
    pub severity: crate::finding::FindingSeverity,
    pub category: crate::finding::FindingCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluatedPayload {
    pub tenant_message_id: crate::transaction::TenantMessageId,
    pub transaction_id: crate::transaction::TransactionId,
    pub disposition: crate::transaction::Disposition,
    pub reason_code: crate::policy::ReasonCode,
    pub policy_revision_id: crate::policy::PolicyRevisionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluatedSafePayload {
    pub tenant_message_id: String,
    pub disposition: crate::transaction::Disposition,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCompletePayload {
    pub transaction_id: crate::transaction::TransactionId,
    pub scanner: crate::finding::ScannerType,
    pub findings_count: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCompleteSafePayload {
    pub transaction_id: String,
    pub scanner: crate::finding::ScannerType,
    pub findings_count: usize,
}

//! Policy evaluation bridge
//!
//! Mail-core integration point for the policy engine.
//! Evaluates policy rules against transaction context and produces disposition decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{
    policy::{PolicyRevisionId, ReasonCode},
    transaction::{Disposition, EnvelopeSender, Recipient},
    CustomerId, DeploymentId, SecurityFinding, TransactionId,
};

/// Policy evaluation request for one tenant message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationRequest {
    pub transaction_id: TransactionId,
    pub customer_id: CustomerId,
    pub deployment_id: DeploymentId,
    pub envelope_sender: EnvelopeSender,
    pub recipients: Vec<Recipient>,
    pub findings: Vec<SecurityFinding>,
    pub spf_result: Option<String>,
    pub dkim_result: Option<String>,
    pub dmarc_result: Option<String>,
    pub policy_revision: PolicyRevisionId,
    pub evaluated_at: DateTime<Utc>,
}

/// Policy evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub disposition: Disposition,
    pub reason_code: ReasonCode,
    pub policy_revision: PolicyRevisionId,
    pub explanation: String,
    pub findings_applied: Vec<String>,
    pub evaluated_at: DateTime<Utc>,
}

/// Policy evaluation error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PolicyEvaluationError {
    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    #[error("policy evaluation failed: {0}")]
    EvaluationFailed(String),

    #[error("policy timeout")]
    Timeout,

    #[error("policy engine unavailable")]
    Unavailable,
}

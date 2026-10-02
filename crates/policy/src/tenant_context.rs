//! TenantContext and feature override foundation
//!
//! Implements `docs/29-TENANT-FEATURE-ROUTING.md`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{ActorId, CustomerId, DeploymentId};

/// Deployment region identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);

impl RegionId {
    pub fn new(region: &str) -> Self {
        Self(region.to_string())
    }
}

/// Authenticated real actor within a TenantContext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextActor {
    pub actor_id: ActorId,
    pub login: String,
    pub roles: Vec<String>,
    pub authentication_assurance: AuthenticationAssurance,
}

/// Authentication assurance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationAssurance {
    /// Basic authenticated session.
    Standard,
    /// Step-up authentication completed (MFA, re-auth).
    StepUp,
    /// Service-to-service workload identity.
    Workload,
}

/// Impersonation context when a support/system admin acts as another user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpersonationContext {
    pub real_actor: ContextActor,
    /// The acted-as subject user. Customer entry has no subject user, so this
    /// stays `None` while `impersonated_customer` names the entered tenant.
    pub impersonated_subject: Option<String>,
    pub impersonated_customer: CustomerId,
    pub started_at: DateTime<Utc>,
    pub reason: String,
    pub session_id: String,
}

/// Tenant-scoped authorization context resolved at the application boundary.
///
/// Constructed from trusted server/session state, never from client-provided
/// tenant/customer IDs directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    /// Deployment/region identity.
    pub deployment_id: DeploymentId,
    pub region: RegionId,

    /// Real authenticated actor.
    pub actor: ContextActor,

    /// Active impersonation context, if any.
    pub impersonation: Option<ImpersonationContext>,

    /// Active authorized customer.
    pub customer_id: CustomerId,
    pub customer_internal_key: i64,
    pub customer_display_name: String,
    pub customer_lifecycle: CustomerLifecycle,

    /// Effective permissions for this tenant scope.
    pub permissions: Vec<String>,

    /// Effective configuration/feature revision.
    pub config_revision: i64,

    /// Trace/correlation identity.
    pub trace_id: String,
    pub correlation_id: String,

    /// Session/authentication state.
    pub session_id: String,
    pub authenticated_at: DateTime<Utc>,
}

/// Customer lifecycle state affecting authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomerLifecycle {
    Active,
    Grace,
    Suspended,
    Terminated,
}

impl TenantContext {
    /// The effective actor — impersonated subject if impersonating, else real actor.
    pub fn effective_actor(&self) -> &ContextActor {
        if let Some(imp) = &self.impersonation {
            &imp.real_actor
        } else {
            &self.actor
        }
    }

    /// Whether this context has step-up authentication assurance.
    pub fn has_step_up(&self) -> bool {
        self.actor.authentication_assurance == AuthenticationAssurance::StepUp
    }

    /// Build a trace context string for logging/propagation.
    pub fn trace_context(&self) -> String {
        format!(
            "deployment={} customer={} trace={}",
            self.deployment_id.0, self.customer_id.0, self.trace_id
        )
    }
}

/// Errors related to tenant context resolution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TenantContextError {
    #[error("customer not found: {0}")]
    CustomerNotFound(String),

    #[error("customer not in authorized set: {0}")]
    CustomerNotAuthorized(String),

    #[error("customer lifecycle prevents action: {0:?}")]
    CustomerLifecycleBlocked(CustomerLifecycle),

    #[error("impersonation not authorized for actor")]
    ImpersonationUnauthorized,

    #[error("impersonation reason required")]
    ImpersonationReasonRequired,

    #[error("session expired")]
    SessionExpired,

    #[error("deployment mismatch: expected {expected}, got {actual}")]
    DeploymentMismatch { expected: String, actual: String },
}

/// Validation result for a tenant selection operation.
#[derive(Debug, Clone)]
pub struct TenantSelectionValidation {
    pub valid: bool,
    pub customer_id: CustomerId,
    pub error: Option<TenantContextError>,
}

impl TenantSelectionValidation {
    pub fn valid(customer_id: CustomerId) -> Self {
        Self {
            valid: true,
            customer_id,
            error: None,
        }
    }

    pub fn invalid(customer_id: CustomerId, error: TenantContextError) -> Self {
        Self {
            valid: false,
            customer_id,
            error: Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_context() -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId("CZA-1".to_string()),
            region: RegionId::new("af-south-1"),
            actor: ContextActor {
                actor_id: ActorId(Uuid::new_v4()),
                login: "admin@example.com".to_string(),
                roles: vec!["system_admin".to_string()],
                authentication_assurance: AuthenticationAssurance::Standard,
            },
            impersonation: None,
            customer_id: CustomerId("cust-001".to_string()),
            customer_internal_key: 1,
            customer_display_name: "Test Customer".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions: vec!["mail:read".to_string(), "mail:write".to_string()],
            config_revision: 1,
            trace_id: Uuid::new_v4().to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            authenticated_at: Utc::now(),
        }
    }

    #[test]
    fn effective_actor_without_impersonation() {
        let ctx = test_context();
        assert_eq!(ctx.effective_actor().actor_id, ctx.actor.actor_id);
    }

    #[test]
    fn effective_actor_with_impersonation() {
        let mut ctx = test_context();
        ctx.impersonation = Some(ImpersonationContext {
            real_actor: ctx.actor.clone(),
            impersonated_subject: Some("support-user".to_string()),
            impersonated_customer: CustomerId("cust-002".to_string()),
            started_at: Utc::now(),
            reason: "debugging".to_string(),
            session_id: "imp-session".to_string(),
        });
        // effective_actor returns the real actor, not impersonated subject
        assert_eq!(ctx.effective_actor().actor_id, ctx.actor.actor_id);
    }

    #[test]
    fn trace_context_format() {
        let ctx = test_context();
        let tc = ctx.trace_context();
        assert!(tc.contains("CZA-1"));
        assert!(tc.contains("cust-001"));
    }
}

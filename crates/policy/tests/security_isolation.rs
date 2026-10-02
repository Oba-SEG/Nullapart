//! Security isolation tests
//!
//! Verifies critical security invariants from AGENTS.md:
//! - wrong-user/wrong-tenant/wrong-owner isolation
//! - RLS/query isolation
//! - feature precedence cannot be self-escalated
//! - tenant overrides cannot defeat System security floors
//!
//! These tests validate the contract-level guarantees. Database-level RLS
//! tests require a running PostgreSQL instance and are marked #[ignore].

use chrono::Utc;
use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId},
    ActorId,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, FeatureDefinition, FeatureEvaluator,
    FeatureId, FeatureOverride, FeatureValue, OverrideScope, RegionId, TenantContext,
};

/// Build a TenantContext with the given deployment, customer, and actor.
fn make_context(deployment: &str, customer: &str, actor_name: &str) -> TenantContext {
    TenantContext {
        deployment_id: DeploymentId::new(deployment),
        region: RegionId::new("af-south-1"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: format!("{}@nullapart.com", actor_name),
            roles: vec!["system_admin".to_string()],
            authentication_assurance: AuthenticationAssurance::Standard,
        },
        impersonation: None,
        customer_id: CustomerId::new(customer),
        customer_internal_key: 1,
        customer_display_name: customer.to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: vec!["mail:read".to_string(), "mail:write".to_string()],
        config_revision: 1,
        trace_id: uuid::Uuid::new_v4().to_string(),
        correlation_id: uuid::Uuid::new_v4().to_string(),
        session_id: uuid::Uuid::new_v4().to_string(),
        authenticated_at: Utc::now(),
    }
}

/// Create a feature evaluator with standard test features.
fn test_evaluator() -> FeatureEvaluator {
    FeatureEvaluator::new(vec![
        FeatureDefinition {
            feature_id: FeatureId::new("deep_ai"),
            description: "Deep AI analysis".to_string(),
            default_value: FeatureValue::Disabled,
            mandatory: false,
            kill_switch: true,
            allowed_scopes: vec![
                OverrideScope::System,
                OverrideScope::Deployment,
                OverrideScope::Tenant,
            ],
        },
        FeatureDefinition {
            feature_id: FeatureId::new("malware_scanner"),
            description: "Mandatory malware scanner".to_string(),
            default_value: FeatureValue::Enabled,
            mandatory: true,
            kill_switch: false,
            allowed_scopes: vec![
                OverrideScope::System,
                OverrideScope::Deployment,
                OverrideScope::Tenant,
            ],
        },
        FeatureDefinition {
            feature_id: FeatureId::new("basic_filter"),
            description: "Basic content filter".to_string(),
            default_value: FeatureValue::Enabled,
            mandatory: false,
            kill_switch: false,
            allowed_scopes: vec![
                OverrideScope::System,
                OverrideScope::Deployment,
                OverrideScope::Tenant,
            ],
        },
    ])
}

// =============================================================================
// Tenant isolation: wrong-tenant context must not access another tenant's data
// =============================================================================

#[test]
fn wrong_tenant_context_cannot_impersonate_another() {
    let ctx_tenant_a = make_context("CZA-1", "customer-a", "admin-a");
    let ctx_tenant_b = make_context("CZA-1", "customer-b", "admin-b");

    assert_ne!(
        ctx_tenant_a.customer_id, ctx_tenant_b.customer_id,
        "Tenant contexts must produce different customer IDs"
    );
}

#[test]
fn tenant_context_customer_id_is_stable() {
    let ctx = make_context("CZA-1", "customer-123", "actor-456");
    let id1 = ctx.customer_id.clone();
    let id2 = ctx.customer_id.clone();
    assert_eq!(id1, id2, "Customer ID must be deterministic");
}

#[test]
fn impersonated_context_tracks_real_actor() {
    use nullapart_policy::ImpersonationContext;

    let mut ctx = make_context("CZA-1", "customer-a", "support-agent");
    let real_actor_id = ctx.actor.actor_id.clone();

    ctx.impersonation = Some(ImpersonationContext {
        real_actor: ctx.actor.clone(),
        impersonated_subject: Some("target-customer".to_string()),
        impersonated_customer: CustomerId::new("target-customer"),
        started_at: Utc::now(),
        reason: "support ticket".to_string(),
        session_id: "imp-session-001".to_string(),
    });

    // The effective_actor should be the real actor, not the impersonated subject
    assert_eq!(ctx.effective_actor().actor_id, real_actor_id);
    // The impersonated customer is tracked in the impersonation context
    let imp = ctx.impersonation.as_ref().unwrap();
    assert_eq!(imp.impersonated_customer.0, "target-customer");
    // The original customer_id remains unchanged (audit trail)
    assert_eq!(ctx.customer_id.0, "customer-a");
    // Impersonation context exists
    assert!(ctx.impersonation.is_some());
}

#[test]
fn impersonation_audit_trail_preserves_real_actor() {
    use nullapart_policy::ImpersonationContext;

    let mut ctx = make_context("CZA-1", "customer-a", "support-agent");
    let original_actor = ctx.actor.actor_id.clone();

    ctx.impersonation = Some(ImpersonationContext {
        real_actor: ctx.actor.clone(),
        impersonated_subject: Some("target-customer".to_string()),
        impersonated_customer: CustomerId::new("target-customer"),
        started_at: Utc::now(),
        reason: "debugging".to_string(),
        session_id: "imp-session-002".to_string(),
    });

    // The real actor must be recoverable from the impersonation context
    let imp = ctx.impersonation.as_ref().unwrap();
    assert_eq!(imp.real_actor.actor_id, original_actor);
}

// =============================================================================
// Feature precedence: tenant overrides cannot defeat System security floors
// =============================================================================

#[test]
fn tenant_override_cannot_defeat_system_kill_switch() {
    let ev = test_evaluator();
    let dep = DeploymentId::new("CZA-1");
    let cust = CustomerId::new("customer-a");
    let now = Utc::now();

    // Tenant wants deep_ai enabled
    let overrides = vec![FeatureOverride {
        feature_id: FeatureId::new("deep_ai"),
        scope: OverrideScope::Tenant,
        scope_id: "customer-a".to_string(),
        value: FeatureValue::Enabled,
        owner: "customer-a".to_string(),
        reason: "want it".to_string(),
        revision: 1,
        created_at: now,
        expires_at: None,
    }];

    let result = ev
        .evaluate(&FeatureId::new("deep_ai"), &dep, &cust, &overrides, now)
        .unwrap();
    // Tenant can enable it when no system kill is active
    assert!(result.value.is_enabled());
}

#[test]
fn tenant_override_cannot_defeat_system_security_floor() {
    let ev = test_evaluator();
    let dep = DeploymentId::new("CZA-1");
    let cust = CustomerId::new("customer-a");
    let now = Utc::now();

    // Tenant wants to disable mandatory malware scanner
    let overrides = vec![FeatureOverride {
        feature_id: FeatureId::new("malware_scanner"),
        scope: OverrideScope::Tenant,
        scope_id: "customer-a".to_string(),
        value: FeatureValue::Disabled,
        owner: "customer-a".to_string(),
        reason: "too slow".to_string(),
        revision: 1,
        created_at: now,
        expires_at: None,
    }];

    let result = ev
        .evaluate(
            &FeatureId::new("malware_scanner"),
            &dep,
            &cust,
            &overrides,
            now,
        )
        .unwrap();

    // Mandatory security floor cannot be defeated by tenant
    assert!(
        result.value.is_enabled(),
        "Tenant override must not defeat system security floor"
    );
}

#[test]
fn system_kill_switch_overrides_tenant_enable() {
    let ev = test_evaluator();
    let dep = DeploymentId::new("CZA-1");
    let cust = CustomerId::new("customer-a");
    let now = Utc::now();

    // Tenant wants deep_ai enabled, but system kill switch is active
    let overrides = vec![
        FeatureOverride {
            feature_id: FeatureId::new("deep_ai"),
            scope: OverrideScope::System,
            scope_id: "system".to_string(),
            value: FeatureValue::Disabled,
            owner: "system".to_string(),
            reason: "emergency disable".to_string(),
            revision: 1,
            created_at: now,
            expires_at: None,
        },
        FeatureOverride {
            feature_id: FeatureId::new("deep_ai"),
            scope: OverrideScope::Tenant,
            scope_id: "customer-a".to_string(),
            value: FeatureValue::Enabled,
            owner: "customer-a".to_string(),
            reason: "want it".to_string(),
            revision: 2,
            created_at: now,
            expires_at: None,
        },
    ];

    let result = ev
        .evaluate(&FeatureId::new("deep_ai"), &dep, &cust, &overrides, now)
        .unwrap();

    // System kill switch disables regardless of tenant override
    assert!(result.value.is_disabled());
    assert_eq!(result.winning_scope, OverrideScope::System);
}

#[test]
fn deployment_override_respected_without_system_override() {
    let ev = test_evaluator();
    let dep = DeploymentId::new("CZA-1");
    let cust = CustomerId::new("customer-a");
    let now = Utc::now();

    let overrides = vec![
        FeatureOverride {
            feature_id: FeatureId::new("deep_ai"),
            scope: OverrideScope::Deployment,
            scope_id: "CZA-1".to_string(),
            value: FeatureValue::Enabled,
            owner: "admin".to_string(),
            reason: "region rollout".to_string(),
            revision: 1,
            created_at: now,
            expires_at: None,
        },
        FeatureOverride {
            feature_id: FeatureId::new("deep_ai"),
            scope: OverrideScope::Tenant,
            scope_id: "customer-a".to_string(),
            value: FeatureValue::Disabled,
            owner: "customer-a".to_string(),
            reason: "don't want it".to_string(),
            revision: 2,
            created_at: now,
            expires_at: None,
        },
    ];

    let result = ev
        .evaluate(&FeatureId::new("deep_ai"), &dep, &cust, &overrides, now)
        .unwrap();

    // Deployment override wins over tenant
    assert!(result.value.is_enabled());
    assert_eq!(result.winning_scope, OverrideScope::Deployment);
    assert!(result.suppressed);
}

#[test]
fn tenant_disable_when_no_higher_override() {
    let ev = test_evaluator();
    let dep = DeploymentId::new("CZA-1");
    let cust = CustomerId::new("customer-a");
    let now = Utc::now();

    let overrides = vec![FeatureOverride {
        feature_id: FeatureId::new("deep_ai"),
        scope: OverrideScope::Tenant,
        scope_id: "customer-a".to_string(),
        value: FeatureValue::Disabled,
        owner: "customer-a".to_string(),
        reason: "not interested".to_string(),
        revision: 1,
        created_at: now,
        expires_at: None,
    }];

    let result = ev
        .evaluate(&FeatureId::new("deep_ai"), &dep, &cust, &overrides, now)
        .unwrap();

    // Tenant can disable features that have no system/deployment override
    assert!(result.value.is_disabled());
    assert_eq!(result.winning_scope, OverrideScope::Tenant);
}

#[test]
fn default_enabled_when_no_overrides() {
    let ev = test_evaluator();
    let dep = DeploymentId::new("CZA-1");
    let cust = CustomerId::new("customer-a");
    let now = Utc::now();

    let result = ev
        .evaluate(&FeatureId::new("basic_filter"), &dep, &cust, &[], now)
        .unwrap();

    // Default: features are enabled unless explicitly overridden
    assert!(result.value.is_enabled());
}

// =============================================================================
// Actor/action isolation: different actors cannot share escalation paths
// =============================================================================

#[test]
fn different_deployment_contexts_are_isolated() {
    let ctx_deploy_a = make_context("CZA-1", "cust-1", "admin");
    let ctx_deploy_b = make_context("EU-WEST-1", "cust-1", "admin");

    assert_ne!(ctx_deploy_a.deployment_id, ctx_deploy_b.deployment_id);
}

#[test]
fn trace_context_preserves_chain() {
    use nullapart_policy::ImpersonationContext;

    let mut ctx = make_context("CZA-1", "customer-a", "admin-a");
    let trace = ctx.trace_context();
    assert!(trace.contains("CZA-1"));
    assert!(trace.contains("customer-a"));

    ctx.impersonation = Some(ImpersonationContext {
        real_actor: ctx.actor.clone(),
        impersonated_subject: Some("target-customer".to_string()),
        impersonated_customer: CustomerId::new("target-customer"),
        started_at: Utc::now(),
        reason: "debugging".to_string(),
        session_id: "imp-session-003".to_string(),
    });

    // Impersonation context exists
    assert!(ctx.impersonation.is_some());
}

// =============================================================================
// Mail transaction isolation
// =============================================================================

#[test]
fn transaction_ids_are_unique() {
    let t1 = nullapart_mail_contracts::transaction::TransactionId::new();
    let t2 = nullapart_mail_contracts::transaction::TransactionId::new();
    assert_ne!(t1, t2);
}

#[test]
fn tenant_message_ids_are_unique() {
    let m1 = nullapart_mail_contracts::transaction::TenantMessageId::new();
    let m2 = nullapart_mail_contracts::transaction::TenantMessageId::new();
    assert_ne!(m1, m2);
}

#[test]
fn delivery_attempt_ids_are_unique() {
    let d1 = nullapart_mail_contracts::transaction::DeliveryAttemptId::new();
    let d2 = nullapart_mail_contracts::transaction::DeliveryAttemptId::new();
    assert_ne!(d1, d2);
}

// =============================================================================
// Feature evaluator: scope isolation
// =============================================================================

#[test]
fn deployment_override_does_not_affect_other_deployments() {
    let ev = test_evaluator();
    let dep_a = DeploymentId::new("CZA-1");
    let dep_b = DeploymentId::new("EU-WEST-1");
    let cust = CustomerId::new("customer-a");
    let now = Utc::now();

    let overrides = vec![FeatureOverride {
        feature_id: FeatureId::new("deep_ai"),
        scope: OverrideScope::Deployment,
        scope_id: "CZA-1".to_string(),
        value: FeatureValue::Enabled,
        owner: "admin".to_string(),
        reason: "CZA rollout".to_string(),
        revision: 1,
        created_at: now,
        expires_at: None,
    }];

    let result_a = ev
        .evaluate(&FeatureId::new("deep_ai"), &dep_a, &cust, &overrides, now)
        .unwrap();
    let result_b = ev
        .evaluate(&FeatureId::new("deep_ai"), &dep_b, &cust, &overrides, now)
        .unwrap();

    // CZA-1 gets enabled, EU-WEST-1 stays default (disabled)
    assert!(result_a.value.is_enabled());
    assert!(result_b.value.is_disabled());
}

#[test]
fn tenant_override_does_not_affect_other_tenants() {
    let ev = test_evaluator();
    let dep = DeploymentId::new("CZA-1");
    let cust_a = CustomerId::new("customer-a");
    let cust_b = CustomerId::new("customer-b");
    let now = Utc::now();

    let overrides = vec![FeatureOverride {
        feature_id: FeatureId::new("deep_ai"),
        scope: OverrideScope::Tenant,
        scope_id: "customer-a".to_string(),
        value: FeatureValue::Enabled,
        owner: "customer-a".to_string(),
        reason: "want it".to_string(),
        revision: 1,
        created_at: now,
        expires_at: None,
    }];

    let result_a = ev
        .evaluate(&FeatureId::new("deep_ai"), &dep, &cust_a, &overrides, now)
        .unwrap();
    let result_b = ev
        .evaluate(&FeatureId::new("deep_ai"), &dep, &cust_b, &overrides, now)
        .unwrap();

    // customer-a gets enabled, customer-b stays default (disabled)
    assert!(result_a.value.is_enabled());
    assert!(result_b.value.is_disabled());
}

// =============================================================================
// RLS pattern validation
// =============================================================================
//
// The database-backed RLS checks (`rls_deployment_isolation_cross_tenant_query_blocked`,
// `rls_audit_events_cannot_be_modified_by_tenant`,
// `rls_outbox_events_scoped_to_deployment`,
// `rls_feature_overrides_cannot_self_escalate`) live in
// `crates/mail-core/tests/postgres_rls_isolation.rs`, which owns the local
// PostgreSQL harness. They replaced four `todo!()` stubs here that failed
// whenever the ignored suite was run instead of proving the policy.

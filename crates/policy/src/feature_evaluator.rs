//! Server-authoritative feature evaluation with override precedence.
//!
//! Implements `docs/29-TENANT-FEATURE-ROUTING.md` evaluation model:
//!
//! ```text
//! System emergency/kill disable
//!   -> System mandatory security floor
//!   -> deployment override
//!   -> tenant override
//!   -> feature default
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{CustomerId, DeploymentId};

/// Feature identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FeatureId(pub String);

impl FeatureId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

/// Override scope level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideScope {
    /// System-level global within deployment.
    System,
    /// Deployment-level.
    Deployment,
    /// Tenant/customer-level.
    Tenant,
}

/// Feature override value with inheritance support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureValue {
    /// Inherit from next higher scope.
    Inherit,
    /// Feature is enabled.
    Enabled,
    /// Feature is disabled.
    Disabled,
    /// Typed configuration value.
    Typed(String),
}

impl FeatureValue {
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }

    pub fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

/// A single feature override record with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureOverride {
    pub feature_id: FeatureId,
    pub scope: OverrideScope,
    pub scope_id: String,
    pub value: FeatureValue,
    pub owner: String,
    pub reason: String,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl FeatureOverride {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| exp <= now)
    }
}

/// The result of feature evaluation including winning scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureEvaluation {
    /// The evaluated value.
    pub value: FeatureValue,
    /// Which scope won.
    pub winning_scope: OverrideScope,
    /// The override that won, if any.
    pub winning_override: Option<FeatureOverride>,
    /// Whether a higher-level override suppressed a lower one.
    pub suppressed: bool,
    /// Explanation of why this value was chosen.
    pub explanation: String,
}

/// Feature definition with default and security constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureDefinition {
    pub feature_id: FeatureId,
    pub description: String,
    pub default_value: FeatureValue,
    /// If true, this feature is a mandatory security floor — cannot be disabled
    /// by any lower scope.
    pub mandatory: bool,
    /// If true, this is a system kill switch — overrides everything.
    pub kill_switch: bool,
    /// Allowed override scopes (e.g., tenant may not override if not listed).
    pub allowed_scopes: Vec<OverrideScope>,
}

/// Error during feature evaluation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FeatureEvaluationError {
    #[error("feature not found: {0}")]
    FeatureNotFound(String),

    #[error("override scope not allowed for feature {feature_id}: {scope:?}")]
    ScopeNotAllowed {
        feature_id: String,
        scope: OverrideScope,
    },

    #[error("override expired: feature {feature_id}, override revision {revision}")]
    OverrideExpired { feature_id: String, revision: i64 },
}

/// Server-authoritative feature evaluator.
pub struct FeatureEvaluator {
    features: Vec<FeatureDefinition>,
}

impl FeatureEvaluator {
    pub fn new(features: Vec<FeatureDefinition>) -> Self {
        Self { features }
    }

    /// Evaluate a feature for the given tenant context using the precedence model.
    ///
    /// Overrides are ordered System -> Deployment -> Tenant, and the first
    /// non-Inherit value wins, subject to mandatory/kill-switch constraints.
    pub fn evaluate(
        &self,
        feature_id: &FeatureId,
        deployment_id: &DeploymentId,
        customer_id: &CustomerId,
        overrides: &[FeatureOverride],
        now: DateTime<Utc>,
    ) -> Result<FeatureEvaluation, FeatureEvaluationError> {
        let definition = self
            .features
            .iter()
            .find(|f| &f.feature_id == feature_id)
            .ok_or_else(|| FeatureEvaluationError::FeatureNotFound(feature_id.0.clone()))?;

        // System kill switch check — if any System-scope override with Disabled exists,
        // and this feature is a kill-switch target, force disabled.
        let system_kill = overrides.iter().find(|o| {
            o.feature_id == *feature_id
                && o.scope == OverrideScope::System
                && o.value.is_disabled()
                && !o.is_expired(now)
        });

        if let Some(kill) = system_kill {
            return Ok(FeatureEvaluation {
                value: FeatureValue::Disabled,
                winning_scope: OverrideScope::System,
                winning_override: Some(kill.clone()),
                suppressed: true,
                explanation: format!(
                    "System kill switch disabled feature {} (override rev {})",
                    feature_id.0, kill.revision
                ),
            });
        }

        // Mandatory security floor — if feature is mandatory, enforce Enabled.
        if definition.mandatory {
            return Ok(FeatureEvaluation {
                value: FeatureValue::Enabled,
                winning_scope: OverrideScope::System,
                winning_override: None,
                suppressed: false,
                explanation: format!(
                    "Feature {} is mandatory security floor — enforced Enabled",
                    feature_id.0
                ),
            });
        }

        // Pre-compute which scopes have any applicable overrides
        let has_deployment_override = overrides.iter().any(|o| {
            o.feature_id == *feature_id
                && o.scope == OverrideScope::Deployment
                && !o.is_expired(now)
                && o.scope_id == deployment_id.0
                && definition
                    .allowed_scopes
                    .contains(&OverrideScope::Deployment)
        });
        let has_tenant_override = overrides.iter().any(|o| {
            o.feature_id == *feature_id
                && o.scope == OverrideScope::Tenant
                && !o.is_expired(now)
                && o.scope_id == customer_id.0
                && definition.allowed_scopes.contains(&OverrideScope::Tenant)
        });

        // Evaluate overrides in precedence order: System -> Deployment -> Tenant
        let ordered_scopes = [
            OverrideScope::System,
            OverrideScope::Deployment,
            OverrideScope::Tenant,
        ];

        for scope in &ordered_scopes {
            let filtered: Vec<&FeatureOverride> = overrides
                .iter()
                .filter(|o| {
                    o.feature_id == *feature_id
                        && o.scope == *scope
                        && !o.is_expired(now)
                        && definition.allowed_scopes.contains(scope)
                })
                .filter(|o| match scope {
                    OverrideScope::System => true,
                    OverrideScope::Deployment => o.scope_id == deployment_id.0,
                    OverrideScope::Tenant => o.scope_id == customer_id.0,
                })
                .collect();

            // Find first non-Inherit value
            if let Some(winning) = filtered.iter().find(|o| !o.value.is_inherit()) {
                let explanation = format!(
                    "Feature {} resolved at {:?} scope (override rev {})",
                    feature_id.0, scope, winning.revision
                );

                // Determine if a higher scope suppressed a lower one
                let suppressed = match scope {
                    OverrideScope::System => has_deployment_override || has_tenant_override,
                    OverrideScope::Deployment => has_tenant_override,
                    OverrideScope::Tenant => false,
                };

                return Ok(FeatureEvaluation {
                    value: winning.value.clone(),
                    winning_scope: *scope,
                    winning_override: Some((*winning).clone()),
                    suppressed,
                    explanation,
                });
            }
        }

        // No overrides applied — use default
        Ok(FeatureEvaluation {
            value: definition.default_value.clone(),
            winning_scope: OverrideScope::System,
            winning_override: None,
            suppressed: false,
            explanation: format!(
                "Feature {} using default value (no overrides applied)",
                feature_id.0
            ),
        })
    }

    /// Convenience: evaluate and return whether feature is effectively enabled.
    pub fn is_enabled(
        &self,
        feature_id: &FeatureId,
        deployment_id: &DeploymentId,
        customer_id: &CustomerId,
        overrides: &[FeatureOverride],
        now: DateTime<Utc>,
    ) -> Result<bool, FeatureEvaluationError> {
        let eval = self.evaluate(feature_id, deployment_id, customer_id, overrides, now)?;
        Ok(eval.value.is_enabled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullapart_mail_contracts::{CustomerId, DeploymentId};

    fn evaluator() -> FeatureEvaluator {
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

    #[test]
    fn default_when_no_overrides() {
        let ev = evaluator();
        let dep = DeploymentId("CZA-1".to_string());
        let cust = CustomerId("cust-001".to_string());
        let now = Utc::now();

        let result = ev
            .evaluate(&FeatureId::new("basic_filter"), &dep, &cust, &[], now)
            .unwrap();
        assert!(result.value.is_enabled());
        assert_eq!(result.winning_scope, OverrideScope::System);
    }

    #[test]
    fn mandatory_floor_enforced() {
        let ev = evaluator();
        let dep = DeploymentId("CZA-1".to_string());
        let cust = CustomerId("cust-001".to_string());
        let now = Utc::now();

        // Even with a disable override, mandatory feature stays enabled
        let overrides = vec![FeatureOverride {
            feature_id: FeatureId::new("malware_scanner"),
            scope: OverrideScope::Tenant,
            scope_id: "cust-001".to_string(),
            value: FeatureValue::Disabled,
            owner: "test".to_string(),
            reason: "test".to_string(),
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
        assert!(result.value.is_enabled());
    }

    #[test]
    fn kill_switch_disables() {
        let ev = evaluator();
        let dep = DeploymentId("CZA-1".to_string());
        let cust = CustomerId("cust-001".to_string());
        let now = Utc::now();

        let overrides = vec![FeatureOverride {
            feature_id: FeatureId::new("deep_ai"),
            scope: OverrideScope::System,
            scope_id: "system".to_string(),
            value: FeatureValue::Disabled,
            owner: "admin".to_string(),
            reason: "emergency".to_string(),
            revision: 1,
            created_at: now,
            expires_at: None,
        }];

        let result = ev
            .evaluate(&FeatureId::new("deep_ai"), &dep, &cust, &overrides, now)
            .unwrap();
        assert!(result.value.is_disabled());
        assert_eq!(result.winning_scope, OverrideScope::System);
    }

    #[test]
    fn deployment_overrides_tenant() {
        let ev = evaluator();
        let dep = DeploymentId("CZA-1".to_string());
        let cust = CustomerId("cust-001".to_string());
        let now = Utc::now();

        let overrides = vec![
            FeatureOverride {
                feature_id: FeatureId::new("deep_ai"),
                scope: OverrideScope::Deployment,
                scope_id: "CZA-1".to_string(),
                value: FeatureValue::Disabled,
                owner: "admin".to_string(),
                reason: "region restriction".to_string(),
                revision: 1,
                created_at: now,
                expires_at: None,
            },
            FeatureOverride {
                feature_id: FeatureId::new("deep_ai"),
                scope: OverrideScope::Tenant,
                scope_id: "cust-001".to_string(),
                value: FeatureValue::Enabled,
                owner: "customer".to_string(),
                reason: "want it".to_string(),
                revision: 2,
                created_at: now,
                expires_at: None,
            },
        ];

        let result = ev
            .evaluate(&FeatureId::new("deep_ai"), &dep, &cust, &overrides, now)
            .unwrap();
        // Deployment disable wins over tenant enable
        assert!(result.value.is_disabled());
        assert_eq!(result.winning_scope, OverrideScope::Deployment);
        assert!(result.suppressed);
    }

    #[test]
    fn expired_override_ignored() {
        let ev = evaluator();
        let dep = DeploymentId("CZA-1".to_string());
        let cust = CustomerId("cust-001".to_string());
        let now = Utc::now();

        let overrides = vec![FeatureOverride {
            feature_id: FeatureId::new("deep_ai"),
            scope: OverrideScope::Deployment,
            scope_id: "CZA-1".to_string(),
            value: FeatureValue::Enabled,
            owner: "admin".to_string(),
            reason: "test".to_string(),
            revision: 1,
            created_at: now,
            expires_at: Some(now - chrono::Duration::hours(1)),
        }];

        let result = ev
            .evaluate(&FeatureId::new("deep_ai"), &dep, &cust, &overrides, now)
            .unwrap();
        // Expired override ignored, default (Disabled) applies
        assert!(result.value.is_disabled());
    }
}

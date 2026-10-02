//! Threshold configuration for inline ML score → finding conversion.
//!
//! Thresholds are policy, never model artifacts and never constants:
//! `PHASE-4-INLINE-ML.md` requires them to live in the support-managed
//! `ml_threat_classification` policy family. Support publishes them in the
//! existing `PolicyAction.metadata` slot of a family rule
//! (`{"thresholds": {"version": 1, "classes": {...}}}`) through the
//! audited policy publish API; this module validates that payload, merges
//! the active revision's rules into the effective configuration, and maps
//! a score onto a Low/Medium/High threat band.
//!
//! Runtime resolution follows the feature-switch resolver pattern
//! (transaction + RLS scope + explicit `None` on any failure). When no
//! valid thresholds exist for a scope the stage logs an explicit WARN and
//! scores stay evidence only — they are never converted into findings and
//! a numeric default is never invented in code.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use nullapart_mail_contracts::finding::{Confidence, FindingCategory, FindingSeverity};
use nullapart_mail_contracts::policy::PolicyRule;

use super::runtime::INLINE_ML_CLASS_COUNT;

/// The policy family that owns ML thresholds and band semantics
/// (`migrations/014_policy_administration.sql` seed, support-managed).
pub const ML_THREAT_CLASSIFICATION_FAMILY: &str = "ml_threat_classification";

/// Only accepted payload version today. A future incompatible shape bumps
/// this value and older payloads are rejected explicitly, never guessed.
pub const INLINE_ML_THRESHOLDS_VERSION: u32 = 1;

/// Per-class operating points: the score at which a class becomes a
/// finding (`low`) and the band cutoffs for Medium and High.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassThreshold {
    pub low: f32,
    pub medium: f32,
    pub high: f32,
}

/// Effective threshold configuration for one scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlThresholdConfig {
    pub version: u32,
    pub classes: BTreeMap<String, ClassThreshold>,
}

/// Map a canonical model label (`INLINE_ML_LABELS` entry) to its category.
pub fn label_to_category(label: &str) -> Option<FindingCategory> {
    match label {
        "Malware" => Some(FindingCategory::Malware),
        "Phishing" => Some(FindingCategory::Phishing),
        "Spam" => Some(FindingCategory::Spam),
        "Spoofing" => Some(FindingCategory::Spoofing),
        "BusinessEmailCompromise" => Some(FindingCategory::BusinessEmailCompromise),
        "CredentialHarvest" => Some(FindingCategory::CredentialHarvest),
        "MaliciousUrl" => Some(FindingCategory::MaliciousUrl),
        "MaliciousAttachment" => Some(FindingCategory::MaliciousAttachment),
        "SuspiciousContent" => Some(FindingCategory::SuspiciousContent),
        "PolicyViolation" => Some(FindingCategory::PolicyViolation),
        "AuthFailure" => Some(FindingCategory::AuthFailure),
        "Reputation" => Some(FindingCategory::Reputation),
        "Unknown" => Some(FindingCategory::Unknown),
        _ => None,
    }
}

/// The policy-JSON key for a category (its canonical snake_case wire form,
/// identical to what `FindingCondition.category` uses).
pub fn category_key(category: FindingCategory) -> String {
    serde_json::to_value(category)
        .expect("a data-less category enum serializes")
        .as_str()
        .expect("a category serializes to a string")
        .to_string()
}

fn valid_class_threshold(threshold: &ClassThreshold) -> bool {
    threshold.low.is_finite()
        && threshold.medium.is_finite()
        && threshold.high.is_finite()
        && threshold.low > 0.0
        && threshold.low <= threshold.medium
        && threshold.medium <= threshold.high
        && threshold.high <= 1.0
}

fn known_category_key(key: &str) -> bool {
    super::runtime::INLINE_ML_LABELS.iter().any(|label| {
        label_to_category(label)
            .map(category_key)
            .is_some_and(|candidate| candidate == key)
    })
}

/// Parse one rule's `action.metadata` into an effective configuration.
/// Returns `None` for absent or invalid payloads; invalid payloads must
/// never be silently coerced into a different set of numbers.
pub fn parse_thresholds(metadata: &serde_json::Value) -> Option<MlThresholdConfig> {
    let outer = metadata.as_object()?;
    if outer.len() != 1 {
        return None;
    }
    let payload = outer.get("thresholds")?;
    let config: MlThresholdConfig = serde_json::from_value(payload.clone()).ok()?;
    if config.version != INLINE_ML_THRESHOLDS_VERSION {
        return None;
    }
    if config.classes.is_empty() || config.classes.len() > INLINE_ML_CLASS_COUNT {
        return None;
    }
    if !config
        .classes
        .iter()
        .all(|(key, threshold)| known_category_key(key) && valid_class_threshold(threshold))
    {
        return None;
    }
    Some(config)
}

/// Publish-time validation for the `ml_threat_classification` family: any
/// rule that carries metadata must carry a fully valid threshold payload;
/// rules without metadata are allowed (the family may be published
/// unconfigured, which the stage reports as an explicit WARN).
pub fn validate_family_rules(rules: &[PolicyRule]) -> bool {
    rules
        .iter()
        .all(|rule| match rule.action.metadata.as_ref() {
            None => true,
            Some(metadata) => parse_thresholds(metadata).is_some(),
        })
}

/// Merge the effective thresholds from a revision's rules. Mirrors
/// [`crate::policy::PolicyRuleEvaluator`] ordering — enabled rules,
/// highest priority first, first definition of a class wins.
pub fn thresholds_from_rules(rules: &[PolicyRule]) -> Option<MlThresholdConfig> {
    let mut ordered: Vec<&PolicyRule> = rules.iter().filter(|rule| rule.enabled).collect();
    ordered.sort_by_key(|rule| std::cmp::Reverse(rule.priority));
    let mut classes = BTreeMap::new();
    for rule in ordered {
        let Some(config) = rule.action.metadata.as_ref().and_then(parse_thresholds) else {
            continue;
        };
        for (key, threshold) in config.classes {
            classes.entry(key).or_insert(threshold);
        }
    }
    (!classes.is_empty()).then_some(MlThresholdConfig {
        version: INLINE_ML_THRESHOLDS_VERSION,
        classes,
    })
}

/// Map one score onto its band. `None` means the class score stays
/// evidence only (below the configured `low` operating point).
pub fn band_for(score: f32, threshold: &ClassThreshold) -> Option<FindingSeverity> {
    if score >= threshold.high {
        Some(FindingSeverity::High)
    } else if score >= threshold.medium {
        Some(FindingSeverity::Medium)
    } else if score >= threshold.low {
        Some(FindingSeverity::Low)
    } else {
        None
    }
}

/// Lowercase wire label for a band (used in finding details).
pub fn band_label(band: FindingSeverity) -> &'static str {
    match band {
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Critical => "high",
        FindingSeverity::Info => "low",
    }
}

/// The confidence a scored finding carries alongside its band.
pub fn band_confidence(band: FindingSeverity) -> Confidence {
    match band {
        FindingSeverity::Critical | FindingSeverity::High => Confidence::High,
        FindingSeverity::Medium => Confidence::Medium,
        FindingSeverity::Low | FindingSeverity::Info => Confidence::Low,
    }
}

const ACTIVE_ML_REVISION_SQL: &str = "SELECT rules FROM policy_revisions \
     WHERE family_id = $1 AND deactivated_at IS NULL \
       AND deployment_id = $2 AND scope_level = 'tenant' AND customer_id = $3 \
     ORDER BY revision_number DESC \
     LIMIT 1";

/// Runtime resolver for the effective thresholds of one message scope,
/// following the feature-switch resolver pattern: one transaction, RLS
/// scope established server-side, and `None` for every failure mode.
pub struct MlThresholdResolver {
    pool: PgPool,
}

impl MlThresholdResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Resolve the effective thresholds for this deployment/customer.
    /// Absent family revision, absent or invalid payloads and any
    /// database/scope error all resolve to `None` (evidence only).
    pub async fn resolve(
        &self,
        deployment_id: &nullapart_mail_contracts::transaction::DeploymentId,
        customer_id: &nullapart_mail_contracts::transaction::CustomerId,
    ) -> Option<MlThresholdConfig> {
        let mut transaction = match self.pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => {
                tracing::warn!(error = %error, "inline ml threshold resolution transaction failed");
                return None;
            },
        };
        if crate::policy_admin::set_scope(&mut transaction, &deployment_id.0, &customer_id.0)
            .await
            .is_err()
        {
            tracing::warn!("inline ml threshold resolution scope failed");
            return None;
        }
        let rules: Option<serde_json::Value> = match sqlx::query_scalar(ACTIVE_ML_REVISION_SQL)
            .bind(ML_THREAT_CLASSIFICATION_FAMILY)
            .bind(&deployment_id.0)
            .bind(&customer_id.0)
            .fetch_optional(&mut *transaction)
            .await
        {
            Ok(rules) => rules,
            Err(error) => {
                tracing::warn!(error = %error, "inline ml threshold revision read failed");
                return None;
            },
        };
        let rules = rules?;
        let Ok(rules) = serde_json::from_value::<Vec<PolicyRule>>(rules) else {
            tracing::warn!("inline ml threshold revision rules are malformed");
            return None;
        };
        thresholds_from_rules(&rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullapart_mail_contracts::policy::{
        ConditionScope, PolicyAction, PolicyCondition, PolicyRuleId, ReasonCode,
    };
    use nullapart_mail_contracts::transaction::Disposition;

    fn threshold_payload(value: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "thresholds": value })
    }

    fn valid_payload() -> serde_json::Value {
        threshold_payload(serde_json::json!({
            "version": 1,
            "classes": {
                "malware": { "low": 0.4, "medium": 0.7, "high": 0.9 },
                "phishing": { "low": 0.5, "medium": 0.75, "high": 0.95 }
            }
        }))
    }

    fn rule_with(priority: i32, metadata: Option<serde_json::Value>) -> PolicyRule {
        PolicyRule {
            id: PolicyRuleId::new(),
            name: "threshold rule".to_string(),
            priority,
            condition: PolicyCondition {
                sender: None,
                recipient: None,
                auth: None,
                content: None,
                finding: None,
                scope: ConditionScope::Transaction,
            },
            action: PolicyAction {
                disposition: Disposition::Allow,
                reason_code: ReasonCode("ALLOWED".to_string()),
                notify: None,
                metadata,
            },
            enabled: true,
        }
    }

    #[test]
    fn valid_payload_parses_with_sorted_class_keys() {
        let config = parse_thresholds(&valid_payload()).expect("valid payload must parse");
        assert_eq!(config.version, INLINE_ML_THRESHOLDS_VERSION);
        assert_eq!(config.classes.len(), 2);
        let malware = config.classes.get("malware").expect("malware entry");
        assert_eq!(malware.low, 0.4);
        assert_eq!(malware.medium, 0.7);
        assert_eq!(malware.high, 0.9);
    }

    #[test]
    fn invalid_payloads_are_rejected_explicitly() {
        let mut unknown_version = valid_payload();
        unknown_version["thresholds"]["version"] = serde_json::json!(2);
        assert!(parse_thresholds(&unknown_version).is_none(), "version 2");

        let mut unknown_class = valid_payload();
        unknown_class["thresholds"]["classes"]["not_a_category"] =
            serde_json::json!({ "low": 0.4, "medium": 0.7, "high": 0.9 });
        assert!(parse_thresholds(&unknown_class).is_none(), "unknown class");

        let mut inverted = valid_payload();
        inverted["thresholds"]["classes"]["malware"] =
            serde_json::json!({ "low": 0.9, "medium": 0.7, "high": 0.5 });
        assert!(
            parse_thresholds(&inverted).is_none(),
            "low <= medium <= high"
        );

        let mut zero_low = valid_payload();
        zero_low["thresholds"]["classes"]["malware"] =
            serde_json::json!({ "low": 0.0, "medium": 0.7, "high": 0.9 });
        assert!(parse_thresholds(&zero_low).is_none(), "low must be > 0");

        let mut above_one = valid_payload();
        above_one["thresholds"]["classes"]["malware"] =
            serde_json::json!({ "low": 0.4, "medium": 0.7, "high": 1.5 });
        assert!(parse_thresholds(&above_one).is_none(), "high <= 1");

        let mut empty = valid_payload();
        empty["thresholds"]["classes"] = serde_json::json!({});
        assert!(
            parse_thresholds(&empty).is_none(),
            "classes must be non-empty"
        );

        let mut extra_key = valid_payload();
        extra_key["thresholds"]["surprise"] = serde_json::json!(1);
        assert!(
            parse_thresholds(&extra_key).is_none(),
            "unknown keys are rejected, not ignored"
        );

        assert!(
            parse_thresholds(&serde_json::json!({ "tresholds": {} })).is_none(),
            "a typo must not silently configure nothing"
        );
        assert!(
            parse_thresholds(&serde_json::json!({ "thresholds": {}, "extra": 1 })).is_none(),
            "metadata must be exactly the threshold payload"
        );
        assert!(parse_thresholds(&serde_json::json!({ "thresholds": 7 })).is_none());
    }

    #[test]
    fn band_mapping_honours_boundaries() {
        let threshold = ClassThreshold {
            low: 0.4,
            medium: 0.7,
            high: 0.9,
        };
        assert_eq!(band_for(0.39, &threshold), None);
        assert_eq!(band_for(0.4, &threshold), Some(FindingSeverity::Low));
        assert_eq!(band_for(0.69, &threshold), Some(FindingSeverity::Low));
        assert_eq!(band_for(0.7, &threshold), Some(FindingSeverity::Medium));
        assert_eq!(band_for(0.89, &threshold), Some(FindingSeverity::Medium));
        assert_eq!(band_for(0.9, &threshold), Some(FindingSeverity::High));
        assert_eq!(band_for(1.0, &threshold), Some(FindingSeverity::High));
    }

    #[test]
    fn rules_merge_first_definition_wins_by_priority() {
        let high = rule_with(10, Some(valid_payload()));
        let low = rule_with(
            0,
            Some(threshold_payload(serde_json::json!({
                "version": 1,
                "classes": { "malware": { "low": 0.99, "medium": 0.995, "high": 0.999 } }
            }))),
        );
        let config = thresholds_from_rules(&[low, high]).expect("merged thresholds must exist");
        assert_eq!(
            config.classes.get("malware").expect("malware").low,
            0.4,
            "the higher-priority rule defines the class"
        );
        assert!(config.classes.contains_key("phishing"));
    }

    #[test]
    fn disabled_or_invalid_rules_do_not_configure_thresholds() {
        let mut disabled = rule_with(10, Some(valid_payload()));
        disabled.enabled = false;
        assert_eq!(
            thresholds_from_rules(&[disabled]),
            None,
            "a disabled rule contributes nothing"
        );

        let invalid = rule_with(10, Some(serde_json::json!({ "thresholds": 7 })));
        assert_eq!(
            thresholds_from_rules(&[invalid]),
            None,
            "an invalid payload never becomes configuration"
        );

        let absent = rule_with(10, None);
        assert_eq!(thresholds_from_rules(&[absent]), None);
    }

    #[test]
    fn publish_validation_is_metadata_conditional() {
        assert!(validate_family_rules(&[rule_with(0, None)]));
        assert!(validate_family_rules(&[rule_with(
            0,
            Some(valid_payload())
        )]));
        assert!(!validate_family_rules(&[rule_with(
            0,
            Some(serde_json::json!({ "thresholds": { "version": 1, "classes": {} } }))
        )]));
        assert!(!validate_family_rules(&[
            rule_with(0, Some(valid_payload())),
            rule_with(1, Some(serde_json::json!({ "thresholds": 7 })))
        ]));
    }

    #[test]
    fn category_keys_are_the_canonical_wire_names() {
        assert_eq!(
            category_key(FindingCategory::BusinessEmailCompromise),
            "business_email_compromise"
        );
        assert_eq!(category_key(FindingCategory::Malware), "malware");
        for label in super::super::runtime::INLINE_ML_LABELS {
            let category = label_to_category(label).expect("every label maps to a category");
            assert!(known_category_key(&category_key(category)));
        }
    }

    #[test]
    fn band_labels_and_confidence_follow_the_three_levels() {
        assert_eq!(band_label(FindingSeverity::High), "high");
        assert_eq!(band_label(FindingSeverity::Medium), "medium");
        assert_eq!(band_label(FindingSeverity::Low), "low");
        assert_eq!(band_confidence(FindingSeverity::High), Confidence::High);
        assert_eq!(band_confidence(FindingSeverity::Medium), Confidence::Medium);
        assert_eq!(band_confidence(FindingSeverity::Low), Confidence::Low);
    }
}

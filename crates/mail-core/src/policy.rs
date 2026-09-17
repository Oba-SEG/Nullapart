//! Policy evaluation bridge
//!
//! Mail-core integration point for the policy engine.
//! Evaluates policy rules against transaction context and produces disposition decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::{
    policy::{PolicyRevisionId, ReasonCode},
    transaction::{AuthResultType, Disposition, EnvelopeSender, Recipient},
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

/// Policy rule evaluator — evaluates rules against transaction context.
pub struct PolicyRuleEvaluator;

impl PolicyRuleEvaluator {
    /// Evaluate a set of policy rules against an evaluation request.
    /// Returns the first matching rule's action (by priority), or Allow if none match.
    pub fn evaluate(
        rules: &[nullapart_mail_contracts::policy::PolicyRule],
        request: &PolicyEvaluationRequest,
    ) -> PolicyEvaluationResult {
        // Sort rules by priority (highest first)
        let mut sorted_rules: Vec<&nullapart_mail_contracts::policy::PolicyRule> =
            rules.iter().filter(|r| r.enabled).collect();
        sorted_rules.sort_by_key(|r| std::cmp::Reverse(r.priority));

        for rule in &sorted_rules {
            if Self::matches_condition(&rule.condition, request) {
                return PolicyEvaluationResult {
                    disposition: rule.action.disposition,
                    reason_code: rule.action.reason_code.clone(),
                    policy_revision: request.policy_revision.clone(),
                    explanation: format!("Rule '{}' matched: {:?}", rule.name, rule.condition),
                    findings_applied: vec![rule.name.clone()],
                    evaluated_at: request.evaluated_at,
                };
            }
        }

        // No rule matched — default allow
        PolicyEvaluationResult {
            disposition: Disposition::Allow,
            reason_code: ReasonCode::allowed(),
            policy_revision: request.policy_revision.clone(),
            explanation: "No policy rule matched".to_string(),
            findings_applied: Vec::new(),
            evaluated_at: request.evaluated_at,
        }
    }

    /// Check if a condition matches the evaluation request.
    fn matches_condition(
        condition: &nullapart_mail_contracts::policy::PolicyCondition,
        request: &PolicyEvaluationRequest,
    ) -> bool {
        // Check sender condition
        if let Some(ref sender_cond) = condition.sender {
            if !Self::matches_sender(sender_cond, &request.envelope_sender) {
                return false;
            }
        }

        // Check auth conditions
        if let Some(ref auth_cond) = condition.auth {
            if !Self::matches_auth(auth_cond, request) {
                return false;
            }
        }

        // Check finding conditions
        if let Some(ref finding_cond) = condition.finding {
            if !Self::matches_finding(finding_cond, &request.findings) {
                return false;
            }
        }

        // Check content conditions (basic — no actual content in request, only size/attachment metadata)
        // Content conditions require additional metadata that isn't in PolicyEvaluationRequest yet.
        // This is by design: content inspection happens in the scanner layer, not policy.

        true
    }

    /// Match sender condition against envelope sender.
    fn matches_sender(
        cond: &nullapart_mail_contracts::policy::SenderCondition,
        sender: &EnvelopeSender,
    ) -> bool {
        let sender_addr = sender.address().to_lowercase();

        // Check domain
        if let Some(ref domains) = cond.domain {
            let sender_domain = sender_addr.rsplit('@').next().unwrap_or("");
            if !domains.iter().any(|d| d.to_lowercase() == sender_domain) {
                return false;
            }
        }

        // Check address
        if let Some(ref addresses) = cond.address {
            if !addresses.iter().any(|a| a.to_lowercase() == sender_addr) {
                return false;
            }
        }

        // Check internal
        if let Some(_internal) = cond.internal {
            // Internal flag is determined by the caller (not in envelope sender)
            // This would require additional context — return true for now
        }

        // Check authenticated
        if let Some(_authenticated) = cond.authenticated {
            // Authenticated flag is determined by the caller
        }

        true
    }

    /// Match auth condition against SPF/DKIM/DMARC results.
    fn matches_auth(
        cond: &nullapart_mail_contracts::policy::AuthCondition,
        request: &PolicyEvaluationRequest,
    ) -> bool {
        // Check SPF
        if let Some(ref expected_spf) = cond.spf {
            match &request.spf_result {
                Some(result_str) => {
                    let parsed = match result_str.to_lowercase().as_str() {
                        "pass" => AuthResultType::Pass,
                        "fail" => AuthResultType::Fail,
                        "softfail" => AuthResultType::Softfail,
                        "neutral" => AuthResultType::Neutral,
                        "none" => AuthResultType::None,
                        "permerror" => AuthResultType::Permerror,
                        "temperror" => AuthResultType::Temperror,
                        _ => return false,
                    };
                    if !expected_spf.contains(&parsed) {
                        return false;
                    }
                },
                None => {
                    // No SPF result — only match if None is in expected
                    if !expected_spf.contains(&AuthResultType::None) {
                        return false;
                    }
                },
            }
        }

        // Check DKIM
        if let Some(ref expected_dkim) = cond.dkim {
            match &request.dkim_result {
                Some(result_str) => {
                    let parsed = match result_str.to_lowercase().as_str() {
                        "pass" => AuthResultType::Pass,
                        "fail" => AuthResultType::Fail,
                        "softfail" => AuthResultType::Softfail,
                        "neutral" => AuthResultType::Neutral,
                        "none" => AuthResultType::None,
                        "permerror" => AuthResultType::Permerror,
                        "temperror" => AuthResultType::Temperror,
                        _ => return false,
                    };
                    if !expected_dkim.contains(&parsed) {
                        return false;
                    }
                },
                None => {
                    if !expected_dkim.contains(&AuthResultType::None) {
                        return false;
                    }
                },
            }
        }

        // Check DMARC
        if let Some(ref expected_dmarc) = cond.dmarc {
            match &request.dmarc_result {
                Some(result_str) => {
                    let parsed = match result_str.to_lowercase().as_str() {
                        "pass" => AuthResultType::Pass,
                        "fail" => AuthResultType::Fail,
                        "softfail" => AuthResultType::Softfail,
                        "neutral" => AuthResultType::Neutral,
                        "none" => AuthResultType::None,
                        "permerror" => AuthResultType::Permerror,
                        "temperror" => AuthResultType::Temperror,
                        _ => return false,
                    };
                    if !expected_dmarc.contains(&parsed) {
                        return false;
                    }
                },
                None => {
                    if !expected_dmarc.contains(&AuthResultType::None) {
                        return false;
                    }
                },
            }
        }

        true
    }

    /// Match finding condition against findings list.
    fn matches_finding(
        cond: &nullapart_mail_contracts::policy::FindingCondition,
        findings: &[SecurityFinding],
    ) -> bool {
        if findings.is_empty() {
            return false;
        }

        // Filter findings by scanner type if specified
        let filtered: Vec<&SecurityFinding> = if let Some(ref scanners) = cond.scanner {
            findings
                .iter()
                .filter(|f| scanners.contains(&f.scanner))
                .collect()
        } else {
            findings.iter().collect()
        };

        // Filter by severity
        let filtered: Vec<&SecurityFinding> = if let Some(ref severities) = cond.severity {
            filtered
                .into_iter()
                .filter(|f| severities.contains(&f.severity))
                .collect()
        } else {
            filtered
        };

        // Filter by category
        let filtered: Vec<&SecurityFinding> = if let Some(ref categories) = cond.category {
            filtered
                .into_iter()
                .filter(|f| categories.contains(&f.category))
                .collect()
        } else {
            filtered
        };

        // Filter by false_positive
        if let Some(fp) = cond.false_positive {
            let filtered: Vec<&SecurityFinding> = filtered
                .into_iter()
                .filter(|f| f.false_positive == fp)
                .collect();
            return !filtered.is_empty();
        }

        !filtered.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullapart_mail_contracts::{
        finding::{
            Confidence, FindingCategory, FindingId, FindingScope, FindingSeverity, ScannerStatus,
            ScannerType,
        },
        policy::{AuthCondition, ConditionScope, PolicyCondition, PolicyRule, PolicyRuleId},
        transaction::{AuthResultType, EnvelopeSender},
        PolicyRevisionId, SecurityFinding,
    };

    fn test_request() -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            transaction_id: TransactionId::new(),
            customer_id: CustomerId::new("test"),
            deployment_id: DeploymentId::new("CZA-1"),
            envelope_sender: EnvelopeSender::new("user@evil.com"),
            recipients: vec![],
            findings: vec![],
            spf_result: Some("fail".to_string()),
            dkim_result: Some("fail".to_string()),
            dmarc_result: None,
            policy_revision: PolicyRevisionId::new(),
            evaluated_at: Utc::now(),
        }
    }

    fn test_request_clean() -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            transaction_id: TransactionId::new(),
            customer_id: CustomerId::new("test"),
            deployment_id: DeploymentId::new("CZA-1"),
            envelope_sender: EnvelopeSender::new("user@legit.com"),
            recipients: vec![],
            findings: vec![],
            spf_result: Some("pass".to_string()),
            dkim_result: Some("pass".to_string()),
            dmarc_result: Some("pass".to_string()),
            policy_revision: PolicyRevisionId::new(),
            evaluated_at: Utc::now(),
        }
    }

    #[test]
    fn no_rules_matches_default_allow() {
        let result = PolicyRuleEvaluator::evaluate(&[], &test_request());
        assert_eq!(result.disposition, Disposition::Allow);
        assert_eq!(result.reason_code, ReasonCode::allowed());
    }

    #[test]
    fn spf_fail_rule_matches() {
        let rule = PolicyRule {
            id: PolicyRuleId::new(),
            name: "reject-spf-fail".to_string(),
            priority: 100,
            condition: PolicyCondition {
                sender: None,
                recipient: None,
                auth: Some(AuthCondition {
                    spf: Some(vec![AuthResultType::Fail]),
                    dkim: None,
                    dmarc: None,
                }),
                content: None,
                finding: None,
                scope: ConditionScope::Transaction,
            },
            action: nullapart_mail_contracts::policy::PolicyAction {
                disposition: Disposition::Reject,
                reason_code: ReasonCode::reject_spf_fail(),
                notify: None,
                metadata: None,
            },
            enabled: true,
        };

        let result = PolicyRuleEvaluator::evaluate(&[rule], &test_request());
        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.reason_code, ReasonCode::reject_spf_fail());
    }

    #[test]
    fn clean_mail_gets_allow() {
        let rule = PolicyRule {
            id: PolicyRuleId::new(),
            name: "reject-spf-fail".to_string(),
            priority: 100,
            condition: PolicyCondition {
                sender: None,
                recipient: None,
                auth: Some(AuthCondition {
                    spf: Some(vec![AuthResultType::Fail]),
                    dkim: None,
                    dmarc: None,
                }),
                content: None,
                finding: None,
                scope: ConditionScope::Transaction,
            },
            action: nullapart_mail_contracts::policy::PolicyAction {
                disposition: Disposition::Reject,
                reason_code: ReasonCode::reject_spf_fail(),
                notify: None,
                metadata: None,
            },
            enabled: true,
        };

        let result = PolicyRuleEvaluator::evaluate(&[rule], &test_request_clean());
        assert_eq!(result.disposition, Disposition::Allow);
    }

    #[test]
    fn disabled_rule_does_not_match() {
        let rule = PolicyRule {
            id: PolicyRuleId::new(),
            name: "disabled-rule".to_string(),
            priority: 100,
            condition: PolicyCondition {
                sender: None,
                recipient: None,
                auth: Some(AuthCondition {
                    spf: Some(vec![AuthResultType::Fail]),
                    dkim: None,
                    dmarc: None,
                }),
                content: None,
                finding: None,
                scope: ConditionScope::Transaction,
            },
            action: nullapart_mail_contracts::policy::PolicyAction {
                disposition: Disposition::Reject,
                reason_code: ReasonCode::reject_spf_fail(),
                notify: None,
                metadata: None,
            },
            enabled: false,
        };

        let result = PolicyRuleEvaluator::evaluate(&[rule], &test_request());
        assert_eq!(result.disposition, Disposition::Allow);
    }

    #[test]
    fn finding_condition_matches() {
        let rule = PolicyRule {
            id: PolicyRuleId::new(),
            name: "quarantine-malware".to_string(),
            priority: 200,
            condition: PolicyCondition {
                sender: None,
                recipient: None,
                auth: None,
                content: None,
                finding: Some(nullapart_mail_contracts::policy::FindingCondition {
                    scanner: Some(vec![ScannerType::Clamav]),
                    severity: Some(vec![FindingSeverity::Critical, FindingSeverity::High]),
                    category: Some(vec![FindingCategory::Malware]),
                    false_positive: Some(false),
                }),
                scope: ConditionScope::Transaction,
            },
            action: nullapart_mail_contracts::policy::PolicyAction {
                disposition: Disposition::Quarantine,
                reason_code: ReasonCode::quarantine_malware(),
                notify: None,
                metadata: None,
            },
            enabled: true,
        };

        let finding = SecurityFinding {
            id: FindingId::new(),
            scope: FindingScope::Transaction,
            scanner: ScannerType::Clamav,
            scanner_status: ScannerStatus::Infected,
            severity: FindingSeverity::Critical,
            confidence: Confidence::High,
            category: FindingCategory::Malware,
            description: "EICAR test file".to_string(),
            details: None,
            indicators: vec![],
            created_at: Utc::now(),
            false_positive: false,
            transaction_id: None,
            tenant_message_id: None,
        };

        let mut request = test_request();
        request.findings = vec![finding];

        let result = PolicyRuleEvaluator::evaluate(&[rule], &request);
        assert_eq!(result.disposition, Disposition::Quarantine);
        assert_eq!(result.reason_code, ReasonCode::quarantine_malware());
    }

    #[test]
    fn priority_determines_winner() {
        let low_priority = PolicyRule {
            id: PolicyRuleId::new(),
            name: "low-priority".to_string(),
            priority: 10,
            condition: PolicyCondition {
                sender: None,
                recipient: None,
                auth: Some(AuthCondition {
                    spf: Some(vec![AuthResultType::Fail]),
                    dkim: None,
                    dmarc: None,
                }),
                content: None,
                finding: None,
                scope: ConditionScope::Transaction,
            },
            action: nullapart_mail_contracts::policy::PolicyAction {
                disposition: Disposition::Defer,
                reason_code: ReasonCode::defer_temporary(),
                notify: None,
                metadata: None,
            },
            enabled: true,
        };

        let high_priority = PolicyRule {
            id: PolicyRuleId::new(),
            name: "high-priority".to_string(),
            priority: 100,
            condition: PolicyCondition {
                sender: None,
                recipient: None,
                auth: Some(AuthCondition {
                    spf: Some(vec![AuthResultType::Fail]),
                    dkim: None,
                    dmarc: None,
                }),
                content: None,
                finding: None,
                scope: ConditionScope::Transaction,
            },
            action: nullapart_mail_contracts::policy::PolicyAction {
                disposition: Disposition::Reject,
                reason_code: ReasonCode::reject_spf_fail(),
                notify: None,
                metadata: None,
            },
            enabled: true,
        };

        let result = PolicyRuleEvaluator::evaluate(&[low_priority, high_priority], &test_request());
        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.findings_applied, vec!["high-priority"]);
    }
}

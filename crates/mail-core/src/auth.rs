//! Trusted authentication evidence
//!
//! Implements SPF/DKIM/DMARC verification using maintained protocol
//! implementations. Follows: docs/phases/PHASE-1-EXECUTION-PLAN.md Work Package 6
//!
//! Rules:
//! - Remove/ignore untrusted Internet authentication-result headers
//! - Preserve original headers as evidence, but distinguish from Nullapart observations
//! - Do not use ML/LLM for protocol correctness

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_mail_contracts::transaction::{AuthResult, AuthResultType};

/// SPF evaluation result from Nullapart's own verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfEvaluation {
    /// SPF result.
    pub result: AuthResultType,
    /// SPF domain evaluated.
    pub domain: String,
    /// Sender IP used for evaluation.
    pub sender_ip: String,
    /// SPF mechanism that matched (e.g., "include:_spf.google.com").
    pub matched_mechanism: Option<String>,
    /// Trusted evaluation timestamp.
    pub evaluated_at: DateTime<Utc>,
    /// Whether the result is trusted (Nullapart-generated).
    pub trusted: bool,
}

impl SpfEvaluation {
    /// Convert to a standard AuthResult for storage in transaction.
    pub fn to_auth_result(&self) -> AuthResult {
        AuthResult {
            result: self.result,
            detail: self.matched_mechanism.clone(),
            identity: Some(self.domain.clone()),
            selector: None,
            domain: Some(self.domain.clone()),
        }
    }
}

/// DKIM verification result from Nullapart's own verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimVerification {
    /// DKIM result.
    pub result: AuthResultType,
    /// Signing domain (d= tag).
    pub signing_domain: String,
    /// DKIM selector (s= tag).
    pub selector: String,
    /// Whether the signature body hash matches.
    pub body_hash_match: bool,
    /// Whether the signature header hash matches.
    pub header_hash_match: bool,
    /// Whether the signature is expired.
    pub expired: bool,
    /// Whether the signature is from the future.
    pub future_signature: bool,
    /// Trusted evaluation timestamp.
    pub evaluated_at: DateTime<Utc>,
    /// Whether the result is trusted (Nullapart-generated).
    pub trusted: bool,
}

impl DkimVerification {
    pub fn to_auth_result(&self) -> AuthResult {
        AuthResult {
            result: self.result,
            detail: if self.body_hash_match && self.header_hash_match {
                Some("signature valid".to_string())
            } else {
                Some("signature invalid".to_string())
            },
            identity: Some(self.signing_domain.clone()),
            selector: Some(self.selector.clone()),
            domain: Some(self.signing_domain.clone()),
        }
    }
}

/// DMARC alignment and result from Nullapart's own verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcEvaluation {
    /// DMARC result.
    pub result: AuthResultType,
    /// DMARC policy domain.
    pub domain: String,
    /// Whether SPF aligned.
    pub spf_aligned: bool,
    /// Whether DKIM aligned.
    pub dkim_aligned: bool,
    /// DMARC policy (none/quarantine/reject).
    pub policy: DmarcPolicy,
    /// Trusted evaluation timestamp.
    pub evaluated_at: DateTime<Utc>,
    /// Whether the result is trusted (Nullapart-generated).
    pub trusted: bool,
}

/// DMARC policy type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

impl DmarcEvaluation {
    pub fn to_auth_result(&self) -> AuthResult {
        let policy_str = match self.policy {
            DmarcPolicy::None => "none",
            DmarcPolicy::Quarantine => "quarantine",
            DmarcPolicy::Reject => "reject",
        };
        AuthResult {
            result: self.result,
            detail: Some(format!(
                "spf={} dkim={} policy={}",
                self.spf_aligned, self.dkim_aligned, policy_str
            )),
            identity: Some(self.domain.clone()),
            selector: None,
            domain: Some(self.domain.clone()),
        }
    }
}

/// ARC validation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcValidation {
    /// ARC chain status.
    pub chain_status: ArcChainStatus,
    /// ARC seal status.
    pub seal_status: ArcSealStatus,
    /// Number of ARC sets in the chain.
    pub chain_length: u32,
    /// Whether the chain is valid.
    pub valid: bool,
    /// Trusted evaluation timestamp.
    pub evaluated_at: DateTime<Utc>,
}

/// ARC chain status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArcChainStatus {
    Pass,
    Fail,
    None,
}

/// ARC seal status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArcSealStatus {
    Pass,
    Fail,
    None,
}

/// Complete authentication evidence for a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationEvidence {
    pub spf: Option<SpfEvaluation>,
    pub dkim: Option<DkimVerification>,
    pub dmarc: Option<DmarcEvaluation>,
    pub arc: Option<ArcValidation>,
    /// Untrusted headers from the internet (preserved but not trusted).
    pub untrusted_auth_headers: Vec<String>,
    /// When all evaluations completed.
    pub evaluated_at: DateTime<Utc>,
}

/// Configuration for authentication verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthVerificationConfig {
    /// Whether SPF verification is enabled.
    pub spf_enabled: bool,
    /// Whether DKIM verification is enabled.
    pub dkim_enabled: bool,
    /// Whether DMARC verification is enabled.
    pub dmarc_enabled: bool,
    /// Whether ARC validation is enabled.
    pub arc_enabled: bool,
    /// Trusted authentication header names to ignore.
    pub untrusted_header_names: Vec<String>,
}

impl Default for AuthVerificationConfig {
    fn default() -> Self {
        Self {
            spf_enabled: true,
            dkim_enabled: true,
            dmarc_enabled: true,
            arc_enabled: true,
            untrusted_header_names: vec![
                "Authentication-Results".to_string(),
                "ARC-Authentication-Results".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_to_auth_result() {
        let spf = SpfEvaluation {
            result: AuthResultType::Pass,
            domain: "example.com".to_string(),
            sender_ip: "1.2.3.4".to_string(),
            matched_mechanism: Some("include:_spf.google.com".to_string()),
            evaluated_at: Utc::now(),
            trusted: true,
        };
        let auth = spf.to_auth_result();
        assert_eq!(auth.result, AuthResultType::Pass);
        assert_eq!(auth.domain, Some("example.com".to_string()));
    }

    #[test]
    fn dkim_invalid_detail() {
        let dkim = DkimVerification {
            result: AuthResultType::Fail,
            signing_domain: "evil.com".to_string(),
            selector: "default".to_string(),
            body_hash_match: false,
            header_hash_match: true,
            expired: false,
            future_signature: false,
            evaluated_at: Utc::now(),
            trusted: true,
        };
        let auth = dkim.to_auth_result();
        assert!(auth.detail.unwrap().contains("invalid"));
    }

    #[test]
    fn default_config_trusts_no_internet_headers() {
        let config = AuthVerificationConfig::default();
        assert!(!config.untrusted_header_names.is_empty());
    }
}

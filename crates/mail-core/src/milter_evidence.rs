//! Pre-queue Rspamd/milter evidence: parse, validate and merge.
//!
//! Trust chain (docs/26 boundary, AGENTS evidence rules): client-supplied
//! spam-evidence headers are stripped at the milter stage by
//! `infrastructure/rspamd/lua.d/nullapart_evidence.lua` and re-added only
//! when the metric action is at least "add header"; the private reinjection
//! listener strips them again in Postfix (`header_checks_reinjection`)
//! because it runs without milters. The after-queue `mailcore-filter`
//! therefore reads `X-Rspamd-*` headers from the queued message — which are
//! authored exclusively by this deployment's Rspamd — and forwards them
//! inside the HMAC-authenticated handoff. This module owns the bounded
//! parser, the contract validation and the merge into the scanner-fabric
//! result. Mail Core keeps final disposition authority; Rspamd reject stays
//! disabled.
//!
//! The pipeline's message headers are never consulted anywhere else
//! (`domain_auth_telemetry` reads only the authenticated handoff channel),
//! so a forged Internet-supplied header cannot become evidence.

use chrono::Utc;
use nullapart_mail_contracts::finding::{
    Confidence, FindingCategory, FindingId, FindingScope, FindingSeverity, ScannerStatus,
    ScannerType, SecurityFinding,
};
use nullapart_scanner_sdk::fabric::ScannerOutcome;
use nullapart_scanner_sdk::trait_defs::ScannerId as SdkScannerId;
use nullapart_scanner_sdk::types::{ExecutionClass, ScannerProvenance};

use crate::handoff::MilterObservations;
use crate::scanner_fabric::{ScannerFabricResult, ScannerResultProfile};
use crate::scanner_pipeline::TenantScanContext;

/// Scanner identity recorded in `scanner_results` for milter evidence.
pub const RSPAMD_SCANNER_ID: &str = "rspamd";

const MAX_HEADER_SCAN_BYTES: usize = 64 * 1024;
const MAX_SCORE: f64 = 1000.0;
const MAX_SYMBOLS: usize = 64;
const MAX_SYMBOL_LEN: usize = 64;
const MAX_ACTIONS: usize = 8;
const MAX_ACTION_LEN: usize = 32;
const MAX_AUTH_RESULT_LEN: usize = 64;
const MAX_LATENCY_MS: u64 = 60_000;
/// At most this many symbols are carried into finding details JSON.
const MAX_DETAIL_SYMBOLS: usize = 32;

/// Parse the bounded evidence headers Rspamd attached to a queued message.
///
/// Absent headers yield zero-valued observations (no evidence), which the
/// caller treats as "nothing to merge". Every field is bounds-checked while
/// parsing so hostile header content cannot inflate memory or the handoff.
pub fn parse_queued_evidence(raw_message: &[u8]) -> MilterObservations {
    let mut score: Option<f64> = None;
    let mut actions: Vec<String> = Vec::new();
    let mut is_spam = false;
    let mut symbols: Vec<String> = Vec::new();

    for (name, value) in bounded_headers(raw_message) {
        let value = value.trim();
        match name.as_str() {
            "x-rspamd-score" => {
                if let Ok(parsed) = value.parse::<f64>() {
                    if parsed.is_finite() && (0.0..=MAX_SCORE).contains(&parsed) {
                        score = Some(parsed);
                    }
                }
            },
            "x-rspamd-action" => {
                if !value.is_empty() && value.len() <= MAX_ACTION_LEN && actions.len() < MAX_ACTIONS
                {
                    let action = value.to_ascii_lowercase();
                    if action != "no action" {
                        is_spam = true;
                    }
                    actions.push(action);
                }
            },
            "x-rspamd-is-spam" | "x-spam" => {
                let lower = value.to_ascii_lowercase();
                if lower == "yes" || lower == "true" {
                    is_spam = true;
                }
            },
            "x-rspamd-symbols" => {
                for part in value.split(',') {
                    let symbol = part.trim();
                    let symbol = symbol.split('(').next().unwrap_or(symbol).trim();
                    if symbol.is_empty()
                        || symbol.len() > MAX_SYMBOL_LEN
                        || symbols.len() >= MAX_SYMBOLS
                    {
                        continue;
                    }
                    if !symbols.iter().any(|existing| existing == symbol) {
                        symbols.push(symbol.to_ascii_uppercase());
                    }
                }
            },
            _ => {},
        }
    }

    let (spf_result, dkim_result, dmarc_result) = derive_auth_results(&symbols);
    MilterObservations {
        score: score.unwrap_or(0.0),
        actions,
        is_spam,
        dkim_result,
        spf_result,
        dmarc_result,
        symbols,
        latency_ms: 0,
    }
}

/// Validate handoff observation bounds (defense in depth; the producer is
/// our own filter, but the contract is independently enforced).
pub fn validate_observations(observations: &MilterObservations) -> bool {
    observations.score.is_finite()
        && (0.0..=MAX_SCORE).contains(&observations.score)
        && observations.actions.len() <= MAX_ACTIONS
        && observations
            .actions
            .iter()
            .all(|action| !action.is_empty() && action.len() <= MAX_ACTION_LEN)
        && observations.symbols.len() <= MAX_SYMBOLS
        && observations
            .symbols
            .iter()
            .all(|symbol| !symbol.is_empty() && symbol.len() <= MAX_SYMBOL_LEN)
        && observations
            .dkim_result
            .as_deref()
            .is_none_or(|value| !value.is_empty() && value.len() <= MAX_AUTH_RESULT_LEN)
        && observations
            .spf_result
            .as_deref()
            .is_none_or(|value| !value.is_empty() && value.len() <= MAX_AUTH_RESULT_LEN)
        && observations
            .dmarc_result
            .as_deref()
            .is_none_or(|value| !value.is_empty() && value.len() <= MAX_AUTH_RESULT_LEN)
        && observations.latency_ms <= MAX_LATENCY_MS
}

/// Merge trusted milter evidence into the durable scan result: one `rspamd`
/// scanner row always (when evidence was observed) and a spam finding when
/// Rspamd's verdict is a spam action. The finding follows the existing local
/// policy contract (any applied finding quarantines); a clean or absent
/// evidence set adds no finding and never changes disposition.
pub fn merge_milter_evidence(
    mut result: ScannerFabricResult,
    context: &TenantScanContext,
) -> ScannerFabricResult {
    let Some(observations) = context.milter_observations.as_ref() else {
        return result;
    };

    let status = if observations.is_spam {
        ScannerStatus::Threat
    } else {
        ScannerStatus::Clean
    };
    let finding_count = usize::from(observations.is_spam);
    result.results.push(ScannerOutcome {
        scanner_id: SdkScannerId::new(RSPAMD_SCANNER_ID),
        scanner_type: ScannerType::Rspamd,
        execution_class: ExecutionClass::OptionalEnrichment,
        required: false,
        applicable: true,
        status,
        duration_ms: observations.latency_ms,
        finding_count,
        failure: None,
        completed_at: Utc::now(),
        provenance: ScannerProvenance {
            scanner_node_id: None,
            scanner_profile_id: Some(RSPAMD_SCANNER_ID.to_string()),
            scanner_profile_version: None,
            engine_version: None,
            ruleset_version: None,
            started_at: Utc::now(),
        },
    });
    result.scanner_profiles.push(ScannerResultProfile {
        scanner_id: SdkScannerId::new(RSPAMD_SCANNER_ID),
        scanner_type: ScannerType::Rspamd,
        required: false,
    });

    if observations.is_spam {
        let action = observations
            .actions
            .first()
            .map(String::as_str)
            .unwrap_or("unknown");
        let detail_symbols: Vec<&str> = observations
            .symbols
            .iter()
            .take(MAX_DETAIL_SYMBOLS)
            .map(String::as_str)
            .collect();
        result.findings.push(SecurityFinding {
            id: FindingId::new(),
            scope: FindingScope::Transaction,
            scanner: ScannerType::Rspamd,
            scanner_status: ScannerStatus::Threat,
            severity: FindingSeverity::High,
            confidence: Confidence::High,
            category: FindingCategory::Spam,
            description: format!(
                "Rspamd spam verdict: score {:.2} (action: {action})",
                observations.score
            ),
            details: Some(serde_json::json!({
                "score": observations.score,
                "action": action,
                "is_spam": observations.is_spam,
                "symbols": detail_symbols,
            })),
            indicators: Vec::new(),
            created_at: Utc::now(),
            false_positive: false,
            transaction_id: Some(context.transaction_id.clone()),
            tenant_message_id: Some(context.tenant_message_id.clone()),
        });
    }

    result
}

/// Derive normalized SPF/DKIM/DMARC results from Rspamd symbol names.
/// Failure-class symbols take precedence over passes so mixed evidence
/// resolves fail-closed.
fn derive_auth_results(symbols: &[String]) -> (Option<String>, Option<String>, Option<String>) {
    fn mapped(symbols: &[String], table: &[(&str, &str)]) -> Option<String> {
        table
            .iter()
            .find(|(symbol, _)| symbols.iter().any(|value| value == symbol))
            .map(|(_, result)| (*result).to_string())
    }

    let spf = mapped(
        symbols,
        &[
            ("R_SPF_FAIL", "fail"),
            ("R_SPF_SOFTFAIL", "softfail"),
            ("R_SPF_PERMERROR", "permerror"),
            ("R_SPF_DROPT", "fail"),
            ("R_SPF_NEUTRAL", "neutral"),
            ("R_SPF_NONE", "none"),
            ("R_SPF_ALLOW", "pass"),
        ],
    );
    let dkim = mapped(
        symbols,
        &[
            ("DKIM_FAIL", "fail"),
            ("DKIM_TEMPFAIL", "temperror"),
            ("DKIM_PERMERROR", "permerror"),
            ("DKIM_MISSING", "none"),
            ("DKIM_ALLOW", "pass"),
        ],
    );
    let dmarc = mapped(
        symbols,
        &[
            ("DMARC_REJECT", "reject"),
            ("DMARC_QUARANTINE", "quarantine"),
            ("DMARC_FAIL", "fail"),
            ("DMARC_UNKNOWN", "none"),
            ("DMARC_ALLOW", "pass"),
        ],
    );
    (spf, dkim, dmarc)
}

/// Extract case-insensitive `name: value` pairs from the message header
/// block only, unfolding RFC 5322 continuation lines. Truncated at
/// [`MAX_HEADER_SCAN_BYTES`]; a missing header block yields nothing.
fn bounded_headers(raw_message: &[u8]) -> Vec<(String, String)> {
    let slice = &raw_message[..raw_message.len().min(MAX_HEADER_SCAN_BYTES)];
    let header_end = slice
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .or_else(|| slice.windows(2).position(|window| window == b"\n\n"))
        .unwrap_or(slice.len());
    let header_block = &slice[..header_end];

    let text = String::from_utf8_lossy(header_block);
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, previous)) = headers.last_mut() {
                previous.push(' ');
                previous.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            if !name.is_empty() {
                headers.push((name, value.trim_start().to_string()));
            }
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use nullapart_mail_contracts::transaction::{
        CustomerId, DeploymentId, TenantMessageId, TraceId, TransactionId,
    };

    use super::*;

    fn observation(score: f64, is_spam: bool) -> MilterObservations {
        MilterObservations {
            score,
            actions: if is_spam {
                vec!["add header".to_string()]
            } else {
                Vec::new()
            },
            is_spam,
            dkim_result: None,
            spf_result: None,
            dmarc_result: None,
            symbols: Vec::new(),
            latency_ms: 0,
        }
    }

    fn empty_result() -> ScannerFabricResult {
        ScannerFabricResult {
            results: Vec::new(),
            scanner_profiles: Vec::new(),
            findings: Vec::new(),
            failures: Vec::new(),
            requires_hold: false,
        }
    }

    fn context(observations: Option<MilterObservations>) -> TenantScanContext {
        TenantScanContext {
            tenant_message_id: TenantMessageId::new(),
            transaction_id: TransactionId::new(),
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            customer_id: CustomerId::new("customer-one"),
            trace_id: TraceId::new(),
            accepted_at: Utc::now(),
            envelope_sender: "sender@example.test".to_string(),
            recipients: vec!["recipient@example.test".to_string()],
            milter_observations: observations,
        }
    }

    #[test]
    fn parse_extracts_evidence_headers_and_derives_auth_fail_closed() {
        let raw = b"Received: from example.com\r\n\
X-Rspamd-Score: 7.41\r\n\
X-Rspamd-Action: add header\r\n\
X-Rspamd-Is-Spam: yes\r\n\
X-Rspamd-Symbols: R_SPF_FAIL,DKIM_ALLOW,DMARC_QUARANTINE,SUBJ_ALL_CAPS(3.00),MISSING_MID\r\n\
From: promo@gmail.com\r\n\
\r\nbody";
        let observations = parse_queued_evidence(raw);
        assert_eq!(observations.score, 7.41);
        assert!(observations.is_spam);
        assert_eq!(observations.actions, vec!["add header"]);
        assert_eq!(observations.spf_result.as_deref(), Some("fail"));
        assert_eq!(observations.dkim_result.as_deref(), Some("pass"));
        assert_eq!(observations.dmarc_result.as_deref(), Some("quarantine"));
        assert!(observations.symbols.contains(&"SUBJ_ALL_CAPS".to_string()));
        assert!(observations.symbols.contains(&"MISSING_MID".to_string()));
    }

    #[test]
    fn parse_unfolds_continuations_and_ignores_forged_untrusted_names() {
        let raw = b"X-Rspamd-Symbols: A,B,\r\n\tC\r\n\
X-Spam-Score: 99.9\r\n\
Subject: hi\r\n\nbody";
        let observations = parse_queued_evidence(raw);
        assert_eq!(
            observations.symbols,
            vec!["A".to_string(), "B".to_string(), "C".to_string()]
        );
        assert_eq!(observations.score, 0.0, "untrusted X-Spam-Score ignored");
        assert!(!observations.is_spam);
    }

    #[test]
    fn parse_without_evidence_headers_yields_nothing() {
        let observations = parse_queued_evidence(b"From: a@example.test\r\n\r\nbody");
        assert_eq!(observations.score, 0.0);
        assert!(!observations.is_spam);
        assert!(observations.actions.is_empty());
        assert!(observations.symbols.is_empty());
        assert!(observations.spf_result.is_none());
    }

    #[test]
    fn parse_rejects_out_of_range_scores_and_oversized_symbols() {
        let long_symbol = "X".repeat(MAX_SYMBOL_LEN + 1);
        let raw = format!("X-Rspamd-Score: 5000\r\nX-Rspamd-Symbols: {long_symbol},GOOD\r\n\r\n");
        let observations = parse_queued_evidence(raw.as_bytes());
        assert_eq!(observations.score, 0.0);
        assert_eq!(observations.symbols, vec!["GOOD".to_string()]);
    }

    #[test]
    fn validation_enforces_contract_bounds() {
        assert!(validate_observations(&observation(7.41, true)));
        assert!(!validate_observations(&observation(f64::NAN, false)));
        assert!(!validate_observations(&observation(-1.0, false)));

        let mut oversized = observation(1.0, false);
        oversized.symbols = vec!["OK".to_string(); MAX_SYMBOLS + 1];
        assert!(!validate_observations(&oversized));

        let mut slow = observation(1.0, false);
        slow.latency_ms = MAX_LATENCY_MS + 1;
        assert!(!validate_observations(&slow));
    }

    #[test]
    fn merge_with_spam_evidence_adds_threat_row_and_finding() {
        let context = context(Some(observation(7.41, true)));
        let merged = merge_milter_evidence(empty_result(), &context);
        assert_eq!(merged.results.len(), 1);
        let outcome = &merged.results[0];
        assert_eq!(outcome.scanner_id.0, RSPAMD_SCANNER_ID);
        assert_eq!(outcome.scanner_type, ScannerType::Rspamd);
        assert_eq!(outcome.status, ScannerStatus::Threat);
        assert!(!outcome.required);
        assert_eq!(merged.findings.len(), 1);
        let finding = &merged.findings[0];
        assert_eq!(finding.category, FindingCategory::Spam);
        assert_eq!(finding.severity, FindingSeverity::High);
        assert!(finding.description.contains("7.41"));
        assert_eq!(
            finding.transaction_id.as_ref(),
            Some(&context.transaction_id)
        );
    }

    #[test]
    fn merge_with_clean_evidence_adds_row_without_finding() {
        let context = context(Some(observation(0.0, false)));
        let merged = merge_milter_evidence(empty_result(), &context);
        assert_eq!(merged.results.len(), 1);
        assert_eq!(merged.results[0].status, ScannerStatus::Clean);
        assert!(merged.findings.is_empty());
    }

    #[test]
    fn merge_without_evidence_is_a_no_op() {
        let context = context(None);
        let merged = merge_milter_evidence(empty_result(), &context);
        assert!(merged.results.is_empty());
        assert!(merged.findings.is_empty());
        assert!(merged.scanner_profiles.is_empty());
    }
}

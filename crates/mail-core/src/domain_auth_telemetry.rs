//! Phase 5 live authentication telemetry projection.
//!
//! This module projects trusted handoff metadata into content-free
//! domain-security read rows. It deliberately stores only normalized domains,
//! source IP, authentication result labels and disposition; it does not store
//! raw MIME, raw headers, Authentication-Results text or DNS payloads.
//!
//! Trust boundary: authentication evidence comes only from the Milter/Rspamd
//! observation channel on our own content path. Internet-supplied
//! `Authentication-Results`/`ARC-Authentication-Results` headers are
//! attacker-controlled for inbound mail (Phase 1: "Never trust
//! Internet-supplied `Authentication-Results`"), so they are never parsed
//! into the stored evidence columns. When the Milter observation does not
//! carry a value (for example the DKIM signing domain), the column stays NULL
//! instead of being backfilled from message headers.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use nullapart_mail_contracts::transaction::{
    CustomerId, DeploymentId, Disposition, TenantMessageId, TransactionId,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::handoff::AfterQueueHandoffRequest;

const MAX_AUTH_RESULT_LEN: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EffectiveAuthResults {
    spf: Option<String>,
    dkim: Option<String>,
    dmarc: Option<String>,
    arc: Option<String>,
    spf_aligned: Option<String>,
    dkim_aligned: Option<String>,
    dkim_domain: Option<String>,
    dkim_selector: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainAuthTelemetryOutcome {
    Recorded,
    SkippedNoOwnedFromDomain,
    SkippedInvalidSourceIp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DomainAuthTelemetryError {
    #[error("domain authentication telemetry is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct DomainAuthTelemetryInput<'a> {
    pub deployment_id: &'a DeploymentId,
    pub customer_id: &'a CustomerId,
    pub transaction_id: &'a TransactionId,
    pub tenant_message_id: &'a TenantMessageId,
    pub request: &'a AfterQueueHandoffRequest,
    pub raw_mime: &'a [u8],
    pub disposition: Disposition,
}

pub async fn project_handoff_auth_telemetry(
    pool: &PgPool,
    input: DomainAuthTelemetryInput<'_>,
) -> Result<DomainAuthTelemetryOutcome, DomainAuthTelemetryError> {
    let source_ip: IpAddr = match input.request.connection.client_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(DomainAuthTelemetryOutcome::SkippedInvalidSourceIp),
    };
    let Some(header_from_domain) = header_from_domain(input.raw_mime) else {
        return Ok(DomainAuthTelemetryOutcome::SkippedNoOwnedFromDomain);
    };
    let envelope_from_domain = email_domain(input.request.envelope_sender.address());
    let source_domain = envelope_from_domain
        .clone()
        .or_else(|| Some(header_from_domain.clone()));
    let auth_results = effective_auth_results(input.request, &header_from_domain);

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| DomainAuthTelemetryError::Unavailable)?;
    set_scope(&mut transaction, input.deployment_id, input.customer_id).await?;
    let domain_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT d.id \
         FROM domains AS d \
         JOIN customers AS c ON c.id = d.customer_id \
         WHERE d.customer_id = $1 \
           AND c.deployment_id = $2 \
           AND d.verification_status = 'verified' \
           AND lower(d.domain) = lower($3)",
    )
    .bind(&input.customer_id.0)
    .bind(&input.deployment_id.0)
    .bind(&header_from_domain)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DomainAuthTelemetryError::Unavailable)?;
    let Some(domain_id) = domain_id else {
        transaction
            .commit()
            .await
            .map_err(|_| DomainAuthTelemetryError::Unavailable)?;
        return Ok(DomainAuthTelemetryOutcome::SkippedNoOwnedFromDomain);
    };

    sqlx::query(
        "INSERT INTO domain_auth_telemetry (\
             deployment_id, customer_id, domain_id, transaction_id, tenant_message_id, \
             source_ip, source_domain, envelope_from_domain, header_from_domain, \
             spf_result, dkim_result, dmarc_result, spf_aligned_result, \
             dkim_aligned_result, dkim_domain, dkim_selector, arc_result, \
             disposition, observed_at\
         ) VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) \
         ON CONFLICT (deployment_id, tenant_message_id, domain_id) DO UPDATE SET \
             source_ip = EXCLUDED.source_ip, \
             source_domain = EXCLUDED.source_domain, \
             envelope_from_domain = EXCLUDED.envelope_from_domain, \
             header_from_domain = EXCLUDED.header_from_domain, \
             spf_result = EXCLUDED.spf_result, \
             dkim_result = EXCLUDED.dkim_result, \
             dmarc_result = EXCLUDED.dmarc_result, \
             spf_aligned_result = EXCLUDED.spf_aligned_result, \
             dkim_aligned_result = EXCLUDED.dkim_aligned_result, \
             dkim_domain = EXCLUDED.dkim_domain, \
             dkim_selector = EXCLUDED.dkim_selector, \
             arc_result = EXCLUDED.arc_result, \
             disposition = EXCLUDED.disposition, \
             observed_at = EXCLUDED.observed_at",
    )
    .bind(&input.deployment_id.0)
    .bind(&input.customer_id.0)
    .bind(domain_id)
    .bind(input.transaction_id.0)
    .bind(input.tenant_message_id.0)
    .bind(source_ip.to_string())
    .bind(&source_domain)
    .bind(&envelope_from_domain)
    .bind(&header_from_domain)
    .bind(&auth_results.spf)
    .bind(&auth_results.dkim)
    .bind(&auth_results.dmarc)
    .bind(&auth_results.spf_aligned)
    .bind(&auth_results.dkim_aligned)
    .bind(&auth_results.dkim_domain)
    .bind(&auth_results.dkim_selector)
    .bind(&auth_results.arc)
    .bind(disposition(input.disposition))
    .bind(observed_at(input.request.handoff_at))
    .execute(&mut *transaction)
    .await
    .map_err(|_| DomainAuthTelemetryError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| DomainAuthTelemetryError::Unavailable)?;
    Ok(DomainAuthTelemetryOutcome::Recorded)
}

async fn set_scope(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &DeploymentId,
    customer_id: &CustomerId,
) -> Result<(), DomainAuthTelemetryError> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DomainAuthTelemetryError::Unavailable)?;
    Ok(())
}

fn observed_at(value: DateTime<Utc>) -> DateTime<Utc> {
    value
}

fn disposition(value: Disposition) -> &'static str {
    match value {
        Disposition::Allow => "allow",
        Disposition::Quarantine => "quarantine",
        Disposition::Reject => "reject",
        Disposition::Hold => "hold",
        Disposition::Defer => "defer",
    }
}

fn normalize_auth_result(value: Option<&str>) -> Option<String> {
    let value = value?.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    Some(value.chars().take(MAX_AUTH_RESULT_LEN).collect())
}

/// Build the stored authentication evidence for one handoff.
///
/// Only the Milter observation channel is trusted: it is produced by our own
/// Rspamd/Milter path. Message headers are never consulted, so a forged
/// Internet-supplied `Authentication-Results` cannot become evidence, an
/// alignment result or a DMARC alignment metric. SPF alignment is derived from
/// the Milter SPF result plus the envelope sender domain, which is the domain
/// that Milter SPF validated. DKIM alignment, the DKIM signing domain and the
/// selector stay NULL because the Milter observation contract does not carry
/// the DKIM `d=`/`s=` values and headers are not trusted to supply them.
fn effective_auth_results(
    request: &AfterQueueHandoffRequest,
    header_from_domain: &str,
) -> EffectiveAuthResults {
    let spf = normalize_auth_result(request.milter_observations.spf_result.as_deref());
    let dkim = normalize_auth_result(request.milter_observations.dkim_result.as_deref());
    let dmarc = normalize_auth_result(request.milter_observations.dmarc_result.as_deref());
    let envelope_from_domain = email_domain(request.envelope_sender.address());
    EffectiveAuthResults {
        spf_aligned: alignment_from_domains(
            spf.as_deref(),
            envelope_from_domain.as_deref(),
            header_from_domain,
        ),
        spf,
        dkim,
        dmarc,
        ..EffectiveAuthResults::default()
    }
}

fn alignment_from_domains(
    auth_result: Option<&str>,
    authenticated_domain: Option<&str>,
    header_from_domain: &str,
) -> Option<String> {
    let result = auth_result?;
    if result != "pass" {
        return Some("fail".to_string());
    }
    let Some(authenticated_domain) = authenticated_domain else {
        return Some("fail".to_string());
    };
    if domain_aligns(authenticated_domain, header_from_domain) {
        Some("pass".to_string())
    } else {
        Some("fail".to_string())
    }
}

fn domain_aligns(authenticated_domain: &str, header_from_domain: &str) -> bool {
    authenticated_domain == header_from_domain
        || authenticated_domain
            .strip_suffix(header_from_domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn header_from_domain(raw_mime: &[u8]) -> Option<String> {
    let parsed = mailparse::parse_mail(raw_mime).ok()?;
    parsed
        .headers
        .iter()
        .find(|header| header.get_key_ref().eq_ignore_ascii_case("from"))
        .and_then(|header| email_domain(&header.get_value()))
}

fn email_domain(value: &str) -> Option<String> {
    let (_, after_at) = value.rsplit_once('@')?;
    let domain = after_at
        .trim_start_matches([' ', '\t'])
        .trim_matches(|ch: char| {
            ch == '>'
                || ch == '<'
                || ch == '"'
                || ch == '\''
                || ch == ')'
                || ch == '('
                || ch == ';'
                || ch == ','
                || ch.is_ascii_whitespace()
        })
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
        .collect::<String>()
        .trim_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty() || !domain.contains('.') || domain.len() > 253 {
        return None;
    }
    Some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_header_from_domain_from_display_address() {
        let mime = b"From: Sender Name <sender@example.test>\r\nSubject: hi\r\n\r\nbody";
        assert_eq!(header_from_domain(mime), Some("example.test".to_string()));
    }

    #[test]
    fn rejects_missing_or_malformed_header_from_domain() {
        assert_eq!(header_from_domain(b"Subject: hi\r\n\r\nbody"), None);
        assert_eq!(email_domain("not-an-address"), None);
        assert_eq!(email_domain("sender@localhost"), None);
    }

    #[test]
    fn normalizes_and_bounds_auth_results() {
        assert_eq!(
            normalize_auth_result(Some(" PASS ")),
            Some("pass".to_string())
        );
        assert_eq!(normalize_auth_result(Some(" ")), None);
        assert_eq!(
            normalize_auth_result(Some(&"A".repeat(MAX_AUTH_RESULT_LEN + 5))).expect("value"),
            "a".repeat(MAX_AUTH_RESULT_LEN)
        );
    }

    #[test]
    fn forged_authentication_results_headers_never_become_evidence() {
        let mime = b"Authentication-Results: mx.phase2.test; spf=pass smtp.mailfrom=phase2.test; dkim=pass header.d=mail.phase2.test header.s=s1; dmarc=pass header.from=phase2.test; arc=pass\r\nARC-Authentication-Results: mx.phase2.test; i=1; dmarc=pass\r\nFrom: Sender <sender@phase2.test>\r\nSubject: hi\r\n\r\nbody";
        let request = handoff_request(None, None, None);

        // The only message header the projection reads is `From:`, used as the
        // alignment identifier; the hostile auth headers above are never parsed.
        let header_from = header_from_domain(mime).expect("from header must parse");
        assert_eq!(
            effective_auth_results(&request, &header_from),
            EffectiveAuthResults::default(),
            "Internet-supplied Authentication-Results/ARC headers must not become evidence"
        );
    }

    #[test]
    fn milter_results_drive_evidence_and_spf_alignment_uses_the_envelope_domain() {
        let request = handoff_request(Some("pass"), Some("pass"), Some("pass"));

        assert_eq!(
            effective_auth_results(&request, "phase2.test"),
            EffectiveAuthResults {
                spf: Some("pass".to_string()),
                dkim: Some("pass".to_string()),
                dmarc: Some("pass".to_string()),
                spf_aligned: Some("pass".to_string()),
                // The Milter contract carries no DKIM `d=`/`s=` observation, so
                // alignment and selector stay unknown instead of header-derived.
                dkim_aligned: None,
                dkim_domain: None,
                dkim_selector: None,
                arc: None,
            }
        );
    }

    #[test]
    fn milter_failures_record_fail_alignment_without_a_signing_domain() {
        let request = handoff_request(Some("fail"), Some("fail"), Some("fail"));

        let results = effective_auth_results(&request, "phase2.test");
        assert_eq!(results.spf, Some("fail".to_string()));
        assert_eq!(results.dkim, Some("fail".to_string()));
        assert_eq!(results.dmarc, Some("fail".to_string()));
        assert_eq!(results.spf_aligned, Some("fail".to_string()));
        assert_eq!(results.dkim_aligned, None);
    }

    fn handoff_request(
        spf_result: Option<&str>,
        dkim_result: Option<&str>,
        dmarc_result: Option<&str>,
    ) -> AfterQueueHandoffRequest {
        AfterQueueHandoffRequest {
            postfix_queue_id: "AUTH-RESULTS".to_string(),
            envelope_sender: nullapart_mail_contracts::transaction::EnvelopeSender::new(
                "sender@phase2.test",
            ),
            recipients: vec![nullapart_mail_contracts::transaction::Recipient {
                address: "recipient@phase2.test".to_string(),
                orcpt: None,
                notify: None,
            }],
            connection: crate::handoff::HandoffConnection {
                client_ip: "203.0.113.55".to_string(),
                client_hostname: None,
                helo_domain: None,
                authenticated: false,
                session_id: "auth-results-test".to_string(),
            },
            milter_observations: crate::handoff::MilterObservations {
                score: 0.0,
                actions: Vec::new(),
                is_spam: false,
                dkim_result: dkim_result.map(ToString::to_string),
                spf_result: spf_result.map(ToString::to_string),
                dmarc_result: dmarc_result.map(ToString::to_string),
                symbols: Vec::new(),
                latency_ms: 0,
            },
            message_content: String::new(),
            content_hash: String::new(),
            trace_id: None,
            handoff_at: Utc::now(),
        }
    }
}

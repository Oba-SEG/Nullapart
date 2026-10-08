//! Phase 5 live authentication telemetry projection.
//!
//! This module projects trusted handoff metadata into content-free
//! domain-security read rows. It deliberately stores only normalized domains,
//! source IP, authentication result labels and disposition; it does not store
//! raw MIME, raw headers, Authentication-Results text or DNS payloads.

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
    let auth_results = effective_auth_results(input.request, input.raw_mime);

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
             spf_result, dkim_result, dmarc_result, disposition, observed_at\
         ) VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,$9,$10,$11,$12,$13,$14) \
         ON CONFLICT (deployment_id, tenant_message_id, domain_id) DO UPDATE SET \
             source_ip = EXCLUDED.source_ip, \
             source_domain = EXCLUDED.source_domain, \
             envelope_from_domain = EXCLUDED.envelope_from_domain, \
             header_from_domain = EXCLUDED.header_from_domain, \
             spf_result = EXCLUDED.spf_result, \
             dkim_result = EXCLUDED.dkim_result, \
             dmarc_result = EXCLUDED.dmarc_result, \
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
    .bind(auth_results.spf)
    .bind(auth_results.dkim)
    .bind(auth_results.dmarc)
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

fn effective_auth_results(
    request: &AfterQueueHandoffRequest,
    raw_mime: &[u8],
) -> EffectiveAuthResults {
    let mut results = EffectiveAuthResults {
        spf: normalize_auth_result(request.milter_observations.spf_result.as_deref()),
        dkim: normalize_auth_result(request.milter_observations.dkim_result.as_deref()),
        dmarc: normalize_auth_result(request.milter_observations.dmarc_result.as_deref()),
    };
    if results.spf.is_some() && results.dkim.is_some() && results.dmarc.is_some() {
        return results;
    }

    let Some(parsed) = mailparse::parse_mail(raw_mime).ok() else {
        return results;
    };
    for header in parsed.headers.iter().filter(|header| {
        header
            .get_key_ref()
            .eq_ignore_ascii_case("authentication-results")
    }) {
        let value = header.get_value();
        if results.spf.is_none() {
            results.spf = auth_method_result(&value, "spf");
        }
        if results.dkim.is_none() {
            results.dkim = auth_method_result(&value, "dkim");
        }
        if results.dmarc.is_none() {
            results.dmarc = auth_method_result(&value, "dmarc");
        }
        if results.spf.is_some() && results.dkim.is_some() && results.dmarc.is_some() {
            break;
        }
    }
    results
}

fn auth_method_result(header_value: &str, method: &str) -> Option<String> {
    let header_value = header_value.to_ascii_lowercase();
    for segment in header_value.split(';') {
        let segment = segment.trim_start();
        let Some(rest) = segment.strip_prefix(method) else {
            continue;
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('=').or_else(|| rest.strip_prefix(' '))?;
        let result = rest
            .trim_start()
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect::<String>();
        if !result.is_empty() {
            return normalize_auth_result(Some(&result));
        }
    }
    None
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
    fn falls_back_to_authentication_results_header_without_storing_header_text() {
        let mime = b"Authentication-Results: mx.phase2.test; spf=pass smtp.mailfrom=phase2.test; dkim=fail header.d=other.test; dmarc=pass header.from=phase2.test\r\nFrom: Sender <sender@phase2.test>\r\n\r\nbody";
        let request = AfterQueueHandoffRequest {
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
                dkim_result: None,
                spf_result: None,
                dmarc_result: None,
                symbols: Vec::new(),
                latency_ms: 0,
            },
            message_content: String::new(),
            content_hash: String::new(),
            trace_id: None,
            handoff_at: Utc::now(),
        };

        assert_eq!(
            effective_auth_results(&request, mime),
            EffectiveAuthResults {
                spf: Some("pass".to_string()),
                dkim: Some("fail".to_string()),
                dmarc: Some("pass".to_string()),
            }
        );
    }
}

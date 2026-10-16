//! Private outbound SMTP submission after trusted authorization.
//!
//! This module deliberately has no HTTP handler or connector authentication
//! logic. A future trusted connector worker must authorize a message here
//! before it can be submitted to Postfix's private signed-outbound listener.
//! The listener is a fixed private service endpoint; it is not an Internet
//! SMTP relay. DKIM key material remains exclusively in the Rspamd secret
//! mount and never enters Mail Core.

use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use crate::outbound::{
    validate_outbound_with_signing_config, DkimSigningStatus, DomainAuthorization,
    DomainValidation, OutboundError, OutboundIntakeRequest, OutboundSigningConfig,
};

const PRIVATE_OUTBOUND_PORT: u16 = 10027;
const MAX_SMTP_RESPONSE_LINE_BYTES: usize = 1_024;
const MAX_SMTP_RESPONSE_LINES: usize = 20;

/// Configuration for the private Mail Core-to-Postfix signed-outbound hop.
///
/// This deliberately permits only the Compose service name `postfix` or a
/// loopback/private IP on port 10027. It therefore cannot be repurposed as a
/// direct-to-Internet SMTP client merely through configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateOutboundSmtpConfig {
    endpoint: String,
    timeout: Duration,
    helo_identity: String,
}

impl PrivateOutboundSmtpConfig {
    /// Create configuration for the isolated signed-outbound Postfix listener.
    pub fn new(
        endpoint: impl Into<String>,
        timeout: Duration,
        helo_identity: impl Into<String>,
    ) -> Result<Self, OutboundSubmissionError> {
        let endpoint = endpoint.into();
        let helo_identity = helo_identity.into();
        validate_private_endpoint(&endpoint)?;
        if timeout.is_zero() || !valid_smtp_atom(&helo_identity) {
            return Err(OutboundSubmissionError::InvalidConfiguration);
        }

        Ok(Self {
            endpoint,
            timeout,
            helo_identity,
        })
    }
}

/// A message authorized for the private signed-outbound listener.
///
/// Its fields are intentionally private so callers cannot construct a value
/// by asserting that a message was authorized or DKIM-capable. Construct it
/// only through [`authorize_outbound_submission`].
#[derive(Debug)]
pub struct AuthorizedOutboundSubmission {
    transaction_id: String,
    idempotency_key: String,
    envelope_sender: String,
    recipients: Vec<String>,
    raw_mime: Vec<u8>,
}

impl AuthorizedOutboundSubmission {
    /// The server-generated outbound transaction identifier for audit linkage.
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

/// Result of an accepted private SMTP submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSubmissionReceipt {
    pub transaction_id: String,
    pub postfix_queue_id: String,
}

/// Result of an atomic idempotency claim made before an external SMTP side
/// effect. A production implementation must never return `Submit` twice for
/// the same transaction identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundSubmissionClaim {
    /// This worker owns the one allowed SMTP attempt.
    Submit,
    /// A prior attempt recorded its accepted Postfix queue identifier.
    AlreadySubmitted(OutboundSubmissionReceipt),
    /// Another worker owns an attempt, or an earlier attempt has an ambiguous
    /// result. Recovery must defer rather than resend.
    InProgress,
}

/// Durable idempotency boundary for private outbound SMTP submission.
///
/// The ledger is required by [`submit_authorized_outbound`], so a network
/// retry cannot turn into a duplicate message when Postfix accepted the first
/// transaction but the client lost its final response. A production worker
/// must implement this against its authoritative outbound-delivery store.
#[async_trait]
pub trait OutboundSubmissionLedger: Send + Sync {
    async fn claim_submission(
        &self,
        idempotency_key: &str,
        transaction_id: &str,
    ) -> Result<OutboundSubmissionClaim, ()>;

    async fn record_submission(
        &self,
        idempotency_key: &str,
        receipt: &OutboundSubmissionReceipt,
    ) -> Result<(), ()>;
}

/// PostgreSQL implementation of the private outbound submission ledger.
///
/// Each instance is permanently scoped to the workload-derived deployment and
/// customer. The row is claimed before the SMTP side effect and remains
/// `in_progress` if a connection fails after Postfix may have accepted DATA.
/// That conservative state deliberately requires reconciliation rather than
/// risking a duplicate customer delivery by retrying blindly.
#[derive(Clone)]
pub struct PostgresOutboundSubmissionLedger {
    pool: PgPool,
    deployment_id: DeploymentId,
    customer_id: CustomerId,
}

impl PostgresOutboundSubmissionLedger {
    pub fn new(pool: PgPool, deployment_id: DeploymentId, customer_id: CustomerId) -> Self {
        Self {
            pool,
            deployment_id,
            customer_id,
        }
    }

    async fn begin_scoped(&self) -> Result<Transaction<'_, Postgres>, ()> {
        let mut transaction = self.pool.begin().await.map_err(|_| ())?;
        sqlx::query(
            "SELECT set_config('app.current_deployment_id', $1, true), \
                    set_config('app.current_customer_id', $2, true)",
        )
        .bind(&self.deployment_id.0)
        .bind(&self.customer_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ())?;
        Ok(transaction)
    }
}

#[async_trait]
impl OutboundSubmissionLedger for PostgresOutboundSubmissionLedger {
    async fn claim_submission(
        &self,
        idempotency_key: &str,
        transaction_id: &str,
    ) -> Result<OutboundSubmissionClaim, ()> {
        if !is_sha256_hex(idempotency_key) || transaction_id.trim().is_empty() {
            return Err(());
        }

        let mut transaction = self.begin_scoped().await?;
        let inserted = sqlx::query(
            "INSERT INTO outbound_submission_ledger \
             (deployment_id, customer_id, idempotency_key, transaction_id, submission_state) \
             VALUES ($1, $2, $3, $4, 'in_progress') \
             ON CONFLICT (deployment_id, customer_id, idempotency_key) DO NOTHING",
        )
        .bind(&self.deployment_id.0)
        .bind(&self.customer_id.0)
        .bind(idempotency_key)
        .bind(transaction_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ())?
        .rows_affected();
        if inserted == 1 {
            transaction.commit().await.map_err(|_| ())?;
            return Ok(OutboundSubmissionClaim::Submit);
        }

        let row = sqlx::query(
            "SELECT submission_state, transaction_id, postfix_queue_id \
             FROM outbound_submission_ledger \
             WHERE deployment_id = $1 AND customer_id = $2 AND idempotency_key = $3 \
             FOR UPDATE",
        )
        .bind(&self.deployment_id.0)
        .bind(&self.customer_id.0)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ())?
        .ok_or(())?;
        let claim = match (
            row.get::<String, _>("submission_state").as_str(),
            row.get::<Option<String>, _>("transaction_id"),
            row.get::<Option<String>, _>("postfix_queue_id"),
        ) {
            ("submitted", Some(transaction_id), Some(postfix_queue_id)) => {
                OutboundSubmissionClaim::AlreadySubmitted(OutboundSubmissionReceipt {
                    transaction_id,
                    postfix_queue_id,
                })
            },
            ("in_progress", _, _) => OutboundSubmissionClaim::InProgress,
            _ => return Err(()),
        };
        transaction.commit().await.map_err(|_| ())?;
        Ok(claim)
    }

    async fn record_submission(
        &self,
        idempotency_key: &str,
        receipt: &OutboundSubmissionReceipt,
    ) -> Result<(), ()> {
        if !is_sha256_hex(idempotency_key)
            || receipt.transaction_id.trim().is_empty()
            || receipt.postfix_queue_id.trim().is_empty()
        {
            return Err(());
        }
        let mut transaction = self.begin_scoped().await?;
        let updated = sqlx::query(
            "UPDATE outbound_submission_ledger \
             SET submission_state = 'submitted', postfix_queue_id = $5, \
                 submitted_at = now() \
             WHERE deployment_id = $1 AND customer_id = $2 AND idempotency_key = $3 \
               AND submission_state = 'in_progress' AND transaction_id = $4",
        )
        .bind(&self.deployment_id.0)
        .bind(&self.customer_id.0)
        .bind(idempotency_key)
        .bind(&receipt.transaction_id)
        .bind(&receipt.postfix_queue_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ())?
        .rows_affected();
        if updated != 1 {
            return Err(());
        }
        transaction.commit().await.map_err(|_| ())
    }
}

/// Authorize and bind a raw outbound message to its validated intake request.
///
/// Customer outbound mail must use a non-null envelope sender and a trusted,
/// matching provisioned DKIM signer. DSNs and quarantine reinjection are
/// separate delivery paths and are intentionally rejected here.
pub fn authorize_outbound_submission(
    request: &OutboundIntakeRequest,
    allowed_domains: &[DomainValidation],
    authorization: &DomainAuthorization,
    signing_config: &OutboundSigningConfig,
    raw_mime: Vec<u8>,
) -> Result<AuthorizedOutboundSubmission, OutboundSubmissionError> {
    let sender = request.envelope_sender.address();
    if sender.is_empty() || sender == "<>" {
        return Err(OutboundSubmissionError::NullEnvelopeSender);
    }
    if !valid_smtp_path(sender)
        || request
            .recipients
            .iter()
            .any(|recipient| !valid_smtp_path(&recipient.address))
    {
        return Err(OutboundSubmissionError::NotAuthorized);
    }
    if raw_mime.is_empty() || !content_hash_matches(&request.content_hash, &raw_mime) {
        return Err(OutboundSubmissionError::MessageIntegrity);
    }

    let intake = validate_outbound_with_signing_config(
        request,
        allowed_domains,
        authorization,
        signing_config,
    )
    .map_err(map_authorization_error)?;

    if !intake.signing.dkim_enabled
        || intake.signing.dkim_status != DkimSigningStatus::Available
        || intake.signing.dkim_domain.is_none()
        || intake.signing.dkim_selector.is_none()
    {
        return Err(OutboundSubmissionError::SigningUnavailable);
    }

    Ok(AuthorizedOutboundSubmission {
        transaction_id: intake.transaction_id,
        idempotency_key: outbound_idempotency_key(request, &raw_mime),
        envelope_sender: sender.to_string(),
        recipients: request
            .recipients
            .iter()
            .map(|recipient| recipient.address.clone())
            .collect(),
        raw_mime,
    })
}

/// Submit a previously authorized message to the private Postfix listener.
pub async fn submit_authorized_outbound(
    config: &PrivateOutboundSmtpConfig,
    ledger: &impl OutboundSubmissionLedger,
    submission: AuthorizedOutboundSubmission,
) -> Result<OutboundSubmissionReceipt, OutboundSubmissionError> {
    let idempotency_key = submission.idempotency_key().to_string();
    let transaction_id = submission.transaction_id().to_string();
    match ledger
        .claim_submission(&idempotency_key, &transaction_id)
        .await
        .map_err(|_| OutboundSubmissionError::LedgerUnavailable)?
    {
        OutboundSubmissionClaim::Submit => {},
        OutboundSubmissionClaim::AlreadySubmitted(receipt) => return Ok(receipt),
        OutboundSubmissionClaim::InProgress => {
            return Err(OutboundSubmissionError::SubmissionInProgress);
        },
    }

    let queue_id = tokio::time::timeout(config.timeout, async {
        let stream = TcpStream::connect(&config.endpoint)
            .await
            .map_err(|_| OutboundSubmissionError::SmtpFailure)?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        expect_response(&mut reader, 220).await?;
        smtp_command(
            &mut reader,
            &mut write_half,
            format!("EHLO {}\r\n", config.helo_identity).as_bytes(),
            250,
        )
        .await?;
        smtp_command(
            &mut reader,
            &mut write_half,
            format!("MAIL FROM:<{}>\r\n", submission.envelope_sender).as_bytes(),
            250,
        )
        .await?;
        for recipient in &submission.recipients {
            smtp_command(
                &mut reader,
                &mut write_half,
                format!("RCPT TO:<{recipient}>\r\n").as_bytes(),
                250,
            )
            .await?;
        }
        smtp_command(&mut reader, &mut write_half, b"DATA\r\n", 354).await?;
        write_dot_stuffed_message(&mut write_half, &submission.raw_mime).await?;
        let response = expect_response(&mut reader, 250).await?;
        let queue_id = extract_queue_id(&response)?;
        let _ = smtp_command(&mut reader, &mut write_half, b"QUIT\r\n", 221).await;
        Ok(queue_id)
    })
    .await
    .map_err(|_| OutboundSubmissionError::SmtpTimeout)??;

    let receipt = OutboundSubmissionReceipt {
        transaction_id: submission.transaction_id,
        postfix_queue_id: queue_id,
    };
    ledger
        .record_submission(&idempotency_key, &receipt)
        .await
        .map_err(|_| OutboundSubmissionError::DeliveryStateUnknown)?;
    Ok(receipt)
}

fn map_authorization_error(_: OutboundError) -> OutboundSubmissionError {
    OutboundSubmissionError::NotAuthorized
}

fn content_hash_matches(expected: &str, raw_mime: &[u8]) -> bool {
    if !is_sha256_hex(expected) {
        return false;
    }
    let actual = hex::encode(Sha256::digest(raw_mime));
    bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Derive a stable key for delivery retries from trusted submission identity
/// and the hash-bound message. It excludes transient transaction IDs and
/// credentials, so reconstructing the same accepted submission after a
/// process restart cannot evade the durable ledger.
fn outbound_idempotency_key(request: &OutboundIntakeRequest, raw_mime: &[u8]) -> String {
    let mut recipients = request
        .recipients
        .iter()
        .map(|recipient| recipient.address.as_str())
        .collect::<Vec<_>>();
    recipients.sort_unstable();

    let mut digest = Sha256::new();
    for value in [
        request.connector.customer_id.0.as_str(),
        request.connector.deployment_id.0.as_str(),
        request.connector.connector_id.as_str(),
        request.envelope_sender.address(),
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    for recipient in recipients {
        digest.update(recipient.as_bytes());
        digest.update([0]);
    }
    digest.update(raw_mime);
    hex::encode(digest.finalize())
}

fn validate_private_endpoint(endpoint: &str) -> Result<(), OutboundSubmissionError> {
    if endpoint.is_empty() || endpoint.contains(char::is_whitespace) || endpoint.contains('/') {
        return Err(OutboundSubmissionError::InvalidConfiguration);
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Err(OutboundSubmissionError::InvalidConfiguration);
    };
    let Ok(port) = port.parse::<u16>() else {
        return Err(OutboundSubmissionError::InvalidConfiguration);
    };
    if port != PRIVATE_OUTBOUND_PORT || host.is_empty() || host.contains(['[', ']', '@']) {
        return Err(OutboundSubmissionError::InvalidConfiguration);
    }
    if host == "postfix" {
        return Ok(());
    }
    let Ok(address) = host.parse::<IpAddr>() else {
        return Err(OutboundSubmissionError::InvalidConfiguration);
    };
    if is_private_or_loopback(address) {
        Ok(())
    } else {
        Err(OutboundSubmissionError::InvalidConfiguration)
    }
}

fn is_private_or_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_loopback(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unique_local(),
    }
}

fn valid_smtp_atom(value: &str) -> bool {
    !value.is_empty()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn valid_smtp_path(value: &str) -> bool {
    !value.is_empty()
        && value.contains('@')
        && !value.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'<' | b'>' | b'(' | b')' | b'[' | b']')
        })
}

async fn write_dot_stuffed_message(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    message: &[u8],
) -> Result<(), OutboundSubmissionError> {
    let normalized = normalize_newlines(message);
    for line in normalized.split_inclusive(|byte| *byte == b'\n') {
        if line.first() == Some(&b'.') {
            writer
                .write_all(b".")
                .await
                .map_err(|_| OutboundSubmissionError::SmtpFailure)?;
        }
        writer
            .write_all(line)
            .await
            .map_err(|_| OutboundSubmissionError::SmtpFailure)?;
    }
    if !normalized.ends_with(b"\n") {
        writer
            .write_all(b"\r\n")
            .await
            .map_err(|_| OutboundSubmissionError::SmtpFailure)?;
    }
    writer
        .write_all(b".\r\n")
        .await
        .map_err(|_| OutboundSubmissionError::SmtpFailure)
}

fn normalize_newlines(message: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(message.len().saturating_add(16));
    let mut previous = None;
    for byte in message {
        if *byte == b'\n' && previous != Some(b'\r') {
            output.push(b'\r');
        }
        output.push(*byte);
        previous = Some(*byte);
    }
    output
}

async fn smtp_command<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    command: &[u8],
    expected: u16,
) -> Result<String, OutboundSubmissionError> {
    writer
        .write_all(command)
        .await
        .map_err(|_| OutboundSubmissionError::SmtpFailure)?;
    expect_response(reader, expected).await
}

async fn expect_response<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    expected: u16,
) -> Result<String, OutboundSubmissionError> {
    for _ in 0..MAX_SMTP_RESPONSE_LINES {
        let line = read_response_line(reader).await?;
        let bytes = line.as_bytes();
        if bytes.len() < 4 {
            return Err(OutboundSubmissionError::SmtpFailure);
        }
        let Ok(code) = line[..3].parse::<u16>() else {
            return Err(OutboundSubmissionError::SmtpFailure);
        };
        if code != expected || !matches!(bytes[3], b' ' | b'-') {
            return Err(OutboundSubmissionError::SmtpFailure);
        }
        let continuation = bytes[3] == b'-';
        if !continuation {
            return Ok(line);
        }
    }
    Err(OutboundSubmissionError::SmtpFailure)
}

async fn read_response_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<String, OutboundSubmissionError> {
    let mut bytes = Vec::with_capacity(128);
    for _ in 0..MAX_SMTP_RESPONSE_LINE_BYTES {
        let byte = reader
            .read_u8()
            .await
            .map_err(|_| OutboundSubmissionError::SmtpFailure)?;
        bytes.push(byte);
        if byte == b'\n' {
            return String::from_utf8(bytes)
                .map(|line| line.trim_end_matches(['\r', '\n']).to_string())
                .map_err(|_| OutboundSubmissionError::SmtpFailure);
        }
    }
    Err(OutboundSubmissionError::SmtpFailure)
}

fn extract_queue_id(response: &str) -> Result<String, OutboundSubmissionError> {
    response
        .split_whitespace()
        .last()
        .filter(|value| value.len() >= 5 && value.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .map(str::to_string)
        .ok_or(OutboundSubmissionError::SmtpFailure)
}

/// Safe failures for the private submission boundary. Variants intentionally
/// contain no server response or message-content detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OutboundSubmissionError {
    #[error("outbound message is not authorized for private submission")]
    NotAuthorized,
    #[error("customer outbound submission requires a non-null envelope sender")]
    NullEnvelopeSender,
    #[error("outbound message integrity validation failed")]
    MessageIntegrity,
    #[error("a matching provisioned outbound signer is unavailable")]
    SigningUnavailable,
    #[error("private outbound SMTP configuration is invalid")]
    InvalidConfiguration,
    #[error("private outbound SMTP submission timed out")]
    SmtpTimeout,
    #[error("private outbound SMTP submission failed")]
    SmtpFailure,
    #[error("outbound submission idempotency state is unavailable")]
    LedgerUnavailable,
    #[error("outbound submission is already in progress")]
    SubmissionInProgress,
    #[error("outbound submission delivery state is unknown")]
    DeliveryStateUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use nullapart_mail_contracts::transaction::{
        CustomerId, DeploymentId, EnvelopeSender, Recipient,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[derive(Default)]
    struct TestLedger(std::sync::Mutex<Option<OutboundSubmissionReceipt>>);

    #[async_trait]
    impl OutboundSubmissionLedger for TestLedger {
        async fn claim_submission(&self, _: &str, _: &str) -> Result<OutboundSubmissionClaim, ()> {
            Ok(self
                .0
                .lock()
                .map_err(|_| ())?
                .clone()
                .map(OutboundSubmissionClaim::AlreadySubmitted)
                .unwrap_or(OutboundSubmissionClaim::Submit))
        }

        async fn record_submission(
            &self,
            _: &str,
            receipt: &OutboundSubmissionReceipt,
        ) -> Result<(), ()> {
            *self.0.lock().map_err(|_| ())? = Some(receipt.clone());
            Ok(())
        }
    }

    use crate::outbound::{
        ConnectorType, DomainValidationSource, OutboundConnector, ProvisionedDkimSigner,
    };

    fn request(raw_mime: &[u8]) -> OutboundIntakeRequest {
        OutboundIntakeRequest {
            connector: OutboundConnector {
                connector_id: "connector-a".to_string(),
                customer_id: CustomerId::new("customer-a"),
                deployment_id: DeploymentId::new("LOCAL-TEST"),
                ip_address: "172.30.0.10".to_string(),
                authenticated_as: Some("workload-identity".to_string()),
                connector_type: ConnectorType::SmtpMta,
            },
            envelope_sender: EnvelopeSender::new("sender@customer-a.test"),
            recipients: vec![Recipient {
                address: "recipient@example.test".to_string(),
                orcpt: None,
                notify: None,
            }],
            message_id: Some("test-message".to_string()),
            content_hash: hex::encode(Sha256::digest(raw_mime)),
        }
    }

    fn domains() -> Vec<DomainValidation> {
        vec![DomainValidation {
            domain: "customer-a.test".to_string(),
            customer_id: CustomerId::new("customer-a"),
            validated: true,
            validation_source: DomainValidationSource::DnsTxt,
            validated_at: Utc::now(),
        }]
    }

    fn signer(domain: &str) -> OutboundSigningConfig {
        OutboundSigningConfig {
            dkim: Some(ProvisionedDkimSigner {
                domain: domain.to_string(),
                selector: "selector1".to_string(),
            }),
            helo_identity: Some("mailcore.local".to_string()),
        }
    }

    #[test]
    fn private_endpoint_allows_only_the_postfix_service_or_private_network() {
        assert!(PrivateOutboundSmtpConfig::new(
            "postfix:10027",
            Duration::from_secs(1),
            "mailcore.local"
        )
        .is_ok());
        assert!(PrivateOutboundSmtpConfig::new(
            "172.30.0.2:10027",
            Duration::from_secs(1),
            "mailcore.local"
        )
        .is_ok());
        assert!(PrivateOutboundSmtpConfig::new(
            "smtp.example.test:25",
            Duration::from_secs(1),
            "mailcore.local"
        )
        .is_err());
        assert!(PrivateOutboundSmtpConfig::new(
            "203.0.113.9:10027",
            Duration::from_secs(1),
            "mailcore.local"
        )
        .is_err());
    }

    #[test]
    fn content_hash_requires_lowercase_sha256() {
        let mime = b"From: sender@example.test\r\n\r\nbody";
        let digest = hex::encode(Sha256::digest(mime));
        assert!(content_hash_matches(&digest, mime));
        assert!(!content_hash_matches(&digest.to_uppercase(), mime));
        assert!(!content_hash_matches("not-a-hash", mime));
    }

    #[test]
    fn idempotency_key_is_stable_for_a_reconstructed_submission() {
        let raw_mime = b"From: sender@customer-a.test\r\n\r\nbody";
        let mut first = request(raw_mime);
        first.recipients.push(Recipient {
            address: "second@example.test".to_string(),
            orcpt: None,
            notify: None,
        });
        let mut reconstructed = first.clone();
        reconstructed.message_id = Some("different-untrusted-message-id".to_string());
        reconstructed.recipients.reverse();
        assert_eq!(
            outbound_idempotency_key(&first, raw_mime),
            outbound_idempotency_key(&reconstructed, raw_mime)
        );

        reconstructed.recipients[0].address = "other@example.test".to_string();
        assert_ne!(
            outbound_idempotency_key(&first, raw_mime),
            outbound_idempotency_key(&reconstructed, raw_mime)
        );
    }

    #[test]
    fn normalization_and_dot_stuffing_boundary_is_explicit() {
        assert_eq!(
            normalize_newlines(b"one\ntwo\r\nthree"),
            b"one\r\ntwo\r\nthree"
        );
    }

    #[test]
    fn authorization_requires_matching_signer_hash_and_non_null_sender() {
        let raw_mime = b"From: sender@customer-a.test\n\n.body";
        let signed = authorize_outbound_submission(
            &request(raw_mime),
            &domains(),
            &DomainAuthorization::Full,
            &signer("customer-a.test"),
            raw_mime.to_vec(),
        );
        assert!(signed.is_ok());

        let unavailable = authorize_outbound_submission(
            &request(raw_mime),
            &domains(),
            &DomainAuthorization::Full,
            &signer("other.test"),
            raw_mime.to_vec(),
        );
        assert_eq!(
            unavailable.unwrap_err(),
            OutboundSubmissionError::SigningUnavailable
        );

        let mut mismatched_hash = request(raw_mime);
        mismatched_hash.content_hash = "a".repeat(64);
        assert_eq!(
            authorize_outbound_submission(
                &mismatched_hash,
                &domains(),
                &DomainAuthorization::Full,
                &signer("customer-a.test"),
                raw_mime.to_vec(),
            )
            .unwrap_err(),
            OutboundSubmissionError::MessageIntegrity
        );

        let mut null_sender = request(raw_mime);
        null_sender.envelope_sender = EnvelopeSender::new("<>");
        assert_eq!(
            authorize_outbound_submission(
                &null_sender,
                &domains(),
                &DomainAuthorization::Full,
                &signer("customer-a.test"),
                raw_mime.to_vec(),
            )
            .unwrap_err(),
            OutboundSubmissionError::NullEnvelopeSender
        );

        let mut injection_attempt = request(raw_mime);
        injection_attempt.recipients[0].address =
            "recipient@example.test\r\nRCPT TO:<attacker@example.test>".to_string();
        assert_eq!(
            authorize_outbound_submission(
                &injection_attempt,
                &domains(),
                &DomainAuthorization::Full,
                &signer("customer-a.test"),
                raw_mime.to_vec(),
            )
            .unwrap_err(),
            OutboundSubmissionError::NotAuthorized
        );
    }

    #[tokio::test]
    async fn authorized_submission_uses_private_smtp_sequence_and_dot_stuffs_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            write.write_all(b"220 test-smtp\r\n").await.unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "EHLO mailcore.local\r\n");
            write
                .write_all(b"250-test-smtp\r\n250 PIPELINING\r\n")
                .await
                .unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "MAIL FROM:<sender@customer-a.test>\r\n");
            write.write_all(b"250 2.1.0 Ok\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "RCPT TO:<recipient@example.test>\r\n");
            write.write_all(b"250 2.1.5 Ok\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "DATA\r\n");
            write.write_all(b"354 End data\r\n").await.unwrap();
            let mut data = Vec::new();
            loop {
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                if line == ".\r\n" {
                    break;
                }
                data.extend_from_slice(line.as_bytes());
            }
            write
                .write_all(b"250 2.0.0 Ok: queued as ABCD1234\r\n")
                .await
                .unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "QUIT\r\n");
            write.write_all(b"221 Bye\r\n").await.unwrap();
            data
        });
        let raw_mime = b"From: sender@customer-a.test\n\n.leading\nplain";
        let submission = authorize_outbound_submission(
            &request(raw_mime),
            &domains(),
            &DomainAuthorization::Full,
            &signer("customer-a.test"),
            raw_mime.to_vec(),
        )
        .unwrap();
        let config = PrivateOutboundSmtpConfig {
            endpoint,
            timeout: Duration::from_secs(2),
            helo_identity: "mailcore.local".to_string(),
        };
        let ledger = TestLedger::default();
        let receipt = submit_authorized_outbound(&config, &ledger, submission)
            .await
            .unwrap();
        assert_eq!(receipt.postfix_queue_id, "ABCD1234");
        assert_eq!(
            server.await.unwrap(),
            b"From: sender@customer-a.test\r\n\r\n..leading\r\nplain\r\n"
        );
    }

    #[tokio::test]
    async fn unexpected_smtp_response_fails_without_exposing_response_text() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"554 internal details must not escape\r\n")
                .await
                .unwrap();
        });
        let raw_mime = b"From: sender@customer-a.test\r\n\r\nbody";
        let submission = authorize_outbound_submission(
            &request(raw_mime),
            &domains(),
            &DomainAuthorization::Full,
            &signer("customer-a.test"),
            raw_mime.to_vec(),
        )
        .unwrap();
        let config = PrivateOutboundSmtpConfig {
            endpoint,
            timeout: Duration::from_secs(2),
            helo_identity: "mailcore.local".to_string(),
        };
        assert_eq!(
            submit_authorized_outbound(&config, &TestLedger::default(), submission)
                .await
                .unwrap_err(),
            OutboundSubmissionError::SmtpFailure
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn prior_submission_receipt_prevents_a_second_smtp_attempt() {
        let raw_mime = b"From: sender@customer-a.test\r\n\r\nbody";
        let submission = authorize_outbound_submission(
            &request(raw_mime),
            &domains(),
            &DomainAuthorization::Full,
            &signer("customer-a.test"),
            raw_mime.to_vec(),
        )
        .unwrap();
        let existing = OutboundSubmissionReceipt {
            transaction_id: "existing-transaction".to_string(),
            postfix_queue_id: "EXIST1234".to_string(),
        };
        let ledger = TestLedger(std::sync::Mutex::new(Some(existing.clone())));
        let config = PrivateOutboundSmtpConfig {
            endpoint: "127.0.0.1:9".to_string(),
            timeout: Duration::from_secs(1),
            helo_identity: "mailcore.local".to_string(),
        };
        assert_eq!(
            submit_authorized_outbound(&config, &ledger, submission)
                .await
                .unwrap(),
            existing
        );
    }
}

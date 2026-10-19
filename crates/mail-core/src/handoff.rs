//! After-queue Mail Core handoff endpoint.
//!
//! The endpoint is private and authenticated before JSON parsing. The raw body,
//! HTTP method and path are covered by the canonical Nullapart HMAC contract.

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use nullapart_mail_contracts::hmac::{verify_http, HmacSignature};
use nullapart_mail_contracts::transaction::{
    DeploymentId, EnvelopeSender, Recipient, TransactionId,
};

pub(crate) const HANDOFF_PATH: &str = "/internal/handoff";
pub(crate) const HANDOFF_METHOD: &str = "POST";

#[derive(Debug, Clone)]
pub struct HandoffConfig {
    pub deployment_id: DeploymentId,
    pub node_id: String,
    pub max_message_size: u64,
    /// Per-deployment/workload HMAC key. Production configuration must provide it
    /// from the approved secret store. Missing keys fail closed at the HTTP boundary.
    pub hmac_secret: Option<String>,
    pub hmac_key_id: String,
    pub signature_max_age_secs: u64,
    pub signature_future_skew_secs: u64,
}

impl Default for HandoffConfig {
    fn default() -> Self {
        Self {
            deployment_id: DeploymentId::new("CZA-1"),
            node_id: "mail-node-1".to_string(),
            max_message_size: 52_428_800,
            hmac_secret: None,
            hmac_key_id: "mail-handoff-v1".to_string(),
            signature_max_age_secs: 300,
            signature_future_skew_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AfterQueueHandoffRequest {
    pub postfix_queue_id: String,
    pub envelope_sender: EnvelopeSender,
    pub recipients: Vec<Recipient>,
    pub connection: HandoffConnection,
    pub milter_observations: MilterObservations,
    pub message_content: String,
    pub content_hash: String,
    pub trace_id: Option<String>,
    pub handoff_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffConnection {
    pub client_ip: String,
    pub client_hostname: Option<String>,
    pub helo_domain: Option<String>,
    pub authenticated: bool,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MilterObservations {
    pub score: f64,
    pub actions: Vec<String>,
    pub is_spam: bool,
    pub dkim_result: Option<String>,
    pub spf_result: Option<String>,
    pub dmarc_result: Option<String>,
    pub symbols: Vec<String>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AfterQueueHandoffResponse {
    pub transaction_id: String,
    pub status: HandoffStatus,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandoffStatus {
    Accepted,
    Rejected,
    Deferred,
    Duplicate,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HandoffError {
    #[error("message too large: {0} exceeds maximum {1}")]
    MessageTooLarge(u64, u64),
    #[error("invalid envelope sender")]
    InvalidSender,
    #[error("no valid recipients")]
    NoRecipients,
    #[error("invalid content hash")]
    InvalidContentHash,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("malformed request")]
    MalformedRequest,
}

/// Derive a stable transaction identifier from facts that identify one accepted
/// Postfix queue item. Persistence uses this ID as the idempotency key so retries
/// cannot create a second transaction.
pub(crate) fn deterministic_transaction_id(
    config: &HandoffConfig,
    request: &AfterQueueHandoffRequest,
) -> TransactionId {
    let namespace = Uuid::NAMESPACE_OID;
    let material = format!(
        "{}\n{}\n{}\n{}",
        config.deployment_id.0, config.node_id, request.postfix_queue_id, request.content_hash
    );
    TransactionId(Uuid::new_v5(&namespace, material.as_bytes()))
}

pub fn process_handoff(
    config: &HandoffConfig,
    request: &AfterQueueHandoffRequest,
) -> Result<AfterQueueHandoffResponse, HandoffError> {
    // The SMTP null reverse-path ("<>") is valid and must be preserved for DSNs.
    // Reject only obviously unsafe/unbounded sender representations.
    if request.envelope_sender.address().len() > 320
        || request.envelope_sender.address().contains(['\r', '\n'])
    {
        return Err(HandoffError::InvalidSender);
    }
    if request.recipients.is_empty() {
        return Err(HandoffError::NoRecipients);
    }
    // Milter evidence must satisfy the shared bounds even though the
    // producer is our own after-queue filter; the contract is enforced at
    // the trust boundary, not trusted wholesale.
    if !crate::milter_evidence::validate_observations(&request.milter_observations) {
        return Err(HandoffError::MalformedRequest);
    }

    let decoded = STANDARD
        .decode(request.message_content.as_bytes())
        .map_err(|_| HandoffError::MalformedRequest)?;
    if decoded.len() as u64 > config.max_message_size {
        return Err(HandoffError::MessageTooLarge(
            decoded.len() as u64,
            config.max_message_size,
        ));
    }

    let calculated_hash_bytes: [u8; 32] = Sha256::digest(&decoded).into();
    let provided_hash_bytes =
        hex::decode(&request.content_hash).map_err(|_| HandoffError::InvalidContentHash)?;
    if provided_hash_bytes.len() != 32
        || provided_hash_bytes
            .ct_eq(&calculated_hash_bytes)
            .unwrap_u8()
            != 1
    {
        return Err(HandoffError::InvalidContentHash);
    }

    let transaction_id = deterministic_transaction_id(config, request);

    tracing::info!(
        transaction_id = %transaction_id,
        postfix_queue_id = %request.postfix_queue_id,
        recipient_count = request.recipients.len(),
        "after-queue handoff accepted"
    );

    Ok(AfterQueueHandoffResponse {
        transaction_id: transaction_id.to_string(),
        status: HandoffStatus::Accepted,
        message: format!(
            "Transaction {} accepted for queue {}",
            transaction_id, request.postfix_queue_id
        ),
    })
}

pub fn handoff_router(config: HandoffConfig) -> Router {
    let body_limit = handoff_body_limit(config.max_message_size);
    Router::new()
        .route(HANDOFF_PATH, post(handle_handoff))
        .layer(axum::extract::DefaultBodyLimit::max(body_limit))
        .with_state(config)
}

/// HTTP body limit for the JSON + base64 handoff envelope.
///
/// `max_message_size` bounds the raw message, but the transport carries the
/// message base64-encoded inside JSON. A raw message of exactly the maximum
/// size therefore encodes to `ceil(n/3) * 4` characters before any envelope
/// fields, so an equal-sized limit rejects valid maximum-size messages with
/// 413 before the handler runs. The fixed headroom covers the JSON envelope
/// (recipients, connection, milter observations) around the encoded message.
pub(crate) fn handoff_body_limit(max_message_size: u64) -> usize {
    const HANDOFF_ENVELOPE_HEADROOM: usize = 1024 * 1024;
    let base64_expanded = (max_message_size as usize).div_ceil(3) * 4;
    base64_expanded.saturating_add(HANDOFF_ENVELOPE_HEADROOM)
}

pub(crate) fn verify_request_auth(
    config: &HandoffConfig,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), HandoffError> {
    let secret = config
        .hmac_secret
        .as_ref()
        .ok_or(HandoffError::AuthenticationFailed)?;

    let signature_header = headers
        .get("x-nullapart-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(HandoffError::AuthenticationFailed)?;
    let event_id = headers
        .get("x-nullapart-event-id")
        .and_then(|v| v.to_str().ok())
        .ok_or(HandoffError::AuthenticationFailed)?;

    let signature =
        HmacSignature::parse(signature_header).map_err(|_| HandoffError::AuthenticationFailed)?;
    if signature.key_id != config.hmac_key_id {
        return Err(HandoffError::AuthenticationFailed);
    }

    verify_http(
        body,
        secret.as_bytes(),
        &signature,
        event_id,
        HANDOFF_METHOD,
        HANDOFF_PATH,
        config.signature_max_age_secs,
        config.signature_future_skew_secs,
    )
    .map_err(|_| HandoffError::AuthenticationFailed)
}

async fn handle_handoff(
    State(config): State<HandoffConfig>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<AfterQueueHandoffResponse>), (StatusCode, String)> {
    verify_request_auth(&config, &headers, &body)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized".to_string()))?;

    let request: AfterQueueHandoffRequest = serde_json::from_slice(&body).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "malformed handoff request".to_string(),
        )
    })?;

    match process_handoff(&config, &request) {
        Ok(response) => Ok((StatusCode::OK, Json(response))),
        Err(HandoffError::MessageTooLarge(_, _)) => Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "message too large".to_string(),
        )),
        Err(HandoffError::InvalidContentHash) => {
            Err((StatusCode::BAD_REQUEST, "content hash mismatch".to_string()))
        },
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            "invalid handoff request".to_string(),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffIdempotencyResult {
    pub transaction_id: TransactionId,
    pub duplicate: bool,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HandoffIdempotencyError {
    #[error("invalid handoff idempotency input")]
    InvalidInput,
    #[error("handoff idempotency conflict")]
    Conflict,
    #[error("handoff idempotency store unavailable")]
    Unavailable,
}

#[async_trait]
pub trait HandoffIdempotencyStore: Send + Sync {
    async fn create_or_get(
        &self,
        deployment_id: &DeploymentId,
        postfix_queue_id: &str,
        content_hash: &str,
    ) -> Result<HandoffIdempotencyResult, HandoffIdempotencyError>;
}

#[derive(Clone)]
pub struct PostgresHandoffIdempotencyStore {
    pool: PgPool,
}

impl PostgresHandoffIdempotencyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HandoffIdempotencyStore for PostgresHandoffIdempotencyStore {
    async fn create_or_get(
        &self,
        deployment_id: &DeploymentId,
        postfix_queue_id: &str,
        content_hash: &str,
    ) -> Result<HandoffIdempotencyResult, HandoffIdempotencyError> {
        let postfix_queue_id_len = postfix_queue_id.trim().len();
        if !(1..=320).contains(&postfix_queue_id_len) {
            return Err(HandoffIdempotencyError::InvalidInput);
        }
        let content_hash_len = content_hash.trim().len();
        if !(1..=128).contains(&content_hash_len) {
            return Err(HandoffIdempotencyError::InvalidInput);
        }

        let transaction_id = TransactionId::new();
        // handoff_idempotency carries FORCE RLS keyed on deployment_id
        // (migration 034); claim/select must run under the deployment GUC.
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| HandoffIdempotencyError::Unavailable)?;
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(&deployment_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| HandoffIdempotencyError::Unavailable)?;
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO handoff_idempotency \
             (deployment_id, postfix_queue_id, content_hash, transaction_id) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (deployment_id, postfix_queue_id) DO NOTHING \
             RETURNING transaction_id",
        )
        .bind(&deployment_id.0)
        .bind(postfix_queue_id)
        .bind(content_hash)
        .bind(transaction_id.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| HandoffIdempotencyError::Unavailable)?;

        if let Some(transaction_id) = inserted {
            transaction
                .commit()
                .await
                .map_err(|_| HandoffIdempotencyError::Unavailable)?;
            return Ok(HandoffIdempotencyResult {
                transaction_id: TransactionId(transaction_id),
                duplicate: false,
            });
        }

        let existing = sqlx::query_as::<_, (String, Uuid)>(
            "SELECT content_hash, transaction_id \
             FROM handoff_idempotency \
             WHERE deployment_id = $1 AND postfix_queue_id = $2",
        )
        .bind(&deployment_id.0)
        .bind(postfix_queue_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| HandoffIdempotencyError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| HandoffIdempotencyError::Unavailable)?;

        let (stored_hash, stored_transaction_id) =
            existing.ok_or(HandoffIdempotencyError::Unavailable)?;

        if stored_hash != content_hash {
            return Err(HandoffIdempotencyError::Conflict);
        }

        Ok(HandoffIdempotencyResult {
            transaction_id: TransactionId(stored_transaction_id),
            duplicate: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullapart_mail_contracts::hmac::sign_http;

    fn test_handoff_request() -> AfterQueueHandoffRequest {
        AfterQueueHandoffRequest {
            postfix_queue_id: "ABC123".to_string(),
            envelope_sender: EnvelopeSender::new("sender@example.com"),
            recipients: vec![Recipient {
                address: "user@customer.com".to_string(),
                orcpt: None,
                notify: None,
            }],
            connection: HandoffConnection {
                client_ip: "192.168.1.1".to_string(),
                client_hostname: Some("mail.example.com".to_string()),
                helo_domain: Some("example.com".to_string()),
                authenticated: false,
                session_id: "sess-123".to_string(),
            },
            milter_observations: MilterObservations {
                score: 1.5,
                actions: vec![],
                is_spam: false,
                dkim_result: Some("pass".to_string()),
                spf_result: Some("pass".to_string()),
                dmarc_result: Some("pass".to_string()),
                symbols: vec![],
                latency_ms: 15,
            },
            message_content: "SGVsbG8gV29ybGQ=".to_string(),
            content_hash: hex::encode(Sha256::digest(b"Hello World")),
            trace_id: None,
            handoff_at: Utc::now(),
        }
    }

    #[test]
    fn duplicate_handoffs_have_same_transaction_id() {
        let config = HandoffConfig::default();
        let request = test_handoff_request();
        let first = process_handoff(&config, &request).unwrap();
        let second = process_handoff(&config, &request).unwrap();
        assert_eq!(first.transaction_id, second.transaction_id);
    }

    #[test]
    fn empty_sender_and_recipient_set_are_rejected() {
        let config = HandoffConfig::default();
        let mut request = test_handoff_request();
        request.envelope_sender = EnvelopeSender::new("<>");
        assert!(process_handoff(&config, &request).is_ok());

        let mut request = test_handoff_request();
        request.envelope_sender = EnvelopeSender::new("bad\r\nsender");
        assert!(matches!(
            process_handoff(&config, &request),
            Err(HandoffError::InvalidSender)
        ));

        let mut request = test_handoff_request();
        request.recipients.clear();
        assert!(matches!(
            process_handoff(&config, &request),
            Err(HandoffError::NoRecipients)
        ));
    }

    #[test]
    fn message_too_large_rejected() {
        let config = HandoffConfig {
            max_message_size: 100,
            ..Default::default()
        };
        let mut request = test_handoff_request();
        request.message_content = "A".repeat(200);
        assert!(matches!(
            process_handoff(&config, &request),
            Err(HandoffError::MessageTooLarge(_, _))
        ));
    }

    #[test]
    fn hmac_auth_covers_raw_body_method_and_path() {
        let secret = "test-handoff-secret";
        let config = HandoffConfig {
            hmac_secret: Some(secret.to_string()),
            ..Default::default()
        };
        let body = br#"{"postfix_queue_id":"ABC123"}"#;
        let event_id = "handoff-ABC123";
        let sig = sign_http(
            body,
            secret.as_bytes(),
            &config.hmac_key_id,
            event_id,
            HANDOFF_METHOD,
            HANDOFF_PATH,
        )
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("x-nullapart-signature", sig.to_header().parse().unwrap());
        headers.insert("x-nullapart-event-id", event_id.parse().unwrap());
        assert!(verify_request_auth(&config, &headers, body).is_ok());

        assert!(verify_request_auth(&config, &headers, br#"{"changed":true}"#).is_err());
    }
}

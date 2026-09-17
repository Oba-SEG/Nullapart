//! HMAC-SHA-256 signing and verification primitives.
//!
//! Implements `docs/security/26-HMAC-SIGNING-WEBHOOKS.md`.
//! One reviewed HMAC contract for Nullapart-signed webhook/event use.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Signature version for format evolution.
pub const SIGNATURE_VERSION: u32 = 1;

/// HMAC signature result.
#[derive(Debug, Clone)]
pub struct HmacSignature {
    /// Base64-encoded signature bytes.
    pub signature: String,
    /// Key ID used for signing (for key rotation).
    pub key_id: String,
    /// Signature format version.
    pub version: u32,
    /// Unix timestamp of signing.
    pub timestamp: u64,
}

impl HmacSignature {
    /// Parse a signature header value in the format:
    /// `v1,key_id,timestamp,base64_signature`
    pub fn parse(header: &str) -> Result<Self, HmacError> {
        let parts: Vec<&str> = header.splitn(4, ',').collect();
        if parts.len() != 4 {
            return Err(HmacError::InvalidFormat);
        }

        let version: u32 = parts[0]
            .strip_prefix('v')
            .and_then(|v| v.parse().ok())
            .ok_or(HmacError::InvalidVersion)?;

        let key_id = parts[1].to_string();
        let timestamp: u64 = parts[2].parse().map_err(|_| HmacError::InvalidTimestamp)?;
        let signature = parts[3].to_string();

        Ok(Self {
            signature,
            key_id,
            version,
            timestamp,
        })
    }

    /// Format as header value string.
    pub fn to_header(&self) -> String {
        format!(
            "v{},{},{},{}",
            self.version, self.key_id, self.timestamp, self.signature
        )
    }
}

/// Sign a raw body with HMAC-SHA-256.
///
/// - `body`: raw bytes to sign (canonical form)
/// - `key`: signing key
/// - `key_id`: identifier for the key used
/// - `event_id`: event ID for replay protection context
pub fn sign(
    body: &[u8],
    key: &[u8],
    key_id: &str,
    event_id: &str,
) -> Result<HmacSignature, HmacError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HmacError::TimestampError)?
        .as_secs();

    let payload = format!("{}.{}.{}", SIGNATURE_VERSION, timestamp, event_id);

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| HmacError::InvalidKey)?;
    mac.update(payload.as_bytes());
    mac.update(body);
    let result = mac.finalize();

    Ok(HmacSignature {
        signature: STANDARD.encode(result.into_bytes()),
        key_id: key_id.to_string(),
        version: SIGNATURE_VERSION,
        timestamp,
    })
}

/// Verify an HMAC-SHA-256 signature.
///
/// - `body`: raw bytes that were signed
/// - `key`: signing key
/// - `signature`: parsed signature to verify
/// - `event_id`: event ID for replay protection context
/// - `max_age_secs`: maximum age of signature (replay protection window)
pub fn verify(
    body: &[u8],
    key: &[u8],
    signature: &HmacSignature,
    event_id: &str,
    max_age_secs: u64,
) -> Result<(), HmacError> {
    if signature.version != SIGNATURE_VERSION {
        return Err(HmacError::InvalidVersion);
    }

    // Replay protection: reject old signatures
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HmacError::TimestampError)?
        .as_secs();

    if now.saturating_sub(signature.timestamp) > max_age_secs {
        return Err(HmacError::SignatureExpired);
    }

    let sig_bytes = STANDARD
        .decode(&signature.signature)
        .map_err(|_| HmacError::InvalidSignatureEncoding)?;

    let payload = format!("{}.{}.{}", signature.version, signature.timestamp, event_id);

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| HmacError::InvalidKey)?;
    mac.update(payload.as_bytes());
    mac.update(body);

    // Constant-time verification
    mac.verify_slice(&sig_bytes)
        .map_err(|_| HmacError::VerificationFailed)
}

/// HMAC operation errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HmacError {
    #[error("invalid signature format")]
    InvalidFormat,

    #[error("invalid signature version")]
    InvalidVersion,

    #[error("invalid timestamp")]
    InvalidTimestamp,

    #[error("invalid HMAC key")]
    InvalidKey,

    #[error("signature expired (older than max_age)")]
    SignatureExpired,

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid base64 signature encoding")]
    InvalidSignatureEncoding,

    #[error("timestamp error")]
    TimestampError,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &[u8] = b"test-secret-key-for-hmac-signing";
    const TEST_EVENT_ID: &str = "evt-123-abc";

    #[test]
    fn sign_and_verify_roundtrip() {
        let body = b"test body content";
        let sig = sign(body, TEST_KEY, "key-1", TEST_EVENT_ID).unwrap();
        let header = sig.to_header();
        let parsed = HmacSignature::parse(&header).unwrap();

        assert!(verify(body, TEST_KEY, &parsed, TEST_EVENT_ID, 300).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let body = b"test body content";
        let sig = sign(body, TEST_KEY, "key-1", TEST_EVENT_ID).unwrap();
        let header = sig.to_header();
        let parsed = HmacSignature::parse(&header).unwrap();

        let wrong_key = b"wrong-key";
        assert!(verify(body, wrong_key, &parsed, TEST_EVENT_ID, 300).is_err());
    }

    #[test]
    fn verify_rejects_wrong_body() {
        let body = b"test body content";
        let sig = sign(body, TEST_KEY, "key-1", TEST_EVENT_ID).unwrap();
        let header = sig.to_header();
        let parsed = HmacSignature::parse(&header).unwrap();

        let wrong_body = b"different body content";
        assert!(verify(wrong_body, TEST_KEY, &parsed, TEST_EVENT_ID, 300).is_err());
    }

    #[test]
    fn verify_rejects_expired_signature() {
        let body = b"test body content";
        let sig = sign(body, TEST_KEY, "key-1", TEST_EVENT_ID).unwrap();

        // Manually create an expired signature
        let expired = HmacSignature {
            timestamp: sig.timestamp - 600,
            ..sig
        };
        let header = expired.to_header();
        let parsed = HmacSignature::parse(&header).unwrap();

        // max_age 300s, but signature is 600s old
        assert!(verify(body, TEST_KEY, &parsed, TEST_EVENT_ID, 300).is_err());
    }

    #[test]
    fn parse_rejects_invalid_format() {
        assert!(HmacSignature::parse("invalid").is_err());
        assert!(HmacSignature::parse("v1,key,ts").is_err()); // missing sig
    }
}

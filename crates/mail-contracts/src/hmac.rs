//! HMAC-SHA-256 signing and verification primitives.
//!
//! Implements `docs/security/26-HMAC-SIGNING-WEBHOOKS.md`.
//! All Nullapart-owned HTTP HMAC boundaries use the same canonical form.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const SIGNATURE_VERSION: u32 = 1;

/// Signature header wire format:
/// `v1,<key_id>,<unix_timestamp>,<lowercase_hex_signature>`.
#[derive(Debug, Clone)]
pub struct HmacSignature {
    pub signature: String,
    pub key_id: String,
    pub version: u32,
    pub timestamp: u64,
}

impl HmacSignature {
    pub fn parse(header: &str) -> Result<Self, HmacError> {
        let parts: Vec<&str> = header.splitn(4, ',').collect();
        if parts.len() != 4 {
            return Err(HmacError::InvalidFormat);
        }

        let version = parts[0]
            .strip_prefix('v')
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or(HmacError::InvalidVersion)?;

        validate_key_id(parts[1])?;

        let timestamp = parts[2]
            .parse::<u64>()
            .map_err(|_| HmacError::InvalidTimestamp)?;

        if parts[3].len() != 64 || !parts[3].bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(HmacError::InvalidSignatureEncoding);
        }

        Ok(Self {
            signature: parts[3].to_ascii_lowercase(),
            key_id: parts[1].to_string(),
            version,
            timestamp,
        })
    }

    pub fn to_header(&self) -> String {
        format!(
            "v{},{},{},{}",
            self.version, self.key_id, self.timestamp, self.signature
        )
    }
}

/// Build the canonical signed input documented by the security contract.
fn canonical_input(
    version: u32,
    timestamp: u64,
    event_id: &str,
    method: &str,
    normalized_path: &str,
    body: &[u8],
) -> Result<Vec<u8>, HmacError> {
    validate_event_id(event_id)?;
    validate_http_component(method)?;
    validate_path(normalized_path)?;

    let body_hash = hex::encode(Sha256::digest(body));
    Ok(format!(
        "v{}\n{}\n{}\n{}\n{}\n{}",
        version,
        timestamp,
        event_id,
        method.to_ascii_uppercase(),
        normalized_path,
        body_hash
    )
    .into_bytes())
}

fn validate_key_id(key_id: &str) -> Result<(), HmacError> {
    // Key IDs travel in a comma-delimited header. Restrict to printable
    // ASCII so a key_id can never smuggle control characters, whitespace,
    // or the `,` field separator that `parse` splits on.
    if key_id.is_empty()
        || key_id.len() > 128
        || !key_id
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b',')
    {
        return Err(HmacError::InvalidKeyId);
    }
    Ok(())
}

fn validate_event_id(event_id: &str) -> Result<(), HmacError> {
    if event_id.is_empty()
        || event_id.len() > 160
        || !event_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(HmacError::InvalidEventId);
    }
    Ok(())
}

fn validate_http_component(method: &str) -> Result<(), HmacError> {
    if method.is_empty() || method.len() > 16 || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(HmacError::InvalidHttpContext);
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), HmacError> {
    if !path.starts_with('/') || path.len() > 2048 || path.contains('\n') || path.contains('\r') {
        return Err(HmacError::InvalidHttpContext);
    }
    Ok(())
}

pub fn sign_http(
    body: &[u8],
    key: &[u8],
    key_id: &str,
    event_id: &str,
    method: &str,
    normalized_path: &str,
) -> Result<HmacSignature, HmacError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HmacError::TimestampError)?
        .as_secs();
    sign_http_at(
        body,
        key,
        key_id,
        event_id,
        method,
        normalized_path,
        timestamp,
    )
}

fn sign_http_at(
    body: &[u8],
    key: &[u8],
    key_id: &str,
    event_id: &str,
    method: &str,
    normalized_path: &str,
    timestamp: u64,
) -> Result<HmacSignature, HmacError> {
    validate_key_id(key_id)?;

    let canonical = canonical_input(
        SIGNATURE_VERSION,
        timestamp,
        event_id,
        method,
        normalized_path,
        body,
    )?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| HmacError::InvalidKey)?;
    mac.update(&canonical);

    Ok(HmacSignature {
        signature: hex::encode(mac.finalize().into_bytes()),
        key_id: key_id.to_string(),
        version: SIGNATURE_VERSION,
        timestamp,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_http(
    body: &[u8],
    key: &[u8],
    signature: &HmacSignature,
    event_id: &str,
    method: &str,
    normalized_path: &str,
    max_age_secs: u64,
    max_future_skew_secs: u64,
) -> Result<(), HmacError> {
    if signature.version != SIGNATURE_VERSION {
        return Err(HmacError::InvalidVersion);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HmacError::TimestampError)?
        .as_secs();

    if signature.timestamp > now.saturating_add(max_future_skew_secs) {
        return Err(HmacError::SignatureFromFuture);
    }
    if now.saturating_sub(signature.timestamp) > max_age_secs {
        return Err(HmacError::SignatureExpired);
    }

    let sig_bytes =
        hex::decode(&signature.signature).map_err(|_| HmacError::InvalidSignatureEncoding)?;
    let canonical = canonical_input(
        signature.version,
        signature.timestamp,
        event_id,
        method,
        normalized_path,
        body,
    )?;

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| HmacError::InvalidKey)?;
    mac.update(&canonical);
    mac.verify_slice(&sig_bytes)
        .map_err(|_| HmacError::VerificationFailed)
}

/// Compatibility wrappers for non-HTTP event signing. New HTTP integrations must
/// use `sign_http` / `verify_http`.
pub fn sign(
    body: &[u8],
    key: &[u8],
    key_id: &str,
    event_id: &str,
) -> Result<HmacSignature, HmacError> {
    sign_http(body, key, key_id, event_id, "EVENT", "/event")
}

pub fn verify(
    body: &[u8],
    key: &[u8],
    signature: &HmacSignature,
    event_id: &str,
    max_age_secs: u64,
) -> Result<(), HmacError> {
    verify_http(
        body,
        key,
        signature,
        event_id,
        "EVENT",
        "/event",
        max_age_secs,
        30,
    )
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HmacError {
    #[error("invalid signature format")]
    InvalidFormat,
    #[error("invalid signature version")]
    InvalidVersion,
    #[error("invalid key id")]
    InvalidKeyId,
    #[error("invalid event id")]
    InvalidEventId,
    #[error("invalid HTTP signing context")]
    InvalidHttpContext,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("invalid HMAC key")]
    InvalidKey,
    #[error("signature expired")]
    SignatureExpired,
    #[error("signature timestamp is too far in the future")]
    SignatureFromFuture,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid signature encoding")]
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
        let sig = sign_http(body, TEST_KEY, "key-1", TEST_EVENT_ID, "POST", "/hook").unwrap();
        let parsed = HmacSignature::parse(&sig.to_header()).unwrap();
        assert!(verify_http(
            body,
            TEST_KEY,
            &parsed,
            TEST_EVENT_ID,
            "POST",
            "/hook",
            300,
            30
        )
        .is_ok());
    }

    #[test]
    fn modified_method_or_path_is_rejected() {
        let body = b"test body content";
        let sig = sign_http(body, TEST_KEY, "key-1", TEST_EVENT_ID, "POST", "/hook").unwrap();
        assert!(verify_http(body, TEST_KEY, &sig, TEST_EVENT_ID, "GET", "/hook", 300, 30).is_err());
        assert!(verify_http(
            body,
            TEST_KEY,
            &sig,
            TEST_EVENT_ID,
            "POST",
            "/other",
            300,
            30
        )
        .is_err());
    }

    #[test]
    fn wrong_key_or_body_is_rejected() {
        let body = b"test body content";
        let sig = sign_http(body, TEST_KEY, "key-1", TEST_EVENT_ID, "POST", "/hook").unwrap();
        assert!(verify_http(
            body,
            b"wrong-key",
            &sig,
            TEST_EVENT_ID,
            "POST",
            "/hook",
            300,
            30
        )
        .is_err());
        assert!(verify_http(
            b"changed",
            TEST_KEY,
            &sig,
            TEST_EVENT_ID,
            "POST",
            "/hook",
            300,
            30
        )
        .is_err());
    }

    #[test]
    fn expired_and_future_signatures_are_rejected() {
        let body = b"test";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired = sign_http_at(
            body,
            TEST_KEY,
            "key-1",
            TEST_EVENT_ID,
            "POST",
            "/hook",
            now - 600,
        )
        .unwrap();
        assert!(matches!(
            verify_http(
                body,
                TEST_KEY,
                &expired,
                TEST_EVENT_ID,
                "POST",
                "/hook",
                300,
                30
            ),
            Err(HmacError::SignatureExpired)
        ));

        let future = sign_http_at(
            body,
            TEST_KEY,
            "key-1",
            TEST_EVENT_ID,
            "POST",
            "/hook",
            now + 120,
        )
        .unwrap();
        assert!(matches!(
            verify_http(
                body,
                TEST_KEY,
                &future,
                TEST_EVENT_ID,
                "POST",
                "/hook",
                300,
                30
            ),
            Err(HmacError::SignatureFromFuture)
        ));
    }

    #[test]
    fn parse_rejects_invalid_format() {
        assert!(HmacSignature::parse("invalid").is_err());
        assert!(HmacSignature::parse("v1,key,ts").is_err());
    }

    #[test]
    fn key_id_rejects_header_separator_and_control_characters() {
        // `,` is the header field separator — a smuggled extra field shifts
        // the timestamp/signature slots and must never parse cleanly.
        let injected = "v1,evil,extra,1700000000,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(HmacSignature::parse(injected).is_err());

        for bad_key_id in [
            "with space",
            "with\nnewline",
            "with\rreturn",
            "with\ttab",
            "with\x00null",
            "with\x1bansi",
            "ünïcode-key",
            "",
        ] {
            let header = format!(
                "v1,{bad_key_id},1700000000,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            );
            assert!(
                HmacSignature::parse(&header).is_err(),
                "key_id {bad_key_id:?} must be rejected"
            );
        }

        let overlong = "a".repeat(129);
        let header = format!(
            "v1,{overlong},1700000000,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert!(HmacSignature::parse(&header).is_err());

        // Known-good IDs used in production keep working.
        assert!(HmacSignature::parse(
            "v1,primary,1700000000,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_ok());
        assert!(HmacSignature::parse(
            "v1,mail-handoff-v1,1700000000,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_ok());
    }

    #[test]
    fn sign_rejects_invalid_key_id() {
        let now = 1_700_000_000u64;
        for bad_key_id in ["with space", "with,comma", "with\nnewline", "ünïcode", ""] {
            assert!(
                matches!(
                    sign_http_at(
                        b"body",
                        TEST_KEY,
                        bad_key_id,
                        TEST_EVENT_ID,
                        "POST",
                        "/hook",
                        now,
                    ),
                    Err(HmacError::InvalidKeyId)
                ),
                "signing with key_id {bad_key_id:?} must fail"
            );
        }
    }
}

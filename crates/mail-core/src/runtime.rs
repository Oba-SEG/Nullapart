//! Runtime composition for private Mail Core boundaries.
//!
//! This module deliberately keeps process-local test doubles out of the
//! executable composition path. A mail node must fail startup before accepting
//! any handoff if its workload HMAC keyring is unusable. Durable idempotency
//! integration is not claimed here until the authenticated handoff handler
//! accepts an idempotency store.

use std::collections::HashMap;

use nullapart_mail_contracts::transaction::DeploymentId;

use crate::handoff::HandoffConfig;

/// Safe startup failures for Mail Core's private workload boundaries.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeConfigError {
    #[error("Mail Core requires at least one workload HMAC key")]
    MissingWorkloadHmacKey,
    #[error("Mail Core workload HMAC keys may not be empty")]
    EmptyWorkloadHmacKey,
    #[error("Mail Core requires exactly one workload HMAC key")]
    MultipleWorkloadHmacKeys,
    #[error("Mail Core workload HMAC key material must be valid UTF-8")]
    NonUtf8WorkloadHmacKey,
}

/// Builds a handoff configuration from the node's workload HMAC keyring.
///
/// Exactly one key is required: it becomes the single active HMAC secret and
/// key id. This is the only constructor intended for a running mail node;
/// [`HandoffConfig::default`] is retained for isolated unit tests.
pub fn handoff_config(
    deployment_id: DeploymentId,
    node_id: String,
    max_message_size: u64,
    hmac_keys: HashMap<String, Vec<u8>>,
    hmac_max_age_secs: u64,
) -> Result<HandoffConfig, RuntimeConfigError> {
    if hmac_keys.is_empty() {
        return Err(RuntimeConfigError::MissingWorkloadHmacKey);
    }
    if hmac_keys.values().any(Vec::is_empty) {
        return Err(RuntimeConfigError::EmptyWorkloadHmacKey);
    }
    if hmac_keys.len() != 1 {
        return Err(RuntimeConfigError::MultipleWorkloadHmacKeys);
    }

    let (hmac_key_id, key_material) = hmac_keys
        .into_iter()
        .next()
        .expect("keyring length was checked");
    let hmac_secret =
        String::from_utf8(key_material).map_err(|_| RuntimeConfigError::NonUtf8WorkloadHmacKey)?;

    Ok(HandoffConfig {
        deployment_id,
        node_id,
        max_message_size,
        hmac_secret: Some(hmac_secret),
        hmac_key_id,
        signature_max_age_secs: hmac_max_age_secs,
        ..HandoffConfig::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring(entries: &[(&str, &[u8])]) -> HashMap<String, Vec<u8>> {
        entries
            .iter()
            .map(|(key_id, material)| (key_id.to_string(), material.to_vec()))
            .collect()
    }

    #[test]
    fn runtime_rejects_an_empty_keyring() {
        let result = handoff_config(
            DeploymentId::new("LOCAL-TEST"),
            "mail-local-1".to_string(),
            1024,
            HashMap::new(),
            300,
        );

        assert!(matches!(
            result,
            Err(RuntimeConfigError::MissingWorkloadHmacKey)
        ));
    }

    #[test]
    fn runtime_rejects_empty_key_values() {
        let result = handoff_config(
            DeploymentId::new("LOCAL-TEST"),
            "mail-local-1".to_string(),
            1024,
            keyring(&[("primary", b"")]),
            300,
        );

        assert!(matches!(
            result,
            Err(RuntimeConfigError::EmptyWorkloadHmacKey)
        ));
    }

    #[test]
    fn runtime_rejects_multiple_keys() {
        let result = handoff_config(
            DeploymentId::new("LOCAL-TEST"),
            "mail-local-1".to_string(),
            1024,
            keyring(&[("primary", b"secret-a"), ("secondary", b"secret-b")]),
            300,
        );

        assert!(matches!(
            result,
            Err(RuntimeConfigError::MultipleWorkloadHmacKeys)
        ));
    }

    #[test]
    fn runtime_rejects_non_utf8_key_material() {
        let result = handoff_config(
            DeploymentId::new("LOCAL-TEST"),
            "mail-local-1".to_string(),
            1024,
            keyring(&[("primary", &[0xff, 0xfe, 0xfd])]),
            300,
        );

        assert!(matches!(
            result,
            Err(RuntimeConfigError::NonUtf8WorkloadHmacKey)
        ));
    }

    #[test]
    fn runtime_derives_the_single_active_hmac_key() {
        let config = handoff_config(
            DeploymentId::new("LOCAL-TEST"),
            "mail-local-1".to_string(),
            1024,
            keyring(&[("primary", b"shared-secret")]),
            300,
        )
        .expect("single UTF-8 key is accepted");

        assert_eq!(config.hmac_key_id, "primary");
        assert_eq!(config.hmac_secret.as_deref(), Some("shared-secret"));
        assert_eq!(config.signature_max_age_secs, 300);
        assert_eq!(
            config.signature_future_skew_secs,
            HandoffConfig::default().signature_future_skew_secs
        );
        assert_eq!(config.max_message_size, 1024);
        assert_eq!(config.node_id, "mail-local-1");
    }
}

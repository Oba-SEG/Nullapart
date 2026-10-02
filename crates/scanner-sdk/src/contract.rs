//! Versioned scanner request/result contract.
//!
//! Scanner SDK request/result contracts are explicitly versioned per
//! `docs/27-API-VERSIONING-FEATURE-FLAGS.md`: consumers validate the contract
//! version and reject unsupported versions rather than parsing unknown output
//! optimistically. This is an in-SDK/library contract only — it does not
//! introduce a public endpoint, API major version or storage migration.
//!
//! Additive compatible changes stay within the current version; a breaking
//! change to [`crate::types::ScanRequest`]/[`crate::types::ScanResult`]
//! semantics requires bumping [`SCANNER_CONTRACT_VERSION`] and extending
//! [`SUPPORTED_SCANNER_CONTRACT_VERSIONS`] for a coordinated rollout.

/// Current scanner request/result contract version emitted by this SDK.
pub const SCANNER_CONTRACT_VERSION: u32 = 1;

/// Default contract version stamped on newly constructed requests/results.
pub const DEFAULT_SCANNER_CONTRACT_VERSION: u32 = SCANNER_CONTRACT_VERSION;

/// Contract versions this SDK release accepts when validating requests/results.
pub const SUPPORTED_SCANNER_CONTRACT_VERSIONS: &[u32] = &[SCANNER_CONTRACT_VERSION];

/// Error returned when a scanner request/result carries an unsupported
/// contract version. Unsupported versions are rejected explicitly; the
/// fabric never optimistically parses unknown contract output.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported scanner contract version {version}; supported versions: {supported:?}")]
pub struct UnsupportedContractVersion {
    /// The contract version that was presented.
    pub version: u32,
    /// The contract versions this SDK release accepts.
    pub supported: &'static [u32],
}

/// Validate a scanner contract version against the supported set.
///
/// Returns [`UnsupportedContractVersion`] for any version outside
/// [`SUPPORTED_SCANNER_CONTRACT_VERSIONS`] so callers can fail closed with
/// explicit evidence instead of guessing at unknown field semantics.
pub fn validate_scanner_contract_version(version: u32) -> Result<(), UnsupportedContractVersion> {
    if SUPPORTED_SCANNER_CONTRACT_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err(UnsupportedContractVersion {
            version,
            supported: SUPPORTED_SCANNER_CONTRACT_VERSIONS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_is_supported() {
        assert_eq!(SCANNER_CONTRACT_VERSION, 1);
        assert!(validate_scanner_contract_version(SCANNER_CONTRACT_VERSION).is_ok());
    }

    #[test]
    fn default_version_equals_current_version() {
        assert_eq!(DEFAULT_SCANNER_CONTRACT_VERSION, SCANNER_CONTRACT_VERSION);
        assert!(validate_scanner_contract_version(DEFAULT_SCANNER_CONTRACT_VERSION).is_ok());
    }

    #[test]
    fn unsupported_versions_are_rejected() {
        for version in [0u32, 2, 99, u32::MAX] {
            let error = validate_scanner_contract_version(version)
                .expect_err("version outside the supported set must be rejected");
            assert_eq!(error.version, version);
            assert_eq!(error.supported, SUPPORTED_SCANNER_CONTRACT_VERSIONS);
        }
    }

    #[test]
    fn unsupported_version_error_is_explicit() {
        let error = validate_scanner_contract_version(7).expect_err("7 is unsupported");
        let message = error.to_string();
        assert!(
            message.contains("7"),
            "message must name the version: {message}"
        );
        assert!(
            message.contains("supported"),
            "message must name support: {message}"
        );
    }
}

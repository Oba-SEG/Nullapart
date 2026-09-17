//! API versioning and compatibility conventions.
//!
//! Implements `docs/27-API-VERSIONING-FEATURE-FLAGS.md`.
//! Initial Control Plane namespace: `/api/v1/...`.

use serde::{Deserialize, Serialize};

/// API version identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiVersion {
    pub major: u32,
    pub minor: u32,
}

impl ApiVersion {
    pub const V1: Self = Self { major: 1, minor: 0 };

    /// Check if this version is compatible with the required version.
    /// Major version must match. Minor version is additive-compatible.
    pub fn is_compatible_with(&self, required: &ApiVersion) -> bool {
        self.major == required.major && self.minor >= required.minor
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.major)
    }
}

/// Standard API error response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Machine-readable error code.
    pub error: String,
    /// Human-readable message.
    pub message: String,
    /// Request trace/correlation ID.
    pub trace_id: String,
    /// API version that generated this error.
    pub api_version: String,
}

/// Standard API success response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
    pub api_version: String,
    pub trace_id: String,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn new(data: T, trace_id: &str) -> Self {
        Self {
            data,
            api_version: ApiVersion::V1.to_string(),
            trace_id: trace_id.to_string(),
        }
    }
}

/// API schema compatibility rule: additions are non-breaking, removals are breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaChangeType {
    /// Non-breaking: new field, new endpoint, new enum variant.
    Additive,
    /// Breaking: removed field, removed endpoint, changed type.
    Breaking,
    /// Potentially breaking: changed default, changed validation.
    Behavioral,
}

/// Record of an API schema change for compatibility tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaChangeRecord {
    pub change_type: SchemaChangeType,
    pub description: String,
    pub affected_version: ApiVersion,
    pub migration_required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compatibility() {
        let v1_0 = ApiVersion { major: 1, minor: 0 };
        let v1_1 = ApiVersion { major: 1, minor: 1 };
        let v2_0 = ApiVersion { major: 2, minor: 0 };

        assert!(v1_1.is_compatible_with(&v1_0));
        assert!(v1_0.is_compatible_with(&v1_0));
        assert!(!v1_0.is_compatible_with(&v1_1));
        assert!(!v2_0.is_compatible_with(&v1_0));
    }

    #[test]
    fn api_response_format() {
        let resp = ApiResponse::new("test", "trace-123");
        assert_eq!(resp.api_version, "v1");
        assert_eq!(resp.trace_id, "trace-123");
    }
}

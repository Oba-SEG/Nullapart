//! Error types for API and protocol responses

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Nullapart error types
#[derive(Debug, Error)]
pub enum NullapartError {
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Tenant message not found: {0}")]
    TenantMessageNotFound(String),

    #[error("Customer not found: {0}")]
    CustomerNotFound(String),

    #[error("Domain not found: {0}")]
    DomainNotFound(String),

    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Configuration not found: {0}")]
    ConfigNotFound(String),

    #[error("Feature not found: {0}")]
    FeatureNotFound(String),

    #[error("Artifact not found: {0}")]
    ArtifactNotFound(String),

    #[error("Delivery attempt not found: {0}")]
    DeliveryAttemptNotFound(String),

    // Authorization errors
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Invalid tenant: {0}")]
    InvalidTenant(String),

    #[error("Tenant not authorized: {0}")]
    TenantNotAuthorized(String),

    #[error("Insufficient permissions: {0}")]
    InsufficientPermissions(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    // Validation errors
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Malformed message: {0}")]
    MalformedMessage(String),

    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Invalid sender: {0}")]
    InvalidSender(String),

    // Policy errors
    #[error("Message rejected: {0}")]
    MessageRejected(String),

    #[error("Message quarantined: {0}")]
    MessageQuarantined(String),

    #[error("Message deferred: {0}")]
    MessageDeferred(String),

    #[error("Message held: {0}")]
    MessageHeld(String),

    // Processing errors
    #[error("Processing error: {0}")]
    ProcessingError(String),

    #[error("Scanner error: {0}")]
    ScannerError(String),

    #[error("Scanner unavailable: {0}")]
    ScannerUnavailable(String),

    #[error("Scanner timeout: {0}")]
    ScannerTimeout(String),

    #[error("Policy evaluation error: {0}")]
    PolicyEvaluationError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Delivery error: {0}")]
    DeliveryError(String),

    #[error("Downstream error: {0}")]
    DownstreamError(String),

    // Infrastructure errors
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    // Rate limiting
    #[error("Rate limited: {0}")]
    RateLimited(String),

    // Internal errors
    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
    pub code: ErrorCode,
    pub details: Option<serde_json::Value>,
    pub trace_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: &str) -> Self {
        Self {
            error: code.to_string(),
            message: message.to_string(),
            code,
            details: None,
            trace_id: None,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_trace_id(mut self, trace_id: &str) -> Self {
        self.trace_id = Some(trace_id.to_string());
        self
    }
}

/// Error code for categorizing errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotFound,
    Unauthorized,
    Forbidden,
    InvalidInput,
    ValidationError,
    MessageRejected,
    MessageQuarantined,
    MessageDeferred,
    ScannerError,
    ScannerUnavailable,
    ScannerTimeout,
    PolicyError,
    StorageError,
    DeliveryError,
    ServiceUnavailable,
    DatabaseError,
    CacheError,
    RateLimited,
    InternalError,
    NotImplemented,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not_found"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Forbidden => write!(f, "forbidden"),
            Self::InvalidInput => write!(f, "invalid_input"),
            Self::ValidationError => write!(f, "validation_error"),
            Self::MessageRejected => write!(f, "message_rejected"),
            Self::MessageQuarantined => write!(f, "message_quarantined"),
            Self::MessageDeferred => write!(f, "message_deferred"),
            Self::ScannerError => write!(f, "scanner_error"),
            Self::ScannerUnavailable => write!(f, "scanner_unavailable"),
            Self::ScannerTimeout => write!(f, "scanner_timeout"),
            Self::PolicyError => write!(f, "policy_error"),
            Self::StorageError => write!(f, "storage_error"),
            Self::DeliveryError => write!(f, "delivery_error"),
            Self::ServiceUnavailable => write!(f, "service_unavailable"),
            Self::DatabaseError => write!(f, "database_error"),
            Self::CacheError => write!(f, "cache_error"),
            Self::RateLimited => write!(f, "rate_limited"),
            Self::InternalError => write!(f, "internal_error"),
            Self::NotImplemented => write!(f, "not_implemented"),
        }
    }
}

impl From<NullapartError> for ApiError {
    fn from(err: NullapartError) -> Self {
        let (code, message) = match &err {
            NullapartError::TransactionNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::TenantMessageNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::CustomerNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::DomainNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::PolicyNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::ConfigNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::FeatureNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::ArtifactNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::DeliveryAttemptNotFound(_) => (ErrorCode::NotFound, err.to_string()),
            NullapartError::Unauthorized(_) => (ErrorCode::Unauthorized, err.to_string()),
            NullapartError::Forbidden(_) => (ErrorCode::Forbidden, err.to_string()),
            NullapartError::InvalidTenant(_) => (ErrorCode::InvalidInput, err.to_string()),
            NullapartError::TenantNotAuthorized(_) => (ErrorCode::Forbidden, err.to_string()),
            NullapartError::InsufficientPermissions(_) => (ErrorCode::Forbidden, err.to_string()),
            NullapartError::AccessDenied(_) => (ErrorCode::Forbidden, err.to_string()),
            NullapartError::ValidationError(_) => (ErrorCode::ValidationError, err.to_string()),
            NullapartError::InvalidInput(_) => (ErrorCode::InvalidInput, err.to_string()),
            NullapartError::MalformedMessage(_) => (ErrorCode::InvalidInput, err.to_string()),
            NullapartError::InvalidEnvelope(_) => (ErrorCode::InvalidInput, err.to_string()),
            NullapartError::InvalidRecipient(_) => (ErrorCode::InvalidInput, err.to_string()),
            NullapartError::InvalidSender(_) => (ErrorCode::InvalidInput, err.to_string()),
            NullapartError::MessageRejected(_) => (ErrorCode::MessageRejected, err.to_string()),
            NullapartError::MessageQuarantined(_) => {
                (ErrorCode::MessageQuarantined, err.to_string())
            },
            NullapartError::MessageDeferred(_) => (ErrorCode::MessageDeferred, err.to_string()),
            NullapartError::MessageHeld(_) => (ErrorCode::MessageDeferred, err.to_string()),
            NullapartError::ProcessingError(_) => (
                ErrorCode::InternalError,
                "internal processing error".to_string(),
            ),
            NullapartError::ScannerError(_) => (ErrorCode::ScannerError, err.to_string()),
            NullapartError::ScannerUnavailable(_) => {
                (ErrorCode::ScannerUnavailable, err.to_string())
            },
            NullapartError::ScannerTimeout(_) => (ErrorCode::ScannerTimeout, err.to_string()),
            NullapartError::PolicyEvaluationError(_) => (ErrorCode::PolicyError, err.to_string()),
            NullapartError::StorageError(_) => {
                (ErrorCode::StorageError, "storage backend error".to_string())
            },
            NullapartError::DeliveryError(_) => (ErrorCode::DeliveryError, err.to_string()),
            NullapartError::DownstreamError(_) => (ErrorCode::DeliveryError, err.to_string()),
            NullapartError::ServiceUnavailable(_) => {
                (ErrorCode::ServiceUnavailable, err.to_string())
            },
            NullapartError::DatabaseError(_) => {
                (ErrorCode::DatabaseError, "database error".to_string())
            },
            NullapartError::CacheError(_) => {
                (ErrorCode::CacheError, "cache backend error".to_string())
            },
            NullapartError::ConfigError(_) => {
                (ErrorCode::InternalError, "configuration error".to_string())
            },
            NullapartError::RateLimited(_) => (ErrorCode::RateLimited, err.to_string()),
            NullapartError::InternalError(_) => {
                (ErrorCode::InternalError, "internal error".to_string())
            },
            NullapartError::NotImplemented(_) => (ErrorCode::NotImplemented, err.to_string()),
        };

        ApiError {
            error: code.to_string(),
            message,
            code,
            details: None,
            trace_id: None,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// SMTP response with enhanced status code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpResponse {
    pub code: u32,
    pub enhanced_code: Option<crate::transaction::EnhancedCode>,
    pub message: String,
    pub action: SmtpAction,
}

/// SMTP action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpAction {
    Ok,
    Continue,
    Retry,
    Reject,
    Drop,
}

impl SmtpResponse {
    pub fn ok(message: &str) -> Self {
        Self {
            code: 250,
            enhanced_code: None,
            message: message.to_string(),
            action: SmtpAction::Ok,
        }
    }

    pub fn temp_failure(
        code: u32,
        enhanced: Option<crate::transaction::EnhancedCode>,
        message: &str,
    ) -> Self {
        Self {
            code,
            enhanced_code: enhanced,
            message: message.to_string(),
            action: SmtpAction::Retry,
        }
    }

    pub fn perm_failure(
        code: u32,
        enhanced: Option<crate::transaction::EnhancedCode>,
        message: &str,
    ) -> Self {
        Self {
            code,
            enhanced_code: enhanced,
            message: message.to_string(),
            action: SmtpAction::Reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_never_leak_details_to_api_response() {
        let leaks = [
            "postgres://user:secret@db.internal/nullapart",
            "connection refused 10.0.3.7:5432",
            "/etc/nullapart/secrets.yaml: missing key",
        ];

        let internal_errors = [
            NullapartError::DatabaseError(leaks[0].to_string()),
            NullapartError::CacheError(leaks[0].to_string()),
            NullapartError::StorageError(leaks[0].to_string()),
            NullapartError::ConfigError(leaks[1].to_string()),
            NullapartError::ProcessingError(leaks[1].to_string()),
            NullapartError::InternalError(leaks[2].to_string()),
        ];

        for err in internal_errors {
            let api: ApiError = err.into();
            for leak in leaks {
                assert!(
                    !api.message.contains(leak),
                    "ApiError message must not leak internal detail: {:?}",
                    api.message
                );
            }
            assert!(!api.message.contains("secret"));
            assert!(!api.message.contains("internal/"));
            assert!(!api.message.contains("10.0.3.7"));
        }
    }

    #[test]
    fn internal_error_codes_are_preserved_with_safe_messages() {
        let api: ApiError = NullapartError::DatabaseError("pg://x".to_string()).into();
        assert_eq!(api.code, ErrorCode::DatabaseError);
        assert_eq!(api.message, "database error");

        let api: ApiError = NullapartError::CacheError("redis://x".to_string()).into();
        assert_eq!(api.code, ErrorCode::CacheError);
        assert_eq!(api.message, "cache backend error");

        let api: ApiError = NullapartError::StorageError("s3://x".to_string()).into();
        assert_eq!(api.code, ErrorCode::StorageError);
        assert_eq!(api.message, "storage backend error");

        let api: ApiError = NullapartError::ConfigError("bad yaml".to_string()).into();
        assert_eq!(api.code, ErrorCode::InternalError);
        assert_eq!(api.message, "configuration error");

        let api: ApiError = NullapartError::ProcessingError("boom".to_string()).into();
        assert_eq!(api.code, ErrorCode::InternalError);
        assert_eq!(api.message, "internal processing error");

        let api: ApiError = NullapartError::InternalError("panic".to_string()).into();
        assert_eq!(api.code, ErrorCode::InternalError);
        assert_eq!(api.message, "internal error");
    }

    #[test]
    fn user_facing_errors_keep_their_messages() {
        let api: ApiError = NullapartError::TransactionNotFound("tx-123".to_string()).into();
        assert_eq!(api.code, ErrorCode::NotFound);
        assert!(api.message.contains("tx-123"));

        let api: ApiError =
            NullapartError::ValidationError("field 'subject' required".to_string()).into();
        assert_eq!(api.code, ErrorCode::ValidationError);
        assert!(api.message.contains("subject"));
    }
}

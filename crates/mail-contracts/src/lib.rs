//! Nullapart Mail Contracts
//!
//! Core domain types and contracts for the mail system.
//! These types define the stable interfaces between components.

pub mod api;
pub mod artifact;
pub mod audit;
pub mod error;
pub mod event;
pub mod finding;
pub mod hmac;
pub mod policy;
pub mod rate_limit;
pub mod transaction;

pub use artifact::{
    Artifact, ArtifactHash, ArtifactId, ContentType, HashAlgorithm, RetentionClass, StorageBackend,
    StorageLocation,
};
pub use audit::{
    Actor, ActorId, ActorType, AuditAction, AuditEvent, AuditEventId, AuditResource, AuditResult,
    CorrelationId, ResourceType, SessionId,
};
pub use error::*;
pub use event::{
    DataClassification, Event, EventId, EventPayload, EventSafePayload, EventType, EventVersion,
    IdempotencyKey,
};
pub use finding::{
    Confidence, FailureType, FindingCategory, FindingId, FindingScope, FindingSeverity, Indicator,
    IndicatorType, ScannerFailure, ScannerStatus, ScannerType, SecurityFinding,
};
pub use policy::{
    AuthCondition, ConditionScope, ConfigRevision, ConfigRevisionId, ContentCondition, FeatureId,
    FeatureScope, FeatureSwitch, FeatureValue, FindingCondition, NotifyAction, PolicyAction,
    PolicyCondition, PolicyRevision, PolicyRevisionId, PolicyRule, PolicyRuleId, ReasonCode,
    RecipientCondition, SenderCondition,
};
pub use rate_limit::{
    AppRateLimits, ExceededAction, HighRiskLimits, RateLimitConfig, RateLimitKey, RateLimitResult,
    SmtpRateLimits, TokenBucket,
};
pub use transaction::*;

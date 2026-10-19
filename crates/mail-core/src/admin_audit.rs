//! Authenticated Control Plane administrative audit query slice.
//!
//! Reads the append-only `audit_events` store for the Admin Audit UI
//! (`docs/17-ADMIN-AUDIT-LOGGING.md`) and records its own access.
//!
//! Security invariants:
//!
//! - scope is derived from the server-injected `TenantContext` only; a client
//!   may narrow its own read (never widen it), and every query additionally
//!   narrows through transaction-scoped RLS context so a forgotten filter
//!   cannot widen the result set (migration `009_admin_audit_scope.sql`);
//! - audit reads and exports are themselves audited in the same transaction as
//!   the read, so a failed audit write fails the read closed;
//! - export additionally requires the export permission, step-up assurance and
//!   a dedicated high-risk rate limit, and is column-limited: free-form
//!   `details` never leaves the service through export;
//! - detail projections render `details` as redacted key/value pairs rather
//!   than raw JSON, so Support never gains a change-dump or content path;
//! - projections carry no secrets, message content or artifact locations.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{rejection::JsonRejection, rejection::QueryRejection, Extension, Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use nullapart_mail_contracts::{
    rate_limit::{HighRiskLimits, RateLimitConfig, TokenBucket},
    DeploymentId,
};
use nullapart_policy::{CustomerLifecycle, TenantContext};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

/// Read permission required for every audit route.
pub const AUDIT_VIEW_PERMISSION: &str = "audit:view";
/// Export permission; also requires step-up assurance.
pub const AUDIT_EXPORT_PERMISSION: &str = "audit:export";
/// Platform permission letting Support open an explicit customer scope
/// (`docs/29-TENANT-FEATURE-ROUTING.md`: cross-customer paths are explicit
/// permission plus a specific customer scope).
pub const AUDIT_CROSS_CUSTOMER_PERMISSION: &str = "audit:cross_customer";

const ACCESS_LIST_ACTION: &str = "audit_access_list";
const ACCESS_DETAIL_ACTION: &str = "audit_access_detail";
const ACCESS_DENIED_ACTION: &str = "audit_access_denied";
const EXPORT_ACTION: &str = "audit_export";
const AUDIT_RESOURCE_TYPE: &str = "audit";

const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 200;
const MAX_EXPORT_ROWS: i64 = 10_000;
const MAX_FILTER_LENGTH: usize = 200;
const REDACTED: &str = "[redacted]";

const CSV_HEADER: &str = "time,actor,roles,acting_as,acting_customer,action,resource_type,resource_id,result,source_ip,reason,trace_id";

/// Key fragments whose detail values are replaced with `[redacted]` before any
/// projection or export leaves the service.
const REDACTED_KEY_FRAGMENTS: [&str; 9] = [
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "credential",
    "private_key",
    "api_key",
    "authorization",
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminAuditError {
    #[error("permission denied")]
    PermissionDenied,
    #[error("customer inactive")]
    CustomerInactive,
    #[error("deployment mismatch")]
    DeploymentMismatch,
    #[error("step-up required")]
    StepUpRequired,
    #[error("invalid request")]
    InvalidRequest,
    #[error("not found")]
    NotFound,
    #[error("rate limited")]
    RateLimited,
    #[error("persistence failed")]
    PersistenceFailed,
}

/// Server-derived read scope for one authorized audit query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditScope {
    /// System Admin regional read: every audit row in the deployment.
    Platform,
    /// Customer-scoped read (Customer Admin context, or System/Support
    /// deliberately narrowed to one customer).
    Customer(String),
    /// Support own-activity read: only rows this actor produced.
    Own,
}

impl AuditScope {
    fn as_guc(&self) -> &'static str {
        match self {
            AuditScope::Platform => "platform",
            AuditScope::Customer(_) => "tenant",
            AuditScope::Own => "own",
        }
    }

    /// Customer attribution for rows this access writes.
    fn written_customer_id(&self) -> Option<&str> {
        match self {
            AuditScope::Customer(customer_id) => Some(customer_id.as_str()),
            AuditScope::Platform | AuditScope::Own => None,
        }
    }
}

/// Authorized audit access derived from an authenticated `TenantContext`.
///
/// Fields are private-by-construction: handlers obtain one only through
/// [`AuthorizedAuditAccess::from_context`], which performs the server-side
/// authorization checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedAuditAccess {
    deployment_id: String,
    scope: AuditScope,
    actor_id: String,
    actor_login: String,
    actor_roles: Vec<String>,
    impersonated_subject: Option<String>,
    impersonated_customer: Option<String>,
    session_id: String,
    trace_id: String,
    source_ip: Option<String>,
    /// The actor's own placement, not the read filter. `scope` says which rows
    /// this read may see; it says nothing about who is asking, because a System
    /// Admin filtering to one customer and a Customer Admin both end up in
    /// `AuditScope::Customer`. Platform readouts key off this field.
    platform_placement: bool,
}

impl AuthorizedAuditAccess {
    /// Derives scope from the injected context. `requested_customer` is a
    /// client-supplied *filter* only: it may narrow the read, never widen it.
    pub fn from_context(
        context: &TenantContext,
        deployment_id: &DeploymentId,
        requested_customer: Option<&str>,
        source_ip: Option<String>,
    ) -> Result<Self, AdminAuditError> {
        if context.deployment_id != *deployment_id {
            return Err(AdminAuditError::DeploymentMismatch);
        }
        if context.customer_lifecycle != CustomerLifecycle::Active {
            return Err(AdminAuditError::CustomerInactive);
        }
        if !context
            .permissions
            .iter()
            .any(|permission| permission == AUDIT_VIEW_PERMISSION)
        {
            return Err(AdminAuditError::PermissionDenied);
        }

        let requested = requested_customer
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                if value.len() > MAX_FILTER_LENGTH {
                    Err(AdminAuditError::InvalidRequest)
                } else {
                    Ok(value.to_string())
                }
            })
            .transpose()?;

        let is_system = context
            .actor
            .roles
            .iter()
            .any(|role| role == "system_admin");
        let is_support = context.actor.roles.iter().any(|role| role == "support");

        let scope = if let Some(impersonation) = context.impersonation.as_ref() {
            // Impersonation narrows every audit read to the impersonated
            // tenant, regardless of the real actor's own role scope.
            if let Some(customer_id) = requested {
                if customer_id != impersonation.impersonated_customer.0 {
                    return Err(AdminAuditError::PermissionDenied);
                }
            }
            AuditScope::Customer(impersonation.impersonated_customer.0.clone())
        } else if is_system {
            match requested {
                Some(customer_id) => AuditScope::Customer(customer_id),
                None => AuditScope::Platform,
            }
        } else if is_support {
            match requested {
                Some(customer_id) => {
                    if !context
                        .permissions
                        .iter()
                        .any(|permission| permission == AUDIT_CROSS_CUSTOMER_PERMISSION)
                    {
                        return Err(AdminAuditError::PermissionDenied);
                    }
                    AuditScope::Customer(customer_id)
                },
                None => AuditScope::Own,
            }
        } else {
            // Customer Admin: the context customer is the only reachable scope.
            if let Some(customer_id) = requested {
                if customer_id != context.customer_id.0 {
                    return Err(AdminAuditError::PermissionDenied);
                }
            }
            AuditScope::Customer(context.customer_id.0.clone())
        };

        Ok(Self {
            deployment_id: deployment_id.0.clone(),
            scope,
            actor_id: context.actor.actor_id.0.to_string(),
            actor_login: context.actor.login.clone(),
            actor_roles: context.actor.roles.clone(),
            impersonated_subject: context
                .impersonation
                .as_ref()
                .and_then(|impersonation| impersonation.impersonated_subject.clone()),
            impersonated_customer: context
                .impersonation
                .as_ref()
                .map(|impersonation| impersonation.impersonated_customer.0.clone()),
            session_id: context.session_id.clone(),
            trace_id: context.trace_id.clone(),
            source_ip,
            // An operator standing inside a customer's console is treated as that
            // customer for readout purposes: impersonation narrows what they may
            // see, so it also narrows what the platform tells them.
            platform_placement: (is_system || is_support) && context.impersonation.is_none(),
        })
    }
}

/// Raw client filter input. Every field is optional; validation happens in
/// [`AuditQueryFilters::validate`].
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AuditQueryFilters {
    pub from: Option<String>,
    pub to: Option<String>,
    pub action: Option<String>,
    pub actor_login: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub result: Option<String>,
    pub trace_id: Option<String>,
    pub impersonated_only: Option<bool>,
    pub customer_id: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditResultFilter {
    Success,
    Denied,
    Failed,
}

impl AuditResultFilter {
    fn as_str(&self) -> &'static str {
        match self {
            AuditResultFilter::Success => "success",
            AuditResultFilter::Denied => "denied",
            AuditResultFilter::Failed => "failed",
        }
    }
}

/// Validated, bounded query filters.
#[derive(Debug, Clone)]
pub struct ValidatedAuditFilters {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub action: Option<String>,
    pub actor_login: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub result: Option<AuditResultFilter>,
    pub trace_id: Option<String>,
    pub impersonated_only: bool,
    pub customer_id: Option<String>,
    pub cursor: Option<(DateTime<Utc>, Uuid)>,
    pub limit: i64,
}

impl AuditQueryFilters {
    pub fn validate(self) -> Result<ValidatedAuditFilters, AdminAuditError> {
        let parse_time = |value: Option<String>| -> Result<Option<DateTime<Utc>>, AdminAuditError> {
            match value {
                None => Ok(None),
                Some(raw) => DateTime::parse_from_rfc3339(&raw)
                    .map(|parsed| Some(parsed.with_timezone(&Utc)))
                    .map_err(|_| AdminAuditError::InvalidRequest),
            }
        };
        let from = parse_time(self.from)?;
        let to = parse_time(self.to)?;
        if matches!((from, to), (Some(from), Some(to)) if from > to) {
            return Err(AdminAuditError::InvalidRequest);
        }

        let bounded = |value: Option<String>| -> Result<Option<String>, AdminAuditError> {
            match value.map(|raw| raw.trim().to_string()) {
                None => Ok(None),
                Some(raw) if raw.is_empty() => Ok(None),
                Some(raw) if raw.len() > MAX_FILTER_LENGTH => Err(AdminAuditError::InvalidRequest),
                Some(raw) => Ok(Some(raw)),
            }
        };

        let result = match bounded(self.result)?.as_deref() {
            None => None,
            Some("success") => Some(AuditResultFilter::Success),
            Some("denied") => Some(AuditResultFilter::Denied),
            Some("failed") => Some(AuditResultFilter::Failed),
            Some(_) => return Err(AdminAuditError::InvalidRequest),
        };

        let limit = self.limit.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(AdminAuditError::InvalidRequest);
        }

        let cursor = match bounded(self.cursor)? {
            None => None,
            Some(raw) => Some(parse_cursor(&raw)?),
        };

        Ok(ValidatedAuditFilters {
            from,
            to,
            action: bounded(self.action)?,
            actor_login: bounded(self.actor_login)?,
            resource_type: bounded(self.resource_type)?,
            resource_id: bounded(self.resource_id)?,
            result,
            trace_id: bounded(self.trace_id)?,
            impersonated_only: self.impersonated_only.unwrap_or(false),
            customer_id: bounded(self.customer_id)?,
            cursor,
            limit,
        })
    }
}

fn encode_cursor(created_at: &DateTime<Utc>, id: &Uuid) -> String {
    format!("{}-{}", created_at.timestamp_micros(), id)
}

fn parse_cursor(raw: &str) -> Result<(DateTime<Utc>, Uuid), AdminAuditError> {
    let (micros, id) = raw.split_once('-').ok_or(AdminAuditError::InvalidRequest)?;
    let timestamp_micros: i64 = micros
        .parse()
        .map_err(|_| AdminAuditError::InvalidRequest)?;
    let timestamp =
        DateTime::from_timestamp_micros(timestamp_micros).ok_or(AdminAuditError::InvalidRequest)?;
    let id = Uuid::parse_str(id).map_err(|_| AdminAuditError::InvalidRequest)?;
    Ok((timestamp, id))
}

/// Safe list projection. It never carries `details`, content or artifact data.
#[derive(Debug, Serialize, Clone)]
pub struct AuditEventListItem {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub actor_login: String,
    pub actor_roles: Vec<String>,
    pub impersonated_subject: Option<String>,
    pub impersonated_customer: Option<String>,
    pub customer_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub result: String,
    pub reason: Option<String>,
    pub source_ip: Option<String>,
    pub trace_id: String,
}

/// One redacted key/value pair rendered instead of raw JSON.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct AuditDetailField {
    pub key: String,
    pub value: String,
}

/// Safe detail projection: list fields plus session context and redacted
/// change details.
#[derive(Debug, Serialize)]
pub struct AuditEventDetail {
    #[serde(flatten)]
    pub item: AuditEventListItem,
    pub session_id: Option<String>,
    pub details: Vec<AuditDetailField>,
}

#[derive(Debug, Serialize)]
pub struct AuditEventPage {
    pub events: Vec<AuditEventListItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditCheckpointState {
    Current,
    Stale,
    NotConfigured,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct AuditCheckpointStatus {
    pub state: AuditCheckpointState,
    pub last_checkpoint_at: Option<DateTime<Utc>>,
    pub covers_events_through: Option<DateTime<Utc>>,
    pub checkpoint_sequence: Option<i64>,
    pub event_count: Option<i64>,
    pub root_hash: Option<String>,
    pub signer_key_id: Option<String>,
    pub archive_uri: Option<String>,
}

/// Stored audit row before projection.
#[derive(Debug, Clone)]
pub struct AuditEventRecord {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    /// Stable actor identifier (user id or deterministic login-derived id
    /// for boundary identities that have no user row yet).
    pub actor_id: String,
    pub actor_login: String,
    pub actor_roles: Vec<String>,
    pub impersonated_subject: Option<String>,
    pub impersonated_customer: Option<String>,
    pub customer_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub result: String,
    pub source_ip: Option<String>,
    pub session_id: Option<String>,
    pub trace_id: String,
    pub details: serde_json::Value,
}

impl AuditEventRecord {
    /// Extracts a single human reason from known detail keys for the table's
    /// Reason column; free-form details otherwise stay in the drawer.
    pub fn reason(&self) -> Option<String> {
        ["reason", "release_reason", "reason_code", "failure_code"]
            .iter()
            .find_map(|key| {
                self.details.get(key).and_then(|value| match value {
                    serde_json::Value::String(text) if !text.is_empty() => Some(text.clone()),
                    serde_json::Value::Number(number) => Some(number.to_string()),
                    _ => None,
                })
            })
    }

    fn list_item(&self) -> AuditEventListItem {
        AuditEventListItem {
            id: self.id,
            created_at: self.created_at,
            actor_login: self.actor_login.clone(),
            actor_roles: self.actor_roles.clone(),
            impersonated_subject: self.impersonated_subject.clone(),
            impersonated_customer: self.impersonated_customer.clone(),
            customer_id: self.customer_id.clone(),
            action: self.action.clone(),
            resource_type: self.resource_type.clone(),
            resource_id: self.resource_id.clone(),
            result: self.result.clone(),
            reason: self.reason(),
            source_ip: self.source_ip.clone(),
            trace_id: self.trace_id.clone(),
        }
    }

    fn detail(&self) -> AuditEventDetail {
        AuditEventDetail {
            item: self.list_item(),
            session_id: self.session_id.clone(),
            details: detail_fields(&self.details),
        }
    }
}

/// Flattens audit details into sorted redacted key/value pairs. Nested values
/// are rendered as compact JSON after recursive key redaction.
pub fn detail_fields(details: &serde_json::Value) -> Vec<AuditDetailField> {
    let mut fields = Vec::new();
    match details {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                let value = &map[key];
                fields.push(AuditDetailField {
                    key: key.clone(),
                    value: if is_redacted_key(key) {
                        REDACTED.to_string()
                    } else {
                        render_detail_value(value)
                    },
                });
            }
        },
        serde_json::Value::Null => {},
        other => fields.push(AuditDetailField {
            key: "value".to_string(),
            value: render_detail_value(other),
        }),
    }
    fields
}

fn render_detail_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Bool(flag) => flag.to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Null => String::new(),
        nested => {
            serde_json::to_string(&redact_value(nested)).unwrap_or_else(|_| REDACTED.to_string())
        },
    }
}

fn redact_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let safe = if is_redacted_key(key) {
                        serde_json::Value::String(REDACTED.to_string())
                    } else {
                        redact_value(value)
                    };
                    (key.clone(), safe)
                })
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_value).collect())
        },
        other => other.clone(),
    }
}

fn is_redacted_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    REDACTED_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

/// Storage boundary for audit reads. The Postgres implementation performs the
/// read and its own access record in one transaction; the in-memory
/// implementation exists for deterministic API tests.
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn list(
        &self,
        access: &AuthorizedAuditAccess,
        filters: &ValidatedAuditFilters,
    ) -> Result<AuditEventPage, AdminAuditError>;

    async fn detail(
        &self,
        access: &AuthorizedAuditAccess,
        event_id: Uuid,
    ) -> Result<Option<AuditEventDetail>, AdminAuditError>;

    async fn export(
        &self,
        access: &AuthorizedAuditAccess,
        filters: &ValidatedAuditFilters,
    ) -> Result<Vec<AuditEventRecord>, AdminAuditError>;

    async fn checkpoint_status(
        &self,
        access: &AuthorizedAuditAccess,
    ) -> Result<AuditCheckpointStatus, AdminAuditError>;

    /// Records a denied high-risk attempt (export denial, cross-tenant probe).
    async fn record_denied(
        &self,
        access: &AuthorizedAuditAccess,
        action: &str,
        resource_id: Option<&str>,
        reason: &str,
    ) -> Result<(), AdminAuditError>;

    /// Records an administrative action raised outside this module (session
    /// login/logout, role grants/revokes, user management). The record carries
    /// its own actor; `deployment_id` is applied as the row's deployment
    /// boundary. Implementations use the same transactional RLS context as
    /// their reads, so a row that cannot be attributed cannot commit.
    async fn record_event(
        &self,
        deployment_id: &str,
        record: AuditEventRecord,
    ) -> Result<(), AdminAuditError>;
}

/// Deterministic in-memory store used by API tests. It mirrors the Postgres
/// scoping rules (scope first, then filters, then keyset ordering) so handler
/// tests exercise the same authorization shape.
#[derive(Default)]
pub struct InMemoryAuditStore {
    events: std::sync::Mutex<Vec<AuditEventRecord>>,
}

impl InMemoryAuditStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, record: AuditEventRecord) {
        self.events
            .lock()
            .expect("audit store poisoned")
            .push(record);
    }

    /// Stable ordered copy of stored rows for assertions.
    pub fn records(&self) -> Vec<AuditEventRecord> {
        self.events.lock().expect("audit store poisoned").clone()
    }

    fn matching(&self, access: &AuthorizedAuditAccess) -> Vec<AuditEventRecord> {
        self.events
            .lock()
            .expect("audit store poisoned")
            .iter()
            .filter(|record| record_matches_scope(record, access))
            .cloned()
            .collect()
    }

    fn push_access(
        &self,
        access: &AuthorizedAuditAccess,
        action: &str,
        resource_id: Option<String>,
        result: &str,
        details: serde_json::Value,
    ) {
        self.events
            .lock()
            .expect("audit store poisoned")
            .push(AuditEventRecord {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                actor_id: access.actor_id.clone(),
                actor_login: access.actor_login.clone(),
                actor_roles: access.actor_roles.clone(),
                impersonated_subject: access.impersonated_subject.clone(),
                impersonated_customer: access.impersonated_customer.clone(),
                customer_id: access.scope.written_customer_id().map(str::to_string),
                action: action.to_string(),
                resource_type: AUDIT_RESOURCE_TYPE.to_string(),
                resource_id,
                result: result.to_string(),
                source_ip: access.source_ip.clone(),
                session_id: Some(access.session_id.clone()),
                trace_id: access.trace_id.clone(),
                details,
            });
    }
}

fn record_matches_scope(record: &AuditEventRecord, access: &AuthorizedAuditAccess) -> bool {
    match &access.scope {
        AuditScope::Platform => true,
        AuditScope::Customer(customer_id) => {
            record.customer_id.as_deref() == Some(customer_id.as_str())
        },
        // The in-memory double keys "own activity" on the stable login; the
        // Postgres store keys it on `actor_id`, which the RLS policy enforces.
        AuditScope::Own => record.actor_login == access.actor_login,
    }
}

#[async_trait]
impl AuditStore for InMemoryAuditStore {
    async fn list(
        &self,
        access: &AuthorizedAuditAccess,
        filters: &ValidatedAuditFilters,
    ) -> Result<AuditEventPage, AdminAuditError> {
        let mut matching: Vec<AuditEventRecord> = self
            .matching(access)
            .into_iter()
            .filter(|record| record_filters_match(record, filters))
            .collect();
        matching.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        if let Some((cursor_at, cursor_id)) = filters.cursor {
            matching.retain(|record| (record.created_at, record.id) < (cursor_at, cursor_id));
        }

        let page_size = filters.limit as usize;
        let truncated = matching.len() > page_size;
        let selected: Vec<AuditEventRecord> = matching.into_iter().take(page_size).collect();
        let next_cursor = if truncated {
            selected
                .last()
                .map(|record| encode_cursor(&record.created_at, &record.id))
        } else {
            None
        };

        self.push_access(
            access,
            ACCESS_LIST_ACTION,
            None,
            "success",
            serde_json::json!({
                "scope": access.scope.as_guc(),
                "row_count": selected.len(),
                "filters": filters_summary(filters),
            }),
        );

        Ok(AuditEventPage {
            events: selected.iter().map(AuditEventRecord::list_item).collect(),
            next_cursor,
        })
    }

    async fn detail(
        &self,
        access: &AuthorizedAuditAccess,
        event_id: Uuid,
    ) -> Result<Option<AuditEventDetail>, AdminAuditError> {
        let found = self
            .matching(access)
            .into_iter()
            .find(|record| record.id == event_id);
        match found {
            Some(record) => {
                self.push_access(
                    access,
                    ACCESS_DETAIL_ACTION,
                    Some(event_id.to_string()),
                    "success",
                    serde_json::json!({ "scope": access.scope.as_guc() }),
                );
                Ok(Some(record.detail()))
            },
            None => {
                self.push_access(
                    access,
                    ACCESS_DENIED_ACTION,
                    Some(event_id.to_string()),
                    "denied",
                    serde_json::json!({
                        "scope": access.scope.as_guc(),
                        "reason": "audit event not in scope",
                    }),
                );
                Ok(None)
            },
        }
    }

    async fn export(
        &self,
        access: &AuthorizedAuditAccess,
        filters: &ValidatedAuditFilters,
    ) -> Result<Vec<AuditEventRecord>, AdminAuditError> {
        let mut matching: Vec<AuditEventRecord> = self
            .matching(access)
            .into_iter()
            .filter(|record| record_filters_match(record, filters))
            .collect();
        matching.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        matching.truncate(MAX_EXPORT_ROWS as usize);

        self.push_access(
            access,
            EXPORT_ACTION,
            None,
            "success",
            serde_json::json!({
                "scope": access.scope.as_guc(),
                "format": "csv",
                "row_count": matching.len(),
                "truncated": matching.len() as i64 == MAX_EXPORT_ROWS,
                "filters": filters_summary(filters),
            }),
        );
        Ok(matching)
    }

    async fn checkpoint_status(
        &self,
        access: &AuthorizedAuditAccess,
    ) -> Result<AuditCheckpointStatus, AdminAuditError> {
        self.push_access(
            access,
            ACCESS_DETAIL_ACTION,
            Some("checkpoint-status".to_string()),
            "success",
            serde_json::json!({
                "scope": access.scope.as_guc(),
                "status": "not_configured",
            }),
        );
        Ok(AuditCheckpointStatus {
            state: AuditCheckpointState::NotConfigured,
            last_checkpoint_at: None,
            covers_events_through: None,
            checkpoint_sequence: None,
            event_count: None,
            root_hash: None,
            signer_key_id: None,
            archive_uri: None,
        })
    }

    async fn record_denied(
        &self,
        access: &AuthorizedAuditAccess,
        action: &str,
        resource_id: Option<&str>,
        reason: &str,
    ) -> Result<(), AdminAuditError> {
        self.push_access(
            access,
            action,
            resource_id.map(str::to_string),
            "denied",
            serde_json::json!({
                "scope": access.scope.as_guc(),
                "reason": reason,
            }),
        );
        Ok(())
    }

    async fn record_event(
        &self,
        _deployment_id: &str,
        record: AuditEventRecord,
    ) -> Result<(), AdminAuditError> {
        // The in-memory double mirrors the Postgres scoping shape, not the
        // deployment column: tests run against a single deployment.
        self.events
            .lock()
            .expect("audit store poisoned")
            .push(record);
        Ok(())
    }
}

fn filters_summary(filters: &ValidatedAuditFilters) -> serde_json::Value {
    serde_json::json!({
        "from": filters.from.map(|value| value.to_rfc3339()),
        "to": filters.to.map(|value| value.to_rfc3339()),
        "action": filters.action,
        "actor_login": filters.actor_login,
        "resource_type": filters.resource_type,
        "resource_id": filters.resource_id,
        "result": filters.result.as_ref().map(|result| result.as_str()),
        "trace_id": filters.trace_id,
        "impersonated_only": filters.impersonated_only,
        "customer_id": filters.customer_id,
        "limit": filters.limit,
    })
}

fn record_filters_match(record: &AuditEventRecord, filters: &ValidatedAuditFilters) -> bool {
    if let Some(from) = filters.from {
        if record.created_at < from {
            return false;
        }
    }
    if let Some(to) = filters.to {
        if record.created_at > to {
            return false;
        }
    }
    if let Some(action) = &filters.action {
        if &record.action != action {
            return false;
        }
    }
    if let Some(actor_login) = &filters.actor_login {
        if &record.actor_login != actor_login {
            return false;
        }
    }
    if let Some(resource_type) = &filters.resource_type {
        if &record.resource_type != resource_type {
            return false;
        }
    }
    if let Some(resource_id) = &filters.resource_id {
        if record.resource_id.as_deref() != Some(resource_id.as_str()) {
            return false;
        }
    }
    if let Some(result) = &filters.result {
        if record.result != result.as_str() {
            return false;
        }
    }
    if let Some(trace_id) = &filters.trace_id {
        if &record.trace_id != trace_id {
            return false;
        }
    }
    if filters.impersonated_only && record.impersonated_subject.is_none() {
        return false;
    }
    if let Some(customer_id) = &filters.customer_id {
        if record.customer_id.as_deref() != Some(customer_id.as_str()) {
            return false;
        }
    }
    true
}

/// Bound parameter for the dynamic Postgres query builder.
enum Bind {
    Text(String),
    Timestamp(DateTime<Utc>),
    Id(Uuid),
    Int(i64),
}

struct ScopedSelect {
    sql: String,
    binds: Vec<Bind>,
    index: u32,
}

impl ScopedSelect {
    fn new(columns: &str, access: &AuthorizedAuditAccess) -> Self {
        let mut builder = Self {
            sql: format!("SELECT {columns} FROM audit_events WHERE deployment_id = $1"),
            binds: vec![Bind::Text(access.deployment_id.clone())],
            index: 1,
        };
        match &access.scope {
            AuditScope::Platform => {},
            AuditScope::Customer(customer_id) => {
                builder.push(" AND customer_id = ${}", Bind::Text(customer_id.clone()));
            },
            AuditScope::Own => {
                builder.push(" AND actor_id = ${}", Bind::Text(access.actor_id.clone()));
            },
        }
        builder
    }

    /// Appends a clause containing one `{}` placeholder for the next parameter.
    fn push(&mut self, clause: &str, bind: Bind) {
        self.index += 1;
        let placeholder = self.index;
        self.sql
            .push_str(&clause.replace("{}", &placeholder.to_string()));
        self.binds.push(bind);
    }

    /// Appends a clause that needs no parameter binding.
    fn push_literal(&mut self, clause: &str) {
        self.sql.push_str(clause);
    }

    /// Keyset cursor: strictly older than `(created_at, id)`.
    fn push_cursor(&mut self, created_at: DateTime<Utc>, id: Uuid) {
        self.index += 1;
        let created_at_index = self.index;
        self.index += 1;
        let id_index = self.index;
        self.sql.push_str(&format!(
            " AND (created_at, id) < (${created_at_index}, ${id_index})"
        ));
        self.binds.push(Bind::Timestamp(created_at));
        self.binds.push(Bind::Id(id));
    }
}

/// Builds the parameterised query for a scope/filter selection. The borrow of
/// `builder` lasts exactly as long as the returned query.
fn prepared(
    builder: &ScopedSelect,
) -> sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments> {
    let mut query = sqlx::query(&builder.sql);
    for bind in &builder.binds {
        query = match bind {
            Bind::Text(value) => query.bind(value),
            Bind::Timestamp(value) => query.bind(value),
            Bind::Id(value) => query.bind(value),
            Bind::Int(value) => query.bind(value),
        };
    }
    query
}

fn push_common_filters(builder: &mut ScopedSelect, filters: &ValidatedAuditFilters) {
    if let Some(from) = filters.from {
        builder.push(" AND created_at >= ${}", Bind::Timestamp(from));
    }
    if let Some(to) = filters.to {
        builder.push(" AND created_at <= ${}", Bind::Timestamp(to));
    }
    if let Some(action) = &filters.action {
        builder.push(" AND action = ${}", Bind::Text(action.clone()));
    }
    if let Some(actor_login) = &filters.actor_login {
        builder.push(" AND actor_login = ${}", Bind::Text(actor_login.clone()));
    }
    if let Some(resource_type) = &filters.resource_type {
        builder.push(
            " AND resource_type = ${}",
            Bind::Text(resource_type.clone()),
        );
    }
    if let Some(resource_id) = &filters.resource_id {
        builder.push(" AND resource_id = ${}", Bind::Text(resource_id.clone()));
    }
    if let Some(result) = &filters.result {
        builder.push(" AND result = ${}", Bind::Text(result.as_str().to_string()));
    }
    if let Some(trace_id) = &filters.trace_id {
        builder.push(" AND trace_id = ${}", Bind::Text(trace_id.clone()));
    }
    if filters.impersonated_only {
        builder.push_literal(" AND impersonated_subject IS NOT NULL");
    }
    if let Some(customer_id) = &filters.customer_id {
        builder.push(" AND customer_id = ${}", Bind::Text(customer_id.clone()));
    }
}

const LIST_COLUMNS: &str =
    "id, created_at, actor_id, actor_login, actor_roles, impersonated_subject, \
     impersonated_customer, customer_id, action, resource_type, resource_id, result, \
     source_ip, session_id, trace_id, details";

fn record_from_row(row: &sqlx::postgres::PgRow) -> AuditEventRecord {
    AuditEventRecord {
        id: row.get("id"),
        created_at: row.get("created_at"),
        actor_id: row.get("actor_id"),
        actor_login: row.get("actor_login"),
        actor_roles: row.get("actor_roles"),
        impersonated_subject: row.get("impersonated_subject"),
        impersonated_customer: row.get("impersonated_customer"),
        customer_id: row.get("customer_id"),
        action: row.get("action"),
        resource_type: row.get("resource_type"),
        resource_id: row.get("resource_id"),
        result: row.get("result"),
        source_ip: row.get("source_ip"),
        session_id: row.get("session_id"),
        trace_id: row.get("trace_id"),
        details: row
            .get::<Option<serde_json::Value>, _>("details")
            .unwrap_or(serde_json::Value::Null),
    }
}

/// Postgres-backed store: every read opens a transaction, applies the RLS
/// scope, reads, records its own access row and only then commits.
pub struct PostgresAuditStore {
    pool: sqlx::PgPool,
}

impl PostgresAuditStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn apply_scope(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        access: &AuthorizedAuditAccess,
    ) -> Result<(), AdminAuditError> {
        let customer_scope = match &access.scope {
            AuditScope::Customer(customer_id) => customer_id.clone(),
            AuditScope::Platform | AuditScope::Own => String::new(),
        };
        sqlx::query(
            "SELECT set_config('app.current_deployment_id', $1, true), \
                    set_config('app.current_customer_id', $2, true), \
                    set_config('app.current_actor_id', $3, true), \
                    set_config('app.audit_scope', $4, true)",
        )
        .bind(&access.deployment_id)
        .bind(customer_scope)
        .bind(&access.actor_id)
        .bind(access.scope.as_guc())
        .execute(&mut **transaction)
        .await
        .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Ok(())
    }

    async fn record_access(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        access: &AuthorizedAuditAccess,
        action: &str,
        resource_id: Option<&str>,
        result: &str,
        details: serde_json::Value,
    ) -> Result<(), AdminAuditError> {
        let record = AuditEventRecord {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            actor_id: access.actor_id.clone(),
            actor_login: access.actor_login.clone(),
            actor_roles: access.actor_roles.clone(),
            impersonated_subject: access.impersonated_subject.clone(),
            impersonated_customer: access.impersonated_customer.clone(),
            customer_id: access.scope.written_customer_id().map(str::to_string),
            action: action.to_string(),
            resource_type: AUDIT_RESOURCE_TYPE.to_string(),
            resource_id: resource_id.map(str::to_string),
            result: result.to_string(),
            source_ip: access.source_ip.clone(),
            session_id: Some(access.session_id.clone()),
            trace_id: access.trace_id.clone(),
            details,
        };
        Self::insert_record(transaction, &access.deployment_id, &record).await
    }

    pub(crate) async fn insert_record(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        deployment_id: &str,
        record: &AuditEventRecord,
    ) -> Result<(), AdminAuditError> {
        sqlx::query(
            "INSERT INTO audit_events (deployment_id, customer_id, actor_id, actor_login, \
                    actor_roles, impersonated_subject, impersonated_customer, action, \
                    resource_type, resource_id, result, source_ip, session_id, trace_id, details) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(deployment_id)
        .bind(&record.customer_id)
        .bind(&record.actor_id)
        .bind(&record.actor_login)
        .bind(&record.actor_roles)
        .bind(&record.impersonated_subject)
        .bind(&record.impersonated_customer)
        .bind(&record.action)
        .bind(&record.resource_type)
        .bind(&record.resource_id)
        .bind(&record.result)
        .bind(&record.source_ip)
        .bind(&record.session_id)
        .bind(&record.trace_id)
        .bind(sqlx::types::Json(record.details.clone()))
        .execute(&mut **transaction)
        .await
        .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Ok(())
    }
}

#[async_trait]
impl AuditStore for PostgresAuditStore {
    async fn list(
        &self,
        access: &AuthorizedAuditAccess,
        filters: &ValidatedAuditFilters,
    ) -> Result<AuditEventPage, AdminAuditError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Self::apply_scope(&mut transaction, access).await?;

        let mut builder = ScopedSelect::new(LIST_COLUMNS, access);
        push_common_filters(&mut builder, filters);
        if let Some((cursor_at, cursor_id)) = filters.cursor {
            builder.push_cursor(cursor_at, cursor_id);
        }
        builder.push_literal(" ORDER BY created_at DESC, id DESC ");
        builder.push("LIMIT ${}", Bind::Int(filters.limit + 1));

        let rows = prepared(&builder)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;

        let has_more = rows.len() as i64 > filters.limit;
        let selected_rows: Vec<_> = rows.into_iter().take(filters.limit as usize).collect();
        let selected: Vec<AuditEventRecord> = selected_rows.iter().map(record_from_row).collect();
        let next_cursor = if has_more {
            selected
                .last()
                .map(|record| encode_cursor(&record.created_at, &record.id))
        } else {
            None
        };

        Self::record_access(
            &mut transaction,
            access,
            ACCESS_LIST_ACTION,
            None,
            "success",
            serde_json::json!({
                "scope": access.scope.as_guc(),
                "row_count": selected.len(),
                "filters": filters_summary(filters),
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;

        Ok(AuditEventPage {
            events: selected.iter().map(AuditEventRecord::list_item).collect(),
            next_cursor,
        })
    }

    async fn detail(
        &self,
        access: &AuthorizedAuditAccess,
        event_id: Uuid,
    ) -> Result<Option<AuditEventDetail>, AdminAuditError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Self::apply_scope(&mut transaction, access).await?;

        let mut builder = ScopedSelect::new(LIST_COLUMNS, access);
        builder.push(" AND id = ${}", Bind::Id(event_id));
        builder.push_literal(" LIMIT 1");
        let row = prepared(&builder)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;

        match row {
            Some(row) => {
                let record = record_from_row(&row);
                Self::record_access(
                    &mut transaction,
                    access,
                    ACCESS_DETAIL_ACTION,
                    Some(&event_id.to_string()),
                    "success",
                    serde_json::json!({ "scope": access.scope.as_guc() }),
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| AdminAuditError::PersistenceFailed)?;
                Ok(Some(record.detail()))
            },
            None => {
                Self::record_access(
                    &mut transaction,
                    access,
                    ACCESS_DENIED_ACTION,
                    Some(&event_id.to_string()),
                    "denied",
                    serde_json::json!({
                        "scope": access.scope.as_guc(),
                        "reason": "audit event not in scope",
                    }),
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| AdminAuditError::PersistenceFailed)?;
                Ok(None)
            },
        }
    }

    async fn export(
        &self,
        access: &AuthorizedAuditAccess,
        filters: &ValidatedAuditFilters,
    ) -> Result<Vec<AuditEventRecord>, AdminAuditError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Self::apply_scope(&mut transaction, access).await?;

        let mut builder = ScopedSelect::new(LIST_COLUMNS, access);
        push_common_filters(&mut builder, filters);
        builder.push_literal(" ORDER BY created_at DESC, id DESC ");
        builder.push("LIMIT ${}", Bind::Int(MAX_EXPORT_ROWS));
        let rows = prepared(&builder)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        let truncated = rows.len() as i64 == MAX_EXPORT_ROWS;
        let selected: Vec<AuditEventRecord> = rows.iter().map(record_from_row).collect();

        // High-risk action: the export fails closed if its own audit record
        // cannot commit (docs/17 Transactional correctness).
        Self::record_access(
            &mut transaction,
            access,
            EXPORT_ACTION,
            None,
            "success",
            serde_json::json!({
                "scope": access.scope.as_guc(),
                "format": "csv",
                "row_count": selected.len(),
                "truncated": truncated,
                "filters": filters_summary(filters),
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Ok(selected)
    }

    async fn checkpoint_status(
        &self,
        access: &AuthorizedAuditAccess,
    ) -> Result<AuditCheckpointStatus, AdminAuditError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Self::apply_scope(&mut transaction, access).await?;

        let row = sqlx::query(
            "SELECT checkpoint_sequence, covers_events_through, event_count, root_hash, \
                    signer_key_id, archive_uri, created_at \
             FROM audit_checkpoints \
             WHERE deployment_id = $1 \
             ORDER BY checkpoint_sequence DESC \
             LIMIT 1",
        )
        .bind(&access.deployment_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminAuditError::PersistenceFailed)?;

        let status = match row {
            Some(row) => {
                let covers_events_through: DateTime<Utc> = row.get("covers_events_through");
                let last_checkpoint_at: DateTime<Utc> = row.get("created_at");
                let newest_event_at: Option<DateTime<Utc>> = sqlx::query_scalar(
                    "SELECT max(created_at) FROM audit_events WHERE deployment_id = $1",
                )
                .bind(&access.deployment_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| AdminAuditError::PersistenceFailed)?;
                let state = if newest_event_at
                    .map(|created_at| created_at <= covers_events_through)
                    .unwrap_or(true)
                {
                    AuditCheckpointState::Current
                } else {
                    AuditCheckpointState::Stale
                };
                AuditCheckpointStatus {
                    state,
                    last_checkpoint_at: Some(last_checkpoint_at),
                    covers_events_through: Some(covers_events_through),
                    checkpoint_sequence: Some(row.get("checkpoint_sequence")),
                    event_count: Some(row.get("event_count")),
                    root_hash: Some(row.get("root_hash")),
                    signer_key_id: Some(row.get("signer_key_id")),
                    archive_uri: row.get("archive_uri"),
                }
            },
            None => AuditCheckpointStatus {
                state: AuditCheckpointState::NotConfigured,
                last_checkpoint_at: None,
                covers_events_through: None,
                checkpoint_sequence: None,
                event_count: None,
                root_hash: None,
                signer_key_id: None,
                archive_uri: None,
            },
        };

        Self::record_access(
            &mut transaction,
            access,
            ACCESS_DETAIL_ACTION,
            Some("checkpoint-status"),
            "success",
            serde_json::json!({
                "scope": access.scope.as_guc(),
                "status": status.state,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Ok(status)
    }

    async fn record_denied(
        &self,
        access: &AuthorizedAuditAccess,
        action: &str,
        resource_id: Option<&str>,
        reason: &str,
    ) -> Result<(), AdminAuditError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Self::apply_scope(&mut transaction, access).await?;
        Self::record_access(
            &mut transaction,
            access,
            action,
            resource_id,
            "denied",
            serde_json::json!({
                "scope": access.scope.as_guc(),
                "reason": reason,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Ok(())
    }

    async fn record_event(
        &self,
        deployment_id: &str,
        record: AuditEventRecord,
    ) -> Result<(), AdminAuditError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        // Attribute the row before writing: tenant rows require tenant scope
        // matching the record's customer, platform rows require platform scope.
        let (customer_scope, scope_guc) = match &record.customer_id {
            Some(customer_id) => (
                customer_id.clone(),
                AuditScope::Customer(customer_id.clone()).as_guc(),
            ),
            None => (String::new(), AuditScope::Platform.as_guc()),
        };
        sqlx::query(
            "SELECT set_config('app.current_deployment_id', $1, true), \
                    set_config('app.current_customer_id', $2, true), \
                    set_config('app.current_actor_id', $3, true), \
                    set_config('app.audit_scope', $4, true)",
        )
        .bind(deployment_id)
        .bind(customer_scope)
        .bind(&record.actor_id)
        .bind(scope_guc)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Self::insert_record(&mut transaction, deployment_id, &record).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminAuditError::PersistenceFailed)?;
        Ok(())
    }
}

struct AuditStateInner {
    store: Arc<dyn AuditStore>,
    deployment_id: DeploymentId,
    export_limiter: std::sync::Mutex<TokenBucket>,
}

/// Shared router state: the audit store plus the dedicated high-risk export
/// limiter.
#[derive(Clone)]
pub struct AdminAuditState(Arc<AuditStateInner>);

impl AdminAuditState {
    pub fn new(store: Arc<dyn AuditStore>, deployment_id: DeploymentId) -> Self {
        Self::with_rate_limit(store, deployment_id, HighRiskLimits::audit_export())
    }

    pub fn with_rate_limit(
        store: Arc<dyn AuditStore>,
        deployment_id: DeploymentId,
        config: RateLimitConfig,
    ) -> Self {
        Self(Arc::new(AuditStateInner {
            store,
            deployment_id,
            export_limiter: std::sync::Mutex::new(TokenBucket::new(&config)),
        }))
    }

    pub fn postgres(pool: sqlx::PgPool, deployment_id: DeploymentId) -> Self {
        Self::new(Arc::new(PostgresAuditStore::new(pool)), deployment_id)
    }
}

pub fn admin_audit_router(state: AdminAuditState) -> Router {
    Router::new()
        .route("/api/v1/audit/events", get(list_events))
        .route("/api/v1/audit/checkpoint-status", get(checkpoint_status))
        .route("/api/v1/audit/events/export", post(export_events))
        .route("/api/v1/audit/events/:audit_event_id", get(get_event))
        .with_state(state)
}

/// Advisory source IP: only the value set by the trusted local reverse proxy
/// is used; it is audit metadata, never an authorization input.
pub(crate) fn source_ip_from(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .map(str::to_string)
}

async fn list_events(
    axum::extract::State(state): axum::extract::State<AdminAuditState>,
    filters: Result<Query<AuditQueryFilters>, QueryRejection>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let Ok(Query(filters)) = filters else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        );
    };
    let access = match access_for(&state, &context, filters.customer_id.as_deref(), &headers) {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    let filters = match filters.validate() {
        Ok(filters) => filters,
        Err(error) => return error_response(error),
    };
    match state.0.store.list(&access, &filters).await {
        Ok(page) => (StatusCode::OK, Json(ApiEnvelope { data: page })).into_response(),
        Err(error) => error_response(error),
    }
}

async fn get_event(
    axum::extract::State(state): axum::extract::State<AdminAuditState>,
    Path(audit_event_id): Path<String>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let Ok(event_id) = Uuid::parse_str(&audit_event_id) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        );
    };
    let access = match access_for(&state, &context, None, &headers) {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    match state.0.store.detail(&access, event_id).await {
        Ok(Some(detail)) => (StatusCode::OK, Json(ApiEnvelope { data: detail })).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Audit event was not found",
        ),
        Err(error) => error_response(error),
    }
}

async fn checkpoint_status(
    axum::extract::State(state): axum::extract::State<AdminAuditState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let access = match access_for(&state, &context, None, &headers) {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    // The checkpoint seals the whole append-only ledger of the installation and
    // carries its root hash, signer key id and archive location. A customer
    // console has no use for any of that, so the readout is platform-only even
    // though `audit:view` is what reaches this route.
    if !access.platform_placement {
        let _ = state
            .0
            .store
            .record_denied(
                &access,
                ACCESS_DENIED_ACTION,
                None,
                "checkpoint is a platform readout",
            )
            .await;
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    match state.0.store.checkpoint_status(&access).await {
        Ok(status) => (StatusCode::OK, Json(ApiEnvelope { data: status })).into_response(),
        Err(error) => error_response(error),
    }
}

async fn export_events(
    axum::extract::State(state): axum::extract::State<AdminAuditState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    body: Result<Json<AuditQueryFilters>, JsonRejection>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let Ok(Json(filters)) = body else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        );
    };
    let access = match access_for(&state, &context, filters.customer_id.as_deref(), &headers) {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    let filters = match filters.validate() {
        Ok(filters) => filters,
        Err(error) => return error_response(error),
    };
    if !context
        .permissions
        .iter()
        .any(|permission| permission == AUDIT_EXPORT_PERMISSION)
    {
        let _ = state
            .0
            .store
            .record_denied(&access, EXPORT_ACTION, None, "export permission missing")
            .await;
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }
    if !context.has_step_up() {
        let _ = state
            .0
            .store
            .record_denied(&access, EXPORT_ACTION, None, "step-up assurance missing")
            .await;
        return api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        );
    }
    // Rate limit before any further write so a limited caller cannot amplify
    // its own audit traffic (docs/security/22 high-risk action limits).
    let allowed = state
        .0
        .export_limiter
        .lock()
        .map(|mut bucket| bucket.try_consume())
        .unwrap_or(false);
    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "60")],
            Json(ApiErrorBody {
                code: "RATE_LIMITED",
                message: "Too many export requests",
            }),
        )
            .into_response();
    }

    match state.0.store.export(&access, &filters).await {
        Ok(records) => {
            let truncated = records.len() as i64 == MAX_EXPORT_ROWS;
            let csv = render_csv(&records);
            let mut response = (
                StatusCode::OK,
                [
                    (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        "attachment; filename=\"nullapart-audit-export.csv\"",
                    ),
                ],
                csv,
            )
                .into_response();
            if truncated {
                response.headers_mut().insert(
                    axum::http::HeaderName::from_static("x-nullapart-export-truncated"),
                    axum::http::HeaderValue::from_static("true"),
                );
            }
            response
        },
        Err(error) => error_response(error),
    }
}

fn access_for(
    state: &AdminAuditState,
    context: &TenantContext,
    requested_customer: Option<&str>,
    headers: &HeaderMap,
) -> Result<AuthorizedAuditAccess, AdminAuditError> {
    AuthorizedAuditAccess::from_context(
        context,
        &state.0.deployment_id,
        requested_customer,
        source_ip_from(headers),
    )
}

#[derive(Debug, Serialize)]
struct ApiEnvelope<T> {
    data: T,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
}

fn error_response(error: AdminAuditError) -> Response {
    match error {
        AdminAuditError::PermissionDenied
        | AdminAuditError::CustomerInactive
        | AdminAuditError::DeploymentMismatch => {
            api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required")
        },
        AdminAuditError::StepUpRequired => api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        ),
        AdminAuditError::NotFound => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Audit event was not found",
        ),
        AdminAuditError::InvalidRequest => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        ),
        AdminAuditError::RateLimited => api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            "Too many requests",
        ),
        AdminAuditError::PersistenceFailed => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UNAVAILABLE",
            "Service is unavailable",
        ),
    }
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

/// Renders export rows as CSV. Cells are quoted, control characters are
/// removed and spreadsheet-formula prefixes are neutralised; the free-form
/// `details` column is deliberately never exported.
pub fn render_csv(records: &[AuditEventRecord]) -> String {
    let mut output = String::from(CSV_HEADER);
    output.push('\n');
    for record in records {
        let roles = record.actor_roles.join(";");
        let row = [
            record.created_at.to_rfc3339(),
            record.actor_login.clone(),
            roles,
            record.impersonated_subject.clone().unwrap_or_default(),
            record.impersonated_customer.clone().unwrap_or_default(),
            record.action.clone(),
            record.resource_type.clone(),
            record.resource_id.clone().unwrap_or_default(),
            record.result.clone(),
            record.source_ip.clone().unwrap_or_default(),
            record.reason().unwrap_or_default(),
            record.trace_id.clone(),
        ];
        let rendered: Vec<String> = row.iter().map(|cell| csv_cell(cell)).collect();
        output.push_str(&rendered.join(","));
        output.push('\n');
    }
    output
}

fn csv_cell(value: &str) -> String {
    let mut sanitized = value.replace(['\r', '\n'], " ");
    if sanitized.starts_with(['=', '+', '-', '@']) {
        sanitized.insert(0, '\'');
    }
    format!("\"{}\"", sanitized.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use nullapart_mail_contracts::ActorId;
    use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId, TenantContext};
    use tower::ServiceExt;

    use super::*;

    const TEST_DEPLOYMENT: &str = "LOCAL-TEST";

    fn context(roles: &[&str], permissions: &[&str], step_up: bool) -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId::new(TEST_DEPLOYMENT),
            region: RegionId::new("local"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "admin@example.test".to_string(),
                roles: roles.iter().map(|role| role.to_string()).collect(),
                authentication_assurance: if step_up {
                    AuthenticationAssurance::StepUp
                } else {
                    AuthenticationAssurance::Standard
                },
            },
            impersonation: None,
            customer_id: nullapart_mail_contracts::CustomerId::new("customer-a"),
            customer_internal_key: 1,
            customer_display_name: "Customer A".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions: permissions
                .iter()
                .map(|permission| permission.to_string())
                .collect(),
            config_revision: 1,
            trace_id: "trace".to_string(),
            correlation_id: "correlation".to_string(),
            session_id: "session".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn record(customer_id: Option<&str>, action: &str, actor: &str) -> AuditEventRecord {
        AuditEventRecord {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            actor_id: actor.to_string(),
            actor_login: actor.to_string(),
            actor_roles: vec!["customer_admin".to_string()],
            impersonated_subject: None,
            impersonated_customer: None,
            customer_id: customer_id.map(str::to_string),
            action: action.to_string(),
            resource_type: "quarantine".to_string(),
            resource_id: Some("event-1".to_string()),
            result: "success".to_string(),
            source_ip: None,
            session_id: Some("session".to_string()),
            trace_id: "trace".to_string(),
            details: serde_json::json!({"release_reason": "false positive"}),
        }
    }

    fn state_for(store: Arc<InMemoryAuditStore>) -> AdminAuditState {
        AdminAuditState::with_rate_limit(
            store,
            DeploymentId::new(TEST_DEPLOYMENT),
            RateLimitConfig {
                max_tokens: 3,
                refill_rate_per_sec: 0.001,
                ..HighRiskLimits::audit_export()
            },
        )
    }

    fn state_with(store: InMemoryAuditStore) -> AdminAuditState {
        state_for(Arc::new(store))
    }

    /// One own-customer row and one foreign row with known ids.
    fn seed_pair() -> (Arc<InMemoryAuditStore>, Uuid, Uuid) {
        let store = Arc::new(InMemoryAuditStore::new());
        let own = record(Some("customer-a"), "release", "admin@example.test");
        let foreign = record(Some("customer-b"), "release", "other@example.test");
        let own_id = own.id;
        let foreign_id = foreign.id;
        store.insert(own);
        store.insert(foreign);
        (store, own_id, foreign_id)
    }

    #[test]
    fn customer_admin_scope_cannot_request_another_customer() {
        let context = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], false);
        let denied = AuthorizedAuditAccess::from_context(
            &context,
            &DeploymentId::new(TEST_DEPLOYMENT),
            Some("customer-b"),
            None,
        );
        assert_eq!(denied, Err(AdminAuditError::PermissionDenied));

        let allowed = AuthorizedAuditAccess::from_context(
            &context,
            &DeploymentId::new(TEST_DEPLOYMENT),
            Some("customer-a"),
            None,
        )
        .expect("own customer is a valid narrowing");
        assert_eq!(
            allowed.scope,
            AuditScope::Customer("customer-a".to_string())
        );
    }

    #[test]
    fn support_defaults_to_own_activity_and_needs_platform_permission_to_widen() {
        let own_context = context(&["support"], &[AUDIT_VIEW_PERMISSION], false);
        let own = AuthorizedAuditAccess::from_context(
            &own_context,
            &DeploymentId::new(TEST_DEPLOYMENT),
            None,
            None,
        )
        .expect("own activity read");
        assert_eq!(own.scope, AuditScope::Own);

        let cross_context = context(&["support"], &[AUDIT_VIEW_PERMISSION], false);
        let denied = AuthorizedAuditAccess::from_context(
            &cross_context,
            &DeploymentId::new(TEST_DEPLOYMENT),
            Some("customer-a"),
            None,
        );
        assert_eq!(denied, Err(AdminAuditError::PermissionDenied));

        let granted = context(
            &["support"],
            &[AUDIT_VIEW_PERMISSION, AUDIT_CROSS_CUSTOMER_PERMISSION],
            false,
        );
        let scoped = AuthorizedAuditAccess::from_context(
            &granted,
            &DeploymentId::new(TEST_DEPLOYMENT),
            Some("customer-a"),
            None,
        )
        .expect("explicit customer scope with platform permission");
        assert_eq!(scoped.scope, AuditScope::Customer("customer-a".to_string()));
    }

    #[test]
    fn impersonation_narrows_the_scope_to_the_impersonated_customer() {
        use nullapart_policy::ImpersonationContext;

        let mut acting = context(&["system_admin"], &[AUDIT_VIEW_PERMISSION], true);
        acting.impersonation = Some(ImpersonationContext {
            real_actor: acting.actor.clone(),
            impersonated_subject: Some("subject@example.test".to_string()),
            impersonated_customer: nullapart_mail_contracts::CustomerId::new("customer-b"),
            started_at: Utc::now(),
            reason: "investigating a customer report".to_string(),
            session_id: "session".to_string(),
        });
        let access = AuthorizedAuditAccess::from_context(
            &acting,
            &DeploymentId::new(TEST_DEPLOYMENT),
            None,
            None,
        )
        .expect("an acting-as session keeps audit view");
        assert_eq!(access.scope, AuditScope::Customer("customer-b".to_string()));
        assert_eq!(
            access.impersonated_subject.as_deref(),
            Some("subject@example.test")
        );
        assert_eq!(access.impersonated_customer.as_deref(), Some("customer-b"));

        // The platform scope disappears: only the impersonated tenant is
        // reachable, and requesting another customer is denied outright.
        assert_eq!(
            AuthorizedAuditAccess::from_context(
                &acting,
                &DeploymentId::new(TEST_DEPLOYMENT),
                Some("customer-a"),
                None,
            ),
            Err(AdminAuditError::PermissionDenied)
        );
        let allowed = AuthorizedAuditAccess::from_context(
            &acting,
            &DeploymentId::new(TEST_DEPLOYMENT),
            Some("customer-b"),
            None,
        )
        .expect("the impersonated customer may be requested explicitly");
        assert_eq!(
            allowed.scope,
            AuditScope::Customer("customer-b".to_string())
        );
    }

    #[test]
    fn missing_view_permission_and_inactive_customer_are_denied() {
        let no_permission = context(&["customer_admin"], &[], false);
        assert_eq!(
            AuthorizedAuditAccess::from_context(
                &no_permission,
                &DeploymentId::new(TEST_DEPLOYMENT),
                None,
                None
            ),
            Err(AdminAuditError::PermissionDenied)
        );

        let mut inactive = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], false);
        inactive.customer_lifecycle = CustomerLifecycle::Suspended;
        assert_eq!(
            AuthorizedAuditAccess::from_context(
                &inactive,
                &DeploymentId::new(TEST_DEPLOYMENT),
                None,
                None
            ),
            Err(AdminAuditError::CustomerInactive)
        );

        let mut foreign = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], false);
        foreign.deployment_id = DeploymentId::new("OTHER-DEPLOYMENT");
        assert_eq!(
            AuthorizedAuditAccess::from_context(
                &foreign,
                &DeploymentId::new(TEST_DEPLOYMENT),
                None,
                None
            ),
            Err(AdminAuditError::DeploymentMismatch)
        );
    }

    #[tokio::test]
    async fn list_requires_context_and_permission() {
        let app = admin_audit_router(state_with(InMemoryAuditStore::new()));
        let unauthenticated = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let no_permission = context(&["customer_admin"], &[], false);
        let forbidden = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/events")
                    .extension(no_permission)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let permitted = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], false);
        let allowed = app
            .oneshot(
                Request::get("/api/v1/audit/events")
                    .extension(permitted)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn checkpoint_status_requires_context_and_reports_configuration_state() {
        let store = Arc::new(InMemoryAuditStore::new());
        let app = admin_audit_router(state_for(Arc::clone(&store)));
        let unauthenticated = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/checkpoint-status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let permitted = context(&["system_admin"], &[AUDIT_VIEW_PERMISSION], false);
        let response = app
            .oneshot(
                Request::get("/api/v1/audit/checkpoint-status")
                    .extension(permitted)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rendered = String::from_utf8(body.to_vec()).expect("utf-8 response");
        assert!(rendered.contains("\"state\":\"not_configured\""));
        assert!(store
            .records()
            .iter()
            .any(|record| record.resource_id.as_deref() == Some("checkpoint-status")));
    }

    #[tokio::test]
    async fn checkpoint_status_is_a_platform_readout_for_a_tenant() {
        let store = Arc::new(InMemoryAuditStore::new());
        let app = admin_audit_router(state_for(Arc::clone(&store)));

        // A Customer Admin holds audit:view, which is what reaches this route, so
        // the ledger's seal material has to be withheld by placement rather than
        // by permission.
        let tenant = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], false);
        let response = app
            .oneshot(
                Request::get("/api/v1/audit/checkpoint-status")
                    .extension(tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"code":"FORBIDDEN","message":"Permission is required"}"#
        );
        assert!(store
            .records()
            .iter()
            .any(|record| record.result == "denied"
                && record.actor_roles.contains(&"customer_admin".to_string())));
    }

    #[tokio::test]
    async fn customer_scope_excludes_other_tenants_and_platform_rows() {
        let (store, _, _) = seed_pair();
        let app = admin_audit_router(state_for(store));
        let customer_a = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], false);
        let response = app
            .oneshot(
                Request::get("/api/v1/audit/events")
                    .extension(customer_a)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rendered = String::from_utf8(body.to_vec()).expect("utf-8 response");
        assert!(rendered.contains("customer-a"));
        assert!(!rendered.contains("customer-b"), "leaked: {rendered}");
        assert!(
            !rendered.contains("other@example.test"),
            "leaked: {rendered}"
        );
    }

    #[tokio::test]
    async fn system_admin_reads_every_customer_in_the_deployment() {
        let (store, _, _) = seed_pair();
        let app = admin_audit_router(state_for(store));
        let system = context(&["system_admin"], &[AUDIT_VIEW_PERMISSION], false);
        let response = app
            .oneshot(
                Request::get("/api/v1/audit/events")
                    .extension(system)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rendered = String::from_utf8(body.to_vec()).expect("utf-8 response");
        assert!(rendered.contains("customer-a"));
        assert!(rendered.contains("customer-b"));
    }

    #[tokio::test]
    async fn detail_is_scoped_and_audits_cross_tenant_probes() {
        let (store, own_id, foreign_id) = seed_pair();
        let app = admin_audit_router(state_for(store.clone()));
        let context_a = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], false);

        let denied = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/audit/events/{foreign_id}"))
                    .extension(context_a.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);

        // The cross-tenant probe itself must be recorded as denied access,
        // attributed to the probing actor's own customer.
        let records = store.records();
        let probe = records
            .iter()
            .find(|record| record.action == "audit_access_denied")
            .expect("denied access must be audited");
        assert_eq!(probe.result, "denied");
        assert_eq!(
            probe.resource_id.as_deref(),
            Some(foreign_id.to_string().as_str())
        );
        assert_eq!(probe.actor_login, "admin@example.test");
        assert_eq!(probe.customer_id.as_deref(), Some("customer-a"));

        let allowed = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/audit/events/{own_id}"))
                    .extension(context_a.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);

        let invalid = app
            .oneshot(
                Request::get("/api/v1/audit/events/not-a-uuid")
                    .extension(context_a)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn detail_returns_redacted_key_value_pairs_not_raw_json() {
        let store = InMemoryAuditStore::new();
        let mut seeded = record(Some("customer-a"), "release", "admin@example.test");
        seeded.details = serde_json::json!({
            "release_reason": "false positive",
            "session_token": "super-secret-value",
            "nested": {"password": "hunter2", "count": 2},
        });
        let event_id = seeded.id;
        store.insert(seeded);
        let app = admin_audit_router(state_with(store));

        let detail = app
            .oneshot(
                Request::get(format!("/api/v1/audit/events/{event_id}"))
                    .extension(context(
                        &["customer_admin"],
                        &[AUDIT_VIEW_PERMISSION],
                        false,
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(detail.into_body(), usize::MAX)
            .await
            .unwrap();
        let rendered = String::from_utf8(body.to_vec()).expect("utf-8 response");
        assert!(rendered.contains("[redacted]"));
        assert!(
            !rendered.contains("super-secret-value"),
            "leaked: {rendered}"
        );
        assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
        assert!(rendered.contains("\"key\":\"release_reason\""));
        assert!(rendered.contains("false positive"));
    }

    #[tokio::test]
    async fn pagination_is_keyset_scoped_and_rejects_invalid_cursor() {
        let store = InMemoryAuditStore::new();
        let mut previous = None;
        let mut ids = Vec::new();
        for offset in 0..3 {
            let mut entry = record(Some("customer-a"), "release", "admin@example.test");
            entry.created_at = Utc::now() - chrono::Duration::seconds(offset);
            ids.push(entry.id);
            previous = Some(entry.created_at);
            store.insert(entry);
        }
        let _ = previous;
        let app = admin_audit_router(state_with(store));

        let read_page = |cursor: Option<String>| {
            let app = app.clone();
            let context = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], false);
            async move {
                let uri = match cursor {
                    Some(cursor) => format!("/api/v1/audit/events?limit=1&cursor={cursor}"),
                    None => "/api/v1/audit/events?limit=1".to_string(),
                };
                let response = app
                    .oneshot(
                        Request::get(uri)
                            .extension(context)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                (
                    status,
                    String::from_utf8(body.to_vec()).expect("utf-8 response"),
                )
            }
        };

        let (status, first) = read_page(None).await;
        assert_eq!(status, StatusCode::OK);
        let first_id = first
            .split("\"id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("event id");
        let first_cursor = first
            .split("\"next_cursor\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("cursor");

        let (status, second) = read_page(Some(first_cursor.to_string())).await;
        assert_eq!(status, StatusCode::OK);
        let second_id = second
            .split("\"id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("event id");
        assert_ne!(first_id, second_id);
        assert!(!second.contains(first_id), "cursor page repeated an event");

        let (status, _) = read_page(Some("not-a-cursor".to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn export_requires_step_up_permission_and_is_rate_limited() {
        let store = InMemoryAuditStore::new();
        store.insert(record(Some("customer-a"), "release", "admin@example.test"));
        let app = admin_audit_router(state_with(store));

        let no_export_permission = context(&["customer_admin"], &[AUDIT_VIEW_PERMISSION], true);
        let forbidden = app
            .clone()
            .oneshot(
                Request::post("/api/v1/audit/events/export")
                    .header("content-type", "application/json")
                    .extension(no_export_permission)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let no_step_up = context(
            &["customer_admin"],
            &[AUDIT_VIEW_PERMISSION, AUDIT_EXPORT_PERMISSION],
            false,
        );
        let step_up_required = app
            .clone()
            .oneshot(
                Request::post("/api/v1/audit/events/export")
                    .header("content-type", "application/json")
                    .extension(no_step_up)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(step_up_required.status(), StatusCode::FORBIDDEN);

        let allowed_context = || {
            context(
                &["customer_admin"],
                &[AUDIT_VIEW_PERMISSION, AUDIT_EXPORT_PERMISSION],
                true,
            )
        };
        for attempt in 0..3 {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/api/v1/audit/events/export")
                        .header("content-type", "application/json")
                        .extension(allowed_context())
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "attempt {attempt}");
        }
        let limited = app
            .oneshot(
                Request::post("/api/v1/audit/events/export")
                    .header("content-type", "application/json")
                    .extension(allowed_context())
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn export_writes_audited_row_and_renders_safe_csv() {
        let store = InMemoryAuditStore::new();
        store.insert(record(Some("customer-a"), "release", "admin@example.test"));
        let app = admin_audit_router(state_with(store));
        let context = context(
            &["customer_admin"],
            &[AUDIT_VIEW_PERMISSION, AUDIT_EXPORT_PERMISSION],
            true,
        );
        let response = app
            .oneshot(
                Request::post("/api/v1/audit/events/export")
                    .header("content-type", "application/json")
                    .extension(context)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("content type")
            .to_str()
            .expect("utf-8")
            .to_string();
        assert!(content_type.starts_with("text/csv"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rendered = String::from_utf8(body.to_vec()).expect("utf-8 response");
        assert!(rendered.starts_with(CSV_HEADER));
        assert!(rendered.contains("\"false positive\""));
        assert!(
            !rendered.contains("release_reason"),
            "details leaked: {rendered}"
        );
        assert!(!rendered.contains('{'), "raw json leaked: {rendered}");
    }

    #[test]
    fn csv_neutralises_formula_prefixes_and_quotes() {
        let record = AuditEventRecord {
            id: Uuid::nil(),
            created_at: Utc::now(),
            actor_id: "actor".to_string(),
            actor_login: "actor\"@example.test".to_string(),
            actor_roles: vec![],
            impersonated_subject: Some("=cmd()".to_string()),
            impersonated_customer: None,
            customer_id: None,
            action: "release".to_string(),
            resource_type: "quarantine".to_string(),
            resource_id: None,
            result: "success".to_string(),
            source_ip: Some("line\nbreak".to_string()),
            session_id: None,
            trace_id: "trace".to_string(),
            details: serde_json::Value::Null,
        };
        let csv = render_csv(&[record]);
        assert!(csv.contains("\"actor\"\"@example.test\""));
        assert!(csv.contains("\"'=cmd()\""));
        assert!(csv.contains("\"line break\""));
    }

    #[test]
    fn filters_reject_invalid_input() {
        let invalid_result = AuditQueryFilters {
            result: Some("unknown".to_string()),
            ..Default::default()
        };
        assert_eq!(
            invalid_result.validate().err(),
            Some(AdminAuditError::InvalidRequest)
        );

        let invalid_limit = AuditQueryFilters {
            limit: Some(MAX_PAGE_SIZE + 1),
            ..Default::default()
        };
        assert_eq!(
            invalid_limit.validate().err(),
            Some(AdminAuditError::InvalidRequest)
        );

        let invalid_cursor = AuditQueryFilters {
            cursor: Some("not-a-cursor".to_string()),
            ..Default::default()
        };
        assert_eq!(
            invalid_cursor.validate().err(),
            Some(AdminAuditError::InvalidRequest)
        );

        let invalid_range = AuditQueryFilters {
            from: Some(Utc::now().to_rfc3339()),
            to: Some((Utc::now() - chrono::Duration::hours(1)).to_rfc3339()),
            ..Default::default()
        };
        assert_eq!(
            invalid_range.validate().err(),
            Some(AdminAuditError::InvalidRequest)
        );
    }

    #[test]
    fn cursor_round_trips() {
        let created_at = Utc::now();
        let id = Uuid::new_v4();
        let encoded = encode_cursor(&created_at, &id);
        let (decoded_at, decoded_id) = parse_cursor(&encoded).expect("valid cursor");
        assert_eq!(decoded_at, created_at);
        assert_eq!(decoded_id, id);
    }
}

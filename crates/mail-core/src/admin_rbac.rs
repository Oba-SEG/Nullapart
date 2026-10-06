//! Server-side administrative sessions and RBAC foundation (Phase 3).
//!
//! Nullapart owns admin users, role membership and opaque sessions here
//! (docs/03-IDENTITY-RBAC-IMPERSONATION.md). The external identity provider,
//! when the owner records that decision, supplies authentication only; it does
//! not replace these tables.
//!
//! Trust model (local/dev boundary, see docs/phases/PHASE-3-CONTROL-PLANE.md):
//!   * The reverse proxy authenticates the browser (basic auth) and forwards
//!     the authenticated identity in `x-nullapart-local-user`. Mail Core
//!     additionally requires a private workload bearer token the browser
//!     never sees, so only the proxy reaches these routes.
//!   * `POST /api/v1/auth/login` exchanges that boundary identity for an
//!     opaque server-side session: a random 64-hex token in an HttpOnly,
//!     SameSite=Strict cookie; only its SHA-256 hash is persisted.
//!   * When the server-authoritative identity mode is OIDC instead
//!     (`NULLAPART_IDENTITY_PROVIDER=oidc`), the same endpoints start and
//!     complete an authorization-code flow against the configured provider
//!     (docs/03-IDENTITY-RBAC-IMPERSONATION.md): GET login redirects to the
//!     IdP, the callback claims a one-time hashed `state`, fully verifies
//!     the ID token (PKCE, nonce, signature, issuer, audience, expiry) and
//!     maps the subject through `auth_subject`/link-by-login/bootstrap
//!     before establishing the very same session. An IdP subject is
//!     identity mapping only, never authorization.
//!   * Every mutating request with an active session must echo the session's
//!     CSRF token; role changes additionally require the `admin:users:manage`
//!     permission, a fresh step-up, and the shared high-risk rate limit, and
//!     they audit success and denial in the same transaction as the change.
//!     A grantor can never assign or revoke a role above their own level.
//!   * Customer entry / impersonation (`admin:impersonate`, System/Support)
//!     switches the session's customer scope to an active customer for a
//!     reasoned, step-up-gated, rate-limited interval. The actor's roles and
//!     permissions stay exactly their own (never intersected or reduced);
//!     start/end and every action in between audit the real actor and the
//!     entered customer (docs/03-IDENTITY-RBAC-IMPERSONATION.md).
//!   * Session/RBAC persistence applies deployment row-level security as
//!     defense in depth; every query also filters `deployment_id` directly.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use nullapart_mail_contracts::{
    rate_limit::{HighRiskLimits, RateLimitConfig, TokenBucket},
    transaction::{CustomerId, DeploymentId},
    ActorId,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, ImpersonationContext, RegionId,
    TenantContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row};
use subtle::ConstantTimeEq;
use tracing::error;
use uuid::Uuid;

use crate::admin_audit::{
    source_ip_from, AuditEventRecord, AuditStore, PostgresAuditStore,
    AUDIT_CROSS_CUSTOMER_PERMISSION, AUDIT_EXPORT_PERMISSION, AUDIT_VIEW_PERMISSION,
};
use crate::oidc::{
    self, IdentityConfig, IdentityProviderKind, OidcConfig, OidcError, OIDC_CALLBACK_PATH,
    OIDC_REAUTH_PATH,
};
use crate::operations_api::{OPERATIONS_MANAGE_PERMISSION, OPERATIONS_VIEW_PERMISSION};
use crate::quarantine::{QUARANTINE_RELEASE_PERMISSION, QUARANTINE_VIEW_PERMISSION};
use crate::scanner_operations::SCANNER_OPERATIONS_VIEW_PERMISSION;

/// Cookie holding the opaque session token (HttpOnly; never readable by JS).
const SESSION_COOKIE: &str = "nullapart_session";
/// Double-submit OIDC flow cookie binding an authorization code/state pair
/// to the browser that started the flow. Scoped to the callback path and
/// `SameSite=Lax` so it is still sent on the top-level cross-site redirect
/// back from the identity provider.
const OIDC_FLOW_COOKIE: &str = "nullapart_oidc_flow";
/// Header the reverse proxy sets with the basic-authenticated identity.
const IDENTITY_HEADER: &str = "x-nullapart-local-user";
/// Per-session CSRF token echoed by mutating requests.
const CSRF_HEADER: &str = "x-csrf-token";
const LOGIN_PATH: &str = "/api/v1/auth/login";

pub const ADMIN_USERS_MANAGE_PERMISSION: &str = "admin:users:manage";
/// Explicit permission to act as a Customer Admin (audited, step-up gated).
pub const IMPERSONATE_PERMISSION: &str = "admin:impersonate";
/// Read a mail transaction's routing and delivery metadata.
pub const TRACE_VIEW_PERMISSION: &str = "trace:view";
/// Read a mail transaction's rendered message content (headers/body).
pub const TRACE_CONTENT_PERMISSION: &str = "trace:content";

pub const SYSTEM_ADMIN_ROLE: &str = "system_admin";
pub const SUPPORT_ROLE: &str = "support";
pub const CUSTOMER_ADMIN_ROLE: &str = "customer_admin";
/// Role granted to the first identity that logs into an empty deployment.
/// The first identity is the platform operator of the local boundary, so it
/// starts with System Admin rights; Customer Admins are created afterwards.
const BOOTSTRAP_ROLE: &str = SYSTEM_ADMIN_ROLE;

const SESSION_LOGIN_ACTION: &str = "session_login";
const SESSION_LOGOUT_ACTION: &str = "session_logout";
const SESSION_STEP_UP_ACTION: &str = "session_step_up";
const USER_LIST_ACTION: &str = "admin_users_list";
const USER_CREATE_ACTION: &str = "admin_user_created";
const ROLE_GRANT_ACTION: &str = "admin_role_granted";
const ROLE_REVOKE_ACTION: &str = "admin_role_revoked";
const IMPERSONATION_START_ACTION: &str = "impersonation_started";
const IMPERSONATION_END_ACTION: &str = "impersonation_ended";
const RESOURCE_SESSION: &str = "session";
const RESOURCE_USER: &str = "admin_user";
const RESOURCE_IMPERSONATION: &str = "admin_impersonation";

const MAX_IDENTITY_LEN: usize = 254;
const MAX_LOGIN_LEN: usize = 254;
const MAX_DISPLAY_NAME_LEN: usize = 128;
const MIN_IMPERSONATION_REASON_LEN: usize = 10;
const MAX_IMPERSONATION_REASON_LEN: usize = 500;

/// One builtin role: seeded idempotently per deployment and the only role
/// keys the management API accepts.
pub struct BuiltinRole {
    pub key: &'static str,
    pub display_name: &'static str,
    pub role_level: &'static str,
    pub permissions: &'static [&'static str],
}

pub const BUILTIN_ROLES: [BuiltinRole; 3] = [
    BuiltinRole {
        key: SYSTEM_ADMIN_ROLE,
        display_name: "System Administrator",
        role_level: "system",
        permissions: &[
            ADMIN_USERS_MANAGE_PERMISSION,
            IMPERSONATE_PERMISSION,
            AUDIT_VIEW_PERMISSION,
            AUDIT_EXPORT_PERMISSION,
            AUDIT_CROSS_CUSTOMER_PERMISSION,
            QUARANTINE_VIEW_PERMISSION,
            QUARANTINE_RELEASE_PERMISSION,
            SCANNER_OPERATIONS_VIEW_PERMISSION,
            crate::admin_customers::CUSTOMERS_VIEW_PERMISSION,
            crate::admin_customers::CUSTOMERS_MANAGE_PERMISSION,
            crate::admin_customers::DOMAINS_MANAGE_PERMISSION,
            crate::domain_security::DOMAIN_SECURITY_VIEW_PERMISSION,
            crate::domain_security::DOMAIN_SECURITY_MANAGE_PERMISSION,
            crate::policy_admin::POLICIES_VIEW_PERMISSION,
            crate::policy_admin::POLICIES_MANAGE_PERMISSION,
            crate::model_registry::MODELS_VIEW_PERMISSION,
            crate::model_registry::MODELS_MANAGE_PERMISSION,
            OPERATIONS_VIEW_PERMISSION,
            OPERATIONS_MANAGE_PERMISSION,
            TRACE_VIEW_PERMISSION,
            TRACE_CONTENT_PERMISSION,
        ],
    },
    BuiltinRole {
        key: SUPPORT_ROLE,
        display_name: "Support",
        role_level: "support",
        permissions: &[
            IMPERSONATE_PERMISSION,
            AUDIT_VIEW_PERMISSION,
            QUARANTINE_VIEW_PERMISSION,
            SCANNER_OPERATIONS_VIEW_PERMISSION,
            crate::admin_customers::CUSTOMERS_VIEW_PERMISSION,
            crate::admin_customers::CUSTOMERS_MANAGE_PERMISSION,
            crate::admin_customers::DOMAINS_MANAGE_PERMISSION,
            crate::domain_security::DOMAIN_SECURITY_VIEW_PERMISSION,
            crate::domain_security::DOMAIN_SECURITY_MANAGE_PERMISSION,
            crate::policy_admin::POLICIES_VIEW_PERMISSION,
            crate::policy_admin::POLICIES_MANAGE_PERMISSION,
            crate::model_registry::MODELS_VIEW_PERMISSION,
            OPERATIONS_VIEW_PERMISSION,
            OPERATIONS_MANAGE_PERMISSION,
            TRACE_VIEW_PERMISSION,
        ],
    },
    BuiltinRole {
        key: CUSTOMER_ADMIN_ROLE,
        display_name: "Customer Administrator",
        role_level: "customer",
        permissions: &[
            ADMIN_USERS_MANAGE_PERMISSION,
            AUDIT_VIEW_PERMISSION,
            AUDIT_EXPORT_PERMISSION,
            QUARANTINE_VIEW_PERMISSION,
            QUARANTINE_RELEASE_PERMISSION,
            SCANNER_OPERATIONS_VIEW_PERMISSION,
            crate::admin_customers::CUSTOMERS_VIEW_PERMISSION,
            crate::domain_security::DOMAIN_SECURITY_VIEW_PERMISSION,
            crate::policy_admin::POLICIES_VIEW_PERMISSION,
            crate::policy_admin::POLICIES_MANAGE_PERMISSION,
            TRACE_VIEW_PERMISSION,
            TRACE_CONTENT_PERMISSION,
        ],
    },
];

fn is_builtin_role(role_key: &str) -> bool {
    BUILTIN_ROLES.iter().any(|role| role.key == role_key)
}

/// Ordering rank of a builtin role level: a grantor may only assign or revoke
/// roles at or below their own highest level (no privilege escalation).
fn role_level_rank(role_key: &str) -> u8 {
    BUILTIN_ROLES
        .iter()
        .find(|role| role.key == role_key)
        .map(|role| match role.role_level {
            "system" => 3,
            "support" => 2,
            "customer" => 1,
            _ => 0,
        })
        .unwrap_or(0)
}

/// Whether every listed role is within the grantor's own level.
fn roles_within_grantor_level(grantor_roles: &[String], requested: &[String]) -> bool {
    let grantor_rank = grantor_roles
        .iter()
        .map(|role| role_level_rank(role))
        .max()
        .unwrap_or(0);
    requested
        .iter()
        .all(|role| role_level_rank(role) <= grantor_rank)
}

/// Effective permissions for a set of role keys (in-memory store; the
/// Postgres store reads `admin_role_permissions`, seeded from this map).
fn permissions_for_roles(roles: &[String]) -> Vec<String> {
    let mut permissions: Vec<String> = BUILTIN_ROLES
        .iter()
        .filter(|role| roles.iter().any(|granted| granted == role.key))
        .flat_map(|role| {
            role.permissions
                .iter()
                .map(|permission| permission.to_string())
        })
        .collect();
    permissions.sort();
    permissions.dedup();
    permissions
}

#[derive(Debug, thiserror::Error)]
pub enum AdminRbacError {
    #[error("admin rbac persistence failed")]
    PersistenceFailed,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Idle timeout: a session untouched for longer expires.
    pub idle_ttl_secs: i64,
    /// Absolute session lifetime regardless of activity.
    pub absolute_ttl_secs: i64,
    /// Freshness window for step-up-gated administrative changes.
    pub step_up_ttl_secs: i64,
    /// Persist a `last_seen_at` touch only when the session is staler than
    /// this, keeping reads cheap under load.
    pub touch_after_secs: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_ttl_secs: 3_600,
            absolute_ttl_secs: 28_800,
            step_up_ttl_secs: 600,
            touch_after_secs: 60,
        }
    }
}

/// Static customer/config facts used to build a per-request `TenantContext`
/// from a resolved session (the local deployment serves one seeded customer).
#[derive(Debug, Clone)]
pub struct ControlPlaneTemplate {
    pub region: RegionId,
    pub customer_id: CustomerId,
    pub customer_internal_key: i64,
    pub customer_display_name: String,
    pub customer_lifecycle: CustomerLifecycle,
    pub config_revision: i64,
}

/// One admin user with role membership.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserRecord {
    pub id: Uuid,
    pub login: String,
    pub display_name: String,
    pub customer_id: Option<String>,
    pub lifecycle: String,
    pub roles: Vec<String>,
}

/// Resolved server-side session; carries no bearer/workload credential.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub session_id: Uuid,
    pub deployment_id: String,
    pub user_id: Uuid,
    pub login: String,
    /// Real actor's roles; impersonation never changes identity ownership.
    pub roles: Vec<String>,
    /// Effective permissions for this request: always the real actor's own
    /// permission set. Customer entry changes the customer scope only and
    /// never intersects, reduces or extends permissions.
    pub permissions: Vec<String>,
    pub customer_id: Option<String>,
    pub csrf_token: String,
    pub authenticated_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub step_up_at: Option<DateTime<Utc>>,
    /// Active acting-as context for this session, if any.
    pub impersonation: Option<ActiveImpersonation>,
}

/// Active customer-entry overlay resolved with the session.
#[derive(Debug, Clone)]
pub struct ActiveImpersonation {
    pub id: Uuid,
    pub customer_id: String,
    pub customer_display_name: String,
    pub customer_internal_key: i64,
    pub customer_lifecycle: String,
    pub reason: String,
    pub started_at: DateTime<Utc>,
}

impl ActiveSession {
    pub fn step_up_active(&self, now: DateTime<Utc>, ttl_secs: i64) -> bool {
        self.step_up_at
            .map(|at| now <= at + Duration::seconds(ttl_secs))
            .unwrap_or(false)
    }
}

/// Safe browser projection of the active session.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionView {
    authenticated: bool,
    user_id: String,
    email: String,
    roles: Vec<String>,
    /// Server-derived permission claims for UI affordances only; every API
    /// call re-authorizes them server-side. Always the real actor's own
    /// permissions, including during customer entry.
    permissions: Vec<String>,
    customer_id: String,
    expires_at: String,
    step_up_active: bool,
    csrf_token: String,
    /// Active acting-as context powering the persistent impersonation banner.
    impersonation: Option<SessionImpersonationView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionImpersonationView {
    id: String,
    customer_id: String,
    customer_display_name: String,
    reason: String,
    started_at: String,
}

fn session_view(
    session: &ActiveSession,
    template: &ControlPlaneTemplate,
    step_up_ttl_secs: i64,
) -> SessionView {
    SessionView {
        authenticated: true,
        user_id: session.user_id.to_string(),
        email: session.login.clone(),
        roles: session.roles.clone(),
        permissions: session.permissions.clone(),
        customer_id: session
            .impersonation
            .as_ref()
            .map(|impersonation| impersonation.customer_id.clone())
            .unwrap_or_else(|| template.customer_id.0.clone()),
        expires_at: session.absolute_expires_at.to_rfc3339(),
        step_up_active: session.step_up_active(Utc::now(), step_up_ttl_secs),
        csrf_token: session.csrf_token.clone(),
        impersonation: session.impersonation.as_ref().map(|impersonation| {
            SessionImpersonationView {
                id: impersonation.id.to_string(),
                customer_id: impersonation.customer_id.clone(),
                customer_display_name: impersonation.customer_display_name.clone(),
                reason: impersonation.reason.clone(),
                started_at: impersonation.started_at.to_rfc3339(),
            }
        }),
    }
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: Vec<u8>,
    pub csrf_token: String,
    pub source_ip: Option<String>,
    pub authenticated_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub step_up_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub login: String,
    pub display_name: String,
    pub customer_id: Option<String>,
    pub roles: Vec<String>,
    pub created_by: String,
}

/// Display facts for a customer a session may enter; powers the banner and
/// audit details.
#[derive(Debug, Clone)]
pub struct CustomerEntryTarget {
    pub display_name: String,
    pub internal_key: i64,
    pub lifecycle: String,
}

/// One customer-entry interval to persist atomically with its audit row.
#[derive(Debug, Clone)]
pub struct NewImpersonation {
    pub id: Uuid,
    pub session_id: Uuid,
    pub actor_user_id: Uuid,
    pub actor_login: String,
    pub customer_id: String,
    pub reason: String,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug)]
pub enum AuthenticateOutcome {
    Authenticated {
        user: AdminUserRecord,
        permissions: Vec<String>,
    },
    Bootstrapped {
        user: AdminUserRecord,
        permissions: Vec<String>,
    },
    Unknown,
    Suspended,
}

/// Identity mapping outcome for a verified IdP assertion: the same
/// authentication outcomes as the boundary identity, plus whether this
/// login first bound the IdP subject to an existing local user.
#[derive(Debug)]
pub struct ExternalAuthOutcome {
    pub outcome: AuthenticateOutcome,
    /// True when the assertion was linked to an existing unlinked local
    /// user by login match during this call.
    pub linked: bool,
}

/// An in-flight OIDC authorization request. Rows are claimed exactly once
/// and expire quickly; they carry no tokens or assertion claims.
#[derive(Debug, Clone)]
pub enum LoginFlowKind {
    /// Interactive login: completing it establishes a new session.
    Login,
    /// Step-up re-authentication bound to an existing session.
    Reauth { session_id: Uuid },
}

/// Pending flow to persist when the browser is redirected to the IdP.
#[derive(Debug, Clone)]
pub struct NewLoginFlow {
    /// SHA-256 of the opaque `state` value (the raw value only travels in
    /// the redirect, never rests in storage).
    pub state_hash: Vec<u8>,
    pub nonce: String,
    pub code_verifier: String,
    pub kind: LoginFlowKind,
    /// Same-origin path to return to after completion (validated `/…`).
    pub return_to: String,
    pub expires_at: DateTime<Utc>,
}

/// A claimed pending flow.
#[derive(Debug, Clone)]
pub struct LoginFlow {
    pub nonce: String,
    pub code_verifier: String,
    pub kind: LoginFlowKind,
    pub return_to: String,
}

pub enum CreateUserOutcome {
    Created(AdminUserRecord),
    AlreadyExists,
}

#[derive(Debug, Clone)]
pub struct RoleMutation {
    pub changed: bool,
    pub roles: Vec<String>,
}

/// Actor attribution shared by every audit row this module writes.
#[derive(Debug, Clone)]
pub struct AuditSubject {
    pub actor_id: String,
    pub actor_login: String,
    pub actor_roles: Vec<String>,
    pub customer_id: Option<String>,
    pub session_id: Option<String>,
    pub source_ip: Option<String>,
    pub trace_id: String,
    /// Impersonated subject login while the session is acting as a Customer
    /// Admin; every action taken during impersonation retains both identities.
    pub impersonated_subject: Option<String>,
    /// Customer the impersonated subject belongs to.
    pub impersonated_customer: Option<String>,
}

/// Audit intent for a change that has not happened yet; the store writes it
/// in the same transaction as the mutation so neither can exist alone.
#[derive(Debug, Clone)]
pub struct AuditEventDraft {
    pub subject: AuditSubject,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub details: serde_json::Value,
}

impl AuditEventDraft {
    fn into_record(self, result: &str, patch: Option<serde_json::Value>) -> AuditEventRecord {
        let mut details = self.details;
        if let Some(patch) = patch {
            if let (Some(base), Some(patch)) = (details.as_object_mut(), patch.as_object()) {
                for (key, value) in patch {
                    base.insert(key.clone(), value.clone());
                }
            }
        }
        AuditEventRecord {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            actor_id: self.subject.actor_id,
            actor_login: self.subject.actor_login,
            actor_roles: self.subject.actor_roles,
            impersonated_subject: self.subject.impersonated_subject,
            impersonated_customer: self.subject.impersonated_customer,
            customer_id: self.subject.customer_id,
            action: self.action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            result: result.to_string(),
            source_ip: self.subject.source_ip,
            session_id: self.subject.session_id,
            trace_id: self.subject.trace_id,
            details,
        }
    }
}

/// Persistence boundary for admin users, role membership and sessions.
#[async_trait]
pub trait AdminRbacStore: Send + Sync {
    /// Resolves a boundary identity to an admin user, bootstrapping the
    /// first identity of an empty deployment as `BOOTSTRAP_ROLE`.
    async fn authenticate_identity(
        &self,
        deployment_id: &str,
        identity: &str,
        bootstrap_customer_id: Option<&str>,
    ) -> Result<AuthenticateOutcome, AdminRbacError>;

    /// Maps a verified IdP subject to a local admin user. Precedence:
    /// exact `auth_subject` match, then link-by-login-candidates for an
    /// existing still-unlinked user, then the empty-deployment bootstrap
    /// (first IdP identity becomes `BOOTSTRAP_ROLE`). Unknown subjects
    /// stay `Unknown` so the caller can refuse and audit them; `auth_subject`
    /// is mapping only and never authorization.
    async fn authenticate_external_identity(
        &self,
        deployment_id: &str,
        subject: &str,
        login_candidates: &[String],
        bootstrap_customer_id: Option<&str>,
    ) -> Result<ExternalAuthOutcome, AdminRbacError>;

    /// Persists an in-flight OIDC authorization request keyed by the
    /// hashed `state` (duplicate states fail closed).
    async fn create_login_flow(
        &self,
        deployment_id: &str,
        flow: NewLoginFlow,
    ) -> Result<(), AdminRbacError>;

    /// Claims a pending flow exactly once (delete-returning) for the
    /// deployment, refusing unknown or expired states.
    async fn claim_login_flow(
        &self,
        deployment_id: &str,
        state_hash: &[u8],
    ) -> Result<Option<LoginFlow>, AdminRbacError>;

    /// Marks an existing session freshly step-up-authenticated after a
    /// successful IdP re-authentication and writes the `session_step_up`
    /// audit row in the same transaction. The update only applies while
    /// the session is still active and still owned by `user_id` (binding
    /// checked in the same statement). Returns false when it is gone,
    /// revoked or expired, in which case nothing (including audit) is
    /// written; an audit failure rolls the refresh back (fail closed).
    async fn refresh_step_up(
        &self,
        deployment_id: &str,
        session_id: Uuid,
        user_id: Uuid,
        config: &SessionConfig,
        audit: AuditEventDraft,
    ) -> Result<bool, AdminRbacError>;

    /// Creates a session row and writes its login audit row atomically;
    /// an audit failure rolls the session back (fail closed).
    async fn create_session(
        &self,
        deployment_id: &str,
        session: NewSession,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError>;

    /// Resolves a cookie token hash to an active session, enforcing idle and
    /// absolute expiry plus account lifecycle, and touching `last_seen_at`
    /// only when staler than the configured threshold.
    async fn resolve_session(
        &self,
        deployment_id: &str,
        token_hash: &[u8],
        config: &SessionConfig,
    ) -> Result<Option<ActiveSession>, AdminRbacError>;

    /// Revokes a session and writes the logout audit row atomically.
    async fn revoke_session(
        &self,
        deployment_id: &str,
        session_id: Uuid,
        reason: &str,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError>;

    async fn list_users(
        &self,
        deployment_id: &str,
        customer_filter: Option<&str>,
    ) -> Result<Vec<AdminUserRecord>, AdminRbacError>;

    async fn get_user(
        &self,
        deployment_id: &str,
        user_id: Uuid,
    ) -> Result<Option<AdminUserRecord>, AdminRbacError>;

    /// Creates a user with role grants and its audit row atomically.
    async fn create_user(
        &self,
        deployment_id: &str,
        user: NewUser,
        audit: AuditEventDraft,
    ) -> Result<CreateUserOutcome, AdminRbacError>;

    /// Grants a role idempotently and audits the change atomically.
    async fn grant_role(
        &self,
        deployment_id: &str,
        user_id: Uuid,
        role_key: &str,
        granted_by: &str,
        audit: AuditEventDraft,
    ) -> Result<RoleMutation, AdminRbacError>;

    /// Revokes a role idempotently and audits the change atomically.
    async fn revoke_role(
        &self,
        deployment_id: &str,
        user_id: Uuid,
        role_key: &str,
        audit: AuditEventDraft,
    ) -> Result<RoleMutation, AdminRbacError>;

    /// Starts an impersonation interval and writes its audit row atomically;
    /// fails when the session already has an active impersonation.
    async fn start_impersonation(
        &self,
        deployment_id: &str,
        record: NewImpersonation,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError>;

    /// Ends the session's active impersonation and audits it. Returns `false`
    /// (without an audit row) when there was nothing to end, so retries stay
    /// idempotent.
    async fn end_impersonation(
        &self,
        deployment_id: &str,
        session_id: Uuid,
        ended_reason: &str,
        audit: AuditEventDraft,
    ) -> Result<bool, AdminRbacError>;

    /// Resolves a customer as an entry target (existence/lifecycle check plus
    /// the display facts stored on the session overlay).
    async fn customer_entry_target(
        &self,
        deployment_id: &str,
        customer_id: &str,
    ) -> Result<Option<CustomerEntryTarget>, AdminRbacError>;
}

// ---------------------------------------------------------------------------
// In-memory store (unit tests and non-database local tooling)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MemoryUser {
    id: Uuid,
    deployment_id: String,
    login: String,
    display_name: String,
    customer_id: Option<String>,
    lifecycle: String,
    roles: Vec<String>,
    /// External IdP subject this local account is bound to, if linked.
    auth_subject: Option<String>,
}

impl MemoryUser {
    fn record(&self) -> AdminUserRecord {
        AdminUserRecord {
            id: self.id,
            login: self.login.clone(),
            display_name: self.display_name.clone(),
            customer_id: self.customer_id.clone(),
            lifecycle: self.lifecycle.clone(),
            roles: self.roles.clone(),
        }
    }
}

struct MemorySession {
    id: Uuid,
    deployment_id: String,
    user_id: Uuid,
    token_hash: Vec<u8>,
    csrf_token: String,
    authenticated_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    absolute_expires_at: DateTime<Utc>,
    step_up_at: Option<DateTime<Utc>>,
    revoked: bool,
}

#[derive(Clone)]
struct MemoryImpersonation {
    id: Uuid,
    deployment_id: String,
    session_id: Uuid,
    customer_id: String,
    reason: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
}

/// Pending OIDC authorization request (see [`NewLoginFlow`]).
struct MemoryFlow {
    state_hash: Vec<u8>,
    deployment_id: String,
    nonce: String,
    code_verifier: String,
    kind: LoginFlowKind,
    return_to: String,
    expires_at: DateTime<Utc>,
}

pub struct InMemoryAdminRbacStore {
    users: std::sync::Mutex<Vec<MemoryUser>>,
    sessions: std::sync::Mutex<Vec<MemorySession>>,
    impersonations: std::sync::Mutex<Vec<MemoryImpersonation>>,
    customers: std::sync::Mutex<Vec<MemoryCustomer>>,
    flows: std::sync::Mutex<Vec<MemoryFlow>>,
    audit: Arc<dyn AuditStore>,
}

#[derive(Clone)]
struct MemoryCustomer {
    deployment_id: String,
    id: String,
    display_name: String,
    internal_key: i64,
    lifecycle: String,
}

impl InMemoryAdminRbacStore {
    pub fn new(audit: Arc<dyn AuditStore>) -> Self {
        Self {
            users: std::sync::Mutex::new(Vec::new()),
            sessions: std::sync::Mutex::new(Vec::new()),
            impersonations: std::sync::Mutex::new(Vec::new()),
            customers: std::sync::Mutex::new(Vec::new()),
            flows: std::sync::Mutex::new(Vec::new()),
            audit,
        }
    }

    /// Seeds a customer entry target (tests and local fixtures).
    pub fn seed_customer(
        &self,
        deployment_id: &str,
        customer_id: &str,
        display_name: &str,
        lifecycle: &str,
    ) {
        let mut customers = self.customers.lock().expect("admin rbac store poisoned");
        if let Some(existing) = customers
            .iter_mut()
            .find(|customer| customer.deployment_id == deployment_id && customer.id == customer_id)
        {
            existing.display_name = display_name.to_string();
            existing.lifecycle = lifecycle.to_string();
            return;
        }
        let next_key = customers.len() as i64 + 1;
        customers.push(MemoryCustomer {
            deployment_id: deployment_id.to_string(),
            id: customer_id.to_string(),
            display_name: display_name.to_string(),
            internal_key: next_key,
            lifecycle: lifecycle.to_string(),
        });
    }

    /// Seeds a user directly (tests and local fixtures).
    pub fn seed_user(
        &self,
        deployment_id: &str,
        login: &str,
        display_name: &str,
        customer_id: Option<&str>,
        lifecycle: &str,
        roles: &[&str],
    ) -> Uuid {
        let id = Uuid::new_v4();
        self.users
            .lock()
            .expect("admin rbac store poisoned")
            .push(MemoryUser {
                id,
                deployment_id: deployment_id.to_string(),
                login: login.to_string(),
                display_name: display_name.to_string(),
                customer_id: customer_id.map(str::to_string),
                lifecycle: lifecycle.to_string(),
                roles: roles.iter().map(|role| role.to_string()).collect(),
                auth_subject: None,
            });
        id
    }

    /// Test/fixture helper: binds (or with `None`, unbinds) an IdP subject
    /// to a seeded local user, mirroring the database `auth_subject` link.
    pub fn set_auth_subject(
        &self,
        deployment_id: &str,
        login: &str,
        subject: Option<&str>,
    ) -> bool {
        let mut users = self.users.lock().expect("admin rbac store poisoned");
        match users
            .iter_mut()
            .find(|user| user.deployment_id == deployment_id && user.login == login)
        {
            Some(user) => {
                user.auth_subject = subject.map(str::to_string);
                true
            },
            None => false,
        }
    }

    fn user_for_login(&self, deployment_id: &str, login: &str) -> Option<MemoryUser> {
        self.users
            .lock()
            .expect("admin rbac store poisoned")
            .iter()
            .find(|user| user.deployment_id == deployment_id && user.login == login)
            .cloned()
    }

    fn deployment_user_count(&self, deployment_id: &str) -> usize {
        self.users
            .lock()
            .expect("admin rbac store poisoned")
            .iter()
            .filter(|user| user.deployment_id == deployment_id)
            .count()
    }

    fn user(&self, deployment_id: &str, user_id: Uuid) -> Option<MemoryUser> {
        self.users
            .lock()
            .expect("admin rbac store poisoned")
            .iter()
            .find(|user| user.deployment_id == deployment_id && user.id == user_id)
            .cloned()
    }

    async fn write_audit(
        &self,
        draft: AuditEventDraft,
        result: &str,
        patch: Option<serde_json::Value>,
    ) -> Result<(), AdminRbacError> {
        let record = draft.into_record(result, patch);
        self.audit
            .record_event("", record)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)
    }
}

#[async_trait]
impl AdminRbacStore for InMemoryAdminRbacStore {
    async fn authenticate_identity(
        &self,
        deployment_id: &str,
        identity: &str,
        bootstrap_customer_id: Option<&str>,
    ) -> Result<AuthenticateOutcome, AdminRbacError> {
        if self.deployment_user_count(deployment_id) == 0 {
            let id = self.seed_user(
                deployment_id,
                identity,
                identity,
                bootstrap_customer_id,
                "active",
                &[BOOTSTRAP_ROLE],
            );
            let user = self.user(deployment_id, id).expect("just seeded");
            let permissions = permissions_for_roles(&user.roles);
            return Ok(AuthenticateOutcome::Bootstrapped {
                user: user.record(),
                permissions,
            });
        }
        let Some(user) = self.user_for_login(deployment_id, identity) else {
            return Ok(AuthenticateOutcome::Unknown);
        };
        if user.lifecycle != "active" {
            return Ok(AuthenticateOutcome::Suspended);
        }
        let permissions = permissions_for_roles(&user.roles);
        Ok(AuthenticateOutcome::Authenticated {
            user: user.record(),
            permissions,
        })
    }

    async fn authenticate_external_identity(
        &self,
        deployment_id: &str,
        subject: &str,
        login_candidates: &[String],
        bootstrap_customer_id: Option<&str>,
    ) -> Result<ExternalAuthOutcome, AdminRbacError> {
        let mut users = self.users.lock().expect("admin rbac store poisoned");
        // 1. Exact subject match on an already-linked local account.
        if let Some(user) = users
            .iter()
            .find(|user| {
                user.deployment_id == deployment_id && user.auth_subject.as_deref() == Some(subject)
            })
            .cloned()
        {
            if user.lifecycle != "active" {
                return Ok(ExternalAuthOutcome {
                    outcome: AuthenticateOutcome::Suspended,
                    linked: false,
                });
            }
            let permissions = permissions_for_roles(&user.roles);
            return Ok(ExternalAuthOutcome {
                outcome: AuthenticateOutcome::Authenticated {
                    user: user.record(),
                    permissions,
                },
                linked: false,
            });
        }
        // 2. Link by login candidates among still-unlinked active users.
        let matched = users
            .iter_mut()
            .find(|user| {
                user.deployment_id == deployment_id
                    && user.auth_subject.is_none()
                    && user.lifecycle == "active"
                    && login_candidates
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(&user.login))
            })
            .map(|user| {
                user.auth_subject = Some(subject.to_string());
                user.clone()
            });
        if let Some(user) = matched {
            let permissions = permissions_for_roles(&user.roles);
            return Ok(ExternalAuthOutcome {
                outcome: AuthenticateOutcome::Authenticated {
                    user: user.record(),
                    permissions,
                },
                linked: true,
            });
        }
        // 3. First identity of an empty deployment bootstraps the owner.
        if users.iter().all(|user| user.deployment_id != deployment_id) {
            let login = login_candidates
                .first()
                .cloned()
                .filter(|login| valid_login(login))
                .unwrap_or_else(|| subject.to_string());
            let user = MemoryUser {
                id: Uuid::new_v4(),
                deployment_id: deployment_id.to_string(),
                login: login.clone(),
                display_name: login,
                customer_id: bootstrap_customer_id.map(str::to_string),
                lifecycle: "active".to_string(),
                roles: vec![BOOTSTRAP_ROLE.to_string()],
                auth_subject: Some(subject.to_string()),
            };
            let permissions = permissions_for_roles(&user.roles);
            let record = user.record();
            users.push(user);
            return Ok(ExternalAuthOutcome {
                outcome: AuthenticateOutcome::Bootstrapped {
                    user: record,
                    permissions,
                },
                linked: false,
            });
        }
        // 4. Unknown subject: refuse (the caller audits the denial).
        Ok(ExternalAuthOutcome {
            outcome: AuthenticateOutcome::Unknown,
            linked: false,
        })
    }

    async fn create_login_flow(
        &self,
        deployment_id: &str,
        flow: NewLoginFlow,
    ) -> Result<(), AdminRbacError> {
        let mut flows = self.flows.lock().expect("admin rbac store poisoned");
        if flows.iter().any(|pending| {
            pending.deployment_id == deployment_id && pending.state_hash == flow.state_hash
        }) {
            return Err(AdminRbacError::PersistenceFailed);
        }
        flows.push(MemoryFlow {
            state_hash: flow.state_hash,
            deployment_id: deployment_id.to_string(),
            nonce: flow.nonce,
            code_verifier: flow.code_verifier,
            kind: flow.kind,
            return_to: flow.return_to,
            expires_at: flow.expires_at,
        });
        Ok(())
    }

    async fn claim_login_flow(
        &self,
        deployment_id: &str,
        state_hash: &[u8],
    ) -> Result<Option<LoginFlow>, AdminRbacError> {
        let mut flows = self.flows.lock().expect("admin rbac store poisoned");
        let now = Utc::now();
        let index = flows.iter().position(|pending| {
            pending.deployment_id == deployment_id
                && pending.state_hash == state_hash
                && pending.expires_at > now
        });
        Ok(index.map(|index| {
            let pending = flows.remove(index);
            LoginFlow {
                nonce: pending.nonce,
                code_verifier: pending.code_verifier,
                kind: pending.kind,
                return_to: pending.return_to,
            }
        }))
    }

    async fn refresh_step_up(
        &self,
        deployment_id: &str,
        session_id: Uuid,
        user_id: Uuid,
        config: &SessionConfig,
        audit: AuditEventDraft,
    ) -> Result<bool, AdminRbacError> {
        let now = Utc::now();
        let idle_cutoff = now - Duration::seconds(config.idle_ttl_secs);
        let refreshed = {
            let mut sessions = self.sessions.lock().expect("admin rbac store poisoned");
            match sessions.iter_mut().find(|session| {
                session.deployment_id == deployment_id
                    && session.id == session_id
                    && session.user_id == user_id
            }) {
                Some(session)
                    if !session.revoked
                        && session.absolute_expires_at > now
                        && session.last_seen_at > idle_cutoff =>
                {
                    session.step_up_at = Some(now);
                    true
                },
                _ => false,
            }
        };
        if !refreshed {
            return Ok(false);
        }
        self.write_audit(audit, "success", None).await?;
        Ok(true)
    }

    async fn create_session(
        &self,
        deployment_id: &str,
        session: NewSession,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError> {
        self.sessions
            .lock()
            .expect("admin rbac store poisoned")
            .push(MemorySession {
                id: session.id,
                deployment_id: deployment_id.to_string(),
                user_id: session.user_id,
                token_hash: session.token_hash,
                csrf_token: session.csrf_token,
                authenticated_at: session.authenticated_at,
                last_seen_at: session.authenticated_at,
                absolute_expires_at: session.absolute_expires_at,
                step_up_at: session.step_up_at,
                revoked: false,
            });
        self.write_audit(audit, "success", None).await
    }

    async fn resolve_session(
        &self,
        deployment_id: &str,
        token_hash: &[u8],
        config: &SessionConfig,
    ) -> Result<Option<ActiveSession>, AdminRbacError> {
        let now = Utc::now();
        let idle_cutoff = now - Duration::seconds(config.idle_ttl_secs);
        let mut sessions = self.sessions.lock().expect("admin rbac store poisoned");
        let found = sessions.iter_mut().find(|session| {
            session.deployment_id == deployment_id
                && session.token_hash == token_hash
                && !session.revoked
                && session.absolute_expires_at > now
                && session.last_seen_at > idle_cutoff
        });
        let Some(session) = found else {
            return Ok(None);
        };
        let user = match self.user(deployment_id, session.user_id) {
            Some(user) if user.lifecycle == "active" => user,
            _ => return Ok(None),
        };
        if session.last_seen_at <= now - Duration::seconds(config.touch_after_secs) {
            session.last_seen_at = now;
        }
        let session_id = session.id;
        let csrf_token = session.csrf_token.clone();
        let authenticated_at = session.authenticated_at;
        let absolute_expires_at = session.absolute_expires_at;
        let step_up_at = session.step_up_at;
        let actor_permissions = permissions_for_roles(&user.roles);
        drop(sessions);

        let active_impersonation = self
            .impersonations
            .lock()
            .expect("admin rbac store poisoned")
            .iter()
            .find(|impersonation| {
                impersonation.deployment_id == deployment_id
                    && impersonation.session_id == session_id
                    && impersonation.ended_at.is_none()
            })
            .cloned();
        // Customer entry never narrows the actor's permissions: the overlay
        // only switches customer scope.
        let entry = {
            let customers = self.customers.lock().expect("admin rbac store poisoned");
            active_impersonation.and_then(|impersonation| {
                let customer = customers
                    .iter()
                    .find(|customer| {
                        customer.deployment_id == deployment_id
                            && customer.id == impersonation.customer_id
                    })
                    .cloned();
                customer.map(|customer| ActiveImpersonation {
                    id: impersonation.id,
                    customer_id: customer.id,
                    customer_display_name: customer.display_name,
                    customer_internal_key: customer.internal_key,
                    customer_lifecycle: customer.lifecycle,
                    reason: impersonation.reason.clone(),
                    started_at: impersonation.started_at,
                })
            })
        };
        let (impersonation, permissions) = match entry {
            Some(entry) => (Some(entry), actor_permissions),
            None => (None, actor_permissions),
        };
        let active = ActiveSession {
            session_id,
            deployment_id: deployment_id.to_string(),
            user_id: user.id,
            login: user.login.clone(),
            roles: user.roles.clone(),
            permissions,
            customer_id: user.customer_id.clone(),
            csrf_token,
            authenticated_at,
            absolute_expires_at,
            step_up_at,
            impersonation,
        };
        Ok(Some(active))
    }

    async fn revoke_session(
        &self,
        _deployment_id: &str,
        session_id: Uuid,
        _reason: &str,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError> {
        {
            let mut sessions = self.sessions.lock().expect("admin rbac store poisoned");
            if let Some(session) = sessions.iter_mut().find(|session| session.id == session_id) {
                session.revoked = true;
            }
        }
        {
            let mut impersonations = self
                .impersonations
                .lock()
                .expect("admin rbac store poisoned");
            for impersonation in impersonations.iter_mut() {
                if impersonation.session_id == session_id && impersonation.ended_at.is_none() {
                    impersonation.ended_at = Some(Utc::now());
                }
            }
        }
        self.write_audit(audit, "success", None).await
    }

    async fn list_users(
        &self,
        deployment_id: &str,
        customer_filter: Option<&str>,
    ) -> Result<Vec<AdminUserRecord>, AdminRbacError> {
        let mut users: Vec<AdminUserRecord> = self
            .users
            .lock()
            .expect("admin rbac store poisoned")
            .iter()
            .filter(|user| {
                user.deployment_id == deployment_id
                    && customer_filter
                        .map(|customer| user.customer_id.as_deref() == Some(customer))
                        .unwrap_or(true)
            })
            .map(|user| user.record())
            .collect();
        users.sort_by(|left, right| left.login.cmp(&right.login));
        Ok(users)
    }

    async fn get_user(
        &self,
        deployment_id: &str,
        user_id: Uuid,
    ) -> Result<Option<AdminUserRecord>, AdminRbacError> {
        Ok(self.user(deployment_id, user_id).map(|user| user.record()))
    }

    async fn create_user(
        &self,
        deployment_id: &str,
        user: NewUser,
        audit: AuditEventDraft,
    ) -> Result<CreateUserOutcome, AdminRbacError> {
        if self.user_for_login(deployment_id, &user.login).is_some() {
            return Ok(CreateUserOutcome::AlreadyExists);
        }
        let id = self.seed_user(
            deployment_id,
            &user.login,
            &user.display_name,
            user.customer_id.as_deref(),
            "active",
            &user.roles.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let record = self.user(deployment_id, id).expect("just seeded").record();
        let mut audit = audit;
        audit.resource_id = Some(id.to_string());
        self.write_audit(
            audit,
            "success",
            Some(serde_json::json!({ "created": true })),
        )
        .await?;
        Ok(CreateUserOutcome::Created(record))
    }

    async fn grant_role(
        &self,
        deployment_id: &str,
        user_id: Uuid,
        role_key: &str,
        _granted_by: &str,
        audit: AuditEventDraft,
    ) -> Result<RoleMutation, AdminRbacError> {
        let (changed, roles) = {
            let mut users = self.users.lock().expect("admin rbac store poisoned");
            let changed = if let Some(user) = users
                .iter_mut()
                .find(|user| user.deployment_id == deployment_id && user.id == user_id)
            {
                if user.roles.iter().any(|granted| granted == role_key) {
                    false
                } else {
                    user.roles.push(role_key.to_string());
                    true
                }
            } else {
                return Err(AdminRbacError::PersistenceFailed);
            };
            let roles = users
                .iter()
                .find(|user| user.id == user_id)
                .map(|user| user.roles.clone())
                .unwrap_or_default();
            (changed, roles)
        };
        self.write_audit(
            audit,
            "success",
            Some(serde_json::json!({ "role_key": role_key, "changed": changed })),
        )
        .await?;
        Ok(RoleMutation { changed, roles })
    }

    async fn revoke_role(
        &self,
        deployment_id: &str,
        user_id: Uuid,
        role_key: &str,
        audit: AuditEventDraft,
    ) -> Result<RoleMutation, AdminRbacError> {
        let (changed, roles) = {
            let mut users = self.users.lock().expect("admin rbac store poisoned");
            let changed = if let Some(user) = users
                .iter_mut()
                .find(|user| user.deployment_id == deployment_id && user.id == user_id)
            {
                let before = user.roles.len();
                user.roles.retain(|granted| granted != role_key);
                user.roles.len() != before
            } else {
                return Err(AdminRbacError::PersistenceFailed);
            };
            let roles = users
                .iter()
                .find(|user| user.id == user_id)
                .map(|user| user.roles.clone())
                .unwrap_or_default();
            (changed, roles)
        };
        self.write_audit(
            audit,
            "success",
            Some(serde_json::json!({ "role_key": role_key, "changed": changed })),
        )
        .await?;
        Ok(RoleMutation { changed, roles })
    }

    async fn start_impersonation(
        &self,
        deployment_id: &str,
        record: NewImpersonation,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError> {
        {
            let impersonations = self
                .impersonations
                .lock()
                .expect("admin rbac store poisoned");
            let active = impersonations.iter().any(|impersonation| {
                impersonation.deployment_id == deployment_id
                    && impersonation.session_id == record.session_id
                    && impersonation.ended_at.is_none()
            });
            if active {
                return Err(AdminRbacError::PersistenceFailed);
            }
        }
        self.impersonations
            .lock()
            .expect("admin rbac store poisoned")
            .push(MemoryImpersonation {
                id: record.id,
                deployment_id: deployment_id.to_string(),
                session_id: record.session_id,
                customer_id: record.customer_id,
                reason: record.reason,
                started_at: record.started_at,
                ended_at: None,
            });
        self.write_audit(audit, "success", None).await
    }

    async fn customer_entry_target(
        &self,
        deployment_id: &str,
        customer_id: &str,
    ) -> Result<Option<CustomerEntryTarget>, AdminRbacError> {
        let customers = self.customers.lock().expect("admin rbac store poisoned");
        Ok(customers
            .iter()
            .find(|customer| customer.deployment_id == deployment_id && customer.id == customer_id)
            .map(|customer| CustomerEntryTarget {
                display_name: customer.display_name.clone(),
                internal_key: customer.internal_key,
                lifecycle: customer.lifecycle.clone(),
            }))
    }

    async fn end_impersonation(
        &self,
        deployment_id: &str,
        session_id: Uuid,
        _ended_reason: &str,
        audit: AuditEventDraft,
    ) -> Result<bool, AdminRbacError> {
        let ended = {
            let mut impersonations = self
                .impersonations
                .lock()
                .expect("admin rbac store poisoned");
            let active = impersonations.iter_mut().find(|impersonation| {
                impersonation.deployment_id == deployment_id
                    && impersonation.session_id == session_id
                    && impersonation.ended_at.is_none()
            });
            match active {
                Some(impersonation) => {
                    impersonation.ended_at = Some(Utc::now());
                    true
                },
                None => false,
            }
        };
        if !ended {
            return Ok(false);
        }
        self.write_audit(
            audit,
            "success",
            Some(serde_json::json!({ "changed": true })),
        )
        .await?;
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Postgres store
// ---------------------------------------------------------------------------

pub struct PostgresAdminRbacStore {
    pool: sqlx::PgPool,
}

impl PostgresAdminRbacStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Opens a transaction with the deployment row-level-security setting
    /// applied; every query below also filters `deployment_id` directly.
    async fn begin_scoped(
        &self,
        deployment_id: &str,
    ) -> Result<sqlx::Transaction<'static, Postgres>, AdminRbacError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(deployment_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(transaction)
    }

    /// Applies the audit write-scope settings so `audit_events` row-level
    /// security accepts rows this transaction is about to insert.
    async fn apply_audit_scope(
        transaction: &mut sqlx::Transaction<'static, Postgres>,
        subject: &AuditSubject,
    ) -> Result<(), AdminRbacError> {
        let customer_scope = subject.customer_id.clone().unwrap_or_default();
        let scope = if subject.customer_id.is_some() {
            "tenant"
        } else {
            "platform"
        };
        sqlx::query(
            "SELECT set_config('app.current_customer_id', $1, true), \
                    set_config('app.current_actor_id', $2, true), \
                    set_config('app.audit_scope', $3, true)",
        )
        .bind(customer_scope)
        .bind(&subject.actor_id)
        .bind(scope)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(())
    }

    /// Idempotently seeds the builtin roles and their permissions for a
    /// deployment (called on every login, before any management change).
    async fn ensure_builtin_roles(
        transaction: &mut sqlx::Transaction<'static, Postgres>,
        deployment_id: &str,
    ) -> Result<(), AdminRbacError> {
        for role in BUILTIN_ROLES.iter() {
            sqlx::query(
                "INSERT INTO admin_roles (deployment_id, role_key, display_name, role_level) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (deployment_id, role_key) DO NOTHING",
            )
            .bind(deployment_id)
            .bind(role.key)
            .bind(role.display_name)
            .bind(role.role_level)
            .execute(&mut **transaction)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
            for permission in role.permissions {
                sqlx::query(
                    "INSERT INTO admin_role_permissions (role_id, permission) \
                     SELECT id, $3 FROM admin_roles \
                     WHERE deployment_id = $1 AND role_key = $2 \
                     ON CONFLICT DO NOTHING",
                )
                .bind(deployment_id)
                .bind(role.key)
                .bind(permission)
                .execute(&mut **transaction)
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            }
        }
        Ok(())
    }

    async fn roles_for_user(
        transaction: &mut sqlx::Transaction<'static, Postgres>,
        deployment_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<String>, AdminRbacError> {
        let rows = sqlx::query(
            "SELECT role.role_key FROM admin_user_roles AS grant_row \
             JOIN admin_roles AS role ON role.id = grant_row.role_id \
             WHERE grant_row.user_id = $1 AND role.deployment_id = $2 \
             ORDER BY role.role_key",
        )
        .bind(user_id)
        .bind(deployment_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(rows
            .iter()
            .map(|row| row.get::<String, _>("role_key"))
            .collect())
    }

    async fn permissions_for_user(
        transaction: &mut sqlx::Transaction<'static, Postgres>,
        deployment_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<String>, AdminRbacError> {
        let rows = sqlx::query(
            "SELECT DISTINCT role_permission.permission \
             FROM admin_user_roles AS grant_row \
             JOIN admin_roles AS role ON role.id = grant_row.role_id \
             JOIN admin_role_permissions AS role_permission \
               ON role_permission.role_id = role.id \
             WHERE grant_row.user_id = $1 AND role.deployment_id = $2 \
             ORDER BY role_permission.permission",
        )
        .bind(user_id)
        .bind(deployment_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(rows
            .iter()
            .map(|row| row.get::<String, _>("permission"))
            .collect())
    }

    async fn record_row(
        transaction: &mut sqlx::Transaction<'static, Postgres>,
        deployment_id: &str,
        draft: AuditEventDraft,
        result: &str,
        patch: Option<serde_json::Value>,
    ) -> Result<(), AdminRbacError> {
        let record = draft.into_record(result, patch);
        PostgresAuditStore::insert_record(transaction, deployment_id, &record)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)
    }

    fn user_from_row(row: &sqlx::postgres::PgRow) -> AdminUserRecord {
        AdminUserRecord {
            id: row.get("id"),
            login: row.get("login"),
            display_name: row.get("display_name"),
            customer_id: row.get("customer_id"),
            lifecycle: row.get("lifecycle"),
            roles: Vec::new(),
        }
    }
}

#[async_trait]
impl AdminRbacStore for PostgresAdminRbacStore {
    async fn authenticate_identity(
        &self,
        deployment_id: &str,
        identity: &str,
        bootstrap_customer_id: Option<&str>,
    ) -> Result<AuthenticateOutcome, AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        Self::ensure_builtin_roles(&mut transaction, deployment_id).await?;

        let user_count: i64 =
            sqlx::query_scalar("SELECT count(*)::bigint FROM admin_users WHERE deployment_id = $1")
                .bind(deployment_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;

        let user = if user_count == 0 {
            let id = Uuid::new_v4();
            let inserted = sqlx::query(
                "INSERT INTO admin_users \
                 (id, deployment_id, login, display_name, customer_id, lifecycle) \
                 VALUES ($1, $2, $3, $4, $5, 'active') \
                 ON CONFLICT (deployment_id, login) DO NOTHING \
                 RETURNING id, login, display_name, customer_id, lifecycle",
            )
            .bind(id)
            .bind(deployment_id)
            .bind(identity)
            .bind(identity)
            .bind(bootstrap_customer_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
            let Some(row) = inserted else {
                // Lost a race with another first login; re-read below.
                transaction
                    .commit()
                    .await
                    .map_err(|_| AdminRbacError::PersistenceFailed)?;
                return Box::pin(self.authenticate_identity(
                    deployment_id,
                    identity,
                    bootstrap_customer_id,
                ))
                .await;
            };
            sqlx::query(
                "INSERT INTO admin_user_roles (user_id, role_id, granted_by) \
                 SELECT $1, id, $3 FROM admin_roles \
                 WHERE deployment_id = $2 AND role_key = $4 \
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(deployment_id)
            .bind("bootstrap")
            .bind(BOOTSTRAP_ROLE)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
            Self::user_from_row(&row)
        } else {
            let row = sqlx::query(
                "SELECT id, login, display_name, customer_id, lifecycle \
                 FROM admin_users WHERE deployment_id = $1 AND login = $2",
            )
            .bind(deployment_id)
            .bind(identity)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
            let Some(row) = row else {
                transaction
                    .commit()
                    .await
                    .map_err(|_| AdminRbacError::PersistenceFailed)?;
                return Ok(AuthenticateOutcome::Unknown);
            };
            let user = Self::user_from_row(&row);
            if user.lifecycle != "active" {
                transaction
                    .commit()
                    .await
                    .map_err(|_| AdminRbacError::PersistenceFailed)?;
                return Ok(AuthenticateOutcome::Suspended);
            }
            user
        };

        let roles = Self::roles_for_user(&mut transaction, deployment_id, user.id).await?;
        let permissions =
            Self::permissions_for_user(&mut transaction, deployment_id, user.id).await?;
        let mut user = user;
        user.roles = roles;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;

        if user_count == 0 {
            Ok(AuthenticateOutcome::Bootstrapped { user, permissions })
        } else {
            Ok(AuthenticateOutcome::Authenticated { user, permissions })
        }
    }

    async fn authenticate_external_identity(
        &self,
        deployment_id: &str,
        subject: &str,
        login_candidates: &[String],
        bootstrap_customer_id: Option<&str>,
    ) -> Result<ExternalAuthOutcome, AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        Self::ensure_builtin_roles(&mut transaction, deployment_id).await?;

        // 1. Exact subject match on an already-linked local account.
        let subject_row = sqlx::query(
            "SELECT id, login, display_name, customer_id, lifecycle \
             FROM admin_users WHERE deployment_id = $1 AND auth_subject = $2",
        )
        .bind(deployment_id)
        .bind(subject)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;

        let mut linked = false;
        let mut bootstrapped = false;
        let user = if let Some(row) = subject_row {
            let user = Self::user_from_row(&row);
            if user.lifecycle != "active" {
                transaction
                    .commit()
                    .await
                    .map_err(|_| AdminRbacError::PersistenceFailed)?;
                return Ok(ExternalAuthOutcome {
                    outcome: AuthenticateOutcome::Suspended,
                    linked: false,
                });
            }
            user
        } else {
            // 2. Link by login candidates among still-unlinked active users.
            //    The `auth_subject IS NULL` guard makes each claim atomic
            //    and never steals an existing link.
            let mut claimed = None;
            for candidate in login_candidates {
                let row = sqlx::query(
                    "UPDATE admin_users SET auth_subject = $3 \
                     WHERE deployment_id = $1 AND lower(login) = $2 \
                       AND auth_subject IS NULL AND lifecycle = 'active' \
                     RETURNING id, login, display_name, customer_id, lifecycle",
                )
                .bind(deployment_id)
                .bind(candidate)
                .bind(subject)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
                if let Some(row) = row {
                    claimed = Some(Self::user_from_row(&row));
                    break;
                }
            }
            if let Some(user) = claimed {
                linked = true;
                user
            } else {
                // 3. First identity of an empty deployment bootstraps the
                //    owner as `BOOTSTRAP_ROLE`.
                let user_count: i64 = sqlx::query_scalar(
                    "SELECT count(*)::bigint FROM admin_users WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
                if user_count > 0 {
                    transaction
                        .commit()
                        .await
                        .map_err(|_| AdminRbacError::PersistenceFailed)?;
                    // 4. Unknown subject: refuse (the caller audits it).
                    return Ok(ExternalAuthOutcome {
                        outcome: AuthenticateOutcome::Unknown,
                        linked: false,
                    });
                }
                let bootstrap_login = login_candidates
                    .first()
                    .map(String::as_str)
                    .filter(|login| valid_login(login))
                    .map(str::to_string)
                    .or_else(|| valid_login(subject).then(|| subject.to_string()));
                let Some(bootstrap_login) = bootstrap_login else {
                    transaction
                        .commit()
                        .await
                        .map_err(|_| AdminRbacError::PersistenceFailed)?;
                    return Ok(ExternalAuthOutcome {
                        outcome: AuthenticateOutcome::Unknown,
                        linked: false,
                    });
                };
                let inserted = sqlx::query(
                    "INSERT INTO admin_users \
                     (id, deployment_id, login, display_name, customer_id, lifecycle, auth_subject) \
                     VALUES ($1, $2, $3, $4, $5, 'active', $6) \
                     ON CONFLICT (deployment_id, login) DO NOTHING \
                     RETURNING id, login, display_name, customer_id, lifecycle",
                )
                .bind(Uuid::new_v4())
                .bind(deployment_id)
                .bind(&bootstrap_login)
                .bind(&bootstrap_login)
                .bind(bootstrap_customer_id)
                .bind(subject)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
                let Some(row) = inserted else {
                    // Lost a race with another first login; re-read once.
                    transaction
                        .commit()
                        .await
                        .map_err(|_| AdminRbacError::PersistenceFailed)?;
                    return Box::pin(self.authenticate_external_identity(
                        deployment_id,
                        subject,
                        login_candidates,
                        bootstrap_customer_id,
                    ))
                    .await;
                };
                sqlx::query(
                    "INSERT INTO admin_user_roles (user_id, role_id, granted_by) \
                     SELECT $1, id, $3 FROM admin_roles \
                     WHERE deployment_id = $2 AND role_key = $4 \
                     ON CONFLICT DO NOTHING",
                )
                .bind(row.get::<Uuid, _>("id"))
                .bind(deployment_id)
                .bind("bootstrap")
                .bind(BOOTSTRAP_ROLE)
                .execute(&mut *transaction)
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
                bootstrapped = true;
                Self::user_from_row(&row)
            }
        };

        let mut user = user;
        user.roles = Self::roles_for_user(&mut transaction, deployment_id, user.id).await?;
        let permissions =
            Self::permissions_for_user(&mut transaction, deployment_id, user.id).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        let outcome = if bootstrapped {
            AuthenticateOutcome::Bootstrapped { user, permissions }
        } else {
            AuthenticateOutcome::Authenticated { user, permissions }
        };
        Ok(ExternalAuthOutcome { outcome, linked })
    }

    async fn create_login_flow(
        &self,
        deployment_id: &str,
        flow: NewLoginFlow,
    ) -> Result<(), AdminRbacError> {
        let NewLoginFlow {
            state_hash,
            nonce,
            code_verifier,
            kind,
            return_to,
            expires_at,
        } = flow;
        let (flow_kind, session_id) = match kind {
            LoginFlowKind::Login => ("login", None),
            LoginFlowKind::Reauth { session_id } => ("reauth", Some(session_id)),
        };
        let mut transaction = self.begin_scoped(deployment_id).await?;
        let inserted = sqlx::query(
            "INSERT INTO oidc_login_flows \
             (deployment_id, state_hash, nonce, code_verifier, flow_kind, session_id, \
              return_to, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8) \
             ON CONFLICT (state_hash) DO NOTHING \
             RETURNING state_hash",
        )
        .bind(deployment_id)
        .bind(&state_hash)
        .bind(&nonce)
        .bind(&code_verifier)
        .bind(flow_kind)
        .bind(session_id)
        .bind(&return_to)
        .bind(expires_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        if inserted.is_none() {
            // Duplicate state: fail closed rather than overwrite a flow.
            return Err(AdminRbacError::PersistenceFailed);
        }
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)
    }

    async fn claim_login_flow(
        &self,
        deployment_id: &str,
        state_hash: &[u8],
    ) -> Result<Option<LoginFlow>, AdminRbacError> {
        let now = Utc::now();
        let mut transaction = self.begin_scoped(deployment_id).await?;
        // Claim-once: the row is deleted, so a replayed callback finds
        // nothing even under concurrent use of the same state.
        let row = sqlx::query(
            "DELETE FROM oidc_login_flows \
             WHERE deployment_id = $1 AND state_hash = $2 AND expires_at > $3 \
             RETURNING nonce, code_verifier, flow_kind, session_id, return_to",
        )
        .bind(deployment_id)
        .bind(state_hash)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(row.map(|row| {
            let kind = match (
                row.get::<String, _>("flow_kind").as_str(),
                row.get::<Option<Uuid>, _>("session_id"),
            ) {
                ("reauth", Some(session_id)) => LoginFlowKind::Reauth { session_id },
                _ => LoginFlowKind::Login,
            };
            LoginFlow {
                nonce: row.get("nonce"),
                code_verifier: row.get("code_verifier"),
                kind,
                return_to: row.get("return_to"),
            }
        }))
    }

    async fn refresh_step_up(
        &self,
        deployment_id: &str,
        session_id: Uuid,
        user_id: Uuid,
        config: &SessionConfig,
        audit: AuditEventDraft,
    ) -> Result<bool, AdminRbacError> {
        let now = Utc::now();
        let idle_cutoff = now - Duration::seconds(config.idle_ttl_secs);
        let mut transaction = self.begin_scoped(deployment_id).await?;
        // One statement enforces the binding (same session, same user)
        // and the liveness conditions together; no refresh otherwise.
        let updated = sqlx::query(
            "UPDATE admin_sessions SET step_up_at = $1 \
             WHERE deployment_id = $2 AND id = $3 AND user_id = $4 \
               AND revoked_at IS NULL AND absolute_expires_at > $1 \
               AND last_seen_at > $5 \
             RETURNING id",
        )
        .bind(now)
        .bind(deployment_id)
        .bind(session_id)
        .bind(user_id)
        .bind(idle_cutoff)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        if updated.is_none() {
            transaction
                .commit()
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            return Ok(false);
        }
        Self::apply_audit_scope(&mut transaction, &audit.subject).await?;
        Self::record_row(&mut transaction, deployment_id, audit, "success", None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(true)
    }

    async fn create_session(
        &self,
        deployment_id: &str,
        session: NewSession,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        sqlx::query(
            "INSERT INTO admin_sessions \
             (id, deployment_id, user_id, token_hash, csrf_token, source_ip, \
              authenticated_at, last_seen_at, absolute_expires_at, step_up_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9)",
        )
        .bind(session.id)
        .bind(deployment_id)
        .bind(session.user_id)
        .bind(&session.token_hash)
        .bind(&session.csrf_token)
        .bind(&session.source_ip)
        .bind(session.authenticated_at)
        .bind(session.absolute_expires_at)
        .bind(session.step_up_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Self::apply_audit_scope(&mut transaction, &audit.subject).await?;
        Self::record_row(&mut transaction, deployment_id, audit, "success", None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)
    }

    async fn resolve_session(
        &self,
        deployment_id: &str,
        token_hash: &[u8],
        config: &SessionConfig,
    ) -> Result<Option<ActiveSession>, AdminRbacError> {
        let now = Utc::now();
        let idle_cutoff = now - Duration::seconds(config.idle_ttl_secs);
        let mut transaction = self.begin_scoped(deployment_id).await?;
        let row = sqlx::query(
            "SELECT session.id, session.user_id, session.csrf_token, \
                    session.authenticated_at, session.absolute_expires_at, \
                    session.step_up_at, admin_user.login, admin_user.customer_id \
             FROM admin_sessions AS session \
             JOIN admin_users AS admin_user ON admin_user.id = session.user_id \
             WHERE session.deployment_id = $1 AND session.token_hash = $2 \
               AND session.revoked_at IS NULL \
               AND session.absolute_expires_at > $3 \
               AND session.last_seen_at > $4 \
               AND admin_user.deployment_id = $1 \
               AND admin_user.lifecycle = 'active'",
        )
        .bind(deployment_id)
        .bind(token_hash)
        .bind(now)
        .bind(idle_cutoff)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        let Some(row) = row else {
            transaction
                .commit()
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            return Ok(None);
        };

        let session_id: Uuid = row.get("id");
        let user_id: Uuid = row.get("user_id");
        let last_touch = sqlx::query_scalar::<_, DateTime<Utc>>(
            "SELECT last_seen_at FROM admin_sessions \
             WHERE deployment_id = $1 AND id = $2",
        )
        .bind(deployment_id)
        .bind(session_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        if last_touch <= now - Duration::seconds(config.touch_after_secs) {
            sqlx::query(
                "UPDATE admin_sessions SET last_seen_at = $1 \
                 WHERE deployment_id = $2 AND id = $3",
            )
            .bind(now)
            .bind(deployment_id)
            .bind(session_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        }

        let roles = Self::roles_for_user(&mut transaction, deployment_id, user_id).await?;
        let actor_permissions =
            Self::permissions_for_user(&mut transaction, deployment_id, user_id).await?;
        // Customer entry never narrows the actor's permissions: the overlay
        // only switches customer scope (display facts ride along).
        let impersonation_row = sqlx::query(
            "SELECT impersonation.id, impersonation.subject_customer_id, \
                    impersonation.reason, impersonation.started_at, \
                    customer.display_name AS customer_display_name, \
                    customer.internal_key AS customer_internal_key, \
                    customer.lifecycle AS customer_lifecycle \
             FROM admin_impersonations AS impersonation \
             LEFT JOIN customers AS customer \
               ON customer.id = impersonation.subject_customer_id \
              AND customer.deployment_id = impersonation.deployment_id \
             WHERE impersonation.deployment_id = $1 AND impersonation.session_id = $2 \
               AND impersonation.ended_at IS NULL",
        )
        .bind(deployment_id)
        .bind(session_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        let impersonation = impersonation_row.map(|row| {
            let customer_id: String = row.get("subject_customer_id");
            let display_name: Option<String> = row.get("customer_display_name");
            ActiveImpersonation {
                id: row.get("id"),
                customer_id,
                customer_display_name: display_name
                    .unwrap_or_else(|| row.get::<String, _>("subject_customer_id")),
                customer_internal_key: row
                    .get::<Option<i64>, _>("customer_internal_key")
                    .unwrap_or(0),
                customer_lifecycle: row
                    .get::<Option<String>, _>("customer_lifecycle")
                    .unwrap_or_else(|| "active".to_string()),
                reason: row.get("reason"),
                started_at: row.get("started_at"),
            }
        });
        let permissions = actor_permissions;
        let active = ActiveSession {
            session_id,
            deployment_id: deployment_id.to_string(),
            user_id,
            login: row.get("login"),
            roles,
            permissions,
            customer_id: row.get("customer_id"),
            csrf_token: row.get("csrf_token"),
            authenticated_at: row.get("authenticated_at"),
            absolute_expires_at: row.get("absolute_expires_at"),
            step_up_at: row.get("step_up_at"),
            impersonation,
        };
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(Some(active))
    }

    async fn revoke_session(
        &self,
        deployment_id: &str,
        session_id: Uuid,
        reason: &str,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        sqlx::query(
            "UPDATE admin_sessions SET revoked_at = $1, revoked_reason = $2 \
             WHERE deployment_id = $3 AND id = $4 AND revoked_at IS NULL",
        )
        .bind(Utc::now())
        .bind(reason)
        .bind(deployment_id)
        .bind(session_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        sqlx::query(
            "UPDATE admin_impersonations \
             SET ended_at = $1, ended_reason = 'session_revoked' \
             WHERE deployment_id = $2 AND session_id = $3 AND ended_at IS NULL",
        )
        .bind(Utc::now())
        .bind(deployment_id)
        .bind(session_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Self::apply_audit_scope(&mut transaction, &audit.subject).await?;
        Self::record_row(&mut transaction, deployment_id, audit, "success", None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)
    }

    async fn list_users(
        &self,
        deployment_id: &str,
        customer_filter: Option<&str>,
    ) -> Result<Vec<AdminUserRecord>, AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        let rows = sqlx::query(
            "SELECT id, login, display_name, customer_id, lifecycle \
             FROM admin_users \
             WHERE deployment_id = $1 AND ($2::text IS NULL OR customer_id = $2) \
             ORDER BY login",
        )
        .bind(deployment_id)
        .bind(customer_filter)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        let mut users: Vec<AdminUserRecord> = rows.iter().map(Self::user_from_row).collect();
        for user in &mut users {
            user.roles = Self::roles_for_user(&mut transaction, deployment_id, user.id).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(users)
    }

    async fn get_user(
        &self,
        deployment_id: &str,
        user_id: Uuid,
    ) -> Result<Option<AdminUserRecord>, AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        let row = sqlx::query(
            "SELECT id, login, display_name, customer_id, lifecycle \
             FROM admin_users WHERE deployment_id = $1 AND id = $2",
        )
        .bind(deployment_id)
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        let Some(row) = row else {
            transaction
                .commit()
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            return Ok(None);
        };
        let mut user = Self::user_from_row(&row);
        user.roles = Self::roles_for_user(&mut transaction, deployment_id, user.id).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(Some(user))
    }

    async fn create_user(
        &self,
        deployment_id: &str,
        user: NewUser,
        mut audit: AuditEventDraft,
    ) -> Result<CreateUserOutcome, AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        let id = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO admin_users \
             (id, deployment_id, login, display_name, customer_id, lifecycle) \
             VALUES ($1, $2, $3, $4, $5, 'active') \
             ON CONFLICT (deployment_id, login) DO NOTHING \
             RETURNING id, login, display_name, customer_id, lifecycle",
        )
        .bind(id)
        .bind(deployment_id)
        .bind(&user.login)
        .bind(&user.display_name)
        .bind(&user.customer_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        let Some(row) = inserted else {
            transaction
                .commit()
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            return Ok(CreateUserOutcome::AlreadyExists);
        };
        let mut record = Self::user_from_row(&row);
        for role_key in &user.roles {
            let granted = sqlx::query(
                "INSERT INTO admin_user_roles (user_id, role_id, granted_by) \
                 SELECT $1, id, $4 FROM admin_roles \
                 WHERE deployment_id = $2 AND role_key = $3 \
                 ON CONFLICT DO NOTHING RETURNING role_id",
            )
            .bind(record.id)
            .bind(deployment_id)
            .bind(role_key)
            .bind(&user.created_by)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
            if granted.is_none() {
                // Unknown role key: treat as a failed change and roll back.
                transaction
                    .rollback()
                    .await
                    .map_err(|_| AdminRbacError::PersistenceFailed)?;
                return Err(AdminRbacError::PersistenceFailed);
            }
            record.roles.push(role_key.clone());
        }
        audit.resource_id = Some(record.id.to_string());
        Self::apply_audit_scope(&mut transaction, &audit.subject).await?;
        Self::record_row(
            &mut transaction,
            deployment_id,
            audit,
            "success",
            Some(serde_json::json!({ "created": true })),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(CreateUserOutcome::Created(record))
    }

    async fn grant_role(
        &self,
        deployment_id: &str,
        user_id: Uuid,
        role_key: &str,
        granted_by: &str,
        audit: AuditEventDraft,
    ) -> Result<RoleMutation, AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        Self::apply_audit_scope(&mut transaction, &audit.subject).await?;
        let inserted = sqlx::query(
            "INSERT INTO admin_user_roles (user_id, role_id, granted_by) \
             SELECT admin_user.id, role.id, $4 \
             FROM admin_users AS admin_user \
             JOIN admin_roles AS role \
               ON role.deployment_id = admin_user.deployment_id AND role.role_key = $3 \
             WHERE admin_user.deployment_id = $1 AND admin_user.id = $2 \
             ON CONFLICT DO NOTHING RETURNING role_id",
        )
        .bind(deployment_id)
        .bind(user_id)
        .bind(role_key)
        .bind(granted_by)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;

        let target_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM admin_users WHERE deployment_id = $1 AND id = $2)",
        )
        .bind(deployment_id)
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        if !target_exists {
            transaction
                .rollback()
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            return Err(AdminRbacError::PersistenceFailed);
        }

        let changed = inserted.is_some();
        let roles = Self::roles_for_user(&mut transaction, deployment_id, user_id).await?;
        Self::record_row(
            &mut transaction,
            deployment_id,
            audit,
            "success",
            Some(serde_json::json!({ "role_key": role_key, "changed": changed })),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(RoleMutation { changed, roles })
    }

    async fn revoke_role(
        &self,
        deployment_id: &str,
        user_id: Uuid,
        role_key: &str,
        audit: AuditEventDraft,
    ) -> Result<RoleMutation, AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        Self::apply_audit_scope(&mut transaction, &audit.subject).await?;
        let target_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM admin_users WHERE deployment_id = $1 AND id = $2)",
        )
        .bind(deployment_id)
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        if !target_exists {
            transaction
                .rollback()
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            return Err(AdminRbacError::PersistenceFailed);
        }
        let deleted = sqlx::query(
            "DELETE FROM admin_user_roles \
             WHERE user_id = $1 \
               AND role_id = (SELECT id FROM admin_roles \
                              WHERE deployment_id = $2 AND role_key = $3)",
        )
        .bind(user_id)
        .bind(deployment_id)
        .bind(role_key)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        let changed = deleted.rows_affected() > 0;
        let roles = Self::roles_for_user(&mut transaction, deployment_id, user_id).await?;
        Self::record_row(
            &mut transaction,
            deployment_id,
            audit,
            "success",
            Some(serde_json::json!({ "role_key": role_key, "changed": changed })),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(RoleMutation { changed, roles })
    }

    async fn start_impersonation(
        &self,
        deployment_id: &str,
        record: NewImpersonation,
        audit: AuditEventDraft,
    ) -> Result<(), AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        let inserted = sqlx::query(
            "INSERT INTO admin_impersonations \
             (id, deployment_id, session_id, actor_user_id, actor_login, \
              subject_user_id, subject_login, subject_customer_id, reason, started_at) \
             SELECT $1, $2, session.id, $3, $4, NULL, NULL, customer.id, $5, $6 \
             FROM admin_sessions AS session \
             CROSS JOIN customers AS customer \
             WHERE session.deployment_id = $2 AND session.id = $7 \
               AND session.user_id = $3 AND session.revoked_at IS NULL \
               AND customer.deployment_id = $2 AND customer.id = $8 \
               AND customer.lifecycle = 'active' \
                AND NOT EXISTS ( \
                    SELECT 1 FROM admin_impersonations AS active \
                    WHERE active.session_id = session.id AND active.ended_at IS NULL \
                ) \
             RETURNING id",
        )
        .bind(record.id)
        .bind(deployment_id)
        .bind(record.actor_user_id)
        .bind(&record.actor_login)
        .bind(&record.reason)
        .bind(record.started_at)
        .bind(record.session_id)
        .bind(&record.customer_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        if inserted.is_none() {
            transaction
                .rollback()
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            return Err(AdminRbacError::PersistenceFailed);
        }
        Self::apply_audit_scope(&mut transaction, &audit.subject).await?;
        Self::record_row(&mut transaction, deployment_id, audit, "success", None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)
    }

    async fn end_impersonation(
        &self,
        deployment_id: &str,
        session_id: Uuid,
        ended_reason: &str,
        audit: AuditEventDraft,
    ) -> Result<bool, AdminRbacError> {
        let mut transaction = self.begin_scoped(deployment_id).await?;
        let ended = sqlx::query(
            "UPDATE admin_impersonations \
             SET ended_at = $1, ended_reason = $2 \
             WHERE deployment_id = $3 AND session_id = $4 AND ended_at IS NULL \
             RETURNING id",
        )
        .bind(Utc::now())
        .bind(ended_reason)
        .bind(deployment_id)
        .bind(session_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminRbacError::PersistenceFailed)?;
        if ended.is_none() {
            transaction
                .commit()
                .await
                .map_err(|_| AdminRbacError::PersistenceFailed)?;
            return Ok(false);
        }
        Self::apply_audit_scope(&mut transaction, &audit.subject).await?;
        Self::record_row(
            &mut transaction,
            deployment_id,
            audit,
            "success",
            Some(serde_json::json!({ "changed": true })),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminRbacError::PersistenceFailed)?;
        Ok(true)
    }

    async fn customer_entry_target(
        &self,
        deployment_id: &str,
        customer_id: &str,
    ) -> Result<Option<CustomerEntryTarget>, AdminRbacError> {
        sqlx::query(
            "SELECT display_name, internal_key, lifecycle \
             FROM customers WHERE deployment_id = $1 AND id = $2",
        )
        .bind(deployment_id)
        .bind(customer_id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| {
            row.map(|row| CustomerEntryTarget {
                display_name: row.get("display_name"),
                internal_key: row.get("internal_key"),
                lifecycle: row.get("lifecycle"),
            })
        })
        .map_err(|_| AdminRbacError::PersistenceFailed)
    }
}

// ---------------------------------------------------------------------------
// Shared router state, boundary middleware and handlers
// ---------------------------------------------------------------------------

struct AdminRbacStateInner {
    token: String,
    store: Arc<dyn AdminRbacStore>,
    audit: Arc<dyn AuditStore>,
    deployment_id: DeploymentId,
    session_config: SessionConfig,
    template: ControlPlaneTemplate,
    identity: IdentityConfig,
    change_limiter: std::sync::Mutex<TokenBucket>,
    impersonation_limiter: std::sync::Mutex<TokenBucket>,
}

/// Fail-closed rate-limit budgets for audited high-risk admin actions.
#[derive(Debug, Clone)]
pub struct AdminRbacRateLimits {
    /// Shared budget for role grants/revokes and user creation.
    pub permission_change: RateLimitConfig,
    /// Stricter budget for starting an impersonation window.
    pub impersonation: RateLimitConfig,
}

impl Default for AdminRbacRateLimits {
    fn default() -> Self {
        Self {
            permission_change: HighRiskLimits::permission_change(),
            impersonation: HighRiskLimits::impersonation_start(),
        }
    }
}

/// Server-side runtime settings for the local auth stack: session
/// lifetimes, fail-closed budgets and the identity-provider mode.
#[derive(Debug, Clone)]
pub struct AdminRbacAuthConfig {
    pub session: SessionConfig,
    pub rate_limits: AdminRbacRateLimits,
    pub identity: IdentityConfig,
}

impl AdminRbacAuthConfig {
    /// Proxy-header identity with default session and rate-limit settings
    /// (development/CI baseline).
    pub fn proxy_header_defaults(session: SessionConfig) -> Self {
        Self {
            session,
            rate_limits: AdminRbacRateLimits::default(),
            identity: IdentityConfig::proxy_header(),
        }
    }
}

/// Shared state for the session/RBAC routes and the local-control boundary
/// middleware that fronts every private control-plane route.
#[derive(Clone)]
pub struct AdminRbacState(Arc<AdminRbacStateInner>);

impl AdminRbacState {
    pub fn with_rate_limit(
        token: String,
        store: Arc<dyn AdminRbacStore>,
        audit: Arc<dyn AuditStore>,
        deployment_id: DeploymentId,
        template: ControlPlaneTemplate,
        auth: AdminRbacAuthConfig,
    ) -> Result<Self, &'static str> {
        if token.len() < 32 || token.contains(['\r', '\n']) {
            return Err("local control token must contain at least 32 safe characters");
        }
        let AdminRbacAuthConfig {
            session: session_config,
            rate_limits: limits,
            identity,
        } = auth;
        Ok(Self(Arc::new(AdminRbacStateInner {
            token,
            store,
            audit,
            deployment_id,
            session_config,
            template,
            identity,
            change_limiter: std::sync::Mutex::new(TokenBucket::new(&limits.permission_change)),
            impersonation_limiter: std::sync::Mutex::new(TokenBucket::new(&limits.impersonation)),
        })))
    }

    pub fn new(
        token: String,
        store: Arc<dyn AdminRbacStore>,
        audit: Arc<dyn AuditStore>,
        deployment_id: DeploymentId,
        template: ControlPlaneTemplate,
        session_config: SessionConfig,
    ) -> Result<Self, &'static str> {
        Self::with_rate_limit(
            token,
            store,
            audit,
            deployment_id,
            template,
            AdminRbacAuthConfig::proxy_header_defaults(session_config),
        )
    }

    pub fn postgres(
        pool: sqlx::PgPool,
        token: String,
        deployment_id: DeploymentId,
        template: ControlPlaneTemplate,
        session_config: SessionConfig,
        identity: IdentityConfig,
    ) -> Result<Self, &'static str> {
        Self::with_rate_limit(
            token,
            Arc::new(PostgresAdminRbacStore::new(pool.clone())),
            Arc::new(PostgresAuditStore::new(pool)),
            deployment_id,
            template,
            AdminRbacAuthConfig {
                session: session_config,
                rate_limits: AdminRbacRateLimits::default(),
                identity,
            },
        )
    }

    /// Server-authoritative identity-provider mode (configuration only).
    fn identity_kind(&self) -> IdentityProviderKind {
        self.0.identity.kind
    }

    /// OIDC settings when the provider mode is `oidc`.
    fn oidc_config(&self) -> Option<&OidcConfig> {
        self.0.identity.oidc.as_ref()
    }

    fn bearer_valid(&self, candidate: &str) -> bool {
        candidate.len() == self.0.token.len()
            && candidate
                .as_bytes()
                .ct_eq(self.0.token.as_bytes())
                .unwrap_u8()
                == 1
    }

    /// High-risk permission change budget (fail closed when exhausted).
    fn change_token_available(&self) -> bool {
        Self::limiter_token_available(&self.0.change_limiter)
    }

    /// Stricter impersonation start budget (fail closed when exhausted).
    fn impersonation_token_available(&self) -> bool {
        Self::limiter_token_available(&self.0.impersonation_limiter)
    }

    fn limiter_token_available(limiter: &std::sync::Mutex<TokenBucket>) -> bool {
        limiter
            .lock()
            .map(|mut bucket| bucket.try_consume())
            .unwrap_or(false)
    }
}

pub fn admin_rbac_router(state: AdminRbacState) -> Router {
    Router::new()
        .route(LOGIN_PATH, get(login_redirect).post(login))
        .route(OIDC_CALLBACK_PATH, get(oidc_callback))
        .route(OIDC_REAUTH_PATH, get(begin_reauth))
        .route("/api/v1/auth/session", get(get_session))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/admin/users", get(list_users).post(create_user))
        .route("/api/v1/admin/users/:user_id", get(get_user))
        .route("/api/v1/admin/users/:user_id/roles", post(grant_role))
        .route(
            "/api/v1/admin/users/:user_id/roles/:role_key",
            delete(revoke_role),
        )
        .route("/api/v1/admin/impersonations", post(start_impersonation))
        .route("/api/v1/admin/impersonations/end", post(end_impersonation))
        .with_state(state)
}

/// Applies the local/dev boundary to a set of private control routes: the
/// workload bearer token proves the request came through the reverse proxy,
/// and an active session cookie (or the login route itself) is required
/// before the server-derived tenant context is injected.
pub fn authenticated_local_router(router: Router, state: AdminRbacState) -> Router {
    router.layer(middleware::from_fn_with_state(state, require_local_auth))
}

async fn require_local_auth(
    State(state): State<AdminRbacState>,
    mut request: axum::http::Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(candidate) = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if !state.bearer_valid(candidate) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // The login entry points and the OIDC callback are protocol navigation
    // targets: they may run without an (old) session cookie, but still
    // require the workload bearer that only the reverse proxy adds. The
    // callback creates nothing until its one-time flow and the ID-token
    // proofs verify; login itself is never CSRF-exempt beyond this.
    let path = request.uri().path();
    let cookie_exempt = (path == LOGIN_PATH
        && matches!(*request.method(), Method::GET | Method::POST))
        || (path == OIDC_CALLBACK_PATH && *request.method() == Method::GET);
    let mutating = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );

    if let Some(token) = session_cookie(request.headers()) {
        let token_hash = hash_token(token);
        let resolved = state
            .0
            .store
            .resolve_session(
                &state.0.deployment_id.0,
                &token_hash,
                &state.0.session_config,
            )
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        match resolved {
            Some(session) => {
                if mutating && path != LOGIN_PATH {
                    let csrf = request
                        .headers()
                        .get(CSRF_HEADER)
                        .and_then(|value| value.to_str().ok());
                    if !csrf_matches(&session.csrf_token, csrf) {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
                let context = build_context(&state, &session, request.headers());
                request.extensions_mut().insert(context);
                request.extensions_mut().insert(session);
            },
            None => {
                if !cookie_exempt {
                    return Err(StatusCode::UNAUTHORIZED);
                }
            },
        }
    } else if !cookie_exempt {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

/// Map a stored customer lifecycle string onto the typed lifecycle.
fn lifecycle_from_db(lifecycle: &str) -> CustomerLifecycle {
    match lifecycle {
        "grace" => CustomerLifecycle::Grace,
        "suspended" => CustomerLifecycle::Suspended,
        "terminated" => CustomerLifecycle::Terminated,
        _ => CustomerLifecycle::Active,
    }
}

fn build_context(
    state: &AdminRbacState,
    session: &ActiveSession,
    headers: &HeaderMap,
) -> TenantContext {
    let correlation = header_str(headers, "x-correlation-id")
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let impersonation = session.impersonation.as_ref().map(|impersonation| {
        ImpersonationContext {
            real_actor: ContextActor {
                actor_id: ActorId(session.user_id),
                login: session.login.clone(),
                roles: session.roles.clone(),
                authentication_assurance: if session
                    .step_up_active(Utc::now(), state.0.session_config.step_up_ttl_secs)
                {
                    AuthenticationAssurance::StepUp
                } else {
                    AuthenticationAssurance::Standard
                },
            },
            // Customer entry has no acted-as subject user; attribution stays
            // with the real actor and the entered customer.
            impersonated_subject: None,
            impersonated_customer: CustomerId(impersonation.customer_id.clone()),
            started_at: impersonation.started_at,
            reason: impersonation.reason.clone(),
            session_id: session.session_id.to_string(),
        }
    });
    TenantContext {
        deployment_id: DeploymentId::new(&session.deployment_id),
        region: state.0.template.region.clone(),
        actor: ContextActor {
            actor_id: ActorId(session.user_id),
            login: session.login.clone(),
            roles: session.roles.clone(),
            authentication_assurance: if session
                .step_up_active(Utc::now(), state.0.session_config.step_up_ttl_secs)
            {
                AuthenticationAssurance::StepUp
            } else {
                AuthenticationAssurance::Standard
            },
        },
        impersonation,
        customer_id: session
            .impersonation
            .as_ref()
            .map(|impersonation| CustomerId(impersonation.customer_id.clone()))
            .unwrap_or_else(|| state.0.template.customer_id.clone()),
        customer_internal_key: session
            .impersonation
            .as_ref()
            .map(|impersonation| impersonation.customer_internal_key)
            .unwrap_or(state.0.template.customer_internal_key),
        customer_display_name: session
            .impersonation
            .as_ref()
            .map(|impersonation| impersonation.customer_display_name.clone())
            .unwrap_or_else(|| state.0.template.customer_display_name.clone()),
        customer_lifecycle: session
            .impersonation
            .as_ref()
            .map(|impersonation| lifecycle_from_db(&impersonation.customer_lifecycle))
            .unwrap_or(state.0.template.customer_lifecycle),
        permissions: session.permissions.clone(),
        config_revision: state.0.template.config_revision,
        trace_id: correlation.clone(),
        correlation_id: correlation,
        session_id: session.session_id.to_string(),
        authenticated_at: session.authenticated_at,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mint_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn csrf_matches(expected: &str, candidate: Option<&str>) -> bool {
    match candidate {
        Some(candidate) if candidate.len() == expected.len() => {
            expected.as_bytes().ct_eq(candidate.as_bytes()).unwrap_u8() == 1
        },
        _ => false,
    }
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let pair = pair.trim();
            if let Some(rest) = pair.strip_prefix(SESSION_COOKIE) {
                if let Some(token) = rest.strip_prefix('=') {
                    if !token.is_empty() {
                        return Some(token);
                    }
                }
            }
        }
    }
    None
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 64)
}

/// The OIDC double-submit flow cookie bound to the browser that started
/// the authorization flow, if present.
fn oidc_flow_cookie(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let pair = pair.trim();
            if let Some(rest) = pair.strip_prefix(OIDC_FLOW_COOKIE) {
                if let Some(token) = rest.strip_prefix('=') {
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }
    }
    None
}

fn identity_from(headers: &HeaderMap) -> Option<String> {
    header_str(headers, IDENTITY_HEADER)
        .map(str::to_string)
        .filter(|identity| {
            identity.len() <= MAX_IDENTITY_LEN
                && !identity
                    .chars()
                    .any(|character| character.is_whitespace() || character.is_control())
        })
}

fn trace_from(headers: &HeaderMap) -> String {
    header_str(headers, "x-correlation-id")
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= MAX_LOGIN_LEN
        && !login
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

fn valid_display_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_DISPLAY_NAME_LEN
        && !name.chars().any(|character| character.is_control())
}

fn subject_from_session(session: &ActiveSession, headers: &HeaderMap) -> AuditSubject {
    // While acting as a Customer Admin the event belongs to the impersonated
    // customer's tenant scope, but attribution stays with the real actor.
    let (customer_id, impersonated_subject, impersonated_customer) =
        match session.impersonation.as_ref() {
            Some(impersonation) => (
                Some(impersonation.customer_id.clone()),
                None,
                Some(impersonation.customer_id.clone()),
            ),
            None => (session.customer_id.clone(), None, None),
        };
    AuditSubject {
        actor_id: session.user_id.to_string(),
        actor_login: session.login.clone(),
        actor_roles: session.roles.clone(),
        customer_id,
        session_id: Some(session.session_id.to_string()),
        source_ip: source_ip_from(headers),
        trace_id: trace_from(headers),
        impersonated_subject,
        impersonated_customer,
    }
}

fn subject_for_identity(identity: &str, deployment_id: &str, headers: &HeaderMap) -> AuditSubject {
    AuditSubject {
        actor_id: Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!("nullapart-rbac-denied:{deployment_id}:{identity}").as_bytes(),
        )
        .to_string(),
        actor_login: identity.to_string(),
        actor_roles: Vec::new(),
        customer_id: None,
        session_id: None,
        source_ip: source_ip_from(headers),
        trace_id: trace_from(headers),
        impersonated_subject: None,
        impersonated_customer: None,
    }
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

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        "Service is unavailable",
    )
}

/// Audits a denial (observability only; the response is a denial either
/// way, so an audit write failure never changes the outcome) and returns
/// the response.
async fn denied(
    state: &AdminRbacState,
    subject: &AuditSubject,
    action: &str,
    resource_id: Option<String>,
    reason: &str,
    code: &'static str,
    message: &'static str,
) -> Response {
    let record = AuditEventDraft {
        subject: subject.clone(),
        action: action.to_string(),
        resource_type: RESOURCE_USER.to_string(),
        resource_id,
        details: serde_json::json!({ "reason": reason }),
    }
    .into_record("denied", None);
    if let Err(error) = state
        .0
        .audit
        .record_event(&state.0.deployment_id.0, record)
        .await
    {
        error!(%error, "failed to audit administrative denial");
    }
    api_error(StatusCode::FORBIDDEN, code, message)
}

/// Validates one high-risk management change: permission, fresh step-up,
/// then the shared fail-closed rate limit (deliberately after permission
/// checks and before any audit or mutation write).
async fn authorize_management_change(
    state: &AdminRbacState,
    context: &TenantContext,
    session: &ActiveSession,
    headers: &HeaderMap,
    action: &'static str,
    resource_id: Option<String>,
) -> Result<(), Response> {
    authorize_change(
        state,
        context,
        session,
        headers,
        action,
        resource_id,
        ChangeGate::UsersManage,
    )
    .await
}

/// Which permission claim and fail-closed budget gates a high-risk action.
enum ChangeGate {
    /// `admin:users:manage` with the shared permission-change budget.
    UsersManage,
    /// `admin:impersonate` with the stricter impersonation budget.
    Impersonate,
}

impl ChangeGate {
    fn permission(&self) -> &'static str {
        match self {
            ChangeGate::UsersManage => ADMIN_USERS_MANAGE_PERMISSION,
            ChangeGate::Impersonate => IMPERSONATE_PERMISSION,
        }
    }
}

/// Shared high-risk gate: required permission, fresh step-up, then the
/// dedicated rate-limit budget — in that order, before any audit write.
async fn authorize_change(
    state: &AdminRbacState,
    context: &TenantContext,
    session: &ActiveSession,
    headers: &HeaderMap,
    action: &'static str,
    resource_id: Option<String>,
    gate: ChangeGate,
) -> Result<(), Response> {
    let required_permission = gate.permission();
    if !context
        .permissions
        .iter()
        .any(|permission| permission == required_permission)
    {
        return Err(denied(
            state,
            &subject_from_session(session, headers),
            action,
            resource_id,
            &format!("missing {required_permission} permission"),
            "FORBIDDEN",
            "Permission is required",
        )
        .await);
    }
    if !session.step_up_active(Utc::now(), state.0.session_config.step_up_ttl_secs) {
        return Err(denied(
            state,
            &subject_from_session(session, headers),
            action,
            resource_id,
            "step-up authentication expired",
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        )
        .await);
    }
    let token_available = match gate {
        ChangeGate::UsersManage => state.change_token_available(),
        ChangeGate::Impersonate => state.impersonation_token_available(),
    };
    if !token_available {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "60")],
            Json(ApiErrorBody {
                code: "RATE_LIMITED",
                message: "Too many high-risk changes",
            }),
        )
            .into_response());
    }
    Ok(())
}

fn can_manage_target(context: &TenantContext, target_customer: Option<&str>) -> bool {
    match target_customer {
        Some(customer_id) => context.customer_id.0 == customer_id,
        None => context
            .actor
            .roles
            .iter()
            .any(|role| role == SYSTEM_ADMIN_ROLE),
    }
}

fn session_cookie_header(token: &str, headers: &HeaderMap) -> header::HeaderValue {
    let secure = header_str(headers, "x-forwarded-proto") == Some("https");
    let mut value = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        8 * 60 * 60
    );
    if secure {
        value.push_str("; Secure");
    }
    header::HeaderValue::from_str(&value).expect("session cookie value is always valid")
}

fn clear_cookie_header() -> header::HeaderValue {
    header::HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
    ))
    .expect("clear cookie value is always valid")
}

fn oidc_flow_cookie_header(state: &str, headers: &HeaderMap) -> header::HeaderValue {
    let secure = header_str(headers, "x-forwarded-proto") == Some("https");
    let mut value = format!(
        "{OIDC_FLOW_COOKIE}={state}; Path={OIDC_CALLBACK_PATH}; HttpOnly; SameSite=Lax; Max-Age={}",
        oidc::OIDC_FLOW_TTL_SECS
    );
    if secure {
        value.push_str("; Secure");
    }
    header::HeaderValue::from_str(&value).expect("oidc flow cookie value is always valid")
}

fn clear_oidc_flow_cookie_header() -> header::HeaderValue {
    header::HeaderValue::from_str(&format!(
        "{OIDC_FLOW_COOKIE}=; Path={OIDC_CALLBACK_PATH}; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .expect("clear oidc flow cookie value is always valid")
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// How a successful login reaches the caller: the JSON contract for the
/// legacy XHR exchange, or a redirect for full-page navigation flows.
#[derive(Debug)]
enum LoginPresentation {
    Json,
    Redirect(String),
}

/// Query parameters accepted by the navigation login entry points.
#[derive(Debug, Default, Deserialize)]
struct LoginQuery {
    #[serde(default)]
    return_to: Option<String>,
}

/// Accepts only same-origin absolute paths (`/…`, ASCII, never `//…`,
/// backslash or control tricks) so a login destination can never leave
/// the app or smuggle header bytes.
fn safe_return_to(candidate: Option<String>) -> String {
    match candidate {
        Some(value)
            if value.starts_with('/')
                && !value.starts_with("//")
                && !value.contains('\\')
                && value.is_ascii()
                && !value.chars().any(char::is_control) =>
        {
            value
        },
        _ => "/".to_string(),
    }
}

/// Shared session establishment for every login path: writes the session
/// and its `session_login` audit event in one transaction, then answers
/// in the caller's presentation.
async fn establish_session(
    state: &AdminRbacState,
    headers: &HeaderMap,
    user: AdminUserRecord,
    permissions: Vec<String>,
    bootstrapped: bool,
    auth_details: serde_json::Value,
    presentation: LoginPresentation,
) -> Response {
    let deployment_id = state.0.deployment_id.0.as_str();
    let now = Utc::now();
    let session_id = Uuid::new_v4();
    let token = mint_token();
    let csrf_token = Uuid::new_v4().simple().to_string();
    let absolute_expires_at = now + Duration::seconds(state.0.session_config.absolute_ttl_secs);
    let source_ip = source_ip_from(headers);
    let mut details = serde_json::json!({
        "identity": user.login.clone(),
        "bootstrapped": bootstrapped,
    });
    if let (Some(base), Some(extra)) = (details.as_object_mut(), auth_details.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    let draft = AuditEventDraft {
        subject: AuditSubject {
            actor_id: user.id.to_string(),
            actor_login: user.login.clone(),
            actor_roles: user.roles.clone(),
            customer_id: user.customer_id.clone(),
            session_id: Some(session_id.to_string()),
            source_ip: source_ip.clone(),
            trace_id: trace_from(headers),
            impersonated_subject: None,
            impersonated_customer: None,
        },
        action: SESSION_LOGIN_ACTION.to_string(),
        resource_type: RESOURCE_SESSION.to_string(),
        resource_id: Some(session_id.to_string()),
        details,
    };
    let created = state
        .0
        .store
        .create_session(
            deployment_id,
            NewSession {
                id: session_id,
                user_id: user.id,
                token_hash: hash_token(&token),
                csrf_token: csrf_token.clone(),
                source_ip,
                authenticated_at: now,
                absolute_expires_at,
                step_up_at: Some(now),
            },
            draft,
        )
        .await;
    if created.is_err() {
        return unavailable();
    }

    let session = ActiveSession {
        session_id,
        deployment_id: deployment_id.to_string(),
        user_id: user.id,
        login: user.login,
        roles: user.roles,
        permissions,
        customer_id: user.customer_id,
        csrf_token,
        authenticated_at: now,
        absolute_expires_at,
        step_up_at: Some(now),
        // A freshly minted session can never have an active impersonation.
        impersonation: None,
    };
    let view = session_view(
        &session,
        &state.0.template,
        state.0.session_config.step_up_ttl_secs,
    );
    match presentation {
        LoginPresentation::Json => (
            StatusCode::OK,
            [(header::SET_COOKIE, session_cookie_header(&token, headers))],
            Json(ApiEnvelope { data: view }),
        )
            .into_response(),
        LoginPresentation::Redirect(target) => {
            let location = header::HeaderValue::from_str(&target)
                .unwrap_or_else(|_| header::HeaderValue::from_static("/"));
            (
                StatusCode::SEE_OTHER,
                [
                    (header::LOCATION, location),
                    (header::SET_COOKIE, session_cookie_header(&token, headers)),
                ],
            )
                .into_response()
        },
    }
}

/// Boundary-header login (development/CI mode): resolve the identity
/// header, map it to a local user, and establish a session.
async fn proxy_login(
    state: &AdminRbacState,
    headers: &HeaderMap,
    presentation: LoginPresentation,
) -> Response {
    let Some(identity) = identity_from(headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let deployment_id = state.0.deployment_id.0.as_str();
    let bootstrap_customer = state.0.template.customer_id.0.as_str();
    let outcome = state
        .0
        .store
        .authenticate_identity(deployment_id, &identity, Some(bootstrap_customer))
        .await;
    let (user, permissions, bootstrapped) = match outcome {
        Ok(AuthenticateOutcome::Authenticated { user, permissions }) => (user, permissions, false),
        Ok(AuthenticateOutcome::Bootstrapped { user, permissions }) => (user, permissions, true),
        Ok(AuthenticateOutcome::Unknown) => {
            return denied(
                state,
                &subject_for_identity(&identity, deployment_id, headers),
                SESSION_LOGIN_ACTION,
                None,
                "identity is not provisioned",
                "FORBIDDEN",
                "Account is not provisioned",
            )
            .await;
        },
        Ok(AuthenticateOutcome::Suspended) => {
            return denied(
                state,
                &subject_for_identity(&identity, deployment_id, headers),
                SESSION_LOGIN_ACTION,
                None,
                "account is suspended",
                "FORBIDDEN",
                "Account is suspended",
            )
            .await;
        },
        Err(_) => return unavailable(),
    };

    establish_session(
        state,
        headers,
        user,
        permissions,
        bootstrapped,
        serde_json::json!({}),
        presentation,
    )
    .await
}

/// POST login: the JSON contract in boundary-header mode; in OIDC mode
/// the exchange carries no identity, so the browser is sent to the GET
/// entry point that starts the authorization-code flow.
async fn login(State(state): State<AdminRbacState>, headers: HeaderMap) -> Response {
    match state.identity_kind() {
        IdentityProviderKind::ProxyHeader => {
            proxy_login(&state, &headers, LoginPresentation::Json).await
        },
        IdentityProviderKind::Oidc => {
            (StatusCode::SEE_OTHER, [(header::LOCATION, LOGIN_PATH)]).into_response()
        },
    }
}

/// GET login (navigation entry): full-page login that finishes with a
/// redirect back into the app (`?return_to=…`, same-origin only).
async fn login_redirect(
    State(state): State<AdminRbacState>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Response {
    let return_to = safe_return_to(query.return_to);
    match state.identity_kind() {
        IdentityProviderKind::ProxyHeader => {
            proxy_login(&state, &headers, LoginPresentation::Redirect(return_to)).await
        },
        IdentityProviderKind::Oidc => {
            begin_oidc_flow(&state, &headers, LoginFlowKind::Login, return_to).await
        },
    }
}

/// Starts an OIDC authorization request: discovery + PKCE, persist the
/// one-time flow keyed by the hashed `state`, redirect the browser to
/// the IdP. Protocol/provider failures are audited before answering.
async fn begin_oidc_flow(
    state: &AdminRbacState,
    headers: &HeaderMap,
    kind: LoginFlowKind,
    return_to: String,
) -> Response {
    let Some(config) = state.oidc_config() else {
        return api_error(
            StatusCode::CONFLICT,
            "IDENTITY_PROVIDER_DISABLED",
            "OIDC is not the configured identity provider",
        );
    };
    let http = match oidc::http_client() {
        Ok(http) => http,
        Err(error) => return oidc_protocol_failure(state, headers, "oidc-start", &error).await,
    };
    let prompt_login = matches!(kind, LoginFlowKind::Reauth { .. });
    match oidc::start_authorization(config, &http, prompt_login).await {
        Ok(start) => {
            let flow = NewLoginFlow {
                state_hash: hash_token(&start.state),
                nonce: start.nonce,
                code_verifier: start.code_verifier,
                kind,
                return_to,
                expires_at: Utc::now() + Duration::seconds(oidc::OIDC_FLOW_TTL_SECS),
            };
            match state
                .0
                .store
                .create_login_flow(&state.0.deployment_id.0, flow)
                .await
            {
                Ok(()) => {
                    let authorize_url = header::HeaderValue::from_str(&start.authorize_url)
                        .expect("authorize URL is always a valid header value");
                    let flow_cookie = oidc_flow_cookie_header(&start.state, headers);
                    (
                        StatusCode::SEE_OTHER,
                        [
                            (header::LOCATION, authorize_url),
                            (header::SET_COOKIE, flow_cookie),
                        ],
                    )
                        .into_response()
                },
                Err(_) => unavailable(),
            }
        },
        Err(error) => oidc_protocol_failure(state, headers, "oidc-start", &error).await,
    }
}

/// Fixed OIDC login outcomes: each carries a non-leaky audit reason and
/// maps to a safe status/code/message, so neither protocol details nor
/// stored data can shape the response.
#[derive(Debug, Clone, Copy)]
enum OidcLoginOutcome {
    /// Infrastructure/provider problem (discovery, network): `failed`, 503.
    ProviderUnavailable(&'static str),
    /// The exchange or assertion failed verification: `denied`, 400.
    ProtocolRejected(&'static str),
    /// Subject has no local account: `denied`, 403.
    NotProvisioned,
    /// Local account exists but is not active: `denied`, 403.
    Suspended,
    /// The step-up target session is gone or expired: `denied`, 401.
    SessionGone,
}

impl OidcLoginOutcome {
    const fn reason(self) -> &'static str {
        match self {
            Self::ProviderUnavailable(reason) => reason,
            Self::ProtocolRejected(reason) => reason,
            Self::NotProvisioned => "identity is not provisioned",
            Self::Suspended => "account is suspended",
            Self::SessionGone => "session is no longer active",
        }
    }

    const fn result(self) -> &'static str {
        match self {
            Self::ProviderUnavailable(_) => "failed",
            _ => "denied",
        }
    }

    const fn response(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::ProviderUnavailable(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "UNAVAILABLE",
                "Service is unavailable",
            ),
            Self::ProtocolRejected(_) => (
                StatusCode::BAD_REQUEST,
                "OIDC_REJECTED",
                "Identity verification failed",
            ),
            Self::NotProvisioned => (
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Account is not provisioned",
            ),
            Self::Suspended => (StatusCode::FORBIDDEN, "FORBIDDEN", "Account is suspended"),
            Self::SessionGone => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHENTICATED",
                "Authentication is required",
            ),
        }
    }
}

/// Records a failed or denied OIDC login attempt with a fixed reason
/// (no codes, tokens or claims reach the audit trail), then returns the
/// caller's response. Observability only, like `denied`.
async fn oidc_login_audit(
    state: &AdminRbacState,
    headers: &HeaderMap,
    identity_hint: &str,
    outcome: OidcLoginOutcome,
) -> Response {
    let record = AuditEventDraft {
        subject: subject_for_identity(identity_hint, &state.0.deployment_id.0, headers),
        action: SESSION_LOGIN_ACTION.to_string(),
        resource_type: RESOURCE_SESSION.to_string(),
        resource_id: None,
        details: serde_json::json!({ "reason": outcome.reason(), "auth_method": "oidc" }),
    }
    .into_record(outcome.result(), None);
    if let Err(error) = state
        .0
        .audit
        .record_event(&state.0.deployment_id.0, record)
        .await
    {
        error!(%error, "failed to audit OIDC login failure");
    }
    let (status, code, message) = outcome.response();
    api_error(status, code, message)
}

/// Audits an OIDC protocol/provider failure with its fixed class
/// (`failed`/`denied`) and maps it to a safe status.
async fn oidc_protocol_failure(
    state: &AdminRbacState,
    headers: &HeaderMap,
    identity_hint: &str,
    error: &OidcError,
) -> Response {
    let outcome = match error {
        OidcError::ProviderUnavailable(reason) => OidcLoginOutcome::ProviderUnavailable(reason),
        OidcError::Rejected(reason) => OidcLoginOutcome::ProtocolRejected(reason),
    };
    oidc_login_audit(state, headers, identity_hint, outcome).await
}

/// OIDC redirect target: proves the one-time flow (state), completes and
/// fully verifies the token exchange (PKCE, nonce, signature, issuer,
/// audience, expiry), then maps the subject to a new session — or, for a
/// re-authentication flow, refreshes step-up freshness on the bound
/// session. Every failure is audited with a fixed reason.
async fn oidc_callback(
    State(state): State<AdminRbacState>,
    Query(query): Query<OidcCallbackQuery>,
    headers: HeaderMap,
) -> Response {
    const NO_SUBJECT: &str = "oidc-callback";
    let Some(config) = state.oidc_config() else {
        return api_error(
            StatusCode::CONFLICT,
            "IDENTITY_PROVIDER_DISABLED",
            "OIDC is not the configured identity provider",
        );
    };
    if query.error.is_some() {
        return oidc_login_audit(
            &state,
            &headers,
            NO_SUBJECT,
            OidcLoginOutcome::ProtocolRejected("identity provider returned an error"),
        )
        .await;
    }
    let (Some(code), Some(raw_state)) = (query.code, query.state) else {
        return oidc_login_audit(
            &state,
            &headers,
            NO_SUBJECT,
            OidcLoginOutcome::ProtocolRejected("callback was missing code or state"),
        )
        .await;
    };
    // Issuer mix-up defence: a supplied `iss` must name our provider.
    if let Some(iss) = query.iss {
        if iss != config.issuer {
            return oidc_login_audit(
                &state,
                &headers,
                NO_SUBJECT,
                OidcLoginOutcome::ProtocolRejected(
                    "callback issuer did not match the configured issuer",
                ),
            )
            .await;
        }
    }
    // Double-submit binding: the callback must come back to the browser that
    // started the flow, otherwise a replayed code/state pair could log a
    // victim into an attacker's session (login CSRF).
    if oidc_flow_cookie(&headers).as_deref() != Some(raw_state.as_str()) {
        return oidc_login_audit(
            &state,
            &headers,
            NO_SUBJECT,
            OidcLoginOutcome::ProtocolRejected("callback did not match the login flow cookie"),
        )
        .await;
    }
    let flow = match state
        .0
        .store
        .claim_login_flow(&state.0.deployment_id.0, &hash_token(&raw_state))
        .await
    {
        Ok(flow) => flow,
        Err(_) => return unavailable(),
    };
    let Some(flow) = flow else {
        return oidc_login_audit(
            &state,
            &headers,
            NO_SUBJECT,
            OidcLoginOutcome::ProtocolRejected("login flow was unknown or expired"),
        )
        .await;
    };
    let http = match oidc::http_client() {
        Ok(http) => http,
        Err(error) => return oidc_protocol_failure(&state, &headers, NO_SUBJECT, &error).await,
    };
    let token =
        match oidc::complete_authorization(config, &http, &code, &flow.code_verifier, &flow.nonce)
            .await
        {
            Ok(token) => token,
            Err(error) => return oidc_protocol_failure(&state, &headers, NO_SUBJECT, &error).await,
        };
    let subject = token.subject.clone();
    let candidates = oidc::login_candidates(&token);
    let bootstrap_customer = state.0.template.customer_id.0.as_str();
    let mapped = match state
        .0
        .store
        .authenticate_external_identity(
            &state.0.deployment_id.0,
            &subject,
            &candidates,
            Some(bootstrap_customer),
        )
        .await
    {
        Ok(mapped) => mapped,
        Err(_) => return unavailable(),
    };
    match flow.kind {
        LoginFlowKind::Login => {
            let ExternalAuthOutcome { outcome, linked } = mapped;
            let (user, permissions, bootstrapped) = match outcome {
                AuthenticateOutcome::Authenticated { user, permissions } => {
                    (user, permissions, false)
                },
                AuthenticateOutcome::Bootstrapped { user, permissions } => {
                    (user, permissions, true)
                },
                AuthenticateOutcome::Unknown => {
                    return oidc_login_audit(
                        &state,
                        &headers,
                        &subject,
                        OidcLoginOutcome::NotProvisioned,
                    )
                    .await;
                },
                AuthenticateOutcome::Suspended => {
                    return oidc_login_audit(
                        &state,
                        &headers,
                        &subject,
                        OidcLoginOutcome::Suspended,
                    )
                    .await;
                },
            };
            let auth_details = serde_json::json!({
                "auth_method": "oidc",
                "auth_subject": subject,
                "linked": linked,
            });
            let mut response = establish_session(
                &state,
                &headers,
                user,
                permissions,
                bootstrapped,
                auth_details,
                LoginPresentation::Redirect(flow.return_to),
            )
            .await;
            response
                .headers_mut()
                .append(header::SET_COOKIE, clear_oidc_flow_cookie_header());
            response
        },
        LoginFlowKind::Reauth { session_id } => {
            let (user, roles, user_id) = match &mapped.outcome {
                AuthenticateOutcome::Authenticated { user, .. }
                | AuthenticateOutcome::Bootstrapped { user, .. } => {
                    (user.login.clone(), user.roles.clone(), user.id)
                },
                AuthenticateOutcome::Unknown => {
                    return oidc_login_audit(
                        &state,
                        &headers,
                        &subject,
                        OidcLoginOutcome::NotProvisioned,
                    )
                    .await;
                },
                AuthenticateOutcome::Suspended => {
                    return oidc_login_audit(
                        &state,
                        &headers,
                        &subject,
                        OidcLoginOutcome::Suspended,
                    )
                    .await;
                },
            };
            let draft = AuditEventDraft {
                subject: AuditSubject {
                    actor_id: user_id.to_string(),
                    actor_login: user,
                    actor_roles: roles,
                    customer_id: None,
                    session_id: Some(session_id.to_string()),
                    source_ip: source_ip_from(&headers),
                    trace_id: trace_from(&headers),
                    impersonated_subject: None,
                    impersonated_customer: None,
                },
                action: SESSION_STEP_UP_ACTION.to_string(),
                resource_type: RESOURCE_SESSION.to_string(),
                resource_id: Some(session_id.to_string()),
                details: serde_json::json!({
                    "auth_method": "oidc",
                    "auth_subject": subject,
                }),
            };
            let refreshed = state
                .0
                .store
                .refresh_step_up(
                    &state.0.deployment_id.0,
                    session_id,
                    user_id,
                    &state.0.session_config,
                    draft,
                )
                .await;
            match refreshed {
                Err(_) => unavailable(),
                Ok(false) => {
                    oidc_login_audit(&state, &headers, &subject, OidcLoginOutcome::SessionGone)
                        .await
                },
                // The refresh and its audit committed together above.
                Ok(true) => {
                    let location = header::HeaderValue::from_str(&flow.return_to)
                        .unwrap_or_else(|_| header::HeaderValue::from_static("/"));
                    (
                        StatusCode::SEE_OTHER,
                        [
                            (header::LOCATION, location),
                            (header::SET_COOKIE, clear_oidc_flow_cookie_header()),
                        ],
                    )
                        .into_response()
                },
            }
        },
    }
}

/// Step-up re-authentication entry point for an existing session: the
/// boundary mode simply re-runs the header exchange; OIDC mode forces an
/// interactive IdP prompt (`prompt=login`) bound to this session.
async fn begin_reauth(
    State(state): State<AdminRbacState>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
    session: Option<Extension<ActiveSession>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let return_to = safe_return_to(query.return_to);
    match state.identity_kind() {
        IdentityProviderKind::ProxyHeader => {
            proxy_login(&state, &headers, LoginPresentation::Redirect(return_to)).await
        },
        IdentityProviderKind::Oidc => {
            begin_oidc_flow(
                &state,
                &headers,
                LoginFlowKind::Reauth {
                    session_id: session.session_id,
                },
                return_to,
            )
            .await
        },
    }
}

/// Query echoed by the OIDC provider on the redirect callback.
#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

async fn get_session(
    State(state): State<AdminRbacState>,
    session: Option<Extension<ActiveSession>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let view = session_view(
        &session,
        &state.0.template,
        state.0.session_config.step_up_ttl_secs,
    );
    (StatusCode::OK, Json(ApiEnvelope { data: view })).into_response()
}

async fn logout(
    State(state): State<AdminRbacState>,
    headers: HeaderMap,
    session: Option<Extension<ActiveSession>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let draft = AuditEventDraft {
        subject: subject_from_session(&session, &headers),
        action: SESSION_LOGOUT_ACTION.to_string(),
        resource_type: RESOURCE_SESSION.to_string(),
        resource_id: Some(session.session_id.to_string()),
        details: serde_json::json!({}),
    };
    match state
        .0
        .store
        .revoke_session(
            &state.0.deployment_id.0,
            session.session_id,
            "user logout",
            draft,
        )
        .await
    {
        // Local revocation above is the security control; the IdP logout
        // URL is best-effort discovery so the browser can also end its
        // IdP session (availability only, never required for safety).
        Ok(()) => {
            let idp_logout_url = match (state.identity_kind(), state.oidc_config()) {
                (IdentityProviderKind::Oidc, Some(config)) => match oidc::http_client() {
                    Ok(http) => oidc::end_session_url(config, &http).await,
                    Err(_) => None,
                },
                _ => None,
            };
            (
                StatusCode::OK,
                [(header::SET_COOKIE, clear_cookie_header())],
                Json(ApiEnvelope {
                    data: serde_json::json!({
                        "authenticated": false,
                        "idpLogoutUrl": idp_logout_url,
                    }),
                }),
            )
                .into_response()
        },
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::SET_COOKIE, clear_cookie_header())],
            Json(ApiErrorBody {
                code: "UNAVAILABLE",
                message: "Service is unavailable",
            }),
        )
            .into_response(),
    }
}

async fn list_users(
    State(state): State<AdminRbacState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    session: Option<Extension<ActiveSession>>,
) -> Response {
    let (Some(Extension(context)), Some(Extension(session))) = (context, session) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !context.permissions.iter().any(|permission| {
        permission == ADMIN_USERS_MANAGE_PERMISSION || permission == IMPERSONATE_PERMISSION
    }) {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            USER_LIST_ACTION,
            None,
            "missing admin:users:manage permission",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }
    let customer_filter = if context
        .actor
        .roles
        .iter()
        .any(|role| role == SYSTEM_ADMIN_ROLE)
    {
        None
    } else {
        Some(context.customer_id.0.as_str())
    };
    match state
        .0
        .store
        .list_users(&state.0.deployment_id.0, customer_filter)
        .await
    {
        Ok(users) => (StatusCode::OK, Json(ApiEnvelope { data: users })).into_response(),
        Err(_) => unavailable(),
    }
}

async fn get_user(
    State(state): State<AdminRbacState>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    session: Option<Extension<ActiveSession>>,
) -> Response {
    let (Some(Extension(context)), Some(Extension(session))) = (context, session) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !context
        .permissions
        .iter()
        .any(|permission| permission == ADMIN_USERS_MANAGE_PERMISSION)
    {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            USER_LIST_ACTION,
            Some(user_id.to_string()),
            "missing admin:users:manage permission",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }
    match state
        .0
        .store
        .get_user(&state.0.deployment_id.0, user_id)
        .await
    {
        Ok(Some(user)) if can_manage_target(&context, user.customer_id.as_deref()) => {
            (StatusCode::OK, Json(ApiEnvelope { data: user })).into_response()
        },
        Ok(Some(_)) => {
            denied(
                &state,
                &subject_from_session(&session, &headers),
                USER_LIST_ACTION,
                Some(user_id.to_string()),
                "target user outside management scope",
                "FORBIDDEN",
                "Permission is required",
            )
            .await
        },
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Admin user was not found",
        ),
        Err(_) => unavailable(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserBody {
    login: String,
    display_name: String,
    customer_id: Option<String>,
    roles: Vec<String>,
}

async fn create_user(
    State(state): State<AdminRbacState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    session: Option<Extension<ActiveSession>>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let (Some(Extension(context)), Some(Extension(session))) = (context, session) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let login = body.login.trim();
    if !valid_login(login)
        || !valid_display_name(body.display_name.trim())
        || body.roles.is_empty()
        || body.roles.iter().any(|role| !is_builtin_role(role))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        );
    }
    if let Err(response) = authorize_management_change(
        &state,
        &context,
        &session,
        &headers,
        USER_CREATE_ACTION,
        None,
    )
    .await
    {
        return response;
    }
    if !roles_within_grantor_level(&session.roles, &body.roles) {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            USER_CREATE_ACTION,
            None,
            "cannot grant a role above own level",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }
    let is_system_admin = context
        .actor
        .roles
        .iter()
        .any(|role| role == SYSTEM_ADMIN_ROLE);
    match body.customer_id.as_deref() {
        Some(customer_id) if customer_id != context.customer_id.0 => {
            return denied(
                &state,
                &subject_from_session(&session, &headers),
                USER_CREATE_ACTION,
                None,
                "customer scope mismatch",
                "FORBIDDEN",
                "Permission is required",
            )
            .await;
        },
        None if !is_system_admin => {
            return denied(
                &state,
                &subject_from_session(&session, &headers),
                USER_CREATE_ACTION,
                None,
                "platform user creation requires the system_admin role",
                "FORBIDDEN",
                "Permission is required",
            )
            .await;
        },
        _ => {},
    }

    let mut roles = body.roles.clone();
    roles.sort();
    roles.dedup();
    let draft = AuditEventDraft {
        subject: subject_from_session(&session, &headers),
        action: USER_CREATE_ACTION.to_string(),
        resource_type: RESOURCE_USER.to_string(),
        resource_id: None,
        details: serde_json::json!({
            "login": login,
            "roles": roles,
            "customer_id": body.customer_id,
        }),
    };
    match state
        .0
        .store
        .create_user(
            &state.0.deployment_id.0,
            NewUser {
                login: login.to_string(),
                display_name: body.display_name.trim().to_string(),
                customer_id: body.customer_id.clone(),
                roles,
                created_by: session.login.clone(),
            },
            draft,
        )
        .await
    {
        Ok(CreateUserOutcome::Created(user)) => {
            (StatusCode::CREATED, Json(ApiEnvelope { data: user })).into_response()
        },
        Ok(CreateUserOutcome::AlreadyExists) => api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Admin user already exists",
        ),
        Err(_) => unavailable(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleBody {
    role_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoleMutationResponse {
    changed: bool,
    roles: Vec<String>,
}

async fn grant_role(
    State(state): State<AdminRbacState>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    session: Option<Extension<ActiveSession>>,
    Json(body): Json<RoleBody>,
) -> Response {
    let (Some(Extension(context)), Some(Extension(session))) = (context, session) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !is_builtin_role(&body.role_key) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        );
    }
    if let Err(response) = authorize_management_change(
        &state,
        &context,
        &session,
        &headers,
        ROLE_GRANT_ACTION,
        Some(user_id.to_string()),
    )
    .await
    {
        return response;
    }
    let target = match state
        .0
        .store
        .get_user(&state.0.deployment_id.0, user_id)
        .await
    {
        Ok(Some(target)) => target,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Admin user was not found",
            )
        },
        Err(_) => return unavailable(),
    };
    if target.id == session.user_id {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            ROLE_GRANT_ACTION,
            Some(user_id.to_string()),
            "cannot modify own roles",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }
    if !can_manage_target(&context, target.customer_id.as_deref()) {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            ROLE_GRANT_ACTION,
            Some(user_id.to_string()),
            "target user outside management scope",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }
    if !roles_within_grantor_level(&session.roles, std::slice::from_ref(&body.role_key)) {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            ROLE_GRANT_ACTION,
            Some(user_id.to_string()),
            "cannot grant a role above own level",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }

    let draft = AuditEventDraft {
        subject: subject_from_session(&session, &headers),
        action: ROLE_GRANT_ACTION.to_string(),
        resource_type: RESOURCE_USER.to_string(),
        resource_id: Some(user_id.to_string()),
        details: serde_json::json!({ "target_login": target.login }),
    };
    match state
        .0
        .store
        .grant_role(
            &state.0.deployment_id.0,
            user_id,
            &body.role_key,
            &session.login,
            draft,
        )
        .await
    {
        Ok(mutation) => (
            StatusCode::OK,
            Json(ApiEnvelope {
                data: RoleMutationResponse {
                    changed: mutation.changed,
                    roles: mutation.roles,
                },
            }),
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

async fn revoke_role(
    State(state): State<AdminRbacState>,
    Path((user_id, role_key)): Path<(Uuid, String)>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    session: Option<Extension<ActiveSession>>,
) -> Response {
    let (Some(Extension(context)), Some(Extension(session))) = (context, session) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if !is_builtin_role(&role_key) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        );
    }
    if let Err(response) = authorize_management_change(
        &state,
        &context,
        &session,
        &headers,
        ROLE_REVOKE_ACTION,
        Some(user_id.to_string()),
    )
    .await
    {
        return response;
    }
    let target = match state
        .0
        .store
        .get_user(&state.0.deployment_id.0, user_id)
        .await
    {
        Ok(Some(target)) => target,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Admin user was not found",
            )
        },
        Err(_) => return unavailable(),
    };
    if target.id == session.user_id {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            ROLE_REVOKE_ACTION,
            Some(user_id.to_string()),
            "cannot modify own roles",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }
    if !can_manage_target(&context, target.customer_id.as_deref()) {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            ROLE_REVOKE_ACTION,
            Some(user_id.to_string()),
            "target user outside management scope",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }

    if !roles_within_grantor_level(&session.roles, std::slice::from_ref(&role_key)) {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            ROLE_REVOKE_ACTION,
            Some(user_id.to_string()),
            "cannot revoke a role above own level",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }

    let draft = AuditEventDraft {
        subject: subject_from_session(&session, &headers),
        action: ROLE_REVOKE_ACTION.to_string(),
        resource_type: RESOURCE_USER.to_string(),
        resource_id: Some(user_id.to_string()),
        details: serde_json::json!({ "target_login": target.login }),
    };
    match state
        .0
        .store
        .revoke_role(&state.0.deployment_id.0, user_id, &role_key, draft)
        .await
    {
        Ok(mutation) => (
            StatusCode::OK,
            Json(ApiEnvelope {
                data: RoleMutationResponse {
                    changed: mutation.changed,
                    roles: mutation.roles,
                },
            }),
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

// ---------------------------------------------------------------------------
// Impersonation (docs/03-IDENTITY-RBAC-IMPERSONATION.md)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartImpersonationBody {
    customer_id: String,
    reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EndImpersonationResponse {
    ended: bool,
}

async fn start_impersonation(
    State(state): State<AdminRbacState>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    session: Option<Extension<ActiveSession>>,
    Json(body): Json<StartImpersonationBody>,
) -> Response {
    let (Some(Extension(context)), Some(Extension(session))) = (context, session) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let reason = body.reason.trim();
    if reason.len() < MIN_IMPERSONATION_REASON_LEN || reason.len() > MAX_IMPERSONATION_REASON_LEN {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        );
    }
    let customer_id = body.customer_id.trim();
    if customer_id.is_empty()
        || customer_id.len() > 64
        || customer_id
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        );
    }
    if session.impersonation.is_some() {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Customer entry is already active for this session",
        );
    }
    if let Err(response) = authorize_change(
        &state,
        &context,
        &session,
        &headers,
        IMPERSONATION_START_ACTION,
        Some(customer_id.to_string()),
        ChangeGate::Impersonate,
    )
    .await
    {
        return response;
    }
    let target = match state
        .0
        .store
        .customer_entry_target(&state.0.deployment_id.0, customer_id)
        .await
    {
        Ok(Some(target)) => target,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Customer was not found"),
        Err(_) => return unavailable(),
    };
    if target.lifecycle != "active" {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            IMPERSONATION_START_ACTION,
            Some(customer_id.to_string()),
            "customer is not active",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }
    let started_at = Utc::now();
    let impersonation_id = Uuid::new_v4();
    let view = SessionImpersonationView {
        id: impersonation_id.to_string(),
        customer_id: customer_id.to_string(),
        customer_display_name: target.display_name.clone(),
        reason: reason.to_string(),
        started_at: started_at.to_rfc3339(),
    };
    let record = NewImpersonation {
        id: impersonation_id,
        session_id: session.session_id,
        actor_user_id: session.user_id,
        actor_login: session.login.clone(),
        customer_id: customer_id.to_string(),
        reason: reason.to_string(),
        started_at,
    };
    let draft = AuditEventDraft {
        subject: {
            // The overlay is only visible to later requests, so this row
            // attributes the entered customer explicitly. The real actor's
            // permissions and identity stay untouched.
            let mut subject = subject_from_session(&session, &headers);
            subject.customer_id = Some(customer_id.to_string());
            subject.impersonated_subject = None;
            subject.impersonated_customer = Some(customer_id.to_string());
            subject
        },
        action: IMPERSONATION_START_ACTION.to_string(),
        resource_type: RESOURCE_IMPERSONATION.to_string(),
        resource_id: Some(impersonation_id.to_string()),
        details: serde_json::json!({
            "reason": record.reason,
            "customer_id": customer_id,
            "customer_display_name": target.display_name,
        }),
    };
    if state
        .0
        .store
        .start_impersonation(&state.0.deployment_id.0, record, draft)
        .await
        .is_err()
    {
        return unavailable();
    }
    (StatusCode::OK, Json(ApiEnvelope { data: view })).into_response()
}

async fn end_impersonation(
    State(state): State<AdminRbacState>,
    headers: HeaderMap,
    session: Option<Extension<ActiveSession>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    // Ending entry must always stay possible for the real actor, so this
    // gate checks the actor's own roles (entry never changes them) and skips
    // the step-up and rate-limit budgets.
    let real_permissions = permissions_for_roles(&session.roles);
    if !real_permissions
        .iter()
        .any(|permission| permission == IMPERSONATE_PERMISSION)
    {
        return denied(
            &state,
            &subject_from_session(&session, &headers),
            IMPERSONATION_END_ACTION,
            session
                .impersonation
                .as_ref()
                .map(|entry| entry.id.to_string()),
            "missing admin:impersonate permission",
            "FORBIDDEN",
            "Permission is required",
        )
        .await;
    }
    let Some(impersonation) = session.impersonation.as_ref() else {
        return (
            StatusCode::OK,
            Json(ApiEnvelope {
                data: EndImpersonationResponse { ended: false },
            }),
        )
            .into_response();
    };
    let draft = AuditEventDraft {
        subject: subject_from_session(&session, &headers),
        action: IMPERSONATION_END_ACTION.to_string(),
        resource_type: RESOURCE_IMPERSONATION.to_string(),
        resource_id: Some(impersonation.id.to_string()),
        details: serde_json::json!({
            "customer_id": impersonation.customer_id,
            "customer_display_name": impersonation.customer_display_name,
            "changed": true,
        }),
    };
    match state
        .0
        .store
        .end_impersonation(
            &state.0.deployment_id.0,
            session.session_id,
            "manual",
            draft,
        )
        .await
    {
        Ok(ended) => (
            StatusCode::OK,
            Json(ApiEnvelope {
                data: EndImpersonationResponse { ended },
            }),
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::admin_audit::InMemoryAuditStore;
    use crate::oidc::testkit::MockIdp;

    const TOKEN: &str = "test-local-control-token-abcdef0123456789";

    struct Fixture {
        state: AdminRbacState,
        store: Arc<InMemoryAdminRbacStore>,
        audit: Arc<InMemoryAuditStore>,
    }

    fn fixture(
        config: SessionConfig,
        change_limit: RateLimitConfig,
        impersonation_limit: RateLimitConfig,
    ) -> Fixture {
        fixture_with_identity(
            config,
            change_limit,
            impersonation_limit,
            IdentityConfig::proxy_header(),
        )
    }

    /// Like [`fixture`], but with an explicit identity-provider mode so
    /// OIDC-mode behaviour can be exercised against the memory store.
    fn fixture_with_identity(
        config: SessionConfig,
        change_limit: RateLimitConfig,
        impersonation_limit: RateLimitConfig,
        identity: IdentityConfig,
    ) -> Fixture {
        let audit = Arc::new(InMemoryAuditStore::new());
        let store = Arc::new(InMemoryAdminRbacStore::new(audit.clone()));
        store.seed_customer(
            "TEST-DEPLOYMENT",
            "test-customer",
            "Test Customer",
            "active",
        );
        store.seed_customer(
            "TEST-DEPLOYMENT",
            "retired-customer",
            "Retired Customer",
            "suspended",
        );
        let state = AdminRbacState::with_rate_limit(
            TOKEN.to_string(),
            store.clone(),
            audit.clone(),
            DeploymentId::new("TEST-DEPLOYMENT"),
            ControlPlaneTemplate {
                region: RegionId::new("local"),
                customer_id: CustomerId::new("test-customer"),
                customer_internal_key: 1,
                customer_display_name: "Test Customer".to_string(),
                customer_lifecycle: CustomerLifecycle::Active,
                config_revision: 1,
            },
            AdminRbacAuthConfig {
                session: config,
                rate_limits: AdminRbacRateLimits {
                    permission_change: change_limit,
                    impersonation: impersonation_limit,
                },
                identity,
            },
        )
        .expect("test token is valid");
        Fixture {
            state,
            store,
            audit,
        }
    }

    fn default_fixture() -> Fixture {
        fixture(
            SessionConfig::default(),
            HighRiskLimits::permission_change(),
            HighRiskLimits::impersonation_start(),
        )
    }

    fn app(fixture: &Fixture) -> Router {
        authenticated_local_router(
            admin_rbac_router(fixture.state.clone()),
            fixture.state.clone(),
        )
    }

    fn bearer(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.header("authorization", format!("Bearer {TOKEN}"))
    }

    fn login_request(identity: Option<&str>) -> Request<Body> {
        let mut builder = bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/auth/login");
        if let Some(identity) = identity {
            builder = builder.header("x-nullapart-local-user", identity);
        }
        builder.body(Body::empty()).expect("request builds")
    }

    async fn read_body(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    fn set_cookie_of(response: &Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .expect("session cookie is set")
            .to_str()
            .expect("cookie is ascii")
            .to_string()
    }

    /// The first `Set-Cookie` pair when it is the session cookie, else `None`.
    fn session_cookie_of(response: &Response) -> Option<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(&format!("{SESSION_COOKIE}=")))
            .map(|value| value.split(';').next().expect("cookie pair").to_string())
    }

    async fn login(app: &Router, identity: &str) -> (String, String) {
        let response = app
            .clone()
            .oneshot(login_request(Some(identity)))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = set_cookie_of(&response)
            .split(';')
            .next()
            .expect("cookie pair")
            .to_string();
        let body = read_body(response).await;
        let csrf = serde_json::from_str::<serde_json::Value>(&body).expect("session json")["data"]
            ["csrfToken"]
            .as_str()
            .expect("csrf token")
            .to_string();
        (cookie, csrf)
    }

    fn grant_request(cookie: &str, csrf: Option<&str>, user_id: Uuid, role: &str) -> Request<Body> {
        let mut builder = bearer(Request::builder())
            .method("POST")
            .uri(format!("/api/v1/admin/users/{user_id}/roles"))
            .header("cookie", cookie)
            .header("content-type", "application/json");
        if let Some(csrf) = csrf {
            builder = builder.header("x-csrf-token", csrf);
        }
        builder
            .body(Body::from(format!(r#"{{"roleKey":"{role}"}}"#)))
            .expect("request builds")
    }

    fn session_request(cookie: Option<&str>) -> Request<Body> {
        let mut builder = bearer(Request::builder())
            .method("GET")
            .uri("/api/v1/auth/session");
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", cookie);
        }
        builder.body(Body::empty()).expect("request builds")
    }

    fn logout_request(cookie: &str, csrf: &str) -> Request<Body> {
        bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/auth/logout")
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
            .body(Body::empty())
            .expect("request builds")
    }

    #[tokio::test]
    async fn boundary_requires_workload_bearer() {
        let fixture = default_fixture();
        // No bearer: rejected before any identity handling.
        let no_bearer = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("x-nullapart-local-user", "admin@example.test")
            .body(Body::empty())
            .expect("request builds");
        let response = app(&fixture)
            .oneshot(no_bearer)
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(fixture.audit.records().is_empty());
    }

    #[tokio::test]
    async fn login_requires_identity_header() {
        let fixture = default_fixture();
        let response = app(&fixture)
            .oneshot(login_request(None))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(fixture.audit.records().is_empty());
    }

    #[tokio::test]
    async fn unknown_identity_is_denied_and_audited() {
        let fixture = default_fixture();
        let app = app(&fixture);
        // First identity bootstraps the deployment...
        login(&app, "admin@example.test").await;
        // ...so a later unprovisioned identity is a denial, not a bootstrap.
        let response = app
            .clone()
            .oneshot(login_request(Some("stranger@example.test")))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].action, SESSION_LOGIN_ACTION);
        assert_eq!(events[1].result, "denied");
        assert_eq!(events[1].details["reason"], "identity is not provisioned");
        assert_eq!(events[1].customer_id, None);
    }

    #[tokio::test]
    async fn first_login_bootstraps_admin_and_sets_hardened_cookie() {
        let fixture = default_fixture();
        let response = app(&fixture)
            .oneshot(login_request(Some("admin@example.test")))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = set_cookie_of(&response);
        assert!(cookie.starts_with("nullapart_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(
            !cookie.contains("Secure"),
            "plain http must not mark Secure"
        );

        let body = read_body(response).await;
        assert!(body.contains("\"roles\":[\"system_admin\"]"));
        assert!(body.contains("\"permissions\":["));
        assert!(body.contains("admin:users:manage"));
        assert!(body.contains("\"stepUpActive\":true"));

        let events = fixture.audit.records();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, SESSION_LOGIN_ACTION);
        assert_eq!(events[0].result, "success");
        assert_eq!(events[0].details["bootstrapped"], true);
        assert_eq!(events[0].resource_type, RESOURCE_SESSION);
    }

    #[tokio::test]
    async fn second_login_is_authenticated_not_bootstrapped() {
        let fixture = default_fixture();
        let app = app(&fixture);
        login(&app, "admin@example.test").await;
        login(&app, "admin@example.test").await;
        let events = fixture.audit.records();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].details["bootstrapped"], false);
    }

    #[tokio::test]
    async fn session_endpoint_projects_permissions_with_cookie() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (cookie, csrf) = login(&app, "admin@example.test").await;
        let response = app
            .clone()
            .oneshot(session_request(Some(&cookie)))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(body.contains("\"authenticated\":true"));
        assert!(body.contains("audit:view"));
        assert!(body.contains("csrfToken"));
        assert!(body.contains(&csrf));
    }

    #[tokio::test]
    async fn session_endpoint_requires_cookie() {
        let fixture = default_fixture();
        let response = app(&fixture)
            .clone()
            .oneshot(session_request(None))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_revokes_session_and_is_audited() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (cookie, csrf) = login(&app, "admin@example.test").await;
        let response = app
            .clone()
            .oneshot(logout_request(&cookie, &csrf))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(set_cookie_of(&response).contains("Max-Age=0"));

        let response = app
            .clone()
            .oneshot(session_request(Some(&cookie)))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let events = fixture.audit.records();
        assert!(events
            .iter()
            .any(|event| event.action == SESSION_LOGOUT_ACTION && event.result == "success"));
    }

    #[tokio::test]
    async fn mutating_requests_require_csrf_header() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (cookie, _) = login(&app, "admin@example.test").await;
        let target = fixture
            .store
            .list_users("TEST-DEPLOYMENT", None)
            .await
            .expect("lists");
        let other = fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "other@example.test",
            "Other",
            Some("test-customer"),
            "active",
            &[],
        );
        assert_ne!(other, target[0].id);
        let response = app
            .clone()
            .oneshot(grant_request(&cookie, None, other, CUSTOMER_ADMIN_ROLE))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(fixture
            .audit
            .records()
            .iter()
            .all(|event| event.action == SESSION_LOGIN_ACTION));
    }

    #[tokio::test]
    async fn expired_absolute_session_is_rejected() {
        let config = SessionConfig {
            absolute_ttl_secs: 0,
            ..SessionConfig::default()
        };
        let fixture = fixture(
            config,
            HighRiskLimits::permission_change(),
            HighRiskLimits::impersonation_start(),
        );
        let app = app(&fixture);
        let (cookie, _) = login(&app, "admin@example.test").await;
        let response = app
            .clone()
            .oneshot(session_request(Some(&cookie)))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn suspended_identity_cannot_login() {
        let fixture = default_fixture();
        fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "suspended@example.test",
            "Suspended",
            Some("test-customer"),
            "suspended",
            &[CUSTOMER_ADMIN_ROLE],
        );
        let response = app(&fixture)
            .oneshot(login_request(Some("suspended@example.test")))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result, "denied");
        assert_eq!(events[0].details["reason"], "account is suspended");
    }

    #[tokio::test]
    async fn management_change_without_permission_is_denied_and_audited() {
        let fixture = default_fixture();
        let app = app(&fixture);
        fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "support@example.test",
            "Support",
            Some("test-customer"),
            "active",
            &[SUPPORT_ROLE],
        );
        let target = fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "target@example.test",
            "Target",
            Some("test-customer"),
            "active",
            &[],
        );
        let (cookie, csrf) = login(&app, "support@example.test").await;
        let response = app
            .clone()
            .oneshot(grant_request(
                &cookie,
                Some(&csrf),
                target,
                CUSTOMER_ADMIN_ROLE,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == ROLE_GRANT_ACTION
                && event.result == "denied"
                && event.details["reason"] == "missing admin:users:manage permission"
        }));
    }

    #[tokio::test]
    async fn management_change_requires_fresh_step_up() {
        let config = SessionConfig {
            step_up_ttl_secs: 0,
            ..SessionConfig::default()
        };
        let fixture = fixture(
            config,
            HighRiskLimits::permission_change(),
            HighRiskLimits::impersonation_start(),
        );
        let app = app(&fixture);
        let (cookie, csrf) = login(&app, "admin@example.test").await;
        let target = fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "target@example.test",
            "Target",
            Some("test-customer"),
            "active",
            &[],
        );
        let response = app
            .clone()
            .oneshot(grant_request(
                &cookie,
                Some(&csrf),
                target,
                CUSTOMER_ADMIN_ROLE,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == ROLE_GRANT_ACTION
                && event.result == "denied"
                && event.details["reason"] == "step-up authentication expired"
        }));
    }

    #[tokio::test]
    async fn rate_limited_change_returns_429_without_extra_audit() {
        let limit = RateLimitConfig {
            max_tokens: 1,
            refill_rate_per_sec: 0.0,
            ..HighRiskLimits::permission_change()
        };
        let fixture = fixture(
            SessionConfig::default(),
            limit,
            HighRiskLimits::impersonation_start(),
        );
        let app = app(&fixture);
        let (cookie, csrf) = login(&app, "admin@example.test").await;
        let first = fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "first@example.test",
            "First",
            Some("test-customer"),
            "active",
            &[],
        );
        let second = fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "second@example.test",
            "Second",
            Some("test-customer"),
            "active",
            &[],
        );

        let response = app
            .clone()
            .oneshot(grant_request(
                &cookie,
                Some(&csrf),
                first,
                CUSTOMER_ADMIN_ROLE,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(grant_request(
                &cookie,
                Some(&csrf),
                second,
                CUSTOMER_ADMIN_ROLE,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let events = fixture.audit.records();
        let grants = events
            .iter()
            .filter(|event| event.action == ROLE_GRANT_ACTION)
            .count();
        assert_eq!(grants, 1, "429 must not write an audit row");
    }

    #[tokio::test]
    async fn role_grant_is_idempotent_and_audited_with_change_flag() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (cookie, csrf) = login(&app, "admin@example.test").await;
        let target = fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "target@example.test",
            "Target",
            Some("test-customer"),
            "active",
            &[],
        );

        let response = app
            .clone()
            .oneshot(grant_request(
                &cookie,
                Some(&csrf),
                target,
                CUSTOMER_ADMIN_ROLE,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(body.contains("\"changed\":true"));

        let response = app
            .clone()
            .oneshot(grant_request(
                &cookie,
                Some(&csrf),
                target,
                CUSTOMER_ADMIN_ROLE,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(body.contains("\"changed\":false"));

        let events = fixture.audit.records();
        let grants: Vec<_> = events
            .iter()
            .filter(|event| event.action == ROLE_GRANT_ACTION && event.result == "success")
            .collect();
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].details["changed"], true);
        assert_eq!(grants[1].details["changed"], false);
        assert_eq!(grants[0].resource_type, RESOURCE_USER);
        assert_eq!(
            grants[0].resource_id.as_deref(),
            Some(target.to_string().as_str())
        );
    }

    #[tokio::test]
    async fn own_roles_cannot_be_modified() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (cookie, csrf) = login(&app, "admin@example.test").await;
        let own_id = fixture
            .store
            .list_users("TEST-DEPLOYMENT", None)
            .await
            .expect("lists")[0]
            .id;
        let response = app
            .clone()
            .oneshot(grant_request(&cookie, Some(&csrf), own_id, SUPPORT_ROLE))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == ROLE_GRANT_ACTION
                && event.result == "denied"
                && event.details["reason"] == "cannot modify own roles"
        }));
    }

    #[tokio::test]
    async fn cross_customer_target_is_denied() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (cookie, csrf) = login(&app, "admin@example.test").await;
        let target = fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "other-tenant@example.test",
            "Other Tenant",
            Some("other-customer"),
            "active",
            &[],
        );
        let response = app
            .clone()
            .oneshot(grant_request(
                &cookie,
                Some(&csrf),
                target,
                CUSTOMER_ADMIN_ROLE,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == ROLE_GRANT_ACTION
                && event.result == "denied"
                && event.details["reason"] == "target user outside management scope"
        }));
    }

    #[tokio::test]
    async fn platform_user_creation_requires_system_admin() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (bootstrap_cookie, bootstrap_csrf) = login(&app, "admin@example.test").await;
        let create = bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/admin/users")
            .header("cookie", &bootstrap_cookie)
            .header("x-csrf-token", &bootstrap_csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"login":"ca@example.test","displayName":"CA","roles":["customer_admin"]}"#,
            ))
            .expect("request builds");
        let created = app.clone().oneshot(create).await.expect("request runs");
        assert_eq!(created.status(), StatusCode::CREATED);
        let (cookie, csrf) = login(&app, "ca@example.test").await;
        let request = bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/admin/users")
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"login":"platform@example.test","displayName":"Platform","roles":["customer_admin"]}"#,
            ))
            .expect("request builds");
        let response = app.clone().oneshot(request).await.expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == USER_CREATE_ACTION
                && event.result == "denied"
                && event.details["reason"]
                    == "platform user creation requires the system_admin role"
        }));
    }

    #[tokio::test]
    async fn grantor_cannot_assign_a_role_above_own_level() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (bootstrap_cookie, bootstrap_csrf) = login(&app, "admin@example.test").await;
        let create = bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/admin/users")
            .header("cookie", &bootstrap_cookie)
            .header("x-csrf-token", &bootstrap_csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"login":"ca@example.test","displayName":"CA","roles":["customer_admin"]}"#,
            ))
            .expect("request builds");
        let created = app.clone().oneshot(create).await.expect("request runs");
        assert_eq!(created.status(), StatusCode::CREATED);
        let (cookie, csrf) = login(&app, "ca@example.test").await;
        let request = bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/admin/users")
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"login":"elevated@example.test","displayName":"Elevated","roles":["support"]}"#,
            ))
            .expect("request builds");
        let response = app.clone().oneshot(request).await.expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == USER_CREATE_ACTION
                && event.result == "denied"
                && event.details["reason"] == "cannot grant a role above own level"
        }));
    }

    #[tokio::test]
    async fn grantor_cannot_grant_or_revoke_a_role_above_own_level() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (bootstrap_cookie, bootstrap_csrf) = login(&app, "admin@example.test").await;
        let create = |csrf: &str, body: &'static str| {
            bearer(Request::builder())
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("cookie", bootstrap_cookie.clone())
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request builds")
        };
        let created = app
            .clone()
            .oneshot(create(
                &bootstrap_csrf,
                r#"{"login":"ca@example.test","displayName":"CA","roles":["customer_admin"]}"#,
            ))
            .await
            .expect("request runs");
        assert_eq!(created.status(), StatusCode::CREATED);
        let target = fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "target@example.test",
            "Target",
            Some("test-customer"),
            "active",
            &[],
        );
        let (cookie, csrf) = login(&app, "ca@example.test").await;
        let grant = bearer(Request::builder())
            .method("POST")
            .uri(format!("/api/v1/admin/users/{target}/roles"))
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"roleKey":"support"}"#))
            .expect("request builds");
        let response = app.clone().oneshot(grant).await.expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == ROLE_GRANT_ACTION
                && event.result == "denied"
                && event.details["reason"] == "cannot grant a role above own level"
        }));
        let revoke = bearer(Request::builder())
            .method("DELETE")
            .uri(format!("/api/v1/admin/users/{target}/roles/support"))
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .expect("request builds");
        let response = app.clone().oneshot(revoke).await.expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == ROLE_REVOKE_ACTION
                && event.result == "denied"
                && event.details["reason"] == "cannot revoke a role above own level"
        }));
    }

    #[tokio::test]
    async fn customer_scoped_user_creation_succeeds_and_conflicts_are_409() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (cookie, csrf) = login(&app, "admin@example.test").await;
        let request = |body: &'static str| {
            bearer(Request::builder())
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request builds")
        };
        let response = app
            .clone()
            .oneshot(request(
                r#"{"login":"new@example.test","displayName":"New","customerId":"test-customer","roles":["support"]}"#,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = app
            .clone()
            .oneshot(request(
                r#"{"login":"new@example.test","displayName":"New","customerId":"test-customer","roles":["support"]}"#,
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let events = fixture.audit.records();
        let creates: Vec<_> = events
            .iter()
            .filter(|event| event.action == USER_CREATE_ACTION && event.result == "success")
            .collect();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].details["created"], true);
    }

    #[tokio::test]
    async fn list_users_is_scoped_to_the_session_customer() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (bootstrap_cookie, bootstrap_csrf) = login(&app, "admin@example.test").await;
        let create = bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/admin/users")
            .header("cookie", &bootstrap_cookie)
            .header("x-csrf-token", &bootstrap_csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"login":"scoped@example.test","displayName":"Scoped","roles":["customer_admin"]}"#,
            ))
            .expect("request builds");
        let created = app.clone().oneshot(create).await.expect("request runs");
        assert_eq!(created.status(), StatusCode::CREATED);
        fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "mine@example.test",
            "Mine",
            Some("test-customer"),
            "active",
            &[],
        );
        fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "theirs@example.test",
            "Theirs",
            Some("other-customer"),
            "active",
            &[],
        );
        let (cookie, _) = login(&app, "scoped@example.test").await;
        let response = app
            .clone()
            .oneshot(
                bearer(Request::builder())
                    .method("GET")
                    .uri("/api/v1/admin/users")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(body.contains("mine@example.test"));
        assert!(!body.contains("theirs@example.test"));
        assert!(!body.contains("stranger"));
    }

    fn impersonation_request(
        cookie: &str,
        csrf: &str,
        customer_id: &str,
        reason: &str,
    ) -> Request<Body> {
        bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/admin/impersonations")
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "customerId": customer_id,
                    "reason": reason,
                })
                .to_string(),
            ))
            .expect("request builds")
    }

    fn end_impersonation_request(cookie: &str, csrf: &str) -> Request<Body> {
        bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/admin/impersonations/end")
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
            .body(Body::empty())
            .expect("request builds")
    }

    async fn create_customer_admin(app: &Router, cookie: &str, csrf: &str, login_id: &str) {
        let create = bearer(Request::builder())
            .method("POST")
            .uri("/api/v1/admin/users")
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "login": login_id,
                    "displayName": "Subject",
                    "customerId": "test-customer",
                    "roles": ["customer_admin"],
                })
                .to_string(),
            ))
            .expect("request builds");
        let response = app.clone().oneshot(create).await.expect("request runs");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn customer_entry_keeps_roles_and_permissions_and_is_audited() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (admin_cookie, admin_csrf) = login(&app, "admin@example.test").await;
        let response = app
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "test-customer",
                "investigating a customer report",
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(body.contains("test-customer"));
        assert!(body.contains("Test Customer"));

        let session = app
            .clone()
            .oneshot(session_request(Some(&admin_cookie)))
            .await
            .expect("request runs");
        assert_eq!(session.status(), StatusCode::OK);
        let body = read_body(session).await;
        assert!(body.contains("\"impersonation\":{"));
        assert!(body.contains("\"customerId\":\"test-customer\""));
        assert!(body.contains("Test Customer"));
        assert!(body.contains("admin:users:manage"));
        assert!(
            body.contains("admin:impersonate"),
            "entry must keep every real permission of the actor"
        );

        let conflict = app
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "test-customer",
                "a second attempt to start acting",
            ))
            .await
            .expect("request runs");
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        let end = app
            .clone()
            .oneshot(end_impersonation_request(&admin_cookie, &admin_csrf))
            .await
            .expect("request runs");
        assert_eq!(end.status(), StatusCode::OK);
        let body = read_body(end).await;
        assert!(body.contains("\"ended\":true"));

        let session = app
            .clone()
            .oneshot(session_request(Some(&admin_cookie)))
            .await
            .expect("request runs");
        let body = read_body(session).await;
        assert!(body.contains("\"impersonation\":null"));
        assert!(body.contains("admin:impersonate"));

        let end_again = app
            .clone()
            .oneshot(end_impersonation_request(&admin_cookie, &admin_csrf))
            .await
            .expect("request runs");
        assert_eq!(end_again.status(), StatusCode::OK);
        let body = read_body(end_again).await;
        assert!(body.contains("\"ended\":false"));

        let events = fixture.audit.records();
        let starts: Vec<_> = events
            .iter()
            .filter(|event| event.action == IMPERSONATION_START_ACTION)
            .collect();
        assert_eq!(starts.len(), 1);
        assert_eq!(starts[0].result, "success");
        assert_eq!(starts[0].impersonated_subject, None);
        assert_eq!(
            starts[0].impersonated_customer.as_deref(),
            Some("test-customer")
        );
        assert_eq!(starts[0].customer_id.as_deref(), Some("test-customer"));
        assert_eq!(starts[0].actor_login, "admin@example.test");
        assert_eq!(
            starts[0].details["reason"],
            "investigating a customer report"
        );
        assert_eq!(starts[0].details["customer_id"], "test-customer");
        assert_eq!(starts[0].details["customer_display_name"], "Test Customer");
        let ends: Vec<_> = events
            .iter()
            .filter(|event| event.action == IMPERSONATION_END_ACTION)
            .collect();
        assert_eq!(ends.len(), 1, "ending twice must audit once");
        assert_eq!(ends[0].result, "success");
        assert_eq!(ends[0].impersonated_subject, None);
        assert_eq!(
            ends[0].impersonated_customer.as_deref(),
            Some("test-customer")
        );
        assert_eq!(ends[0].actor_login, "admin@example.test");
    }

    #[tokio::test]
    async fn impersonation_start_requires_reason_permission_and_fresh_step_up() {
        let base = default_fixture();
        let router = app(&base);
        let (admin_cookie, admin_csrf) = login(&router, "admin@example.test").await;

        let short_reason = router
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "test-customer",
                "too short",
            ))
            .await
            .expect("request runs");
        assert_eq!(short_reason.status(), StatusCode::BAD_REQUEST);

        let bad_customer = router
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "not a customer id",
                "attempting an invalid customer",
            ))
            .await
            .expect("request runs");
        assert_eq!(bad_customer.status(), StatusCode::BAD_REQUEST);

        // A Customer Admin session has no admin:impersonate permission.
        create_customer_admin(&router, &admin_cookie, &admin_csrf, "ca@example.test").await;
        let (ca_cookie, ca_csrf) = login(&router, "ca@example.test").await;
        let denied = router
            .clone()
            .oneshot(impersonation_request(
                &ca_cookie,
                &ca_csrf,
                "test-customer",
                "attempting an unauthorized entry",
            ))
            .await
            .expect("request runs");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let events = base.audit.records();
        assert!(events.iter().any(|event| {
            event.action == IMPERSONATION_START_ACTION
                && event.result == "denied"
                && event.details["reason"] == "missing admin:impersonate permission"
        }));

        // A stale step-up never reaches the subject lookup or the limiter.
        let stale = fixture(
            SessionConfig {
                step_up_ttl_secs: 0,
                ..SessionConfig::default()
            },
            HighRiskLimits::permission_change(),
            HighRiskLimits::impersonation_start(),
        );
        let stale_app = app(&stale);
        let (cookie, csrf) = login(&stale_app, "admin@example.test").await;
        let response = stale_app
            .clone()
            .oneshot(impersonation_request(
                &cookie,
                &csrf,
                "test-customer",
                "entering without a fresh step-up",
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = stale.audit.records();
        assert!(events.iter().any(|event| {
            event.action == IMPERSONATION_START_ACTION
                && event.result == "denied"
                && event.details["reason"] == "step-up authentication expired"
        }));
        assert!(!events
            .iter()
            .any(|event| event.action == IMPERSONATION_START_ACTION && event.result == "success"));
    }

    #[tokio::test]
    async fn impersonation_rejects_unknown_and_inactive_customers() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (admin_cookie, admin_csrf) = login(&app, "admin@example.test").await;

        let unknown = app
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "ghost-customer",
                "entering a customer that is missing",
            ))
            .await
            .expect("request runs");
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        let inactive = app
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "retired-customer",
                "entering a suspended customer tenant",
            ))
            .await
            .expect("request runs");
        assert_eq!(inactive.status(), StatusCode::FORBIDDEN);

        let events = fixture.audit.records();
        let reasons: Vec<_> = events
            .iter()
            .filter(|event| event.action == IMPERSONATION_START_ACTION && event.result == "denied")
            .map(|event| event.details["reason"].clone())
            .collect();
        assert!(reasons
            .iter()
            .any(|reason| reason == "customer is not active"));
        assert!(!events
            .iter()
            .any(|event| event.action == IMPERSONATION_START_ACTION && event.result == "success"));
    }

    #[tokio::test]
    async fn impersonation_uses_its_own_rate_limit_budget() {
        let impersonation_limit = RateLimitConfig {
            max_tokens: 1,
            refill_rate_per_sec: 0.0,
            ..HighRiskLimits::impersonation_start()
        };
        let fixture = fixture(
            SessionConfig::default(),
            HighRiskLimits::permission_change(),
            impersonation_limit,
        );
        let app = app(&fixture);
        let (admin_cookie, admin_csrf) = login(&app, "admin@example.test").await;
        let first = app
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "test-customer",
                "first authorized customer window",
            ))
            .await
            .expect("request runs");
        assert_eq!(first.status(), StatusCode::OK);
        let end = app
            .clone()
            .oneshot(end_impersonation_request(&admin_cookie, &admin_csrf))
            .await
            .expect("request runs");
        assert_eq!(end.status(), StatusCode::OK);
        let second = app
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "test-customer",
                "second attempt past the budget",
            ))
            .await
            .expect("request runs");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let events = fixture.audit.records();
        assert_eq!(
            events
                .iter()
                .filter(
                    |event| event.action == IMPERSONATION_START_ACTION && event.result == "success"
                )
                .count(),
            1
        );
        assert!(!events
            .iter()
            .any(|event| event.action == IMPERSONATION_START_ACTION
                && event.result == "denied"
                && event.details["reason"] == "rate limit exceeded"));
    }

    #[tokio::test]
    async fn logout_implicitly_ends_an_active_impersonation() {
        let fixture = default_fixture();
        let app = app(&fixture);
        let (admin_cookie, admin_csrf) = login(&app, "admin@example.test").await;
        let response = app
            .clone()
            .oneshot(impersonation_request(
                &admin_cookie,
                &admin_csrf,
                "test-customer",
                "acting before signing out entirely",
            ))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        let logout = app
            .clone()
            .oneshot(logout_request(&admin_cookie, &admin_csrf))
            .await
            .expect("request runs");
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(
            fixture
                .store
                .impersonations
                .lock()
                .expect("admin rbac store poisoned")
                .iter()
                .all(|impersonation| impersonation.ended_at.is_some()),
            "logout must close the acting-as interval"
        );
        let events = fixture.audit.records();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.action == IMPERSONATION_END_ACTION)
                .count(),
            0,
            "logout ends impersonation without a separate end audit row"
        );
        assert!(events
            .iter()
            .any(|event| event.action == SESSION_LOGOUT_ACTION && event.result == "success"));
    }

    // -----------------------------------------------------------------------
    // OIDC identity flow (increment 4)
    // -----------------------------------------------------------------------

    fn oidc_identity_for(idp: &MockIdp) -> IdentityConfig {
        IdentityConfig::from_lookup(|name| match name {
            "NULLAPART_IDENTITY_PROVIDER" => Some("oidc".to_string()),
            "NULLAPART_OIDC_ISSUER" => Some(idp.issuer().to_string()),
            "NULLAPART_OIDC_REDIRECT_URI" => {
                Some(format!("http://192.168.8.4:53080{OIDC_CALLBACK_PATH}"))
            },
            "NULLAPART_OIDC_CLIENT_ID" => Some("test-oidc-client".to_string()),
            "NULLAPART_OIDC_CLIENT_SECRET" => Some("test-client-secret".to_string()),
            _ => None,
        })
        .expect("oidc identity configuration")
    }

    fn oidc_fixture(idp: &MockIdp) -> Fixture {
        fixture_with_identity(
            SessionConfig::default(),
            HighRiskLimits::permission_change(),
            HighRiskLimits::impersonation_start(),
            oidc_identity_for(idp),
        )
    }

    fn query_param(url: &str, name: &str) -> Option<String> {
        let (_, query) = url.split_once('?')?;
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.to_string())
        })
    }

    /// Starts an authorization flow: asserts the redirect, and returns
    /// `(state, flow_cookie_pair, nonce)`.
    async fn begin_flow(app: &Router, query: &str) -> (String, String, String) {
        let uri = if query.is_empty() {
            LOGIN_PATH.to_string()
        } else {
            format!("{LOGIN_PATH}?{query}")
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&uri)
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("request runs");
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "flow begins with a provider redirect"
        );
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("authorize location")
            .to_string();
        let flow_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.starts_with(&format!("{OIDC_FLOW_COOKIE}=")))
            .expect("flow cookie is set")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_string();
        let state = query_param(&location, "state").expect("state parameter");
        let nonce = query_param(&location, "nonce").expect("nonce parameter");
        (state, flow_cookie, nonce)
    }

    async fn callback(app: &Router, uri: &str, flow_cookie: Option<&str>) -> Response {
        let mut builder = Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {TOKEN}"));
        if let Some(cookie) = flow_cookie {
            builder = builder.header("cookie", cookie);
        }
        app.clone()
            .oneshot(builder.body(Body::empty()).expect("request builds"))
            .await
            .expect("request runs")
    }

    #[tokio::test]
    async fn proxy_login_requires_the_forwarded_identity() {
        let fixture = fixture(
            SessionConfig::default(),
            HighRiskLimits::permission_change(),
            HighRiskLimits::impersonation_start(),
        );
        let app = app(&fixture);
        // Without a forwarded identity the boundary exchange is rejected.
        let response = app
            .clone()
            .oneshot(login_request(None))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // The first provisioned identity bootstraps the owner...
        let response = app
            .clone()
            .oneshot(login_request(Some("bootstrap-admin")))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::OK);
        // ...but any other identity on a non-empty deployment is denied.
        let response = app
            .clone()
            .oneshot(login_request(Some("mallory")))
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = fixture.audit.records();
        let logins: Vec<_> = events
            .iter()
            .filter(|event| event.action == SESSION_LOGIN_ACTION)
            .collect();
        assert_eq!(logins.len(), 2, "provisioned attempts are audited");
        assert_eq!(
            logins
                .iter()
                .filter(|event| event.result == "success")
                .count(),
            1
        );
        assert!(logins.iter().any(|event| event.result == "denied"
            && event.details["reason"] == "identity is not provisioned"));
    }

    #[tokio::test]
    async fn oidc_callback_rejects_missing_forged_and_unbound_requests() {
        let idp = MockIdp::start().await;
        let fixture = oidc_fixture(&idp);
        let app = app(&fixture);

        let response = callback(&app, OIDC_CALLBACK_PATH, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?code=abc&state=forged"),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // A real flow paired with the wrong browser cookie must not claim it.
        let (state, _cookie, _nonce) = begin_flow(&app, "").await;
        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?code=abc&state={state}"),
            Some("nullapart_oidc_flow=not-the-flow"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let events = fixture.audit.records();
        let logins: Vec<_> = events
            .iter()
            .filter(|event| event.action == SESSION_LOGIN_ACTION)
            .collect();
        assert_eq!(logins.len(), 3, "every rejection is audited");
        assert!(logins.iter().all(|event| event.result == "denied"));
        assert!(events
            .iter()
            .all(|event| event.action != SESSION_LOGIN_ACTION || event.result != "success"));
    }

    #[tokio::test]
    async fn oidc_login_bootstraps_the_first_identity_and_gates_the_rest() {
        let idp = MockIdp::start().await;
        let fixture = oidc_fixture(&idp);
        let app = app(&fixture);

        // First identity on an empty deployment bootstraps the owner and
        // honours the validated return destination.
        let (state, cookie, nonce) = begin_flow(&app, "return_to=%2Fdashboard").await;
        idp.set_nonce(&nonce);
        idp.set_subject("subject-first");
        idp.set_preferred_username("owner");
        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?code=mock-code&state={state}"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/dashboard"),
            "login redirects to the requested destination"
        );
        assert!(session_cookie_of(&response).is_some());
        let cleared = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| {
                value.starts_with(&format!("{OIDC_FLOW_COOKIE}=;")) && value.contains("Max-Age=0")
            });
        assert!(cleared, "the consumed flow cookie is cleared");

        // Replaying the same callback fails: the flow was consumed once.
        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?code=mock-code&state={state}"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // A second, unbound subject is not provisioned.
        let (state, cookie, nonce) = begin_flow(&app, "").await;
        idp.set_nonce(&nonce);
        idp.set_subject("subject-second");
        idp.set_preferred_username("intruder");
        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?code=mock-code&state={state}"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(session_cookie_of(&response).is_none());

        // A suspended account bound to a subject is rejected too.
        fixture.store.seed_user(
            "TEST-DEPLOYMENT",
            "suspended@example.test",
            "Suspended",
            Some("test-customer"),
            "suspended",
            &[CUSTOMER_ADMIN_ROLE],
        );
        assert!(fixture.store.set_auth_subject(
            "TEST-DEPLOYMENT",
            "suspended@example.test",
            Some("subject-suspended"),
        ));
        let (state, cookie, nonce) = begin_flow(&app, "").await;
        idp.set_nonce(&nonce);
        idp.set_subject("subject-suspended");
        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?code=mock-code&state={state}"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(session_cookie_of(&response).is_none());

        let events = fixture.audit.records();
        let successes = events
            .iter()
            .filter(|event| event.action == SESSION_LOGIN_ACTION && event.result == "success")
            .count();
        assert_eq!(successes, 1, "exactly one login established a session");
        assert!(events.iter().any(|event| {
            event.action == SESSION_LOGIN_ACTION
                && event.result == "denied"
                && event.details["reason"] == "identity is not provisioned"
        }));
        assert!(events.iter().any(|event| {
            event.action == SESSION_LOGIN_ACTION
                && event.result == "denied"
                && event.details["reason"] == "account is suspended"
        }));
    }

    #[tokio::test]
    async fn oidc_callback_rejects_a_provider_error_and_issuer_mix_up() {
        let idp = MockIdp::start().await;
        let fixture = oidc_fixture(&idp);
        let app = app(&fixture);

        let (state, cookie, _nonce) = begin_flow(&app, "").await;
        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?error=access_denied&state={state}"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(session_cookie_of(&response).is_none());

        let (state, cookie, nonce) = begin_flow(&app, "").await;
        idp.set_nonce(&nonce);
        let response = callback(
            &app,
            &format!(
                "{OIDC_CALLBACK_PATH}?code=mock-code&state={state}&iss=https://evil.example.test"
            ),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(session_cookie_of(&response).is_none());

        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == SESSION_LOGIN_ACTION
                && event.result == "denied"
                && event.details["reason"] == "identity provider returned an error"
        }));
        assert!(events.iter().any(|event| {
            event.action == SESSION_LOGIN_ACTION
                && event.result == "denied"
                && event.details["reason"] == "callback issuer did not match the configured issuer"
        }));
    }

    #[tokio::test]
    async fn oidc_reauth_requires_a_session_and_forces_prompt_login() {
        let idp = MockIdp::start().await;
        let fixture = oidc_fixture(&idp);
        let app = app(&fixture);

        // Anonymous callers cannot start a step-up flow.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(OIDC_REAUTH_PATH)
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Establish a session through a full OIDC login first.
        let (state, cookie, nonce) = begin_flow(&app, "").await;
        idp.set_nonce(&nonce);
        idp.set_subject("subject-reauth");
        idp.set_preferred_username("owner");
        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?code=mock-code&state={state}"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let session = set_cookie_of(&response)
            .split(';')
            .next()
            .expect("session cookie pair")
            .to_string();

        // Step-up begins an interactive prompt bound to the session and
        // returns the browser to a caller-supplied same-origin path.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("{OIDC_REAUTH_PATH}?return_to=%2Fquarantine%2Fabc"))
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .header("cookie", &session)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("request runs");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("authorize location")
            .to_string();
        assert_eq!(query_param(&location, "prompt").as_deref(), Some("login"));
        let state = query_param(&location, "state").expect("state parameter");
        let nonce = query_param(&location, "nonce").expect("nonce parameter");
        let flow_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.starts_with(&format!("{OIDC_FLOW_COOKIE}=")))
            .expect("reauth sets the flow cookie")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_string();

        // Completing it refreshes the step-up freshness window.
        idp.set_nonce(&nonce);
        let response = callback(
            &app,
            &format!("{OIDC_CALLBACK_PATH}?code=mock-code&state={state}"),
            Some(&flow_cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let callback_location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("step-up return location")
            .to_string();
        assert_eq!(callback_location, "/quarantine/abc");
        let events = fixture.audit.records();
        assert!(events.iter().any(|event| {
            event.action == SESSION_STEP_UP_ACTION
                && event.result == "success"
                && event.details["auth_method"] == "oidc"
        }));
    }
}

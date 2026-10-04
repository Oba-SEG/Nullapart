//! Tenant-safe quarantine state and release authorization boundary.
//!
//! The Control Plane constructs `TenantContext` from an authenticated session.
//! This module never accepts a caller-selected customer ID as authorization.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tokio::sync::Mutex;

use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId, TenantMessageId, TransactionId},
    ActorId, ArtifactId, ReasonCode,
};
use nullapart_policy::{CustomerLifecycle, TenantContext};
use nullapart_scanner_sdk::trait_defs::ScannerId;

use crate::scanner_fabric::scanner_capability_label;

/// Permission evaluated by the authenticated Control Plane before release.
pub const QUARANTINE_RELEASE_PERMISSION: &str = "quarantine:release";
pub const QUARANTINE_VIEW_PERMISSION: &str = "quarantine:view";

/// A quarantined tenant-scoped message. Raw MIME remains in ArtifactStore and
/// is never copied into this record or audit metadata.
#[derive(Debug, Clone)]
pub struct QuarantineCase {
    pub tenant_message_id: TenantMessageId,
    pub transaction_id: TransactionId,
    pub deployment_id: DeploymentId,
    pub customer_id: CustomerId,
    pub artifact_id: ArtifactId,
    pub reason_code: ReasonCode,
    pub quarantined_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    pub released_by: Option<ActorId>,
    pub release_reason: Option<String>,
}

/// Safe normalized finding projection for customer operations. It excludes
/// scanner internals, indicators, raw content, and artifact storage details.
#[derive(Debug, Clone)]
pub struct QuarantineFindingSummary {
    pub id: uuid::Uuid,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct QuarantineListItem {
    pub case: QuarantineCase,
    pub envelope_sender: String,
    pub recipient_count: u32,
    pub findings: Vec<QuarantineFindingSummary>,
}

/// Trusted release authority derived from a server-side session. Its fields
/// are intentionally private: browser input cannot select customer/actor.
#[derive(Debug, Clone)]
pub struct AuthorizedQuarantineRelease {
    customer_id: CustomerId,
    actor_id: ActorId,
    deployment_id: DeploymentId,
    actor_login: String,
    actor_roles: Vec<String>,
    trace_id: String,
}

impl AuthorizedQuarantineRelease {
    pub fn from_authenticated_context(context: &TenantContext) -> Result<Self, QuarantineError> {
        if context.customer_lifecycle != CustomerLifecycle::Active {
            return Err(QuarantineError::CustomerInactive);
        }
        if !context.has_step_up() {
            return Err(QuarantineError::StepUpRequired);
        }
        if !context
            .permissions
            .iter()
            .any(|permission| permission == QUARANTINE_RELEASE_PERMISSION)
        {
            return Err(QuarantineError::PermissionDenied);
        }
        Ok(Self {
            customer_id: context.customer_id.clone(),
            actor_id: context.effective_actor().actor_id.clone(),
            deployment_id: context.deployment_id.clone(),
            actor_login: context.effective_actor().login.clone(),
            actor_roles: context.effective_actor().roles.clone(),
            trace_id: context.trace_id.clone(),
        })
    }
}

/// Normalized scanner outcome for one case, projected as a product
/// capability. Scanner identifiers, engine versions and backend endpoints
/// never leave this boundary.
#[derive(Debug, Clone)]
pub struct QuarantineScannerResult {
    pub capability: String,
    pub status: String,
    pub required: bool,
    pub duration_ms: Option<i64>,
    pub completed_at: DateTime<Utc>,
}

/// One administrative audit record linked to a quarantine case. Message body,
/// raw MIME and attachment bytes are never part of audit metadata.
#[derive(Debug, Clone)]
pub struct QuarantineAuditEntry {
    pub action: String,
    pub actor_login: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
}

/// Retention state projected from the immutable artifact record and the
/// quarantine lifecycle.
#[derive(Debug, Clone)]
pub struct QuarantineRetention {
    pub retention_class: String,
    pub artifact_created_at: DateTime<Utc>,
    pub quarantined_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
}

/// Full safe detail projection for one case: the list projection plus
/// retention state, audit linkage and normalized scanner results.
#[derive(Debug, Clone)]
pub struct QuarantineDetail {
    pub item: QuarantineListItem,
    pub retention: Option<QuarantineRetention>,
    pub scanner_results: Vec<QuarantineScannerResult>,
    pub audit: Vec<QuarantineAuditEntry>,
}

/// Controlled high-risk release input. The idempotency key is supplied by the
/// authenticated API boundary and binds repeated attempts to one action.
#[derive(Debug, Clone)]
pub struct QuarantineReleaseRequest {
    pub tenant_message_id: TenantMessageId,
    pub release_reason: String,
    pub idempotency_key: String,
}

/// Mail-worker controlled input for a new security quarantine. This is not an
/// administrator request: its tenant scope is derived from the evaluated mail
/// recipient partition before it reaches this boundary.
#[derive(Debug, Clone)]
pub struct QuarantineCreateRequest {
    pub tenant_message_id: TenantMessageId,
    pub transaction_id: TransactionId,
    pub deployment_id: DeploymentId,
    pub customer_id: CustomerId,
    pub artifact_id: ArtifactId,
    pub reason_code: ReasonCode,
    pub trace_id: String,
    /// Trusted envelope metadata from the recipient partitioner. It is kept
    /// out of audit records and UI responses; it exists only so a released
    /// case can be reconstructed by the private reinjection worker.
    pub envelope_sender: String,
    pub recipients: Vec<String>,
}

/// Repository contract. A production implementation must update the case,
/// audit record, and transactional-outbox event in one database transaction.
#[async_trait]
pub trait QuarantineRepository: Send + Sync {
    async fn create(
        &self,
        request: &QuarantineCreateRequest,
    ) -> Result<QuarantineCase, QuarantineError>;

    async fn release(
        &self,
        authorization: &AuthorizedQuarantineRelease,
        request: &QuarantineReleaseRequest,
    ) -> Result<QuarantineCase, QuarantineError>;

    async fn list(
        &self,
        customer_id: &CustomerId,
        deployment_id: &DeploymentId,
    ) -> Result<Vec<QuarantineListItem>, QuarantineError>;

    async fn get(
        &self,
        customer_id: &CustomerId,
        deployment_id: &DeploymentId,
        tenant_message_id: &TenantMessageId,
    ) -> Result<QuarantineListItem, QuarantineError> {
        self.list(customer_id, deployment_id)
            .await?
            .into_iter()
            .find(|item| &item.case.tenant_message_id == tenant_message_id)
            .ok_or(QuarantineError::NotFound)
    }

    /// Detail projection for one case. The default implementation returns the
    /// list projection with empty evidence sections, so a repository with no
    /// scanner or audit store still cannot widen the tenant boundary.
    async fn detail(
        &self,
        customer_id: &CustomerId,
        deployment_id: &DeploymentId,
        tenant_message_id: &TenantMessageId,
    ) -> Result<QuarantineDetail, QuarantineError> {
        let item = self
            .get(customer_id, deployment_id, tenant_message_id)
            .await?;
        Ok(QuarantineDetail {
            item,
            retention: None,
            scanner_results: Vec::new(),
            audit: Vec::new(),
        })
    }
}

/// Quarantine application service.
#[derive(Clone)]
pub struct QuarantineService {
    repository: Arc<dyn QuarantineRepository>,
}

impl QuarantineService {
    pub fn new(repository: Arc<dyn QuarantineRepository>) -> Self {
        Self { repository }
    }

    pub async fn release(
        &self,
        authorization: AuthorizedQuarantineRelease,
        request: QuarantineReleaseRequest,
    ) -> Result<QuarantineCase, QuarantineError> {
        if request.release_reason.trim().is_empty() || request.release_reason.len() > 500 {
            return Err(QuarantineError::InvalidReleaseReason);
        }
        if request.idempotency_key.is_empty() || request.idempotency_key.len() > 128 {
            return Err(QuarantineError::InvalidIdempotencyKey);
        }
        self.repository.release(&authorization, &request).await
    }

    pub async fn create(
        &self,
        request: QuarantineCreateRequest,
    ) -> Result<QuarantineCase, QuarantineError> {
        if request.trace_id.is_empty() || request.trace_id.len() > 256 {
            return Err(QuarantineError::InvalidTraceId);
        }
        if request.envelope_sender.is_empty()
            || request.envelope_sender.len() > 320
            || request.recipients.is_empty()
            || request.recipients.len() > 500
            || request
                .recipients
                .iter()
                .any(|recipient| recipient.is_empty() || recipient.len() > 320)
        {
            return Err(QuarantineError::InvalidEnvelope);
        }
        self.repository.create(&request).await
    }

    /// Lists only the active caller's scoped cases. Context is constructed by
    /// the authenticated backend and cannot be supplied by a browser request.
    pub async fn list(
        &self,
        context: &TenantContext,
    ) -> Result<Vec<QuarantineListItem>, QuarantineError> {
        if context.customer_lifecycle != CustomerLifecycle::Active {
            return Err(QuarantineError::CustomerInactive);
        }
        if !context
            .permissions
            .iter()
            .any(|permission| permission == QUARANTINE_VIEW_PERMISSION)
        {
            return Err(QuarantineError::PermissionDenied);
        }
        self.repository
            .list(&context.customer_id, &context.deployment_id)
            .await
    }

    /// Returns one tenant-scoped safe case projection using the same
    /// authenticated view permission and lifecycle checks as the list route.
    pub async fn get(
        &self,
        context: &TenantContext,
        tenant_message_id: &TenantMessageId,
    ) -> Result<QuarantineListItem, QuarantineError> {
        if context.customer_lifecycle != CustomerLifecycle::Active {
            return Err(QuarantineError::CustomerInactive);
        }
        if !context
            .permissions
            .iter()
            .any(|permission| permission == QUARANTINE_VIEW_PERMISSION)
        {
            return Err(QuarantineError::PermissionDenied);
        }
        self.repository
            .get(
                &context.customer_id,
                &context.deployment_id,
                tenant_message_id,
            )
            .await
    }

    /// Returns the full safe detail projection for one tenant-scoped case
    /// using the same authenticated view permission and lifecycle checks as
    /// the list route.
    pub async fn detail(
        &self,
        context: &TenantContext,
        tenant_message_id: &TenantMessageId,
    ) -> Result<QuarantineDetail, QuarantineError> {
        if context.customer_lifecycle != CustomerLifecycle::Active {
            return Err(QuarantineError::CustomerInactive);
        }
        if !context
            .permissions
            .iter()
            .any(|permission| permission == QUARANTINE_VIEW_PERMISSION)
        {
            return Err(QuarantineError::PermissionDenied);
        }
        self.repository
            .detail(
                &context.customer_id,
                &context.deployment_id,
                tenant_message_id,
            )
            .await
    }
}

/// Safe release failures for the Control Plane to map to stable responses.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum QuarantineError {
    #[error("quarantine release permission is required")]
    PermissionDenied,
    #[error("step-up authentication is required for quarantine release")]
    StepUpRequired,
    #[error("customer lifecycle prevents quarantine release")]
    CustomerInactive,
    #[error("invalid quarantine release reason")]
    InvalidReleaseReason,
    #[error("invalid idempotency key")]
    InvalidIdempotencyKey,
    #[error("invalid trace identity")]
    InvalidTraceId,
    #[error("invalid reinjection envelope")]
    InvalidEnvelope,
    #[error("quarantine case already exists")]
    AlreadyQuarantined,
    #[error("quarantine case not found")]
    NotFound,
    #[error("quarantine case belongs to another tenant or deployment")]
    OwnershipDenied,
    #[error("quarantine case was already released by another action")]
    AlreadyReleased,
    #[error("quarantine persistence is unavailable")]
    PersistenceFailed,
}

/// Test/local repository. Production must use the PostgreSQL implementation;
/// keeping it injected prevents an accidental process-local authorization path.
#[derive(Default)]
pub struct InMemoryQuarantineRepository {
    cases: Mutex<HashMap<TenantMessageId, QuarantineCase>>,
    idempotency: Mutex<HashMap<(String, String), TenantMessageId>>,
}

impl InMemoryQuarantineRepository {
    pub async fn insert(&self, case: QuarantineCase) {
        self.cases
            .lock()
            .await
            .insert(case.tenant_message_id.clone(), case);
    }
}

#[async_trait]
impl QuarantineRepository for InMemoryQuarantineRepository {
    async fn create(
        &self,
        request: &QuarantineCreateRequest,
    ) -> Result<QuarantineCase, QuarantineError> {
        let mut cases = self.cases.lock().await;
        if cases.contains_key(&request.tenant_message_id) {
            return Err(QuarantineError::AlreadyQuarantined);
        }
        let case = QuarantineCase {
            tenant_message_id: request.tenant_message_id.clone(),
            transaction_id: request.transaction_id.clone(),
            deployment_id: request.deployment_id.clone(),
            customer_id: request.customer_id.clone(),
            artifact_id: request.artifact_id.clone(),
            reason_code: request.reason_code.clone(),
            quarantined_at: Utc::now(),
            released_at: None,
            released_by: None,
            release_reason: None,
        };
        cases.insert(case.tenant_message_id.clone(), case.clone());
        Ok(case)
    }

    async fn release(
        &self,
        authorization: &AuthorizedQuarantineRelease,
        request: &QuarantineReleaseRequest,
    ) -> Result<QuarantineCase, QuarantineError> {
        let idempotency_key = (
            authorization.customer_id.0.clone(),
            request.idempotency_key.clone(),
        );
        let mut cases = self.cases.lock().await;
        let mut idempotency = self.idempotency.lock().await;

        if let Some(existing_id) = idempotency.get(&idempotency_key) {
            if existing_id != &request.tenant_message_id {
                return Err(QuarantineError::AlreadyReleased);
            }
            return cases
                .get(existing_id)
                .cloned()
                .ok_or(QuarantineError::NotFound);
        }

        let case = cases
            .get_mut(&request.tenant_message_id)
            .ok_or(QuarantineError::NotFound)?;
        if case.customer_id != authorization.customer_id
            || case.deployment_id != authorization.deployment_id
        {
            return Err(QuarantineError::OwnershipDenied);
        }
        if case.released_at.is_some() {
            return Err(QuarantineError::AlreadyReleased);
        }

        case.released_at = Some(Utc::now());
        case.released_by = Some(authorization.actor_id.clone());
        case.release_reason = Some(request.release_reason.clone());
        let released = case.clone();
        idempotency.insert(idempotency_key, request.tenant_message_id.clone());
        Ok(released)
    }

    async fn list(
        &self,
        customer_id: &CustomerId,
        deployment_id: &DeploymentId,
    ) -> Result<Vec<QuarantineListItem>, QuarantineError> {
        let cases = self.cases.lock().await;
        let mut scoped = cases
            .values()
            .filter(|case| {
                &case.customer_id == customer_id
                    && &case.deployment_id == deployment_id
                    && case.released_at.is_none()
            })
            .cloned()
            .map(|case| QuarantineListItem {
                case,
                envelope_sender: "Unavailable".to_string(),
                recipient_count: 0,
                findings: Vec::new(),
            })
            .collect::<Vec<_>>();
        scoped.sort_by_key(|item| std::cmp::Reverse(item.case.quarantined_at));
        Ok(scoped)
    }
}

/// PostgreSQL release repository. It locks the case and commits the state
/// change, administrative audit record, and transactional-outbox event
/// together. A caller must still establish transaction-scoped RLS context.
#[derive(Clone)]
pub struct PostgresQuarantineRepository {
    pool: PgPool,
}

impl PostgresQuarantineRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Reads one case, its envelope projection and its safe finding summary
    /// inside an already tenant-scoped transaction.
    ///
    /// Unlike [`QuarantineRepository::list`], this does not filter on release
    /// state: the active quarantine list stays active-only, while the detail
    /// projection must still resolve a released case so its retention and
    /// audit history remain inspectable.
    async fn fetch_case(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        customer_id: &CustomerId,
        deployment_id: &DeploymentId,
        tenant_message_id: &TenantMessageId,
    ) -> Result<QuarantineListItem, QuarantineError> {
        let row = sqlx::query(
            "SELECT quarantine_cases.tenant_message_id, quarantine_cases.transaction_id, quarantine_cases.deployment_id, quarantine_cases.customer_id, quarantine_cases.artifact_id, quarantine_cases.reason_code, \
                    quarantined_at, released_at, released_by, release_reason, \
                    smtp_transactions.envelope_sender, \
                    jsonb_array_length(quarantine_reinjection_envelopes.recipients)::BIGINT AS recipient_count \
             FROM quarantine_cases \
             JOIN smtp_transactions ON smtp_transactions.id = quarantine_cases.transaction_id \
             JOIN quarantine_reinjection_envelopes ON quarantine_reinjection_envelopes.tenant_message_id = quarantine_cases.tenant_message_id \
             WHERE quarantine_cases.tenant_message_id = $1 AND quarantine_cases.customer_id = $2 AND quarantine_cases.deployment_id = $3",
        )
        .bind(tenant_message_id.0)
        .bind(&customer_id.0)
        .bind(&deployment_id.0)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        let Some(row) = row else {
            return Err(QuarantineError::NotFound);
        };
        let case = case_from_row(&row)?;
        let finding_rows = sqlx::query(
            "SELECT id, category, severity, description, created_at FROM security_findings \
             WHERE tenant_message_id = $1 AND customer_id = $2 ORDER BY created_at DESC",
        )
        .bind(case.tenant_message_id.0)
        .bind(&customer_id.0)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        Ok(QuarantineListItem {
            case,
            envelope_sender: row.get("envelope_sender"),
            recipient_count: u32::try_from(row.get::<i64, _>("recipient_count"))
                .map_err(|_| QuarantineError::PersistenceFailed)?,
            findings: finding_rows
                .iter()
                .map(|finding| QuarantineFindingSummary {
                    id: finding.get("id"),
                    category: finding.get("category"),
                    severity: finding.get("severity"),
                    description: finding.get("description"),
                    created_at: finding.get("created_at"),
                })
                .collect(),
        })
    }
}

#[async_trait]
impl QuarantineRepository for PostgresQuarantineRepository {
    async fn create(
        &self,
        request: &QuarantineCreateRequest,
    ) -> Result<QuarantineCase, QuarantineError> {
        let mut database_transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&request.customer_id.0)
            .execute(&mut *database_transaction)
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        let quarantined_at = Utc::now();
        let created = sqlx::query(
            "INSERT INTO quarantine_cases (tenant_message_id, transaction_id, deployment_id, customer_id, \
                    artifact_id, reason_code, quarantined_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (tenant_message_id) DO NOTHING",
        )
        .bind(request.tenant_message_id.0)
        .bind(request.transaction_id.0)
        .bind(&request.deployment_id.0)
        .bind(&request.customer_id.0)
        .bind(request.artifact_id.0)
        .bind(&request.reason_code.0)
        .bind(quarantined_at)
        .execute(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        if created.rows_affected() != 1 {
            return Err(QuarantineError::AlreadyQuarantined);
        }
        sqlx::query(
            "INSERT INTO quarantine_reinjection_envelopes (tenant_message_id, transaction_id, deployment_id, customer_id, envelope_sender, recipients) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(request.tenant_message_id.0)
        .bind(request.transaction_id.0)
        .bind(&request.deployment_id.0)
        .bind(&request.customer_id.0)
        .bind(&request.envelope_sender)
        .bind(serde_json::json!(request.recipients))
        .execute(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        database_transaction
            .commit()
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        Ok(QuarantineCase {
            tenant_message_id: request.tenant_message_id.clone(),
            transaction_id: request.transaction_id.clone(),
            deployment_id: request.deployment_id.clone(),
            customer_id: request.customer_id.clone(),
            artifact_id: request.artifact_id.clone(),
            reason_code: request.reason_code.clone(),
            quarantined_at,
            released_at: None,
            released_by: None,
            release_reason: None,
        })
    }

    async fn release(
        &self,
        authorization: &AuthorizedQuarantineRelease,
        request: &QuarantineReleaseRequest,
    ) -> Result<QuarantineCase, QuarantineError> {
        let mut database_transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(&authorization.deployment_id.0)
            .execute(&mut *database_transaction)
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&authorization.customer_id.0)
            .execute(&mut *database_transaction)
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        let row = sqlx::query(
            "SELECT tenant_message_id, transaction_id, deployment_id, customer_id, artifact_id, reason_code, \
                    quarantined_at, released_at, released_by, release_reason, release_idempotency_key \
             FROM quarantine_cases WHERE tenant_message_id = $1 FOR UPDATE",
        )
        .bind(request.tenant_message_id.0)
        .fetch_optional(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?
        .ok_or(QuarantineError::NotFound)?;
        let mut case = case_from_row(&row)?;
        if case.customer_id != authorization.customer_id
            || case.deployment_id != authorization.deployment_id
        {
            return Err(QuarantineError::OwnershipDenied);
        }
        if case.released_at.is_some() {
            if row.get::<Option<String>, _>("release_idempotency_key")
                == Some(request.idempotency_key.clone())
            {
                return Ok(case);
            }
            return Err(QuarantineError::AlreadyReleased);
        }

        let released_at = Utc::now();
        sqlx::query(
            "UPDATE quarantine_cases SET released_at = $1, released_by = $2, release_reason = $3, \
                    release_idempotency_key = $4 WHERE tenant_message_id = $5",
        )
        .bind(released_at)
        .bind(authorization.actor_id.0)
        .bind(&request.release_reason)
        .bind(&request.idempotency_key)
        .bind(request.tenant_message_id.0)
        .execute(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        sqlx::query(
            "INSERT INTO audit_events (deployment_id, customer_id, actor_id, actor_login, actor_roles, action, \
                    resource_type, resource_id, result, trace_id, details) \
             VALUES ($1, $2, $3, $4, $5, 'release', 'quarantine', $6, 'success', $7, $8)",
        )
        .bind(&authorization.deployment_id.0)
        .bind(&authorization.customer_id.0)
        .bind(authorization.actor_id.0.to_string())
        .bind(&authorization.actor_login)
        .bind(&authorization.actor_roles)
        .bind(request.tenant_message_id.0.to_string())
        .bind(&authorization.trace_id)
        .bind(serde_json::json!({
            "reason_code": case.reason_code.0,
            "release_reason": request.release_reason,
        }))
        .execute(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        sqlx::query(
            "INSERT INTO ml_feedback_candidates \
             (deployment_id, customer_id, tenant_message_id, transaction_id, source, proposed_label, actor_login, reason) \
             VALUES ($1, $2, $3, $4, 'quarantine_release', 'false_positive', $5, $6) \
             ON CONFLICT (deployment_id, tenant_message_id, source) \
             WHERE tenant_message_id IS NOT NULL DO NOTHING",
        )
        .bind(&authorization.deployment_id.0)
        .bind(&authorization.customer_id.0)
        .bind(request.tenant_message_id.0)
        .bind(case.transaction_id.0)
        .bind(&authorization.actor_login)
        .bind(&request.release_reason)
        .execute(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        sqlx::query(
            "INSERT INTO outbox_events (event_type, event_version, payload, idempotency_key, customer_id, \
                    deployment_id, trace_id) VALUES ('quarantine.released', 1, $1, $2, $3, $4, $5)",
        )
        .bind(serde_json::json!({"tenant_message_id": request.tenant_message_id.0.to_string()}))
        .bind(format!("quarantine-release:{}", request.idempotency_key))
        .bind(&authorization.customer_id.0)
        .bind(&authorization.deployment_id.0)
        .bind(&authorization.trace_id)
        .execute(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        database_transaction
            .commit()
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;

        case.released_at = Some(released_at);
        case.released_by = Some(authorization.actor_id.clone());
        case.release_reason = Some(request.release_reason.clone());
        Ok(case)
    }

    async fn list(
        &self,
        customer_id: &CustomerId,
        deployment_id: &DeploymentId,
    ) -> Result<Vec<QuarantineListItem>, QuarantineError> {
        let mut database_transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&customer_id.0)
            .execute(&mut *database_transaction)
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        let rows = sqlx::query(
            "SELECT quarantine_cases.tenant_message_id, quarantine_cases.transaction_id, quarantine_cases.deployment_id, quarantine_cases.customer_id, quarantine_cases.artifact_id, quarantine_cases.reason_code, \
                    quarantined_at, released_at, released_by, release_reason \
                    , smtp_transactions.envelope_sender, \
                    jsonb_array_length(quarantine_reinjection_envelopes.recipients)::BIGINT AS recipient_count \
             FROM quarantine_cases \
             JOIN smtp_transactions ON smtp_transactions.id = quarantine_cases.transaction_id \
             JOIN quarantine_reinjection_envelopes ON quarantine_reinjection_envelopes.tenant_message_id = quarantine_cases.tenant_message_id \
             WHERE quarantine_cases.customer_id = $1 AND quarantine_cases.deployment_id = $2 AND released_at IS NULL \
             ORDER BY quarantined_at DESC",
        )
        .bind(&customer_id.0)
        .bind(&deployment_id.0)
        .fetch_all(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let case = case_from_row(&row)?;
            let finding_rows = sqlx::query(
                "SELECT id, category, severity, description, created_at FROM security_findings \
                 WHERE tenant_message_id = $1 AND customer_id = $2 ORDER BY created_at DESC",
            )
            .bind(case.tenant_message_id.0)
            .bind(&customer_id.0)
            .fetch_all(&mut *database_transaction)
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
            items.push(QuarantineListItem {
                case,
                envelope_sender: row.get("envelope_sender"),
                recipient_count: u32::try_from(row.get::<i64, _>("recipient_count"))
                    .map_err(|_| QuarantineError::PersistenceFailed)?,
                findings: finding_rows
                    .iter()
                    .map(|finding| QuarantineFindingSummary {
                        id: finding.get("id"),
                        category: finding.get("category"),
                        severity: finding.get("severity"),
                        description: finding.get("description"),
                        created_at: finding.get("created_at"),
                    })
                    .collect(),
            });
        }
        database_transaction
            .commit()
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        Ok(items)
    }

    async fn detail(
        &self,
        customer_id: &CustomerId,
        deployment_id: &DeploymentId,
        tenant_message_id: &TenantMessageId,
    ) -> Result<QuarantineDetail, QuarantineError> {
        let mut database_transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&customer_id.0)
            .execute(&mut *database_transaction)
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;

        // Retention is read through the joined artifact record under the same
        // tenant RLS scope, so a detail call can never widen the boundary the
        // list call already enforces.
        let retention_row = sqlx::query(
            "SELECT a.retention_class, a.created_at AS artifact_created_at, \
                    q.quarantined_at, q.released_at \
             FROM quarantine_cases q \
             JOIN artifacts a ON a.id = q.artifact_id \
             WHERE q.tenant_message_id = $1 AND q.customer_id = $2 AND q.deployment_id = $3",
        )
        .bind(tenant_message_id.0)
        .bind(&customer_id.0)
        .bind(&deployment_id.0)
        .fetch_optional(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        let Some(retention_row) = retention_row else {
            return Err(QuarantineError::NotFound);
        };
        let retention = QuarantineRetention {
            retention_class: retention_row.get("retention_class"),
            artifact_created_at: retention_row.get("artifact_created_at"),
            quarantined_at: retention_row.get("quarantined_at"),
            released_at: retention_row.get("released_at"),
        };

        let result_rows = sqlx::query(
            "SELECT scanner_id, status, required, duration_ms, completed_at \
             FROM scanner_results \
             WHERE tenant_message_id = $1 AND customer_id = $2 AND deployment_id = $3 \
             ORDER BY completed_at DESC",
        )
        .bind(tenant_message_id.0)
        .bind(&customer_id.0)
        .bind(&deployment_id.0)
        .fetch_all(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        let scanner_results = result_rows
            .iter()
            .map(|row| {
                let scanner_id: String = row.get("scanner_id");
                QuarantineScannerResult {
                    capability: scanner_capability_label(&ScannerId::new(&scanner_id)).to_string(),
                    status: row.get("status"),
                    required: row.get("required"),
                    duration_ms: row.get("duration_ms"),
                    completed_at: row.get("completed_at"),
                }
            })
            .collect();

        let audit_rows = sqlx::query(
            "SELECT action, actor_login, result, created_at \
             FROM audit_events \
             WHERE customer_id = $1 AND deployment_id = $2 AND resource_type = 'quarantine' \
               AND resource_id = $3 \
             ORDER BY created_at DESC",
        )
        .bind(&customer_id.0)
        .bind(&deployment_id.0)
        .bind(tenant_message_id.0.to_string())
        .fetch_all(&mut *database_transaction)
        .await
        .map_err(|_| QuarantineError::PersistenceFailed)?;
        let audit = audit_rows
            .iter()
            .map(|row| QuarantineAuditEntry {
                action: row.get("action"),
                actor_login: row.get("actor_login"),
                result: row.get("result"),
                created_at: row.get("created_at"),
            })
            .collect();

        let item = Self::fetch_case(
            &mut database_transaction,
            customer_id,
            deployment_id,
            tenant_message_id,
        )
        .await?;

        database_transaction
            .commit()
            .await
            .map_err(|_| QuarantineError::PersistenceFailed)?;

        Ok(QuarantineDetail {
            item,
            retention: Some(retention),
            scanner_results,
            audit,
        })
    }
}

fn case_from_row(row: &sqlx::postgres::PgRow) -> Result<QuarantineCase, QuarantineError> {
    Ok(QuarantineCase {
        tenant_message_id: TenantMessageId(row.get("tenant_message_id")),
        transaction_id: TransactionId(row.get("transaction_id")),
        deployment_id: DeploymentId::new(row.get::<String, _>("deployment_id").as_str()),
        customer_id: CustomerId::new(row.get::<String, _>("customer_id").as_str()),
        artifact_id: ArtifactId(row.get("artifact_id")),
        reason_code: ReasonCode(row.get("reason_code")),
        quarantined_at: row.get("quarantined_at"),
        released_at: row.get("released_at"),
        released_by: row.get::<Option<uuid::Uuid>, _>("released_by").map(ActorId),
        release_reason: row.get("release_reason"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId};

    fn context(customer_id: &str, step_up: bool, permitted: bool) -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            region: RegionId::new("local"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "admin@example.test".to_string(),
                roles: vec!["customer_admin".to_string()],
                authentication_assurance: if step_up {
                    AuthenticationAssurance::StepUp
                } else {
                    AuthenticationAssurance::Standard
                },
            },
            impersonation: None,
            customer_id: CustomerId::new(customer_id),
            customer_internal_key: 1,
            customer_display_name: "Test customer".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions: if permitted {
                vec![QUARANTINE_RELEASE_PERMISSION.to_string()]
            } else {
                Vec::new()
            },
            config_revision: 1,
            trace_id: "trace".to_string(),
            correlation_id: "correlation".to_string(),
            session_id: "session".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    fn case(customer_id: &str) -> QuarantineCase {
        QuarantineCase {
            tenant_message_id: TenantMessageId::new(),
            transaction_id: TransactionId::new(),
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            customer_id: CustomerId::new(customer_id),
            artifact_id: ArtifactId::new(),
            reason_code: ReasonCode::quarantine_malware(),
            quarantined_at: Utc::now(),
            released_at: None,
            released_by: None,
            release_reason: None,
        }
    }

    #[tokio::test]
    async fn release_requires_step_up_permission_and_matching_tenant() {
        let repository = Arc::new(InMemoryQuarantineRepository::default());
        let stored = case("customer-a");
        repository.insert(stored.clone()).await;
        let service = QuarantineService::new(repository);
        let request = QuarantineReleaseRequest {
            tenant_message_id: stored.tenant_message_id.clone(),
            release_reason: "Confirmed false positive".to_string(),
            idempotency_key: "release-1".to_string(),
        };

        assert!(matches!(
            AuthorizedQuarantineRelease::from_authenticated_context(&context(
                "customer-a",
                false,
                true
            )),
            Err(QuarantineError::StepUpRequired)
        ));
        let other_tenant = AuthorizedQuarantineRelease::from_authenticated_context(&context(
            "customer-b",
            true,
            true,
        ))
        .unwrap();
        assert!(matches!(
            service.release(other_tenant, request.clone()).await,
            Err(QuarantineError::OwnershipDenied)
        ));

        let authorization = AuthorizedQuarantineRelease::from_authenticated_context(&context(
            "customer-a",
            true,
            true,
        ))
        .unwrap();
        let released = service.release(authorization, request).await.unwrap();
        assert!(released.released_at.is_some());
        assert!(released.released_by.is_some());
    }
}

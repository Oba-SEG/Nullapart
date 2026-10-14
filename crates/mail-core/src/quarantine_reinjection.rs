//! Durable quarantine-release reinjection worker.
//!
//! The worker consumes only transactional `quarantine.released` outbox
//! records. Tenant scope is restored from the persisted event before RLS
//! protected case/envelope/delivery rows are touched. Raw MIME is read only
//! through an exact, short-lived ArtifactStore capability and is submitted to
//! a private Postfix listener that bypasses the inbound content filter.

use std::time::Duration;

use chrono::Utc;
use nullapart_mail_contracts::artifact::{
    Artifact, ArtifactHash, ArtifactId, ContentType, HashAlgorithm, RetentionClass, StorageBackend,
    StorageLocation,
};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use serde_json::Value;
use sqlx::{pool::PoolConnection, PgPool, Postgres, Row, Transaction};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::artifact_store::{
    ArtifactAccessGrant, ArtifactAccessPurpose, ArtifactPermissions, ArtifactScope,
    FilesystemArtifactStore,
};

const RELEASE_EVENT_TYPE: &str = "quarantine.released";
const WORKER_ACTOR: &str = "quarantine-reinjection-worker";

#[derive(Debug, Clone)]
pub struct QuarantineReinjectionConfig {
    pub endpoint: String,
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub max_attempts: i64,
}

impl Default for QuarantineReinjectionConfig {
    fn default() -> Self {
        Self {
            endpoint: "127.0.0.1:10026".to_string(),
            timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(5),
            max_attempts: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReinjectionRunOutcome {
    Idle,
    Delivered {
        outbox_event_id: Uuid,
        queue_id: String,
    },
    AlreadyDelivered {
        outbox_event_id: Uuid,
    },
    Failed {
        outbox_event_id: Uuid,
        code: &'static str,
    },
    AttemptsExhausted {
        outbox_event_id: Uuid,
    },
    InvalidEventRecorded {
        outbox_event_id: Uuid,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ReinjectionWorkerError {
    #[error("reinjection persistence unavailable")]
    Persistence,
    #[error("reinjection event is invalid")]
    InvalidEvent,
}

#[derive(Clone)]
pub struct QuarantineReinjectionWorker {
    pool: PgPool,
    store: FilesystemArtifactStore,
    config: QuarantineReinjectionConfig,
}

impl QuarantineReinjectionWorker {
    pub fn new(
        pool: PgPool,
        store: FilesystemArtifactStore,
        config: QuarantineReinjectionConfig,
    ) -> Self {
        Self {
            pool,
            store,
            config,
        }
    }

    pub async fn run(self) {
        loop {
            match self.run_once().await {
                Ok(ReinjectionRunOutcome::Delivered {
                    outbox_event_id,
                    queue_id,
                }) => {
                    tracing::info!(%outbox_event_id, %queue_id, "quarantine reinjection succeeded");
                },
                Ok(ReinjectionRunOutcome::Failed {
                    outbox_event_id,
                    code,
                }) => {
                    tracing::warn!(%outbox_event_id, failure_code = code, "quarantine reinjection attempt failed");
                },
                Ok(ReinjectionRunOutcome::AttemptsExhausted { outbox_event_id }) => {
                    tracing::error!(%outbox_event_id, "quarantine reinjection attempts exhausted");
                },
                Ok(ReinjectionRunOutcome::InvalidEventRecorded { outbox_event_id }) => {
                    tracing::error!(%outbox_event_id, "quarantine reinjection event dead-lettered as invalid");
                },
                Err(error) => {
                    tracing::error!(error = %error, "quarantine reinjection worker failed")
                },
                _ => {},
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    pub async fn run_once(&self) -> Result<ReinjectionRunOutcome, ReinjectionWorkerError> {
        // Events that cannot be attributed to a tenant message, or whose
        // delivery guard is held by a sibling process, are excluded only for
        // this cycle so one stuck event can never starve the release queue.
        let mut skipped: Vec<Uuid> = Vec::new();
        loop {
            let Some(claim) = self.claim_next(&skipped).await? else {
                return Ok(ReinjectionRunOutcome::Idle);
            };
            let ClaimedEvent {
                event_id,
                event,
                outcome,
                guard,
            } = claim;
            match outcome {
                ClaimOutcome::Terminal(outcome) => {
                    if let Some(guard) = guard {
                        guard.release().await;
                    }
                    return Ok(outcome);
                },
                ClaimOutcome::Contended => {
                    tracing::debug!(%event_id, "quarantine reinjection event is being delivered by a sibling process; skipping this cycle");
                    skipped.push(event_id);
                },
                ClaimOutcome::Invalid => {
                    let recorded = self.dead_letter_invalid_event(&event).await;
                    if let Some(guard) = guard {
                        guard.release().await;
                    }
                    if recorded {
                        return Ok(ReinjectionRunOutcome::InvalidEventRecorded {
                            outbox_event_id: event_id,
                        });
                    }
                    tracing::warn!(%event_id, "quarantine reinjection event lacks tenant attribution; skipping this cycle");
                    skipped.push(event_id);
                },
                ClaimOutcome::Ready(prepared) => {
                    let result = self.deliver(*prepared).await;
                    if let Some(guard) = guard {
                        guard.release().await;
                    }
                    return result;
                },
            }
        }
    }

    /// Claims the oldest eligible release event, resolves every database-only
    /// outcome inside the claim transaction, and hands a prepared delivery to
    /// the network phase. The claim transaction is always committed or rolled
    /// back before this function returns: no row lock survives into
    /// artifact-store or SMTP I/O.
    async fn claim_next(
        &self,
        skipped: &[Uuid],
    ) -> Result<Option<ClaimedEvent>, ReinjectionWorkerError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ReinjectionWorkerError::Persistence)?;
        let event = sqlx::query(
            "SELECT id, customer_id, deployment_id, trace_id, payload \
             FROM claim_quarantine_reinjection_event($1, $2)",
        )
        .bind(RELEASE_EVENT_TYPE)
        .bind(skipped)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ReinjectionWorkerError::Persistence)?;
        let Some(event) = event else {
            transaction
                .commit()
                .await
                .map_err(|_| ReinjectionWorkerError::Persistence)?;
            return Ok(None);
        };
        let event_id: Uuid = event.get("id");

        let customer_id = event
            .get::<Option<String>, _>("customer_id")
            .filter(|value| !value.is_empty());
        let tenant_message_id = event
            .get::<Value, _>("payload")
            .get("tenant_message_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok());
        let (Some(customer_id), Some(tenant_message_id)) = (customer_id, tenant_message_id) else {
            // The claim transaction is rolled back on return, matching the
            // former drop-before-dead-letter behaviour.
            return Ok(Some(ClaimedEvent {
                event_id,
                event,
                guard: None,
                outcome: ClaimOutcome::Invalid,
            }));
        };
        let event_context = EventContext {
            customer_id,
            deployment_id: event.get("deployment_id"),
            trace_id: event.get("trace_id"),
            tenant_message_id,
        };

        // Cross-process delivery guard, taken before the claim row lock is
        // released so a sibling worker can never observe this event as both
        // claimable and unguarded.
        let Some(guard) = self.try_acquire_guard(event_id).await? else {
            return Ok(Some(ClaimedEvent {
                event_id,
                event,
                guard: None,
                outcome: ClaimOutcome::Contended,
            }));
        };

        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&event_context.customer_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ReinjectionWorkerError::Persistence)?;

        if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM reinjection_deliveries \
             WHERE outbox_event_id = $1 AND outcome = 'succeeded')",
        )
        .bind(event_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ReinjectionWorkerError::Persistence)?
        {
            mark_published(&mut transaction, event_id).await?;
            transaction
                .commit()
                .await
                .map_err(|_| ReinjectionWorkerError::Persistence)?;
            return Ok(Some(ClaimedEvent {
                event_id,
                event,
                guard: Some(guard),
                outcome: ClaimOutcome::Terminal(ReinjectionRunOutcome::AlreadyDelivered {
                    outbox_event_id: event_id,
                }),
            }));
        }

        let failed_attempts = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM reinjection_deliveries \
             WHERE outbox_event_id = $1 AND outcome = 'failed'",
        )
        .bind(event_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ReinjectionWorkerError::Persistence)?;
        if failed_attempts >= self.config.max_attempts {
            record_dead_letter(
                &mut transaction,
                event_id,
                event_context.tenant_message_id,
                &event_context.deployment_id,
                &event_context.customer_id,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| ReinjectionWorkerError::Persistence)?;
            return Ok(Some(ClaimedEvent {
                event_id,
                event,
                guard: Some(guard),
                outcome: ClaimOutcome::Terminal(ReinjectionRunOutcome::AttemptsExhausted {
                    outbox_event_id: event_id,
                }),
            }));
        }

        let row = sqlx::query(
            "SELECT q.tenant_message_id, q.transaction_id, q.deployment_id, q.customer_id, \
                    q.artifact_id, e.envelope_sender, e.recipients, \
                    a.content_type, a.size_bytes, a.content_hash, a.storage_backend, \
                    a.storage_path, a.retention_class, a.encryption_enabled, a.created_at \
             FROM quarantine_cases q \
             JOIN quarantine_reinjection_envelopes e ON e.tenant_message_id = q.tenant_message_id \
             JOIN artifacts a ON a.id = q.artifact_id \
             WHERE q.tenant_message_id = $1 AND q.customer_id = $2 AND q.deployment_id = $3 \
               AND q.released_at IS NOT NULL",
        )
        .bind(event_context.tenant_message_id)
        .bind(&event_context.customer_id)
        .bind(&event_context.deployment_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ReinjectionWorkerError::Persistence)?;

        let Some(row) = row else {
            return Ok(Some(ClaimedEvent {
                event_id,
                event,
                guard: Some(guard),
                outcome: ClaimOutcome::Invalid,
            }));
        };

        let prepared = match prepare_delivery(event_id, &event_context, &row, failed_attempts) {
            Ok(prepared) => Box::new(prepared),
            Err(ReinjectionWorkerError::InvalidEvent) => {
                return Ok(Some(ClaimedEvent {
                    event_id,
                    event,
                    guard: Some(guard),
                    outcome: ClaimOutcome::Invalid,
                }));
            },
            Err(error) => return Err(error),
        };

        transaction
            .commit()
            .await
            .map_err(|_| ReinjectionWorkerError::Persistence)?;
        Ok(Some(ClaimedEvent {
            event_id,
            event,
            guard: Some(guard),
            outcome: ClaimOutcome::Ready(prepared),
        }))
    }

    /// Takes the cross-process delivery guard for one event on a dedicated
    /// pooled connection. Returns `None` when a sibling process already holds
    /// it; the connection is then returned to the pool without the lock.
    async fn try_acquire_guard(
        &self,
        event_id: Uuid,
    ) -> Result<Option<AdvisoryGuard>, ReinjectionWorkerError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReinjectionWorkerError::Persistence)?;
        let key = advisory_lock_key(event_id);
        let acquired = match sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1, $2)")
            .bind(key.0)
            .bind(key.1)
            .fetch_one(&mut *connection)
            .await
        {
            Ok(acquired) => acquired,
            Err(_) => {
                // Never return a session of unknown lock state to the pool.
                let _ = connection.close().await;
                return Err(ReinjectionWorkerError::Persistence);
            },
        };
        if acquired {
            Ok(Some(AdvisoryGuard {
                connection: Some(connection),
                key,
            }))
        } else {
            drop(connection);
            Ok(None)
        }
    }

    /// Phase B + C: artifact-store and SMTP I/O with no database transaction
    /// held, then one short transaction that records the terminal outcome.
    /// The tenant GUC is re-established in the finalize transaction because
    /// `set_config(..., true)` is scoped to the transaction that set it.
    async fn deliver(
        &self,
        prepared: PreparedDelivery,
    ) -> Result<ReinjectionRunOutcome, ReinjectionWorkerError> {
        let PreparedDelivery {
            event_id,
            customer_id,
            deployment_id,
            trace_id,
            tenant_message_id,
            transaction_id,
            artifact,
            artifact_id,
            envelope_sender,
            recipients,
            attempt_id,
            failed_attempts,
            grant,
        } = prepared;

        if self.store.recover_existing(artifact).await.is_err() {
            return self
                .finalize_failure(
                    &DeliveryIdentity {
                        event_id,
                        tenant_message_id,
                        transaction_id,
                        deployment_id: &deployment_id,
                        customer_id: &customer_id,
                        attempt_id,
                    },
                    failed_attempts,
                    "ARTIFACT_UNAVAILABLE",
                )
                .await;
        }
        let authorized = match self.store.get(&grant, &ArtifactId(artifact_id)).await {
            Ok(artifact) => artifact,
            Err(_) => {
                return self
                    .finalize_failure(
                        &DeliveryIdentity {
                            event_id,
                            tenant_message_id,
                            transaction_id,
                            deployment_id: &deployment_id,
                            customer_id: &customer_id,
                            attempt_id,
                        },
                        failed_attempts,
                        "ARTIFACT_UNAVAILABLE",
                    )
                    .await;
            },
        };
        if contains_loop_header(&authorized.bytes) {
            return self
                .finalize_failure(
                    &DeliveryIdentity {
                        event_id,
                        tenant_message_id,
                        transaction_id,
                        deployment_id: &deployment_id,
                        customer_id: &customer_id,
                        attempt_id,
                    },
                    failed_attempts,
                    "LOOP_HEADER_PRESENT",
                )
                .await;
        }

        let message = add_reinjection_headers(
            authorized.bytes,
            &deployment_id,
            transaction_id,
            tenant_message_id,
            attempt_id,
            &trace_id,
        );
        let queue_id = match submit_smtp(
            &self.config.endpoint,
            self.config.timeout,
            &envelope_sender,
            &recipients,
            &message,
        )
        .await
        {
            Ok(queue_id) => queue_id,
            Err(_) => {
                return self
                    .finalize_failure(
                        &DeliveryIdentity {
                            event_id,
                            tenant_message_id,
                            transaction_id,
                            deployment_id: &deployment_id,
                            customer_id: &customer_id,
                            attempt_id,
                        },
                        failed_attempts,
                        "SMTP_UNAVAILABLE",
                    )
                    .await;
            },
        };

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ReinjectionWorkerError::Persistence)?;
        set_tenant_scope(&mut transaction, &customer_id).await?;
        sqlx::query(
            "INSERT INTO reinjection_deliveries \
             (outbox_event_id, tenant_message_id, transaction_id, deployment_id, customer_id, \
              delivery_attempt_id, outcome, postfix_queue_id) \
             VALUES ($1,$2,$3,$4,$5,$6,'succeeded',$7)",
        )
        .bind(event_id)
        .bind(tenant_message_id)
        .bind(transaction_id)
        .bind(&deployment_id)
        .bind(&customer_id)
        .bind(attempt_id)
        .bind(&queue_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ReinjectionWorkerError::Persistence)?;
        mark_published(&mut transaction, event_id).await?;
        transaction
            .commit()
            .await
            .map_err(|_| ReinjectionWorkerError::Persistence)?;
        Ok(ReinjectionRunOutcome::Delivered {
            outbox_event_id: event_id,
            queue_id,
        })
    }

    /// Records one failed delivery attempt in its own short transaction,
    /// dead-lettering the event when the attempt budget is exhausted.
    async fn finalize_failure(
        &self,
        identity: &DeliveryIdentity<'_>,
        failed_attempts: i64,
        code: &'static str,
    ) -> Result<ReinjectionRunOutcome, ReinjectionWorkerError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ReinjectionWorkerError::Persistence)?;
        set_tenant_scope(&mut transaction, identity.customer_id).await?;
        record_failure(&mut transaction, identity, code).await?;
        if failed_attempts + 1 >= self.config.max_attempts {
            record_dead_letter(
                &mut transaction,
                identity.event_id,
                identity.tenant_message_id,
                identity.deployment_id,
                identity.customer_id,
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| ReinjectionWorkerError::Persistence)?;
        Ok(ReinjectionRunOutcome::Failed {
            outbox_event_id: identity.event_id,
            code,
        })
    }

    /// Dead-letters a release event whose reinjection context can never be
    /// rebuilt, so terminal records are recorded instead of retried forever.
    /// Returns `false` when the event is not attributable to an existing
    /// tenant message, in which case the caller skips it for this cycle.
    async fn dead_letter_invalid_event(&self, event: &sqlx::postgres::PgRow) -> bool {
        let Ok(event_id) = event.try_get::<Uuid, _>("id") else {
            return false;
        };
        let customer_id = event
            .try_get::<Option<String>, _>("customer_id")
            .ok()
            .flatten()
            .filter(|value| !value.is_empty());
        let deployment_id = event.try_get::<String, _>("deployment_id").ok();
        let tenant_message_id = event
            .try_get::<Value, _>("payload")
            .ok()
            .and_then(|payload| {
                payload
                    .get("tenant_message_id")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
            });
        let (Some(customer_id), Some(deployment_id), Some(tenant_message_id)) =
            (customer_id, deployment_id, tenant_message_id)
        else {
            return false;
        };

        let mut transaction = match self.pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => {
                tracing::error!(error = %error, "quarantine reinjection dead-letter transaction unavailable");
                return false;
            },
        };
        if sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&customer_id)
            .execute(&mut *transaction)
            .await
            .is_err()
        {
            drop(transaction);
            return false;
        }
        let attributed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM tenant_message_instances \
                            WHERE id = $1 AND customer_id = $2) \
               AND EXISTS (SELECT 1 FROM customers WHERE id = $2) \
               AND EXISTS (SELECT 1 FROM deployments WHERE id = $3)",
        )
        .bind(tenant_message_id)
        .bind(&customer_id)
        .bind(&deployment_id)
        .fetch_one(&mut *transaction)
        .await;
        let Ok(true) = attributed else {
            drop(transaction);
            return false;
        };
        let recorded = sqlx::query(
            "INSERT INTO reinjection_dead_letters \
             (outbox_event_id, tenant_message_id, deployment_id, customer_id, failure_code) \
             VALUES ($1,$2,$3,$4,'INVALID_EVENT') ON CONFLICT (outbox_event_id) DO NOTHING",
        )
        .bind(event_id)
        .bind(tenant_message_id)
        .bind(&deployment_id)
        .bind(&customer_id)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = recorded {
            tracing::error!(error = %error, "quarantine reinjection dead-letter rejected");
            drop(transaction);
            return false;
        }
        match transaction.commit().await {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(error = %error, "quarantine reinjection dead-letter commit failed");
                false
            },
        }
    }
}

/// One claimed release event plus its cross-process delivery guard. The guard
/// must outlive the network phase and be released immediately after the
/// finalize transaction commits or rolls back.
struct ClaimedEvent {
    event_id: Uuid,
    event: sqlx::postgres::PgRow,
    outcome: ClaimOutcome,
    guard: Option<AdvisoryGuard>,
}

enum ClaimOutcome {
    /// Resolved entirely inside the claim transaction (already delivered or
    /// attempts exhausted); the claim transaction is committed.
    Terminal(ReinjectionRunOutcome),
    /// The event cannot be delivered as recorded; the claim transaction was
    /// rolled back and the caller may dead-letter or skip it.
    Invalid,
    /// A sibling process holds the delivery guard for this event.
    Contended,
    /// Claim transaction committed; the event is ready for Phase B/C.
    Ready(Box<PreparedDelivery>),
}

/// Everything Phase A proved from the database, ready for the network phase.
struct PreparedDelivery {
    event_id: Uuid,
    customer_id: String,
    deployment_id: String,
    trace_id: String,
    tenant_message_id: Uuid,
    transaction_id: Uuid,
    artifact: Artifact,
    artifact_id: Uuid,
    envelope_sender: String,
    recipients: Vec<String>,
    attempt_id: Uuid,
    failed_attempts: i64,
    grant: ArtifactAccessGrant,
}

/// Extracts and validates the delivery plan from the claimed event's
/// quarantine context. Pure database/payload validation: no I/O, so it runs
/// inside the claim transaction.
fn prepare_delivery(
    event_id: Uuid,
    event_context: &EventContext,
    row: &sqlx::postgres::PgRow,
    failed_attempts: i64,
) -> Result<PreparedDelivery, ReinjectionWorkerError> {
    let transaction_id: Uuid = row.get("transaction_id");
    let artifact_id: Uuid = row.get("artifact_id");
    let recipients = parse_recipients(row.get("recipients"))?;
    let envelope_sender: String = row.get("envelope_sender");
    validate_envelope(&envelope_sender, &recipients)?;
    let artifact = artifact_from_row(
        row,
        artifact_id,
        &event_context.deployment_id,
        &event_context.customer_id,
    )?;
    let grant = ArtifactAccessGrant::issue_server_authorized(
        DeploymentId::new(&event_context.deployment_id),
        ArtifactScope::Customer(CustomerId::new(&event_context.customer_id)),
        WORKER_ACTOR.to_string(),
        ArtifactPermissions::content_read_only(),
        ArtifactAccessPurpose::QuarantineRelease,
        [ArtifactId(artifact_id)],
        Utc::now() + chrono::Duration::seconds(60),
    )
    .map_err(|_| ReinjectionWorkerError::InvalidEvent)?;
    Ok(PreparedDelivery {
        event_id,
        customer_id: event_context.customer_id.clone(),
        deployment_id: event_context.deployment_id.clone(),
        trace_id: event_context.trace_id.clone(),
        tenant_message_id: event_context.tenant_message_id,
        transaction_id,
        artifact,
        artifact_id,
        envelope_sender,
        recipients,
        attempt_id: Uuid::new_v4(),
        failed_attempts,
        grant,
    })
}

/// Tenant attribution parsed from the claimed outbox event before any
/// quarantine context is loaded.
struct EventContext {
    customer_id: String,
    deployment_id: String,
    trace_id: String,
    tenant_message_id: Uuid,
}

/// Session-level advisory lock held on a dedicated pooled connection for the
/// duration of one event's network-delivery window. It replaces the claim
/// transaction's row lock during artifact-store and SMTP I/O. Postgres
/// releases the lock when the session ends, so a crashed worker can never
/// strand an event: the lock disappears with its connection.
struct AdvisoryGuard {
    connection: Option<PoolConnection<Postgres>>,
    key: (i32, i32),
}

impl AdvisoryGuard {
    async fn release(mut self) {
        if let Some(mut connection) = self.connection.take() {
            let released = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1, $2)")
                .bind(self.key.0)
                .bind(self.key.1)
                .fetch_one(&mut *connection)
                .await
                .unwrap_or(false);
            if released {
                drop(connection);
            } else {
                // The session's lock state is unknown; never reuse it.
                let _ = connection.close().await;
            }
        }
    }
}

impl Drop for AdvisoryGuard {
    fn drop(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            let (key1, key2) = self.key;
            // Safety net for paths that did not await `release`: unlock the
            // session before it returns to the pool so the lock can never be
            // inherited by an unrelated checkout. The worker always runs
            // inside the Tokio runtime; without one the connection is simply
            // dropped and the lock dies with the session.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = sqlx::query("SELECT pg_advisory_unlock($1, $2)")
                        .bind(key1)
                        .bind(key2)
                        .execute(&mut *connection)
                        .await;
                });
            }
        }
    }
}

/// Advisory lock namespace for reinjection delivery guards. The second key
/// is the first four bytes of the event UUID, so distinct events never
/// contend with each other.
fn advisory_lock_key(event_id: Uuid) -> (i32, i32) {
    let bytes = event_id.as_bytes();
    (
        0x7172_6569, // "qrei"
        i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    )
}

/// Restores the tenant GUC inside a fresh transaction before any RLS
/// protected row is written; `set_config(..., true)` is transaction-local.
async fn set_tenant_scope(
    transaction: &mut Transaction<'_, Postgres>,
    customer_id: &str,
) -> Result<(), ReinjectionWorkerError> {
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(customer_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ReinjectionWorkerError::Persistence)?;
    Ok(())
}

struct DeliveryIdentity<'a> {
    event_id: Uuid,
    tenant_message_id: Uuid,
    transaction_id: Uuid,
    deployment_id: &'a str,
    customer_id: &'a str,
    attempt_id: Uuid,
}

async fn record_failure(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &DeliveryIdentity<'_>,
    code: &'static str,
) -> Result<(), ReinjectionWorkerError> {
    sqlx::query(
        "INSERT INTO reinjection_deliveries \
         (outbox_event_id, tenant_message_id, transaction_id, deployment_id, customer_id, \
          delivery_attempt_id, outcome, error_code) VALUES ($1,$2,$3,$4,$5,$6,'failed',$7)",
    )
    .bind(identity.event_id)
    .bind(identity.tenant_message_id)
    .bind(identity.transaction_id)
    .bind(identity.deployment_id)
    .bind(identity.customer_id)
    .bind(identity.attempt_id)
    .bind(code)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ReinjectionWorkerError::Persistence)?;
    Ok(())
}

async fn record_dead_letter(
    transaction: &mut Transaction<'_, Postgres>,
    event_id: Uuid,
    tenant_message_id: Uuid,
    deployment_id: &str,
    customer_id: &str,
) -> Result<(), ReinjectionWorkerError> {
    let failure_code = sqlx::query_scalar::<_, String>(
        "SELECT error_code FROM reinjection_deliveries \
         WHERE outbox_event_id = $1 AND outcome = 'failed' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(event_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ReinjectionWorkerError::Persistence)?;
    sqlx::query(
        "INSERT INTO reinjection_dead_letters \
         (outbox_event_id, tenant_message_id, deployment_id, customer_id, failure_code) \
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (outbox_event_id) DO NOTHING",
    )
    .bind(event_id)
    .bind(tenant_message_id)
    .bind(deployment_id)
    .bind(customer_id)
    .bind(failure_code)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ReinjectionWorkerError::Persistence)?;
    Ok(())
}

async fn mark_published(
    transaction: &mut Transaction<'_, Postgres>,
    event_id: Uuid,
) -> Result<(), ReinjectionWorkerError> {
    sqlx::query(
        "UPDATE outbox_events SET published_at = now() WHERE id = $1 AND published_at IS NULL",
    )
    .bind(event_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ReinjectionWorkerError::Persistence)?;
    Ok(())
}

fn artifact_from_row(
    row: &sqlx::postgres::PgRow,
    artifact_id: Uuid,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Artifact, ReinjectionWorkerError> {
    let content_hash: String = row.get("content_hash");
    let hash = content_hash
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64)
        .ok_or(ReinjectionWorkerError::InvalidEvent)?;
    if row.get::<String, _>("storage_backend") != "filesystem"
        || row.get::<String, _>("storage_path") != format!("{artifact_id}.artifact")
        || row.get::<String, _>("retention_class") != "standard"
    {
        return Err(ReinjectionWorkerError::InvalidEvent);
    }
    let size = u64::try_from(row.get::<i64, _>("size_bytes"))
        .map_err(|_| ReinjectionWorkerError::InvalidEvent)?;
    let content_type: String = row.get("content_type");
    Ok(Artifact {
        id: ArtifactId(artifact_id),
        deployment_id: DeploymentId::new(deployment_id),
        customer_id: Some(CustomerId::new(customer_id)),
        content_type: ContentType::new(&content_type),
        size,
        storage_location: StorageLocation {
            backend: StorageBackend::Filesystem,
            bucket: None,
            key: format!("{artifact_id}.artifact"),
            region: None,
        },
        hash: ArtifactHash {
            algorithm: HashAlgorithm::Sha256,
            value: hash.to_string(),
        },
        retention_class: RetentionClass::Standard,
        created_at: row.get("created_at"),
        expires_at: None,
        encrypted: row.get("encryption_enabled"),
        scanner_eligible: true,
    })
}

fn parse_recipients(value: Value) -> Result<Vec<String>, ReinjectionWorkerError> {
    let recipients = value
        .as_array()
        .ok_or(ReinjectionWorkerError::InvalidEvent)?
        .iter()
        .map(|value| value.as_str().map(str::to_string))
        .collect::<Option<Vec<_>>>()
        .ok_or(ReinjectionWorkerError::InvalidEvent)?;
    if recipients.is_empty() || recipients.len() > 500 {
        return Err(ReinjectionWorkerError::InvalidEvent);
    }
    Ok(recipients)
}

fn validate_envelope(sender: &str, recipients: &[String]) -> Result<(), ReinjectionWorkerError> {
    let valid = |address: &str| {
        !address.is_empty()
            && address.len() <= 320
            && !address.contains(['\r', '\n'])
            && (address == "<>" || (address.contains('@') && !address.contains(['<', '>'])))
    };
    if !valid(sender)
        || recipients
            .iter()
            .any(|recipient| !valid(recipient) || recipient == "<>")
    {
        return Err(ReinjectionWorkerError::InvalidEvent);
    }
    Ok(())
}

fn contains_loop_header(message: &[u8]) -> bool {
    let header_end = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 2)
        .or_else(|| {
            message
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 1)
        })
        .unwrap_or(message.len());
    message[..header_end]
        .split(|byte| *byte == b'\n')
        .filter_map(|line| std::str::from_utf8(line).ok())
        .map(|line| line.trim_end_matches('\r').to_ascii_lowercase())
        .any(|line| {
            line.starts_with("x-nullapart-reinjected:") || line.starts_with("x-nullapart-loop:")
        })
}

fn add_reinjection_headers(
    mut message: Vec<u8>,
    deployment_id: &str,
    transaction_id: Uuid,
    tenant_message_id: Uuid,
    attempt_id: Uuid,
    trace_id: &str,
) -> Vec<u8> {
    let safe_trace = trace_id.replace(['\r', '\n'], "");
    let headers = format!(
        "X-Nullapart-Reinjected: {deployment_id};{transaction_id}\r\n\
         X-Nullapart-Tenant-Message: {tenant_message_id}\r\n\
         X-Nullapart-Delivery-Attempt: {attempt_id}\r\n\
         X-Nullapart-Trace: {safe_trace}\r\n"
    );
    let mut combined = Vec::with_capacity(headers.len() + message.len());
    combined.extend_from_slice(headers.as_bytes());
    combined.append(&mut message);
    combined
}

async fn submit_smtp(
    endpoint: &str,
    timeout: Duration,
    sender: &str,
    recipients: &[String],
    message: &[u8],
) -> Result<String, ()> {
    tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect(endpoint).await.map_err(|_| ())?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        expect_response(&mut reader, 220).await?;
        smtp_command(
            &mut reader,
            &mut write_half,
            b"EHLO mailcore.local\r\n",
            250,
        )
        .await?;
        let sender_path = if sender == "<>" { "" } else { sender };
        smtp_command(
            &mut reader,
            &mut write_half,
            format!("MAIL FROM:<{sender_path}>\r\n").as_bytes(),
            250,
        )
        .await?;
        for recipient in recipients {
            smtp_command(
                &mut reader,
                &mut write_half,
                format!("RCPT TO:<{recipient}>\r\n").as_bytes(),
                250,
            )
            .await?;
        }
        smtp_command(&mut reader, &mut write_half, b"DATA\r\n", 354).await?;
        let normalized = message.replace_newlines();
        for line in normalized.split_inclusive(|byte| *byte == b'\n') {
            if line.first() == Some(&b'.') {
                write_half.write_all(b".").await.map_err(|_| ())?;
            }
            write_half.write_all(line).await.map_err(|_| ())?;
        }
        if !normalized.ends_with(b"\n") {
            write_half.write_all(b"\r\n").await.map_err(|_| ())?;
        }
        write_half.write_all(b".\r\n").await.map_err(|_| ())?;
        let response = expect_response(&mut reader, 250).await?;
        let queue_id = response
            .split_whitespace()
            .last()
            .filter(|value| value.len() >= 5 && value.chars().all(|ch| ch.is_ascii_alphanumeric()))
            .ok_or(())?
            .to_string();
        let _ = smtp_command(&mut reader, &mut write_half, b"QUIT\r\n", 221).await;
        Ok(queue_id)
    })
    .await
    .map_err(|_| ())?
}

trait NormalizeNewlines {
    fn replace_newlines(&self) -> Vec<u8>;
}

impl NormalizeNewlines for [u8] {
    fn replace_newlines(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.len() + 16);
        let mut previous = None;
        for byte in self {
            if *byte == b'\n' && previous != Some(b'\r') {
                output.push(b'\r');
            }
            output.push(*byte);
            previous = Some(*byte);
        }
        output
    }
}

async fn smtp_command<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    command: &[u8],
    expected: u16,
) -> Result<String, ()> {
    writer.write_all(command).await.map_err(|_| ())?;
    expect_response(reader, expected).await
}

async fn expect_response<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    expected: u16,
) -> Result<String, ()> {
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.map_err(|_| ())? == 0 || line.len() < 4 {
            return Err(());
        }
        let code = line[..3].parse::<u16>().map_err(|_| ())?;
        if code != expected {
            return Err(());
        }
        let continuation = line.as_bytes().get(3) == Some(&b'-');
        if !continuation {
            return Ok(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_headers_are_detected_only_in_the_header_block() {
        assert!(contains_loop_header(
            b"From: a@example.test\r\nX-Nullapart-Reinjected: yes\r\n\r\nbody"
        ));
        assert!(contains_loop_header(b"x-nullapart-loop: yes\n\nbody"));
        assert!(!contains_loop_header(
            b"From: a@example.test\r\n\r\nX-Nullapart-Reinjected: body text"
        ));
    }

    #[test]
    fn envelope_validation_rejects_command_injection() {
        assert!(
            validate_envelope("a@example.test\r\nDATA", &["b@example.test".to_string()]).is_err()
        );
        assert!(validate_envelope(
            "a@example.test",
            &["b@example.test\nRCPT TO:<x@y>".to_string()]
        )
        .is_err());
    }

    #[test]
    fn reinjection_headers_are_server_derived() {
        let bytes = add_reinjection_headers(
            b"From: a@example.test\r\n\r\nbody".to_vec(),
            "LOCAL-TEST",
            Uuid::nil(),
            Uuid::nil(),
            Uuid::nil(),
            "trace\r\ninjected",
        );
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("X-Nullapart-Reinjected: LOCAL-TEST;"));
        assert!(!text.contains("trace\r\ninjected"));
    }
}

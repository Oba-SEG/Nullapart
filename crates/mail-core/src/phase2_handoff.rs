//! Durable authenticated Postfix handoff for the local Phase 2 runtime.
//!
//! The handler verifies the canonical HMAC before JSON parsing, resolves
//! recipients to active tenants from authoritative domain ownership, creates
//! deterministic retry-safe transaction/tenant rows, and invokes the scanner
//! pipeline. Raw MIME never enters PostgreSQL.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::Utc;
use nullapart_mail_contracts::artifact::ContentType;
use nullapart_mail_contracts::policy::{PolicyRevisionId, ReasonCode};
use nullapart_mail_contracts::transaction::{
    CustomerId, Disposition, TenantMessageId, TraceId, TransactionId,
};
use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::artifact_store::FilesystemArtifactStore;
use crate::dmarc_mailbox_ingress::ingest_dmarc_report_mailbox_message;
use crate::domain_auth_telemetry::{project_handoff_auth_telemetry, DomainAuthTelemetryInput};
use crate::handoff::{
    deterministic_transaction_id, process_handoff, verify_request_auth, AfterQueueHandoffRequest,
    AfterQueueHandoffResponse, HandoffConfig, HandoffStatus, HANDOFF_PATH,
};
use crate::policy::PolicyEvaluationResult;
use crate::scanner_pipeline::{DurableScannerPipeline, TenantScanContext};

#[derive(Clone)]
pub struct DurableHandoffState {
    config: HandoffConfig,
    pool: PgPool,
    pipeline: Arc<DurableScannerPipeline>,
    artifact_store: FilesystemArtifactStore,
}

impl DurableHandoffState {
    pub fn new(
        config: HandoffConfig,
        pool: PgPool,
        pipeline: DurableScannerPipeline,
        artifact_store: FilesystemArtifactStore,
    ) -> Self {
        Self {
            config,
            pool,
            pipeline: Arc::new(pipeline),
            artifact_store,
        }
    }
}

pub fn durable_handoff_router(state: DurableHandoffState) -> Router {
    Router::new()
        .route(HANDOFF_PATH, post(handle_durable_handoff))
        .layer(axum::extract::DefaultBodyLimit::max(
            state.config.max_message_size as usize,
        ))
        .with_state(state)
}

async fn handle_durable_handoff(
    State(state): State<DurableHandoffState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<AfterQueueHandoffResponse>), (StatusCode, &'static str)> {
    verify_request_auth(&state.config, &headers, &body)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized"))?;
    let request: AfterQueueHandoffRequest = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "malformed handoff request"))?;
    process_handoff(&state.config, &request)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid handoff request"))?;

    let raw_mime = STANDARD
        .decode(request.message_content.as_bytes())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid handoff request"))?;
    let transaction_id = deterministic_transaction_id(&state.config, &request);
    let prepared = prepare_tenant_rows(&state, &request, &transaction_id)
        .await
        .map_err(|error| error.http())?;

    if prepared.complete_duplicate {
        return Ok((
            StatusCode::OK,
            Json(AfterQueueHandoffResponse {
                transaction_id: transaction_id.to_string(),
                status: HandoffStatus::Duplicate,
                message: "Handoff already processed".to_string(),
            }),
        ));
    }

    for tenant in prepared.tenants {
        if tenant.already_scanned {
            continue;
        }
        let policy_revision = PolicyRevisionId(Uuid::new_v5(
            &tenant.tenant_message_id.0,
            b"nullapart-local-finding-policy-v1",
        ));
        let context = TenantScanContext {
            tenant_message_id: tenant.tenant_message_id,
            transaction_id: transaction_id.clone(),
            deployment_id: state.config.deployment_id.clone(),
            customer_id: tenant.customer_id,
            trace_id: request
                .trace_id
                .as_deref()
                .and_then(|value| Uuid::parse_str(value).ok())
                .map(TraceId)
                .unwrap_or_default(),
            accepted_at: request.handoff_at,
            envelope_sender: request.envelope_sender.address().to_string(),
            recipients: tenant.recipients,
        };
        let outcome = state
            .pipeline
            .process_with_policy(
                context.clone(),
                raw_mime.clone(),
                ContentType::new("message/rfc822"),
                move |scan| local_finding_policy(scan, policy_revision),
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "phase 2 handoff pipeline failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "mail security processing unavailable",
                )
            })?;
        if let Err(error) = project_handoff_auth_telemetry(
            &state.pool,
            DomainAuthTelemetryInput {
                deployment_id: &state.config.deployment_id,
                customer_id: &context.customer_id,
                transaction_id: &transaction_id,
                tenant_message_id: &context.tenant_message_id,
                request: &request,
                raw_mime: &raw_mime,
                disposition: outcome.disposition,
            },
        )
        .await
        {
            tracing::warn!(error = %error, "domain authentication telemetry projection skipped");
        }
        match ingest_dmarc_report_mailbox_message(
            &state.pool,
            &state.artifact_store,
            &state.config.deployment_id,
            &context.customer_id,
            &context.tenant_message_id,
            &raw_mime,
        )
        .await
        {
            Ok(outcome) if outcome.queued > 0 || outcome.skipped_oversize > 0 => {
                tracing::info!(
                    queued = outcome.queued,
                    skipped_oversize = outcome.skipped_oversize,
                    "dmarc report mailbox parts inspected"
                );
            },
            Ok(_) => {},
            Err(error) => {
                tracing::warn!(error = %error, "dmarc report mailbox ingestion skipped");
            },
        }
    }

    Ok((
        StatusCode::OK,
        Json(AfterQueueHandoffResponse {
            transaction_id: transaction_id.to_string(),
            status: HandoffStatus::Accepted,
            message: "Handoff durably scanned and evaluated".to_string(),
        }),
    ))
}

/// The local reviewed finding policy: any normalized, non-false-positive
/// finding quarantines; complete clean required coverage allows. This is
/// the production consequence of inline ML evidence, asserted directly by
/// the pipeline integration tests.
pub fn local_finding_policy(
    scan: &crate::scanner_fabric::ScannerFabricResult,
    policy_revision: PolicyRevisionId,
) -> PolicyEvaluationResult {
    let has_finding = scan.findings.iter().any(|finding| !finding.false_positive);
    PolicyEvaluationResult {
        disposition: if has_finding {
            Disposition::Quarantine
        } else {
            Disposition::Allow
        },
        reason_code: if has_finding {
            ReasonCode::quarantine_malware()
        } else {
            ReasonCode::allowed()
        },
        policy_revision,
        explanation: if has_finding {
            "Local reviewed policy quarantines normalized security findings".to_string()
        } else {
            "Local reviewed policy allows complete clean required coverage".to_string()
        },
        findings_applied: scan
            .findings
            .iter()
            .filter(|finding| !finding.false_positive)
            .map(|finding| finding.id.0.to_string())
            .collect(),
        evaluated_at: Utc::now(),
    }
}

struct PreparedTenant {
    tenant_message_id: TenantMessageId,
    customer_id: CustomerId,
    recipients: Vec<String>,
    already_scanned: bool,
}

struct PreparedHandoff {
    tenants: Vec<PreparedTenant>,
    complete_duplicate: bool,
}

#[derive(Debug)]
enum PrepareError {
    Conflict,
    UnmappedRecipient,
    Unavailable,
}

impl PrepareError {
    fn http(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Conflict => (StatusCode::CONFLICT, "handoff identity conflict"),
            Self::UnmappedRecipient => (StatusCode::UNPROCESSABLE_ENTITY, "recipient is unmapped"),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "handoff persistence unavailable",
            ),
        }
    }
}

async fn prepare_tenant_rows(
    state: &DurableHandoffState,
    request: &AfterQueueHandoffRequest,
    transaction_id: &TransactionId,
) -> Result<PreparedHandoff, PrepareError> {
    let mut transaction = state
        .pool
        .begin()
        .await
        .map_err(|_| PrepareError::Unavailable)?;
    let existing = sqlx::query(
        "SELECT content_hash, transaction_id FROM handoff_idempotency \
         WHERE deployment_id = $1 AND postfix_queue_id = $2 FOR UPDATE",
    )
    .bind(&state.config.deployment_id.0)
    .bind(&request.postfix_queue_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| PrepareError::Unavailable)?;
    let duplicate = if let Some(row) = existing {
        if row.get::<String, _>("content_hash") != request.content_hash
            || row.get::<Uuid, _>("transaction_id") != transaction_id.0
        {
            return Err(PrepareError::Conflict);
        }
        true
    } else {
        sqlx::query(
            "INSERT INTO handoff_idempotency \
             (deployment_id, postfix_queue_id, content_hash, transaction_id) VALUES ($1,$2,$3,$4)",
        )
        .bind(&state.config.deployment_id.0)
        .bind(&request.postfix_queue_id)
        .bind(&request.content_hash)
        .bind(transaction_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PrepareError::Unavailable)?;
        false
    };

    let domains = request
        .recipients
        .iter()
        .filter_map(|recipient| {
            recipient
                .address
                .rsplit_once('@')
                .map(|(_, domain)| domain.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();
    if domains.len() != request.recipients.len() {
        return Err(PrepareError::UnmappedRecipient);
    }
    let mappings = sqlx::query(
        "SELECT domain, customer_id \
         FROM resolve_verified_recipient_domains($1, $2)",
    )
    .bind(&domains)
    .bind(&state.config.deployment_id.0)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| PrepareError::Unavailable)?;
    let domain_to_customer = mappings
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("domain"),
                row.get::<String, _>("customer_id"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut groups = BTreeMap::<String, Vec<String>>::new();
    for recipient in &request.recipients {
        let domain = recipient
            .address
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_ascii_lowercase())
            .ok_or(PrepareError::UnmappedRecipient)?;
        let customer = domain_to_customer
            .get(&domain)
            .ok_or(PrepareError::UnmappedRecipient)?;
        groups
            .entry(customer.clone())
            .or_default()
            .push(recipient.address.clone());
    }

    let inserted_transaction = sqlx::query(
        "INSERT INTO smtp_transactions \
         (id, deployment_id, direction, envelope_sender, content_hash, mime_artifact_id, \
          spf_result, dkim_result, dmarc_result, received_at, connection_id, trace_id, postfix_queue_ids) \
         VALUES ($1,$2,'inbound',$3,$4,'pending',$5,$6,$7,$8,$9,$10,$11) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(transaction_id.0)
    .bind(&state.config.deployment_id.0)
    .bind(request.envelope_sender.address())
    .bind(&request.content_hash)
    .bind(json!({"result": request.milter_observations.spf_result}))
    .bind(json!({"result": request.milter_observations.dkim_result}))
    .bind(json!({"result": request.milter_observations.dmarc_result}))
    .bind(request.handoff_at)
    .bind(&request.connection.session_id)
    .bind(request.trace_id.as_deref())
    .bind(vec![request.postfix_queue_id.clone()])
    .execute(&mut *transaction)
    .await
    .map_err(|_| PrepareError::Unavailable)?
    .rows_affected()
        == 1;
    if inserted_transaction {
        for recipient in &request.recipients {
            let notify = recipient.notify.as_ref().map(|options| {
                options
                    .iter()
                    .map(|option| format!("{option:?}").to_ascii_lowercase())
                    .collect::<Vec<_>>()
            });
            sqlx::query(
                "INSERT INTO smtp_transaction_recipients (transaction_id, address, orcpt, notify) \
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(transaction_id.0)
            .bind(&recipient.address)
            .bind(&recipient.orcpt)
            .bind(notify)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PrepareError::Unavailable)?;
        }
    }

    let mut tenants = Vec::with_capacity(groups.len());
    for (customer, recipients) in groups {
        let tenant_message_id =
            TenantMessageId(Uuid::new_v5(&transaction_id.0, customer.as_bytes()));
        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&customer)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PrepareError::Unavailable)?;
        let inserted = sqlx::query(
            "INSERT INTO tenant_message_instances (id, transaction_id, customer_id, disposition) \
             VALUES ($1,$2,$3,'hold') ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant_message_id.0)
        .bind(transaction_id.0)
        .bind(&customer)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PrepareError::Unavailable)?
        .rows_affected()
            == 1;
        if inserted {
            for recipient in &recipients {
                sqlx::query(
                    "INSERT INTO tenant_message_recipients (tenant_message_id, address) VALUES ($1,$2)",
                )
                .bind(tenant_message_id.0)
                .bind(recipient)
                .execute(&mut *transaction)
                .await
                .map_err(|_| PrepareError::Unavailable)?;
            }
        }
        let already_scanned = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM scanner_results WHERE tenant_message_id = $1)",
        )
        .bind(tenant_message_id.0)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| PrepareError::Unavailable)?;
        tenants.push(PreparedTenant {
            tenant_message_id,
            customer_id: CustomerId::new(&customer),
            recipients,
            already_scanned,
        });
    }
    let complete_duplicate = duplicate && tenants.iter().all(|tenant| tenant.already_scanned);
    transaction
        .commit()
        .await
        .map_err(|_| PrepareError::Unavailable)?;
    Ok(PreparedHandoff {
        tenants,
        complete_duplicate,
    })
}

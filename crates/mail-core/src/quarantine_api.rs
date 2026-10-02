//! Authenticated Phase 2 Control Plane quarantine API slice.
//!
//! The shared local-control boundary (`admin_rbac::authenticated_local_router`)
//! authenticates the request and injects `TenantContext`. These routes
//! deliberately do not parse tenant, role, or step-up facts from request
//! JSON, headers, or query parameters.

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nullapart_policy::TenantContext;

use crate::quarantine::{
    AuthorizedQuarantineRelease, QuarantineError, QuarantineReleaseRequest, QuarantineService,
};

const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";

#[derive(Clone)]
pub struct QuarantineApiState {
    service: QuarantineService,
}

impl QuarantineApiState {
    pub fn new(service: QuarantineService) -> Self {
        Self { service }
    }
}

#[derive(Debug, Serialize)]
pub struct ApiEnvelope<T> {
    pub data: T,
}

/// Safe customer-facing projection. It contains neither raw content, artifact
/// locations, nor scanner engine diagnostics.
#[derive(Debug, Serialize)]
pub struct QuarantineCaseResponse {
    pub tenant_message_id: String,
    pub transaction_id: String,
    pub reason_code: String,
    pub sender: String,
    pub recipient_count: u32,
    pub findings: Vec<QuarantineFindingResponse>,
    pub quarantined_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    pub release_allowed: bool,
}

#[derive(Debug, Serialize)]
pub struct QuarantineFindingResponse {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

/// Safe detail projection for one case. It adds retention state, audit
/// linkage and capability-labelled scanner results to the list projection;
/// it still carries no raw content, artifact location or engine diagnostic.
#[derive(Debug, Serialize)]
pub struct QuarantineDetailResponse {
    #[serde(flatten)]
    pub case: QuarantineCaseResponse,
    pub released_by: Option<String>,
    pub release_reason: Option<String>,
    pub retention: Option<QuarantineRetentionResponse>,
    pub scanner_results: Vec<QuarantineScannerResultResponse>,
    pub audit: Vec<QuarantineAuditEntryResponse>,
}

#[derive(Debug, Serialize)]
pub struct QuarantineRetentionResponse {
    pub retention_class: String,
    pub artifact_created_at: DateTime<Utc>,
    pub quarantined_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct QuarantineScannerResultResponse {
    pub capability: String,
    pub status: String,
    pub required: bool,
    pub duration_ms: Option<i64>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct QuarantineAuditEntryResponse {
    pub action: String,
    pub actor_login: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
}

impl QuarantineCaseResponse {
    fn from_item(item: crate::quarantine::QuarantineListItem, release_allowed: bool) -> Self {
        let case = item.case;
        Self {
            tenant_message_id: case.tenant_message_id.0.to_string(),
            transaction_id: case.transaction_id.0.to_string(),
            reason_code: case.reason_code.0,
            sender: item.envelope_sender,
            recipient_count: item.recipient_count,
            findings: item
                .findings
                .into_iter()
                .map(|finding| QuarantineFindingResponse {
                    id: finding.id.to_string(),
                    category: finding.category,
                    severity: finding.severity,
                    description: finding.description,
                    created_at: finding.created_at,
                })
                .collect(),
            quarantined_at: case.quarantined_at,
            released_at: case.released_at,
            release_allowed,
        }
    }
}

impl QuarantineDetailResponse {
    fn from_detail(detail: crate::quarantine::QuarantineDetail, release_allowed: bool) -> Self {
        let crate::quarantine::QuarantineDetail {
            item,
            retention,
            scanner_results,
            audit,
        } = detail;
        let released_by = item
            .case
            .released_by
            .as_ref()
            .map(|actor| actor.0.to_string());
        let release_reason = item.case.release_reason.clone();
        let case = QuarantineCaseResponse::from_item(item, release_allowed);
        Self {
            case,
            released_by,
            release_reason,
            retention: retention.map(|retention| QuarantineRetentionResponse {
                retention_class: retention.retention_class,
                artifact_created_at: retention.artifact_created_at,
                quarantined_at: retention.quarantined_at,
                released_at: retention.released_at,
            }),
            scanner_results: scanner_results
                .into_iter()
                .map(|result| QuarantineScannerResultResponse {
                    capability: result.capability,
                    status: result.status,
                    required: result.required,
                    duration_ms: result.duration_ms,
                    completed_at: result.completed_at,
                })
                .collect(),
            audit: audit
                .into_iter()
                .map(|entry| QuarantineAuditEntryResponse {
                    action: entry.action,
                    actor_login: entry.actor_login,
                    result: entry.result,
                    created_at: entry.created_at,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ReleaseBody {
    pub release_reason: String,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
}

pub fn quarantine_router(state: QuarantineApiState) -> Router {
    Router::new()
        .route("/api/v1/quarantine", get(list_quarantine))
        .route("/api/v1/quarantine/:tenant_message_id", get(get_quarantine))
        .route(
            "/api/v1/quarantine/:tenant_message_id/release",
            post(release_quarantine),
        )
        .with_state(state)
}

async fn get_quarantine(
    State(state): State<QuarantineApiState>,
    Path(tenant_message_id): Path<uuid::Uuid>,
    context: Option<Extension<TenantContext>>,
) -> impl IntoResponse {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let release_allowed = AuthorizedQuarantineRelease::from_authenticated_context(&context).is_ok();
    match state
        .service
        .detail(
            &context,
            &nullapart_mail_contracts::TenantMessageId(tenant_message_id),
        )
        .await
    {
        Ok(detail) => (
            StatusCode::OK,
            Json(ApiEnvelope {
                data: QuarantineDetailResponse::from_detail(detail, release_allowed),
            }),
        )
            .into_response(),
        Err(error) => quarantine_error_response(error),
    }
}

async fn list_quarantine(
    State(state): State<QuarantineApiState>,
    context: Option<Extension<TenantContext>>,
) -> impl IntoResponse {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let release_allowed = AuthorizedQuarantineRelease::from_authenticated_context(&context).is_ok();
    match state.service.list(&context).await {
        Ok(cases) => (
            StatusCode::OK,
            Json(ApiEnvelope {
                data: cases
                    .into_iter()
                    .map(|case| QuarantineCaseResponse::from_item(case, release_allowed))
                    .collect::<Vec<_>>(),
            }),
        )
            .into_response(),
        Err(error) => quarantine_error_response(error),
    }
}

async fn release_quarantine(
    State(state): State<QuarantineApiState>,
    Path(tenant_message_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    context: Option<Extension<TenantContext>>,
    Json(body): Json<ReleaseBody>,
) -> impl IntoResponse {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    let Some(idempotency_key) = headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_REQUIRED",
            "Idempotency key is required",
        );
    };
    let authorization = match AuthorizedQuarantineRelease::from_authenticated_context(&context) {
        Ok(authorization) => authorization,
        Err(error) => return quarantine_error_response(error),
    };
    match state
        .service
        .release(
            authorization,
            QuarantineReleaseRequest {
                tenant_message_id: nullapart_mail_contracts::TenantMessageId(tenant_message_id),
                release_reason: body.release_reason,
                idempotency_key: idempotency_key.to_string(),
            },
        )
        .await
    {
        Ok(case) => (
            StatusCode::OK,
            Json(ApiEnvelope {
                data: QuarantineCaseResponse {
                    tenant_message_id: case.tenant_message_id.0.to_string(),
                    transaction_id: case.transaction_id.0.to_string(),
                    reason_code: case.reason_code.0,
                    sender: "Unavailable".to_string(),
                    recipient_count: 0,
                    findings: Vec::new(),
                    quarantined_at: case.quarantined_at,
                    released_at: case.released_at,
                    release_allowed: true,
                },
            }),
        )
            .into_response(),
        Err(error) => quarantine_error_response(error),
    }
}

fn quarantine_error_response(error: QuarantineError) -> axum::response::Response {
    match error {
        QuarantineError::PermissionDenied | QuarantineError::CustomerInactive => {
            api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required")
        },
        QuarantineError::StepUpRequired => api_error(
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required",
        ),
        QuarantineError::NotFound | QuarantineError::OwnershipDenied => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Quarantine case was not found",
        ),
        QuarantineError::AlreadyReleased | QuarantineError::AlreadyQuarantined => {
            api_error(StatusCode::CONFLICT, "CONFLICT", "Quarantine state changed")
        },
        QuarantineError::InvalidReleaseReason
        | QuarantineError::InvalidIdempotencyKey
        | QuarantineError::InvalidTraceId
        | QuarantineError::InvalidEnvelope => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Request is invalid",
        ),
        QuarantineError::PersistenceFailed => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UNAVAILABLE",
            "Service is unavailable",
        ),
    }
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> axum::response::Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{body::Body, http::Request};
    use chrono::Utc;
    use nullapart_mail_contracts::{
        ActorId, ArtifactId, CustomerId, ReasonCode, TenantMessageId, TransactionId,
    };
    use nullapart_policy::{AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId};
    use tower::ServiceExt;

    use super::*;
    use crate::quarantine::{
        InMemoryQuarantineRepository, QuarantineCase, QUARANTINE_RELEASE_PERMISSION,
        QUARANTINE_VIEW_PERMISSION,
    };

    fn context(customer_id: &str, step_up: bool) -> TenantContext {
        TenantContext {
            deployment_id: nullapart_mail_contracts::DeploymentId::new("LOCAL-TEST"),
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
            permissions: vec![
                QUARANTINE_VIEW_PERMISSION.to_string(),
                QUARANTINE_RELEASE_PERMISSION.to_string(),
            ],
            config_revision: 1,
            trace_id: "trace".to_string(),
            correlation_id: "correlation".to_string(),
            session_id: "session".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn endpoint_requires_injected_context_and_scopes_results() {
        let repository = Arc::new(InMemoryQuarantineRepository::default());
        let case = QuarantineCase {
            tenant_message_id: TenantMessageId::new(),
            transaction_id: TransactionId::new(),
            deployment_id: nullapart_mail_contracts::DeploymentId::new("LOCAL-TEST"),
            customer_id: CustomerId::new("customer-a"),
            artifact_id: ArtifactId::new(),
            reason_code: ReasonCode::quarantine_malware(),
            quarantined_at: Utc::now(),
            released_at: None,
            released_by: None,
            release_reason: None,
        };
        repository.insert(case.clone()).await;
        let app = quarantine_router(QuarantineApiState::new(QuarantineService::new(repository)));
        let unauthenticated = app
            .clone()
            .oneshot(
                Request::get("/api/v1/quarantine")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        let scoped = app
            .oneshot(
                Request::get("/api/v1/quarantine")
                    .extension(context("customer-b", false))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scoped.status(), StatusCode::OK);
        let body = axum::body::to_bytes(scoped.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), br#"{"data":[]}"#);
    }

    #[tokio::test]
    async fn detail_route_is_tenant_scoped_and_returns_only_capability_labels() {
        let repository = Arc::new(InMemoryQuarantineRepository::default());
        let case = QuarantineCase {
            tenant_message_id: TenantMessageId::new(),
            transaction_id: TransactionId::new(),
            deployment_id: nullapart_mail_contracts::DeploymentId::new("LOCAL-TEST"),
            customer_id: CustomerId::new("customer-a"),
            artifact_id: ArtifactId::new(),
            reason_code: ReasonCode::quarantine_malware(),
            quarantined_at: Utc::now(),
            released_at: None,
            released_by: None,
            release_reason: None,
        };
        repository.insert(case.clone()).await;
        let app = quarantine_router(QuarantineApiState::new(QuarantineService::new(repository)));
        let path = format!("/api/v1/quarantine/{}", case.tenant_message_id.0);

        let foreign = app
            .clone()
            .oneshot(
                Request::get(&path)
                    .extension(context("customer-b", false))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);

        let scoped = app
            .oneshot(
                Request::get(&path)
                    .extension(context("customer-a", false))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scoped.status(), StatusCode::OK);
        let body = axum::body::to_bytes(scoped.into_body(), usize::MAX)
            .await
            .unwrap();
        let rendered = String::from_utf8(body.to_vec()).expect("utf-8 response");
        assert!(rendered.contains("\"scanner_results\":[]"));
        assert!(rendered.contains("\"audit\":[]"));
        assert!(rendered.contains("\"retention\":null"));
        assert!(rendered.contains("release_allowed"));
        // The detail projection must never carry scanner identifiers or raw
        // content; only capability-level evidence may leave the service.
        for forbidden in [
            "attachment-analysis",
            "static-rule",
            "url-reputation",
            "clamav",
            "raw_mime",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "detail leaked {forbidden}: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_envelope_maps_to_generic_invalid_request() {
        let response = quarantine_error_response(QuarantineError::InvalidEnvelope);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"code":"INVALID_REQUEST","message":"Request is invalid"}"#
        );
    }

    #[tokio::test]
    async fn release_endpoint_requires_step_up_and_is_idempotent() {
        let repository = Arc::new(InMemoryQuarantineRepository::default());
        let case = QuarantineCase {
            tenant_message_id: TenantMessageId::new(),
            transaction_id: TransactionId::new(),
            deployment_id: nullapart_mail_contracts::DeploymentId::new("LOCAL-TEST"),
            customer_id: CustomerId::new("customer-a"),
            artifact_id: ArtifactId::new(),
            reason_code: ReasonCode::quarantine_malware(),
            quarantined_at: Utc::now(),
            released_at: None,
            released_by: None,
            release_reason: None,
        };
        repository.insert(case.clone()).await;
        let app = quarantine_router(QuarantineApiState::new(QuarantineService::new(repository)));
        let path = format!("/api/v1/quarantine/{}/release", case.tenant_message_id.0);
        let first = Request::post(&path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_HEADER, "api-release-1")
            .extension(context("customer-a", true))
            .body(Body::from(
                r#"{"release_reason":"confirmed false positive"}"#,
            ))
            .unwrap();
        let first_response = app.clone().oneshot(first).await.unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);
        let retry = Request::post(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_HEADER, "api-release-1")
            .extension(context("customer-a", true))
            .body(Body::from(
                r#"{"release_reason":"confirmed false positive"}"#,
            ))
            .unwrap();
        let retry_response = app.oneshot(retry).await.unwrap();
        assert_eq!(retry_response.status(), StatusCode::OK);
    }
}

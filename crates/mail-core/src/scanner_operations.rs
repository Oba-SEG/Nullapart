//! Authenticated, tenant-scoped scanner/node operations projection.
//!
//! This API exposes product capability health and normalized aggregate counts
//! only. It never returns engine identifiers, versions, endpoints, raw
//! scanner messages, findings, MIME, attachment bytes, or storage details.

use std::sync::Arc;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use nullapart_mail_contracts::transaction::DeploymentId;
use nullapart_policy::{CustomerLifecycle, TenantContext};
use serde::Serialize;
use sqlx::{PgPool, Row};

use crate::scanner_fabric::ScannerFabric;

pub const SCANNER_OPERATIONS_VIEW_PERMISSION: &str = "scanner:operations:view";

#[derive(Clone)]
pub struct ScannerOperationsState {
    pool: PgPool,
    fabric: Arc<ScannerFabric>,
    deployment_id: DeploymentId,
    node_id: String,
}

impl ScannerOperationsState {
    pub fn new(
        pool: PgPool,
        fabric: Arc<ScannerFabric>,
        deployment_id: DeploymentId,
        node_id: String,
    ) -> Self {
        Self {
            pool,
            fabric,
            deployment_id,
            node_id,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiEnvelope<T> {
    data: T,
}

#[derive(Debug, Serialize)]
struct ScannerOperationsResponse {
    node: NodeStatusResponse,
    capabilities: Vec<CapabilityStatusResponse>,
    last_24_hours: RecentScannerTotals,
}

#[derive(Debug, Serialize)]
struct NodeStatusResponse {
    node_id: String,
    status: &'static str,
    configured_capabilities: usize,
    required_unhealthy: usize,
}

#[derive(Debug, Serialize)]
struct CapabilityStatusResponse {
    capability: String,
    requirement: &'static str,
    status: &'static str,
    checked_at: DateTime<Utc>,
    queue_depth: Option<u32>,
}

#[derive(Debug, Serialize)]
struct RecentScannerTotals {
    total: i64,
    clean: i64,
    non_clean: i64,
    inconclusive: i64,
    average_duration_ms: f64,
    release_reinjection_failures: i64,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
}

pub fn scanner_operations_router(state: ScannerOperationsState) -> Router {
    Router::new()
        .route("/api/v1/scanner-operations", get(get_scanner_operations))
        .with_state(state)
}

async fn get_scanner_operations(
    State(state): State<ScannerOperationsState>,
    context: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(context)) = context else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required",
        );
    };
    if context.customer_lifecycle != CustomerLifecycle::Active
        || context.deployment_id != state.deployment_id
        || !context
            .permissions
            .iter()
            .any(|permission| permission == SCANNER_OPERATIONS_VIEW_PERMISSION)
    {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }

    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(&context.customer_id.0)
        .execute(&mut *transaction)
        .await
        .is_err()
    {
        return unavailable();
    }
    let totals = match sqlx::query(
        "SELECT count(*)::bigint AS total, \
                count(*) FILTER (WHERE status = 'clean')::bigint AS clean, \
                count(*) FILTER (WHERE status IN ('threat', 'suspicious'))::bigint AS non_clean, \
                count(*) FILTER (WHERE status IN ('unknown', 'error'))::bigint AS inconclusive, \
                COALESCE(avg(duration_ms), 0)::float8 AS average_duration_ms, \
                (SELECT count(*)::bigint FROM reinjection_dead_letters \
                 WHERE customer_id = $1 AND deployment_id = $2 \
                   AND exhausted_at >= now() - interval '24 hours') \
                    AS release_reinjection_failures \
         FROM scanner_results \
         WHERE customer_id = $1 AND deployment_id = $2 \
           AND completed_at >= now() - interval '24 hours'",
    )
    .bind(&context.customer_id.0)
    .bind(&state.deployment_id.0)
    .fetch_one(&mut *transaction)
    .await
    {
        Ok(row) => RecentScannerTotals {
            total: row.get("total"),
            clean: row.get("clean"),
            non_clean: row.get("non_clean"),
            inconclusive: row.get("inconclusive"),
            average_duration_ms: row.get("average_duration_ms"),
            release_reinjection_failures: row.get("release_reinjection_failures"),
        },
        Err(_) => return unavailable(),
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }

    let capability_statuses = state.fabric.operation_statuses().await;
    let required_unhealthy = capability_statuses
        .iter()
        .filter(|status| status.required && !status.healthy)
        .count();
    let capabilities = capability_statuses
        .into_iter()
        .map(|status| CapabilityStatusResponse {
            capability: status.capability,
            requirement: if status.required {
                "required"
            } else {
                "optional"
            },
            status: if status.healthy {
                "healthy"
            } else {
                "unavailable"
            },
            checked_at: status.checked_at,
            queue_depth: status.queue_depth,
        })
        .collect::<Vec<_>>();
    let node_status = if required_unhealthy == 0 {
        "healthy"
    } else {
        "degraded"
    };
    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: ScannerOperationsResponse {
                node: NodeStatusResponse {
                    node_id: state.node_id,
                    status: node_status,
                    configured_capabilities: capabilities.len(),
                    required_unhealthy,
                },
                capabilities,
                last_24_hours: totals,
            },
        }),
    )
        .into_response()
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        "Scanner operations are unavailable",
    )
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiErrorBody { code, message })).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, Extension};
    use nullapart_mail_contracts::{transaction::CustomerId, ActorId};
    use nullapart_policy::{AuthenticationAssurance, ContextActor, RegionId};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::scanner_fabric::{ScannerFabric, ScannerFabricConfig};

    fn state() -> ScannerOperationsState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse");
        let fabric = ScannerFabric::new(ScannerFabricConfig::default(), Vec::new())
            .expect("empty test fabric must construct");
        ScannerOperationsState::new(
            pool,
            Arc::new(fabric),
            DeploymentId::new("LOCAL-TEST"),
            "mailcore-test".to_string(),
        )
    }

    fn context(permissions: Vec<String>) -> TenantContext {
        TenantContext {
            deployment_id: DeploymentId::new("LOCAL-TEST"),
            region: RegionId::new("local"),
            actor: ContextActor {
                actor_id: ActorId::new(),
                login: "operator@example.test".to_string(),
                roles: vec!["operator".to_string()],
                authentication_assurance: AuthenticationAssurance::StepUp,
            },
            impersonation: None,
            customer_id: CustomerId::new("customer-test"),
            customer_internal_key: 1,
            customer_display_name: "Customer test".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions,
            config_revision: 1,
            trace_id: "scanner-operations-test".to_string(),
            correlation_id: "scanner-operations-test".to_string(),
            session_id: "scanner-operations-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn scanner_operations_requires_authenticated_context() {
        let response = scanner_operations_router(state())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/scanner-operations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn scanner_operations_requires_explicit_permission_before_database_access() {
        let response = scanner_operations_router(state())
            .layer(Extension(context(Vec::new())))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/scanner-operations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

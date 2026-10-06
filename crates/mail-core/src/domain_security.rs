//! Authenticated Phase 5 domain-security projection.
//!
//! This API turns normalized DMARC/report-authorization/BIMI/observer rows
//! into an actionable Control Plane view. It returns counts, status, DNS owner
//! names and suggested next actions only. It never returns raw aggregate XML,
//! failure-report samples, message content, SVG bytes or DNS resolver internals.

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
use uuid::Uuid;

pub const DOMAIN_SECURITY_VIEW_PERMISSION: &str = "domain-security:view";
pub const DOMAIN_SECURITY_MANAGE_PERMISSION: &str = "domain-security:manage";

const DOMAIN_SECURITY_PATH: &str = "/api/v1/domain-security";

#[derive(Clone)]
pub struct DomainSecurityState {
    pool: PgPool,
    deployment_id: DeploymentId,
}

impl DomainSecurityState {
    pub fn new(pool: PgPool, deployment_id: DeploymentId) -> Self {
        Self {
            pool,
            deployment_id,
        }
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

#[derive(Debug, Serialize)]
struct DomainSecurityResponse {
    deployment_id: String,
    generated_at: DateTime<Utc>,
    summary: DomainSecuritySummary,
    domains: Vec<DomainSecurityDomain>,
    notifications: Vec<DomainSecurityNotification>,
}

#[derive(Debug, Serialize, Default)]
struct DomainSecuritySummary {
    domains_total: usize,
    verified_domains: usize,
    messages_30d: i64,
    dmarc_aligned_messages_30d: i64,
    unknown_sources: i64,
    report_authorization_broken: i64,
    bimi_not_ready: i64,
    open_notifications: i64,
}

#[derive(Debug, Serialize)]
struct DomainSecurityDomain {
    id: Uuid,
    domain: String,
    verification_status: String,
    domain_type: String,
    dmarc: DmarcDomainMetrics,
    report_authorization: Option<ReportAuthorizationStatus>,
    bimi: Option<BimiStatus>,
    observations: Vec<DomainObservation>,
    sources: Vec<DomainSourceSummary>,
    next_actions: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
struct DmarcDomainMetrics {
    latest_policy: Option<String>,
    reports_30d: i64,
    messages_30d: i64,
    dkim_aligned_messages_30d: i64,
    spf_aligned_messages_30d: i64,
    dmarc_aligned_messages_30d: i64,
    rejected_or_quarantined_messages_30d: i64,
}

#[derive(Debug, Serialize, Clone)]
struct ReportAuthorizationStatus {
    report_host: String,
    owner_name: String,
    expected_value: String,
    actual_value: Option<String>,
    status: String,
    checked_at: Option<DateTime<Utc>>,
    detail: String,
}

#[derive(Debug, Serialize, Clone)]
struct BimiStatus {
    selector: String,
    status: String,
    logo_url: Option<String>,
    svg_status: String,
    dmarc_enforcement_status: String,
    certificate_status: String,
    errors: Vec<String>,
    checked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Clone)]
struct DomainObservation {
    check_type: String,
    status: String,
    observed_value: Option<String>,
    detail: String,
    observed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Clone)]
struct DomainSourceSummary {
    source_key: String,
    source_ip: String,
    source_domain: Option<String>,
    messages_30d: i64,
    dkim_aligned_messages_30d: i64,
    spf_aligned_messages_30d: i64,
    dmarc_aligned_messages_30d: i64,
    classification: String,
    suggested_action: String,
}

#[derive(Debug, Serialize)]
struct DomainSecurityNotification {
    id: Uuid,
    domain_id: Option<Uuid>,
    notification_type: String,
    severity: String,
    title: String,
    detail: String,
    status: String,
    created_at: DateTime<Utc>,
}

pub fn domain_security_router(state: DomainSecurityState) -> Router {
    Router::new()
        .route(DOMAIN_SECURITY_PATH, get(get_domain_security))
        .with_state(state)
}

async fn get_domain_security(
    State(state): State<DomainSecurityState>,
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
        || !has_permission(&context, DOMAIN_SECURITY_VIEW_PERMISSION)
    {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Permission is required");
    }

    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return unavailable(),
    };
    if set_scope(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    .is_err()
    {
        return unavailable();
    }

    let domain_rows = match sqlx::query(
        "SELECT d.id, d.domain, d.verification_status, d.domain_type \
         FROM domains AS d \
         JOIN customers AS c ON c.id = d.customer_id \
         WHERE d.customer_id = $1 AND c.deployment_id = $2 \
         ORDER BY lower(d.domain)",
    )
    .bind(&context.customer_id.0)
    .bind(&state.deployment_id.0)
    .fetch_all(&mut *transaction)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };

    let metrics = match load_dmarc_metrics(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let sources = match load_sources(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let authorizations = match load_authorizations(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let bimi = match load_bimi(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let observations = match load_observations(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let notifications = match load_notifications(
        &mut transaction,
        &state.deployment_id.0,
        &context.customer_id.0,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };

    if transaction.commit().await.is_err() {
        return unavailable();
    }

    let mut summary = DomainSecuritySummary {
        domains_total: domain_rows.len(),
        ..DomainSecuritySummary::default()
    };
    let mut domains = Vec::with_capacity(domain_rows.len());
    for row in domain_rows {
        let domain_id: Uuid = row.get("id");
        let verification_status: String = row.get("verification_status");
        if verification_status == "verified" {
            summary.verified_domains += 1;
        }
        let dmarc = metrics
            .iter()
            .find(|(id, _)| *id == domain_id)
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        summary.messages_30d += dmarc.messages_30d;
        summary.dmarc_aligned_messages_30d += dmarc.dmarc_aligned_messages_30d;

        let domain_sources = sources
            .iter()
            .filter(|(id, _)| *id == domain_id)
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        summary.unknown_sources += domain_sources
            .iter()
            .filter(|source| source.classification == "unknown")
            .count() as i64;

        let report_authorization = authorizations
            .iter()
            .find(|(id, _)| *id == domain_id)
            .map(|(_, value)| value.clone());
        if report_authorization
            .as_ref()
            .is_some_and(|value| value.status != "valid")
        {
            summary.report_authorization_broken += 1;
        }

        let bimi_status = bimi
            .iter()
            .find(|(id, _)| *id == domain_id)
            .map(|(_, value)| value.clone());
        if bimi_status
            .as_ref()
            .is_some_and(|value| value.status != "ready")
        {
            summary.bimi_not_ready += 1;
        }

        let domain_observations = observations
            .iter()
            .filter(|(id, _)| *id == domain_id)
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();

        domains.push(DomainSecurityDomain {
            id: domain_id,
            domain: row.get("domain"),
            verification_status,
            domain_type: row.get("domain_type"),
            next_actions: next_actions(
                &dmarc,
                report_authorization.as_ref(),
                bimi_status.as_ref(),
                &domain_observations,
                &domain_sources,
            ),
            dmarc,
            report_authorization,
            bimi: bimi_status,
            observations: domain_observations,
            sources: domain_sources,
        });
    }
    summary.open_notifications = notifications
        .iter()
        .filter(|notification| notification.status == "open")
        .count() as i64;

    (
        StatusCode::OK,
        Json(ApiEnvelope {
            data: DomainSecurityResponse {
                deployment_id: state.deployment_id.0,
                generated_at: Utc::now(),
                summary,
                domains,
                notifications,
            },
        }),
    )
        .into_response()
}

async fn load_dmarc_metrics(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<(Uuid, DmarcDomainMetrics)>, Response> {
    sqlx::query(
        "SELECT report.domain_id, \
                (array_agg(report.policy_p ORDER BY report.date_range_end DESC))[1] AS latest_policy, \
                count(DISTINCT report.id)::bigint AS reports_30d, \
                COALESCE(sum(record.message_count), 0)::bigint AS messages_30d, \
                COALESCE(sum(record.message_count) FILTER (WHERE record.dkim_aligned_result = 'pass'), 0)::bigint \
                    AS dkim_aligned_messages_30d, \
                COALESCE(sum(record.message_count) FILTER (WHERE record.spf_aligned_result = 'pass'), 0)::bigint \
                    AS spf_aligned_messages_30d, \
                COALESCE(sum(record.message_count) FILTER (WHERE record.dkim_aligned_result = 'pass' \
                    OR record.spf_aligned_result = 'pass'), 0)::bigint AS dmarc_aligned_messages_30d, \
                COALESCE(sum(record.message_count) FILTER (WHERE record.disposition IN ('quarantine', 'reject')), 0)::bigint \
                    AS rejected_or_quarantined_messages_30d \
         FROM dmarc_aggregate_reports AS report \
         LEFT JOIN dmarc_aggregate_records AS record ON record.report_id = report.id \
         WHERE report.date_range_begin >= now() - interval '30 days' \
           AND report.deployment_id = $1 \
           AND report.customer_id = $2 \
         GROUP BY report.domain_id",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                (
                    row.get("domain_id"),
                    DmarcDomainMetrics {
                        latest_policy: row.get("latest_policy"),
                        reports_30d: row.get("reports_30d"),
                        messages_30d: row.get("messages_30d"),
                        dkim_aligned_messages_30d: row.get("dkim_aligned_messages_30d"),
                        spf_aligned_messages_30d: row.get("spf_aligned_messages_30d"),
                        dmarc_aligned_messages_30d: row.get("dmarc_aligned_messages_30d"),
                        rejected_or_quarantined_messages_30d: row
                            .get("rejected_or_quarantined_messages_30d"),
                    },
                )
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_sources(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<(Uuid, DomainSourceSummary)>, Response> {
    sqlx::query(
        "WITH source_rows AS ( \
             SELECT record.domain_id, record.source_ip::text AS source_ip, \
                    COALESCE(NULLIF(record.envelope_from_domain, ''), record.header_from_domain) AS source_domain, \
                    record.source_ip::text AS source_key, \
                    sum(record.message_count)::bigint AS messages_30d, \
                    COALESCE(sum(record.message_count) FILTER (WHERE record.dkim_aligned_result = 'pass'), 0)::bigint \
                        AS dkim_aligned_messages_30d, \
                    COALESCE(sum(record.message_count) FILTER (WHERE record.spf_aligned_result = 'pass'), 0)::bigint \
                        AS spf_aligned_messages_30d, \
                    COALESCE(sum(record.message_count) FILTER (WHERE record.dkim_aligned_result = 'pass' \
                        OR record.spf_aligned_result = 'pass'), 0)::bigint AS dmarc_aligned_messages_30d, \
                    row_number() OVER (PARTITION BY record.domain_id ORDER BY sum(record.message_count) DESC) AS rank \
             FROM dmarc_aggregate_records AS record \
             JOIN dmarc_aggregate_reports AS report ON report.id = record.report_id \
             WHERE report.date_range_begin >= now() - interval '30 days' \
               AND report.deployment_id = $1 \
               AND report.customer_id = $2 \
             GROUP BY record.domain_id, record.source_ip, \
               COALESCE(NULLIF(record.envelope_from_domain, ''), record.header_from_domain) \
         ) \
         SELECT source_rows.*, COALESCE(classification.classification, 'unknown') AS classification \
         FROM source_rows \
         LEFT JOIN domain_source_classifications AS classification \
           ON classification.domain_id = source_rows.domain_id \
          AND classification.source_key = source_rows.source_key \
          AND classification.deployment_id = $1 \
          AND classification.customer_id = $2 \
         WHERE source_rows.rank <= 5 \
         ORDER BY source_rows.domain_id, source_rows.messages_30d DESC",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                let classification: String = row.get("classification");
                let dmarc_aligned_messages_30d: i64 = row.get("dmarc_aligned_messages_30d");
                (
                    row.get("domain_id"),
                    DomainSourceSummary {
                        source_key: row.get("source_key"),
                        source_ip: row.get("source_ip"),
                        source_domain: row.get("source_domain"),
                        messages_30d: row.get("messages_30d"),
                        dkim_aligned_messages_30d: row.get("dkim_aligned_messages_30d"),
                        spf_aligned_messages_30d: row.get("spf_aligned_messages_30d"),
                        dmarc_aligned_messages_30d,
                        suggested_action: source_action(&classification, dmarc_aligned_messages_30d),
                        classification,
                    },
                )
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_authorizations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<(Uuid, ReportAuthorizationStatus)>, Response> {
    sqlx::query(
        "SELECT DISTINCT ON (domain_id) domain_id, report_host, owner_name, expected_value, \
                actual_value, status, checked_at, detail \
         FROM dmarc_report_authorizations \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY domain_id, updated_at DESC",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                (
                    row.get("domain_id"),
                    ReportAuthorizationStatus {
                        report_host: row.get("report_host"),
                        owner_name: row.get("owner_name"),
                        expected_value: row.get("expected_value"),
                        actual_value: row.get("actual_value"),
                        status: row.get("status"),
                        checked_at: row.get("checked_at"),
                        detail: row.get("detail"),
                    },
                )
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_bimi(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<(Uuid, BimiStatus)>, Response> {
    sqlx::query(
        "SELECT DISTINCT ON (domain_id) domain_id, selector, status, logo_url, svg_status, \
                dmarc_enforcement_status, certificate_status, errors, checked_at \
         FROM bimi_domain_status \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY domain_id, updated_at DESC",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                let errors: serde_json::Value = row.get("errors");
                (
                    row.get("domain_id"),
                    BimiStatus {
                        selector: row.get("selector"),
                        status: row.get("status"),
                        logo_url: row.get("logo_url"),
                        svg_status: row.get("svg_status"),
                        dmarc_enforcement_status: row.get("dmarc_enforcement_status"),
                        certificate_status: row.get("certificate_status"),
                        errors: json_string_array(errors),
                        checked_at: row.get("checked_at"),
                    },
                )
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_observations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<(Uuid, DomainObservation)>, Response> {
    sqlx::query(
        "SELECT DISTINCT ON (domain_id, check_type) domain_id, check_type, status, \
                observed_value, detail, observed_at \
         FROM domain_security_observations \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY domain_id, check_type, observed_at DESC",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                (
                    row.get("domain_id"),
                    DomainObservation {
                        check_type: row.get("check_type"),
                        status: row.get("status"),
                        observed_value: row.get("observed_value"),
                        detail: row.get("detail"),
                        observed_at: row.get("observed_at"),
                    },
                )
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

async fn load_notifications(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Vec<DomainSecurityNotification>, Response> {
    sqlx::query(
        "SELECT id, domain_id, notification_type, severity, title, detail, status, created_at \
         FROM domain_security_notifications \
         WHERE status = 'open' AND deployment_id = $1 AND customer_id = $2 \
         ORDER BY \
           CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, \
           created_at DESC \
         LIMIT 25",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut **transaction)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| DomainSecurityNotification {
                id: row.get("id"),
                domain_id: row.get("domain_id"),
                notification_type: row.get("notification_type"),
                severity: row.get("severity"),
                title: row.get("title"),
                detail: row.get("detail"),
                status: row.get("status"),
                created_at: row.get("created_at"),
            })
            .collect()
    })
    .map_err(|_| unavailable())
}

fn next_actions(
    dmarc: &DmarcDomainMetrics,
    authorization: Option<&ReportAuthorizationStatus>,
    bimi: Option<&BimiStatus>,
    observations: &[DomainObservation],
    sources: &[DomainSourceSummary],
) -> Vec<String> {
    let mut actions = Vec::new();
    match dmarc.latest_policy.as_deref() {
        Some("reject" | "quarantine") => {},
        Some("none") => actions
            .push("Progress DMARC from p=none after unknown sources are resolved.".to_string()),
        _ => actions
            .push("Publish and verify a DMARC record with regional rua reporting.".to_string()),
    }
    if !matches!(
        authorization.map(|value| value.status.as_str()),
        Some("valid")
    ) {
        if let Some(value) = authorization {
            actions.push(format!(
                "Publish external report authorization TXT {} = {}.",
                value.owner_name, value.expected_value
            ));
        } else {
            actions.push(
                "Configure external DMARC report authorization for the regional rua host."
                    .to_string(),
            );
        }
    }
    if sources
        .iter()
        .any(|source| source.classification == "unknown")
    {
        actions.push("Classify high-volume unknown sources as authorized, expected incomplete, suspicious, malicious or third-party.".to_string());
    }
    if bimi.is_some_and(|value| value.status != "ready") {
        actions.push("Fix BIMI readiness: DMARC enforcement, secure SVG profile and certificate state must all pass.".to_string());
    }
    if observations.iter().any(|value| value.status == "fail") {
        actions
            .push("Review failed DNS/security observations before policy escalation.".to_string());
    }
    actions.sort();
    actions.dedup();
    actions
}

fn source_action(classification: &str, dmarc_aligned_messages_30d: i64) -> String {
    match (classification, dmarc_aligned_messages_30d > 0) {
        ("authorized", false) => {
            "Known source has no aligned mail; fix SPF/DKIM alignment.".to_string()
        },
        ("authorized", true) => "Monitor authorized source.".to_string(),
        ("expected_incomplete", _) => {
            "Complete SPF/DKIM onboarding or lower its allowed volume.".to_string()
        },
        ("suspicious" | "malicious", _) => {
            "Investigate and consider rejecting or blocking at policy.".to_string()
        },
        ("third_party", false) => {
            "Ask provider for aligned DKIM or SPF include guidance.".to_string()
        },
        ("third_party", true) => {
            "Verify provider remains in the approved sender inventory.".to_string()
        },
        _ => "Classify this source before progressing DMARC enforcement.".to_string(),
    }
}

fn json_string_array(value: serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn has_permission(context: &TenantContext, permission: &str) -> bool {
    context
        .permissions
        .iter()
        .any(|granted| granted == permission)
}

async fn set_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        "Domain security is unavailable",
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

    fn state() -> DomainSecurityState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy test pool must parse");
        DomainSecurityState::new(pool, DeploymentId::new("LOCAL-TEST"))
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
            customer_id: CustomerId::new("CZA-1"),
            customer_internal_key: 1,
            customer_display_name: "Customer test".to_string(),
            customer_lifecycle: CustomerLifecycle::Active,
            permissions,
            config_revision: 1,
            trace_id: "domain-security-test".to_string(),
            correlation_id: "domain-security-test".to_string(),
            session_id: "domain-security-test".to_string(),
            authenticated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn domain_security_requires_authenticated_context() {
        let response = domain_security_router(state())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/domain-security")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn domain_security_requires_explicit_permission_before_database_access() {
        let response = domain_security_router(state())
            .layer(Extension(context(vec![])))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/domain-security")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

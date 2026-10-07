//! Local PostgreSQL coverage for Phase 5 domain-security projection.
//!
//! Requires PostgreSQL migrated through `022_domain_security_read_models.sql`
//! with `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_domain_security -- --ignored`.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Extension,
};
use chrono::Utc;
use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId},
    ActorId,
};
use nullapart_mail_core::domain_security::{
    domain_security_router, DomainSecurityState, DOMAIN_SECURITY_MANAGE_PERMISSION,
    DOMAIN_SECURITY_VIEW_PERMISSION,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId, TenantContext,
};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

async fn connect() -> PgPool {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable")
}

struct Fixture {
    deployment_id: String,
    customer_id: String,
    customer_internal_key: i64,
    domain_id: Uuid,
    domain: String,
}

async fn seed_fixture(pool: &PgPool, suffix: &str, customer_suffix: &str) -> Fixture {
    let deployment_id = format!("phase5-domain-security-{suffix}");
    let customer_id = format!("C-DS-{customer_suffix}-{suffix}");
    let domain = format!("{customer_suffix}.{suffix}.example.test");
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name, lifecycle) \
         VALUES ($1, 'za', $2, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(&deployment_id)
    .bind(format!("Phase 5 Domain Security {suffix}"))
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    let row = sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
         VALUES ($1, $2, $3, 'active') \
         RETURNING internal_key",
    )
    .bind(&customer_id)
    .bind(&deployment_id)
    .bind(format!("Domain Security Customer {customer_suffix}"))
    .fetch_one(pool)
    .await
    .expect("customer fixture must insert");
    let customer_internal_key: i64 = row.get("internal_key");
    let domain_id: Uuid = sqlx::query_scalar(
        "INSERT INTO domains (customer_id, domain, verification_status, verified_at) \
         VALUES ($1, $2, 'verified', now()) \
         RETURNING id",
    )
    .bind(&customer_id)
    .bind(&domain)
    .fetch_one(pool)
    .await
    .expect("domain fixture must insert");
    Fixture {
        deployment_id,
        customer_id,
        customer_internal_key,
        domain_id,
        domain,
    }
}

async fn seed_domain_security_rows(pool: &PgPool, fixture: &Fixture) {
    let report_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO dmarc_aggregate_reports (\
            deployment_id, customer_id, domain_id, policy_domain, reporter_org_name, \
            report_id, date_range_begin, date_range_end, policy_adkim, policy_aspf, \
            policy_p, parser_version, duplicate_key\
         ) VALUES (\
            $1, $2, $3, $4, 'Reporter', $5, now() - interval '1 day', now(), \
            's', 's', 'quarantine', 'test', $6\
         ) RETURNING id",
    )
    .bind(&fixture.deployment_id)
    .bind(&fixture.customer_id)
    .bind(fixture.domain_id)
    .bind(&fixture.domain)
    .bind(format!("report-{}", fixture.domain))
    .bind(format!("{:064x}", fixture.domain_id.as_u128()))
    .fetch_one(pool)
    .await
    .expect("aggregate report fixture must insert");

    sqlx::query(
        "INSERT INTO dmarc_aggregate_records (\
            deployment_id, customer_id, domain_id, report_id, source_ip, message_count, \
            header_from_domain, envelope_from_domain, disposition, dkim_aligned_result, spf_aligned_result\
         ) VALUES ($1, $2, $3, $4, '203.0.113.44', 12, $5, $5, 'none', 'pass', 'fail')",
    )
    .bind(&fixture.deployment_id)
    .bind(&fixture.customer_id)
    .bind(fixture.domain_id)
    .bind(report_id)
    .bind(&fixture.domain)
    .execute(pool)
    .await
    .expect("aggregate record fixture must insert");

    sqlx::query(
        "INSERT INTO dmarc_report_authorizations (\
            deployment_id, customer_id, domain_id, report_host, owner_name, expected_value, status, checked_at, detail\
         ) VALUES ($1, $2, $3, 'rua.za.nullapart.example', $4, 'v=DMARC1', 'missing', now(), 'authorization TXT missing')",
    )
    .bind(&fixture.deployment_id)
    .bind(&fixture.customer_id)
    .bind(fixture.domain_id)
    .bind(format!("{}._report._dmarc", fixture.domain))
    .execute(pool)
    .await
    .expect("report authorization fixture must insert");

    sqlx::query(
        "INSERT INTO bimi_domain_status (\
            deployment_id, customer_id, domain_id, selector, status, svg_status, \
            dmarc_enforcement_status, certificate_status, errors, checked_at\
         ) VALUES ($1, $2, $3, 'default', 'not_ready', 'not_checked', 'enforced', 'missing', \
                   '[\"certificate missing\"]'::jsonb, now())",
    )
    .bind(&fixture.deployment_id)
    .bind(&fixture.customer_id)
    .bind(fixture.domain_id)
    .execute(pool)
    .await
    .expect("bimi fixture must insert");

    sqlx::query(
        "INSERT INTO domain_security_observations (\
            deployment_id, customer_id, domain_id, check_type, status, observed_value, detail\
         ) VALUES ($1, $2, $3, 'dmarc', 'warning', 'p=quarantine', 'DMARC enforcement ready after source review')",
    )
    .bind(&fixture.deployment_id)
    .bind(&fixture.customer_id)
    .bind(fixture.domain_id)
    .execute(pool)
    .await
    .expect("observation fixture must insert");

    sqlx::query(
        "INSERT INTO domain_security_notifications (\
            deployment_id, customer_id, domain_id, notification_type, severity, title, detail\
         ) VALUES ($1, $2, $3, 'new_unknown_source', 'warning', 'Unknown source detected', '203.0.113.44 requires classification')",
    )
    .bind(&fixture.deployment_id)
    .bind(&fixture.customer_id)
    .bind(fixture.domain_id)
    .execute(pool)
    .await
    .expect("notification fixture must insert");
}

fn context(fixture: &Fixture) -> TenantContext {
    TenantContext {
        deployment_id: DeploymentId::new(&fixture.deployment_id),
        region: RegionId::new("za"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "operator@example.test".to_string(),
            roles: vec!["system_admin".to_string()],
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: CustomerId::new(&fixture.customer_id),
        customer_internal_key: fixture.customer_internal_key,
        customer_display_name: "Domain Security Customer".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: vec![
            DOMAIN_SECURITY_VIEW_PERMISSION.to_string(),
            DOMAIN_SECURITY_MANAGE_PERMISSION.to_string(),
        ],
        config_revision: 1,
        trace_id: "domain-security-postgres-test".to_string(),
        correlation_id: "domain-security-postgres-test".to_string(),
        session_id: "domain-security-postgres-test".to_string(),
        authenticated_at: Utc::now(),
    }
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 022_domain_security_read_models.sql"]
async fn domain_security_projection_is_actionable_and_customer_scoped() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let primary = seed_fixture(&pool, &suffix, "primary").await;
    let other = seed_fixture(&pool, &suffix, "other").await;
    seed_domain_security_rows(&pool, &primary).await;
    seed_domain_security_rows(&pool, &other).await;

    let response = domain_security_router(DomainSecurityState::new(
        pool,
        DeploymentId::new(&primary.deployment_id),
    ))
    .oneshot(
        Request::builder()
            .uri("/api/v1/domain-security")
            .extension(Extension(context(&primary)))
            .body(Body::empty())
            .expect("request must build"),
    )
    .await
    .expect("domain-security route must answer");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must buffer");
    let value: Value = serde_json::from_slice(&bytes).expect("response must be JSON");
    let data = &value["data"];

    assert_eq!(data["summary"]["domains_total"], 1);
    assert_eq!(data["summary"]["messages_30d"], 12);
    assert_eq!(data["summary"]["unknown_sources"], 1);
    assert_eq!(data["summary"]["open_notifications"], 1);
    assert_eq!(data["domains"][0]["domain"], primary.domain);
    assert_eq!(
        data["domains"][0]["report_authorization"]["status"],
        "missing"
    );
    assert_eq!(data["domains"][0]["bimi"]["status"], "not_ready");
    assert_eq!(
        data["domains"][0]["sources"][0]["source_ip"],
        "203.0.113.44"
    );
    assert_eq!(data["notifications"][0]["title"], "Unknown source detected");
    assert!(
        !String::from_utf8_lossy(&bytes).contains(&other.domain),
        "projection must not include another customer's domain"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 022_domain_security_read_models.sql"]
async fn source_classification_mutation_is_idempotent_audited_and_scoped() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let primary = seed_fixture(&pool, &suffix, "primary-action").await;
    let other = seed_fixture(&pool, &suffix, "other-action").await;
    seed_domain_security_rows(&pool, &primary).await;
    seed_domain_security_rows(&pool, &other).await;
    let app = domain_security_router(DomainSecurityState::new(
        pool.clone(),
        DeploymentId::new(&primary.deployment_id),
    ))
    .layer(Extension(context(&primary)));
    let body = serde_json::json!({
        "domain_id": primary.domain_id,
        "source_key": "203.0.113.44",
        "source_ip": "203.0.113.44",
        "source_domain": primary.domain,
        "classification": "third_party",
        "notes": "Provider is approved but SPF alignment still needs follow-up"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/domain-security/source-classifications")
                .header("content-type", "application/json")
                .header("x-idempotency-key", format!("classify-{suffix}"))
                .body(Body::from(body.to_string()))
                .expect("request must build"),
        )
        .await
        .expect("classification route must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must buffer");
    let value: Value = serde_json::from_slice(&bytes).expect("response must be JSON");
    assert_eq!(value["data"]["classification"], "third_party");
    assert_eq!(value["data"]["changed"], true);

    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/domain-security/source-classifications")
                .header("content-type", "application/json")
                .header("x-idempotency-key", format!("classify-{suffix}"))
                .body(Body::from(body.to_string()))
                .expect("request must build"),
        )
        .await
        .expect("classification replay must answer");
    assert_eq!(replay.status(), StatusCode::OK);

    let stored: (String, i64) = sqlx::query_as(
        "SELECT classification, count(*) OVER ()::bigint \
         FROM domain_source_classifications \
         WHERE deployment_id = $1 AND customer_id = $2 AND domain_id = $3 AND source_key = '203.0.113.44'",
    )
    .bind(&primary.deployment_id)
    .bind(&primary.customer_id)
    .bind(primary.domain_id)
    .fetch_one(&pool)
    .await
    .expect("classification must be stored once");
    assert_eq!(stored, ("third_party".to_string(), 1));

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM audit_events \
         WHERE deployment_id = $1 AND customer_id = $2 \
           AND action = 'domain_source_classification_changed'",
    )
    .bind(&primary.deployment_id)
    .bind(&primary.customer_id)
    .fetch_one(&pool)
    .await
    .expect("audit count must be readable");
    assert_eq!(audit_count, 1);

    let cross_tenant = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/domain-security/source-classifications")
                .header("content-type", "application/json")
                .header("x-idempotency-key", format!("classify-other-{suffix}"))
                .body(Body::from(
                    serde_json::json!({
                        "domain_id": other.domain_id,
                        "source_key": "203.0.113.45",
                        "source_ip": "203.0.113.45",
                        "classification": "authorized"
                    })
                    .to_string(),
                ))
                .expect("request must build"),
        )
        .await
        .expect("cross-tenant classification route must answer");
    assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);
}

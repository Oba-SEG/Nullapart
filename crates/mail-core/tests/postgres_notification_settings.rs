//! Local PostgreSQL coverage for tenant notification settings.
//!
//! Requires PostgreSQL migrated through `042_tenant_notification_settings.sql`
//! with `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_notification_settings -- --ignored`.

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
use nullapart_mail_core::notification_api::{
    notification_router, NotificationApiState, NOTIFICATIONS_MANAGE_PERMISSION,
    NOTIFICATIONS_VIEW_PERMISSION,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId, TenantContext,
};
use serde_json::{json, Value};
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

/// The non-owner, non-superuser role the scoped reads assume. The test URL
/// connects as the schema owner, which has BYPASSRLS, so a plain GUC-scoped
/// read would see every tenant's row no matter what the policy says.
const REQUEST_ROLE: &str = "nullapart_local_request";

/// Serializes role and grant creation inside this binary: concurrent GRANTs
/// rewrite shared catalogs and race with a concurrently running test binary.
static ROLE_SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn ensure_request_role(pool: &PgPool) {
    let _setup = ROLE_SETUP_LOCK.lock().await;
    let mut attempt = 0;
    loop {
        match try_ensure_request_role(pool).await {
            Ok(()) => return,
            Err(error) if attempt < 3 => {
                attempt += 1;
                eprintln!("role setup attempt {attempt} failed: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            },
            Err(error) => panic!("the request role setup must succeed: {error}"),
        }
    }
}

async fn try_ensure_request_role(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "DO $$ BEGIN \
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_local_request') THEN \
             EXECUTE 'CREATE ROLE nullapart_local_request NOLOGIN'; \
           END IF; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;",
    )
    .execute(&mut *transaction)
    .await?;
    for grant in [
        "GRANT USAGE ON SCHEMA public TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nullapart_local_request",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nullapart_local_request",
    ] {
        sqlx::query(grant).execute(&mut *transaction).await?;
    }
    transaction.commit().await
}

struct Tenant {
    deployment_id: String,
    customer_id: String,
    customer_internal_key: i64,
    domain: String,
}

async fn seed_tenant(pool: &PgPool, deployment_id: &str, label: &str) -> Tenant {
    let customer_id = format!("C-NS-{label}-{}", Uuid::new_v4().simple());
    let domain = format!("{label}.notification-{deployment_id}.example.test");
    let row = sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
         VALUES ($1, $2, $3, 'active') \
         RETURNING internal_key",
    )
    .bind(&customer_id)
    .bind(deployment_id)
    .bind(format!("Notification Customer {label}"))
    .fetch_one(pool)
    .await
    .expect("customer fixture must insert");
    sqlx::query(
        "INSERT INTO domains (customer_id, domain, verification_status, verified_at) \
         VALUES ($1, $2, 'verified', now())",
    )
    .bind(&customer_id)
    .bind(&domain)
    .execute(pool)
    .await
    .expect("verified domain fixture must insert");
    Tenant {
        deployment_id: deployment_id.to_string(),
        customer_id,
        customer_internal_key: row.get("internal_key"),
        domain,
    }
}

async fn seed_deployment(pool: &PgPool, label: &str) -> String {
    let deployment_id = format!("ns-deploy-{label}-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name, lifecycle) \
         VALUES ($1, 'za', $2, 'active')",
    )
    .bind(&deployment_id)
    .bind(format!("Notification Settings {label}"))
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    deployment_id
}

fn context(tenant: &Tenant, permissions: Vec<String>) -> TenantContext {
    TenantContext {
        deployment_id: DeploymentId::new(&tenant.deployment_id),
        region: RegionId::new("za"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "tenant-admin@example.test".to_string(),
            roles: vec!["customer_admin".to_string()],
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: CustomerId::new(&tenant.customer_id),
        customer_internal_key: tenant.customer_internal_key,
        customer_display_name: "Notification Customer".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions,
        config_revision: 1,
        trace_id: "notification-settings-postgres-test".to_string(),
        correlation_id: "notification-settings-postgres-test".to_string(),
        session_id: "notification-settings-postgres-test".to_string(),
        authenticated_at: Utc::now(),
    }
}

fn tenant_permissions() -> Vec<String> {
    vec![
        NOTIFICATIONS_VIEW_PERMISSION.to_string(),
        NOTIFICATIONS_MANAGE_PERMISSION.to_string(),
    ]
}

async fn put_settings(
    pool: &PgPool,
    deployment_id: &str,
    tenant: &Tenant,
    key: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = notification_router(NotificationApiState::new(
        pool.clone(),
        DeploymentId::new(deployment_id),
    ))
    .layer(Extension(context(tenant, tenant_permissions())))
    .oneshot(
        Request::put("/api/v1/notifications/settings")
            .header("x-idempotency-key", key)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request must build"),
    )
    .await
    .expect("route must answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must buffer");
    (
        status,
        serde_json::from_slice(&bytes).expect("response must be JSON"),
    )
}

async fn get_settings(
    pool: &PgPool,
    deployment_id: &str,
    tenant: &Tenant,
    permissions: Vec<String>,
) -> (StatusCode, Value) {
    let response = notification_router(NotificationApiState::new(
        pool.clone(),
        DeploymentId::new(deployment_id),
    ))
    .layer(Extension(context(tenant, permissions)))
    .oneshot(
        Request::get("/api/v1/notifications/settings")
            .body(Body::empty())
            .expect("request must build"),
    )
    .await
    .expect("route must answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must buffer");
    (
        status,
        serde_json::from_slice(&bytes).expect("response must be JSON"),
    )
}

/// Read the settings table the way the mail-core runtime does: inside a
/// transaction carrying this tenant's GUCs and assuming the non-owner request
/// role, so row-level security actually decides what is visible.
async fn scoped_settings_count(pool: &PgPool, deployment_id: &str, customer_id: &str) -> i64 {
    let mut transaction = pool.begin().await.expect("transaction must open");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("the session must assume the request role");
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut *transaction)
    .await
    .expect("scope GUCs must set");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM tenant_notification_settings")
        .fetch_one(&mut *transaction)
        .await
        .expect("scoped read must succeed");
    transaction
        .rollback()
        .await
        .expect("fixture transaction must roll back");
    count
}

async fn stored_row(pool: &PgPool, deployment_id: &str, customer_id: &str) -> Option<Value> {
    let row = sqlx::query(
        "SELECT enabled, severity_floor, recipient_emails, digest_window_minutes, updated_by \
         FROM tenant_notification_settings \
         WHERE deployment_id = $1 AND customer_id = $2",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_optional(pool)
    .await
    .expect("superuser read must succeed");
    row.map(|row| {
        json!({
            "enabled": row.get::<bool, _>("enabled"),
            "severity_floor": row.get::<String, _>("severity_floor"),
            "recipient_emails": row.get::<Vec<String>, _>("recipient_emails"),
            "digest_window_minutes": row.get::<i32, _>("digest_window_minutes"),
            "updated_by": row.get::<String, _>("updated_by"),
        })
    })
}

async fn audit_count(pool: &PgPool, deployment_id: &str, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE deployment_id = $1 AND action = $2")
        .bind(deployment_id)
        .bind(action)
        .fetch_one(pool)
        .await
        .expect("audit rows must be readable")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 042_tenant_notification_settings.sql"]
async fn settings_write_persists_normalizes_and_is_audited_once_per_idempotency_key() {
    let pool = connect().await;
    let deployment = seed_deployment(&pool, "primary").await;
    let tenant = seed_tenant(&pool, &deployment, "primary").await;

    let recipient = format!("  MailOps@{}", tenant.domain.to_uppercase());
    let (status, value) = put_settings(
        &pool,
        &deployment,
        &tenant,
        "settings-key-1",
        json!({
            "enabled": true,
            "severity_floor": "info",
            "recipient_emails": [recipient, recipient.to_lowercase()],
            "digest_window_minutes": 30,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value["data"]["recipient_emails"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        value["data"]["recipient_emails"][0],
        format!("mailops@{}", tenant.domain)
    );

    let stored = stored_row(&pool, &deployment, &tenant.customer_id)
        .await
        .expect("settings row must persist");
    assert_eq!(stored["severity_floor"], "info");
    assert_eq!(stored["digest_window_minutes"], 30);
    assert_eq!(
        audit_count(&pool, &deployment, "notification_settings_updated").await,
        1
    );

    let view = get_settings(&pool, &deployment, &tenant, tenant_permissions())
        .await
        .1;
    assert_eq!(view["data"]["settings"]["enabled"], true);
    assert_eq!(view["data"]["effective"]["deliverable"], true);
    assert!(view["data"]["verified_domains"]
        .as_array()
        .expect("verified domains must be a list")
        .contains(&json!(tenant.domain)));
    assert_eq!(
        view["data"]["capabilities"]["update_settings"]["allowed"],
        true
    );

    // A read-only session still gets the settings, but the write is published
    // as locked so the console cannot offer an action the API will refuse.
    let read_only = get_settings(
        &pool,
        &deployment,
        &tenant,
        vec![NOTIFICATIONS_VIEW_PERMISSION.to_string()],
    )
    .await;
    assert_eq!(read_only.0, StatusCode::OK);
    assert_eq!(
        read_only.1["data"]["capabilities"]["update_settings"]["allowed"],
        false
    );
    assert_eq!(
        read_only.1["data"]["capabilities"]["update_settings"]["blocker"],
        "permission"
    );

    // A replay returns the recorded response without re-executing the write.
    let (replay_status, replay) = put_settings(
        &pool,
        &deployment,
        &tenant,
        "settings-key-1",
        json!({ "enabled": false }),
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(replay["data"], value["data"]);
    assert_eq!(
        audit_count(&pool, &deployment, "notification_settings_updated").await,
        1
    );
    assert_eq!(
        stored_row(&pool, &deployment, &tenant.customer_id).await,
        Some(stored)
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 042_tenant_notification_settings.sql"]
async fn settings_are_isolated_between_tenants_of_the_same_deployment() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let deployment = seed_deployment(&pool, "isolation").await;
    let primary = seed_tenant(&pool, &deployment, "isolation-a").await;
    let other = seed_tenant(&pool, &deployment, "isolation-b").await;

    let (status, _) = put_settings(
        &pool,
        &deployment,
        &primary,
        "isolation-key-1",
        json!({ "recipient_emails": [format!("ops@{}", primary.domain)] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The neighbour has no row, and reads platform defaults rather than the
    // primary tenant's choices.
    let view = get_settings(&pool, &deployment, &other, tenant_permissions())
        .await
        .1;
    assert!(view["data"]["settings"].is_null());
    assert_eq!(view["data"]["effective"]["recipient_count"], 0);
    assert_eq!(view["data"]["effective"]["deliverable"], false);
    assert_eq!(view["data"]["effective"]["severity_floor"], "warning");
    assert_eq!(
        scoped_settings_count(&pool, &deployment, &other.customer_id).await,
        0,
        "row-level security must not expose another tenant's settings"
    );
    assert_eq!(
        scoped_settings_count(&pool, &deployment, &primary.customer_id).await,
        1
    );

    // Addressing the neighbour's verified domain is a refusal, not a write.
    let (status, value) = put_settings(
        &pool,
        &deployment,
        &other,
        "isolation-key-2",
        json!({ "recipient_emails": [format!("ops@{}", primary.domain)] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["code"], "RECIPIENT_DOMAIN_NOT_VERIFIED");
    assert!(
        stored_row(&pool, &deployment, &other.customer_id)
            .await
            .is_none(),
        "a refused write must leave no settings row"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 042_tenant_notification_settings.sql"]
async fn a_session_from_another_deployment_cannot_reach_the_settings_row() {
    let pool = connect().await;
    let home = seed_deployment(&pool, "home").await;
    let foreign = seed_deployment(&pool, "foreign").await;
    let tenant = seed_tenant(&pool, &home, "home").await;

    let (status, _) = put_settings(
        &pool,
        &home,
        &tenant,
        "cross-deployment-key",
        json!({ "recipient_emails": [format!("ops@{}", tenant.domain)] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The state is bound to one deployment, so a session from another
    // deployment is refused before the store is consulted.
    let (status, value) = put_settings(
        &pool,
        &foreign,
        &tenant,
        "cross-deployment-key-2",
        json!({ "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(value["code"], "FORBIDDEN");

    let (status, value) = get_settings(&pool, &foreign, &tenant, tenant_permissions()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(value["code"], "FORBIDDEN");
    assert_eq!(
        stored_row(&pool, &home, &tenant.customer_id)
            .await
            .expect("home settings row must still exist")["enabled"],
        true,
        "a foreign-deployment session must not flip the home tenant's settings"
    );
}

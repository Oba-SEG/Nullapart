//! Local PostgreSQL coverage for the Phase 3 increment 6 policy family and
//! feature override administration.
//!
//! Requires PostgreSQL migrated through `014_policy_administration.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Every test is `#[ignore]`d so
//! the default suite stays offline; run them explicitly with
//! `cargo test --test postgres_policy_admin -- --ignored`.
//!
//! 1. **Publish**: a publish inserts the revision, audits `policy_published`,
//!    writes the `config.changed` outbox event and completes the idempotency
//!    key; the next publish deactivates the previous active revision and
//!    allocates revision+1; a completed key replays the stored response.
//! 2. **`policy_revisions` RLS**: a tenant revision is visible only under its
//!    own customer GUC, an unset GUC fails closed to zero rows, and a system
//!    revision needs the deployment scope (a customer-only scope cannot mint
//!    one).
//! 3. **`feature_overrides` RLS**: system rows need a deployment scope,
//!    deployment rows are keyed to it, and a tenant row cannot be written by
//!    or observed from a neighbouring tenant.
//! 4. **`config_revisions` RLS**: the same three-level model as
//!    `feature_overrides`.
//! 5. **Static catalog**: `POLICY_FAMILY_MANAGEMENT_LEVELS` mirrors the seeded
//!    `policy_families` rows exactly, so the offline tier gate cannot drift
//!    from the database.
//!
//! `postgres_rls_isolation.rs::rls_feature_overrides_cannot_self_escalate`
//! must keep passing alongside this suite: it is the escalation proof for the
//! same policy this increment rewrites.

use axum::{
    body::{to_bytes, Body},
    extract::Extension,
    http::{Request, StatusCode},
};
use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId},
    ActorId,
};
use nullapart_mail_core::admin_rbac::SYSTEM_ADMIN_ROLE;
use nullapart_mail_core::policy_admin::{
    policy_admin_router, AdminPolicyState, POLICIES_MANAGE_PERMISSION, POLICIES_VIEW_PERMISSION,
    POLICY_FAMILY_MANAGEMENT_LEVELS,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId, TenantContext,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Transaction};
use tower::ServiceExt;
use uuid::Uuid;

/// The non-owner, non-superuser role every RLS statement assumes.
const REQUEST_ROLE: &str = "nullapart_local_request";

async fn connect() -> PgPool {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable")
}

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

/// Begins a transaction as the request role with only the customer scope, so
/// an assertion can prove a forgotten deployment scope fails closed.
async fn begin_customer_only<'a>(
    pool: &'a PgPool,
    customer: &str,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool
        .begin()
        .await
        .expect("a transaction must begin for the scoped statement");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("the session must assume the request role");
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(customer)
        .execute(&mut *transaction)
        .await
        .expect("the customer scope must be established");
    transaction
}

/// Begins a transaction as the request role. `deployment`/`customer` are
/// applied transaction-locally; `None` leaves the GUC unset (fail closed).
async fn begin_scoped<'a>(
    pool: &'a PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool
        .begin()
        .await
        .expect("a transaction must begin for the scoped statement");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("the session must assume the request role");
    if deployment.is_some() || customer.is_some() {
        sqlx::query(
            "SELECT set_config('app.current_deployment_id', $1, true), \
                    set_config('app.current_customer_id', $2, true)",
        )
        .bind(deployment.unwrap_or(""))
        .bind(customer.unwrap_or(""))
        .execute(&mut *transaction)
        .await
        .expect("the tenant settings must be established");
    }
    transaction
}

/// Begins a transaction as the connecting owner, used only to seed and remove
/// fixture rows that the append-only trigger and ownership rules would refuse
/// to a tenant.
async fn begin_as_owner<'a>(pool: &'a PgPool, customer: &str) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool
        .begin()
        .await
        .expect("a transaction must begin for the owner statement");
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(customer)
        .execute(&mut *transaction)
        .await
        .expect("request-scoped tenant context must be established");
    transaction
}

/// Executes a statement that must be rejected inside its own savepoint, so the
/// expected error cannot abort the surrounding transaction (PostgreSQL 25P02).
async fn expect_rejected(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    statement: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query("SAVEPOINT expect_rejected")
        .execute(&mut **transaction)
        .await
        .expect("the savepoint must open");
    let outcome = statement.execute(&mut **transaction).await;
    sqlx::query("ROLLBACK TO SAVEPOINT expect_rejected")
        .execute(&mut **transaction)
        .await
        .expect("the savepoint must roll back");
    outcome
}

struct Fixture {
    deployment_a: DeploymentId,
    deployment_b: DeploymentId,
    customer_a: CustomerId,
    customer_b: CustomerId,
    suffix: String,
    publisher: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = format!("local-policyadmin-{}", Uuid::new_v4().simple());
    let deployment_a = DeploymentId::new(&format!("LOCAL-PA-A-{suffix}"));
    let deployment_b = DeploymentId::new(&format!("LOCAL-PA-B-{suffix}"));
    let customer_a = CustomerId::new(&format!("{suffix}-a"));
    let customer_b = CustomerId::new(&format!("{suffix}-b"));

    for (id, name) in [
        (&deployment_a, "Policy administration deployment A"),
        (&deployment_b, "Policy administration deployment B"),
    ] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id.0)
        .bind(name)
        .execute(pool)
        .await
        .expect("the deployment fixture must be created");
    }
    for (id, deployment) in [(&customer_a, &deployment_a), (&customer_b, &deployment_b)] {
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id.0)
        .bind(&deployment.0)
        .bind(&suffix)
        .execute(pool)
        .await
        .expect("the customer fixture must be created");
    }

    Fixture {
        publisher: format!("local-policy-admin-{suffix}"),
        deployment_a,
        deployment_b,
        customer_a,
        customer_b,
        suffix,
    }
}

fn context(fixture: &Fixture) -> TenantContext {
    TenantContext {
        deployment_id: fixture.deployment_a.clone(),
        region: RegionId::new("local"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "policy-admin@example.test".to_string(),
            roles: vec![SYSTEM_ADMIN_ROLE.to_string()],
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: fixture.customer_a.clone(),
        customer_internal_key: 1,
        customer_display_name: "Policy administration test".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: vec![
            POLICIES_VIEW_PERMISSION.to_string(),
            POLICIES_MANAGE_PERMISSION.to_string(),
        ],
        config_revision: 1,
        trace_id: "postgres-policy-admin-trace".to_string(),
        correlation_id: "postgres-policy-admin-correlation".to_string(),
        session_id: "postgres-policy-admin-session".to_string(),
        authenticated_at: chrono::Utc::now(),
    }
}

fn publish_request(uri: &str, key: &str) -> Request<Body> {
    let rule = "{\"id\":\"11111111-1111-1111-1111-111111111111\",\"name\":\"local rule\",\
                \"priority\":0,\"condition\":{\"scope\":\"transaction\"},\
                \"action\":{\"disposition\":\"allow\",\"reason_code\":\"ALLOWED\"},\
                \"enabled\":true}";
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-idempotency-key", key)
        .body(Body::from(format!("{{\"rules\":[{rule}]}}")))
        .expect("test request must build")
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    serde_json::from_slice(&bytes).expect("the body must be JSON")
}

async fn cleanup(pool: &PgPool, fixture: &Fixture) {
    let mut transaction = begin_as_owner(pool, &fixture.customer_a.0).await;
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update")
        .execute(&mut *transaction)
        .await
        .expect("the append-only trigger must be disableable by the table owner");
    sqlx::query("DELETE FROM audit_events WHERE deployment_id = $1")
        .bind(&fixture.deployment_a.0)
        .execute(&mut *transaction)
        .await
        .expect("the audit fixture must be removable with the trigger disabled");
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update")
        .execute(&mut *transaction)
        .await
        .expect("the append-only trigger must be restored");
    sqlx::query(
        "DELETE FROM feature_overrides WHERE feature_id = $1 OR scope_id IN ($2, $3, $4, $5)",
    )
    .bind(&fixture.suffix)
    .bind(&fixture.customer_a.0)
    .bind(&fixture.customer_b.0)
    .bind(&fixture.deployment_a.0)
    .bind(&fixture.deployment_b.0)
    .execute(&mut *transaction)
    .await
    .expect("the feature override fixture must be removable");
    sqlx::query("DELETE FROM feature_definitions WHERE feature_id = $1")
        .bind(&fixture.suffix)
        .execute(&mut *transaction)
        .await
        .expect("the feature fixture must be removable");
    sqlx::query(
        "DELETE FROM policy_revisions WHERE deployment_id IN ($1, $2) AND family_id IS NOT NULL",
    )
    .bind(&fixture.deployment_a.0)
    .bind(&fixture.deployment_b.0)
    .execute(&mut *transaction)
    .await
    .expect("the policy revision fixture must be removable");
    sqlx::query("DELETE FROM config_revisions WHERE published_by = $1")
        .bind(&fixture.publisher)
        .execute(&mut *transaction)
        .await
        .expect("the config revision fixture must be removable");
    sqlx::query(
        "DELETE FROM outbox_events WHERE deployment_id IN ($1, $2) \
         AND (idempotency_key LIKE $3)",
    )
    .bind(&fixture.deployment_a.0)
    .bind(&fixture.deployment_b.0)
    .bind(format!("policy-publish:{}%", fixture.suffix))
    .execute(&mut *transaction)
    .await
    .expect("the outbox fixture must be removable");
    sqlx::query("DELETE FROM idempotency_keys WHERE key LIKE $1")
        .bind(format!("{}%", fixture.suffix))
        .execute(&mut *transaction)
        .await
        .expect("the idempotency fixture must be removable");
    transaction
        .commit()
        .await
        .expect("the fixture cleanup must commit");

    let mut transaction = begin_as_owner(pool, &fixture.customer_a.0).await;
    for customer in [&fixture.customer_a, &fixture.customer_b] {
        sqlx::query("DELETE FROM customers WHERE id = $1")
            .bind(&customer.0)
            .execute(&mut *transaction)
            .await
            .expect("the customer fixture must be removable");
    }
    for deployment in [&fixture.deployment_a, &fixture.deployment_b] {
        sqlx::query("DELETE FROM deployments WHERE id = $1")
            .bind(&deployment.0)
            .execute(&mut *transaction)
            .await
            .expect("the deployment fixture must be removable");
    }
    transaction
        .commit()
        .await
        .expect("the deployment cleanup must commit");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql"]
async fn publish_writes_revision_audit_and_outbox_and_advances() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let state = AdminPolicyState::new(pool.clone(), fixture.deployment_a.clone());
    let request_context = context(&fixture);
    let config_publisher = request_context.actor.actor_id.0.to_string();
    let app = policy_admin_router(state).layer(Extension(request_context));
    let uri = "/api/v1/policies/attachments/revisions";
    let first_key = format!("{}-first", fixture.suffix);
    let second_key = format!("{}-second", fixture.suffix);

    let response = app
        .clone()
        .oneshot(publish_request(uri, &first_key))
        .await
        .expect("the first publish must answer");
    assert_eq!(response.status(), StatusCode::CREATED);
    let first = json_body(response).await;
    assert_eq!(first["data"]["revision_number"], json!(1));
    assert_eq!(first["data"]["family_key"], json!("attachments"));

    let (revision_count, active_count): (i64, i64) = sqlx::query_as(
        "SELECT count(*)::bigint, count(*) FILTER (WHERE deactivated_at IS NULL)::bigint \
         FROM policy_revisions WHERE family_id = 'attachments' AND scope_level = 'tenant' \
           AND customer_id = $1",
    )
    .bind(&fixture.customer_a.0)
    .fetch_one(&pool)
    .await
    .expect("the revision assertion must run");
    assert_eq!(
        revision_count, 1,
        "the publish must insert exactly one revision"
    );
    assert_eq!(active_count, 1, "the first revision must be the active one");
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events \
         WHERE deployment_id = $1 AND action = 'policy_published' AND result = 'success'",
    )
    .bind(&fixture.deployment_a.0)
    .fetch_one(&pool)
    .await
    .expect("the audit assertion must run");
    assert_eq!(
        audit_count, 1,
        "the publish must write exactly one success audit row"
    );
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox_events WHERE idempotency_key = $1 AND event_type = $2",
    )
    .bind(format!("policy-publish:{first_key}"))
    .bind("config.changed")
    .fetch_one(&pool)
    .await
    .expect("the outbox assertion must run");
    assert_eq!(
        outbox_count, 1,
        "the publish must write exactly one outbox event"
    );
    let config_row: Option<String> = sqlx::query_scalar(
        "SELECT config ->> 'revision_number' FROM config_revisions \
         WHERE scope = 'tenant' AND scope_id = $1 \
           AND config ->> 'source' = 'policy_publish' \
           AND config ->> 'family_key' = 'attachments' \
           AND config ->> 'revision_number' = '1'",
    )
    .bind(&fixture.customer_a.0)
    .fetch_optional(&pool)
    .await
    .expect("the config revision assertion must run");
    assert_eq!(
        config_row.as_deref(),
        Some("1"),
        "the publish must record the tenant-scoped config revision the runtime snapshot reads"
    );

    let response = app
        .clone()
        .oneshot(publish_request(uri, &second_key))
        .await
        .expect("the second publish must answer");
    assert_eq!(response.status(), StatusCode::CREATED);
    let second = json_body(response).await;
    assert_eq!(
        second["data"]["revision_number"],
        json!(2),
        "the next publish must allocate revision+1"
    );

    let (active_revisions, deactivated): (Vec<i64>, i64) = sqlx::query_as(
        "SELECT coalesce(array_agg(revision_number) FILTER (WHERE deactivated_at IS NULL), \
         ARRAY[]::bigint[]), count(*) FILTER (WHERE deactivated_at IS NOT NULL)::bigint \
         FROM policy_revisions WHERE family_id = 'attachments' AND scope_level = 'tenant' \
           AND customer_id = $1",
    )
    .bind(&fixture.customer_a.0)
    .fetch_one(&pool)
    .await
    .expect(" the deactivation assertion must run");
    assert_eq!(
        active_revisions,
        vec![2],
        "exactly the newest revision must stay active"
    );
    assert_eq!(
        deactivated, 1,
        "the previous active revision must be deactivated"
    );

    let response = app
        .clone()
        .oneshot(publish_request(uri, &first_key))
        .await
        .expect("the replay must answer");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a completed key must replay with 200 rather than creating again"
    );
    let replayed = json_body(response).await;
    assert_eq!(
        first, replayed,
        "a completed key must replay the stored response"
    );
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events \
         WHERE deployment_id = $1 AND action = 'policy_published' AND result = 'success'",
    )
    .bind(&fixture.deployment_a.0)
    .fetch_one(&pool)
    .await
    .expect("the replay audit assertion must run");
    assert_eq!(audit_count, 2, "a replay must not write a second audit row");

    sqlx::query(
        "DELETE FROM config_revisions WHERE scope = 'tenant' AND scope_id = $1 \
         AND config ->> 'source' = 'policy_publish' AND published_by = $2",
    )
    .bind(&fixture.customer_a.0)
    .bind(&config_publisher)
    .execute(&pool)
    .await
    .expect("the config revision fixture must be removable");

    cleanup(&pool, &fixture).await;
}

fn ml_publish_request(uri: &str, key: &str, action_json: &str, rule_id: &str) -> Request<Body> {
    let rule = format!(
        "{{\"id\":\"{rule_id}\",\"name\":\"ml thresholds\",\"priority\":10,\
         \"condition\":{{\"scope\":\"transaction\"}},\
         \"action\":{action_json},\
         \"enabled\":true}}"
    );
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-idempotency-key", key)
        .body(Body::from(format!("{{\"rules\":[{rule}]}}")))
        .expect("test request must build")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql"]
async fn ml_family_publish_validates_threshold_metadata() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let state = AdminPolicyState::new(pool.clone(), fixture.deployment_a.clone());
    let request_context = context(&fixture);
    let config_publisher = request_context.actor.actor_id.0.to_string();
    let app = policy_admin_router(state).layer(Extension(request_context));
    let uri = "/api/v1/policies/ml_threat_classification/revisions";

    let valid_action = r#"{"disposition":"quarantine","reason_code":"QUARANTINE_MALWARE",
        "metadata":{"thresholds":{"version":1,"classes":{
            "malware":{"low":0.4,"medium":0.7,"high":0.9},
            "phishing":{"low":0.5,"medium":0.75,"high":0.95}}}}}"#;
    let inverted_action = r#"{"disposition":"quarantine","reason_code":"QUARANTINE_MALWARE",
        "metadata":{"thresholds":{"version":1,"classes":{
            "malware":{"low":0.9,"medium":0.7,"high":0.5}}}}}"#;
    let bare_action = r#"{"disposition":"allow","reason_code":"ALLOWED"}"#;

    let revision_count = || async {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM policy_revisions WHERE family_id = 'ml_threat_classification' AND customer_id = $1",
        )
        .bind(&fixture.customer_a.0)
        .fetch_one(&pool)
        .await
        .expect("the revision count must run");
        count
    };

    // Inverted bands are refused with a specific, safe error code and no write.
    let response = app
        .clone()
        .oneshot(ml_publish_request(
            uri,
            &format!("{}-inverted", fixture.suffix),
            inverted_action,
            "33333333-3333-3333-3333-333333333333",
        ))
        .await
        .expect("the invalid publish must answer");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["code"], json!("INVALID_THRESHOLDS"));
    assert_eq!(
        revision_count().await,
        0,
        "a refused threshold payload must not store a revision"
    );

    // A valid threshold payload publishes through the normal audited path.
    let response = app
        .clone()
        .oneshot(ml_publish_request(
            uri,
            &format!("{}-valid", fixture.suffix),
            valid_action,
            "22222222-2222-2222-2222-222222222222",
        ))
        .await
        .expect("the valid publish must answer");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    assert_eq!(body["data"]["revision_number"], json!(1));
    let stored: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT rules -> 0 -> 'action' -> 'metadata' FROM policy_revisions WHERE family_id = 'ml_threat_classification' AND customer_id = $1 AND deactivated_at IS NULL",
    )
    .bind(&fixture.customer_a.0)
    .fetch_optional(&pool)
    .await
    .expect("the stored metadata must be readable");
    assert_eq!(
        stored
            .as_ref()
            .and_then(|m| m["thresholds"]["classes"]["malware"]["low"].as_f64()),
        Some(0.4),
        "the published thresholds must round-trip"
    );

    // The family stays publishable without thresholds: the stage treats
    // that as explicit unconfigured state (WARN, scores stay evidence).
    let response = app
        .clone()
        .oneshot(ml_publish_request(
            uri,
            &format!("{}-bare", fixture.suffix),
            bare_action,
            "44444444-4444-4444-4444-444444444444",
        ))
        .await
        .expect("the unconfigured publish must answer");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        revision_count().await,
        2,
        "both successful publishes must be stored"
    );

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE deployment_id = $1 AND action = 'policy_published' AND result = 'success' AND resource_type = 'policy_family'",
    )
    .bind(&fixture.deployment_a.0)
    .fetch_one(&pool)
    .await
    .expect("the audit assertion must run");
    assert_eq!(
        audit_count, 2,
        "only successful publishes are audited as successes"
    );

    sqlx::query(
        "DELETE FROM config_revisions WHERE scope = 'tenant' AND scope_id = $1 AND config ->> 'source' = 'policy_publish' AND published_by = $2",
    )
    .bind(&fixture.customer_a.0)
    .bind(&config_publisher)
    .execute(&pool)
    .await
    .expect("the config revision fixture must be removable");

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql"]
async fn tenant_revisions_are_scoped_to_their_customer_and_system_rows_to_the_deployment() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let mut owner = begin_as_owner(&pool, &fixture.customer_a.0).await;
    for (scope_level, customer, family) in [
        ("tenant", Some(&fixture.customer_a.0), "attachments"),
        ("system", None, "malware"),
    ] {
        sqlx::query(
            "INSERT INTO policy_revisions \
             (id, customer_id, deployment_id, family_id, scope_level, revision_number, rules, \
              published_by, published_at) \
             VALUES ($1, $2, $3, $4, $5, 1, '[]', 'local-policy-admin', now())",
        )
        .bind(Uuid::new_v4())
        .bind(customer)
        .bind(&fixture.deployment_a.0)
        .bind(family)
        .bind(scope_level)
        .execute(&mut *owner)
        .await
        .expect("the revision fixture must be created by the owner");
    }
    owner
        .commit()
        .await
        .expect("the revision fixture must commit");

    let mut own_scope = begin_scoped(
        &pool,
        Some(&fixture.deployment_a.0),
        Some(&fixture.customer_a.0),
    )
    .await;
    let visible: Vec<String> = sqlx::query_scalar(
        "SELECT family_id FROM policy_revisions WHERE family_id IS NOT NULL ORDER BY family_id",
    )
    .fetch_all(&mut *own_scope)
    .await
    .expect("the owning scope read must run");
    assert_eq!(
        visible,
        vec!["attachments".to_string(), "malware".to_string()],
        "the owning scope must see its tenant row and the deployment's system row"
    );
    own_scope.commit().await.expect("the read must commit");

    let mut neighbour = begin_scoped(
        &pool,
        Some(&fixture.deployment_a.0),
        Some(&fixture.customer_b.0),
    )
    .await;
    let neighbour_rows: Vec<String> = sqlx::query_scalar(
        "SELECT family_id FROM policy_revisions WHERE family_id = 'attachments'",
    )
    .fetch_all(&mut *neighbour)
    .await
    .expect("the neighbour read must run");
    assert!(
        neighbour_rows.is_empty(),
        "another tenant must not observe the customer's revision"
    );
    neighbour.commit().await.expect("the read must commit");

    let mut unscoped = begin_scoped(&pool, None, None).await;
    let unscoped_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM policy_revisions WHERE family_id IS NOT NULL")
            .fetch_one(&mut *unscoped)
            .await
            .expect("the unscoped read must run");
    assert_eq!(
        unscoped_rows, 0,
        "an unset scope must fail closed to zero rows"
    );
    let unscoped_write = sqlx::query(
        "INSERT INTO policy_revisions \
         (id, customer_id, deployment_id, family_id, scope_level, revision_number, rules, \
          published_by, published_at) \
         VALUES ($1, NULL, $2, 'malware', 'system', 99, '[]', 'local-policy-admin', now())",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.deployment_a.0)
    .execute(&mut *unscoped)
    .await;
    assert!(
        unscoped_write.is_err(),
        "an unset scope must refuse system-scope writes"
    );
    drop(unscoped);

    let mut customer_only = begin_customer_only(&pool, &fixture.customer_a.0).await;
    let customer_system_write = sqlx::query(
        "INSERT INTO policy_revisions \
         (id, customer_id, deployment_id, family_id, scope_level, revision_number, rules, \
          published_by, published_at) \
         VALUES ($1, NULL, $2, 'malware', 'system', 100, '[]', 'local-policy-admin', now())",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.deployment_a.0)
    .execute(&mut *customer_only)
    .await;
    assert!(
        customer_system_write.is_err(),
        "a customer-only scope must not mint a system-scope revision"
    );
    drop(customer_only);

    let mut system_scope = begin_scoped(&pool, Some(&fixture.deployment_a.0), None).await;
    sqlx::query(
        "UPDATE policy_revisions SET deactivated_at = now() \
         WHERE family_id = 'malware' AND scope_level = 'system' AND deactivated_at IS NULL",
    )
    .execute(&mut *system_scope)
    .await
    .expect("the superseded system revision must be deactivated");
    sqlx::query(
        "INSERT INTO policy_revisions \
         (id, customer_id, deployment_id, family_id, scope_level, revision_number, rules, \
          published_by, published_at) \
         VALUES ($1, NULL, $2, 'malware', 'system', 101, '[]', 'local-policy-admin', now())",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.deployment_a.0)
    .execute(&mut *system_scope)
    .await
    .expect("a deployment scope must accept a system-scope revision");
    let wrong_deployment = expect_rejected(
        &mut system_scope,
        sqlx::query(
            "INSERT INTO policy_revisions \
             (id, customer_id, deployment_id, family_id, scope_level, revision_number, rules, \
              published_by, published_at) \
             VALUES ($1, NULL, $2, 'malware', 'system', 102, '[]', 'local-policy-admin', now())",
        )
        .bind(Uuid::new_v4())
        .bind(&fixture.deployment_b.0),
    )
    .await;
    assert!(
        wrong_deployment.is_err(),
        "a deployment scope must not write another deployment's system row"
    );
    system_scope
        .commit()
        .await
        .expect("the system-scope write must commit");

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql"]
async fn feature_overrides_follow_the_three_level_scope_model() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let feature_id = fixture.suffix.clone();

    sqlx::query(
        "INSERT INTO feature_definitions (feature_id, description, default_value) \
         VALUES ($1, 'Local policy administration fixture', 'disabled') \
         ON CONFLICT (feature_id) DO NOTHING",
    )
    .bind(&feature_id)
    .execute(&pool)
    .await
    .expect("the feature fixture must exist before overrides reference it");

    let mut customer_only = begin_customer_only(&pool, &fixture.customer_a.0).await;
    let system_write = expect_rejected(
        &mut customer_only,
        sqlx::query(
            "INSERT INTO feature_overrides \
             (id, feature_id, scope, scope_id, value, owner, reason, revision) \
             VALUES ($1, $2, 'system', 'system', 'enabled', $3, 'local policy admin test', 1)",
        )
        .bind(Uuid::new_v4())
        .bind(&feature_id)
        .bind(&fixture.customer_a.0),
    )
    .await;
    assert!(
        system_write.is_err(),
        "a customer-only scope must not mint a system-scoped override"
    );
    let deployment_write = expect_rejected(
        &mut customer_only,
        sqlx::query(
            "INSERT INTO feature_overrides \
             (id, feature_id, scope, scope_id, value, owner, reason, revision) \
             VALUES ($1, $2, 'deployment', $3, 'enabled', $4, 'local policy admin test', 1)",
        )
        .bind(Uuid::new_v4())
        .bind(&feature_id)
        .bind(&fixture.deployment_a.0)
        .bind(&fixture.customer_a.0),
    )
    .await;
    assert!(
        deployment_write.is_err(),
        "a customer-only scope must not mint a deployment-scoped override"
    );
    drop(customer_only);

    let mut system_scope = begin_scoped(&pool, Some(&fixture.deployment_a.0), None).await;
    sqlx::query(
        "INSERT INTO feature_overrides \
         (id, feature_id, scope, scope_id, value, owner, reason, revision) \
         VALUES ($1, $2, 'system', 'system', 'enabled', 'local-policy-admin', \
                 'local policy admin test', 1)",
    )
    .bind(Uuid::new_v4())
    .bind(&feature_id)
    .execute(&mut *system_scope)
    .await
    .expect("a deployment scope must accept a system-scoped override");
    sqlx::query(
        "INSERT INTO feature_overrides \
         (id, feature_id, scope, scope_id, value, owner, reason, revision) \
         VALUES ($1, $2, 'deployment', $3, 'enabled', 'local-policy-admin', \
                 'local policy admin test', 1)",
    )
    .bind(Uuid::new_v4())
    .bind(&feature_id)
    .bind(&fixture.deployment_a.0)
    .execute(&mut *system_scope)
    .await
    .expect("a deployment scope must accept its own deployment-scoped override");
    let cross_deployment = expect_rejected(
        &mut system_scope,
        sqlx::query(
            "INSERT INTO feature_overrides \
             (id, feature_id, scope, scope_id, value, owner, reason, revision) \
             VALUES ($1, $2, 'deployment', $3, 'enabled', 'local-policy-admin', \
                     'local policy admin test', 1)",
        )
        .bind(Uuid::new_v4())
        .bind(&feature_id)
        .bind(&fixture.deployment_b.0),
    )
    .await;
    assert!(
        cross_deployment.is_err(),
        "a deployment scope must not write another deployment's override"
    );
    let observed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM feature_overrides WHERE feature_id = $1 AND scope = 'system'",
    )
    .bind(&feature_id)
    .fetch_one(&mut *system_scope)
    .await
    .expect("the system-scope read must run");
    assert_eq!(
        observed, 1,
        "the deployment scope must observe the system override"
    );
    system_scope
        .commit()
        .await
        .expect("the system and deployment overrides must commit");

    let mut tenant_scope = begin_scoped(&pool, None, Some(&fixture.customer_a.0)).await;
    sqlx::query(
        "INSERT INTO feature_overrides \
         (id, feature_id, scope, scope_id, value, owner, reason, revision) \
         VALUES ($1, $2, 'tenant', $3, 'enabled', $3, 'local policy admin test', 1)",
    )
    .bind(Uuid::new_v4())
    .bind(&feature_id)
    .bind(&fixture.customer_a.0)
    .execute(&mut *tenant_scope)
    .await
    .expect("a tenant scope must accept its own override");
    let neighbour_write = expect_rejected(
        &mut tenant_scope,
        sqlx::query(
            "INSERT INTO feature_overrides \
             (id, feature_id, scope, scope_id, value, owner, reason, revision) \
             VALUES ($1, $2, 'tenant', $3, 'enabled', $4, 'local policy admin test', 1)",
        )
        .bind(Uuid::new_v4())
        .bind(&feature_id)
        .bind(&fixture.customer_b.0)
        .bind(&fixture.customer_a.0),
    )
    .await;
    assert!(
        neighbour_write.is_err(),
        "a tenant scope must not write a neighbouring tenant's override"
    );
    let visible_system: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM feature_overrides WHERE feature_id = $1 AND scope = 'system'",
    )
    .bind(&feature_id)
    .fetch_one(&mut *tenant_scope)
    .await
    .expect("the tenant read must run");
    assert_eq!(
        visible_system, 0,
        "a tenant scope must not observe system-scoped overrides"
    );
    tenant_scope
        .commit()
        .await
        .expect("the tenant override must commit");

    let mut neighbour = begin_scoped(&pool, None, Some(&fixture.customer_b.0)).await;
    let neighbour_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM feature_overrides WHERE feature_id = $1 AND scope = 'tenant'",
    )
    .bind(&feature_id)
    .fetch_one(&mut *neighbour)
    .await
    .expect("the neighbour read must run");
    assert_eq!(
        neighbour_rows, 0,
        "another tenant must not observe the tenant override at all"
    );
    neighbour.commit().await.expect("the read must commit");

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql"]
async fn config_revisions_follow_the_three_level_scope_model() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let published_by = format!("local-policy-admin-{}", fixture.suffix);

    let mut customer_only = begin_customer_only(&pool, &fixture.customer_a.0).await;
    let system_write = expect_rejected(
        &mut customer_only,
        sqlx::query(
            "INSERT INTO config_revisions (id, scope, scope_id, config, published_by) \
             VALUES ($1, 'system', 'system', '{}', $2)",
        )
        .bind(Uuid::new_v4())
        .bind(&published_by),
    )
    .await;
    assert!(
        system_write.is_err(),
        "a customer-only scope must not mint a system-scoped config revision"
    );
    let deployment_write = expect_rejected(
        &mut customer_only,
        sqlx::query(
            "INSERT INTO config_revisions (id, scope, scope_id, config, published_by) \
             VALUES ($1, 'deployment', $2, '{}', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(&fixture.deployment_a.0)
        .bind(&published_by),
    )
    .await;
    assert!(
        deployment_write.is_err(),
        "a customer-only scope must not mint a deployment-scoped config revision"
    );
    drop(customer_only);

    let mut system_scope = begin_scoped(&pool, Some(&fixture.deployment_a.0), None).await;
    sqlx::query(
        "INSERT INTO config_revisions (id, scope, scope_id, config, published_by) \
         VALUES ($1, 'system', 'system', '{}', $2)",
    )
    .bind(Uuid::new_v4())
    .bind(&published_by)
    .execute(&mut *system_scope)
    .await
    .expect("a deployment scope must accept a system-scoped config revision");
    sqlx::query(
        "INSERT INTO config_revisions (id, scope, scope_id, config, published_by) \
         VALUES ($1, 'deployment', $2, '{}', $3)",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.deployment_a.0)
    .bind(&published_by)
    .execute(&mut *system_scope)
    .await
    .expect("a deployment scope must accept its own config revision");
    let cross_deployment = expect_rejected(
        &mut system_scope,
        sqlx::query(
            "INSERT INTO config_revisions (id, scope, scope_id, config, published_by) \
             VALUES ($1, 'deployment', $2, '{}', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(&fixture.deployment_b.0)
        .bind(&published_by),
    )
    .await;
    assert!(
        cross_deployment.is_err(),
        "a deployment scope must not write another deployment's config revision"
    );
    system_scope
        .commit()
        .await
        .expect("the system and deployment config revisions must commit");

    let mut tenant_scope = begin_scoped(&pool, None, Some(&fixture.customer_a.0)).await;
    sqlx::query(
        "INSERT INTO config_revisions (id, scope, scope_id, config, published_by) \
         VALUES ($1, 'tenant', $2, '{}', $3)",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.customer_a.0)
    .bind(&published_by)
    .execute(&mut *tenant_scope)
    .await
    .expect("a tenant scope must accept its own config revision");
    let neighbour_write = expect_rejected(
        &mut tenant_scope,
        sqlx::query(
            "INSERT INTO config_revisions (id, scope, scope_id, config, published_by) \
             VALUES ($1, 'tenant', $2, '{}', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(&fixture.customer_b.0)
        .bind(&published_by),
    )
    .await;
    assert!(
        neighbour_write.is_err(),
        "a tenant scope must not write a neighbouring tenant's config revision"
    );
    let visible_system: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM config_revisions WHERE scope = 'system' AND scope_id = 'system'",
    )
    .fetch_one(&mut *tenant_scope)
    .await
    .expect("the tenant read must run");
    assert_eq!(
        visible_system, 0,
        "a tenant scope must not observe system-scoped config revisions"
    );
    tenant_scope
        .commit()
        .await
        .expect("the tenant config revision must commit");

    let mut neighbour = begin_scoped(&pool, None, Some(&fixture.customer_b.0)).await;
    let neighbour_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM config_revisions WHERE scope = 'tenant' AND scope_id = $1",
    )
    .bind(&fixture.customer_a.0)
    .fetch_one(&mut *neighbour)
    .await
    .expect("the neighbour read must run");
    assert_eq!(
        neighbour_rows, 0,
        "another tenant must not observe the tenant config revision"
    );
    neighbour.commit().await.expect("the read must commit");

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql"]
async fn static_family_catalog_mirrors_the_seeded_table() {
    let pool = connect().await;
    let seeded: Vec<(String, String)> = sqlx::query_as(
        "SELECT family_key, management_level FROM policy_families ORDER BY family_key",
    )
    .fetch_all(&pool)
    .await
    .expect("the seeded family rows must be readable");

    let catalog: Vec<(String, String)> = POLICY_FAMILY_MANAGEMENT_LEVELS
        .iter()
        .map(|(key, level)| (key.to_string(), level.to_string()))
        .collect();
    assert_eq!(
        catalog.len(),
        24,
        "the offline tier gate must carry all 24 families"
    );
    assert!(
        catalog.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "the offline catalog must stay sorted by family key"
    );
    assert_eq!(
        catalog, seeded,
        "the offline tier gate must mirror the seeded policy_families rows exactly"
    );
}

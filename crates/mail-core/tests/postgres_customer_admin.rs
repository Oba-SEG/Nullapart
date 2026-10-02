//! Local PostgreSQL coverage for the Phase 3 increment 5 customer/domain
//! administration API.
//!
//! Requires PostgreSQL migrated through `013_customer_domain_administration.sql`
//! with `NULLAPART_TEST_DATABASE_URL` pointing at it. Every test is
//! `#[ignore]`d so the default suite stays offline; run them explicitly with
//! `cargo test --test postgres_customer_admin -- --ignored`.
//!
//! 1. **Lifecycle constraint**: the migration 013 CHECK accepts `grace` and
//!    `terminated` and still rejects `deprovisioned`.
//! 2. **`source_ip_groups` RLS**: rows appear only under their own customer
//!    GUC, an unset GUC fails closed to zero rows, and a mismatched write is
//!    refused by `WITH CHECK`.
//! 3. **`domains` uniqueness**: one domain belongs to one customer through
//!    the per-customer key and the global `lower(domain)` index.
//! 4. **Idempotency claims**: fresh, in-flight, replay, operation mismatch,
//!    and `complete` all behave as the administration handlers assume.
//! 5. **Source IP group names**: unique per customer, reusable across
//!    customers.
//! 6. **Lifecycle transitions at the router**: the database row is the
//!    authority, same-state and invalid transitions return 409, the failed
//!    claim rolls back, and a completed key replays the stored response.

use axum::{
    body::{to_bytes, Body},
    extract::Extension,
    http::{Request, StatusCode},
};
use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId},
    ActorId,
};
use nullapart_mail_core::admin_customers::{
    admin_customers_router, AdminCustomersState, CUSTOMERS_MANAGE_PERMISSION,
    CUSTOMERS_VIEW_PERMISSION, DOMAINS_MANAGE_PERMISSION,
};
use nullapart_mail_core::admin_rbac::SYSTEM_ADMIN_ROLE;
use nullapart_mail_core::idempotency::{claim, complete, ClaimOutcome};
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

struct Fixture {
    deployment: DeploymentId,
    customer_a: CustomerId,
    customer_b: CustomerId,
    suffix: String,
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

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = format!("local-custadmin-{}", Uuid::new_v4().simple());
    let deployment = DeploymentId::new(&suffix.to_uppercase());
    let customer_a = CustomerId::new(&format!("{suffix}-a"));
    let customer_b = CustomerId::new(&format!("{suffix}-b"));

    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&deployment.0)
    .bind(&suffix)
    .execute(pool)
    .await
    .expect("the deployment fixture must be created");
    for customer in [&customer_a, &customer_b] {
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&customer.0)
        .bind(&deployment.0)
        .bind(&suffix)
        .execute(pool)
        .await
        .expect("the customer fixture must be created");
    }

    Fixture {
        deployment,
        customer_a,
        customer_b,
        suffix,
    }
}

async fn insert_customer(
    pool: &PgPool,
    deployment: &str,
    id: &str,
    lifecycle: &str,
) -> Result<(), sqlx::Error> {
    let mut transaction = begin_scoped(pool, Some(deployment), None).await;
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(deployment)
    .bind("lifecycle probe")
    .bind(lifecycle)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 013_customer_domain_administration.sql"]
async fn lifecycle_check_accepts_grace_and_terminated_states() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    insert_customer(
        &pool,
        &fixture.deployment.0,
        &format!("{}-grace", fixture.suffix),
        "grace",
    )
    .await
    .expect("grace must be an accepted lifecycle");
    insert_customer(
        &pool,
        &fixture.deployment.0,
        &format!("{}-terminated", fixture.suffix),
        "terminated",
    )
    .await
    .expect("terminated must be an accepted lifecycle");
    insert_customer(
        &pool,
        &fixture.deployment.0,
        &format!("{}-legacy", fixture.suffix),
        "active",
    )
    .await
    .expect("active must remain accepted");

    let rejected = insert_customer(
        &pool,
        &fixture.deployment.0,
        &format!("{}-deprovisioned", fixture.suffix),
        "deprovisioned",
    )
    .await;
    assert!(
        rejected.is_err(),
        "deprovisioned must stay rejected by the 013 CHECK"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 013_customer_domain_administration.sql"]
async fn source_ip_group_rows_are_isolated_by_customer_scope() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let mut transaction = begin_scoped(
        &pool,
        Some(&fixture.deployment.0),
        Some(&fixture.customer_a.0),
    )
    .await;
    sqlx::query(
        "INSERT INTO source_ip_groups (deployment_id, customer_id, name, cidrs, created_by) \
         VALUES ($1, $2, 'office', $3, 'rls-test')",
    )
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer_a.0)
    .bind(&["10.0.0.0/8".to_string()])
    .execute(&mut *transaction)
    .await
    .expect("the owning customer scope must accept its group");
    let own_rows =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM source_ip_groups WHERE name = 'office'")
            .fetch_one(&mut *transaction)
            .await
            .expect("the own-scope read must run");
    assert_eq!(own_rows, 1, "the owning scope must see its group");

    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(&fixture.customer_b.0)
        .execute(&mut *transaction)
        .await
        .expect("the foreign scope must be switchable");
    let foreign_rows =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM source_ip_groups WHERE name = 'office'")
            .fetch_one(&mut *transaction)
            .await
            .expect("the foreign-scope read must run");
    assert_eq!(foreign_rows, 0, "another customer must not see the group");
    let foreign_write = sqlx::query(
        "INSERT INTO source_ip_groups (deployment_id, customer_id, name, cidrs, created_by) \
         VALUES ($1, $2, 'sneaky', $3, 'rls-test')",
    )
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer_a.0)
    .bind(&["10.0.0.0/8".to_string()])
    .execute(&mut *transaction)
    .await;
    assert!(
        foreign_write.is_err(),
        "WITH CHECK must refuse a write for another tenant"
    );
    drop(transaction);

    let mut unscoped = begin_scoped(&pool, None, None).await;
    let unscoped_rows =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM source_ip_groups WHERE name = 'office'")
            .fetch_one(&mut *unscoped)
            .await
            .expect("the unscoped read must run");
    assert_eq!(
        unscoped_rows, 0,
        "an unset customer GUC must fail closed to zero rows"
    );
    let unscoped_write = sqlx::query(
        "INSERT INTO source_ip_groups (deployment_id, customer_id, name, cidrs, created_by) \
         VALUES ($1, $2, 'unscoped', $3, 'rls-test')",
    )
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer_a.0)
    .bind(&["10.0.0.0/8".to_string()])
    .execute(&mut *unscoped)
    .await;
    assert!(
        unscoped_write.is_err(),
        "an unset customer GUC must refuse writes"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 013_customer_domain_administration.sql"]
async fn domain_names_are_unique_per_customer_and_globally() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let domain = format!("{}.example.test", fixture.suffix);

    let mut transaction = begin_scoped(
        &pool,
        Some(&fixture.deployment.0),
        Some(&fixture.customer_a.0),
    )
    .await;
    sqlx::query("INSERT INTO domains (customer_id, domain) VALUES ($1, $2)")
        .bind(&fixture.customer_a.0)
        .bind(&domain)
        .execute(&mut *transaction)
        .await
        .expect("the first registration must succeed");
    let duplicate = expect_rejected(
        &mut transaction,
        sqlx::query("INSERT INTO domains (customer_id, domain) VALUES ($1, $2)")
            .bind(&fixture.customer_a.0)
            .bind(&domain),
    )
    .await;
    assert!(
        duplicate.is_err(),
        "the per-customer unique key must reject a duplicate"
    );
    transaction
        .commit()
        .await
        .expect("the first registration must persist");

    let mut transaction = begin_scoped(
        &pool,
        Some(&fixture.deployment.0),
        Some(&fixture.customer_b.0),
    )
    .await;
    let cross_customer = expect_rejected(
        &mut transaction,
        sqlx::query("INSERT INTO domains (customer_id, domain) VALUES ($1, $2)")
            .bind(&fixture.customer_b.0)
            .bind(domain.to_uppercase()),
    )
    .await;
    assert!(
        cross_customer.is_err(),
        "the global lower(domain) index must bind one domain to one customer"
    );
    sqlx::query("INSERT INTO domains (customer_id, domain) VALUES ($1, $2)")
        .bind(&fixture.customer_b.0)
        .bind(format!("other-{domain}"))
        .execute(&mut *transaction)
        .await
        .expect("an unrelated domain must still register");
    transaction.commit().await.expect("the fixture must commit");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 013_customer_domain_administration.sql"]
async fn idempotency_claims_replay_complete_and_mismatch() {
    let pool = connect().await;
    ensure_request_role(&pool).await;

    let key = format!("test-{}", Uuid::new_v4());
    let operation = "admin:customer:update:test-customer";

    let mut transaction = begin_scoped(&pool, None, None).await;
    let outcome = claim(&mut transaction, &key, operation)
        .await
        .expect("the first claim must run");
    assert!(
        matches!(outcome, ClaimOutcome::Fresh),
        "an unseen key must be fresh"
    );
    let outcome = claim(&mut transaction, &key, operation)
        .await
        .expect("the second claim must run");
    assert!(
        matches!(outcome, ClaimOutcome::InProgress),
        "a claimed key without a stored response must be in flight"
    );

    let stored = json!({ "data": { "id": "test-customer", "lifecycle": "suspended" } });
    complete(&mut transaction, &key, operation, stored.clone())
        .await
        .expect("the completion must store the response");
    let outcome = claim(&mut transaction, &key, operation)
        .await
        .expect("the replay claim must run");
    match outcome {
        ClaimOutcome::Replay(value) => {
            assert_eq!(value, stored, "a replay must return the stored response")
        },
        _ => panic!("a completed key must replay"),
    }
    let mismatch = claim(
        &mut transaction,
        &key,
        "admin:customer:update:other-customer",
    )
    .await
    .expect("the mismatch claim must run");
    assert!(
        matches!(mismatch, ClaimOutcome::OperationMismatch),
        "a key must stay bound to its first operation"
    );
    transaction
        .commit()
        .await
        .expect("the claim fixture must commit");

    let mut wrong_transaction = pool.begin().await.expect("a transaction must begin");
    let wrong_operation =
        complete(&mut wrong_transaction, &key, "other-operation", json!({})).await;
    drop(wrong_transaction);
    assert!(
        wrong_operation.is_err(),
        "complete must refuse an operation that does not own the key"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 013_customer_domain_administration.sql"]
async fn source_ip_group_names_are_unique_per_customer() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let mut transaction = begin_scoped(
        &pool,
        Some(&fixture.deployment.0),
        Some(&fixture.customer_a.0),
    )
    .await;
    sqlx::query(
        "INSERT INTO source_ip_groups (deployment_id, customer_id, name, cidrs, created_by) \
         VALUES ($1, $2, 'office', $3, 'uniqueness-test')",
    )
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer_a.0)
    .bind(&["192.0.2.0/24".to_string()])
    .execute(&mut *transaction)
    .await
    .expect("the first group must insert");
    let duplicate = sqlx::query(
        "INSERT INTO source_ip_groups (deployment_id, customer_id, name, cidrs, created_by) \
         VALUES ($1, $2, 'office', $3, 'uniqueness-test')",
    )
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer_a.0)
    .bind(&["198.51.100.0/24".to_string()])
    .execute(&mut *transaction)
    .await;
    assert!(
        duplicate.is_err(),
        "one customer must not reuse a group name"
    );
    drop(transaction);

    let mut transaction = begin_scoped(
        &pool,
        Some(&fixture.deployment.0),
        Some(&fixture.customer_b.0),
    )
    .await;
    sqlx::query(
        "INSERT INTO source_ip_groups (deployment_id, customer_id, name, cidrs, created_by) \
         VALUES ($1, $2, 'office', $3, 'uniqueness-test')",
    )
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer_b.0)
    .bind(&["203.0.113.0/24".to_string()])
    .execute(&mut *transaction)
    .await
    .expect("another customer must reuse the name freely");
    transaction.commit().await.expect("the fixture must commit");
}

fn context(deployment: &DeploymentId, customer: &CustomerId) -> TenantContext {
    TenantContext {
        deployment_id: deployment.clone(),
        region: RegionId::new("local"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "customer-admin-test@example.test".to_string(),
            roles: vec![SYSTEM_ADMIN_ROLE.to_string()],
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: customer.clone(),
        customer_internal_key: 1,
        customer_display_name: "Customer administration test".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: vec![
            CUSTOMERS_VIEW_PERMISSION.to_string(),
            CUSTOMERS_MANAGE_PERMISSION.to_string(),
            DOMAINS_MANAGE_PERMISSION.to_string(),
        ],
        config_revision: 1,
        trace_id: "postgres-customer-admin-trace".to_string(),
        correlation_id: "postgres-customer-admin-correlation".to_string(),
        session_id: "postgres-customer-admin-session".to_string(),
        authenticated_at: chrono::Utc::now(),
    }
}

fn patch_request(uri: &str, key: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-idempotency-key", key)
        .body(Body::from(body.to_string()))
        .expect("test request must build")
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    serde_json::from_slice(&bytes).expect("the body must be JSON")
}

async fn audit_success_count(pool: &PgPool, deployment: &DeploymentId) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events \
         WHERE deployment_id = $1 AND action = 'customer_updated' AND result = 'success'",
    )
    .bind(&deployment.0)
    .fetch_one(pool)
    .await
    .expect("the audit assertion must run")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 013_customer_domain_administration.sql"]
async fn patch_enforces_database_lifecycle_transitions_and_replays() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let state = AdminCustomersState::new(pool.clone(), fixture.deployment.clone());
    let app = admin_customers_router(state)
        .layer(Extension(context(&fixture.deployment, &fixture.customer_a)));
    let uri = format!("/api/v1/admin/customers/{}", fixture.customer_a.0);
    let transition_key = format!("{}-transition", fixture.suffix);
    let same_state_key = format!("{}-same-state", fixture.suffix);
    let invalid_transition_key = format!("{}-invalid-transition", fixture.suffix);

    let response = app
        .clone()
        .oneshot(patch_request(
            &uri,
            &transition_key,
            r#"{"lifecycle":"suspended","reason":"billing hold applied"}"#,
        ))
        .await
        .expect("the transition must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let first = json_body(response).await;
    assert_eq!(first["data"]["lifecycle"], json!("suspended"));

    let stored_lifecycle = sqlx::query_scalar::<_, String>(
        "SELECT lifecycle FROM customers WHERE id = $1 AND deployment_id = $2",
    )
    .bind(&fixture.customer_a.0)
    .bind(&fixture.deployment.0)
    .fetch_one(&pool)
    .await
    .expect("the customer row must exist");
    assert_eq!(stored_lifecycle, "suspended", "the row must transition");
    assert_eq!(
        audit_success_count(&pool, &fixture.deployment).await,
        1,
        "the transition must write exactly one success audit row"
    );

    let response = app
        .clone()
        .oneshot(patch_request(
            &uri,
            &transition_key,
            r#"{"lifecycle":"suspended","reason":"billing hold applied"}"#,
        ))
        .await
        .expect("the replay must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let replayed = json_body(response).await;
    assert_eq!(first, replayed, "a replay must return the stored response");
    assert_eq!(
        audit_success_count(&pool, &fixture.deployment).await,
        1,
        "a replay must not write a second audit row"
    );

    let same_state = patch_request(
        &uri,
        &same_state_key,
        r#"{"lifecycle":"suspended","reason":"already suspended now"}"#,
    );
    let response = app
        .clone()
        .oneshot(same_state)
        .await
        .expect("the same-state attempt must answer");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let conflict = json_body(response).await;
    assert_eq!(
        conflict,
        json!({
            "code": "CONFLICT",
            "message": "Customer lifecycle transition is not allowed"
        })
    );

    let response = app
        .clone()
        .oneshot(patch_request(
            &uri,
            &same_state_key,
            r#"{"lifecycle":"suspended","reason":"already suspended now"}"#,
        ))
        .await
        .expect("the repeated attempt must answer");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let repeated = json_body(response).await;
    assert_eq!(
        repeated, conflict,
        "a failed claim must roll back so the same key retries the same path"
    );

    let response = app
        .clone()
        .oneshot(patch_request(
            &uri,
            &invalid_transition_key,
            r#"{"lifecycle":"grace","reason":"invalid from suspended"}"#,
        ))
        .await
        .expect("the invalid transition must answer");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let invalid = json_body(response).await;
    assert_eq!(
        invalid,
        json!({
            "code": "CONFLICT",
            "message": "Customer lifecycle transition is not allowed"
        })
    );
}

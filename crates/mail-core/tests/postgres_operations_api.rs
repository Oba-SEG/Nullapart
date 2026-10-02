//! Local PostgreSQL coverage for the Phase 3 increment 7 runtime operations
//! visibility migration (`015_runtime_operations.sql`).
//!
//! Requires PostgreSQL migrated through `015_runtime_operations.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Every test is `#[ignore]`d so
//! the default suite stays offline; run them explicitly with
//! `cargo test --test postgres_operations_api -- --ignored`.
//!
//! Migration 015 widens `outbox_events` and `reinjection_dead_letters` `USING`
//! to a deployment match so the operations projection can report
//! deployment-wide publication lag. `WITH CHECK` is deliberately unchanged, so
//! every test below pairs a read assertion with a write assertion:
//!
//! 1. **`outbox_events`**: the row is readable with either scope alone and with
//!    both, fails closed with neither and across deployments, while minting
//!    stays tenant-bound (cross-customer and platform-scoped inserts are
//!    refused) and a deployment-only scope is read-only.
//! 2. **`reinjection_dead_letters`**: the same four read combinations over the
//!    dead-letter table, plus the same tenant-bound write refusals. This needs
//!    an SMTP transaction, a tenant message and an outbox event fixture.
//! 3. **`config_revisions`**: unchanged by 015 — a system row needs the
//!    deployment scope, a tenant row is invisible to its neighbour and to a
//!    deployment-only scope.
//! 4. **`nodes`**: nodes carry no RLS, so the operations projection relies on
//!    the `deployment_id = $1` filter in its SQL; the ordering contract
//!    (`node_type`, `id`) is asserted alongside it.
//!
//! `postgres_rls_isolation.rs::rls_outbox_events_scoped_to_deployment` must
//! keep passing alongside this suite: it proves the widened read did not weaken
//! the tenant-bound `WITH CHECK`.

use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Transaction};
use uuid::Uuid;

/// The non-owner, non-superuser role every RLS statement assumes.
const REQUEST_ROLE: &str = "nullapart_local_request";

/// The exact node projection the operations snapshot issues: the filter is the
/// contract, because `nodes` has no row-level security to fall back on.
const NODES_SQL: &str = "SELECT id, node_type, role, status, hostname, version, \
     config_revision, last_health_check FROM nodes \
     WHERE deployment_id = $1 ORDER BY node_type, id";

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

/// Begins a transaction as the request role with the deployment RLS setting
/// applied transaction-locally. `None` leaves it unset (fail closed).
async fn begin_deploy_scoped<'a>(
    pool: &'a PgPool,
    deployment: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool
        .begin()
        .await
        .expect("a transaction must begin for the scoped statement");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("the session must assume the request role");
    if let Some(deployment) = deployment {
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(deployment)
            .execute(&mut *transaction)
            .await
            .expect("the deployment setting must be established");
    }
    transaction
}

/// Adds the tenant scope to an already deployment-scoped transaction so each
/// of the four GUC combinations can be exercised independently.
async fn set_customer_scope(transaction: &mut Transaction<'_, sqlx::Postgres>, customer: &str) {
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(customer)
        .execute(&mut **transaction)
        .await
        .expect("the customer setting must be established");
}

/// The four combinations the operations projection and its callers rely on:
/// both scopes, deployment only, customer only, and neither.
async fn scoped<'a>(
    pool: &'a PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = begin_deploy_scoped(pool, deployment).await;
    if let Some(customer) = customer {
        set_customer_scope(&mut transaction, customer).await;
    }
    transaction
}

/// Two customers in deployment A and one in deployment B, so every assertion
/// can separate deployment scope from tenant scope.
struct Identity {
    deployment_a: DeploymentId,
    deployment_b: DeploymentId,
    customer_a1: CustomerId,
    customer_a2: CustomerId,
    customer_b1: CustomerId,
    suffix: String,
}

async fn seed_identity(pool: &PgPool) -> Identity {
    let suffix = format!("local-operations-{}", Uuid::new_v4().simple());
    let deployment_a = DeploymentId::new(&format!("LOCAL-OPS-A-{suffix}"));
    let deployment_b = DeploymentId::new(&format!("LOCAL-OPS-B-{suffix}"));
    let customer_a1 = CustomerId::new(&format!("{suffix}-a1"));
    let customer_a2 = CustomerId::new(&format!("{suffix}-a2"));
    let customer_b1 = CustomerId::new(&format!("{suffix}-b1"));

    for (id, name) in [
        (&deployment_a, "Operations deployment A"),
        (&deployment_b, "Operations deployment B"),
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
    for (id, deployment) in [
        (&customer_a1, &deployment_a),
        (&customer_a2, &deployment_a),
        (&customer_b1, &deployment_b),
    ] {
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

    Identity {
        deployment_a,
        deployment_b,
        customer_a1,
        customer_a2,
        customer_b1,
        suffix,
    }
}

async fn cleanup_identity(pool: &PgPool, identity: &Identity) {
    for customer in [
        &identity.customer_a1,
        &identity.customer_a2,
        &identity.customer_b1,
    ] {
        sqlx::query("DELETE FROM customers WHERE id = $1")
            .bind(&customer.0)
            .execute(pool)
            .await
            .expect("the customer fixture must be removable");
    }
    for deployment in [&identity.deployment_a, &identity.deployment_b] {
        sqlx::query("DELETE FROM deployments WHERE id = $1")
            .bind(&deployment.0)
            .execute(pool)
            .await
            .expect("the deployment fixture must be removable");
    }
}

// ---------------------------------------------------------------------------
// 1. outbox_events
// ---------------------------------------------------------------------------

async fn outbox_rows(
    pool: &PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
    event_id: Uuid,
) -> i64 {
    let mut transaction = scoped(pool, deployment, customer).await;
    let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_events WHERE id = $1")
        .bind(event_id)
        .fetch_one(&mut *transaction)
        .await
        .expect("the outbox read must run");
    transaction
        .commit()
        .await
        .expect("the outbox read must commit");
    count
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 015_runtime_operations.sql"]
async fn outbox_events_read_across_the_deployment_but_mint_only_for_the_tenant() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let identity = seed_identity(&pool).await;

    // Seeded through the request role so the write itself proves the
    // tenant-bound WITH CHECK still admits the ordinary case.
    let event_id = {
        let mut transaction = scoped(
            &pool,
            Some(identity.deployment_a.0.as_str()),
            Some(identity.customer_a1.0.as_str()),
        )
        .await;
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO outbox_events (event_type, payload, customer_id, deployment_id, trace_id) \
             VALUES ('operations.probe', $1, $2, $3, 'local-operations-trace') RETURNING id",
        )
        .bind(serde_json::json!({ "fixture": "operations-api" }))
        .bind(identity.customer_a1.0.as_str())
        .bind(identity.deployment_a.0.as_str())
        .fetch_one(&mut *transaction)
        .await
        .expect("the owning tenant must be able to write its own row");
        transaction.commit().await.expect("the seed must commit");
        id
    };

    let deployment_a = identity.deployment_a.0.as_str();
    let deployment_b = identity.deployment_b.0.as_str();
    let customer_a1 = identity.customer_a1.0.as_str();
    let customer_a2 = identity.customer_a2.0.as_str();
    let customer_b1 = identity.customer_b1.0.as_str();

    // The four GUC combinations: both scopes, deployment only, customer only,
    // and neither (fail closed).
    assert_eq!(
        outbox_rows(&pool, Some(deployment_a), Some(customer_a1), event_id).await,
        1,
        "both scopes must observe the row"
    );
    assert_eq!(
        outbox_rows(&pool, Some(deployment_a), None, event_id).await,
        1,
        "a deployment scope alone must observe the row"
    );
    assert_eq!(
        outbox_rows(&pool, None, Some(customer_a1), event_id).await,
        1,
        "a customer scope alone must still observe its own row"
    );
    assert_eq!(
        outbox_rows(&pool, None, None, event_id).await,
        0,
        "no request-scoped context must expose no rows"
    );

    // The widening is bounded by the deployment: a neighbouring tenant in the
    // same deployment observes the row, another deployment never does.
    assert_eq!(
        outbox_rows(&pool, Some(deployment_a), Some(customer_a2), event_id).await,
        1,
        "a tenant in the same deployment must observe deployment-wide lag"
    );
    assert_eq!(
        outbox_rows(&pool, Some(deployment_b), Some(customer_b1), event_id).await,
        0,
        "another deployment must not observe the row"
    );

    // Writes stay tenant-bound: minting another tenant's scope is refused
    // even though the deployment scope can read it.
    let mut transaction = scoped(&pool, Some(deployment_a), Some(customer_a1)).await;
    let cross_customer = sqlx::query(
        "INSERT INTO outbox_events (event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ('operations.probe', $1, $2, $3, 'local-operations-trace')",
    )
    .bind(serde_json::json!({ "fixture": "operations-api" }))
    .bind(customer_a2)
    .bind(deployment_a)
    .execute(&mut *transaction)
    .await;
    assert!(
        cross_customer.is_err(),
        "WITH CHECK must refuse minting another tenant's scope"
    );
    drop(transaction);

    // A platform-scoped (customer-less) event must still be impossible for a
    // tenant session: customer_id = NULL never equals the customer GUC. It
    // runs in its own transaction so the refusal is the policy, not an
    // already-aborted statement.
    let mut transaction = scoped(&pool, Some(deployment_a), Some(customer_a1)).await;
    let platform_scoped = sqlx::query(
        "INSERT INTO outbox_events (event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ('operations.probe', $1, NULL, $2, 'local-operations-trace')",
    )
    .bind(serde_json::json!({ "fixture": "operations-api" }))
    .bind(deployment_a)
    .execute(&mut *transaction)
    .await;
    assert!(
        platform_scoped.is_err(),
        "WITH CHECK must refuse a platform-scoped event"
    );
    drop(transaction);

    // The deployment scope is read widening only: with the customer scope
    // absent nothing may be minted at all.
    let mut transaction = scoped(&pool, Some(deployment_a), None).await;
    let deployment_only_write = sqlx::query(
        "INSERT INTO outbox_events (event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ('operations.probe', $1, $2, $3, 'local-operations-trace')",
    )
    .bind(serde_json::json!({ "fixture": "operations-api" }))
    .bind(customer_a1)
    .bind(deployment_a)
    .execute(&mut *transaction)
    .await;
    assert!(
        deployment_only_write.is_err(),
        "a deployment-only scope must be read-only"
    );
    transaction
        .commit()
        .await
        .expect("the read-only scope transaction must commit");

    sqlx::query("DELETE FROM outbox_events WHERE id = $1")
        .bind(event_id)
        .execute(&pool)
        .await
        .expect("the outbox fixture must be removable");
    cleanup_identity(&pool, &identity).await;
}

// ---------------------------------------------------------------------------
// 2. reinjection_dead_letters
// ---------------------------------------------------------------------------

async fn dead_letter_rows(
    pool: &PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
    event_id: Uuid,
) -> i64 {
    let mut transaction = scoped(pool, deployment, customer).await;
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM reinjection_dead_letters WHERE outbox_event_id = $1",
    )
    .bind(event_id)
    .fetch_one(&mut *transaction)
    .await
    .expect("the dead-letter read must run");
    transaction
        .commit()
        .await
        .expect("the dead-letter read must commit");
    count
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 015_runtime_operations.sql"]
async fn reinjection_dead_letters_read_across_the_deployment_but_mint_only_for_the_tenant() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let identity = seed_identity(&pool).await;

    let transaction_id = Uuid::new_v4();
    let message_a1 = Uuid::new_v4();
    let message_a2 = Uuid::new_v4();
    let event_a1 = Uuid::new_v4();
    let event_a2 = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO smtp_transactions (id, deployment_id, direction, envelope_sender, \
                content_hash, mime_artifact_id, received_at) \
         VALUES ($1, $2, 'inbound', 'sender@example.test', 'operations-hash', \
                 'local-operations', now())",
    )
    .bind(transaction_id)
    .bind(identity.deployment_a.0.as_str())
    .execute(&pool)
    .await
    .expect("the transaction fixture must be created");
    for (message_id, customer) in [
        (message_a1, identity.customer_a1.0.as_str()),
        (message_a2, identity.customer_a2.0.as_str()),
    ] {
        sqlx::query(
            "INSERT INTO tenant_message_instances (id, transaction_id, customer_id, disposition) \
             VALUES ($1, $2, $3, 'quarantine')",
        )
        .bind(message_id)
        .bind(transaction_id)
        .bind(customer)
        .execute(&pool)
        .await
        .expect("the tenant message fixture must be created");
    }
    for (event_id, customer) in [
        (event_a1, identity.customer_a1.0.as_str()),
        (event_a2, identity.customer_a2.0.as_str()),
    ] {
        sqlx::query(
            "INSERT INTO outbox_events (id, event_type, payload, customer_id, deployment_id, \
                    trace_id) \
             VALUES ($1, 'quarantine.released', $2, $3, $4, 'local-operations-trace')",
        )
        .bind(event_id)
        .bind(serde_json::json!({ "fixture": "operations-api" }))
        .bind(customer)
        .bind(identity.deployment_a.0.as_str())
        .execute(&pool)
        .await
        .expect("the outbox fixture must be created");
    }
    sqlx::query(
        "INSERT INTO reinjection_dead_letters \
                (outbox_event_id, tenant_message_id, deployment_id, customer_id, failure_code) \
         VALUES ($1, $2, $3, $4, 'INVALID_EVENT')",
    )
    .bind(event_a1)
    .bind(message_a1)
    .bind(identity.deployment_a.0.as_str())
    .bind(identity.customer_a1.0.as_str())
    .execute(&pool)
    .await
    .expect("the dead-letter fixture must be created");

    let deployment_a = identity.deployment_a.0.as_str();
    let deployment_b = identity.deployment_b.0.as_str();
    let customer_a1 = identity.customer_a1.0.as_str();
    let customer_a2 = identity.customer_a2.0.as_str();
    let customer_b1 = identity.customer_b1.0.as_str();

    // The same four GUC combinations as the outbox table.
    assert_eq!(
        dead_letter_rows(&pool, Some(deployment_a), Some(customer_a1), event_a1).await,
        1,
        "both scopes must observe the dead letter"
    );
    assert_eq!(
        dead_letter_rows(&pool, Some(deployment_a), None, event_a1).await,
        1,
        "a deployment scope alone must observe the dead letter"
    );
    assert_eq!(
        dead_letter_rows(&pool, None, Some(customer_a1), event_a1).await,
        1,
        "a customer scope alone must still observe its own dead letter"
    );
    assert_eq!(
        dead_letter_rows(&pool, None, None, event_a1).await,
        0,
        "no request-scoped context must expose no rows"
    );
    assert_eq!(
        dead_letter_rows(&pool, Some(deployment_b), Some(customer_b1), event_a1).await,
        0,
        "another deployment must not observe the dead letter"
    );

    // Writes stay tenant-bound even though the deployment scope reads them.
    let mut transaction = scoped(&pool, Some(deployment_a), Some(customer_a1)).await;
    let cross_customer = sqlx::query(
        "INSERT INTO reinjection_dead_letters \
                (outbox_event_id, tenant_message_id, deployment_id, customer_id, failure_code) \
         VALUES ($1, $2, $3, $4, 'INVALID_EVENT')",
    )
    .bind(event_a2)
    .bind(message_a2)
    .bind(deployment_a)
    .bind(customer_a2)
    .execute(&mut *transaction)
    .await;
    assert!(
        cross_customer.is_err(),
        "WITH CHECK must refuse recording another tenant's dead letter"
    );
    transaction
        .commit()
        .await
        .expect("the refused write must roll back cleanly");

    // A deployment-only scope is read-only here as well.
    let mut transaction = scoped(&pool, Some(deployment_a), None).await;
    let deployment_only_write = sqlx::query(
        "INSERT INTO reinjection_dead_letters \
                (outbox_event_id, tenant_message_id, deployment_id, customer_id, failure_code) \
         VALUES ($1, $2, $3, $4, 'INVALID_EVENT')",
    )
    .bind(event_a2)
    .bind(message_a2)
    .bind(deployment_a)
    .bind(customer_a2)
    .execute(&mut *transaction)
    .await;
    assert!(
        deployment_only_write.is_err(),
        "a deployment-only scope must be read-only"
    );
    transaction
        .commit()
        .await
        .expect("the refused write must roll back cleanly");

    sqlx::query("DELETE FROM reinjection_dead_letters WHERE outbox_event_id IN ($1, $2)")
        .bind(event_a1)
        .bind(event_a2)
        .execute(&pool)
        .await
        .expect("the dead-letter fixture must be removable");
    sqlx::query("DELETE FROM outbox_events WHERE id IN ($1, $2)")
        .bind(event_a1)
        .bind(event_a2)
        .execute(&pool)
        .await
        .expect("the outbox fixture must be removable");
    sqlx::query("DELETE FROM tenant_message_instances WHERE id IN ($1, $2)")
        .bind(message_a1)
        .bind(message_a2)
        .execute(&pool)
        .await
        .expect("the tenant message fixture must be removable");
    sqlx::query("DELETE FROM smtp_transactions WHERE id = $1")
        .bind(transaction_id)
        .execute(&pool)
        .await
        .expect("the transaction fixture must be removable");
    cleanup_identity(&pool, &identity).await;
}

// ---------------------------------------------------------------------------
// 3. config_revisions
// ---------------------------------------------------------------------------

async fn system_config_rows(
    pool: &PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
    published_by: &str,
) -> i64 {
    let mut transaction = scoped(pool, deployment, customer).await;
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM config_revisions \
         WHERE scope = 'system' AND scope_id = 'system' AND published_by = $1",
    )
    .bind(published_by)
    .fetch_one(&mut *transaction)
    .await
    .expect("the system config read must run");
    transaction
        .commit()
        .await
        .expect("the system config read must commit");
    count
}

async fn tenant_config_rows(
    pool: &PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
    tenant: &str,
) -> i64 {
    let mut transaction = scoped(pool, deployment, customer).await;
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM config_revisions WHERE scope = 'tenant' AND scope_id = $1",
    )
    .bind(tenant)
    .fetch_one(&mut *transaction)
    .await
    .expect("the tenant config read must run");
    transaction
        .commit()
        .await
        .expect("the tenant config read must commit");
    count
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 015_runtime_operations.sql"]
async fn config_revisions_keep_the_three_level_scope_model() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let identity = seed_identity(&pool).await;

    let system_id = Uuid::new_v4();
    let tenant_a1_id = Uuid::new_v4();
    let tenant_a2_id = Uuid::new_v4();
    for (id, scope, scope_id) in [
        (system_id, "system", "system"),
        (tenant_a1_id, "tenant", identity.customer_a1.0.as_str()),
        (tenant_a2_id, "tenant", identity.customer_a2.0.as_str()),
    ] {
        sqlx::query(
            "INSERT INTO config_revisions (id, scope, scope_id, config, published_by) \
             VALUES ($1, $2, $3, '{}', $4)",
        )
        .bind(id)
        .bind(scope)
        .bind(scope_id)
        .bind(identity.suffix.as_str())
        .execute(&pool)
        .await
        .expect("the config revision fixture must be created");
    }

    let deployment_a = identity.deployment_a.0.as_str();
    let customer_a1 = identity.customer_a1.0.as_str();
    let customer_a2 = identity.customer_a2.0.as_str();
    let published_by = identity.suffix.as_str();

    // A system row needs the deployment scope: with the customer scope alone
    // it must not surface.
    assert_eq!(
        system_config_rows(&pool, Some(deployment_a), None, published_by).await,
        1,
        "a deployment scope must observe the system row"
    );
    assert_eq!(
        system_config_rows(&pool, None, Some(customer_a1), published_by).await,
        0,
        "a customer scope alone must not observe the system row"
    );
    assert_eq!(
        system_config_rows(&pool, Some(deployment_a), Some(customer_a1), published_by).await,
        1,
        "both scopes must observe the system row"
    );
    assert_eq!(
        system_config_rows(&pool, None, None, published_by).await,
        0,
        "no request-scoped context must expose no rows"
    );

    // A tenant row belongs to exactly one customer.
    assert_eq!(
        tenant_config_rows(&pool, Some(deployment_a), Some(customer_a1), customer_a1).await,
        1,
        "the owning tenant must observe its row"
    );
    assert_eq!(
        tenant_config_rows(&pool, Some(deployment_a), Some(customer_a2), customer_a1).await,
        0,
        "a neighbouring tenant must not observe the row"
    );
    assert_eq!(
        tenant_config_rows(&pool, Some(deployment_a), None, customer_a1).await,
        0,
        "a deployment scope alone must not observe a tenant row"
    );
    assert_eq!(
        tenant_config_rows(&pool, None, None, customer_a1).await,
        0,
        "no request-scoped context must expose no rows"
    );

    sqlx::query("DELETE FROM config_revisions WHERE id IN ($1, $2, $3) AND published_by = $4")
        .bind(system_id)
        .bind(tenant_a1_id)
        .bind(tenant_a2_id)
        .bind(identity.suffix.as_str())
        .execute(&pool)
        .await
        .expect("the config revision fixture must be removable");
    cleanup_identity(&pool, &identity).await;
}

// ---------------------------------------------------------------------------
// 4. nodes
// ---------------------------------------------------------------------------

async fn node_ids(pool: &PgPool, deployment: &str) -> Vec<String> {
    let mut transaction = begin_deploy_scoped(pool, Some(deployment)).await;
    let rows = sqlx::query_scalar::<_, String>(NODES_SQL)
        .bind(deployment)
        .fetch_all(&mut *transaction)
        .await
        .expect("the node projection must run");
    transaction
        .commit()
        .await
        .expect("the node read must commit");
    rows
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 015_runtime_operations.sql"]
async fn nodes_are_filtered_and_ordered_by_the_deployment_query() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let identity = seed_identity(&pool).await;

    let mut node_ids_a = Vec::new();
    for (node_id, node_type) in [
        ("local-ops-control-1", "control"),
        ("local-ops-mail-1", "mail"),
        ("local-ops-scanner-1", "scanner"),
    ] {
        node_ids_a.push(node_id.to_string());
        sqlx::query(
            "INSERT INTO nodes (id, deployment_id, node_type, role, status, version) \
             VALUES ($1, $2, $3, $4, 'active', '0.1.0')",
        )
        .bind(node_id)
        .bind(identity.deployment_a.0.as_str())
        .bind(node_type)
        .bind(node_type)
        .execute(&pool)
        .await
        .expect("the node fixture must be created");
    }
    sqlx::query(
        "INSERT INTO nodes (id, deployment_id, node_type, role, status, version) \
         VALUES ($1, $2, 'mail', 'mx', 'draining', '0.1.0')",
    )
    .bind("local-ops-mail-2")
    .bind(identity.deployment_b.0.as_str())
    .execute(&pool)
    .await
    .expect("the node fixture must be created");

    // `ORDER BY node_type, id` is the ordering the snapshot promises.
    let observed_a = node_ids(&pool, identity.deployment_a.0.as_str()).await;
    assert_eq!(
        observed_a, node_ids_a,
        "the projection must return only this deployment's nodes in node_type, id order"
    );
    assert!(
        !observed_a.iter().any(|id| id == "local-ops-mail-2"),
        "another deployment's node must never appear"
    );

    let observed_b = node_ids(&pool, identity.deployment_b.0.as_str()).await;
    assert_eq!(
        observed_b,
        vec!["local-ops-mail-2".to_string()],
        "the neighbouring deployment must see exactly its own node"
    );
    assert!(
        !observed_b
            .iter()
            .any(|id| id.starts_with("local-ops-") && id != "local-ops-mail-2"),
        "the neighbouring deployment must not observe deployment A's nodes"
    );

    assert!(
        node_ids(&pool, "LOCAL-OPS-DOES-NOT-EXIST").await.is_empty(),
        "an unregistered deployment must project no nodes"
    );

    for node_id in [
        "local-ops-control-1",
        "local-ops-mail-1",
        "local-ops-scanner-1",
        "local-ops-mail-2",
    ] {
        sqlx::query("DELETE FROM nodes WHERE id = $1")
            .bind(node_id)
            .execute(&pool)
            .await
            .expect("the node fixture must be removable");
    }
    cleanup_identity(&pool, &identity).await;
}

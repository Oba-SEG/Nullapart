//! Database-level RLS and append-only audit coverage against the migrated
//! local PostgreSQL instance.
//!
//! These tests live in mail-core because that crate already owns the
//! PostgreSQL test harness (`NULLAPART_TEST_DATABASE_URL`) and the local
//! migration set. They replace four `todo!()` placeholders in
//! `nullapart-policy` that failed whenever the ignored suite was run, so the
//! suite now proves the policy instead of panicking on it.
//!
//! Migration 002 states the invariant under test: "Normal request roles must
//! not own these tables and must not have BYPASSRLS." Every tenant statement
//! therefore runs after `SET LOCAL ROLE` to a non-owner, non-superuser request
//! role, because the harness connects as the table owner (a superuser in the
//! local image) and superusers bypass row security entirely — asserting
//! isolation from that session would prove nothing.

use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgPool, Transaction};
use uuid::Uuid;

/// The non-owner, non-superuser role every tenant statement assumes.
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

/// Serializes role and grant creation across the tests in this binary: the
/// grants rewrite shared catalogs, and concurrent attempts race on them.
static ROLE_SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Creates the request role once per test. It has no login, does not own any
/// table and carries no BYPASSRLS attribute, so row security applies to it.
async fn ensure_request_role(pool: &PgPool) {
    let _setup = ROLE_SETUP_LOCK.lock().await;
    let mut transaction = pool
        .begin()
        .await
        .expect("role setup must begin a transaction");
    sqlx::query(
        "DO $$ BEGIN \
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_local_request') THEN \
             EXECUTE 'CREATE ROLE nullapart_local_request NOLOGIN'; \
           END IF; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;",
    )
    .execute(&mut *transaction)
    .await
    .expect("the request role must exist");
    for grant in [
        "GRANT USAGE ON SCHEMA public TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nullapart_local_request",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nullapart_local_request",
    ] {
        sqlx::query(grant)
            .execute(&mut *transaction)
            .await
            .expect("the request role must hold the ordinary DML grants");
    }
    transaction.commit().await.expect("role setup must commit");
}

/// Begins a transaction acting as the request role, optionally with the
/// request-scoped tenant context the reviewed policies read.
async fn begin_as_request<'a>(
    pool: &'a PgPool,
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
    if let Some(customer) = customer {
        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(customer)
            .execute(&mut *transaction)
            .await
            .expect("request-scoped tenant context must be established");
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

/// Two deployments with one customer each, so every assertion can distinguish
/// tenant scope from deployment scope.
struct Fixture {
    deployment_a: DeploymentId,
    deployment_b: DeploymentId,
    customer_a: CustomerId,
    customer_b: CustomerId,
}

async fn seed_deployments(pool: &PgPool) -> Fixture {
    let suffix = Uuid::new_v4().simple().to_string();
    let deployment_a = DeploymentId::new(&format!("LOCAL-RLS-A-{suffix}"));
    let deployment_b = DeploymentId::new(&format!("LOCAL-RLS-B-{suffix}"));
    let customer_a = CustomerId::new(&format!("local-rls-a-{suffix}"));
    let customer_b = CustomerId::new(&format!("local-rls-b-{suffix}"));

    for (id, name) in [
        (&deployment_a, "RLS deployment A"),
        (&deployment_b, "RLS deployment B"),
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
    for (id, deployment, name) in [
        (&customer_a, &deployment_a, "RLS customer A"),
        (&customer_b, &deployment_b, "RLS customer B"),
    ] {
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id.0)
        .bind(&deployment.0)
        .bind(name)
        .execute(pool)
        .await
        .expect("the customer fixture must be created");
    }

    Fixture {
        deployment_a,
        deployment_b,
        customer_a,
        customer_b,
    }
}

/// Deletes everything the fixture created. Audit rows need the append-only
/// trigger disabled for the delete, which is transactional DDL, so the
/// trigger is re-enabled in the same transaction that removes the row.
async fn cleanup(pool: &PgPool, fixture: &Fixture) {
    let mut transaction = begin_as_owner(pool, &fixture.customer_a.0).await;
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update")
        .execute(&mut *transaction)
        .await
        .expect("the append-only trigger must be disableable by the table owner");
    sqlx::query(
        "DELETE FROM audit_events WHERE deployment_id = $1 AND actor_id LIKE 'local-rls-%'",
    )
    .bind(&fixture.deployment_a.0)
    .execute(&mut *transaction)
    .await
    .expect("the audit fixture must be removable with the trigger disabled");
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update")
        .execute(&mut *transaction)
        .await
        .expect("the append-only trigger must be restored");
    sqlx::query("DELETE FROM feature_overrides WHERE scope_id IN ($1, $2)")
        .bind(&fixture.customer_a.0)
        .bind(&fixture.customer_b.0)
        .execute(&mut *transaction)
        .await
        .expect("the feature override fixture must be removable");
    sqlx::query("DELETE FROM outbox_events WHERE customer_id IN ($1, $2)")
        .bind(&fixture.customer_a.0)
        .bind(&fixture.customer_b.0)
        .execute(&mut *transaction)
        .await
        .expect("the outbox fixture must be removable");
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
        .expect("the identity cleanup must commit");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 006_quarantine_reinjection_dead_letters.sql"]
async fn rls_deployment_isolation_cross_tenant_query_blocked() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed_deployments(&pool).await;
    let event_id = Uuid::new_v4();

    let mut writer = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    sqlx::query(
        "INSERT INTO outbox_events (id, event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ($1, 'rls.isolation', $2, $3, $4, 'local-rls-trace')",
    )
    .bind(event_id)
    .bind(serde_json::json!({"fixture": "rls-isolation"}))
    .bind(&fixture.customer_a.0)
    .bind(&fixture.deployment_a.0)
    .execute(&mut *writer)
    .await
    .expect("the owning tenant must be able to write its own row");
    writer.commit().await.expect("the seed must commit");

    let mut reader = begin_as_request(&pool, Some(&fixture.customer_b.0)).await;
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox_events WHERE id = $1 AND deployment_id = $2",
    )
    .bind(event_id)
    .bind(&fixture.deployment_a.0)
    .fetch_one(&mut *reader)
    .await
    .expect("the read must run");
    assert_eq!(
        visible, 0,
        "a customer in another deployment must not observe the row"
    );

    let updated = sqlx::query("UPDATE outbox_events SET event_type = 'tampered' WHERE id = $1")
        .bind(event_id)
        .execute(&mut *reader)
        .await
        .expect("the update must run");
    assert_eq!(
        updated.rows_affected(),
        0,
        "a cross-tenant update must affect no rows"
    );

    let foreign_insert = sqlx::query(
        "INSERT INTO outbox_events (id, event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ($1, 'rls.isolation', $2, $3, $4, 'local-rls-trace')",
    )
    .bind(Uuid::new_v4())
    .bind(serde_json::json!({"fixture": "rls-isolation"}))
    .bind(&fixture.customer_a.0)
    .bind(&fixture.deployment_a.0)
    .execute(&mut *reader)
    .await;
    assert!(
        foreign_insert.is_err(),
        "WITH CHECK must reject writing another tenant's scope"
    );
    drop(reader);

    let mut check = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let unchanged: String =
        sqlx::query_scalar("SELECT event_type FROM outbox_events WHERE id = $1")
            .bind(event_id)
            .fetch_one(&mut *check)
            .await
            .expect("the owning tenant must still read its row");
    assert_eq!(
        unchanged, "rls.isolation",
        "the cross-tenant update must not have changed anything"
    );
    check.commit().await.expect("the verification must commit");

    // Request context is mandatory: without it the reviewed policies have no
    // value to compare against and the query fails closed.
    let mut bare = begin_as_request(&pool, None).await;
    let role_now: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&mut *bare)
        .await
        .expect("current_user must be readable");
    assert_eq!(
        role_now, REQUEST_ROLE,
        "the unscoped probe must still run as the request role"
    );
    // Without request context the policies either refuse to evaluate or
    // compare against an empty context and match nothing; either way no row
    // may surface.
    let unscoped = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_events WHERE id = $1")
        .bind(event_id)
        .fetch_one(&mut *bare)
        .await;
    if let Ok(count) = unscoped {
        assert_eq!(
            count, 0,
            "a query without request-scoped tenant context must expose no rows"
        );
    }
    drop(bare);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 006_quarantine_reinjection_dead_letters.sql"]
async fn rls_audit_events_cannot_be_modified_by_tenant() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed_deployments(&pool).await;
    let audit_id = Uuid::new_v4();

    let mut writer = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    sqlx::query(
        "INSERT INTO audit_events (id, deployment_id, customer_id, actor_id, actor_login, \
                actor_roles, action, resource_type, result, trace_id) \
         VALUES ($1, $2, $3, 'local-rls-actor', 'rls@example.test', ARRAY['customer_admin'], \
                'quarantine.view', 'quarantine_case', 'success', 'local-rls-trace')",
    )
    .bind(audit_id)
    .bind(&fixture.deployment_a.0)
    .bind(&fixture.customer_a.0)
    .execute(&mut *writer)
    .await
    .expect("append must be allowed for the owning tenant");
    writer.commit().await.expect("the seed must commit");

    let mut editor = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let updated = sqlx::query(
        "UPDATE audit_events SET action = 'quarantine.tamper', result = 'denied' WHERE id = $1",
    )
    .bind(audit_id)
    .execute(&mut *editor)
    .await;
    assert!(
        updated.is_err(),
        "the append-only trigger must reject an audit rewrite"
    );
    drop(editor);

    let mut editor = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let deleted = sqlx::query("DELETE FROM audit_events WHERE id = $1")
        .bind(audit_id)
        .execute(&mut *editor)
        .await;
    assert!(
        deleted.is_err(),
        "the append-only trigger must reject audit deletion"
    );
    drop(editor);

    let mut reader = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let action: String = sqlx::query_scalar("SELECT action FROM audit_events WHERE id = $1")
        .bind(audit_id)
        .fetch_one(&mut *reader)
        .await
        .expect("the untouched row must still be readable by its tenant");
    assert_eq!(
        action, "quarantine.view",
        "audit evidence must be unchanged"
    );
    reader.commit().await.expect("the verification must commit");

    let mut other = begin_as_request(&pool, Some(&fixture.customer_b.0)).await;
    let foreign_insert = sqlx::query(
        "INSERT INTO audit_events (id, deployment_id, customer_id, actor_id, actor_login, \
                actor_roles, action, resource_type, result, trace_id) \
         VALUES ($1, $2, $3, 'local-rls-actor', 'rls@example.test', ARRAY['customer_admin'], \
                'quarantine.view', 'quarantine_case', 'success', 'local-rls-trace')",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.deployment_a.0)
    .bind(&fixture.customer_a.0)
    .execute(&mut *other)
    .await;
    assert!(
        foreign_insert.is_err(),
        "a tenant must not append audit evidence for another tenant"
    );
    drop(other);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 006_quarantine_reinjection_dead_letters.sql"]
async fn rls_outbox_events_scoped_to_deployment() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed_deployments(&pool).await;
    let event_id = Uuid::new_v4();

    let mut writer = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    sqlx::query(
        "INSERT INTO outbox_events (id, event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ($1, 'rls.outbox', $2, $3, $4, 'local-rls-trace')",
    )
    .bind(event_id)
    .bind(serde_json::json!({"fixture": "rls-outbox"}))
    .bind(&fixture.customer_a.0)
    .bind(&fixture.deployment_a.0)
    .execute(&mut *writer)
    .await
    .expect("the owning tenant must be able to publish its event");
    writer.commit().await.expect("the seed must commit");

    let mut reader = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let owned: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE id = $1")
        .bind(event_id)
        .fetch_one(&mut *reader)
        .await
        .expect("the owning tenant must read its event");
    assert_eq!(owned, 1, "the owning tenant must see exactly its row");
    reader.commit().await.expect("the read must commit");

    let mut foreign = begin_as_request(&pool, Some(&fixture.customer_b.0)).await;
    let observed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE deployment_id = $1")
            .bind(&fixture.deployment_a.0)
            .fetch_one(&mut *foreign)
            .await
            .expect("the cross-deployment read must run");
    assert_eq!(
        observed, 0,
        "another deployment's tenant must not observe deployment A's events"
    );

    let platform_scoped = sqlx::query(
        "INSERT INTO outbox_events (id, event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ($1, 'rls.outbox', $2, NULL, $3, 'local-rls-trace')",
    )
    .bind(Uuid::new_v4())
    .bind(serde_json::json!({"fixture": "rls-outbox"}))
    .bind(&fixture.deployment_b.0)
    .execute(&mut *foreign)
    .await;
    assert!(
        platform_scoped.is_err(),
        "a tenant session must not mint platform-scoped (customer-less) events"
    );
    drop(foreign);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 006_quarantine_reinjection_dead_letters.sql"]
async fn rls_feature_overrides_cannot_self_escalate() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed_deployments(&pool).await;
    let feature_id = format!("local-rls-feature-{}", Uuid::new_v4().simple());
    let override_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO feature_definitions (feature_id, display_name, description, default_value) \
         VALUES ($1, 'Local RLS fixture feature', \
                 'Seeded by the local RLS isolation test', 'disabled') \
         ON CONFLICT (feature_id) DO NOTHING",
    )
    .bind(&feature_id)
    .execute(&pool)
    .await
    .expect("the feature fixture must exist before overrides reference it");

    let mut writer = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    sqlx::query(
        "INSERT INTO feature_overrides (id, feature_id, scope, scope_id, value, owner, reason, revision) \
         VALUES ($1, $2, 'tenant', $3, 'enabled', $3, 'local RLS fixture', 1)",
    )
    .bind(override_id)
    .bind(&feature_id)
    .bind(&fixture.customer_a.0)
    .execute(&mut *writer)
    .await
    .expect("a tenant must be able to write its own tenant-scoped override");
    writer
        .commit()
        .await
        .expect("the owned override must commit");

    let mut attacker = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let system_escalation = sqlx::query(
        "INSERT INTO feature_overrides (id, feature_id, scope, scope_id, value, owner, reason, revision) \
         VALUES ($1, $2, 'system', 'system', 'enabled', $3, 'escalate', 1)",
    )
    .bind(Uuid::new_v4())
    .bind(&feature_id)
    .bind(&fixture.customer_a.0)
    .execute(&mut *attacker)
    .await;
    assert!(
        system_escalation.is_err(),
        "a tenant session must not create a system-scoped override"
    );
    drop(attacker);

    let mut attacker = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let neighbour_escalation = sqlx::query(
        "INSERT INTO feature_overrides (id, feature_id, scope, scope_id, value, owner, reason, revision) \
         VALUES ($1, $2, 'tenant', $3, 'enabled', $4, 'escalate', 1)",
    )
    .bind(Uuid::new_v4())
    .bind(&feature_id)
    .bind(&fixture.customer_b.0)
    .bind(&fixture.customer_a.0)
    .execute(&mut *attacker)
    .await;
    assert!(
        neighbour_escalation.is_err(),
        "a tenant session must not write another tenant's override"
    );
    drop(attacker);

    let mut escalator = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let scope_change = sqlx::query(
        "UPDATE feature_overrides SET scope = 'system', scope_id = 'system' WHERE id = $1",
    )
    .bind(override_id)
    .execute(&mut *escalator)
    .await;
    assert!(
        scope_change.is_err(),
        "an existing tenant override must not be re-scoped to system"
    );
    drop(escalator);

    let mut reader = begin_as_request(&pool, Some(&fixture.customer_a.0)).await;
    let scope: String = sqlx::query_scalar("SELECT scope FROM feature_overrides WHERE id = $1")
        .bind(override_id)
        .fetch_one(&mut *reader)
        .await
        .expect("the owning tenant must still read its override");
    assert_eq!(
        scope, "tenant",
        "the escalation attempt must leave the override tenant-scoped"
    );
    reader.commit().await.expect("the verification must commit");

    let mut neighbour = begin_as_request(&pool, Some(&fixture.customer_b.0)).await;
    let observed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM feature_overrides WHERE feature_id = $1 AND scope_id = $2",
    )
    .bind(&feature_id)
    .bind(&fixture.customer_a.0)
    .fetch_one(&mut *neighbour)
    .await
    .expect("the neighbouring tenant's read must run");
    assert_eq!(
        observed, 0,
        "another tenant must not observe the override at all"
    );
    neighbour.commit().await.expect("the read must commit");

    cleanup(&pool, &fixture).await;
    sqlx::query("DELETE FROM feature_definitions WHERE feature_id = $1")
        .bind(&feature_id)
        .execute(&pool)
        .await
        .expect("the feature fixture must be removable");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 006_quarantine_reinjection_dead_letters.sql"]
async fn pooled_connection_guc_context_does_not_leak_across_transactions() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed_deployments(&pool).await;
    let event_id = Uuid::new_v4();

    let mut connection = pool
        .acquire()
        .await
        .expect("a single pooled connection must serve both transactions");

    let mut first = connection
        .begin()
        .await
        .expect("the first transaction must begin on the pooled connection");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *first)
        .await
        .expect("the session must assume the request role");
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(&fixture.deployment_a.0)
    .bind(&fixture.customer_a.0)
    .execute(&mut *first)
    .await
    .expect("request-scoped tenant context must be established");
    sqlx::query(
        "INSERT INTO outbox_events (id, event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ($1, 'rls.guc_context', $2, $3, $4, 'local-rls-trace')",
    )
    .bind(event_id)
    .bind(serde_json::json!({"fixture": "rls-guc-context"}))
    .bind(&fixture.customer_a.0)
    .bind(&fixture.deployment_a.0)
    .execute(&mut *first)
    .await
    .expect("the owning tenant must be able to write its own row");
    let owned: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE id = $1")
        .bind(event_id)
        .fetch_one(&mut *first)
        .await
        .expect("the seeded row must be visible while its context is set");
    assert_eq!(owned, 1, "the first transaction must see exactly its row");
    first
        .commit()
        .await
        .expect("the seeded row and its request-scoped context must commit");

    let mut second = connection
        .begin()
        .await
        .expect("the second transaction must reuse the pooled connection");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *second)
        .await
        .expect("the session must assume the request role");
    let unscoped =
        match sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_events WHERE id = $1")
            .bind(event_id)
            .fetch_one(&mut *second)
            .await
        {
            Ok(0) => "the context-free read observed 0 rows".to_string(),
            Ok(observed) => panic!(
                "a pooled connection leaked request-scoped GUC context across transactions: \
             the second transaction set no GUCs yet observed {observed} row(s)"
            ),
            Err(error) => {
                format!("the context-free read failed closed under the strict GUC policy: {error}")
            },
        };
    second
        .rollback()
        .await
        .expect("the context-free probe must roll back");

    let mut third = connection
        .begin()
        .await
        .expect("the third transaction must reuse the pooled connection");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *third)
        .await
        .expect("the session must assume the request role");
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(&fixture.customer_b.0)
        .execute(&mut *third)
        .await
        .expect("the second tenant's request-scoped context must be established");
    let foreign = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_events WHERE id = $1")
        .bind(event_id)
        .fetch_one(&mut *third)
        .await
        .map_err(|error| error.to_string());
    assert!(
        matches!(foreign, Err(_) | Ok(0)),
        "another tenant must never observe the first tenant's row on the same pooled \
         connection ({unscoped}); observed {foreign:?}"
    );
    third
        .rollback()
        .await
        .expect("the scoped probe must roll back");

    drop(connection);
    cleanup(&pool, &fixture).await;
}

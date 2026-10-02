//! Local PostgreSQL coverage for the Phase 3 Admin Audit API.
//!
//! Two layers are proven against the migrated local instance:
//!
//! 1. **RLS read/write scopes** (migration `009_admin_audit_scope.sql`) under
//!    the non-owner request role: an unscoped session fails closed, the tenant
//!    scope reads only its own customer, the platform scope reads every row,
//!    the own scope reads only the actor's rows, and write authority stays
//!    narrow in every scope.
//! 2. **Application store scoping** (`PostgresAuditStore`): server-authorized
//!    scopes drive both the SQL predicates and the self-audited access rows,
//!    a cross-tenant detail probe is denied *and* audited, exports write an
//!    audit row, and reads stay bounded to the deployment.
//!
//! Fixtures use a unique deployment id per run and are intentionally left in
//! the local database: `audit_events` is append-only through an owner-only
//! trigger, and removing the rows would require disabling that trigger while
//! other test binaries may be asserting it blocks writes.

use chrono::Utc;
use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId},
    ActorId,
};
use nullapart_mail_core::admin_audit::{
    AuditCheckpointState, AuditQueryFilters, AuditStore, AuthorizedAuditAccess, PostgresAuditStore,
    AUDIT_VIEW_PERMISSION,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId, TenantContext,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Transaction};
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

/// Creates the request role once per binary; the statement is guarded so a
/// concurrent binary racing the same creation still converges, and the whole
/// setup retries on catalog races (`tuple concurrently updated`).
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

/// Begins a transaction as the request role with the given audit GUCs set
/// transaction-locally. `None` leaves a setting unscoped (fail closed).
async fn begin_scoped<'a>(
    pool: &'a PgPool,
    customer: Option<&str>,
    actor: Option<&str>,
    scope: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool
        .begin()
        .await
        .expect("a transaction must begin for the scoped statement");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("the session must assume the request role");
    for (name, value) in [
        ("app.current_customer_id", customer),
        ("app.current_actor_id", actor),
        ("app.audit_scope", scope),
    ] {
        if let Some(value) = value {
            sqlx::query("SELECT set_config($1, $2, true)")
                .bind(name)
                .bind(value)
                .execute(&mut *transaction)
                .await
                .expect("the request-scoped audit setting must be established");
        }
    }
    transaction
}

/// Unique fixture: one deployment, two customers and three audit rows.
struct Fixture {
    deployment: DeploymentId,
    customer_a: CustomerId,
    customer_b: CustomerId,
    actor_a: String,
    actor_b: String,
    row_a: Uuid,
    row_b: Uuid,
    row_platform: Uuid,
    suffix: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = format!("local-audit-{}", Uuid::new_v4().simple());
    let deployment = DeploymentId::new(&suffix.to_uppercase());
    let customer_a = CustomerId::new(&format!("{suffix}-a"));
    let customer_b = CustomerId::new(&format!("{suffix}-b"));
    let actor_a = format!("{suffix}-actor-a");
    let actor_b = format!("{suffix}-actor-b");

    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&deployment.0)
    .bind(&suffix)
    .execute(pool)
    .await
    .expect("the deployment fixture must be created");
    for (id, name) in [(&customer_a, "customer a"), (&customer_b, "customer b")] {
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

    let row_a = Uuid::new_v4();
    let row_b = Uuid::new_v4();
    let row_platform = Uuid::new_v4();
    let rows = [
        (row_a, Some(&customer_a), &actor_a),
        (row_b, Some(&customer_b), &actor_b),
        (row_platform, None, &actor_a),
    ];
    for (id, customer, actor) in rows {
        sqlx::query(
            "INSERT INTO audit_events (id, deployment_id, customer_id, actor_id, actor_login, \
                    actor_roles, action, resource_type, result, trace_id) \
             VALUES ($1, $2, $3, $4, $5, ARRAY['customer_admin'], 'seed.view', \
                    'quarantine_case', 'success', $6)",
        )
        .bind(id)
        .bind(&deployment.0)
        .bind(customer.map(|value| value.0.as_str()))
        .bind(actor)
        .bind(format!("{actor}@example.test"))
        .bind(&suffix)
        .execute(pool)
        .await
        .expect("the audit fixture row must be appended");
    }

    Fixture {
        deployment,
        customer_a,
        customer_b,
        actor_a,
        actor_b,
        row_a,
        row_b,
        row_platform,
        suffix,
    }
}

/// Reads the fixture deployment's audit rows as the request role under the
/// given GUCs, returning the visible row count.
async fn count_visible(
    pool: &PgPool,
    fixture: &Fixture,
    customer: Option<&str>,
    actor: Option<&str>,
    scope: Option<&str>,
) -> i64 {
    let mut transaction = begin_scoped(pool, customer, actor, scope).await;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE deployment_id = $1 \
         AND (action = 'seed.view' OR action LIKE 'probe.%')",
    )
    .bind(&fixture.deployment.0)
    .fetch_one(&mut *transaction)
    .await
    .expect("the scoped read must be executable");
    transaction.commit().await.expect("the read must commit");
    count
}

/// Attempts an append under the given session scope for the given row customer.
async fn try_append(
    pool: &PgPool,
    deployment: &DeploymentId,
    session_customer: Option<&str>,
    session_scope: Option<&str>,
    row_customer: Option<&str>,
    actor_id: &str,
    trace: &str,
) -> Result<u64, sqlx::Error> {
    let mut transaction = begin_scoped(pool, session_customer, None, session_scope).await;
    let outcome = sqlx::query(
        "INSERT INTO audit_events (deployment_id, customer_id, actor_id, actor_login, \
                actor_roles, action, resource_type, result, trace_id) \
         VALUES ($1, $2, $3, 'probe@example.test', ARRAY['customer_admin'], \
                'probe.append', 'quarantine_case', 'success', $4)",
    )
    .bind(&deployment.0)
    .bind(row_customer)
    .bind(actor_id)
    .bind(trace)
    .execute(&mut *transaction)
    .await;
    let _ = transaction.rollback().await;
    outcome.map(|result| result.rows_affected())
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 009_admin_audit_scope.sql"]
async fn rls_unscoped_session_fails_closed_and_tenant_scope_reads_only_its_rows() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let unscoped = count_visible(&pool, &fixture, None, None, None).await;
    assert_eq!(
        unscoped, 0,
        "a session without audit scope settings must read no rows"
    );

    let tenant_rows = count_visible(&pool, &fixture, Some(&fixture.customer_a.0), None, None).await;
    assert_eq!(
        tenant_rows, 1,
        "the tenant scope must read exactly its own customer's rows"
    );

    let other_tenant =
        count_visible(&pool, &fixture, Some(&fixture.customer_b.0), None, None).await;
    assert_eq!(
        other_tenant, 1,
        "the other tenant sees exactly its own row, never customer A's"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 009_admin_audit_scope.sql"]
async fn rls_platform_and_own_scopes_read_only_their_authorized_rows() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let platform_rows = count_visible(&pool, &fixture, None, None, Some("platform")).await;
    assert_eq!(
        platform_rows, 3,
        "the platform scope must read every row including platform rows"
    );

    let own_rows = count_visible(&pool, &fixture, None, Some(&fixture.actor_a), Some("own")).await;
    assert_eq!(
        own_rows, 2,
        "the own scope must read only the actor's rows (both customers)"
    );

    let other_actor =
        count_visible(&pool, &fixture, None, Some(&fixture.actor_b), Some("own")).await;
    assert_eq!(
        other_actor, 1,
        "the own scope must not expose another actor's rows"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 009_admin_audit_scope.sql"]
async fn rls_write_authority_stays_narrow_in_every_scope() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let trace = fixture.suffix.clone();

    // A tenant session appends audit evidence for its own customer.
    let own_append = try_append(
        &pool,
        &fixture.deployment,
        Some(&fixture.customer_a.0),
        None,
        Some(&fixture.customer_a.0),
        &fixture.actor_a,
        &trace,
    )
    .await;
    assert!(
        own_append.is_ok(),
        "a tenant must append audit evidence for its own customer: {own_append:?}"
    );

    // The same tenant session cannot append platform-scoped (customer-less) rows.
    let platform_append = try_append(
        &pool,
        &fixture.deployment,
        Some(&fixture.customer_a.0),
        None,
        None,
        &fixture.actor_a,
        &trace,
    )
    .await;
    assert!(
        platform_append.is_err(),
        "a tenant scope must not append platform-scoped audit rows"
    );

    // The platform scope appends platform rows but not another tenant's rows.
    let platform_row = try_append(
        &pool,
        &fixture.deployment,
        None,
        Some("platform"),
        None,
        "platform-probe",
        &trace,
    )
    .await;
    assert!(
        platform_row.is_ok(),
        "the platform scope must append platform-scoped rows: {platform_row:?}"
    );

    let foreign_append = try_append(
        &pool,
        &fixture.deployment,
        None,
        Some("platform"),
        Some(&fixture.customer_b.0),
        "platform-probe",
        &trace,
    )
    .await;
    assert!(
        foreign_append.is_err(),
        "a read scope must not fabricate another tenant's audit history"
    );
}

fn context(
    deployment: &DeploymentId,
    customer: &CustomerId,
    roles: &[&str],
    permissions: &[&str],
) -> TenantContext {
    TenantContext {
        deployment_id: deployment.clone(),
        region: RegionId::new("local"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "audit-test@example.test".to_string(),
            roles: roles.iter().map(|role| role.to_string()).collect(),
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: customer.clone(),
        customer_internal_key: 1,
        customer_display_name: "Audit API test customer".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: permissions.iter().map(|value| value.to_string()).collect(),
        config_revision: 1,
        trace_id: "postgres-admin-audit-trace".to_string(),
        correlation_id: "postgres-admin-audit-correlation".to_string(),
        session_id: "postgres-admin-audit-session".to_string(),
        authenticated_at: Utc::now(),
    }
}

fn access_for(context: &TenantContext, requested_customer: Option<&str>) -> AuthorizedAuditAccess {
    AuthorizedAuditAccess::from_context(
        context,
        &context.deployment_id.clone(),
        requested_customer,
        None,
    )
    .expect("the audit access must authorize")
}

async fn action_count(pool: &PgPool, deployment: &DeploymentId, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE deployment_id = $1 AND action = $2")
        .bind(&deployment.0)
        .bind(action)
        .fetch_one(pool)
        .await
        .expect("the audit assertion must be executable")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 009_admin_audit_scope.sql"]
async fn store_scopes_reads_and_audits_every_read() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let store = PostgresAuditStore::new(pool.clone());
    let filters = || AuditQueryFilters::default().validate().unwrap();

    // Customer Admin read: only its own customer's row is returned, and the
    // read itself is audited against the same customer.
    let customer_context = context(
        &fixture.deployment,
        &fixture.customer_a,
        &["customer_admin"],
        &[AUDIT_VIEW_PERMISSION],
    );
    let customer_access = access_for(&customer_context, None);
    let page = store
        .list(&customer_access, &filters())
        .await
        .expect("the tenant-scoped list must succeed");
    let ids: Vec<Uuid> = page.events.iter().map(|event| event.id).collect();
    assert!(
        ids.contains(&fixture.row_a),
        "the tenant scope must return its own row"
    );
    assert!(
        !ids.contains(&fixture.row_b),
        "the tenant scope must not return another customer's row"
    );
    assert!(
        !ids.contains(&fixture.row_platform),
        "the tenant scope must not return platform rows"
    );
    assert_eq!(
        action_count(&pool, &fixture.deployment, "audit_access_list").await,
        1,
        "the read must write exactly one access audit row"
    );

    // Cross-tenant detail probe: denied and recorded as denied access.
    let denied = store
        .detail(&customer_access, fixture.row_b)
        .await
        .expect("the detail read must complete");
    assert!(
        denied.is_none(),
        "a cross-tenant detail probe must not resolve another customer's row"
    );
    let probes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE deployment_id = $1 \
         AND action = 'audit_access_denied' AND resource_id = $2 AND result = 'denied'",
    )
    .bind(&fixture.deployment.0)
    .bind(fixture.row_b.to_string())
    .fetch_one(&pool)
    .await
    .expect("the denied probe must be auditable");
    assert_eq!(
        probes, 1,
        "a denied cross-tenant probe must be recorded once as denied"
    );

    // Platform read: every row in the deployment, including platform rows.
    let system_context = context(
        &fixture.deployment,
        &fixture.customer_a,
        &["system_admin"],
        &[AUDIT_VIEW_PERMISSION],
    );
    let platform_access = access_for(&system_context, None);
    let platform_page = store
        .list(&platform_access, &filters())
        .await
        .expect("the platform-scoped list must succeed");
    let platform_ids: Vec<Uuid> = platform_page.events.iter().map(|event| event.id).collect();
    for row in [fixture.row_a, fixture.row_b, fixture.row_platform] {
        assert!(
            platform_ids.contains(&row),
            "the platform scope must return every row in the deployment"
        );
    }

    // Export is audited as a high-risk action.
    store
        .export(&platform_access, &filters())
        .await
        .expect("the export must succeed");
    assert_eq!(
        action_count(&pool, &fixture.deployment, "audit_export").await,
        1,
        "an export must write one audit row"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 016_audit_checkpoints.sql"]
async fn checkpoint_status_reads_deployment_checkpoint_metadata() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let store = PostgresAuditStore::new(pool.clone());
    let system_context = context(
        &fixture.deployment,
        &fixture.customer_a,
        &["system_admin"],
        &[AUDIT_VIEW_PERMISSION],
    );
    let access = access_for(&system_context, None);
    let covers_events_through = Utc::now() - chrono::Duration::days(1);
    sqlx::query(
        "INSERT INTO audit_checkpoints (deployment_id, checkpoint_sequence, \
                covers_events_through, event_count, root_hash, signer_key_id, signature, archive_uri) \
         VALUES ($1, 7, $2, 3, $3, 'local-test-signer', 'local-test-signature', $4)",
    )
    .bind(&fixture.deployment.0)
    .bind(covers_events_through)
    .bind(format!("sha256:{}", "0".repeat(64)))
    .bind(format!(
        "s3://local-test/{}/audit-checkpoint-7.json",
        fixture.deployment.0
    ))
    .execute(&pool)
    .await
    .expect("the checkpoint fixture must be inserted");

    let status = store
        .checkpoint_status(&access)
        .await
        .expect("checkpoint status must be readable");
    assert_eq!(status.state, AuditCheckpointState::Stale);
    assert_eq!(status.checkpoint_sequence, Some(7));
    assert_eq!(status.event_count, Some(3));
    assert_eq!(status.signer_key_id.as_deref(), Some("local-test-signer"));
    assert_eq!(
        action_count(&pool, &fixture.deployment, "audit_access_detail").await,
        1,
        "reading checkpoint status must be audited"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 009_admin_audit_scope.sql"]
async fn store_reads_are_bounded_to_the_deployment() {
    let pool = connect().await;
    let suffix = format!("local-audit-other-{}", Uuid::new_v4().simple());
    let other_deployment = DeploymentId::new(&suffix.to_uppercase());
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&other_deployment.0)
    .bind(&suffix)
    .execute(&pool)
    .await
    .expect("the other deployment fixture must be created");
    let foreign_row = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_events (id, deployment_id, customer_id, actor_id, actor_login, \
                actor_roles, action, resource_type, result, trace_id) \
         VALUES ($1, $2, NULL, 'other-deployment-actor', 'other@example.test', \
                ARRAY['system_admin'], 'seed.view', 'admin_audit', 'success', $3)",
    )
    .bind(foreign_row)
    .bind(&other_deployment.0)
    .bind(&suffix)
    .execute(&pool)
    .await
    .expect("the other deployment audit row must be appended");

    let fixture = seed(&pool).await;
    let store = PostgresAuditStore::new(pool.clone());
    let system_context = context(
        &fixture.deployment,
        &fixture.customer_a,
        &["system_admin"],
        &[AUDIT_VIEW_PERMISSION],
    );
    let access = access_for(&system_context, None);
    let page = store
        .list(&access, &AuditQueryFilters::default().validate().unwrap())
        .await
        .expect("the platform-scoped list must succeed");
    assert!(
        !page.events.is_empty(),
        "the deployment fixture rows must be visible"
    );
    assert!(
        !page.events.iter().any(|event| event.id == foreign_row),
        "a row from another deployment must never appear in scope"
    );
}

//! Local PostgreSQL coverage for Phase 9 operations-hardening storage.
//!
//! Requires PostgreSQL migrated through `033_operations_automation_categories.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_operations_hardening -- --ignored --test-threads=1`.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Transaction};
use uuid::Uuid;

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

static ROLE_SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn ensure_request_role(pool: &PgPool) {
    let _setup = ROLE_SETUP_LOCK.lock().await;
    let mut transaction = pool
        .begin()
        .await
        .expect("role setup transaction must begin");
    sqlx::query(
        "DO $$ BEGIN \
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_local_request') THEN \
             EXECUTE 'CREATE ROLE nullapart_local_request NOLOGIN'; \
           END IF; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;",
    )
    .execute(&mut *transaction)
    .await
    .expect("request role must exist");
    for grant in [
        "GRANT USAGE ON SCHEMA public TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON operations_tier3_capabilities TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON operations_alert_rules TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON operations_readiness_checks TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON operations_automation_categories TO nullapart_local_request",
    ] {
        sqlx::query(grant)
            .execute(&mut *transaction)
            .await
            .expect("grant must apply");
    }
    transaction.commit().await.expect("role setup must commit");
}

async fn begin_request<'a>(
    pool: &'a PgPool,
    deployment: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("transaction must begin");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("request role must be assumed");
    if let Some(deployment) = deployment {
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(deployment)
            .execute(&mut *transaction)
            .await
            .expect("deployment scope must be established");
    }
    transaction
}

async fn expect_rejected(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    statement: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
) {
    sqlx::query("SAVEPOINT expect_rejected")
        .execute(&mut **transaction)
        .await
        .expect("savepoint must open");
    let outcome = statement.execute(&mut **transaction).await;
    sqlx::query("ROLLBACK TO SAVEPOINT expect_rejected")
        .execute(&mut **transaction)
        .await
        .expect("savepoint must roll back");
    assert!(outcome.is_err(), "statement must be rejected");
}

struct Fixture {
    deployment_a: String,
    deployment_b: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = Uuid::new_v4().simple().to_string();
    let fixture = Fixture {
        deployment_a: format!("phase9-hardening-a-{suffix}"),
        deployment_b: format!("phase9-hardening-b-{suffix}"),
    };
    for deployment in [&fixture.deployment_a, &fixture.deployment_b] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name, lifecycle) \
             VALUES ($1, 'local', $2, 'active')",
        )
        .bind(deployment)
        .bind(format!("Phase 9 {deployment}"))
        .execute(pool)
        .await
        .expect("deployment must insert");
    }
    insert_hardening_rows(pool, &fixture.deployment_a, "inbound_smtp_acceptance").await;
    insert_hardening_rows(pool, &fixture.deployment_b, "control_backend").await;
    fixture
}

async fn insert_hardening_rows(pool: &PgPool, deployment: &str, capability_id: &str) {
    sqlx::query(
        "INSERT INTO operations_tier3_capabilities (\
             deployment_id, capability_id, display_name, owner, sli, slo_target, error_budget, \
             measurement_source, rto_minutes, rpo_minutes, dependency_map, redundancy_design, \
             degraded_mode, capacity_threshold, runbook, readiness_state\
         ) VALUES (\
             $1,$2,'Phase 9 capability','test-owner','test sli','99.9%','0.1%',\
             'test source',60,5,'test dependencies','test redundancy','test degraded',\
             'test capacity','docs/runbooks/PHASE9-OPERATIONS-HARDENING.md','defined'\
         )",
    )
    .bind(deployment)
    .bind(capability_id)
    .execute(pool)
    .await
    .expect("capability must insert");
    sqlx::query(
        "INSERT INTO operations_alert_rules (\
             deployment_id, alert_key, capability_id, severity, burn_rate, long_window_minutes, \
             short_window_minutes, threshold_description, owner, runbook, suppression, escalation\
         ) VALUES ($1,$2,$3,'page',14.4,60,5,'test burn rule','test-owner',\
             'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md','test suppression','test escalation')",
    )
    .bind(deployment)
    .bind(format!("{capability_id}:fast-burn"))
    .bind(capability_id)
    .execute(pool)
    .await
    .expect("alert must insert");
    sqlx::query(
        "INSERT INTO operations_readiness_checks (\
             deployment_id, check_id, category, title, status, owner, evidence_ref, notes\
         ) VALUES ($1,$2,'reliability','Phase 9 readiness check','partial','test-owner',\
             'docs/compliance/08-TIER3-SLO-EVIDENCE.md','test notes')",
    )
    .bind(deployment)
    .bind(format!("{capability_id}:readiness"))
    .execute(pool)
    .await
    .expect("readiness check must insert");
    sqlx::query(
        "INSERT INTO operations_automation_categories (\
             deployment_id, category_id, display_name, destination, severity, owner, \
             minimized_metadata, deduplication_key, aggregation_window_minutes, delivery_mode, \
             blocks_mail_delivery, runbook, readiness_state\
         ) VALUES ($1,$2,'Phase 9 automation','clickup','ticket','test-owner',\
             'deployment and bounded evidence ids only','deployment:capability:rolling_1h',60,\
             'outbox_sqs_worker',false,'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md','defined')",
    )
    .bind(deployment)
    .bind(format!("{capability_id}:automation"))
    .execute(pool)
    .await
    .expect("automation category must insert");
}

async fn count_visible(transaction: &mut Transaction<'_, sqlx::Postgres>, table: &str) -> i64 {
    let sql = format!("SELECT count(*)::bigint FROM {table}");
    sqlx::query_scalar::<_, i64>(&sql)
        .fetch_one(&mut **transaction)
        .await
        .expect("count must succeed")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 033_operations_automation_categories.sql"]
async fn operations_hardening_tables_fail_closed_and_isolate_by_deployment() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let mut unscoped = begin_request(&pool, None).await;
    for table in [
        "operations_tier3_capabilities",
        "operations_alert_rules",
        "operations_readiness_checks",
        "operations_automation_categories",
    ] {
        assert_eq!(count_visible(&mut unscoped, table).await, 0);
    }
    unscoped.rollback().await.expect("rollback");

    let mut scoped_a = begin_request(&pool, Some(&fixture.deployment_a)).await;
    for table in [
        "operations_tier3_capabilities",
        "operations_alert_rules",
        "operations_readiness_checks",
        "operations_automation_categories",
    ] {
        assert_eq!(count_visible(&mut scoped_a, table).await, 1);
    }
    expect_rejected(
        &mut scoped_a,
        sqlx::query(
            "INSERT INTO operations_readiness_checks (\
                 deployment_id, check_id, category, title, status, owner, evidence_ref, notes\
             ) VALUES ($1,'cross-deployment','reliability','Cross deployment','partial',\
                 'test-owner','docs/compliance/08-TIER3-SLO-EVIDENCE.md','must reject')",
        )
        .bind(&fixture.deployment_b),
    )
    .await;
    scoped_a.rollback().await.expect("rollback");

    let mut scoped_b = begin_request(&pool, Some(&fixture.deployment_b)).await;
    let capability_id: String =
        sqlx::query_scalar("SELECT capability_id FROM operations_tier3_capabilities")
            .fetch_one(&mut *scoped_b)
            .await
            .expect("scoped deployment B row must be visible");
    assert_eq!(capability_id, "control_backend");
    let category_id: String =
        sqlx::query_scalar("SELECT category_id FROM operations_automation_categories")
            .fetch_one(&mut *scoped_b)
            .await
            .expect("scoped deployment B automation row must be visible");
    assert_eq!(category_id, "control_backend:automation");
    scoped_b.rollback().await.expect("rollback");
}

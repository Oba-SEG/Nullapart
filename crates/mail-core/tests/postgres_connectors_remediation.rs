//! Local PostgreSQL coverage for Phase 8 connector/remediation storage.
//!
//! Requires PostgreSQL migrated through `031_connectors_remediation.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_connectors_remediation -- --ignored --test-threads=1`.

use chrono::Utc;
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
        "GRANT SELECT, INSERT, UPDATE, DELETE ON connector_integrations TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON connector_capability_grants TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON connector_directory_sync_runs TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON connector_mailbox_searches TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON connector_remediation_actions TO nullapart_local_request",
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
    customer: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("transaction must begin");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("request role must be assumed");
    if deployment.is_some() || customer.is_some() {
        sqlx::query(
            "SELECT set_config('app.current_deployment_id', $1, true), \
                    set_config('app.current_customer_id', $2, true)",
        )
        .bind(deployment.unwrap_or(""))
        .bind(customer.unwrap_or(""))
        .execute(&mut *transaction)
        .await
        .expect("scope must be established");
    }
    transaction
}

async fn begin_owner_scoped<'a>(
    pool: &'a PgPool,
    deployment: &str,
    customer: &str,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("transaction must begin");
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment)
    .bind(customer)
    .execute(&mut *transaction)
    .await
    .expect("owner scope must be established");
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
    customer_a: String,
    customer_b: String,
    connector_a: Uuid,
    connector_b: Uuid,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = Uuid::new_v4().simple().to_string();
    let fixture = Fixture {
        deployment_a: format!("phase8-connectors-a-{suffix}"),
        deployment_b: format!("phase8-connectors-b-{suffix}"),
        customer_a: format!("phase8-connectors-customer-a-{suffix}"),
        customer_b: format!("phase8-connectors-customer-b-{suffix}"),
        connector_a: Uuid::new_v4(),
        connector_b: Uuid::new_v4(),
    };

    for (deployment, customer, region, label) in [
        (&fixture.deployment_a, &fixture.customer_a, "za", "A"),
        (&fixture.deployment_b, &fixture.customer_b, "eu", "B"),
    ] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(deployment)
        .bind(region)
        .bind(format!("Phase 8 deployment {label}"))
        .execute(pool)
        .await
        .expect("deployment fixture must insert");
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(customer)
        .bind(deployment)
        .bind(format!("Phase 8 customer {label}"))
        .execute(pool)
        .await
        .expect("customer fixture must insert");
    }
    insert_connector_rows(
        pool,
        &fixture.deployment_a,
        &fixture.customer_a,
        fixture.connector_a,
        "microsoft_365",
    )
    .await;
    insert_connector_rows(
        pool,
        &fixture.deployment_b,
        &fixture.customer_b,
        fixture.connector_b,
        "google_workspace",
    )
    .await;
    fixture
}

async fn insert_connector_rows(
    pool: &PgPool,
    deployment: &str,
    customer: &str,
    connector_id: Uuid,
    provider: &str,
) {
    let mut transaction = begin_owner_scoped(pool, deployment, customer).await;
    sqlx::query(
        "INSERT INTO connector_integrations \
            (id, deployment_id, customer_id, provider, display_name, external_tenant_id_hash, \
             credential_reference_hash, status, auth_state, created_by) \
         VALUES ($1,$2,$3,$4,'Phase 8 connector','tenant_hash_123456','credential_hash_123456', \
             'active','healthy','test')",
    )
    .bind(connector_id)
    .bind(deployment)
    .bind(customer)
    .bind(provider)
    .execute(&mut *transaction)
    .await
    .expect("connector must insert");
    for capability in ["directory_sync", "mailbox_search", "retro_remediation"] {
        sqlx::query(
            "INSERT INTO connector_capability_grants \
                (connector_id, deployment_id, customer_id, capability, enabled, granted_scopes, approved_by, reason) \
             VALUES ($1,$2,$3,$4,true,ARRAY['User.Read.All'],'test','Phase 8 scoped capability approval')",
        )
        .bind(connector_id)
        .bind(deployment)
        .bind(customer)
        .bind(capability)
        .execute(&mut *transaction)
        .await
        .expect("capability must insert");
    }
    sqlx::query(
        "INSERT INTO connector_directory_sync_runs \
            (connector_id, deployment_id, customer_id, state, completed_at, users_seen, groups_seen, aliases_seen) \
         VALUES ($1,$2,$3,'succeeded',$4,10,2,4)",
    )
    .bind(connector_id)
    .bind(deployment)
    .bind(customer)
    .bind(Utc::now())
    .execute(&mut *transaction)
    .await
    .expect("directory sync run must insert");
    sqlx::query(
        "INSERT INTO connector_mailbox_searches \
            (connector_id, deployment_id, customer_id, mailbox_address_hash, purpose, state, match_confirmation, created_by) \
         VALUES ($1,$2,$3,'mailbox_hash_123456','post_delivery_threat','pending','not_checked','test')",
    )
    .bind(connector_id)
    .bind(deployment)
    .bind(customer)
    .execute(&mut *transaction)
    .await
    .expect("mailbox search must insert");
    sqlx::query(
        "INSERT INTO connector_remediation_actions \
            (connector_id, deployment_id, customer_id, action_type, state, idempotency_key, requested_by, reason) \
         VALUES ($1,$2,$3,'move_to_quarantine','pending',$4,'test','Phase 8 remediation intent')",
    )
    .bind(connector_id)
    .bind(deployment)
    .bind(customer)
    .bind(format!("idem-{connector_id}"))
    .execute(&mut *transaction)
    .await
    .expect("remediation action must insert");
    transaction.commit().await.expect("fixture must commit");
}

async fn count_as_request(
    pool: &PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
    table: &str,
) -> i64 {
    let mut transaction = begin_request(pool, deployment, customer).await;
    let query = format!("SELECT count(*) FROM {table}");
    let count = sqlx::query_scalar::<_, i64>(&query)
        .fetch_one(&mut *transaction)
        .await
        .expect("count must run");
    transaction.commit().await.expect("count must commit");
    count
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 031_connectors_remediation.sql"]
async fn connector_tables_fail_closed_and_isolate_by_tenant() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    assert_eq!(
        count_as_request(&pool, None, None, "connector_integrations").await,
        0
    );
    for table in [
        "connector_integrations",
        "connector_capability_grants",
        "connector_directory_sync_runs",
        "connector_mailbox_searches",
        "connector_remediation_actions",
    ] {
        assert_eq!(
            count_as_request(
                &pool,
                Some(&fixture.deployment_a),
                Some(&fixture.customer_a),
                table,
            )
            .await,
            if table == "connector_capability_grants" {
                3
            } else {
                1
            },
            "{table} should be visible only in the active tenant scope",
        );
        assert_eq!(
            count_as_request(
                &pool,
                Some(&fixture.deployment_b),
                Some(&fixture.customer_b),
                table,
            )
            .await,
            if table == "connector_capability_grants" {
                3
            } else {
                1
            },
            "{table} should be visible in the second tenant scope",
        );
        assert_eq!(
            count_as_request(&pool, Some(&fixture.deployment_a), None, table).await,
            0,
            "{table} must stay fail closed when only the deployment scope is set",
        );
        assert_eq!(
            count_as_request(
                &pool,
                Some(&fixture.deployment_a),
                Some(&fixture.customer_b),
                table,
            )
            .await,
            0,
            "{table} must be invisible when the customer belongs to another deployment",
        );
    }

    let mut transaction = begin_request(
        &pool,
        Some(&fixture.deployment_a),
        Some(&fixture.customer_a),
    )
    .await;
    expect_rejected(
        &mut transaction,
        sqlx::query(
            "INSERT INTO connector_integrations \
                (deployment_id, customer_id, provider, display_name, external_tenant_id_hash, \
                 credential_reference_hash, status, auth_state, created_by) \
             VALUES ($1,$2,'microsoft_365','Cross tenant','tenant_hash_cross_123', \
                 'credential_hash_cross_123','active','healthy','attacker')",
        )
        .bind(&fixture.deployment_a)
        .bind(&fixture.customer_b),
    )
    .await;
    transaction.rollback().await.expect("rollback must succeed");
}

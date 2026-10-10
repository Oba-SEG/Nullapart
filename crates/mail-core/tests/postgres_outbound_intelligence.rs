//! Local PostgreSQL coverage for Phase 6 outbound intelligence storage.
//!
//! Requires PostgreSQL migrated through `028_outbound_intelligence.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_outbound_intelligence -- --ignored`.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row, Transaction};
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
        "GRANT SELECT, INSERT, UPDATE, DELETE ON approved_bulk_senders TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON outbound_behavior_rollups TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON outbound_campaign_fingerprints TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON outbound_security_events TO nullapart_local_request",
    ] {
        sqlx::query(grant)
            .execute(&mut *transaction)
            .await
            .expect("grant must apply");
    }
    transaction.commit().await.expect("role setup must commit");
}

async fn begin_scoped<'a>(
    pool: &'a PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("scoped transaction must begin");
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
        .expect("scope GUCs must be set");
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
    assert!(outcome.is_err(), "statement must be rejected by RLS");
}

struct Fixture {
    deployment_a: String,
    deployment_b: String,
    customer_a: String,
    customer_b: String,
    sender_a: String,
    sender_b: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = Uuid::new_v4().simple().to_string();
    let fixture = Fixture {
        deployment_a: format!("phase6-oi-a-{suffix}"),
        deployment_b: format!("phase6-oi-b-{suffix}"),
        customer_a: format!("phase6-oi-customer-a-{suffix}"),
        customer_b: format!("phase6-oi-customer-b-{suffix}"),
        sender_a: format!("bulk-a-{suffix}@example.test").to_lowercase(),
        sender_b: format!("bulk-b-{suffix}@example.test").to_lowercase(),
    };

    for (deployment, customer, label) in [
        (&fixture.deployment_a, &fixture.customer_a, "A"),
        (&fixture.deployment_b, &fixture.customer_b, "B"),
    ] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name, lifecycle) \
             VALUES ($1, 'za', $2, 'active')",
        )
        .bind(deployment)
        .bind(format!("Phase 6 outbound intelligence {label}"))
        .execute(pool)
        .await
        .expect("deployment fixture must insert");
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(customer)
        .bind(deployment)
        .bind(format!("Phase 6 customer {label}"))
        .execute(pool)
        .await
        .expect("customer fixture must insert");
    }

    insert_phase6_rows(
        pool,
        &fixture.deployment_a,
        &fixture.customer_a,
        &fixture.sender_a,
    )
    .await;
    insert_phase6_rows(
        pool,
        &fixture.deployment_b,
        &fixture.customer_b,
        &fixture.sender_b,
    )
    .await;

    fixture
}

async fn insert_phase6_rows(pool: &PgPool, deployment: &str, customer: &str, sender: &str) {
    sqlx::query(
        "INSERT INTO approved_bulk_senders \
            (deployment_id, customer_id, sender_address, sending_domain, source_kind, source_id, \
             source_ip, max_messages_per_minute, max_messages_per_hour, max_recipients_per_message, \
             max_unique_recipients_per_hour, approved_by, reason) \
         VALUES ($1,$2,$3,'example.test','smtp_mta','mta-a','10.0.0.10',10,100,50,500,'system','phase 6 test approval')",
    )
    .bind(deployment)
    .bind(customer)
    .bind(sender)
    .execute(pool)
    .await
    .expect("approved sender row must insert");

    sqlx::query(
        "INSERT INTO outbound_behavior_rollups \
            (deployment_id, customer_id, source_kind, source_id, source_ip, sender_address, sending_domain, \
             campaign_fingerprint, recipient_domain, window_start, window_seconds, message_count, \
             recipient_count, unique_recipient_count, new_recipient_count) \
         VALUES ($1,$2,'smtp_mta','mta-a','10.0.0.10',$3,'example.test','fp-a','recipient.test', \
             date_trunc('minute', now()), 60, 7, 14, 10, 8)",
    )
    .bind(deployment)
    .bind(customer)
    .bind(sender)
    .execute(pool)
    .await
    .expect("rollup row must insert");

    sqlx::query(
        "INSERT INTO outbound_campaign_fingerprints \
            (deployment_id, customer_id, fingerprint, algorithm, sample_subject_hash, message_count, recipient_count) \
         VALUES ($1,$2,$3,'nullapart_v1','sha256:test',7,14)",
    )
    .bind(deployment)
    .bind(customer)
    .bind(format!("fp-{customer}"))
    .execute(pool)
    .await
    .expect("fingerprint row must insert");

    sqlx::query(
        "INSERT INTO outbound_security_events \
            (deployment_id, customer_id, event_key, event_type, severity, outcome, reason_code, \
             sender_address, source_id, campaign_fingerprint, message_count) \
         VALUES ($1,$2,$3,'unauthorized_bulk','warning','hold','OUTBOUND_UNAUTHORIZED_BULK', \
             $4,'mta-a','fp-a',7)",
    )
    .bind(deployment)
    .bind(customer)
    .bind(format!("{deployment}:{customer}:unauthorized-bulk"))
    .bind(sender)
    .execute(pool)
    .await
    .expect("security event row must insert");
}

async fn visible_count(transaction: &mut Transaction<'_, sqlx::Postgres>, table: &str) -> i64 {
    let row = sqlx::query(&format!("SELECT count(*) AS count FROM {table}"))
        .fetch_one(&mut **transaction)
        .await
        .expect("count query must run");
    row.get("count")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 028_outbound_intelligence.sql"]
async fn outbound_intelligence_tables_are_tenant_isolated() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let tables = [
        "approved_bulk_senders",
        "outbound_behavior_rollups",
        "outbound_campaign_fingerprints",
        "outbound_security_events",
    ];

    let mut unscoped = begin_scoped(&pool, None, None).await;
    for table in tables {
        assert_eq!(
            visible_count(&mut unscoped, table).await,
            0,
            "{table} must fail closed without tenant scope"
        );
    }
    unscoped
        .commit()
        .await
        .expect("unscoped transaction must commit");

    let mut tenant_a = begin_scoped(
        &pool,
        Some(&fixture.deployment_a),
        Some(&fixture.customer_a),
    )
    .await;
    for table in tables {
        assert_eq!(
            visible_count(&mut tenant_a, table).await,
            1,
            "{table} must expose only the scoped tenant row"
        );
    }

    expect_rejected(
        &mut tenant_a,
        sqlx::query(
            "INSERT INTO approved_bulk_senders \
                (deployment_id, customer_id, sender_address, sending_domain, source_kind, source_id, \
                 max_messages_per_minute, max_messages_per_hour, max_recipients_per_message, \
                 max_unique_recipients_per_hour, approved_by, reason) \
             VALUES ($1,$2,$3,'example.test','smtp_mta','mta-a',1,1,1,1,'system','cross tenant write')",
        )
        .bind(&fixture.deployment_b)
        .bind(&fixture.customer_b)
        .bind(&fixture.sender_b),
    )
    .await;

    expect_rejected(
        &mut tenant_a,
        sqlx::query(
            "INSERT INTO outbound_security_events \
                (deployment_id, customer_id, event_key, event_type, severity, outcome, reason_code) \
             VALUES ($1,$2,$3,'source_spoofing','critical','block_sender','REJECT_SPOOFING')",
        )
        .bind(&fixture.deployment_b)
        .bind(&fixture.customer_a)
        .bind(format!("{}:{}:spoof", fixture.deployment_b, fixture.customer_a)),
    )
    .await;

    tenant_a
        .commit()
        .await
        .expect("tenant transaction must commit");
}

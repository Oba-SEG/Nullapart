//! PostgreSQL coverage for the private outbound SMTP idempotency boundary.
//!
//! Requires PostgreSQL migrated through `036_outbound_submission_ledger.sql`
//! with `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_outbound_submission_ledger -- --ignored`.

use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use nullapart_mail_core::outbound_submission::{
    OutboundSubmissionClaim, OutboundSubmissionLedger, OutboundSubmissionReceipt,
    PostgresOutboundSubmissionLedger,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Row, Transaction};
use uuid::Uuid;

const REQUEST_ROLE: &str = "nullapart_local_request";
const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 036 and NULLAPART_TEST_DATABASE_URL"]
async fn ledger_claims_once_records_receipts_and_enforces_scope() {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable");
    ensure_request_role(&pool).await;

    let suffix = Uuid::new_v4().simple().to_string();
    let deployment = DeploymentId::new(&format!("outbound-ledger-deployment-{suffix}"));
    let customer = CustomerId::new(&format!("outbound-ledger-customer-{suffix}"));
    let other_customer = CustomerId::new(&format!("outbound-ledger-other-{suffix}"));
    seed_customer(&pool, &deployment, &customer).await;
    seed_customer(&pool, &deployment, &other_customer).await;

    let ledger =
        PostgresOutboundSubmissionLedger::new(pool.clone(), deployment.clone(), customer.clone());
    assert_eq!(
        ledger
            .claim_submission(KEY, "transaction-safe-id")
            .await
            .expect("first claim"),
        OutboundSubmissionClaim::Submit
    );
    assert_eq!(
        ledger
            .claim_submission(KEY, "transaction-safe-id")
            .await
            .expect("retry claim"),
        OutboundSubmissionClaim::InProgress,
        "ambiguous in-progress work must not be resent"
    );
    let receipt = OutboundSubmissionReceipt {
        transaction_id: "transaction-safe-id".to_string(),
        postfix_queue_id: "ABCD1234".to_string(),
    };
    assert!(
        ledger
            .record_submission(
                KEY,
                &OutboundSubmissionReceipt {
                    transaction_id: "different-transaction".to_string(),
                    postfix_queue_id: "ABCD1234".to_string(),
                },
            )
            .await
            .is_err(),
        "only the worker that claimed the transaction can complete it"
    );
    ledger
        .record_submission(KEY, &receipt)
        .await
        .expect("receipt must be persisted");
    assert_eq!(
        ledger
            .claim_submission(KEY, "transaction-safe-id")
            .await
            .expect("completed retry"),
        OutboundSubmissionClaim::AlreadySubmitted(receipt.clone())
    );

    let other_ledger = PostgresOutboundSubmissionLedger::new(
        pool.clone(),
        deployment.clone(),
        other_customer.clone(),
    );
    assert_eq!(
        other_ledger
            .claim_submission(KEY, "transaction-other-tenant")
            .await
            .expect("same key is tenant-local"),
        OutboundSubmissionClaim::Submit
    );

    assert_eq!(
        scoped_count(&pool, &deployment.0, &customer.0).await,
        1,
        "the scoped request role sees its own ledger row"
    );
    assert_eq!(
        scoped_count(&pool, &deployment.0, &other_customer.0).await,
        1,
        "the other tenant sees only its own identical-key row"
    );
    assert_eq!(
        scoped_count(&pool, &deployment.0, "unrelated-customer").await,
        0,
        "an unrelated tenant scope sees no rows"
    );

    let other_deployment = DeploymentId::new(&format!("outbound-ledger-other-deployment-{suffix}"));
    let cross_deployment_customer =
        CustomerId::new(&format!("outbound-ledger-cross-customer-{suffix}"));
    seed_customer(&pool, &other_deployment, &cross_deployment_customer).await;
    let cross_deployment_insert = sqlx::query(
        "INSERT INTO outbound_submission_ledger \
         (deployment_id, customer_id, idempotency_key, transaction_id, submission_state) \
         VALUES ($1, $2, $3, 'cross-deployment-transaction', 'in_progress')",
    )
    .bind(&deployment.0)
    .bind(&cross_deployment_customer.0)
    .bind("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .execute(&pool)
    .await;
    assert!(
        cross_deployment_insert.is_err(),
        "a customer cannot be attached to an unrelated deployment"
    );
}

async fn ensure_request_role(pool: &PgPool) {
    let mut transaction = pool.begin().await.expect("role setup must begin");
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
        "GRANT SELECT ON outbound_submission_ledger TO nullapart_local_request",
    ] {
        sqlx::query(grant)
            .execute(&mut *transaction)
            .await
            .expect("grant must apply");
    }
    transaction.commit().await.expect("role setup must commit");
}

async fn seed_customer(pool: &PgPool, deployment: &DeploymentId, customer: &CustomerId) {
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) \
         VALUES ($1, 'local', 'Outbound ledger test') ON CONFLICT (id) DO NOTHING",
    )
    .bind(&deployment.0)
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, 'Outbound ledger customer')",
    )
    .bind(&customer.0)
    .bind(&deployment.0)
    .execute(pool)
    .await
    .expect("customer fixture must insert");
}

async fn scoped_count(pool: &PgPool, deployment: &str, customer: &str) -> i64 {
    let mut transaction: Transaction<'_, sqlx::Postgres> =
        pool.begin().await.expect("scoped transaction must begin");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("request role must be assumed");
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment)
    .bind(customer)
    .execute(&mut *transaction)
    .await
    .expect("scope must be configured");
    let count: i64 = sqlx::query("SELECT count(*) AS count FROM outbound_submission_ledger")
        .fetch_one(&mut *transaction)
        .await
        .expect("scoped select must succeed")
        .get("count");
    transaction
        .commit()
        .await
        .expect("scoped transaction must commit");
    count
}

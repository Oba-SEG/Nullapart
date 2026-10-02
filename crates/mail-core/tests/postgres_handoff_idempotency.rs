//! Local PostgreSQL integration coverage for the durable handoff retry boundary.

use nullapart_mail_contracts::transaction::DeploymentId;
use nullapart_mail_core::handoff::{HandoffIdempotencyStore, PostgresHandoffIdempotencyStore};
use sqlx::postgres::PgPoolOptions;
use tokio::task::JoinSet;

#[tokio::test]
#[ignore = "requires a migrated local PostgreSQL instance and NULLAPART_TEST_DATABASE_URL"]
async fn postgres_handoff_store_deduplicates_and_rejects_conflicts() {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable");
    let deployment_id = DeploymentId::new("LOCAL-TEST");
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', 'Local test') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&deployment_id.0)
    .execute(&pool)
    .await
    .expect("test deployment must exist");
    sqlx::query("DELETE FROM handoff_idempotency WHERE deployment_id = $1")
        .bind(&deployment_id.0)
        .execute(&pool)
        .await
        .expect("test handoff rows must be cleaned");

    let store = PostgresHandoffIdempotencyStore::new(pool);
    let mut retries = JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        let deployment_id = deployment_id.clone();
        retries.spawn(async move {
            store
                .create_or_get(&deployment_id, "LOCALQ1", "hash-a")
                .await
        });
    }

    let mut results = Vec::new();
    while let Some(result) = retries.join_next().await {
        results.push(
            result
                .expect("retry task must not panic")
                .expect("retry must succeed"),
        );
    }
    let accepted: Vec<_> = results.iter().filter(|result| !result.duplicate).collect();
    assert_eq!(
        accepted.len(),
        1,
        "exactly one retry must create the transaction"
    );
    let transaction_id = accepted[0].transaction_id.clone();
    assert!(results
        .iter()
        .all(|result| result.transaction_id == transaction_id));

    let conflict = store
        .create_or_get(&deployment_id, "LOCALQ1", "hash-b")
        .await;

    assert!(conflict.is_err());
}

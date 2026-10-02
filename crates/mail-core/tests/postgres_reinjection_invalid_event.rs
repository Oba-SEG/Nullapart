//! Local PostgreSQL coverage for terminal quarantine-release events.
//!
//! A `quarantine.released` record whose reinjection context can never be
//! rebuilt must reach `reinjection_dead_letters` instead of being retried
//! forever: an unresolved event at the head of the outbox would otherwise
//! starve every later release.

use nullapart_mail_core::artifact_store::{FilesystemArtifactRuntime, FilesystemArtifactStore};
use nullapart_mail_core::quarantine_reinjection::{
    QuarantineReinjectionConfig, QuarantineReinjectionWorker, ReinjectionRunOutcome,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn connect() -> PgPool {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable")
}

async fn insert_release_event(
    pool: &PgPool,
    deployment_id: &str,
    customer_id: &str,
    tenant_message_id: Uuid,
) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO outbox_events (event_type, payload, customer_id, deployment_id, trace_id) \
         VALUES ('quarantine.released', $1, $2, $3, 'local-reinjection-trace') RETURNING id",
    )
    .bind(json!({ "tenant_message_id": tenant_message_id.to_string() }))
    .bind(customer_id)
    .bind(deployment_id)
    .fetch_one(pool)
    .await
    .expect("the release event must be persisted")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 007_reinjection_invalid_event.sql"]
async fn terminal_release_event_is_dead_lettered_and_cannot_stall_the_queue() {
    let pool = connect().await;
    let deployment_id = "LOCAL-REINJECTION-INVALID";
    let customer_id = "local-reinjection-invalid-customer";
    let transaction_id = Uuid::new_v4();
    let tenant_message_id = Uuid::new_v4();
    let unattributable_message_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', 'Local reinjection') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("the deployment fixture must exist");
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, 'Local reinjection customer') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(customer_id)
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("the customer fixture must exist");
    sqlx::query(
        "INSERT INTO smtp_transactions (id, deployment_id, direction, envelope_sender, content_hash, \
                mime_artifact_id, received_at) VALUES ($1, $2, 'inbound', 'sender@example.test', \
                'test-hash', 'local-reinjection', now())",
    )
    .bind(transaction_id)
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("the transaction fixture must exist");
    sqlx::query(
        "INSERT INTO tenant_message_instances (id, transaction_id, customer_id, disposition) \
         VALUES ($1, $2, $3, 'quarantine')",
    )
    .bind(tenant_message_id)
    .bind(transaction_id)
    .bind(customer_id)
    .execute(&pool)
    .await
    .expect("the tenant message fixture must exist");

    // No quarantine case, envelope or artifact exists for this tenant message,
    // so the release can never be reinjected.
    let terminal_event =
        insert_release_event(&pool, deployment_id, customer_id, tenant_message_id).await;

    let artifact_root =
        std::env::temp_dir().join(format!("nullapart-reinjection-invalid-{}", Uuid::new_v4()));
    let store = FilesystemArtifactStore::try_new(
        artifact_root.clone(),
        FilesystemArtifactRuntime::LocalDevelopment,
    )
    .await
    .expect("the local artifact store must be creatable");
    let worker = QuarantineReinjectionWorker::new(
        pool.clone(),
        store,
        QuarantineReinjectionConfig {
            poll_interval: std::time::Duration::from_secs(1),
            ..QuarantineReinjectionConfig::default()
        },
    );

    let outcome = worker
        .run_once()
        .await
        .expect("a terminal event must not be treated as a persistence failure");
    assert_eq!(
        outcome,
        ReinjectionRunOutcome::InvalidEventRecorded {
            outbox_event_id: terminal_event,
        }
    );

    let recorded = sqlx::query_scalar::<_, String>(
        "SELECT failure_code FROM reinjection_dead_letters WHERE outbox_event_id = $1",
    )
    .bind(terminal_event)
    .fetch_one(&pool)
    .await
    .expect("the terminal event must be recorded in the dead-letter table");
    assert_eq!(recorded, "INVALID_EVENT");

    // The dead-lettered event is out of the queue, so the next poll is idle
    // rather than a retry loop.
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the queue must stay healthy"),
        ReinjectionRunOutcome::Idle
    );

    // An event that cannot be attributed to an existing tenant message cannot
    // be dead-lettered; it is skipped for the cycle instead of stalling the
    // queue, and it stays unpublished for operations to inspect.
    let unattributable_event =
        insert_release_event(&pool, deployment_id, customer_id, unattributable_message_id).await;
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("an unattributable event must not stall the queue"),
        ReinjectionRunOutcome::Idle
    );
    let dead_letters = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM reinjection_dead_letters WHERE outbox_event_id = $1",
    )
    .bind(unattributable_event)
    .fetch_one(&pool)
    .await
    .expect("the dead-letter probe must run");
    assert_eq!(
        dead_letters, 0,
        "an unattributable event must not be dead-lettered"
    );
    let published = sqlx::query_scalar::<_, bool>(
        "SELECT published_at IS NOT NULL FROM outbox_events WHERE id = $1",
    )
    .bind(unattributable_event)
    .fetch_one(&pool)
    .await
    .expect("the release event must be readable");
    assert!(!published, "an unattributable event must stay unpublished");

    sqlx::query("DELETE FROM reinjection_dead_letters WHERE outbox_event_id = $1")
        .bind(terminal_event)
        .execute(&pool)
        .await
        .expect("the dead letter must be removable");
    for event_id in [terminal_event, unattributable_event] {
        sqlx::query("DELETE FROM outbox_events WHERE id = $1")
            .bind(event_id)
            .execute(&pool)
            .await
            .expect("the release event must be removable");
    }
    sqlx::query("DELETE FROM tenant_message_instances WHERE id = $1")
        .bind(tenant_message_id)
        .execute(&pool)
        .await
        .expect("the tenant message must be removable");
    sqlx::query("DELETE FROM smtp_transactions WHERE id = $1")
        .bind(transaction_id)
        .execute(&pool)
        .await
        .expect("the transaction must be removable");
    sqlx::query("DELETE FROM customers WHERE id = $1")
        .bind(customer_id)
        .execute(&pool)
        .await
        .expect("the customer must be removable");
    sqlx::query("DELETE FROM deployments WHERE id = $1")
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("the deployment must be removable");
    let _ = std::fs::remove_dir_all(artifact_root);
}

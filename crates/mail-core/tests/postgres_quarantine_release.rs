//! Local PostgreSQL coverage for tenant-safe, audited quarantine release.

use chrono::Utc;
use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId, TenantMessageId, TransactionId},
    ActorId, ArtifactId,
};
use nullapart_mail_core::quarantine::{
    AuthorizedQuarantineRelease, PostgresQuarantineRepository, QuarantineReleaseRequest,
    QuarantineRepository,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId, TenantContext,
};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 020_inline_ml_feedback_shadow.sql"]
async fn postgres_release_is_tenant_scoped_idempotent_and_audited() {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable");
    let deployment_id = DeploymentId::new("LOCAL-QUARANTINE");
    let customer_id = CustomerId::new("local-quarantine-customer");
    let transaction_id = TransactionId::new();
    let tenant_message_id = TenantMessageId::new();
    let artifact_id = ArtifactId::new();

    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', 'Local quarantine') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&deployment_id.0)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, 'Local quarantine customer') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&customer_id.0)
    .bind(&deployment_id.0)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO artifacts (id, deployment_id, customer_id, content_type, size_bytes, content_hash, \
                storage_backend, storage_path, retention_class) \
         VALUES ($1, $2, $3, 'message/rfc822', 1, 'test-hash', 'filesystem', 'local/test', 'standard')",
    )
    .bind(artifact_id.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO smtp_transactions (id, deployment_id, direction, envelope_sender, content_hash, \
                mime_artifact_id, received_at) VALUES ($1, $2, 'inbound', 'sender@example.test', \
                'test-hash', $3, now())",
    )
    .bind(transaction_id.0)
    .bind(&deployment_id.0)
    .bind(artifact_id.0.to_string())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tenant_message_instances (id, transaction_id, customer_id, disposition) \
         VALUES ($1, $2, $3, 'quarantine')",
    )
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(&customer_id.0)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO quarantine_cases (tenant_message_id, transaction_id, deployment_id, customer_id, artifact_id, reason_code) \
         VALUES ($1, $2, $3, $4, $5, 'QUARANTINE_MALWARE')",
    )
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(artifact_id.0)
    .execute(&pool)
    .await
    .unwrap();

    let context = TenantContext {
        deployment_id: deployment_id.clone(),
        region: RegionId::new("local"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "security-admin@example.test".to_string(),
            roles: vec!["customer_admin".to_string()],
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: customer_id.clone(),
        customer_internal_key: 1,
        customer_display_name: "Local quarantine customer".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: vec!["quarantine:release".to_string()],
        config_revision: 1,
        trace_id: "local-quarantine-release-trace".to_string(),
        correlation_id: "local-quarantine-release-correlation".to_string(),
        session_id: "local-quarantine-release-session".to_string(),
        authenticated_at: Utc::now(),
    };
    let authorization = AuthorizedQuarantineRelease::from_authenticated_context(&context).unwrap();
    let request = QuarantineReleaseRequest {
        tenant_message_id: tenant_message_id.clone(),
        release_reason: "Validated false positive".to_string(),
        idempotency_key: format!("release-{}", tenant_message_id.0),
    };
    let repository = PostgresQuarantineRepository::new(pool.clone());

    let released = repository
        .release(&authorization, &request)
        .await
        .expect("authorized release must succeed");
    let retry = repository
        .release(&authorization, &request)
        .await
        .expect("same idempotency key must return the release");

    assert!(released.released_at.is_some());
    assert_eq!(released.released_at, retry.released_at);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'release'",
        )
        .bind(tenant_message_id.0.to_string())
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM outbox_events WHERE idempotency_key = $1",
        )
        .bind(format!("quarantine-release:{}", request.idempotency_key))
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let feedback = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT source, proposed_label, curator_state, reason \
         FROM ml_feedback_candidates WHERE tenant_message_id = $1",
    )
    .bind(tenant_message_id.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        feedback,
        (
            "quarantine_release".to_string(),
            "false_positive".to_string(),
            "pending".to_string(),
            "Validated false positive".to_string()
        )
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM ml_feedback_candidates WHERE tenant_message_id = $1",
        )
        .bind(tenant_message_id.0)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    // The release event must go with the fixture: a leftover unpublished
    // event would stall the live reinjection worker on a case that no longer
    // exists. Audit rows are append-only and stay.
    sqlx::query("DELETE FROM ml_feedback_candidates WHERE tenant_message_id = $1")
        .bind(tenant_message_id.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM outbox_events WHERE idempotency_key = $1")
        .bind(format!("quarantine-release:{}", request.idempotency_key))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM quarantine_cases WHERE tenant_message_id = $1")
        .bind(tenant_message_id.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM tenant_message_instances WHERE id = $1")
        .bind(tenant_message_id.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM smtp_transactions WHERE id = $1")
        .bind(transaction_id.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM artifacts WHERE id = $1")
        .bind(artifact_id.0)
        .execute(&pool)
        .await
        .unwrap();
}

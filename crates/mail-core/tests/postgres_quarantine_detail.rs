//! Local PostgreSQL coverage for the tenant-scoped quarantine detail
//! projection: retention state, capability-labelled scanner results and
//! audit linkage, with a cross-tenant denial.

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
#[ignore = "requires migrated local PostgreSQL through 006_quarantine_reinjection_dead_letters.sql"]
async fn postgres_detail_projects_retention_scanner_results_and_audit() {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable");
    let deployment_id = DeploymentId::new("LOCAL-QUARANTINE-DETAIL");
    let customer_id = CustomerId::new("local-quarantine-detail-customer");
    let other_customer_id = CustomerId::new("local-quarantine-detail-other");
    let transaction_id = TransactionId::new();
    let tenant_message_id = TenantMessageId::new();
    let artifact_id = ArtifactId::new();

    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', 'Local quarantine detail') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&deployment_id.0)
    .execute(&pool)
    .await
    .unwrap();
    for (id, name) in [
        (&customer_id, "Local quarantine detail customer"),
        (&other_customer_id, "Local quarantine detail other"),
    ] {
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id.0)
        .bind(&deployment_id.0)
        .bind(name)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO artifacts (id, deployment_id, customer_id, content_type, size_bytes, content_hash, \
                storage_backend, storage_path, retention_class) \
         VALUES ($1, $2, $3, 'message/rfc822', 1, 'detail-hash', 'filesystem', 'local/detail', 'standard')",
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
                'detail-hash', $3, now())",
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
        "INSERT INTO quarantine_cases (tenant_message_id, transaction_id, deployment_id, customer_id, \
                artifact_id, reason_code) VALUES ($1, $2, $3, $4, $5, 'QUARANTINE_MALWARE')",
    )
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(artifact_id.0)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO quarantine_reinjection_envelopes (tenant_message_id, transaction_id, deployment_id, \
                customer_id, envelope_sender, recipients) \
         VALUES ($1, $2, $3, $4, 'sender@example.test', $5)",
    )
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(serde_json::json!(["recipient@example.test"]))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO scanner_results (tenant_message_id, transaction_id, artifact_id, deployment_id, \
                customer_id, scanner_id, scanner_type, status, required, duration_ms, completed_at) \
         VALUES ($1, $2, $3, $4, $5, 'attachment-analysis', 'attachment', 'suspicious', true, 12, now())",
    )
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(artifact_id.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO security_findings (id, tenant_message_id, transaction_id, artifact_id, deployment_id, \
                customer_id, scanner_type, scanner_status, severity, category, description, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'attachment', 'suspicious', 'high', 'malware', \
                'Static malware rule matched', now())",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(artifact_id.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
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
        customer_display_name: "Local quarantine detail customer".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: vec![
            "quarantine:view".to_string(),
            "quarantine:release".to_string(),
        ],
        config_revision: 1,
        trace_id: "local-quarantine-detail-trace".to_string(),
        correlation_id: "local-quarantine-detail-correlation".to_string(),
        session_id: "local-quarantine-detail-session".to_string(),
        authenticated_at: Utc::now(),
    };

    let repository = PostgresQuarantineRepository::new(pool.clone());

    // Another tenant cannot resolve this case at all.
    let foreign = repository
        .detail(&other_customer_id, &deployment_id, &tenant_message_id)
        .await;
    assert!(
        foreign.is_err(),
        "cross-tenant detail must not resolve another customer's case"
    );

    let detail = repository
        .detail(&customer_id, &deployment_id, &tenant_message_id)
        .await
        .expect("scoped detail must resolve");

    let retention = detail
        .retention
        .as_ref()
        .expect("retention state must be projected");
    assert_eq!(retention.retention_class, "standard");
    assert_eq!(retention.quarantined_at, detail.item.case.quarantined_at);
    assert!(retention.released_at.is_none());

    assert_eq!(detail.scanner_results.len(), 1);
    let result = &detail.scanner_results[0];
    assert_eq!(result.capability, "Attachment content analysis");
    assert_eq!(result.status, "suspicious");
    assert!(result.required);
    assert!(!result.capability.contains("attachment-analysis"));
    assert!(detail.audit.is_empty(), "no release has happened yet");
    assert_eq!(
        detail.item.findings.len(),
        1,
        "the normalized finding must be projected for the active case"
    );
    assert_eq!(detail.item.findings[0].severity, "high");
    assert_eq!(detail.item.findings[0].category, "malware");

    // Releasing writes the audit record in the same transaction as the state
    // change, and the case must remain inspectable afterwards.
    let authorization = AuthorizedQuarantineRelease::from_authenticated_context(&context).unwrap();
    repository
        .release(
            &authorization,
            &QuarantineReleaseRequest {
                tenant_message_id: tenant_message_id.clone(),
                release_reason: "Validated false positive".to_string(),
                idempotency_key: format!("detail-release-{}", tenant_message_id.0),
            },
        )
        .await
        .expect("authorized release must succeed");

    let released = repository
        .detail(&customer_id, &deployment_id, &tenant_message_id)
        .await
        .expect("released case must remain inspectable");
    assert!(released.retention.expect("retention").released_at.is_some());
    assert!(released.item.case.released_at.is_some());
    assert_eq!(released.audit.len(), 1);
    assert_eq!(released.audit[0].action, "release");
    assert_eq!(released.audit[0].result, "success");
    assert_eq!(released.audit[0].actor_login, "security-admin@example.test");
    assert_eq!(
        released.item.findings.len(),
        1,
        "release must not drop the normalized findings from the projection"
    );
    assert_eq!(released.item.findings[0].severity, "high");
    assert_eq!(
        released.scanner_results.len(),
        1,
        "release must not drop scanner results from the projection"
    );
    assert_eq!(
        released.scanner_results[0].capability,
        "Attachment content analysis"
    );

    sqlx::query("DELETE FROM quarantine_reinjection_envelopes WHERE tenant_message_id = $1")
        .bind(tenant_message_id.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM quarantine_cases WHERE tenant_message_id = $1")
        .bind(tenant_message_id.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM scanner_results WHERE tenant_message_id = $1")
        .bind(tenant_message_id.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM outbox_events WHERE idempotency_key = $1")
        .bind(format!(
            "quarantine-release:detail-release-{}",
            tenant_message_id.0
        ))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM security_findings WHERE tenant_message_id = $1")
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

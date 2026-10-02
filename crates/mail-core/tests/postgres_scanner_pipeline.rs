//! Real local PostgreSQL proof for the Phase 2 artifact-to-quarantine path.

use std::{env, sync::Arc, time::Duration};

use chrono::Utc;
use nullapart_mail_contracts::{
    artifact::ContentType,
    policy::{PolicyRevisionId, ReasonCode},
    transaction::{CustomerId, DeploymentId, Disposition, TenantMessageId, TraceId, TransactionId},
    ArtifactId, ScannerType,
};
use nullapart_mail_core::{
    artifact_store::{FilesystemArtifactRuntime, FilesystemArtifactStore},
    policy::PolicyEvaluationResult,
    scanner_adapters::FileTypeScanner,
    scanner_fabric::{
        ScannerFabric, ScannerFabricConfig, ScannerProfile, ScannerRegistration,
        ScannerRequirement, ScannerResourceLimits,
    },
    scanner_pipeline::{DurableScannerPipeline, DurableScannerPipelineError, TenantScanContext},
};
use nullapart_scanner_sdk::trait_defs::{Scanner, ScannerId};
use sqlx::{PgPool, Row};

struct TenantFixture {
    deployment: DeploymentId,
    customer: CustomerId,
    transaction_id: TransactionId,
    tenant_message_id: TenantMessageId,
}

async fn seed_tenant(pool: &PgPool, initial_disposition: &str) -> TenantFixture {
    let suffix = uuid::Uuid::new_v4().to_string();
    let deployment = DeploymentId::new(&format!("phase2-{suffix}"));
    let customer = CustomerId::new(&format!("customer-{suffix}"));
    let transaction_id = TransactionId::new();
    let tenant_message_id = TenantMessageId::new();

    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', 'Phase 2 test')",
    )
    .bind(&deployment.0)
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name) \
         VALUES ($1, $2, 'Phase 2 customer')",
    )
    .bind(&customer.0)
    .bind(&deployment.0)
    .execute(pool)
    .await
    .expect("customer fixture must insert");
    sqlx::query(
        "INSERT INTO smtp_transactions \
            (id, deployment_id, direction, envelope_sender, content_hash, mime_artifact_id, received_at) \
         VALUES ($1,$2,'inbound','sender@example.test','pending','pending',$3)",
    )
    .bind(transaction_id.0)
    .bind(&deployment.0)
    .bind(Utc::now())
    .execute(pool)
    .await
    .expect("SMTP transaction fixture must insert");

    let mut transaction = pool.begin().await.expect("tenant fixture transaction");
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(&customer.0)
        .execute(&mut *transaction)
        .await
        .expect("tenant fixture must set RLS scope");
    sqlx::query(
        "INSERT INTO tenant_message_instances (id, transaction_id, customer_id, disposition) \
         VALUES ($1,$2,$3,$4)",
    )
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(&customer.0)
    .bind(initial_disposition)
    .execute(&mut *transaction)
    .await
    .expect("tenant message fixture must insert");
    transaction.commit().await.expect("tenant fixture commit");

    TenantFixture {
        deployment,
        customer,
        transaction_id,
        tenant_message_id,
    }
}

fn context(fixture: &TenantFixture) -> TenantScanContext {
    TenantScanContext {
        tenant_message_id: fixture.tenant_message_id.clone(),
        transaction_id: fixture.transaction_id.clone(),
        deployment_id: fixture.deployment.clone(),
        customer_id: fixture.customer.clone(),
        trace_id: TraceId::new(),
        accepted_at: Utc::now(),
        envelope_sender: "sender@example.test".to_string(),
        recipients: vec!["recipient@example.test".to_string()],
    }
}

fn policy(disposition: Disposition) -> PolicyEvaluationResult {
    PolicyEvaluationResult {
        disposition,
        reason_code: ReasonCode::quarantine_malware(),
        policy_revision: PolicyRevisionId::new(),
        explanation: "integration test policy".to_string(),
        findings_applied: Vec::new(),
        evaluated_at: Utc::now(),
    }
}

fn scanner_fabric() -> ScannerFabric {
    let scanner: Arc<dyn Scanner> = Arc::new(FileTypeScanner::new(1024 * 1024));
    ScannerFabric::new(
        ScannerFabricConfig::default(),
        vec![ScannerRegistration {
            scanner,
            profile: ScannerProfile {
                scanner_id: ScannerId::new("file-type"),
                scanner_type: ScannerType::Attachment,
                requirement: ScannerRequirement::Required,
                max_input_bytes: 1024 * 1024,
                timeout: Duration::from_secs(1),
                max_concurrency: 1,
                limits: ScannerResourceLimits::bounded_default(1024 * 1024),
            },
        }],
    )
    .expect("bounded file-type scanner registration must be valid")
}

async fn scoped_counts(
    pool: &PgPool,
    fixture: &TenantFixture,
) -> (i64, i64, i64, i64, i64, String) {
    let mut transaction = pool.begin().await.expect("assertion transaction");
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(&fixture.customer.0)
        .execute(&mut *transaction)
        .await
        .expect("assertion RLS scope");
    let artifact_id = ArtifactId(fixture.tenant_message_id.0);
    let artifacts = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE id = $1")
        .bind(artifact_id.0)
        .fetch_one(&mut *transaction)
        .await
        .expect("artifact count");
    let results =
        sqlx::query_scalar("SELECT count(*) FROM scanner_results WHERE tenant_message_id = $1")
            .bind(fixture.tenant_message_id.0)
            .fetch_one(&mut *transaction)
            .await
            .expect("scanner result count");
    let findings =
        sqlx::query_scalar("SELECT count(*) FROM security_findings WHERE tenant_message_id = $1")
            .bind(fixture.tenant_message_id.0)
            .fetch_one(&mut *transaction)
            .await
            .expect("finding count");
    let quarantines =
        sqlx::query_scalar("SELECT count(*) FROM quarantine_cases WHERE tenant_message_id = $1")
            .bind(fixture.tenant_message_id.0)
            .fetch_one(&mut *transaction)
            .await
            .expect("quarantine count");
    let envelopes = sqlx::query_scalar(
        "SELECT count(*) FROM quarantine_reinjection_envelopes WHERE tenant_message_id = $1",
    )
    .bind(fixture.tenant_message_id.0)
    .fetch_one(&mut *transaction)
    .await
    .expect("reinjection envelope count");
    let row = sqlx::query("SELECT disposition FROM tenant_message_instances WHERE id = $1")
        .bind(fixture.tenant_message_id.0)
        .fetch_one(&mut *transaction)
        .await
        .expect("tenant disposition");
    let current_disposition = row.get("disposition");
    transaction.commit().await.expect("assertion commit");
    (
        artifacts,
        results,
        findings,
        quarantines,
        envelopes,
        current_disposition,
    )
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 005_quarantine_reinjection.sql and NULLAPART_TEST_DATABASE_URL"]
async fn postgres_pipeline_persists_artifact_evidence_and_quarantine_atomically() {
    let database_url = env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must target local test PostgreSQL");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("local PostgreSQL must connect");
    let fixture = seed_tenant(&pool, "hold").await;
    let root = env::temp_dir().join(format!(
        "nullapart-pipeline-{}",
        fixture.tenant_message_id.0
    ));
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem store must initialize");
    let pipeline = DurableScannerPipeline::new(store, scanner_fabric(), pool.clone());

    let outcome = pipeline
        .process(
            context(&fixture),
            b"Content-Type: image/svg+xml\r\n\r\n<svg/>".to_vec(),
            ContentType::new("message/rfc822"),
            policy(Disposition::Quarantine),
        )
        .await
        .expect("durable Phase 2 workflow must complete");
    assert_eq!(outcome.artifact_id.0, fixture.tenant_message_id.0);
    assert_eq!(outcome.disposition, Disposition::Quarantine);
    assert!(outcome.quarantine_created);
    assert_eq!(
        scoped_counts(&pool, &fixture).await,
        (1, 1, 1, 1, 1, "quarantine".to_string())
    );

    tokio::fs::remove_dir_all(root)
        .await
        .expect("artifact fixture cleanup");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 005_quarantine_reinjection.sql and NULLAPART_TEST_DATABASE_URL"]
async fn late_quarantine_conflict_rolls_back_artifact_evidence_and_disposition() {
    let database_url = env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must target local test PostgreSQL");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("local PostgreSQL must connect");
    let fixture = seed_tenant(&pool, "allow").await;
    let seeded_artifact = ArtifactId::new();

    let mut transaction = pool.begin().await.expect("conflict fixture transaction");
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(&fixture.customer.0)
        .execute(&mut *transaction)
        .await
        .expect("conflict fixture RLS scope");
    sqlx::query(
        "INSERT INTO artifacts \
            (id, deployment_id, customer_id, content_type, size_bytes, content_hash, storage_backend, \
             storage_path, retention_class, encryption_enabled) \
         VALUES ($1,$2,$3,'message/rfc822',1,$4,'filesystem',$5,'standard',false)",
    )
    .bind(seeded_artifact.0)
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer.0)
    .bind(format!("sha256:{}", "0".repeat(64)))
    .bind(format!("{}.artifact", seeded_artifact.0))
    .execute(&mut *transaction)
    .await
    .expect("seed artifact");
    sqlx::query(
        "INSERT INTO quarantine_cases \
            (tenant_message_id, transaction_id, deployment_id, customer_id, artifact_id, reason_code) \
         VALUES ($1,$2,$3,$4,$5,'PREEXISTING_TEST_CASE')",
    )
    .bind(fixture.tenant_message_id.0)
    .bind(fixture.transaction_id.0)
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer.0)
    .bind(seeded_artifact.0)
    .execute(&mut *transaction)
    .await
    .expect("seed quarantine conflict");
    transaction.commit().await.expect("conflict fixture commit");

    let root = env::temp_dir().join(format!(
        "nullapart-pipeline-rollback-{}",
        fixture.tenant_message_id.0
    ));
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem store must initialize");
    let pipeline = DurableScannerPipeline::new(store, scanner_fabric(), pool.clone());
    let error = pipeline
        .process(
            context(&fixture),
            b"Content-Type: image/svg+xml\r\n\r\n<svg/>".to_vec(),
            ContentType::new("message/rfc822"),
            policy(Disposition::Quarantine),
        )
        .await
        .expect_err("existing quarantine must reject the durable transaction");
    assert_eq!(error, DurableScannerPipelineError::PersistenceConflict);

    let counts = scoped_counts(&pool, &fixture).await;
    assert_eq!(counts.0, 0, "new artifact metadata must roll back");
    assert_eq!(counts.1, 0, "scanner results must roll back");
    assert_eq!(counts.2, 0, "findings must roll back");
    assert_eq!(counts.3, 1, "pre-existing quarantine must remain");
    assert_eq!(counts.4, 0, "no reinjection envelope may be added");
    assert_eq!(counts.5, "allow", "disposition update must roll back");

    tokio::fs::remove_dir_all(root)
        .await
        .expect("rollback artifact fixture cleanup");
}

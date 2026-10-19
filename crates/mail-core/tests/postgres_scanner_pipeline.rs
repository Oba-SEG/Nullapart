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
        milter_observations: None,
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

struct FakeInlineRuntime {
    ready: bool,
    probabilities: Vec<f32>,
}

impl nullapart_mail_core::inline_ml::runtime::InlineModelRuntime for FakeInlineRuntime {
    fn ready(&self) -> bool {
        self.ready
    }
    fn representation_version(&self) -> u32 {
        nullapart_mail_core::inline_ml::representation::INLINE_ML_REPRESENTATION_VERSION
    }
    fn identity(&self) -> nullapart_mail_core::inline_ml::runtime::ModelIdentity {
        nullapart_mail_core::inline_ml::runtime::ModelIdentity {
            model_id: "multilabel-v1".to_string(),
            model_version: "1".to_string(),
        }
    }
    fn infer(
        &self,
        _text: &str,
    ) -> Result<
        nullapart_mail_core::inline_ml::runtime::ModelInference,
        nullapart_mail_core::inline_ml::runtime::ModelError,
    > {
        if !self.ready {
            return Err(
                nullapart_mail_core::inline_ml::runtime::ModelError::Unavailable(
                    "fake runtime not ready".to_string(),
                ),
            );
        }
        Ok(nullapart_mail_core::inline_ml::runtime::ModelInference {
            probabilities: self.probabilities.clone(),
        })
    }
}

fn inline_fake_runtime(
    ready: bool,
) -> Arc<dyn nullapart_mail_core::inline_ml::runtime::InlineModelRuntime> {
    Arc::new(FakeInlineRuntime {
        ready,
        probabilities: vec![0.01; nullapart_mail_core::inline_ml::runtime::INLINE_ML_LABELS.len()],
    })
}

fn inline_scored_runtime(
    probabilities: Vec<f32>,
) -> Arc<dyn nullapart_mail_core::inline_ml::runtime::InlineModelRuntime> {
    Arc::new(FakeInlineRuntime {
        ready: true,
        probabilities,
    })
}

async fn scanner_result_row(
    pool: &PgPool,
    fixture: &TenantFixture,
    scanner_id: &str,
) -> Option<(String, bool, i64)> {
    let mut transaction = pool.begin().await.expect("assertion transaction");
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(&fixture.customer.0)
        .execute(&mut *transaction)
        .await
        .expect("assertion RLS scope");
    let row = sqlx::query(
        "SELECT status, required, duration_ms FROM scanner_results \
         WHERE tenant_message_id = $1 AND scanner_id = $2",
    )
    .bind(fixture.tenant_message_id.0)
    .bind(scanner_id)
    .fetch_optional(&mut *transaction)
    .await
    .expect("scanner result row");
    transaction.commit().await.expect("assertion commit");
    row.map(|row| {
        (
            row.get("status"),
            row.get("required"),
            row.get("duration_ms"),
        )
    })
}

async fn finding_rows(pool: &PgPool, fixture: &TenantFixture) -> Vec<(String, String)> {
    let mut transaction = pool.begin().await.expect("assertion transaction");
    sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
        .bind(&fixture.customer.0)
        .execute(&mut *transaction)
        .await
        .expect("assertion RLS scope");
    let rows = sqlx::query(
        "SELECT scanner_type, category FROM security_findings \
         WHERE tenant_message_id = $1 ORDER BY created_at",
    )
    .bind(fixture.tenant_message_id.0)
    .fetch_all(&mut *transaction)
    .await
    .expect("finding rows");
    transaction.commit().await.expect("assertion commit");
    rows.into_iter()
        .map(|row| (row.get("scanner_type"), row.get("category")))
        .collect()
}

fn benign_message() -> Vec<u8> {
    b"Content-Type: text/plain\r\n\r\nhello from the tenant\r\n".to_vec()
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql and NULLAPART_TEST_DATABASE_URL"]
async fn inline_ml_stage_merges_pass2_evidence_when_feature_enabled() {
    let database_url = env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must target local test PostgreSQL");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("local PostgreSQL must connect");
    let fixture = seed_tenant(&pool, "allow").await;
    let root = env::temp_dir().join(format!(
        "nullapart-pipeline-inline-on-{}",
        fixture.tenant_message_id.0
    ));
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem store must initialize");
    let stage = nullapart_mail_core::inline_ml::stage::InlineMlStage::with_runtime(
        pool.clone(),
        inline_fake_runtime(true),
    )
    .expect("single inline ml registration must satisfy fabric validation");
    let pipeline = DurableScannerPipeline::new(store, scanner_fabric(), pool.clone())
        .with_inline_ml(Some(Arc::new(stage)));

    let outcome = pipeline
        .process(
            context(&fixture),
            benign_message(),
            ContentType::new("message/rfc822"),
            policy(Disposition::Allow),
        )
        .await
        .expect("durable workflow with inline pass-2 must complete");
    assert_eq!(outcome.disposition, Disposition::Allow);
    assert!(!outcome.quarantine_created);

    let inline_row = scanner_result_row(&pool, &fixture, "inline-ml-classifier")
        .await
        .expect("pass-2 inline scanner result must persist");
    assert_eq!(inline_row.0, "clean", "successful inference records clean");
    assert!(!inline_row.1, "inline stage is an optional scanner");
    assert!(inline_row.2 >= 0, "duration is recorded");

    let findings = finding_rows(&pool, &fixture).await;
    assert!(
        findings.is_empty(),
        "successful inference must not emit policy findings: {findings:?}"
    );
    assert_eq!(
        scoped_counts(&pool, &fixture).await,
        (1, 2, 0, 0, 0, "allow".to_string()),
        "pass-1 and pass-2 scanner rows persist without policy changes"
    );

    tokio::fs::remove_dir_all(root)
        .await
        .expect("artifact fixture cleanup");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql and NULLAPART_TEST_DATABASE_URL"]
async fn milter_spam_evidence_persists_rspamd_row_and_quarantines() {
    let database_url = env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must target local test PostgreSQL");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("local PostgreSQL must connect");
    let fixture = seed_tenant(&pool, "allow").await;
    let root = env::temp_dir().join(format!(
        "nullapart-pipeline-milter-spam-{}",
        fixture.tenant_message_id.0
    ));
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem store must initialize");
    let pipeline = DurableScannerPipeline::new(store, scanner_fabric(), pool.clone());

    let mut context = context(&fixture);
    context.milter_observations = Some(nullapart_mail_core::handoff::MilterObservations {
        score: 7.41,
        actions: vec!["add header".to_string()],
        is_spam: true,
        dkim_result: Some("pass".to_string()),
        spf_result: Some("fail".to_string()),
        dmarc_result: Some("quarantine".to_string()),
        symbols: vec!["SUBJ_ALL_CAPS".to_string(), "R_SPF_FAIL".to_string()],
        latency_ms: 0,
    });
    let outcome = pipeline
        .process_with_policy(
            context,
            benign_message(),
            ContentType::new("message/rfc822"),
            move |scan| {
                nullapart_mail_core::phase2_handoff::local_finding_policy(
                    scan,
                    PolicyRevisionId::new(),
                )
            },
        )
        .await
        .expect("durable workflow with milter evidence must complete");
    assert_eq!(outcome.disposition, Disposition::Quarantine);
    assert!(outcome.quarantine_created);

    let rspamd_row = scanner_result_row(&pool, &fixture, "rspamd")
        .await
        .expect("rspamd evidence row must persist");
    assert_eq!(rspamd_row.0, "threat");
    assert!(!rspamd_row.1, "milter evidence is an optional scanner");

    let findings = finding_rows(&pool, &fixture).await;
    assert_eq!(
        findings,
        vec![("rspamd".to_string(), "spam".to_string())],
        "spam finding persisted under the rspamd scanner type"
    );

    tokio::fs::remove_dir_all(root)
        .await
        .expect("artifact fixture cleanup");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql and NULLAPART_TEST_DATABASE_URL"]
async fn inline_ml_stage_skips_when_deployment_override_disables_feature() {
    let database_url = env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must target local test PostgreSQL");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("local PostgreSQL must connect");
    let fixture = seed_tenant(&pool, "allow").await;

    let mut transaction = pool.begin().await.expect("override transaction");
    sqlx::query("SELECT set_config('app.current_deployment_id', $1, true), set_config('app.current_customer_id', $2, true)")
        .bind(&fixture.deployment.0)
        .bind(&fixture.customer.0)
        .execute(&mut *transaction)
        .await
        .expect("override RLS scope");
    sqlx::query(
        "INSERT INTO feature_overrides \
            (feature_id, scope, scope_id, value, owner, reason, revision) \
         VALUES ('inline_ml_classification', 'deployment', $1, 'disabled', \
                 'integration-test', 'deployment override off', 1)",
    )
    .bind(&fixture.deployment.0)
    .execute(&mut *transaction)
    .await
    .expect("deployment feature override must insert");
    transaction.commit().await.expect("override commit");

    let root = env::temp_dir().join(format!(
        "nullapart-pipeline-inline-off-{}",
        fixture.tenant_message_id.0
    ));
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem store must initialize");
    let stage = nullapart_mail_core::inline_ml::stage::InlineMlStage::with_runtime(
        pool.clone(),
        inline_fake_runtime(true),
    )
    .expect("single inline ml registration must satisfy fabric validation");
    let pipeline = DurableScannerPipeline::new(store, scanner_fabric(), pool.clone())
        .with_inline_ml(Some(Arc::new(stage)));

    let outcome = pipeline
        .process(
            context(&fixture),
            benign_message(),
            ContentType::new("message/rfc822"),
            policy(Disposition::Allow),
        )
        .await
        .expect("durable workflow must complete with stage skipped");
    assert_eq!(outcome.disposition, Disposition::Allow);
    assert!(
        scanner_result_row(&pool, &fixture, "inline-ml-classifier")
            .await
            .is_none(),
        "disabled feature must skip pass-2 entirely"
    );
    assert_eq!(
        scoped_counts(&pool, &fixture).await,
        (1, 1, 0, 0, 0, "allow".to_string()),
        "only pass-1 evidence persists when the switch is off"
    );

    tokio::fs::remove_dir_all(root)
        .await
        .expect("artifact fixture cleanup");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql and NULLAPART_TEST_DATABASE_URL"]
async fn inline_ml_stage_unavailable_runtime_surfaces_explicit_unknown_failure() {
    let database_url = env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must target local test PostgreSQL");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("local PostgreSQL must connect");
    let fixture = seed_tenant(&pool, "allow").await;
    let root = env::temp_dir().join(format!(
        "nullapart-pipeline-inline-unavailable-{}",
        fixture.tenant_message_id.0
    ));
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem store must initialize");
    let stage = nullapart_mail_core::inline_ml::stage::InlineMlStage::with_runtime(
        pool.clone(),
        inline_fake_runtime(false),
    )
    .expect("single inline ml registration must satisfy fabric validation");
    let pipeline = DurableScannerPipeline::new(store, scanner_fabric(), pool.clone())
        .with_inline_ml(Some(Arc::new(stage)));

    let outcome = pipeline
        .process(
            context(&fixture),
            benign_message(),
            ContentType::new("message/rfc822"),
            policy(Disposition::Allow),
        )
        .await
        .expect("durable workflow must complete with unavailable runtime");
    assert_eq!(
        outcome.disposition,
        Disposition::Allow,
        "optional pass-2 failure never forces a hold on its own"
    );

    let inline_row = scanner_result_row(&pool, &fixture, "inline-ml-classifier")
        .await
        .expect("failed pass-2 attempt must still record evidence");
    assert_eq!(
        inline_row.0, "unknown",
        "unavailable runtime records unknown status, never clean"
    );

    let findings = finding_rows(&pool, &fixture).await;
    assert_eq!(
        findings,
        vec![("inline_ml".to_string(), "unknown".to_string())],
        "failure becomes explicit Unknown evidence, never a clean result"
    );
    assert_eq!(
        scoped_counts(&pool, &fixture).await,
        (1, 2, 1, 0, 0, "allow".to_string())
    );

    tokio::fs::remove_dir_all(root)
        .await
        .expect("artifact fixture cleanup");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 014_policy_administration.sql and NULLAPART_TEST_DATABASE_URL"]
async fn inline_ml_scores_become_findings_and_quarantine_via_local_policy() {
    let database_url = env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must target local test PostgreSQL");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("local PostgreSQL must connect");
    let fixture = seed_tenant(&pool, "allow").await;

    // Publish the threshold policy for this exact scope: one active
    // tenant revision of ml_threat_classification with operating points.
    let rules = serde_json::json!([
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "name": "inline ml operating points",
            "priority": 10,
            "condition": { "scope": "transaction" },
            "action": {
                "disposition": "quarantine",
                "reason_code": "QUARANTINE_MALWARE",
                "metadata": {
                    "thresholds": {
                        "version": 1,
                        "classes": {
                            "malware": { "low": 0.4, "medium": 0.7, "high": 0.9 }
                        }
                    }
                }
            },
            "enabled": true
        }
    ]);
    let mut transaction = pool.begin().await.expect("thresholds transaction");
    sqlx::query(
        "INSERT INTO policy_revisions \
            (id, deployment_id, customer_id, family_id, scope_level, revision_number, \
             rules, published_by, published_at, activated_at) \
         VALUES ($1, $2, $3, 'ml_threat_classification', 'tenant', 1, $4, \
                 'integration-test', now(), now())",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(&fixture.deployment.0)
    .bind(&fixture.customer.0)
    .bind(rules)
    .execute(&mut *transaction)
    .await
    .expect("threshold revision must insert");
    transaction.commit().await.expect("thresholds commit");

    // Malware score 0.96 is above the high operating point of 0.9.
    let mut scores = vec![0.01; nullapart_mail_core::inline_ml::runtime::INLINE_ML_LABELS.len()];
    scores[0] = 0.96;
    let root = env::temp_dir().join(format!(
        "nullapart-pipeline-inline-policy-{}",
        fixture.tenant_message_id.0
    ));
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem store must initialize");
    let stage = nullapart_mail_core::inline_ml::stage::InlineMlStage::with_runtime(
        pool.clone(),
        inline_scored_runtime(scores),
    )
    .expect("single inline ml registration must satisfy fabric validation");
    let pipeline = DurableScannerPipeline::new(store, scanner_fabric(), pool.clone())
        .with_inline_ml(Some(Arc::new(stage)));

    // The real production consequence: the reviewed local finding policy
    // that mailcore applies after scanning.
    let outcome = pipeline
        .process_with_policy(
            context(&fixture),
            benign_message(),
            ContentType::new("message/rfc822"),
            |scan| {
                nullapart_mail_core::phase2_handoff::local_finding_policy(
                    scan,
                    PolicyRevisionId::new(),
                )
            },
        )
        .await
        .expect("durable workflow with thresholds must complete");
    assert_eq!(
        outcome.disposition,
        Disposition::Quarantine,
        "a finding above threshold must quarantine through local policy"
    );
    assert!(outcome.quarantine_created);

    let inline_row = scanner_result_row(&pool, &fixture, "inline-ml-classifier")
        .await
        .expect("pass-2 inline scanner result must persist");
    assert_eq!(
        inline_row.0, "threat",
        "the fabric escalates definite findings in the scanner row"
    );

    let findings = finding_rows(&pool, &fixture).await;
    assert_eq!(
        findings,
        vec![("inline_ml".to_string(), "malware".to_string())],
        "the above-threshold score becomes exactly one normalized finding"
    );

    let (severity, band, score): (String, String, f64) = sqlx::query_as(
        "SELECT severity, details ->> 'band', (details ->> 'score')::float8 \
         FROM security_findings WHERE tenant_message_id = $1",
    )
    .bind(fixture.tenant_message_id.0)
    .fetch_one(&pool)
    .await
    .expect("finding detail must persist");
    assert_eq!(severity, "high", "band severity rides the finding");
    assert_eq!(band, "high");
    assert!(
        (score - 0.96).abs() < 1e-6,
        "score must round-trip: {score}"
    );

    assert_eq!(
        scoped_counts(&pool, &fixture).await,
        (1, 2, 1, 1, 1, "quarantine".to_string()),
        "artifact, both scanner rows, the finding, quarantine, envelope and disposition persist"
    );

    tokio::fs::remove_dir_all(root)
        .await
        .expect("artifact fixture cleanup");
}

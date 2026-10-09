//! Local PostgreSQL coverage for Phase 5 DMARC report ingress worker.
//!
//! Requires PostgreSQL migrated through `023_dmarc_report_ingress_jobs.sql`
//! with `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_dmarc_ingress -- --ignored`.

use chrono::Utc;
use nullapart_mail_contracts::artifact::{
    Artifact, ArtifactHash, ArtifactId, ContentType, HashAlgorithm, RetentionClass, StorageBackend,
    StorageLocation,
};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId, TenantMessageId};
use nullapart_mail_core::artifact_store::{FilesystemArtifactRuntime, FilesystemArtifactStore};
use nullapart_mail_core::dmarc_ingress::{
    enqueue_dmarc_report_artifact, DmarcReportIngressConfig, DmarcReportIngressRunOutcome,
    DmarcReportIngressWorker,
};
use nullapart_mail_core::dmarc_mailbox_ingress::ingest_dmarc_report_mailbox_message;
use sha2::Digest;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
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

async fn seed_verified_domain(pool: &PgPool, suffix: &str) -> (DeploymentId, CustomerId, String) {
    let deployment_id = DeploymentId::new(&format!("phase5-ingress-{suffix}"));
    let customer_id = CustomerId::new(&format!("C-PHASE5-INGRESS-{suffix}"));
    let policy_domain = format!("ingress-{suffix}.example.test");
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name, lifecycle) \
         VALUES ($1, 'za', $2, 'active')",
    )
    .bind(&deployment_id.0)
    .bind(format!("Phase 5 Ingress {suffix}"))
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind(&customer_id.0)
    .bind(&deployment_id.0)
    .bind(format!("Phase 5 Ingress Customer {suffix}"))
    .execute(pool)
    .await
    .expect("customer fixture must insert");
    sqlx::query(
        "INSERT INTO domains (customer_id, domain, verification_status, verified_at) \
         VALUES ($1, $2, 'verified', now())",
    )
    .bind(&customer_id.0)
    .bind(&policy_domain)
    .execute(pool)
    .await
    .expect("verified domain fixture must insert");
    (deployment_id, customer_id, policy_domain)
}

fn aggregate_xml(policy_domain: &str, report_id: &str) -> Vec<u8> {
    format!(
        r#"<feedback>
  <report_metadata>
    <org_name>Reporter Inc</org_name>
    <report_id>{report_id}</report_id>
    <date_range><begin>1767139200</begin><end>1767225600</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>{policy_domain}</domain>
    <adkim>r</adkim>
    <aspf>s</aspf>
    <p>quarantine</p>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.90</source_ip>
      <count>7</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>{policy_domain}</header_from>
      <envelope_from>{policy_domain}</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>{policy_domain}</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>{policy_domain}</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"#
    )
    .into_bytes()
}

async fn store_report_artifact(
    pool: &PgPool,
    store: &FilesystemArtifactStore,
    deployment_id: &DeploymentId,
    customer_id: &CustomerId,
    bytes: Vec<u8>,
) -> ArtifactId {
    let artifact_id = ArtifactId(Uuid::new_v4());
    let hash = hex::encode(sha2::Sha256::digest(&bytes));
    let artifact = Artifact {
        id: artifact_id.clone(),
        deployment_id: deployment_id.clone(),
        customer_id: Some(customer_id.clone()),
        content_type: ContentType::new("application/xml"),
        size: bytes.len() as u64,
        storage_location: StorageLocation {
            backend: StorageBackend::Filesystem,
            bucket: None,
            key: format!("{}.artifact", artifact_id.0),
            region: None,
        },
        hash: ArtifactHash {
            algorithm: HashAlgorithm::Sha256,
            value: hash.clone(),
        },
        retention_class: RetentionClass::Standard,
        created_at: Utc::now(),
        expires_at: None,
        encrypted: false,
        scanner_eligible: false,
    };
    store
        .put(artifact.clone(), bytes)
        .await
        .expect("report artifact bytes must store");
    sqlx::query(
        "INSERT INTO artifacts \
            (id, deployment_id, customer_id, content_type, size_bytes, content_hash, \
             storage_backend, storage_path, retention_class, encryption_enabled, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,'filesystem',$7,'standard',false,$8)",
    )
    .bind(artifact_id.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(&artifact.content_type.0)
    .bind(artifact.size as i64)
    .bind(format!("sha256:{hash}"))
    .bind(&artifact.storage_location.key)
    .bind(artifact.created_at)
    .execute(pool)
    .await
    .expect("artifact row must insert");
    artifact_id
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 023_dmarc_report_ingress_jobs.sql"]
async fn ingress_worker_processes_artifact_once_and_marks_replay_duplicate() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (deployment_id, customer_id, policy_domain) = seed_verified_domain(&pool, &suffix).await;
    let root = std::env::temp_dir().join(format!("nullapart-dmarc-ingress-{suffix}"));
    std::fs::create_dir_all(&root).expect("artifact root must exist");
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem artifact store must start");
    let xml = aggregate_xml(&policy_domain, &format!("report-{suffix}"));
    let artifact_id = store_report_artifact(&pool, &store, &deployment_id, &customer_id, xml).await;

    let first_job = enqueue_dmarc_report_artifact(
        &pool,
        &deployment_id,
        &customer_id,
        &artifact_id,
        &format!("first-{suffix}"),
    )
    .await
    .expect("first ingress job must enqueue");
    let replay_job = enqueue_dmarc_report_artifact(
        &pool,
        &deployment_id,
        &customer_id,
        &artifact_id,
        &format!("replay-{suffix}"),
    )
    .await
    .expect("replay ingress job must enqueue");

    let worker = DmarcReportIngressWorker::new(
        pool.clone(),
        store.clone(),
        deployment_id.clone(),
        DmarcReportIngressConfig::default(),
    );

    let first = worker.run_once().await.expect("first run must succeed");
    assert!(matches!(
        first,
        DmarcReportIngressRunOutcome::Inserted {
            job_id,
            records_inserted: 1,
            ..
        } if job_id == first_job
    ));
    let second = worker.run_once().await.expect("second run must succeed");
    assert!(matches!(
        second,
        DmarcReportIngressRunOutcome::Duplicate { job_id, .. } if job_id == replay_job
    ));

    let statuses: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM dmarc_report_ingress_jobs \
         WHERE id IN ($1, $2) ORDER BY created_at",
    )
    .bind(first_job)
    .bind(replay_job)
    .fetch_all(&pool)
    .await
    .expect("job statuses must be readable");
    assert_eq!(statuses, vec!["succeeded", "duplicate"]);

    let reports: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM dmarc_aggregate_reports WHERE deployment_id = $1",
    )
    .bind(&deployment_id.0)
    .fetch_one(&pool)
    .await
    .expect("report count must be readable");
    assert_eq!(reports, 1);

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 023_dmarc_report_ingress_jobs.sql"]
async fn ingress_worker_dead_letters_unreadable_artifacts_without_starving_queue() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (deployment_id, customer_id, _policy_domain) = seed_verified_domain(&pool, &suffix).await;
    let root = std::env::temp_dir().join(format!("nullapart-dmarc-ingress-missing-{suffix}"));
    std::fs::create_dir_all(&root).expect("artifact root must exist");
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem artifact store must start");
    let missing_artifact = ArtifactId(Uuid::new_v4());
    sqlx::query(
        "INSERT INTO artifacts \
            (id, deployment_id, customer_id, content_type, size_bytes, content_hash, \
             storage_backend, storage_path, retention_class, encryption_enabled, created_at) \
         VALUES ($1,$2,$3,'application/xml',12,$4,'filesystem',$5,'standard',false,now())",
    )
    .bind(missing_artifact.0)
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(format!("sha256:{}", "a".repeat(64)))
    .bind(format!("{}.artifact", missing_artifact.0))
    .execute(&pool)
    .await
    .expect("missing artifact metadata row must insert");
    let job = enqueue_dmarc_report_artifact(
        &pool,
        &deployment_id,
        &customer_id,
        &missing_artifact,
        &format!("missing-{suffix}"),
    )
    .await
    .expect("missing artifact job must enqueue");

    let worker = DmarcReportIngressWorker::new(
        pool.clone(),
        store,
        deployment_id.clone(),
        DmarcReportIngressConfig {
            max_attempts: 1,
            ..DmarcReportIngressConfig::default()
        },
    );

    let outcome = worker.run_once().await.expect("worker must terminalize");
    assert_eq!(
        outcome,
        DmarcReportIngressRunOutcome::DeadLettered {
            job_id: job,
            code: "ARTIFACT_UNAVAILABLE"
        }
    );
    assert_eq!(
        worker.run_once().await.expect("queue must be empty"),
        DmarcReportIngressRunOutcome::Idle
    );
    let status: String =
        sqlx::query_scalar("SELECT status FROM dmarc_report_ingress_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(&pool)
            .await
            .expect("status must be readable");
    assert_eq!(status, "dead_lettered");

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 026_dmarc_failure_report_controls.sql"]
async fn ingress_worker_quarantines_failure_reports_without_parsing_restricted_content() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (deployment_id, customer_id, _policy_domain) = seed_verified_domain(&pool, &suffix).await;
    let root = std::env::temp_dir().join(format!("nullapart-dmarc-failure-ingress-{suffix}"));
    std::fs::create_dir_all(&root).expect("artifact root must exist");
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem artifact store must start");
    let failure_report = b"Content-Type: multipart/report; report-type=feedback-report\r\n\
        \r\nContent-Type: message/feedback-report\r\nFeedback-Type: auth-failure\r\n\
        Reported-Domain: example.test\r\nOriginal-Mail-From: sender@example.test\r\n"
        .to_vec();
    let artifact_id =
        store_report_artifact(&pool, &store, &deployment_id, &customer_id, failure_report).await;
    let job = enqueue_dmarc_report_artifact(
        &pool,
        &deployment_id,
        &customer_id,
        &artifact_id,
        &format!("failure-{suffix}"),
    )
    .await
    .expect("failure report job must enqueue");

    let worker = DmarcReportIngressWorker::new(
        pool.clone(),
        store.clone(),
        deployment_id.clone(),
        DmarcReportIngressConfig::default(),
    );

    let outcome = worker.run_once().await.expect("worker must quarantine");
    assert_eq!(
        outcome,
        DmarcReportIngressRunOutcome::Quarantined { job_id: job }
    );

    let job_row =
        sqlx::query("SELECT status, last_error_code FROM dmarc_report_ingress_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(&pool)
            .await
            .expect("job status must be readable");
    assert_eq!(job_row.get::<String, _>("status"), "quarantined");
    assert_eq!(
        job_row.get::<String, _>("last_error_code"),
        "FAILURE_REPORT_FEATURE_DISABLED"
    );

    let quarantine_row = sqlx::query(
        "SELECT reason_code, detail FROM dmarc_failure_report_quarantine \
         WHERE deployment_id = $1 AND customer_id = $2 AND source_artifact_id = $3",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(artifact_id.0)
    .fetch_one(&pool)
    .await
    .expect("failure report quarantine row must be written");
    assert_eq!(
        quarantine_row.get::<String, _>("reason_code"),
        "FAILURE_REPORT_FEATURE_DISABLED"
    );
    assert!(
        !quarantine_row
            .get::<String, _>("detail")
            .contains("Original-Mail-From"),
        "quarantine detail must not store report content"
    );

    let reports: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM dmarc_aggregate_reports WHERE deployment_id = $1",
    )
    .bind(&deployment_id.0)
    .fetch_one(&pool)
    .await
    .expect("aggregate report count must be readable");
    assert_eq!(
        reports, 0,
        "failure reports must not be handed to aggregate ingestion"
    );

    let mut override_transaction = pool.begin().await.expect("override transaction");
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .execute(&mut *override_transaction)
    .await
    .expect("override RLS scope");
    sqlx::query(
        "INSERT INTO feature_overrides \
            (feature_id, scope, scope_id, value, owner, reason, revision) \
         VALUES ('dmarc_failure_reports', 'tenant', $1, 'enabled', \
                 'integration-test', 'exercise missing failure report handler', 1)",
    )
    .bind(&customer_id.0)
    .execute(&mut *override_transaction)
    .await
    .expect("tenant feature override must insert");
    override_transaction
        .commit()
        .await
        .expect("override transaction must commit");

    let folded_failure_report = b"Content-Type: multipart/report;\r\n\
        \treport-type = feedback-report\r\n\r\nContent-Type: message/feedback-report\r\n\
        Feedback-Type:\r\n\tauth-failure\r\nAuth-Failure: dmarc\r\n"
        .to_vec();
    let enabled_artifact = store_report_artifact(
        &pool,
        &store,
        &deployment_id,
        &customer_id,
        folded_failure_report,
    )
    .await;
    let enabled_job = enqueue_dmarc_report_artifact(
        &pool,
        &deployment_id,
        &customer_id,
        &enabled_artifact,
        &format!("failure-enabled-{suffix}"),
    )
    .await
    .expect("enabled failure report job must enqueue");

    let enabled_outcome = worker
        .run_once()
        .await
        .expect("worker must quarantine enabled failure report");
    assert_eq!(
        enabled_outcome,
        DmarcReportIngressRunOutcome::Quarantined {
            job_id: enabled_job
        }
    );
    let enabled_reason: String = sqlx::query_scalar(
        "SELECT reason_code FROM dmarc_failure_report_quarantine \
         WHERE deployment_id = $1 AND customer_id = $2 AND source_artifact_id = $3",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(enabled_artifact.0)
    .fetch_one(&pool)
    .await
    .expect("enabled failure report quarantine row must be written");
    assert_eq!(enabled_reason, "FAILURE_REPORT_HANDLER_UNAVAILABLE");

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 026_dmarc_failure_report_controls.sql"]
async fn mailbox_hook_stores_report_attachment_and_enqueues_ingress_job() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (deployment_id, customer_id, _policy_domain) = seed_verified_domain(&pool, &suffix).await;
    let root = std::env::temp_dir().join(format!("nullapart-dmarc-mailbox-{suffix}"));
    std::fs::create_dir_all(&root).expect("artifact root must exist");
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("filesystem artifact store must start");
    let tenant_message_id = TenantMessageId(Uuid::new_v4());
    let report = aggregate_xml(
        &format!("auth-{suffix}.example.test"),
        &format!("mailbox-{suffix}"),
    );
    let raw_mime = format!(
        "Content-Type: multipart/mixed; boundary=x\r\n\r\n\
         --x\r\nContent-Type: text/plain\r\n\r\nReport attached\r\n\
         --x\r\nContent-Type: application/xml\r\nContent-Disposition: attachment; filename=\"report.xml\"\r\n\r\n{}\r\n\
         --x--\r\n",
        String::from_utf8_lossy(&report)
    );

    let outcome = ingest_dmarc_report_mailbox_message(
        &pool,
        &store,
        &deployment_id,
        &customer_id,
        &tenant_message_id,
        raw_mime.as_bytes(),
    )
    .await
    .expect("mailbox hook must enqueue report");
    assert_eq!(outcome.queued, 1);
    assert_eq!(outcome.skipped_oversize, 0);

    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM dmarc_report_ingress_jobs \
         WHERE deployment_id = $1 AND source_customer_id = $2",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .fetch_one(&pool)
    .await
    .expect("job count must be readable");
    assert_eq!(queued, 1);

    let artifacts: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM artifacts \
         WHERE deployment_id = $1 AND customer_id = $2 AND content_type = 'application/xml'",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .fetch_one(&pool)
    .await
    .expect("artifact count must be readable");
    assert_eq!(artifacts, 1);

    let _ = std::fs::remove_dir_all(root);
}

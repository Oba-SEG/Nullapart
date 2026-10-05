//! Local PostgreSQL coverage for Phase 5 DMARC aggregate persistence.
//!
//! Requires PostgreSQL migrated through `021_dmarc_aggregate_reports.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_dmarc_aggregate -- --ignored`.

use nullapart_mail_contracts::transaction::DeploymentId;
use nullapart_mail_core::dmarc_aggregate::{
    DmarcAggregateIngestStatus, DmarcAggregateLimits, DmarcAggregateSource, DmarcReportCompression,
    PostgresDmarcAggregateIngestor,
};
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
        .expect("role setup transaction must start");
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
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nullapart_local_request",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nullapart_local_request",
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO nullapart_local_request",
    ] {
        sqlx::query(grant)
            .execute(&mut *transaction)
            .await
            .expect("request role grant must apply");
    }
    transaction.commit().await.expect("role setup must commit");
}

async fn begin_scoped<'a>(
    pool: &'a PgPool,
    deployment_id: &str,
    customer_id: &str,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("scoped transaction must start");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("request role must be assumable");
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .execute(&mut *transaction)
    .await
    .expect("tenant scope must be set");
    transaction
}

async fn seed_verified_domain(pool: &PgPool, suffix: &str) -> (String, String, String) {
    let deployment_id = format!("phase5-{suffix}");
    let customer_id = format!("C-PHASE5-{suffix}");
    let policy_domain = format!("phase5-{suffix}.example.test");
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name, lifecycle) \
         VALUES ($1, 'za', $2, 'active')",
    )
    .bind(&deployment_id)
    .bind(format!("Phase 5 {suffix}"))
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind(&customer_id)
    .bind(&deployment_id)
    .bind(format!("Phase 5 Customer {suffix}"))
    .execute(pool)
    .await
    .expect("customer fixture must insert");
    sqlx::query(
        "INSERT INTO domains (customer_id, domain, verification_status, verified_at) \
         VALUES ($1, $2, 'verified', now())",
    )
    .bind(&customer_id)
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
      <source_ip>203.0.113.10</source_ip>
      <count>4</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>{policy_domain}</header_from>
      <envelope_from>{policy_domain}</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>{policy_domain}</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>{policy_domain}</domain><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>"#
    )
    .into_bytes()
}

fn source_for(input: &[u8]) -> DmarcAggregateSource {
    DmarcAggregateSource {
        artifact_id: None,
        artifact_hash: None,
        compressed_size_bytes: input.len() as u64,
    }
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 021_dmarc_aggregate_reports.sql"]
async fn aggregate_ingestion_is_idempotent_and_tenant_scoped() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (deployment_id, customer_id, policy_domain) = seed_verified_domain(&pool, &suffix).await;
    let ingestor =
        PostgresDmarcAggregateIngestor::new(pool.clone(), DeploymentId(deployment_id.clone()));
    let xml = aggregate_xml(&policy_domain, &format!("report-{suffix}"));
    let limits = DmarcAggregateLimits::default();

    let first = ingestor
        .ingest_bytes(&xml, DmarcReportCompression::Xml, &limits, source_for(&xml))
        .await
        .expect("first ingest must succeed");
    assert_eq!(first.status, DmarcAggregateIngestStatus::Inserted);
    assert_eq!(first.records_inserted, 1);
    let report_row_id = first.report_row_id.expect("inserted report id");

    let replay = ingestor
        .ingest_bytes(&xml, DmarcReportCompression::Xml, &limits, source_for(&xml))
        .await
        .expect("duplicate ingest must succeed");
    assert_eq!(replay.status, DmarcAggregateIngestStatus::Duplicate);
    assert_eq!(replay.report_row_id, Some(report_row_id));
    assert_eq!(replay.records_inserted, 0);

    let record_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM dmarc_aggregate_records WHERE report_id = $1",
    )
    .bind(report_row_id)
    .fetch_one(&pool)
    .await
    .expect("record count must be readable");
    assert_eq!(record_count, 1);

    let mut same_customer = begin_scoped(&pool, &deployment_id, &customer_id).await;
    let visible: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM dmarc_aggregate_reports")
        .fetch_one(&mut *same_customer)
        .await
        .expect("scoped report count must be readable");
    assert_eq!(visible, 1);
    same_customer
        .commit()
        .await
        .expect("same-customer transaction must commit");

    let mut other_customer = begin_scoped(&pool, &deployment_id, "C-PHASE5-OTHER").await;
    let hidden: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM dmarc_aggregate_reports")
        .fetch_one(&mut *other_customer)
        .await
        .expect("cross-tenant report count must be readable");
    assert_eq!(hidden, 0);
    other_customer
        .commit()
        .await
        .expect("other-customer transaction must commit");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 021_dmarc_aggregate_reports.sql"]
async fn unmapped_policy_domain_is_quarantined_without_records() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("phase5-unmapped-{suffix}");
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name, lifecycle) \
         VALUES ($1, 'za', $2, 'active')",
    )
    .bind(&deployment_id)
    .bind(format!("Phase 5 Unmapped {suffix}"))
    .execute(&pool)
    .await
    .expect("deployment fixture must insert");
    let ingestor =
        PostgresDmarcAggregateIngestor::new(pool.clone(), DeploymentId(deployment_id.clone()));
    let xml = aggregate_xml(
        &format!("unmapped-{suffix}.example.test"),
        &format!("report-{suffix}"),
    );

    let outcome = ingestor
        .ingest_bytes(
            &xml,
            DmarcReportCompression::Xml,
            &DmarcAggregateLimits::default(),
            source_for(&xml),
        )
        .await
        .expect("unmapped ingest must quarantine");

    assert_eq!(outcome.status, DmarcAggregateIngestStatus::Quarantined);
    assert_eq!(outcome.report_row_id, None);
    assert_eq!(outcome.records_inserted, 0);

    let error_code: String = sqlx::query_scalar(
        "SELECT error_code FROM dmarc_report_quarantine WHERE deployment_id = $1",
    )
    .bind(&deployment_id)
    .fetch_one(&pool)
    .await
    .expect("quarantine row must exist");
    assert_eq!(error_code, "domain_unmapped");
}

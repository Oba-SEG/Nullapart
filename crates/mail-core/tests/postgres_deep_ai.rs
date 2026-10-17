//! Local PostgreSQL coverage for Phase 7 Deep AI storage and access control.
//!
//! Requires PostgreSQL migrated through `030_deep_ai.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_deep_ai -- --ignored --test-threads=1`.

use chrono::Utc;
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
        "GRANT SELECT, INSERT, UPDATE, DELETE ON deep_ai_skills TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON deep_ai_model_releases TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON deep_ai_regional_benchmarks TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON deep_ai_training_datasets TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON deep_ai_artifact_access_grants TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON deep_ai_analysis_results TO nullapart_local_request",
    ] {
        sqlx::query(grant)
            .execute(&mut *transaction)
            .await
            .expect("grant must apply");
    }
    transaction.commit().await.expect("role setup must commit");
}

async fn begin_request<'a>(
    pool: &'a PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("transaction must begin");
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
        .expect("scope must be established");
    }
    transaction
}

async fn begin_owner_scoped<'a>(
    pool: &'a PgPool,
    deployment: &str,
    customer: &str,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("transaction must begin");
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment)
    .bind(customer)
    .execute(&mut *transaction)
    .await
    .expect("owner scope must be established");
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
    assert!(outcome.is_err(), "statement must be rejected");
}

struct Fixture {
    deployment_a: String,
    deployment_b: String,
    customer_a: String,
    customer_b: String,
    artifact_a: Uuid,
    artifact_b: Uuid,
    grant_a: Uuid,
    grant_b: Uuid,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = Uuid::new_v4().simple().to_string();
    let fixture = Fixture {
        deployment_a: format!("phase7-deep-ai-a-{suffix}"),
        deployment_b: format!("phase7-deep-ai-b-{suffix}"),
        customer_a: format!("phase7-deep-ai-customer-a-{suffix}"),
        customer_b: format!("phase7-deep-ai-customer-b-{suffix}"),
        artifact_a: Uuid::new_v4(),
        artifact_b: Uuid::new_v4(),
        grant_a: Uuid::new_v4(),
        grant_b: Uuid::new_v4(),
    };

    for (deployment, customer, region, label) in [
        (&fixture.deployment_a, &fixture.customer_a, "za", "A"),
        (&fixture.deployment_b, &fixture.customer_b, "eu", "B"),
    ] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(deployment)
        .bind(region)
        .bind(format!("Phase 7 deployment {label}"))
        .execute(pool)
        .await
        .expect("deployment fixture must insert");
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(customer)
        .bind(deployment)
        .bind(format!("Phase 7 customer {label}"))
        .execute(pool)
        .await
        .expect("customer fixture must insert");
    }

    insert_deep_ai_rows(
        pool,
        &fixture.deployment_a,
        &fixture.customer_a,
        fixture.artifact_a,
        fixture.grant_a,
    )
    .await;
    insert_deep_ai_rows(
        pool,
        &fixture.deployment_b,
        &fixture.customer_b,
        fixture.artifact_b,
        fixture.grant_b,
    )
    .await;
    fixture
}

async fn insert_deep_ai_rows(
    pool: &PgPool,
    deployment: &str,
    customer: &str,
    artifact_id: Uuid,
    grant_id: Uuid,
) {
    let mut transaction = begin_owner_scoped(pool, deployment, customer).await;
    sqlx::query(
        "INSERT INTO artifacts \
            (id, deployment_id, customer_id, content_type, size_bytes, content_hash, storage_backend, storage_path) \
         VALUES ($1,$2,$3,'message/rfc822',512,'sha256:phase7','s3','phase7/test.eml')",
    )
    .bind(artifact_id)
    .bind(deployment)
    .bind(customer)
    .execute(&mut *transaction)
    .await
    .expect("artifact must insert");

    sqlx::query(
        "INSERT INTO deep_ai_skills \
            (deployment_id, skill_id, skill_version, owner, purpose, allowed_data_classes, allowed_tools, \
             max_input_tokens, max_output_tokens, max_artifacts, timeout_ms, concurrency_limit, \
             model_requirement, prompt_template_version, input_schema_version, output_schema_version, \
             evaluation_suite_version, release_state, created_by) \
         VALUES ($1,'security.message.deep_analysis','v1','security-platform', \
             'Analyze eligible messages with scoped Deep AI evidence.', \
             ARRAY['quarantined'], ARRAY['artifact.retrieve'], 32768, 2048, 8, 120000, 4, \
             'openai-compatible', 'prompt-v1', 'input-v1', 'output-v1', 'eval-v1', 'released', 'test') \
         ON CONFLICT DO NOTHING",
    )
    .bind(deployment)
    .execute(&mut *transaction)
    .await
    .expect("skill must insert");

    sqlx::query(
        "INSERT INTO deep_ai_model_releases \
            (deployment_id, region, model_release, backend, serving_base_url, quantization, \
             context_window, approval_state, approved_by, approved_at) \
         VALUES ($1,'za','local-qwen3.5-9b-phase7','ollama','http://127.0.0.1:11434/v1', \
             'q4_local_dev', 32768, 'approved', 'test', now()) \
         ON CONFLICT DO NOTHING",
    )
    .bind(deployment)
    .execute(&mut *transaction)
    .await
    .expect("model release must insert");

    sqlx::query(
        "INSERT INTO deep_ai_artifact_access_grants \
            (id, deployment_id, customer_id, artifact_id, resource_type, purpose, skill_id, \
             skill_version, artifact_type, expires_at, created_by, trace_id) \
         VALUES ($1,$2,$3,$4,'reported_phishing','security_analysis', \
             'security.message.deep_analysis','v1','message_rfc822', now() + interval '30 minutes', \
             'test', 'trace-phase7')",
    )
    .bind(grant_id)
    .bind(deployment)
    .bind(customer)
    .bind(artifact_id)
    .execute(&mut *transaction)
    .await
    .expect("artifact grant must insert");

    sqlx::query(
        "INSERT INTO deep_ai_analysis_results \
            (deployment_id, customer_id, skill_id, skill_version, model_release, artifact_grant_id, \
             classification, attack_type, severity, confidence, evidence_references, observations, \
             recommended_action, analyst_summary, processing_duration_ms, validation_state) \
         VALUES ($1,$2,'security.message.deep_analysis','v1','local-qwen3.5-9b-phase7',$3, \
             'malicious','phishing','high',0.91,$4,'[\"credential lure\"]'::jsonb, \
             'quarantine','Deep AI found trusted evidence for a credential lure.', 1200, 'valid')",
    )
    .bind(deployment)
    .bind(customer)
    .bind(grant_id)
    .bind(serde_json::json!([format!("grant:{grant_id}")]))
    .execute(&mut *transaction)
    .await
    .expect("analysis result must insert");

    transaction.commit().await.expect("fixture must commit");
}

async fn count_as_request(
    pool: &PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
    table: &str,
) -> i64 {
    let mut transaction = begin_request(pool, deployment, customer).await;
    let query = format!("SELECT count(*) FROM {table}");
    let count = sqlx::query_scalar::<_, i64>(&query)
        .fetch_one(&mut *transaction)
        .await
        .expect("count must run");
    transaction.commit().await.expect("count must commit");
    count
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 030_deep_ai.sql"]
async fn deep_ai_tables_fail_closed_and_isolate_by_tenant() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    assert_eq!(
        count_as_request(&pool, None, None, "deep_ai_artifact_access_grants").await,
        0
    );
    assert_eq!(
        count_as_request(
            &pool,
            Some(&fixture.deployment_a),
            Some(&fixture.customer_a),
            "deep_ai_artifact_access_grants",
        )
        .await,
        1
    );
    assert_eq!(
        count_as_request(
            &pool,
            Some(&fixture.deployment_b),
            Some(&fixture.customer_b),
            "deep_ai_analysis_results",
        )
        .await,
        1
    );
    assert_eq!(
        count_as_request(
            &pool,
            Some(&fixture.deployment_a),
            Some(&fixture.customer_a),
            "deep_ai_analysis_results",
        )
        .await,
        1
    );

    let mut transaction = begin_request(
        &pool,
        Some(&fixture.deployment_a),
        Some(&fixture.customer_a),
    )
    .await;
    expect_rejected(
        &mut transaction,
        sqlx::query(
            "INSERT INTO deep_ai_artifact_access_grants \
                (deployment_id, customer_id, artifact_id, resource_type, purpose, skill_id, \
                 skill_version, artifact_type, expires_at, created_by) \
             VALUES ($1,$2,$3,'reported_phishing','security_analysis', \
                 'security.message.deep_analysis','v1','message_rfc822', now() + interval '10 minutes', 'attacker')",
        )
        .bind(&fixture.deployment_a)
        .bind(&fixture.customer_b)
        .bind(fixture.artifact_b),
    )
    .await;
    transaction
        .rollback()
        .await
        .expect("transaction must roll back");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 030_deep_ai.sql"]
async fn artifact_grant_rejects_unknown_skill_version() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let mut transaction = begin_request(
        &pool,
        Some(&fixture.deployment_a),
        Some(&fixture.customer_a),
    )
    .await;
    expect_rejected(
        &mut transaction,
        sqlx::query(
            "INSERT INTO deep_ai_artifact_access_grants \
                (deployment_id, customer_id, artifact_id, resource_type, purpose, skill_id, \
                 skill_version, artifact_type, expires_at, created_by) \
             VALUES ($1,$2,$3,'reported_phishing','security_analysis', \
                 'security.message.deep_analysis','v99','message_rfc822', \
                 now() + interval '10 minutes', 'attacker')",
        )
        .bind(&fixture.deployment_a)
        .bind(&fixture.customer_a)
        .bind(fixture.artifact_a),
    )
    .await;
    transaction
        .rollback()
        .await
        .expect("transaction must roll back");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 030_deep_ai.sql"]
async fn grant_revocation_is_all_or_nothing_and_stays_inside_the_tenant() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let reason = "the incident closed and no further analysis is needed";

    // A revocation without a reason is not a revocation. The table forbids the
    // part-filled triple, so no grant can end with no recorded explanation.
    let mut partial = begin_request(
        &pool,
        Some(&fixture.deployment_a),
        Some(&fixture.customer_a),
    )
    .await;
    expect_rejected(
        &mut partial,
        sqlx::query(
            "UPDATE deep_ai_artifact_access_grants \
             SET revoked_at = now(), revoked_by = 'tester' \
             WHERE id = $1",
        )
        .bind(fixture.grant_a),
    )
    .await;
    partial
        .rollback()
        .await
        .expect("partial revocation transaction must roll back");

    // The statement the revoke route runs, replayed under a different tenant,
    // affects nothing: the row-level policy, not the WHERE clause, is what stops
    // one customer ending another customer's grant.
    let mut other = begin_request(
        &pool,
        Some(&fixture.deployment_b),
        Some(&fixture.customer_b),
    )
    .await;
    let foreign = sqlx::query(
        "UPDATE deep_ai_artifact_access_grants \
         SET revoked_at = now(), revoked_by = $2, revoke_reason = $3 \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(fixture.grant_a)
    .bind("attacker")
    .bind(reason)
    .execute(&mut *other)
    .await
    .expect("statement must run under the request role")
    .rows_affected();
    assert_eq!(foreign, 0, "another tenant must not be able to revoke");
    other
        .rollback()
        .await
        .expect("cross-tenant transaction must roll back");

    // Under the owning scope the same statement stamps the whole triple.
    let mut owner = begin_request(
        &pool,
        Some(&fixture.deployment_a),
        Some(&fixture.customer_a),
    )
    .await;
    let stamped = sqlx::query(
        "UPDATE deep_ai_artifact_access_grants \
         SET revoked_at = now(), revoked_by = $2, revoke_reason = $3 \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(fixture.grant_a)
    .bind("tester")
    .bind(reason)
    .execute(&mut *owner)
    .await
    .expect("revocation must apply under the owning scope")
    .rows_affected();
    assert_eq!(stamped, 1, "the owning tenant must be able to revoke");
    let recorded = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
            SELECT 1 FROM deep_ai_artifact_access_grants \
            WHERE id = $1 AND revoked_at IS NOT NULL AND revoked_by = 'tester' \
              AND revoke_reason = $2 \
         )",
    )
    .bind(fixture.grant_a)
    .bind(reason)
    .fetch_one(&mut *owner)
    .await
    .expect("revocation stamp must read back");
    assert!(recorded, "the stamp must be the whole triple");
    owner
        .rollback()
        .await
        .expect("owner transaction must roll back");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 040_deep_ai_result_origin.sql"]
async fn result_origin_records_only_a_real_source() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    // The two sources the console and the runtime actually record.
    insert_result_with_origin(&pool, &fixture, Some("administrator"))
        .await
        .expect("console origin must insert");
    insert_result_with_origin(&pool, &fixture, Some("model_runtime"))
        .await
        .expect("runtime origin must insert");
    // A row written before origin tracking existed stays null; nothing backfills
    // a source nobody recorded.
    insert_result_with_origin(&pool, &fixture, None)
        .await
        .expect("null origin must insert");
    // Provenance a caller would like to claim for itself is not a recorded source.
    assert!(
        insert_result_with_origin(&pool, &fixture, Some("model_runtime_self_report"))
            .await
            .is_err()
    );

    // seed() wrote one result for deployment A without an origin.
    assert_eq!(
        count_as_request(
            &pool,
            Some(&fixture.deployment_a),
            Some(&fixture.customer_a),
            "deep_ai_analysis_results",
        )
        .await,
        4
    );
}

async fn insert_result_with_origin(
    pool: &PgPool,
    fixture: &Fixture,
    origin: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut transaction =
        begin_owner_scoped(pool, &fixture.deployment_a, &fixture.customer_a).await;
    let outcome = sqlx::query(
        "INSERT INTO deep_ai_analysis_results \
            (deployment_id, customer_id, skill_id, skill_version, model_release, artifact_grant_id, \
             classification, attack_type, severity, confidence, evidence_references, observations, \
             recommended_action, analyst_summary, processing_duration_ms, validation_state, \
             recorded_by) \
         VALUES ($1,$2,'security.message.deep_analysis','v1','local-qwen3.5-9b-phase7',$3, \
             'malicious','phishing','high',0.91,$4,'[\"credential lure\"]'::jsonb, \
             'quarantine','Origin constraint verification.',1200,'valid',$5)",
    )
    .bind(&fixture.deployment_a)
    .bind(&fixture.customer_a)
    .bind(fixture.grant_a)
    .bind(serde_json::json!([format!("grant:{}", fixture.grant_a)]))
    .bind(origin)
    .execute(&mut *transaction)
    .await;
    match outcome {
        Ok(_) => {
            transaction
                .commit()
                .await
                .expect("origin insert must commit");
            Ok(())
        },
        Err(error) => {
            transaction
                .rollback()
                .await
                .expect("origin rejection must roll back");
            Err(error)
        },
    }
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 030_deep_ai.sql"]
async fn training_governance_and_benchmarks_are_deployment_scoped() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let mut transaction =
        begin_owner_scoped(&pool, &fixture.deployment_a, &fixture.customer_a).await;
    sqlx::query(
        "INSERT INTO deep_ai_training_datasets \
            (deployment_id, dataset_version, region, allowed_data_classes, provenance, labeling_process, \
             approval_state, approved_by, approved_at, deletion_withdrawal_process) \
         VALUES ($1,'phase7-test-dataset','za',ARRAY['reported_phishing'], \
             'curated reported-phishing messages only', 'analyst labels with protected splits', \
             'approved', 'test', now(), 'delete withdrawn records from future datasets')",
    )
    .bind(&fixture.deployment_a)
    .execute(&mut *transaction)
    .await
    .expect("dataset governance record must insert");
    sqlx::query(
        "INSERT INTO deep_ai_regional_benchmarks \
            (deployment_id, region, model_release, accelerator_family, quantization, vram_gb, gpu_count, \
             topology, model_load_seconds, tokens_per_second, concurrent_requests, context_target_tokens, \
             multimodal_supported, availability_notes, failover_notes, cost_per_case_estimate, approved, \
             approval_note, created_by, measured_at) \
         VALUES ($1,'za','local-qwen3.5-9b-phase7','local-dev','q4',8,0,'single node',0,1,1,32768, \
             false, 'local benchmark only', 'mail path independent', 0, true, \
             'approved for local Phase 7 verification', 'test', $2)",
    )
    .bind(&fixture.deployment_a)
    .bind(Utc::now())
    .execute(&mut *transaction)
    .await
    .expect("benchmark record must insert");
    transaction
        .commit()
        .await
        .expect("fixture update must commit");

    assert_eq!(
        count_as_request(
            &pool,
            Some(&fixture.deployment_a),
            Some(&fixture.customer_a),
            "deep_ai_training_datasets",
        )
        .await,
        1
    );
    assert_eq!(
        count_as_request(
            &pool,
            Some(&fixture.deployment_b),
            Some(&fixture.customer_b),
            "deep_ai_training_datasets",
        )
        .await,
        0
    );
    assert_eq!(
        count_as_request(
            &pool,
            Some(&fixture.deployment_a),
            Some(&fixture.customer_a),
            "deep_ai_regional_benchmarks",
        )
        .await,
        1
    );
}

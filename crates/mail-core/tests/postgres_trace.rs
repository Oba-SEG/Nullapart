//! Local PostgreSQL coverage for the Phase 3 increment 8 mail trace API.
//!
//! Requires PostgreSQL migrated through `004_scanner_evidence.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Every test is `#[ignore]`d so
//! the default suite stays offline; run them explicitly with
//! `cargo test --test postgres_trace -- --ignored`.
//!
//! 1. **Workload surface**: the bearer-authenticated projection only reports the
//!    configured deployment's transactions, counts recipients, and never leaks
//!    another deployment's transaction through the detail route.
//! 2. **Session search**: the customer scope comes from the session context, so
//!    each caller only sees transactions that carry one of its tenant message
//!    instances and only that customer's instance projection.
//! 3. **Session detail**: instances, delivery attempts and security findings are
//!    projected for the owning customer, `smtp_code` is stringified for the
//!    contract, an unseen transaction is 404, and the platform's own identifiers
//!    (deployment, content hash, MTA queue ids, trace id) only appear for a
//!    platform seat.
//! 4. **Content success**: a `trace:content` reader receives the stored MIME
//!    projection and the access is audited as `success`.
//! 5. **Content denials**: missing permission, cross-customer ownership, a
//!    transaction without a stored artifact and missing artifact bytes are all
//!    4xx answers with a `denied` audit row that never records message bytes.

use std::path::PathBuf;

use axum::{
    body::{to_bytes, Body},
    extract::Extension,
    http::{Request, StatusCode},
};
use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId, TenantMessageId, TransactionId},
    ActorId, Artifact, ArtifactHash, ArtifactId, ContentType, HashAlgorithm, RetentionClass,
    StorageBackend, StorageLocation,
};
use nullapart_mail_core::admin_rbac::{
    SUPPORT_ROLE, SYSTEM_ADMIN_ROLE, TRACE_CONTENT_PERMISSION, TRACE_VIEW_PERMISSION,
};
use nullapart_mail_core::artifact_store::{FilesystemArtifactRuntime, FilesystemArtifactStore};
use nullapart_mail_core::trace::{mail_trace_router, trace_router, MailTraceState, TraceConfig};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId, TenantContext,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

const TRACE_WORKLOAD_TOKEN: &str = "postgres-trace-workload-token";
const TRACE_ACTION: &str = "trace_content_accessed";

const MESSAGE: &str = "Subject: Postgres trace content\r\n\
     From: sender@example.test\r\n\
     To: alice@example.test\r\n\
     Date: Wed, 30 Sep 2026 12:00:00 +0000\r\n\
     Content-Type: text/plain; charset=utf-8\r\n\
     \r\n\
     Trace body\r\n";

async fn connect() -> PgPool {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable")
}

struct Fixture {
    deployment: DeploymentId,
    other_deployment: DeploymentId,
    customer_a: CustomerId,
    customer_b: CustomerId,
    suffix: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = Uuid::new_v4().simple().to_string();
    let deployment = DeploymentId::new(&format!("local-trace-{suffix}").to_uppercase());
    let other_deployment = DeploymentId::new(&format!("other-trace-{suffix}").to_uppercase());
    let customer_a = CustomerId::new(&format!("trace-{suffix}-a"));
    let customer_b = CustomerId::new(&format!("trace-{suffix}-b"));

    for (id, display) in [
        (&deployment, "Local trace deployment"),
        (&other_deployment, "Other trace deployment"),
    ] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id.0)
        .bind(display)
        .execute(pool)
        .await
        .expect("the deployment fixture must be created");
    }
    for customer in [&customer_a, &customer_b] {
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&customer.0)
        .bind(&deployment.0)
        .bind("Mail trace test customer")
        .execute(pool)
        .await
        .expect("the customer fixture must be created");
    }

    Fixture {
        deployment,
        other_deployment,
        customer_a,
        customer_b,
        suffix,
    }
}

async fn insert_transaction(
    pool: &PgPool,
    deployment: &DeploymentId,
    transaction_id: &TransactionId,
    envelope_sender: &str,
    mime_artifact_id: &str,
) {
    sqlx::query(
        "INSERT INTO smtp_transactions (id, deployment_id, direction, envelope_sender, message_id, \
                content_hash, mime_artifact_id, trace_id, received_at) \
         VALUES ($1, $2, 'inbound', $3, $4, $5, $6, $7, now())",
    )
    .bind(transaction_id.0)
    .bind(&deployment.0)
    .bind(envelope_sender)
    .bind(format!("mid-{transaction_id}@example.test"))
    .bind(format!("content-hash-{transaction_id}"))
    .bind(mime_artifact_id)
    .bind(format!("trace-{transaction_id}"))
    .execute(pool)
    .await
    .expect("the transaction fixture must be created");
}

async fn insert_recipient(
    pool: &PgPool,
    transaction_id: &TransactionId,
    address: &str,
    notify: &[&str],
) {
    sqlx::query(
        "INSERT INTO smtp_transaction_recipients (transaction_id, address, orcpt, notify) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(transaction_id.0)
    .bind(address)
    .bind(format!("rfc822;{address}"))
    .bind(notify.to_vec())
    .execute(pool)
    .await
    .expect("the recipient fixture must be created");
}

async fn insert_instance(
    pool: &PgPool,
    transaction_id: &TransactionId,
    customer_id: &CustomerId,
    disposition: &str,
) -> TenantMessageId {
    let tenant_message_id = TenantMessageId::new();
    sqlx::query(
        "INSERT INTO tenant_message_instances (id, transaction_id, customer_id, disposition) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(&customer_id.0)
    .bind(disposition)
    .execute(pool)
    .await
    .expect("the tenant message fixture must be created");
    tenant_message_id
}

async fn insert_attempt(pool: &PgPool, tenant_message_id: TenantMessageId, smtp_code: Option<i32>) {
    sqlx::query(
        "INSERT INTO delivery_attempts (id, tenant_message_id, attempt_number, scheduled_at, \
                completed_at, status, smtp_code, enhanced_code, smtp_message) \
         VALUES ($1, $2, 1, now(), now(), 'success', $3, $4, '2.0.0 delivered')",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_message_id.0)
    .bind(smtp_code)
    .bind("2.0.0")
    .execute(pool)
    .await
    .expect("the delivery attempt fixture must be created");
}

async fn insert_artifact_row(
    pool: &PgPool,
    artifact_id: ArtifactId,
    deployment: &DeploymentId,
    customer_id: &CustomerId,
    size_bytes: i64,
    content_hash: &str,
    storage_path: &str,
) {
    sqlx::query(
        "INSERT INTO artifacts (id, deployment_id, customer_id, content_type, size_bytes, \
                content_hash, storage_backend, storage_path, retention_class, encryption_enabled) \
         VALUES ($1, $2, $3, 'message/rfc822', $4, $5, 'filesystem', $6, 'standard', false)",
    )
    .bind(artifact_id.0)
    .bind(&deployment.0)
    .bind(&customer_id.0)
    .bind(size_bytes)
    .bind(content_hash)
    .bind(storage_path)
    .execute(pool)
    .await
    .expect("the artifact fixture must be created");
}

async fn insert_finding(
    pool: &PgPool,
    tenant_message_id: TenantMessageId,
    transaction_id: &TransactionId,
    artifact_id: ArtifactId,
    deployment: &DeploymentId,
    customer_id: &CustomerId,
) {
    sqlx::query(
        "INSERT INTO security_findings (id, tenant_message_id, transaction_id, artifact_id, \
                deployment_id, customer_id, scanner_type, scanner_status, severity, category, \
                description, false_positive, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'static_rule', 'completed', 'medium', 'policy', \
                'Trace fixture finding', false, now())",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(artifact_id.0)
    .bind(&deployment.0)
    .bind(&customer_id.0)
    .execute(pool)
    .await
    .expect("the security finding fixture must be created");
}

fn stored_artifact(
    artifact_id: ArtifactId,
    deployment: &DeploymentId,
    customer_id: &CustomerId,
    bytes: &[u8],
) -> Artifact {
    Artifact {
        id: artifact_id.clone(),
        deployment_id: deployment.clone(),
        customer_id: Some(customer_id.clone()),
        content_type: ContentType::new("message/rfc822"),
        size: bytes.len() as u64,
        storage_location: StorageLocation {
            backend: StorageBackend::Filesystem,
            bucket: None,
            key: format!("{}.artifact", artifact_id.0),
            region: None,
        },
        hash: ArtifactHash {
            algorithm: HashAlgorithm::Sha256,
            value: hex::encode(Sha256::digest(bytes)),
        },
        retention_class: RetentionClass::Standard,
        created_at: chrono::Utc::now(),
        expires_at: None,
        encrypted: false,
        scanner_eligible: true,
    }
}

async fn content_store(
    pool: &PgPool,
    deployment: &DeploymentId,
) -> (MailTraceState, FilesystemArtifactStore, PathBuf) {
    let root = std::env::temp_dir().join(format!("nullapart-trace-db-{}", Uuid::new_v4()));
    let store = FilesystemArtifactStore::try_new(root.clone(), FilesystemArtifactRuntime::Test)
        .await
        .expect("the test artifact root must be created");
    let state = MailTraceState::new(pool.clone(), deployment.clone(), store.clone());
    (state, store, root)
}

fn context(
    deployment: &DeploymentId,
    customer_id: &CustomerId,
    roles: Vec<&str>,
    permissions: Vec<&str>,
) -> TenantContext {
    TenantContext {
        deployment_id: deployment.clone(),
        region: RegionId::new("local"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "mail-trace@example.test".to_string(),
            roles: roles.into_iter().map(str::to_string).collect(),
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: customer_id.clone(),
        customer_internal_key: 1,
        customer_display_name: "Mail trace test customer".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: permissions.into_iter().map(str::to_string).collect(),
        config_revision: 1,
        trace_id: "postgres-trace".to_string(),
        correlation_id: "postgres-trace".to_string(),
        session_id: "postgres-trace-session".to_string(),
        authenticated_at: chrono::Utc::now(),
    }
}

fn admin_context(deployment: &DeploymentId, customer_id: &CustomerId) -> TenantContext {
    context(
        deployment,
        customer_id,
        vec![SYSTEM_ADMIN_ROLE],
        vec![TRACE_VIEW_PERMISSION, TRACE_CONTENT_PERMISSION],
    )
}

fn support_context(deployment: &DeploymentId, customer_id: &CustomerId) -> TenantContext {
    context(
        deployment,
        customer_id,
        vec![SUPPORT_ROLE],
        vec![TRACE_VIEW_PERMISSION],
    )
}

fn workload_config(pool: &PgPool, deployment: &DeploymentId) -> TraceConfig {
    let mut config = TraceConfig {
        deployment_id: deployment.clone(),
        node_id: "mailcore-local-01".to_string(),
        node_version: "0.0.0".to_string(),
        config_revision: None,
        workload_token_sha256: None,
        pool: pool.clone(),
    };
    config.set_workload_token(TRACE_WORKLOAD_TOKEN);
    config
}

fn search_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/trace/search")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {TRACE_WORKLOAD_TOKEN}"))
        .body(Body::from(body.to_string()))
        .expect("test request must build")
}

fn session_search_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/mail-trace/search")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("test request must build")
}

fn get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("test request must build")
}

fn workload_get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {TRACE_WORKLOAD_TOKEN}"))
        .body(Body::empty())
        .expect("test request must build")
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    serde_json::from_slice(&bytes).expect("the body must be JSON")
}

async fn audit_rows(pool: &PgPool, deployment: &DeploymentId, result: &str) -> Vec<Value> {
    let rows = sqlx::query(
        "SELECT resource_id, details->>'reason' AS reason FROM audit_events \
         WHERE deployment_id = $1 AND action = $2 AND result = $3 \
         ORDER BY created_at, id",
    )
    .bind(&deployment.0)
    .bind(TRACE_ACTION)
    .bind(result)
    .fetch_all(pool)
    .await
    .expect("the audit assertion must run");
    rows.iter()
        .map(|row| {
            json!({
                "resource_id": row.get::<Option<String>, _>("resource_id"),
                "reason": row.get::<Option<String>, _>("reason"),
            })
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 004_scanner_evidence.sql"]
async fn workload_search_and_detail_stay_deployment_scoped() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let own_transaction = TransactionId::new();
    let other_transaction = TransactionId::new();
    let sender = format!("trace-{}@example.test", fixture.suffix);
    insert_transaction(
        &pool,
        &fixture.deployment,
        &own_transaction,
        &sender,
        "pending",
    )
    .await;
    insert_transaction(
        &pool,
        &fixture.other_deployment,
        &other_transaction,
        &sender,
        "pending",
    )
    .await;
    insert_recipient(
        &pool,
        &own_transaction,
        "alice@example.test",
        &["failure", "delay"],
    )
    .await;
    insert_recipient(&pool, &own_transaction, "bob@example.test", &[]).await;

    let app = trace_router(workload_config(&pool, &fixture.deployment));

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/trace/search")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"q":"{}"}}"#, fixture.suffix)))
                .expect("test request must build"),
        )
        .await
        .expect("the search must answer");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(search_request(&format!(
            r#"{{"q":"{}","limit":50}}"#,
            fixture.suffix
        )))
        .await
        .expect("the search must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let results = &body["data"]["results"];
    assert_eq!(results.as_array().expect("results must be a list").len(), 1);
    assert_eq!(body["data"]["total_count"], json!(1));
    assert_eq!(body["data"]["has_more"], json!(false));
    let entry = &results[0];
    assert_eq!(
        entry["transaction_id"],
        json!(own_transaction.0.to_string())
    );
    assert_eq!(entry["envelope_sender"], json!(sender));
    assert_eq!(entry["recipient_count"], json!(2));
    assert_eq!(
        entry["message_id"],
        json!(format!("mid-{own_transaction}@example.test"))
    );

    let response = app
        .clone()
        .oneshot(workload_get_request(&format!(
            "/api/v1/trace/transaction/{}",
            own_transaction.0
        )))
        .await
        .expect("the detail must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["data"]["deployment_id"], json!(fixture.deployment.0));
    assert_eq!(
        body["data"]["recipients"],
        json!([
            {
                "address": "alice@example.test",
                "orcpt": "rfc822;alice@example.test",
                "notify": "failure, delay"
            },
            {
                "address": "bob@example.test",
                "orcpt": "rfc822;bob@example.test",
                "notify": null
            }
        ])
    );
    assert_eq!(body["data"]["flow_stages"][0]["stage"], json!("received"));

    let response = app
        .clone()
        .oneshot(workload_get_request(&format!(
            "/api/v1/trace/transaction/{}",
            other_transaction.0
        )))
        .await
        .expect("the foreign detail must answer");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "NOT_FOUND", "message": "Transaction was not found" })
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 004_scanner_evidence.sql"]
async fn session_search_projects_only_the_session_customers_instances() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let shared_transaction = TransactionId::new();
    let owned_transaction = TransactionId::new();
    let sender = format!("trace-{}@example.test", fixture.suffix);
    insert_transaction(
        &pool,
        &fixture.deployment,
        &shared_transaction,
        &sender,
        "pending",
    )
    .await;
    insert_transaction(
        &pool,
        &fixture.deployment,
        &owned_transaction,
        &sender,
        "pending",
    )
    .await;
    insert_recipient(&pool, &shared_transaction, "alice@example.test", &[]).await;
    let shared_for_a =
        insert_instance(&pool, &shared_transaction, &fixture.customer_a, "allow").await;
    let shared_for_b = insert_instance(
        &pool,
        &shared_transaction,
        &fixture.customer_b,
        "quarantine",
    )
    .await;
    let owned_for_a =
        insert_instance(&pool, &owned_transaction, &fixture.customer_a, "allow").await;

    let (state, _store, root) = content_store(&pool, &fixture.deployment).await;
    let body = format!(r#"{{"q":"{}"}}"#, fixture.suffix);

    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_a,
        )))
        .oneshot(session_search_request(&body))
        .await
        .expect("the search must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = json_body(response).await;
    let results = payload["data"]["results"]
        .as_array()
        .expect("results must be a list");
    assert_eq!(results.len(), 2, "customer A owns both transactions");
    assert_eq!(payload["data"]["total_count"], json!(2));
    let shared = results
        .iter()
        .find(|entry| entry["transaction_id"] == json!(shared_transaction.0.to_string()))
        .expect("the shared transaction must be visible to customer A");
    assert_eq!(
        shared["instances"],
        json!([{ "tenant_message_id": shared_for_a.0.to_string(), "disposition": "allow" }])
    );
    let owned = results
        .iter()
        .find(|entry| entry["transaction_id"] == json!(owned_transaction.0.to_string()))
        .expect("the owned transaction must be visible to customer A");
    assert_eq!(
        owned["instances"],
        json!([{ "tenant_message_id": owned_for_a.0.to_string(), "disposition": "allow" }])
    );

    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_b,
        )))
        .oneshot(session_search_request(&body))
        .await
        .expect("the search must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = json_body(response).await;
    let results = payload["data"]["results"]
        .as_array()
        .expect("results must be a list");
    assert_eq!(
        results.len(),
        1,
        "customer B only sees the transaction it has an instance for"
    );
    assert_eq!(
        results[0]["transaction_id"],
        json!(shared_transaction.0.to_string())
    );
    assert_eq!(
        results[0]["instances"],
        json!([{ "tenant_message_id": shared_for_b.0.to_string(), "disposition": "quarantine" }])
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 004_scanner_evidence.sql"]
async fn session_detail_scopes_instances_attempts_and_findings_to_the_customer() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let transaction_id = TransactionId::new();
    let artifact_id = ArtifactId::new();
    let sender = format!("trace-{}@example.test", fixture.suffix);
    insert_artifact_row(
        &pool,
        artifact_id.clone(),
        &fixture.deployment,
        &fixture.customer_a,
        1,
        "detail-hash",
        &format!("{}.artifact", artifact_id.0),
    )
    .await;
    insert_transaction(
        &pool,
        &fixture.deployment,
        &transaction_id,
        &sender,
        &artifact_id.0.to_string(),
    )
    .await;
    let tenant_message_id =
        insert_instance(&pool, &transaction_id, &fixture.customer_a, "allow").await;
    insert_attempt(&pool, tenant_message_id.clone(), Some(250)).await;
    insert_finding(
        &pool,
        tenant_message_id.clone(),
        &transaction_id,
        artifact_id,
        &fixture.deployment,
        &fixture.customer_a,
    )
    .await;

    let (state, _store, root) = content_store(&pool, &fixture.deployment).await;
    let uri = format!("/api/v1/mail-trace/transaction/{}", transaction_id.0);

    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_b,
        )))
        .oneshot(get_request(&uri))
        .await
        .expect("the detail must answer");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "NOT_FOUND", "message": "Transaction was not found" })
    );

    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_a,
        )))
        .oneshot(get_request(&uri))
        .await
        .expect("the detail must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let data = &body["data"];
    assert_eq!(data["transaction_id"], json!(transaction_id.0.to_string()));
    assert_eq!(data["envelope_sender"], json!(sender));
    assert_eq!(data["instances"].as_array().expect("instances").len(), 1);
    assert_eq!(
        data["instances"][0]["tenant_message_id"],
        json!(tenant_message_id.0.to_string())
    );
    assert_eq!(
        data["delivery_attempts"]
            .as_array()
            .expect("attempts")
            .len(),
        1
    );
    assert_eq!(data["delivery_attempts"][0]["attempt_number"], json!(1));
    assert_eq!(data["delivery_attempts"][0]["smtp_code"], json!("250"));
    assert_eq!(data["delivery_attempts"][0]["status"], json!("success"));
    assert_eq!(data["findings"].as_array().expect("findings").len(), 1);
    assert_eq!(data["findings"][0]["severity"], json!("medium"));
    let stages: Vec<&str> = data["flow_stages"]
        .as_array()
        .expect("flow stages")
        .iter()
        .map(|stage| stage["stage"].as_str().expect("stage name"))
        .collect();
    assert_eq!(
        stages,
        vec![
            "received",
            "tenant_message_created",
            "delivery_scheduled",
            "delivery_completed",
        ]
    );

    let malformed = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_a,
        )))
        .oneshot(get_request("/api/v1/mail-trace/transaction/not-a-uuid"))
        .await
        .expect("the detail must answer");
    assert_eq!(malformed.status(), StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(&root);
}

/// The customer trace answers with the message's own history. The installation
/// reference, the content deduplication hash, the MTA queue identifiers and the
/// log correlation id describe the machinery that carried the message, so they
/// are only written for a seat that can act on them.
#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 004_scanner_evidence.sql"]
async fn session_detail_withholds_platform_machinery_from_the_customer_read() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let transaction_id = TransactionId::new();
    let artifact_id = ArtifactId::new();
    let sender = format!("detail-{}@example.test", fixture.suffix);
    insert_artifact_row(
        &pool,
        artifact_id.clone(),
        &fixture.deployment,
        &fixture.customer_a,
        1,
        "detail-hash",
        &format!("{}.artifact", artifact_id.0),
    )
    .await;
    insert_transaction(
        &pool,
        &fixture.deployment,
        &transaction_id,
        &sender,
        &artifact_id.0.to_string(),
    )
    .await;
    let tenant_message_id =
        insert_instance(&pool, &transaction_id, &fixture.customer_a, "allow").await;
    insert_attempt(&pool, tenant_message_id.clone(), Some(250)).await;
    sqlx::query("UPDATE smtp_transactions SET postfix_queue_ids = $2::text[] WHERE id = $1")
        .bind(transaction_id.0)
        .bind(vec!["AA1B2C3D".to_string()])
        .execute(&pool)
        .await
        .expect("the queue identifier fixture must be set");
    sqlx::query("UPDATE delivery_attempts SET postfix_queue_id = $2 WHERE tenant_message_id = $1")
        .bind(tenant_message_id.0)
        .bind("EE4F5G6H")
        .execute(&pool)
        .await
        .expect("the attempt queue identifier fixture must be set");

    let (state, _store, root) = content_store(&pool, &fixture.deployment).await;
    let uri = format!("/api/v1/mail-trace/transaction/{}", transaction_id.0);

    let customer = context(
        &fixture.deployment,
        &fixture.customer_a,
        vec!["customer_admin"],
        vec![TRACE_VIEW_PERMISSION],
    );
    let response = mail_trace_router(state.clone())
        .layer(Extension(customer))
        .oneshot(get_request(&uri))
        .await
        .expect("the detail must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let data = json_body(response).await["data"].clone();
    assert_eq!(
        data["transaction_id"],
        json!(transaction_id.0.to_string()),
        "the customer keeps the handle for their own message"
    );
    assert!(data["deployment_id"].is_null(), "{data}");
    assert!(data["content_hash"].is_null(), "{data}");
    assert!(data["trace_id"].is_null(), "{data}");
    // The queue identifiers are absent as a key, not merely empty: the field
    // name itself names the platform's mail software.
    assert!(data["postfix_queue_ids"].is_null(), "{data}");
    assert!(data["delivery_attempts"][0]["postfix_queue_id"].is_null());
    assert_eq!(
        data["delivery_attempts"][0]["smtp_code"],
        json!("250"),
        "and keeps what the attempt did"
    );

    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_a,
        )))
        .oneshot(get_request(&uri))
        .await
        .expect("the detail must answer");
    let data = json_body(response).await["data"].clone();
    assert_eq!(data["deployment_id"], json!(fixture.deployment.0));
    assert_eq!(
        data["content_hash"],
        json!(format!("content-hash-{}", transaction_id.0))
    );
    assert_eq!(
        data["trace_id"],
        json!(format!("trace-{}", transaction_id.0))
    );
    assert_eq!(data["postfix_queue_ids"], json!(["AA1B2C3D"]));
    assert_eq!(
        data["delivery_attempts"][0]["postfix_queue_id"],
        json!("EE4F5G6H")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 004_scanner_evidence.sql"]
async fn content_read_returns_the_stored_mime_and_audits_a_success() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let transaction_id = TransactionId::new();
    let artifact_id = ArtifactId::new();
    let bytes = MESSAGE.as_bytes().to_vec();
    let sender = format!("trace-{}@example.test", fixture.suffix);
    let (state, store, root) = content_store(&pool, &fixture.deployment).await;
    store
        .put(
            stored_artifact(
                artifact_id.clone(),
                &fixture.deployment,
                &fixture.customer_a,
                &bytes,
            ),
            bytes.clone(),
        )
        .await
        .expect("the artifact bytes must store");
    insert_artifact_row(
        &pool,
        artifact_id.clone(),
        &fixture.deployment,
        &fixture.customer_a,
        bytes.len() as i64,
        &hex::encode(Sha256::digest(&bytes)),
        &format!("{}.artifact", artifact_id.0),
    )
    .await;
    insert_transaction(
        &pool,
        &fixture.deployment,
        &transaction_id,
        &sender,
        &artifact_id.0.to_string(),
    )
    .await;
    insert_instance(&pool, &transaction_id, &fixture.customer_a, "allow").await;

    let uri = format!(
        "/api/v1/mail-trace/transaction/{}/content",
        transaction_id.0
    );
    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_a,
        )))
        .oneshot(get_request(&uri))
        .await
        .expect("the content must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let data = &body["data"];
    assert_eq!(data["transaction_id"], json!(transaction_id.0.to_string()));
    assert_eq!(data["subject"], json!("Postgres trace content"));
    assert_eq!(data["from"], json!("sender@example.test"));
    assert_eq!(data["to"], json!(["alice@example.test"]));
    assert_eq!(data["plain_text"], json!("Trace body\r\n"));
    assert_eq!(data["truncated"], json!(false));
    assert!(data["headers"].as_array().expect("headers").len() >= 4);
    assert_eq!(data["attachments"], json!([]));

    assert_eq!(
        audit_rows(&pool, &fixture.deployment, "success").await,
        vec![json!({
            "resource_id": transaction_id.0.to_string(),
            "reason": Value::Null,
        })],
        "the content access must audit exactly one success"
    );
    let leak = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM audit_events \
         WHERE deployment_id = $1 AND action = $2 AND details::text LIKE '%Trace body%'",
    )
    .bind(&fixture.deployment.0)
    .bind(TRACE_ACTION)
    .fetch_one(&pool)
    .await
    .expect("the audit leak assertion must run");
    assert_eq!(leak, 0, "message bytes must never reach the audit trail");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 004_scanner_evidence.sql"]
async fn content_denials_are_audited_for_permission_ownership_and_missing_artifact() {
    let pool = connect().await;
    let fixture = seed(&pool).await;
    let denied_transaction = TransactionId::new();
    let foreign_transaction = TransactionId::new();
    let artifactless_transaction = TransactionId::new();
    let missing_bytes_transaction = TransactionId::new();
    let artifact_id = ArtifactId::new();
    let sender = format!("trace-{}@example.test", fixture.suffix);
    let (state, _store, root) = content_store(&pool, &fixture.deployment).await;

    insert_transaction(
        &pool,
        &fixture.deployment,
        &denied_transaction,
        &sender,
        "pending",
    )
    .await;
    insert_transaction(
        &pool,
        &fixture.deployment,
        &foreign_transaction,
        &sender,
        "pending",
    )
    .await;
    insert_transaction(
        &pool,
        &fixture.deployment,
        &artifactless_transaction,
        &sender,
        "pending",
    )
    .await;
    insert_artifact_row(
        &pool,
        artifact_id.clone(),
        &fixture.deployment,
        &fixture.customer_a,
        1,
        "missing-bytes-hash",
        &format!("{}.artifact", artifact_id.0),
    )
    .await;
    insert_transaction(
        &pool,
        &fixture.deployment,
        &missing_bytes_transaction,
        &sender,
        &artifact_id.0.to_string(),
    )
    .await;
    insert_instance(&pool, &denied_transaction, &fixture.customer_a, "allow").await;
    insert_instance(&pool, &foreign_transaction, &fixture.customer_a, "allow").await;
    insert_instance(
        &pool,
        &artifactless_transaction,
        &fixture.customer_a,
        "allow",
    )
    .await;
    insert_instance(
        &pool,
        &missing_bytes_transaction,
        &fixture.customer_a,
        "allow",
    )
    .await;

    let uri = format!(
        "/api/v1/mail-trace/transaction/{}/content",
        denied_transaction.0
    );
    let response = mail_trace_router(state.clone())
        .layer(Extension(support_context(
            &fixture.deployment,
            &fixture.customer_a,
        )))
        .oneshot(get_request(&uri))
        .await
        .expect("the content must answer");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "FORBIDDEN", "message": "Permission is required" })
    );

    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_b,
        )))
        .oneshot(get_request(&uri))
        .await
        .expect("the content must answer");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "NOT_FOUND", "message": "Transaction was not found" })
    );

    let uri = format!(
        "/api/v1/mail-trace/transaction/{}/content",
        artifactless_transaction.0
    );
    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_a,
        )))
        .oneshot(get_request(&uri))
        .await
        .expect("the content must answer");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "NOT_FOUND", "message": "Message content was not found" })
    );

    let uri = format!(
        "/api/v1/mail-trace/transaction/{}/content",
        missing_bytes_transaction.0
    );
    let response = mail_trace_router(state.clone())
        .layer(Extension(admin_context(
            &fixture.deployment,
            &fixture.customer_a,
        )))
        .oneshot(get_request(&uri))
        .await
        .expect("the content must answer");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "NOT_FOUND", "message": "Message content was not found" })
    );

    let denied = audit_rows(&pool, &fixture.deployment, "denied").await;
    assert_eq!(denied.len(), 4, "every denial must be audited exactly once");
    let reasons: Vec<&str> = denied
        .iter()
        .map(|row| row["reason"].as_str().expect("audit reason"))
        .collect();
    assert!(reasons.contains(&"missing trace:content permission"));
    assert!(reasons.contains(&"tenant message is not visible"));
    assert!(reasons.contains(&"no stored MIME artifact"));
    assert!(reasons.contains(&"artifact bytes are missing"));
    let leak = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM audit_events \
         WHERE deployment_id = $1 AND action = $2 AND result = 'denied' \
         AND details::text LIKE '%Trace body%'",
    )
    .bind(&fixture.deployment.0)
    .bind(TRACE_ACTION)
    .fetch_one(&pool)
    .await
    .expect("the audit leak assertion must run");
    assert_eq!(leak, 0, "denials must never record message bytes");
    let _ = std::fs::remove_dir_all(&root);
}

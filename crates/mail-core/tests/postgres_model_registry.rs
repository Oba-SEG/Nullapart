//! Local PostgreSQL coverage for the Phase 4 increment 4 model registry.
//!
//! Requires PostgreSQL migrated through `019_inline_ml_models.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Every test is `#[ignore]`d
//! so the default suite stays offline; run them explicitly with
//! `cargo test --test postgres_model_registry -- --ignored`.
//!
//! 1. **Lifecycle**: register creates a pending row, approve moves it to
//!    approved, activate makes it the single active model, and each
//!    transition writes exactly one success audit row; replaying a
//!    completed idempotency key returns the stored response without a new
//!    audit row.
//! 2. **Activation + rollback**: a second activation deactivates the first
//!    (`superseded`) and records it as the rollback target; rollback
//!    re-activates the recorded target only, keeping one active row.
//! 3. **Transition guards**: activating a pending model, approving a
//!    rejected model, duplicate registration, re-activating the active
//!    model, and rolling back without a target all answer 409.
//! 4. **RBAC denials**: a missing permission and a non-system-administrator
//!    caller are both denied (403) with `denied` audit rows.
//! 5. **Deployment scope**: another deployment's registry reads empty, and
//!    the request role observes zero rows with an unset deployment GUC
//!    (fail closed) and only its own deployment's rows when scoped — the
//!    FORCE policy applies to the owner too.
//! 6. **Idempotency**: a mutating request without `x-idempotency-key`
//!    answers 400 `IDEMPOTENCY_REQUIRED`.

use axum::{
    body::{to_bytes, Body},
    extract::Extension,
    http::{Method, Request, StatusCode},
};
use nullapart_mail_contracts::{
    transaction::{CustomerId, DeploymentId},
    ActorId,
};
use nullapart_mail_core::admin_rbac::SYSTEM_ADMIN_ROLE;
use nullapart_mail_core::model_registry::{
    model_registry_router, ModelRegistryState, MODELS_MANAGE_PERMISSION, MODELS_VIEW_PERMISSION,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId, TenantContext,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Transaction};
use tower::ServiceExt;
use uuid::Uuid;

/// The non-owner, non-superuser role every RLS statement assumes.
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

/// Serializes role and grant creation inside this binary: concurrent GRANTs
/// rewrite shared catalogs and race with a concurrently running test binary.
static ROLE_SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn ensure_request_role(pool: &PgPool) {
    let _setup = ROLE_SETUP_LOCK.lock().await;
    let mut attempt = 0;
    loop {
        match try_ensure_request_role(pool).await {
            Ok(()) => return,
            Err(error) if attempt < 3 => {
                attempt += 1;
                eprintln!("role setup attempt {attempt} failed: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            },
            Err(error) => panic!("the request role setup must succeed: {error}"),
        }
    }
}

async fn try_ensure_request_role(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "DO $$ BEGIN \
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_local_request') THEN \
             EXECUTE 'CREATE ROLE nullapart_local_request NOLOGIN'; \
           END IF; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;",
    )
    .execute(&mut *transaction)
    .await?;
    for grant in [
        "GRANT USAGE ON SCHEMA public TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nullapart_local_request",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nullapart_local_request",
    ] {
        sqlx::query(grant).execute(&mut *transaction).await?;
    }
    transaction.commit().await
}

/// Begins a transaction as the request role. `deployment` is applied
/// transaction-locally; `None` leaves the GUC unset (fail closed).
async fn begin_scoped<'a>(
    pool: &'a PgPool,
    deployment: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool
        .begin()
        .await
        .expect("a transaction must begin for the scoped statement");
    sqlx::query(&format!("SET LOCAL ROLE {REQUEST_ROLE}"))
        .execute(&mut *transaction)
        .await
        .expect("the session must assume the request role");
    if let Some(deployment) = deployment {
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(deployment)
            .execute(&mut *transaction)
            .await
            .expect("the deployment scope must be established");
    }
    transaction
}

/// Begins a transaction as the connecting owner, used only to seed and remove
/// fixture rows (the FORCE policy would otherwise require a scope).
async fn begin_as_owner<'a>(pool: &'a PgPool) -> Transaction<'a, sqlx::Postgres> {
    pool.begin()
        .await
        .expect("a transaction must begin for the owner statement")
}

/// `inline_ml_models` runs FORCE RLS, so even the owner establishes the
/// deployment scope before reading rows.
async fn models_visible_to(pool: &PgPool, deployment: Option<&str>) -> i64 {
    let mut transaction = begin_as_owner(pool).await;
    if let Some(deployment) = deployment {
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(deployment)
            .execute(&mut *transaction)
            .await
            .expect("the deployment scope must be established");
    }
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM inline_ml_models WHERE ($1::text IS NULL OR deployment_id = $1)",
    )
    .bind(deployment)
    .fetch_one(&mut *transaction)
    .await
    .expect("the registry count must run");
    transaction
        .commit()
        .await
        .expect("the registry count transaction must commit");
    count
}

/// The request role's view with a given scope (0 = fail closed).
async fn request_role_count(pool: &PgPool, deployment: Option<&str>) -> i64 {
    let mut transaction = begin_scoped(pool, deployment).await;
    let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM inline_ml_models")
        .fetch_one(&mut *transaction)
        .await
        .expect("the request role count must run");
    transaction
        .commit()
        .await
        .expect("the request role count transaction must commit");
    count
}

async fn model_state(
    pool: &PgPool,
    deployment: &str,
    model_id: &str,
) -> Option<(String, Option<String>, bool, Option<String>)> {
    let mut transaction = begin_as_owner(pool).await;
    sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
        .bind(deployment)
        .execute(&mut *transaction)
        .await
        .expect("the deployment scope must be established");
    let row = sqlx::query_as::<_, (String, Option<String>, bool, Option<String>)>(
        "SELECT approval_state, rollback_model_id, \
                (activated_at IS NOT NULL AND deactivated_at IS NULL), deactivation_reason \
         FROM inline_ml_models WHERE deployment_id = $1 AND model_id = $2",
    )
    .bind(deployment)
    .bind(model_id)
    .fetch_optional(&mut *transaction)
    .await
    .expect("the model state assertion must run");
    transaction
        .commit()
        .await
        .expect("the model state transaction must commit");
    row
}

async fn active_count(pool: &PgPool, deployment: &str) -> i64 {
    let mut transaction = begin_as_owner(pool).await;
    sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
        .bind(deployment)
        .execute(&mut *transaction)
        .await
        .expect("the deployment scope must be established");
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM inline_ml_models WHERE deployment_id = $1 \
         AND activated_at IS NOT NULL AND deactivated_at IS NULL",
    )
    .bind(deployment)
    .fetch_one(&mut *transaction)
    .await
    .expect(" the active count assertion must run");
    transaction
        .commit()
        .await
        .expect("the active count transaction must commit");
    count
}

struct Fixture {
    deployment_a: DeploymentId,
    deployment_b: DeploymentId,
    customer_a: CustomerId,
    suffix: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = format!("local-modelreg-{}", Uuid::new_v4().simple());
    let deployment_a = DeploymentId::new(&format!("LOCAL-MR-A-{suffix}"));
    let deployment_b = DeploymentId::new(&format!("LOCAL-MR-B-{suffix}"));
    let customer_a = CustomerId::new(&format!("{suffix}-a"));

    for (id, name) in [
        (&deployment_a, "Model registry deployment A"),
        (&deployment_b, "Model registry deployment B"),
    ] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id.0)
        .bind(name)
        .execute(pool)
        .await
        .expect("the deployment fixture must be created");
    }
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&customer_a.0)
    .bind(&deployment_a.0)
    .bind(&suffix)
    .execute(pool)
    .await
    .expect("the customer fixture must be created");

    Fixture {
        deployment_a,
        deployment_b,
        customer_a,
        suffix,
    }
}

fn base_context(fixture: &Fixture) -> TenantContext {
    TenantContext {
        deployment_id: fixture.deployment_a.clone(),
        region: RegionId::new("local"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "model-registry@example.test".to_string(),
            roles: vec![SYSTEM_ADMIN_ROLE.to_string()],
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: fixture.customer_a.clone(),
        customer_internal_key: 1,
        customer_display_name: "Model registry test".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: vec![
            MODELS_VIEW_PERMISSION.to_string(),
            MODELS_MANAGE_PERMISSION.to_string(),
        ],
        config_revision: 1,
        trace_id: "postgres-model-registry-trace".to_string(),
        correlation_id: "postgres-model-registry-correlation".to_string(),
        session_id: "postgres-model-registry-session".to_string(),
        authenticated_at: chrono::Utc::now(),
    }
}

/// Holds `models:view` only: the permission gate must deny before anything
/// else runs.
fn view_only_context(fixture: &Fixture) -> TenantContext {
    let mut context = base_context(fixture);
    context.permissions = vec![MODELS_VIEW_PERMISSION.to_string()];
    context
}

/// Holds both permissions but not the system administrator role: the role
/// gate must deny the state transition.
fn non_system_context(fixture: &Fixture) -> TenantContext {
    let mut context = base_context(fixture);
    context.actor.roles = vec!["customer_admin".to_string()];
    context
}

fn app_with_pool(pool: &PgPool, context: TenantContext, deployment: DeploymentId) -> axum::Router {
    model_registry_router(ModelRegistryState::new(pool.clone(), deployment))
        .layer(Extension(context))
}

fn json_request(
    method: Method,
    uri: &str,
    key: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(key) = key {
        builder = builder.header("x-idempotency-key", key);
    }
    let body = body.map(|value| value.to_string()).unwrap_or_default();
    builder
        .body(Body::from(body))
        .expect("test request must build")
}

fn register_request(uri: &str, key: &str, body: Value) -> Request<Body> {
    json_request(Method::POST, uri, Some(key), Some(body))
}

fn action_request(uri: &str, key: &str) -> Request<Body> {
    json_request(Method::POST, uri, Some(key), None)
}

fn register_body(model_id: &str, model_version: &str, digest_char: char) -> Value {
    json!({
        "model_id": model_id,
        "model_version": model_version,
        "input_schema_version": 1,
        "training_dataset_version": "multilabel-dataset-v2",
        "code_commit": "239194c",
        "metrics": {"macro_f1": 0.9862, "clean_fpr": 0.0042},
        "artifact_uri": format!("ml/inline/checkpoints/{model_id}"),
        "artifact_sha256": digest_char.to_string().repeat(64),
        "deployment_regions": ["local"],
    })
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    serde_json::from_slice(&bytes).expect("the body must be JSON")
}

async fn audit_count(pool: &PgPool, deployment: &str, action: &str, result: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM audit_events \
         WHERE deployment_id = $1 AND action = $2 AND result = $3",
    )
    .bind(deployment)
    .bind(action)
    .bind(result)
    .fetch_one(pool)
    .await
    .expect("the audit assertion must run")
}

/// Runs the register -> approve -> activate lifecycle once.
async fn activate_first_model(
    app: &axum::Router,
    fixture: &Fixture,
    model_id: &str,
    model_version: &str,
    digest: char,
) {
    let base = format!("/api/v1/admin/models/{model_id}/{model_version}");
    let register = app
        .clone()
        .oneshot(register_request(
            "/api/v1/admin/models",
            &format!("{}-reg-{model_id}", fixture.suffix),
            register_body(model_id, model_version, digest),
        ))
        .await
        .expect("register must answer");
    assert_eq!(register.status(), StatusCode::CREATED);

    let approve = app
        .clone()
        .oneshot(action_request(
            &format!("{base}/approve"),
            &format!("{}-approve-{model_id}", fixture.suffix),
        ))
        .await
        .expect("approve must answer");
    assert_eq!(approve.status(), StatusCode::OK);

    let activate = app
        .clone()
        .oneshot(action_request(
            &format!("{base}/activate"),
            &format!("{}-activate-{model_id}", fixture.suffix),
        ))
        .await
        .expect("activate must answer");
    assert_eq!(activate.status(), StatusCode::OK);
}

async fn cleanup(pool: &PgPool, fixture: &Fixture) {
    let mut transaction = begin_as_owner(pool).await;
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update")
        .execute(&mut *transaction)
        .await
        .expect("the append-only trigger must be disableable by the table owner");
    for deployment in [&fixture.deployment_a, &fixture.deployment_b] {
        sqlx::query("DELETE FROM audit_events WHERE deployment_id = $1")
            .bind(&deployment.0)
            .execute(&mut *transaction)
            .await
            .expect("the audit fixture must be removable with the trigger disabled");
    }
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update")
        .execute(&mut *transaction)
        .await
        .expect("the append-only trigger must be restored");
    for deployment in [&fixture.deployment_a, &fixture.deployment_b] {
        sqlx::query("DELETE FROM inline_ml_models WHERE deployment_id = $1")
            .bind(&deployment.0)
            .execute(&mut *transaction)
            .await
            .expect("the registry fixture must be removable");
    }
    sqlx::query("DELETE FROM idempotency_keys WHERE key LIKE $1")
        .bind(format!("{}%", fixture.suffix))
        .execute(&mut *transaction)
        .await
        .expect("the idempotency fixture must be removable");
    sqlx::query("DELETE FROM customers WHERE id = $1")
        .bind(&fixture.customer_a.0)
        .execute(&mut *transaction)
        .await
        .expect("the customer fixture must be removable");
    for deployment in [&fixture.deployment_a, &fixture.deployment_b] {
        sqlx::query("DELETE FROM deployments WHERE id = $1")
            .bind(&deployment.0)
            .execute(&mut *transaction)
            .await
            .expect("the deployment fixture must be removable");
    }
    transaction
        .commit()
        .await
        .expect("the fixture cleanup must commit");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 019_inline_ml_models.sql"]
async fn register_approve_and_activate_are_audited_and_idempotent() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let app = app_with_pool(&pool, base_context(&fixture), fixture.deployment_a.clone());
    let uri = "/api/v1/admin/models";
    let base = "/api/v1/admin/models/multilabel-v1/1";
    let register_key = format!("{}-lifecycle-register", fixture.suffix);
    let approve_key = format!("{}-lifecycle-approve", fixture.suffix);

    let response = app
        .clone()
        .oneshot(register_request(
            uri,
            &register_key,
            register_body("multilabel-v1", "1", 'a'),
        ))
        .await
        .expect("register must answer");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    assert_eq!(body["data"]["approval_state"], json!("pending"));
    assert_eq!(body["data"]["model_id"], json!("multilabel-v1"));
    assert!(body["data"]["activated_at"].is_null());

    let response = app
        .clone()
        .oneshot(action_request(&format!("{base}/approve"), &approve_key))
        .await
        .expect("approve must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["data"]["approval_state"], json!("approved"));
    assert!(body["data"]["approved_by"].is_string());

    let response = app
        .clone()
        .oneshot(action_request(
            &format!("{base}/activate"),
            &format!("{}-lifecycle-activate", fixture.suffix),
        ))
        .await
        .expect("activate must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert!(body["data"]["activated_at"].is_string());
    assert!(body["data"]["rollback_model_id"].is_null());
    assert_eq!(active_count(&pool, &fixture.deployment_a.0).await, 1);

    for (action, expected) in [
        ("model_registered", 1),
        ("model_approved", 1),
        ("model_activated", 1),
    ] {
        let count = audit_count(&pool, &fixture.deployment_a.0, action, "success").await;
        assert_eq!(
            count, expected,
            "{action} must have exactly one success row"
        );
    }

    // A completed key replays the stored response without new audit rows.
    let response = app
        .clone()
        .oneshot(register_request(
            uri,
            &register_key,
            register_body("multilabel-v1", "1", 'a'),
        ))
        .await
        .expect("the register replay must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let replay = json_body(response).await;
    assert_eq!(
        replay["data"]["approval_state"],
        json!("pending"),
        "the replay must return the response stored at registration time"
    );

    let response = app
        .clone()
        .oneshot(action_request(&format!("{base}/approve"), &approve_key))
        .await
        .expect("the approve replay must answer");
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        audit_count(
            &pool,
            &fixture.deployment_a.0,
            "model_registered",
            "success"
        )
        .await,
        1,
        "a replayed key must not write a second audit row"
    );

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 019_inline_ml_models.sql"]
async fn activation_records_predecessor_and_rollback_restores_it() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let app = app_with_pool(&pool, base_context(&fixture), fixture.deployment_a.clone());

    activate_first_model(&app, &fixture, "reg-a", "1", 'a').await;
    activate_first_model(&app, &fixture, "reg-b", "2", 'b').await;

    let state_a = model_state(&pool, &fixture.deployment_a.0, "reg-a")
        .await
        .expect("reg-a must exist");
    assert_eq!(state_a.0, "approved");
    assert!(
        !state_a.2,
        "reg-a must be deactivated by reg-b's activation"
    );
    assert_eq!(
        state_a.3.as_deref(),
        Some("superseded"),
        "reg-a must record why it left the active slot"
    );

    let state_b = model_state(&pool, &fixture.deployment_a.0, "reg-b")
        .await
        .expect("reg-b must exist");
    assert!(state_b.2, "reg-b must be the active model");
    assert_eq!(
        state_b.1.as_deref(),
        Some("reg-a"),
        "reg-b must record the model it replaced as its rollback target"
    );
    assert_eq!(active_count(&pool, &fixture.deployment_a.0).await, 1);

    // Rollback is addressed to the active model's recorded target only.
    let response = app
        .clone()
        .oneshot(action_request(
            "/api/v1/admin/models/reg-a/1/rollback",
            &format!("{}-rollback", fixture.suffix),
        ))
        .await
        .expect("rollback must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["data"]["model_id"], json!("reg-a"));
    assert!(body["data"]["activated_at"].is_string());

    let state_a = model_state(&pool, &fixture.deployment_a.0, "reg-a")
        .await
        .expect("reg-a must exist");
    assert!(state_a.2, "reg-a must be active again after rollback");
    let state_b = model_state(&pool, &fixture.deployment_a.0, "reg-b")
        .await
        .expect("reg-b must exist");
    assert!(!state_b.2, "reg-b must be deactivated by the rollback");
    assert_eq!(state_b.3.as_deref(), Some("rollback"));
    assert_eq!(active_count(&pool, &fixture.deployment_a.0).await, 1);

    assert_eq!(
        audit_count(
            &pool,
            &fixture.deployment_a.0,
            "model_rolled_back",
            "success"
        )
        .await,
        1,
        "rollback must write exactly one success audit row"
    );

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 019_inline_ml_models.sql"]
async fn transitions_are_guarded() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let app = app_with_pool(&pool, base_context(&fixture), fixture.deployment_a.clone());
    let suffix = &fixture.suffix;

    // A pending model cannot be activated.
    let response = app
        .clone()
        .oneshot(register_request(
            "/api/v1/admin/models",
            &format!("{suffix}-guard-register"),
            register_body("guard-x", "1", 'c'),
        ))
        .await
        .expect("register must answer");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(action_request(
            "/api/v1/admin/models/guard-x/1/activate",
            &format!("{suffix}-guard-activate-pending"),
        ))
        .await
        .expect("activate must answer");
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "activating a pending model must be rejected"
    );

    // Rejection is terminal: approve after reject is a conflict.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v1/admin/models/guard-x/1/reject",
            Some(&format!("{suffix}-guard-reject")),
            Some(json!({"reason": "duplicate of an already registered artifact"})),
        ))
        .await
        .expect("reject must answer");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        model_state(&pool, &fixture.deployment_a.0, "guard-x")
            .await
            .expect("guard-x must exist")
            .0,
        "rejected"
    );

    let response = app
        .clone()
        .oneshot(action_request(
            "/api/v1/admin/models/guard-x/1/approve",
            &format!("{suffix}-guard-approve-rejected"),
        ))
        .await
        .expect("approve must answer");
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "approving a rejected model must be rejected"
    );

    // Duplicate registration of the same version is a conflict.
    let response = app
        .clone()
        .oneshot(register_request(
            "/api/v1/admin/models",
            &format!("{suffix}-guard-duplicate"),
            register_body("guard-x", "1", 'c'),
        ))
        .await
        .expect("the duplicate register must answer");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // The first activation has no rollback target.
    activate_first_model(&app, &fixture, "guard-y", "2", 'd').await;
    // The fail-closed permission-change budget is deliberately tiny (5 per
    // router state, shared across every high-risk call including conflicts).
    // Continue on a fresh router, as if the refill window had elapsed.
    let app = app_with_pool(&pool, base_context(&fixture), fixture.deployment_a.clone());
    let response = app
        .clone()
        .oneshot(action_request(
            "/api/v1/admin/models/guard-y/2/rollback",
            &format!("{suffix}-guard-rollback-empty"),
        ))
        .await
        .expect("rollback must answer");
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "rolling back the first activation has no target"
    );

    // Re-activating the already active model is a conflict.
    let response = app
        .clone()
        .oneshot(action_request(
            "/api/v1/admin/models/guard-y/2/activate",
            &format!("{suffix}-guard-reactivate"),
        ))
        .await
        .expect("the second activate must answer");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    assert_eq!(active_count(&pool, &fixture.deployment_a.0).await, 1);

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 019_inline_ml_models.sql"]
async fn denials_are_denied_and_audited() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let uri = "/api/v1/admin/models";
    let body = || register_body("denied-model", "1", 'e');

    let view_only = app_with_pool(
        &pool,
        view_only_context(&fixture),
        fixture.deployment_a.clone(),
    );
    let response = view_only
        .clone()
        .oneshot(register_request(
            uri,
            &format!("{}-denial-permission", fixture.suffix),
            body(),
        ))
        .await
        .expect("the register must answer");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let parsed = json_body(response).await;
    assert_eq!(parsed["code"], json!("FORBIDDEN"));

    let non_system = app_with_pool(
        &pool,
        non_system_context(&fixture),
        fixture.deployment_a.clone(),
    );
    let response = non_system
        .clone()
        .oneshot(register_request(
            uri,
            &format!("{}-denial-role", fixture.suffix),
            body(),
        ))
        .await
        .expect("the register must answer");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let denied_count =
        audit_count(&pool, &fixture.deployment_a.0, "model_registered", "denied").await;
    assert_eq!(
        denied_count, 2,
        "both denials must be audited (permission and role)"
    );
    assert_eq!(
        audit_count(
            &pool,
            &fixture.deployment_a.0,
            "model_registered",
            "success"
        )
        .await,
        0,
        "a denied request must not register anything"
    );
    assert_eq!(
        models_visible_to(&pool, Some(&fixture.deployment_a.0)).await,
        0
    );

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 019_inline_ml_models.sql"]
async fn deployment_scope_fails_closed_and_separates_deployments() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let app_a = app_with_pool(&pool, base_context(&fixture), fixture.deployment_a.clone());

    let response = app_a
        .clone()
        .oneshot(register_request(
            "/api/v1/admin/models",
            &format!("{}-scope-register", fixture.suffix),
            register_body("scope-model", "1", 'f'),
        ))
        .await
        .expect("register must answer");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Another deployment's registry reads empty through the API.
    let mut context_b = base_context(&fixture);
    context_b.deployment_id = fixture.deployment_b.clone();
    let app_b = app_with_pool(&pool, context_b, fixture.deployment_b.clone());
    let response = app_b
        .clone()
        .oneshot(json_request(
            Method::GET,
            "/api/v1/admin/models",
            None,
            None,
        ))
        .await
        .expect("the list must answer");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(
        body["data"]["models"],
        json!([]),
        "deployment B must observe no rows from deployment A"
    );

    // The request role: no deployment GUC => zero rows (fail closed), its
    // own scope => rows, a foreign scope => zero rows.
    assert_eq!(
        request_role_count(&pool, None).await,
        0,
        "an unset deployment scope must observe zero rows"
    );
    assert_eq!(
        request_role_count(&pool, Some(&fixture.deployment_a.0)).await,
        1,
        "the owning deployment scope must observe the row"
    );
    assert_eq!(
        request_role_count(&pool, Some(&fixture.deployment_b.0)).await,
        0,
        "a foreign deployment scope must observe zero rows"
    );

    cleanup(&pool, &fixture).await;
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 019_inline_ml_models.sql"]
async fn register_requires_idempotency_key() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let app = app_with_pool(&pool, base_context(&fixture), fixture.deployment_a.clone());

    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v1/admin/models",
            None,
            Some(register_body("no-idem", "1", 'a')),
        ))
        .await
        .expect("the register must answer");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["code"], json!("IDEMPOTENCY_REQUIRED"));
    assert_eq!(
        models_visible_to(&pool, Some(&fixture.deployment_a.0)).await,
        0
    );

    cleanup(&pool, &fixture).await;
}

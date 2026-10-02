//! Local PostgreSQL coverage for the Phase 3 OIDC identity integration.
//!
//! Proven against the migrated local instance (through
//! `012_oidc_identity_integration.sql`):
//!
//! 1. **`auth_subject` binding**: one IdP subject maps to at most one local
//!    admin user per deployment (partial unique index), never-null rows are
//!    unaffected, and row-level security keeps a deployment from re-binding
//!    another deployment's user.
//! 2. **`oidc_login_flows`**: the table that holds the in-flight CSRF state
//!    hash, nonce and PKCE verifier fails closed without the deployment GUC,
//!    is invisible and unwritable across deployments, and is claimed exactly
//!    once by the application's `DELETE … RETURNING`.
//!
//! Fixtures use a unique deployment id per run and are intentionally left in
//! the local database, matching `postgres_admin_rbac.rs`.

use chrono::{Duration, Utc};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use nullapart_mail_core::admin_rbac::{
    AdminRbacStore, AuditEventDraft, AuditSubject, AuthenticateOutcome, CreateUserOutcome,
    NewSession, NewUser, PostgresAdminRbacStore, SessionConfig,
};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Transaction};
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

/// Begins a transaction as the request role with the deployment RLS setting
/// applied transaction-locally. `None` leaves it unset (fail closed).
async fn begin_deploy_scoped<'a>(
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
            .expect("the deployment setting must be established");
    }
    transaction
}

struct Fixture {
    deployment: DeploymentId,
    deployment_b: DeploymentId,
    suffix: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = format!("local-oidc-{}", Uuid::new_v4().simple());
    let deployment = DeploymentId::new(&suffix.to_uppercase());
    let deployment_b = DeploymentId::new(&format!("{}-B", suffix.to_uppercase()));

    for id in [&deployment, &deployment_b] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id.0)
        .bind(&suffix)
        .execute(pool)
        .await
        .expect("the deployment fixture must be created");
    }
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(CustomerId::new(&format!("{suffix}-a")).0)
    .bind(&deployment.0)
    .bind("customer a")
    .execute(pool)
    .await
    .expect("the customer fixture must be created");

    Fixture {
        deployment,
        deployment_b,
        suffix,
    }
}

/// Bootstraps `login` as the deployment's first admin, which also seeds the
/// builtin roles every later creation relies on.
async fn bootstrap_first(pool: &PgPool, deployment: &DeploymentId, login: &str) -> Uuid {
    let store = PostgresAdminRbacStore::new(pool.clone());
    let outcome = store
        .authenticate_identity(&deployment.0, login, None)
        .await
        .expect("bootstrap must succeed");
    match outcome {
        AuthenticateOutcome::Bootstrapped { user, .. } => user.id,
        other => panic!("expected a bootstrap outcome, got {other:?}"),
    }
}

/// Adds another admin to a non-empty deployment (bootstrap only ever runs for
/// an empty one) so a test can hold several subjects in one deployment.
async fn create_admin(pool: &PgPool, deployment: &DeploymentId, login: &str) -> Uuid {
    let store = PostgresAdminRbacStore::new(pool.clone());
    let created = store
        .create_user(
            &deployment.0,
            NewUser {
                login: login.to_string(),
                display_name: login.to_string(),
                customer_id: None,
                roles: vec!["customer_admin".to_string()],
                created_by: "oidc-fixtures".to_string(),
            },
            AuditEventDraft {
                subject: AuditSubject {
                    actor_id: login.to_string(),
                    actor_login: login.to_string(),
                    actor_roles: vec!["system_admin".to_string()],
                    customer_id: None,
                    session_id: None,
                    source_ip: None,
                    trace_id: "oidc-fixtures".to_string(),
                    impersonated_subject: None,
                    impersonated_customer: None,
                },
                action: "admin_user_created".to_string(),
                resource_type: "admin_user".to_string(),
                resource_id: None,
                details: serde_json::json!({}),
            },
        )
        .await
        .expect("the fixture user must be created");
    match created {
        CreateUserOutcome::Created(user) => user.id,
        CreateUserOutcome::AlreadyExists => panic!("the fixture user must not already exist"),
    }
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 012_oidc_identity_integration.sql"]
async fn auth_subject_binds_one_subject_to_one_user_per_deployment() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let one = bootstrap_first(
        &pool,
        &fixture.deployment,
        &format!("one-{}@example.test", fixture.suffix),
    )
    .await;
    let two = create_admin(
        &pool,
        &fixture.deployment,
        &format!("two-{}@example.test", fixture.suffix),
    )
    .await;
    let three = create_admin(
        &pool,
        &fixture.deployment,
        &format!("three-{}@example.test", fixture.suffix),
    )
    .await;
    let foreign = bootstrap_first(
        &pool,
        &fixture.deployment_b,
        &format!("b-{}@example.test", fixture.suffix),
    )
    .await;

    // A subject binds to exactly one user in the deployment…
    sqlx::query("UPDATE admin_users SET auth_subject = $1 WHERE id = $2")
        .bind("subject-1")
        .bind(one)
        .execute(&pool)
        .await
        .expect("the first binding must succeed");
    let duplicate = sqlx::query("UPDATE admin_users SET auth_subject = $1 WHERE id = $2")
        .bind("subject-1")
        .bind(two)
        .execute(&pool)
        .await;
    assert!(
        duplicate.is_err(),
        "the same subject must not bind a second user in one deployment"
    );

    // …a different subject binds the second user…
    sqlx::query("UPDATE admin_users SET auth_subject = $1 WHERE id = $2")
        .bind("subject-2")
        .bind(two)
        .execute(&pool)
        .await
        .expect("a distinct subject must bind the second user");

    // …the same subject is usable again in another deployment…
    sqlx::query("UPDATE admin_users SET auth_subject = $1 WHERE id = $2")
        .bind("subject-1")
        .bind(foreign)
        .execute(&pool)
        .await
        .expect("the index must be scoped to a single deployment");

    // …and unbound users are unaffected by the partial index.
    sqlx::query("UPDATE admin_users SET auth_subject = $1 WHERE id = $2")
        .bind(Option::<&str>::None)
        .bind(three)
        .execute(&pool)
        .await
        .expect("null subjects are outside the uniqueness index");

    // The mapped projection: exactly one user resolves for the subject.
    let bound: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, login FROM admin_users \
         WHERE deployment_id = $1 AND auth_subject = $2",
    )
    .bind(&fixture.deployment.0)
    .bind("subject-1")
    .fetch_all(&pool)
    .await
    .expect("the binding must be readable");
    assert_eq!(bound.len(), 1, "one subject must resolve to one user");

    // Row-level security: deployment A cannot rebind deployment B's user.
    let mut foreign_scope = begin_deploy_scoped(&pool, Some(&fixture.deployment.0)).await;
    let touched = sqlx::query("UPDATE admin_users SET auth_subject = $1 WHERE id = $2")
        .bind("subject-hijack")
        .bind(foreign)
        .execute(&mut *foreign_scope)
        .await
        .expect("the scoped update must execute");
    assert_eq!(
        touched.rows_affected(),
        0,
        "another deployment must not rebind this subject"
    );
    foreign_scope
        .rollback()
        .await
        .expect("the probe transaction must roll back");

    let still_bound: Option<String> =
        sqlx::query_scalar("SELECT auth_subject FROM admin_users WHERE id = $1")
            .bind(foreign)
            .fetch_optional(&pool)
            .await
            .expect("the owner read must succeed");
    assert_eq!(
        still_bound.as_deref(),
        Some("subject-1"),
        "the foreign binding must be untouched"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 012_oidc_identity_integration.sql"]
async fn oidc_login_flows_fail_closed_and_are_claimed_once() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let state_hash: Vec<u8> = Sha256::digest(fixture.suffix.as_bytes()).to_vec();
    assert_eq!(state_hash.len(), 32, "state_hash is fixed at 32 bytes");

    sqlx::query(
        "INSERT INTO oidc_login_flows \
           (state_hash, deployment_id, nonce, code_verifier, flow_kind, return_to, expires_at) \
         VALUES ($1, $2, $3, $4, 'login', '/', $5)",
    )
    .bind(&state_hash)
    .bind(&fixture.deployment.0)
    .bind("nonce-fixture")
    .bind("pkce-verifier-fixture")
    .bind(Utc::now() + Duration::minutes(10))
    .execute(&pool)
    .await
    .expect("the flow fixture must be created");

    // Without the deployment GUC the row does not exist (fail closed), and a
    // half-known state hash cannot be claimed by an unscoped writer.
    let mut unscoped = begin_deploy_scoped(&pool, None).await;
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_login_flows")
        .fetch_one(&mut *unscoped)
        .await
        .expect("the unscoped read must be executable");
    assert_eq!(visible, 0, "flows must fail closed without the GUC");
    let claimed = sqlx::query("DELETE FROM oidc_login_flows WHERE state_hash = $1 RETURNING nonce")
        .bind(&state_hash)
        .fetch_optional(&mut *unscoped)
        .await;
    match claimed {
        Ok(None) => {},
        Ok(Some(_)) => panic!("an unscoped claim must never observe the flow"),
        Err(error) => assert!(
            error
                .as_database_error()
                .is_some_and(|db| db.message().contains("row-level security")),
            "an unscoped claim must be refused by RLS, got: {error}"
        ),
    }
    unscoped
        .rollback()
        .await
        .expect("the probe transaction must roll back");

    // The owning deployment sees the flow and claims it exactly once.
    let mut scoped = begin_deploy_scoped(&pool, Some(&fixture.deployment.0)).await;
    let first = sqlx::query_scalar::<_, String>(
        "DELETE FROM oidc_login_flows WHERE state_hash = $1 RETURNING nonce",
    )
    .bind(&state_hash)
    .fetch_optional(&mut *scoped)
    .await
    .expect("the owning claim must execute");
    assert_eq!(
        first.as_deref(),
        Some("nonce-fixture"),
        "the claim must return the stored nonce"
    );
    let second = sqlx::query_scalar::<_, String>(
        "DELETE FROM oidc_login_flows WHERE state_hash = $1 RETURNING nonce",
    )
    .bind(&state_hash)
    .fetch_optional(&mut *scoped)
    .await
    .expect("the second claim must execute");
    assert_eq!(second, None, "a flow must be claimable exactly once");
    scoped.commit().await.expect("the owning claim must commit");

    // Another deployment can neither see nor write the flow.
    let other_hash: Vec<u8> = Sha256::digest(format!("{}-b", fixture.suffix).as_bytes()).to_vec();
    let mut foreign = begin_deploy_scoped(&pool, Some(&fixture.deployment_b.0)).await;
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_login_flows WHERE deployment_id = $1")
            .bind(&fixture.deployment.0)
            .fetch_one(&mut *foreign)
            .await
            .expect("the foreign read must be executable");
    assert_eq!(visible, 0, "another deployment must not see this flow");
    let injected = sqlx::query(
        "INSERT INTO oidc_login_flows \
           (state_hash, deployment_id, nonce, code_verifier, flow_kind, return_to, expires_at) \
         VALUES ($1, $2, 'foreign-nonce', 'foreign-verifier', 'login', '/', $3)",
    )
    .bind(&other_hash)
    .bind(&fixture.deployment.0)
    .bind(Utc::now() + Duration::minutes(10))
    .execute(&mut *foreign)
    .await;
    assert!(
        injected.is_err(),
        "writing a flow into another deployment must be rejected"
    );
    foreign
        .rollback()
        .await
        .expect("the probe transaction must roll back");
}

/// A re-auth flow is only storable when it is bound to the session it steps
/// up; a login flow must not carry one. `SessionConfig` is the same floor the
/// HTTP layer uses, so the fixture exercises the real cascade shape.
#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 012_oidc_identity_integration.sql"]
async fn reauth_flows_must_bind_a_session_and_cascade_with_it() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let store = PostgresAdminRbacStore::new(pool.clone());
    let identity = format!("stepup-{}@example.test", fixture.suffix);

    let AuthenticateOutcome::Bootstrapped { user, .. } = store
        .authenticate_identity(&fixture.deployment.0, &identity, None)
        .await
        .expect("bootstrap must succeed")
    else {
        panic!("the first login must bootstrap");
    };
    let session_id = Uuid::new_v4();
    let config = SessionConfig::default();
    store
        .create_session(
            &fixture.deployment.0,
            NewSession {
                id: session_id,
                user_id: user.id,
                token_hash: Sha256::digest(fixture.suffix.as_bytes()).to_vec(),
                csrf_token: "csrf-fixture".to_string(),
                source_ip: None,
                authenticated_at: Utc::now(),
                absolute_expires_at: Utc::now() + Duration::seconds(config.absolute_ttl_secs),
                step_up_at: None,
            },
            AuditEventDraft {
                subject: AuditSubject {
                    actor_id: user.id.to_string(),
                    actor_login: identity.clone(),
                    actor_roles: user.roles.clone(),
                    customer_id: None,
                    session_id: Some(session_id.to_string()),
                    source_ip: None,
                    trace_id: format!("{}-trace", fixture.suffix),
                    impersonated_subject: None,
                    impersonated_customer: None,
                },
                action: "session_login".to_string(),
                resource_type: "session".to_string(),
                resource_id: None,
                details: serde_json::json!({}),
            },
        )
        .await
        .expect("the session must be created");

    // A reauth row without a session is refused by the table's own CHECK.
    let bare_hash: Vec<u8> = Sha256::digest(format!("{}-bare", fixture.suffix).as_bytes()).to_vec();
    let refused = sqlx::query(
        "INSERT INTO oidc_login_flows \
           (state_hash, deployment_id, nonce, code_verifier, flow_kind, expires_at) \
         VALUES ($1, $2, 'nonce', 'verifier', 'reauth', $3)",
    )
    .bind(&bare_hash)
    .bind(&fixture.deployment.0)
    .bind(Utc::now() + Duration::minutes(10))
    .execute(&pool)
    .await;
    assert!(refused.is_err(), "a reauth flow must be bound to a session");

    // The bound row exists and disappears with its session (ON DELETE
    // CASCADE), so a step-up flow never outlives the session it steps up.
    let bound_hash: Vec<u8> =
        Sha256::digest(format!("{}-bound", fixture.suffix).as_bytes()).to_vec();
    sqlx::query(
        "INSERT INTO oidc_login_flows \
           (state_hash, deployment_id, nonce, code_verifier, flow_kind, session_id, expires_at) \
         VALUES ($1, $2, 'nonce', 'verifier', 'reauth', $3, $4)",
    )
    .bind(&bound_hash)
    .bind(&fixture.deployment.0)
    .bind(session_id)
    .bind(Utc::now() + Duration::minutes(10))
    .execute(&pool)
    .await
    .expect("a bound reauth flow must be storable");

    sqlx::query("DELETE FROM admin_sessions WHERE id = $1")
        .bind(session_id)
        .execute(&pool)
        .await
        .expect("the session must be deletable");
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_login_flows WHERE session_id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .expect("the flow count must be readable");
    assert_eq!(remaining, 0, "a step-up flow must not outlive its session");
}

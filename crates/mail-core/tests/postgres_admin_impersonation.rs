//! Local PostgreSQL coverage for audited customer entry (docs/03).
//!
//! Proven against the migrated local instance (through
//! `017_customer_entry_impersonation.sql`):
//!
//! 1. **Deployment row-level security** on `admin_impersonations`: without
//!    `app.current_deployment_id` every read returns zero rows and writes are
//!    rejected (fail closed); a mismatched deployment cannot see or write the
//!    fixture's rows. Customer-entry rows carry NULL subject columns.
//! 2. **Store lifecycle** (`PostgresAdminRbacStore`): start and end write
//!    their audit rows in the same transaction, duplicate starts are refused,
//!    `resolve_session` overlays the entered customer without narrowing the
//!    actor's permissions, and revoking the session closes the interval
//!    without an extra end audit row.
//!
//! Fixtures use a unique deployment id per run and are intentionally left in
//! the local database, matching `postgres_admin_rbac.rs`.

use chrono::{Duration, Utc};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use nullapart_mail_core::admin_rbac::{
    AdminRbacStore, AuditEventDraft, AuditSubject, AuthenticateOutcome, NewImpersonation,
    NewSession, PostgresAdminRbacStore, SessionConfig,
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
    customer_a: CustomerId,
    deployment_b: DeploymentId,
    suffix: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = format!("local-impersonation-{}", Uuid::new_v4().simple());
    let deployment = DeploymentId::new(&suffix.to_uppercase());
    let deployment_b = DeploymentId::new(&format!("{}-B", suffix.to_uppercase()));
    let customer_a = CustomerId::new(&format!("{suffix}-a"));

    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&deployment.0)
    .bind(&suffix)
    .execute(pool)
    .await
    .expect("the deployment fixture must be created");
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name) VALUES ($1, 'local', $2) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&deployment_b.0)
    .bind(&suffix)
    .execute(pool)
    .await
    .expect("the second deployment fixture must be created");
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&customer_a.0)
    .bind(&deployment.0)
    .bind("customer a")
    .execute(pool)
    .await
    .expect("the customer fixture must be created");

    Fixture {
        deployment,
        deployment_b,
        customer_a,
        suffix,
    }
}

fn subject(fixture: &Fixture, actor: &str) -> AuditSubject {
    AuditSubject {
        actor_id: actor.to_string(),
        actor_login: format!("{actor}@example.test"),
        actor_roles: vec!["system_admin".to_string()],
        customer_id: Some(fixture.customer_a.0.clone()),
        session_id: Some(Uuid::new_v4().to_string()),
        source_ip: Some("192.168.8.4".to_string()),
        trace_id: format!("{}-trace", fixture.suffix),
        impersonated_subject: None,
        impersonated_customer: None,
    }
}

fn draft(fixture: &Fixture, actor: &str, action: &str, resource_type: &str) -> AuditEventDraft {
    AuditEventDraft {
        subject: subject(fixture, actor),
        action: action.to_string(),
        resource_type: resource_type.to_string(),
        resource_id: None,
        details: serde_json::json!({}),
    }
}

/// Mirrors the entry handlers: no subject identity, the entered customer is
/// attributed on the audit row.
fn impersonation_draft(
    fixture: &Fixture,
    actor: &str,
    action: &str,
    impersonation_id: Uuid,
) -> AuditEventDraft {
    let mut audit = draft(fixture, actor, action, "admin_impersonation");
    audit.resource_id = Some(impersonation_id.to_string());
    audit.subject.customer_id = Some(fixture.customer_a.0.clone());
    audit.subject.impersonated_subject = None;
    audit.subject.impersonated_customer = Some(fixture.customer_a.0.clone());
    audit
}

async fn audit_count(pool: &PgPool, deployment: &DeploymentId, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE deployment_id = $1 AND action = $2")
        .bind(&deployment.0)
        .bind(action)
        .fetch_one(pool)
        .await
        .expect("audit rows must be readable")
}

/// Bootstraps the deployment's first admin and an active session; returns
/// (identity, actor_user_id, session_id, token_hash).
async fn provision_session(
    store: &PostgresAdminRbacStore,
    fixture: &Fixture,
) -> (String, Uuid, Uuid, Vec<u8>) {
    let identity = format!("admin-{}@example.test", fixture.suffix);
    let outcome = store
        .authenticate_identity(
            &fixture.deployment.0,
            &identity,
            Some(&fixture.customer_a.0),
        )
        .await
        .expect("the first login must bootstrap");
    let AuthenticateOutcome::Bootstrapped { user, .. } = outcome else {
        panic!("the first identity must bootstrap the deployment");
    };

    let session_id = Uuid::new_v4();
    let token_hash =
        Sha256::digest(format!("{}-impersonation-session", fixture.suffix).as_bytes()).to_vec();
    let config = SessionConfig::default();
    store
        .create_session(
            &fixture.deployment.0,
            NewSession {
                id: session_id,
                user_id: user.id,
                token_hash: token_hash.clone(),
                csrf_token: format!("csrf-{}", fixture.suffix),
                source_ip: Some("192.168.8.4".to_string()),
                authenticated_at: Utc::now(),
                absolute_expires_at: Utc::now() + Duration::seconds(config.absolute_ttl_secs),
                step_up_at: Some(Utc::now()),
            },
            draft(fixture, &identity, "session_login", "session"),
        )
        .await
        .expect("the session must be created");

    (identity, user.id, session_id, token_hash)
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 017_customer_entry_impersonation.sql"]
async fn rls_admin_impersonations_fail_closed_without_or_against_the_wrong_deployment() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let store = PostgresAdminRbacStore::new(pool.clone());
    let (identity, actor_user_id, session_id, _token_hash) =
        provision_session(&store, &fixture).await;

    // Without the deployment setting every read is empty (fail closed).
    let mut scoped = begin_deploy_scoped(&pool, None).await;
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_impersonations")
        .fetch_one(&mut *scoped)
        .await
        .expect("the fail-closed read must run");
    assert_eq!(visible, 0, "RLS must hide every row without a deployment");
    scoped.commit().await.expect("the transaction must close");

    // A customer-entry row (NULL subject columns) written under the correct
    // deployment is invisible elsewhere.
    let impersonation_id = Uuid::new_v4();
    let mut scoped = begin_deploy_scoped(&pool, Some(&fixture.deployment.0)).await;
    sqlx::query(
        "INSERT INTO admin_impersonations \
         (id, deployment_id, session_id, actor_user_id, actor_login, \
          subject_user_id, subject_login, subject_customer_id, reason, started_at) \
         VALUES ($1, $2, $3, $4, $5, NULL, NULL, $6, $7, $8)",
    )
    .bind(impersonation_id)
    .bind(&fixture.deployment.0)
    .bind(session_id)
    .bind(actor_user_id)
    .bind(&identity)
    .bind(&fixture.customer_a.0)
    .bind("a sufficiently long reason")
    .bind(Utc::now())
    .execute(&mut *scoped)
    .await
    .expect("the correctly scoped write must succeed");
    scoped.commit().await.expect("the transaction must commit");

    let mut scoped = begin_deploy_scoped(&pool, Some(&fixture.deployment_b.0)).await;
    let foreign: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_impersonations")
        .fetch_one(&mut *scoped)
        .await
        .expect("the foreign read must run");
    assert_eq!(foreign, 0, "another deployment must not see the entry row");

    // And a write against the wrong deployment is rejected outright.
    let rejected = sqlx::query(
        "INSERT INTO admin_impersonations \
         (id, deployment_id, session_id, actor_user_id, actor_login, \
          subject_user_id, subject_login, subject_customer_id, reason, started_at) \
         VALUES ($1, $2, $3, $4, $5, NULL, NULL, $6, $7, $8)",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.deployment.0)
    .bind(session_id)
    .bind(Uuid::new_v4())
    .bind("intruder")
    .bind(&fixture.customer_a.0)
    .bind("a sufficiently long reason")
    .bind(Utc::now())
    .execute(&mut *scoped)
    .await;
    assert!(
        rejected.is_err(),
        "a mismatched deployment write must violate the RLS policy"
    );
    scoped.commit().await.expect("the transaction must close");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 017_customer_entry_impersonation.sql"]
async fn customer_entry_start_end_resolve_and_audit_lifecycle() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let store = PostgresAdminRbacStore::new(pool.clone());
    let (identity, actor_user_id, session_id, token_hash) =
        provision_session(&store, &fixture).await;
    let config = SessionConfig::default();

    let impersonation_id = Uuid::new_v4();
    store
        .start_impersonation(
            &fixture.deployment.0,
            NewImpersonation {
                id: impersonation_id,
                session_id,
                actor_user_id,
                actor_login: identity.clone(),
                customer_id: fixture.customer_a.0.clone(),
                reason: "investigating a customer report".to_string(),
                started_at: Utc::now(),
            },
            impersonation_draft(
                &fixture,
                &identity,
                "impersonation_started",
                impersonation_id,
            ),
        )
        .await
        .expect("the entry interval must start");
    assert_eq!(
        audit_count(&pool, &fixture.deployment, "impersonation_started").await,
        1,
        "start must write exactly one audit row in the same transaction"
    );
    let (impersonated_subject, impersonated_customer, event_customer): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT impersonated_subject, impersonated_customer, customer_id \
         FROM audit_events WHERE deployment_id = $1 AND action = 'impersonation_started'",
    )
    .bind(&fixture.deployment.0)
    .fetch_one(&pool)
    .await
    .expect("the start audit row must be readable");
    assert_eq!(
        impersonated_subject, None,
        "customer entry has no acted-as subject identity"
    );
    assert_eq!(
        impersonated_customer.as_deref(),
        Some(fixture.customer_a.0.as_str())
    );
    assert_eq!(
        event_customer.as_deref(),
        Some(fixture.customer_a.0.as_str()),
        "the event belongs to the entered tenant"
    );

    // The stored row itself carries NULL subject columns.
    let (subject_user_id, subject_login): (Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT subject_user_id, subject_login FROM admin_impersonations \
         WHERE deployment_id = $1 AND id = $2",
    )
    .bind(&fixture.deployment.0)
    .bind(impersonation_id)
    .fetch_one(&pool)
    .await
    .expect("the entry row must be readable");
    assert_eq!(subject_user_id, None, "entry records no subject user");
    assert_eq!(subject_login, None, "entry records no subject login");

    // A second start for the same session is refused (one active interval).
    let duplicate = store
        .start_impersonation(
            &fixture.deployment.0,
            NewImpersonation {
                id: Uuid::new_v4(),
                session_id,
                actor_user_id,
                actor_login: identity.clone(),
                customer_id: fixture.customer_a.0.clone(),
                reason: "a second reason that is long enough".to_string(),
                started_at: Utc::now(),
            },
            impersonation_draft(&fixture, &identity, "impersonation_started", Uuid::new_v4()),
        )
        .await;
    assert!(
        duplicate.is_err(),
        "a session must never carry two active intervals"
    );

    // Resolution overlays the entered customer and keeps every permission.
    let active = store
        .resolve_session(&fixture.deployment.0, &token_hash, &config)
        .await
        .expect("the session must resolve")
        .expect("the session must be active");
    let overlay = active
        .impersonation
        .as_ref()
        .expect("the overlay must be resolved with the session");
    assert_eq!(overlay.customer_id, fixture.customer_a.0);
    assert_eq!(overlay.customer_display_name, "customer a");
    assert_eq!(overlay.customer_lifecycle, "active");
    assert_eq!(overlay.reason, "investigating a customer report");
    assert!(
        active
            .permissions
            .contains(&"admin:users:manage".to_string()),
        "the actor's permissions survive entry"
    );
    assert!(
        active
            .permissions
            .contains(&"admin:impersonate".to_string()),
        "entry must never narrow the actor's permissions"
    );

    // Ending is audited once and idempotent.
    let ended = store
        .end_impersonation(
            &fixture.deployment.0,
            session_id,
            "manual",
            impersonation_draft(&fixture, &identity, "impersonation_ended", impersonation_id),
        )
        .await
        .expect("the interval must end");
    assert!(ended);
    let ended_again = store
        .end_impersonation(
            &fixture.deployment.0,
            session_id,
            "manual",
            impersonation_draft(&fixture, &identity, "impersonation_ended", impersonation_id),
        )
        .await
        .expect("the idempotent retry must run");
    assert!(
        !ended_again,
        "ending again must resolve without a second change"
    );
    assert_eq!(
        audit_count(&pool, &fixture.deployment, "impersonation_ended").await,
        1,
        "only the first end writes an audit row"
    );

    let restored = store
        .resolve_session(&fixture.deployment.0, &token_hash, &config)
        .await
        .expect("the session must resolve")
        .expect("the session must stay active");
    assert!(
        restored.impersonation.is_none(),
        "the overlay disappears once ended"
    );
    assert!(
        restored
            .permissions
            .contains(&"admin:impersonate".to_string()),
        "the real actor's permissions were never altered"
    );
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 017_customer_entry_impersonation.sql"]
async fn revoke_session_ends_the_interval_without_an_extra_audit_row() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let store = PostgresAdminRbacStore::new(pool.clone());
    let (identity, actor_user_id, session_id, token_hash) =
        provision_session(&store, &fixture).await;
    let config = SessionConfig::default();

    let impersonation_id = Uuid::new_v4();
    store
        .start_impersonation(
            &fixture.deployment.0,
            NewImpersonation {
                id: impersonation_id,
                session_id,
                actor_user_id,
                actor_login: identity.clone(),
                customer_id: fixture.customer_a.0.clone(),
                reason: "entering before signing out entirely".to_string(),
                started_at: Utc::now(),
            },
            impersonation_draft(
                &fixture,
                &identity,
                "impersonation_started",
                impersonation_id,
            ),
        )
        .await
        .expect("the entry interval must start");

    store
        .revoke_session(
            &fixture.deployment.0,
            session_id,
            "manual sign-out",
            draft(&fixture, &identity, "session_logout", "session"),
        )
        .await
        .expect("the session must be revoked");

    let resolved = store
        .resolve_session(&fixture.deployment.0, &token_hash, &config)
        .await
        .expect("the resolution query must run");
    assert!(
        resolved.is_none(),
        "a revoked session must never resolve again"
    );

    let (ended_at, ended_reason): (Option<chrono::DateTime<Utc>>, Option<String>) = sqlx::query_as(
        "SELECT ended_at, ended_reason FROM admin_impersonations \
         WHERE deployment_id = $1 AND id = $2",
    )
    .bind(&fixture.deployment.0)
    .bind(impersonation_id)
    .fetch_one(&pool)
    .await
    .expect("the interval row must be readable");
    assert!(ended_at.is_some(), "logout must close the interval");
    assert_eq!(ended_reason.as_deref(), Some("session_revoked"));

    assert_eq!(
        audit_count(&pool, &fixture.deployment, "session_logout").await,
        1
    );
    assert_eq!(
        audit_count(&pool, &fixture.deployment, "impersonation_ended").await,
        0,
        "logout ends the interval without a separate end audit row"
    );
}

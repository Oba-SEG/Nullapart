//! Local PostgreSQL coverage for the Phase 3 admin sessions/RBAC foundation.
//!
//! Proven against the migrated local instance (through
//! `010_admin_rbac_sessions.sql`):
//!
//! 1. **Deployment row-level security** on the `admin_*` tables: without
//!    `app.current_deployment_id` every read returns zero rows and writes are
//!    rejected (fail closed); a mismatched deployment cannot see or write the
//!    fixture's rows.
//! 2. **Application store scoping** (`PostgresAdminRbacStore`): bootstrap
//!    login, session create/resolve/expiry/revoke with same-transaction audit
//!    rows, idempotent role grant/revoke auditing, and cross-deployment
//!    isolation on every read and mutation.
//!
//! Fixtures use a unique deployment id per run and are intentionally left in
//! the local database, matching `postgres_admin_audit.rs`.

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
    customer_a: CustomerId,
    deployment_b: DeploymentId,
    suffix: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = format!("local-rbac-{}", Uuid::new_v4().simple());
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

/// Mirrors the HTTP handlers, which attribute role changes to the target
/// admin user id in `resource_id`.
fn draft_for_user(fixture: &Fixture, actor: &str, action: &str, user_id: Uuid) -> AuditEventDraft {
    AuditEventDraft {
        subject: subject(fixture, actor),
        action: action.to_string(),
        resource_type: "admin_user".to_string(),
        resource_id: Some(user_id.to_string()),
        details: serde_json::json!({}),
    }
}

async fn audit_count(pool: &PgPool, deployment: &DeploymentId, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE deployment_id = $1 AND action = $2")
        .bind(&deployment.0)
        .bind(action)
        .fetch_one(pool)
        .await
        .expect("audit rows must be readable")
}

async fn audit_count_for_resource(
    pool: &PgPool,
    deployment: &DeploymentId,
    action: &str,
    resource_id: &str,
) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events \
         WHERE deployment_id = $1 AND action = $2 AND resource_id = $3",
    )
    .bind(&deployment.0)
    .bind(action)
    .bind(resource_id)
    .fetch_one(pool)
    .await
    .expect("audit rows must be readable")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 010_admin_rbac_sessions.sql"]
async fn rls_admin_tables_fail_closed_without_or_against_the_wrong_deployment() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let store = PostgresAdminRbacStore::new(pool.clone());

    // The store seeds the builtin roles and the first admin user for this
    // deployment (as the owner role, which RLS does not gate).
    let outcome = store
        .authenticate_identity(
            &fixture.deployment.0,
            "rls-probe@example.test",
            Some(&fixture.customer_a.0),
        )
        .await
        .expect("bootstrap must succeed");
    assert!(matches!(outcome, AuthenticateOutcome::Bootstrapped { .. }));

    // No deployment setting => zero visible rows (fail closed).
    let mut unscoped = begin_deploy_scoped(&pool, None).await;
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_users WHERE deployment_id = $1")
            .bind(&fixture.deployment.0)
            .fetch_one(&mut *unscoped)
            .await
            .expect("the unscoped read must be executable");
    assert_eq!(visible, 0, "RLS must hide admin users without the GUC");
    let rejected = sqlx::query(
        "INSERT INTO admin_users (id, deployment_id, login, display_name) \
         VALUES ($1, $2, 'unscoped@invalid.test', 'unscoped')",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.deployment.0)
    .execute(&mut *unscoped)
    .await;
    assert!(
        rejected.is_err(),
        "writes must be rejected without the deployment GUC"
    );
    unscoped
        .rollback()
        .await
        .expect("the probe transaction must roll back");

    // The matching deployment sees the row...
    let mut scoped = begin_deploy_scoped(&pool, Some(&fixture.deployment.0)).await;
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_users WHERE deployment_id = $1")
            .bind(&fixture.deployment.0)
            .fetch_one(&mut *scoped)
            .await
            .expect("the scoped read must be executable");
    assert!(visible >= 1);
    scoped.commit().await.expect("the scoped read must commit");

    // ...and a different deployment sees none and cannot write into it.
    let mut foreign = begin_deploy_scoped(&pool, Some(&fixture.deployment_b.0)).await;
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_users WHERE deployment_id = $1")
            .bind(&fixture.deployment.0)
            .fetch_one(&mut *foreign)
            .await
            .expect("the foreign read must be executable");
    assert_eq!(visible, 0, "RLS must hide another deployment's admin users");
    let rejected = sqlx::query(
        "INSERT INTO admin_users (id, deployment_id, login, display_name) \
         VALUES ($1, $2, 'foreign@invalid.test', 'foreign')",
    )
    .bind(Uuid::new_v4())
    .bind(&fixture.deployment.0)
    .execute(&mut *foreign)
    .await;
    assert!(
        rejected.is_err(),
        "writes into another deployment must be rejected"
    );
    foreign
        .rollback()
        .await
        .expect("the probe transaction must roll back");

    // Session rows follow the same deployment policy.
    let mut session_probe = begin_deploy_scoped(&pool, None).await;
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_sessions")
        .fetch_one(&mut *session_probe)
        .await
        .expect("the unscoped session read must be executable");
    assert_eq!(sessions, 0, "sessions must fail closed without the GUC");
    session_probe
        .rollback()
        .await
        .expect("the probe transaction must roll back");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 010_admin_rbac_sessions.sql"]
async fn store_bootstrap_session_lifecycle_is_audited_and_scoped() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let store = PostgresAdminRbacStore::new(pool.clone());
    let config = SessionConfig::default();
    let identity = format!("{}@example.test", fixture.suffix);

    let outcome = store
        .authenticate_identity(
            &fixture.deployment.0,
            &identity,
            Some(&fixture.customer_a.0),
        )
        .await
        .expect("the first login must bootstrap");
    let (user, permissions) = match outcome {
        AuthenticateOutcome::Bootstrapped { user, permissions } => (user, permissions),
        other => panic!(
            "expected a bootstrap outcome, got {:?}",
            discriminant_name(&other)
        ),
    };
    assert!(user.roles.contains(&"system_admin".to_string()));
    assert!(permissions.contains(&"audit:view".to_string()));
    assert!(permissions.contains(&"admin:users:manage".to_string()));
    assert!(permissions.contains(&"admin:impersonate".to_string()));

    // A second login for the same identity is a plain authentication.
    let outcome = store
        .authenticate_identity(
            &fixture.deployment.0,
            &identity,
            Some(&fixture.customer_a.0),
        )
        .await
        .expect("the second login must resolve");
    assert!(matches!(outcome, AuthenticateOutcome::Authenticated { .. }));

    // Unknown and suspended identities are refused.
    let outcome = store
        .authenticate_identity(
            &fixture.deployment.0,
            "unknown-identity@example.test",
            Some(&fixture.customer_a.0),
        )
        .await
        .expect("the unknown identity query must succeed");
    assert!(matches!(outcome, AuthenticateOutcome::Unknown));

    sqlx::query(
        "UPDATE admin_users SET lifecycle = 'suspended' WHERE deployment_id = $1 AND login = $2",
    )
    .bind(&fixture.deployment.0)
    .bind(&identity)
    .execute(&pool)
    .await
    .expect("the suspension must be applied");
    let outcome = store
        .authenticate_identity(
            &fixture.deployment.0,
            &identity,
            Some(&fixture.customer_a.0),
        )
        .await
        .expect("the suspended identity query must succeed");
    assert!(matches!(outcome, AuthenticateOutcome::Suspended));
    sqlx::query(
        "UPDATE admin_users SET lifecycle = 'active' WHERE deployment_id = $1 AND login = $2",
    )
    .bind(&fixture.deployment.0)
    .bind(&identity)
    .execute(&pool)
    .await
    .expect("the lifecycle must be restored for the session probes");

    // Session creation writes its login audit row in the same transaction.
    let session_id = Uuid::new_v4();
    let token_hash = Sha256::digest(format!("{}-active", fixture.suffix).as_bytes()).to_vec();
    store
        .create_session(
            &fixture.deployment.0,
            NewSession {
                id: session_id,
                user_id: user.id,
                token_hash: token_hash.clone(),
                csrf_token: "csrf-fixture".to_string(),
                source_ip: Some("192.168.8.4".to_string()),
                authenticated_at: Utc::now(),
                absolute_expires_at: Utc::now() + Duration::seconds(config.absolute_ttl_secs),
                step_up_at: Some(Utc::now()),
            },
            draft(&fixture, &identity, "session_login", "session"),
        )
        .await
        .expect("the session must be created");
    assert_eq!(
        audit_count(&pool, &fixture.deployment, "session_login").await,
        1,
        "login must write exactly one audit row"
    );

    let active = store
        .resolve_session(&fixture.deployment.0, &token_hash, &config)
        .await
        .expect("the session must resolve")
        .expect("the freshly created session must be active");
    assert_eq!(active.session_id, session_id);
    assert_eq!(active.csrf_token, "csrf-fixture");
    assert!(active.permissions.contains(&"audit:view".to_string()));

    // Resolution is bounded to the deployment that created the session.
    let foreign = store
        .resolve_session(&fixture.deployment_b.0, &token_hash, &config)
        .await
        .expect("the foreign resolution query must succeed");
    assert!(
        foreign.is_none(),
        "a session must not resolve under another deployment"
    );

    // An absolutely expired session never resolves.
    let expired_hash = Sha256::digest(format!("{}-expired", fixture.suffix).as_bytes()).to_vec();
    store
        .create_session(
            &fixture.deployment.0,
            NewSession {
                id: Uuid::new_v4(),
                user_id: user.id,
                token_hash: expired_hash.clone(),
                csrf_token: "csrf-expired".to_string(),
                source_ip: None,
                authenticated_at: Utc::now() - Duration::seconds(config.absolute_ttl_secs * 2),
                absolute_expires_at: Utc::now() - Duration::seconds(1),
                step_up_at: None,
            },
            draft(&fixture, &identity, "session_login", "session"),
        )
        .await
        .expect("the expired session must be creatable");
    assert_eq!(
        audit_count(&pool, &fixture.deployment, "session_login").await,
        2
    );
    let expired = store
        .resolve_session(&fixture.deployment.0, &expired_hash, &config)
        .await
        .expect("the expiry resolution query must succeed");
    assert!(
        expired.is_none(),
        "an absolutely expired session must not resolve"
    );

    // Logout revokes atomically with its audit row.
    store
        .revoke_session(
            &fixture.deployment.0,
            session_id,
            "logout",
            draft(&fixture, &identity, "session_logout", "session"),
        )
        .await
        .expect("the session must be revoked");
    assert_eq!(
        audit_count(&pool, &fixture.deployment, "session_logout").await,
        1
    );
    let revoked = store
        .resolve_session(&fixture.deployment.0, &token_hash, &config)
        .await
        .expect("the revoked resolution query must succeed");
    assert!(revoked.is_none(), "a revoked session must not resolve");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 010_admin_rbac_sessions.sql"]
async fn store_user_and_role_management_is_scoped_and_audited() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let store = PostgresAdminRbacStore::new(pool.clone());
    let actor = format!("admin-{}@example.test", fixture.suffix);
    let created_by = format!("creator-{}", fixture.suffix);
    let login_a = format!("operator-a-{}@example.test", fixture.suffix);
    let login_b = format!("operator-b-{}@example.test", fixture.suffix);

    // Bootstrap the deployment's first admin so builtin roles exist.
    let outcome = store
        .authenticate_identity(&fixture.deployment.0, &actor, Some(&fixture.customer_a.0))
        .await
        .expect("bootstrap must succeed");
    assert!(matches!(outcome, AuthenticateOutcome::Bootstrapped { .. }));

    // Customer-scoped creation with a builtin role grant.
    let created = store
        .create_user(
            &fixture.deployment.0,
            NewUser {
                login: login_a.clone(),
                display_name: "Operator A".to_string(),
                customer_id: Some(fixture.customer_a.0.clone()),
                roles: vec!["customer_admin".to_string()],
                created_by: created_by.clone(),
            },
            draft(&fixture, &actor, "admin_user_created", "admin_user"),
        )
        .await
        .expect("the user must be created");
    let CreateUserOutcome::Created(user_a) = created else {
        panic!("the first creation must succeed");
    };
    assert_eq!(user_a.roles, vec!["customer_admin".to_string()]);

    // A duplicate login is refused without an audit row (no change).
    let duplicate = store
        .create_user(
            &fixture.deployment.0,
            NewUser {
                login: login_a.clone(),
                display_name: "Operator A copy".to_string(),
                customer_id: Some(fixture.customer_a.0.clone()),
                roles: vec!["customer_admin".to_string()],
                created_by: created_by.clone(),
            },
            draft(&fixture, &actor, "admin_user_created", "admin_user"),
        )
        .await
        .expect("the duplicate query must succeed");
    assert!(matches!(duplicate, CreateUserOutcome::AlreadyExists));
    assert_eq!(
        audit_count_for_resource(
            &pool,
            &fixture.deployment,
            "admin_user_created",
            &user_a.id.to_string()
        )
        .await,
        1,
        "a refused duplicate must not write an audit row"
    );

    // An unknown role key rolls the whole creation back.
    let refused = store
        .create_user(
            &fixture.deployment.0,
            NewUser {
                login: format!("unknown-role-{}@example.test", fixture.suffix),
                display_name: "Refused".to_string(),
                customer_id: None,
                roles: vec!["not_a_role".to_string()],
                created_by: created_by.clone(),
            },
            draft(&fixture, &actor, "admin_user_created", "admin_user"),
        )
        .await;
    assert!(refused.is_err(), "unknown role keys must fail the creation");

    // Idempotent grant: first call changes, second does not — both audited.
    let granted = store
        .grant_role(
            &fixture.deployment.0,
            user_a.id,
            "support",
            &created_by,
            draft_for_user(&fixture, &actor, "admin_role_granted", user_a.id),
        )
        .await
        .expect("the grant must succeed");
    assert!(granted.changed);
    assert!(granted.roles.contains(&"support".to_string()));
    let again = store
        .grant_role(
            &fixture.deployment.0,
            user_a.id,
            "support",
            &created_by,
            draft_for_user(&fixture, &actor, "admin_role_granted", user_a.id),
        )
        .await
        .expect("the idempotent grant must succeed");
    assert!(!again.changed, "granting twice must not change state");
    assert_eq!(
        audit_count_for_resource(
            &pool,
            &fixture.deployment,
            "admin_role_granted",
            &user_a.id.to_string()
        )
        .await,
        2,
        "every grant attempt is audited with its changed flag"
    );

    // Idempotent revoke mirrors the grant semantics.
    let revoked = store
        .revoke_role(
            &fixture.deployment.0,
            user_a.id,
            "support",
            draft_for_user(&fixture, &actor, "admin_role_revoked", user_a.id),
        )
        .await
        .expect("the revoke must succeed");
    assert!(revoked.changed);
    assert!(!revoked.roles.contains(&"support".to_string()));
    let again = store
        .revoke_role(
            &fixture.deployment.0,
            user_a.id,
            "support",
            draft_for_user(&fixture, &actor, "admin_role_revoked", user_a.id),
        )
        .await
        .expect("the idempotent revoke must succeed");
    assert!(!again.changed);
    assert_eq!(
        audit_count_for_resource(
            &pool,
            &fixture.deployment,
            "admin_role_revoked",
            &user_a.id.to_string()
        )
        .await,
        2
    );

    // Cross-deployment isolation: the second deployment bootstraps its own
    // admin and roles, and neither side can read or mutate the other's users.
    let outcome = store
        .authenticate_identity(
            &fixture.deployment_b.0,
            format!("foreign-{}@example.test", fixture.suffix).as_str(),
            None,
        )
        .await
        .expect("the foreign bootstrap must succeed");
    assert!(matches!(outcome, AuthenticateOutcome::Bootstrapped { .. }));
    let foreign_user = store
        .create_user(
            &fixture.deployment_b.0,
            NewUser {
                login: login_b.clone(),
                display_name: "Operator B".to_string(),
                customer_id: None,
                roles: vec!["support".to_string()],
                created_by: created_by.clone(),
            },
            draft(&fixture, &actor, "admin_user_created", "admin_user"),
        )
        .await
        .expect("the foreign user must be created");
    let CreateUserOutcome::Created(user_b) = foreign_user else {
        panic!("the foreign creation must succeed");
    };

    let visible_a = store
        .list_users(&fixture.deployment.0, None)
        .await
        .expect("the deployment A listing must succeed");
    assert!(
        !visible_a.iter().any(|candidate| candidate.login == login_b),
        "deployment A must not list deployment B's users"
    );
    let visible_b = store
        .list_users(&fixture.deployment_b.0, None)
        .await
        .expect("the deployment B listing must succeed");
    assert!(
        !visible_b.iter().any(|candidate| candidate.login == login_a),
        "deployment B must not list deployment A's users"
    );

    let foreign_lookup = store
        .get_user(&fixture.deployment.0, user_b.id)
        .await
        .expect("the cross-deployment lookup query must succeed");
    assert!(
        foreign_lookup.is_none(),
        "a user from another deployment must not resolve"
    );

    let refused = store
        .grant_role(
            &fixture.deployment.0,
            user_b.id,
            "customer_admin",
            &created_by,
            draft_for_user(&fixture, &actor, "admin_role_granted", user_b.id),
        )
        .await;
    assert!(
        refused.is_err(),
        "granting roles across deployments must fail"
    );
    assert_eq!(
        audit_count_for_resource(
            &pool,
            &fixture.deployment,
            "admin_role_granted",
            &user_b.id.to_string()
        )
        .await,
        0,
        "a refused cross-deployment grant must not write an audit row"
    );

    // Deployment A's customer filter stays within its own scope.
    let filtered = store
        .list_users(&fixture.deployment.0, Some(&fixture.customer_a.0))
        .await
        .expect("the filtered listing must succeed");
    assert!(filtered
        .iter()
        .all(|candidate| candidate.customer_id.as_deref() == Some(fixture.customer_a.0.as_str())));
    assert!(filtered.iter().any(|candidate| candidate.login == login_a));
}

/// `AuthenticateOutcome` carries no `PartialEq`; report the variant name for
/// failure messages without widening the public API.
fn discriminant_name(outcome: &AuthenticateOutcome) -> &'static str {
    match outcome {
        AuthenticateOutcome::Authenticated { .. } => "Authenticated",
        AuthenticateOutcome::Bootstrapped { .. } => "Bootstrapped",
        AuthenticateOutcome::Unknown => "Unknown",
        AuthenticateOutcome::Suspended => "Suspended",
    }
}

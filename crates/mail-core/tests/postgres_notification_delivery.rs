//! Local PostgreSQL coverage for the tenant notification delivery worker.
//!
//! Requires PostgreSQL migrated through `042_tenant_notification_settings.sql`
//! with `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_notification_delivery -- --ignored`.
//!
//! The worker is pointed at a private outbound endpoint with nothing behind it,
//! which is the production failure mode worth proving: the ledger must record
//! the truth about an attempt that never reached Postfix, a retry must not
//! create a second row or a second mail, and a tenant that cannot be signed for
//! must not lose its notification.

use nullapart_mail_contracts::transaction::DeploymentId;
use nullapart_mail_core::notification_delivery::{
    NotificationDeliveryConfig, NotificationDeliveryWorker,
};
use nullapart_mail_core::outbound::ProvisionedDkimSigner;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row, Transaction};
use std::time::Duration;
use uuid::Uuid;

const UNREACHABLE_OUTBOUND: &str = "127.0.0.1:10027";
const PLACEHOLDER_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

async fn connect() -> PgPool {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable")
}

/// A test that expects a failed submission is only honest if the endpoint really
/// refuses, so fail loudly rather than let a stray listener flip the outcome.
fn assert_outbound_is_refused() {
    let Ok(address) = UNREACHABLE_OUTBOUND.parse::<std::net::SocketAddr>() else {
        panic!("the loopback test endpoint must parse");
    };
    assert!(
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_err(),
        "nothing may be listening on {UNREACHABLE_OUTBOUND} while these tests run"
    );
}

struct Tenant {
    customer_id: String,
    domain: String,
    domain_id: Uuid,
}

async fn seed_deployment(pool: &PgPool, label: &str) -> String {
    let deployment_id = format!("nd-deploy-{label}-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name, lifecycle) \
         VALUES ($1, 'za', $2, 'active')",
    )
    .bind(&deployment_id)
    .bind(format!("Notification Delivery {label}"))
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    deployment_id
}

async fn seed_tenant(pool: &PgPool, deployment_id: &str, label: &str) -> Tenant {
    let customer_id = format!("C-ND-{label}-{}", Uuid::new_v4().simple());
    // Domains are globally unique, so the suffix must come from this fixture's
    // own identity rather than the shared test label.
    let domain = format!(
        "{label}.{}nd.example.test",
        customer_id.rsplit('-').next().expect("customer id suffix")
    );
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind(&customer_id)
    .bind(deployment_id)
    .bind(format!("Notification Delivery {label}"))
    .execute(pool)
    .await
    .expect("customer fixture must insert");
    let domain_id: Uuid = sqlx::query_scalar(
        "INSERT INTO domains (customer_id, domain, verification_status, verified_at) \
         VALUES ($1, $2, 'verified', now()) RETURNING id",
    )
    .bind(&customer_id)
    .bind(&domain)
    .fetch_one(pool)
    .await
    .expect("verified domain fixture must insert");
    Tenant {
        customer_id,
        domain,
        domain_id,
    }
}

/// Both tables force row-level security, so every fixture write and every read
/// in these tests runs inside a transaction carrying the tenant's scope.
async fn scoped<'a>(
    pool: &'a PgPool,
    deployment_id: &str,
    customer_id: &str,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("transaction must open");
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .fetch_all(&mut *transaction)
    .await
    .expect("scope GUCs must set");
    transaction
}

async fn put_settings(
    pool: &PgPool,
    deployment_id: &str,
    tenant: &Tenant,
    enabled: bool,
    recipients: &[&str],
    digest_window_minutes: i32,
) {
    let mut transaction = scoped(pool, deployment_id, &tenant.customer_id).await;
    sqlx::query(
        "INSERT INTO tenant_notification_settings \
             (deployment_id, customer_id, enabled, severity_floor, recipient_emails, \
              digest_window_minutes, updated_by) \
         VALUES ($1, $2, $3, 'info', $4, $5, 'nd-postgres-test') \
         ON CONFLICT (deployment_id, customer_id) DO UPDATE \
             SET enabled = EXCLUDED.enabled, \
                 recipient_emails = EXCLUDED.recipient_emails, \
                 digest_window_minutes = EXCLUDED.digest_window_minutes",
    )
    .bind(deployment_id)
    .bind(&tenant.customer_id)
    .bind(enabled)
    .bind(
        recipients
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>(),
    )
    .bind(digest_window_minutes)
    .execute(&mut *transaction)
    .await
    .expect("settings fixture must write");
    transaction.commit().await.expect("settings must commit");
}

async fn seed_notification(
    pool: &PgPool,
    deployment_id: &str,
    tenant: &Tenant,
    notification_type: &str,
    title: &str,
) -> Uuid {
    let mut transaction = scoped(pool, deployment_id, &tenant.customer_id).await;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO domain_security_notifications \
             (deployment_id, customer_id, domain_id, notification_type, severity, title, detail) \
         VALUES ($1, $2, $3, $4, 'warning', $5, 'Three sources failed alignment.') \
         RETURNING id",
    )
    .bind(deployment_id)
    .bind(&tenant.customer_id)
    .bind(tenant.domain_id)
    .bind(notification_type)
    .bind(title)
    .fetch_one(&mut *transaction)
    .await
    .expect("notification fixture must insert");
    transaction
        .commit()
        .await
        .expect("notification must commit");
    id
}

#[derive(Debug)]
struct LedgerRow {
    notification_id: Uuid,
    status: String,
    recipient_count: i32,
    attempts: i32,
    reason: Option<String>,
    outbound_transaction_id: Option<String>,
}

async fn ledger_rows(pool: &PgPool, deployment_id: &str, tenant: &Tenant) -> Vec<LedgerRow> {
    let mut transaction = scoped(pool, deployment_id, &tenant.customer_id).await;
    let rows = sqlx::query(
        "SELECT notification_id, status, recipient_count, attempts, reason, \
                outbound_transaction_id \
         FROM notification_deliveries \
         WHERE deployment_id = $1 AND customer_id = $2 \
         ORDER BY created_at, id",
    )
    .bind(deployment_id)
    .bind(&tenant.customer_id)
    .fetch_all(&mut *transaction)
    .await
    .expect("ledger read must succeed");
    transaction
        .commit()
        .await
        .expect("read transaction must close");
    rows.into_iter()
        .map(|row| LedgerRow {
            notification_id: row.get("notification_id"),
            status: row.get("status"),
            recipient_count: row.get("recipient_count"),
            attempts: row.get("attempts"),
            reason: row.get("reason"),
            outbound_transaction_id: row.get("outbound_transaction_id"),
        })
        .collect()
}

async fn notification_status(
    pool: &PgPool,
    deployment_id: &str,
    tenant: &Tenant,
    notification_id: Uuid,
) -> String {
    let mut transaction = scoped(pool, deployment_id, &tenant.customer_id).await;
    let status: String =
        sqlx::query_scalar("SELECT status FROM domain_security_notifications WHERE id = $1")
            .bind(notification_id)
            .fetch_one(&mut *transaction)
            .await
            .expect("notification status must read");
    transaction
        .commit()
        .await
        .expect("read transaction must close");
    status
}

fn worker(
    pool: &PgPool,
    deployment_id: &str,
    signer_domains: &[&str],
    max_attempts: i32,
) -> NotificationDeliveryWorker {
    let config = NotificationDeliveryConfig {
        poll_interval: Duration::from_secs(60),
        smtp_endpoint: UNREACHABLE_OUTBOUND.to_string(),
        smtp_timeout: Duration::from_secs(2),
        helo_identity: "mail.nullapart.com".to_string(),
        node_id: "mail-nd-test".to_string(),
        connector_ip: "127.0.0.1".to_string(),
        sender_local_part: "notifications".to_string(),
        dkim_identities: signer_domains
            .iter()
            .map(|domain| ProvisionedDkimSigner {
                domain: (*domain).to_string(),
                selector: "default".to_string(),
            })
            .collect(),
        max_attempts,
        batch_limit: 20,
    };
    NotificationDeliveryWorker::new(pool.clone(), DeploymentId::new(deployment_id), config)
        .expect("test worker configuration must be valid")
}

#[tokio::test]
#[ignore = "requires local PostgreSQL migrated through 042_tenant_notification_settings.sql"]
async fn an_unprovisioned_tenant_is_skipped_without_burning_its_idempotency_key() {
    assert_outbound_is_refused();
    let pool = connect().await;
    let deployment_id = seed_deployment(&pool, "unprovisioned").await;
    let tenant = seed_tenant(&pool, &deployment_id, "unprovisioned").await;
    put_settings(
        &pool,
        &deployment_id,
        &tenant,
        true,
        &["admin@example.test"],
        0,
    )
    .await;
    let notification = seed_notification(
        &pool,
        &deployment_id,
        &tenant,
        "dmarc_failure_spike",
        "DMARC failures rose",
    )
    .await;

    // The signer list belongs to another domain, so this tenant cannot be
    // signed for and must be passed over.
    let outcome = worker(&pool, &deployment_id, &["other.example.test"], 3)
        .run_once()
        .await
        .expect("run must complete");
    assert_eq!(outcome.tenants_examined, 1);
    assert_eq!(outcome.tenants_skipped, 1);
    assert_eq!(outcome.notices_attempted, 0);
    assert!(
        ledger_rows(&pool, &deployment_id, &tenant).await.is_empty(),
        "a skipped tenant must not consume the one-time delivery key"
    );
    assert_eq!(
        notification_status(&pool, &deployment_id, &tenant, notification).await,
        "open"
    );

    // Provisioning the tenant's domain afterwards must still be able to work
    // the same notification, which is the reason the skip wrote no row.
    let outcome = worker(&pool, &deployment_id, &[&tenant.domain], 3)
        .run_once()
        .await
        .expect("run must complete");
    assert_eq!(outcome.notices_attempted, 1);
    let rows = ledger_rows(&pool, &deployment_id, &tenant).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].notification_id, notification);
    assert_eq!(rows[0].status, "queued");
}

#[tokio::test]
#[ignore = "requires local PostgreSQL migrated through 042_tenant_notification_settings.sql"]
async fn a_tenant_that_opted_out_or_has_no_recipient_is_not_worked() {
    assert_outbound_is_refused();
    let pool = connect().await;
    let deployment_id = seed_deployment(&pool, "optout").await;

    let disabled = seed_tenant(&pool, &deployment_id, "disabled").await;
    put_settings(
        &pool,
        &deployment_id,
        &disabled,
        false,
        &["admin@example.test"],
        0,
    )
    .await;
    seed_notification(
        &pool,
        &deployment_id,
        &disabled,
        "dmarc_failure_spike",
        "Disabled tenant",
    )
    .await;

    let no_recipients = seed_tenant(&pool, &deployment_id, "norecipients").await;
    put_settings(&pool, &deployment_id, &no_recipients, true, &[], 0).await;
    seed_notification(
        &pool,
        &deployment_id,
        &no_recipients,
        "dmarc_failure_spike",
        "No recipients",
    )
    .await;

    let unusable_recipient = seed_tenant(&pool, &deployment_id, "badrecipient").await;
    put_settings(
        &pool,
        &deployment_id,
        &unusable_recipient,
        true,
        &["not-an-address"],
        0,
    )
    .await;
    seed_notification(
        &pool,
        &deployment_id,
        &unusable_recipient,
        "dmarc_failure_spike",
        "Unusable recipient",
    )
    .await;

    let domains = vec![
        disabled.domain.as_str(),
        no_recipients.domain.as_str(),
        unusable_recipient.domain.as_str(),
    ];
    let outcome = worker(&pool, &deployment_id, &domains, 3)
        .run_once()
        .await
        .expect("run must complete");
    assert_eq!(outcome.tenants_examined, 3);
    assert_eq!(outcome.tenants_skipped, 3);
    assert_eq!(outcome.notices_attempted, 0);
    for tenant in [&disabled, &no_recipients, &unusable_recipient] {
        assert!(
            ledger_rows(&pool, &deployment_id, tenant).await.is_empty(),
            "nothing may be claimed for a tenant that cannot receive mail"
        );
    }
}

#[tokio::test]
#[ignore = "requires local PostgreSQL migrated through 042_tenant_notification_settings.sql"]
async fn a_failed_submission_retries_on_one_row_then_dead_letters() {
    assert_outbound_is_refused();
    let pool = connect().await;
    let deployment_id = seed_deployment(&pool, "retry").await;
    let tenant = seed_tenant(&pool, &deployment_id, "retry").await;
    put_settings(
        &pool,
        &deployment_id,
        &tenant,
        true,
        &["admin@example.test"],
        0,
    )
    .await;
    let notification = seed_notification(
        &pool,
        &deployment_id,
        &tenant,
        "dmarc_failure_spike",
        "Retryable",
    )
    .await;

    let outcome = worker(&pool, &deployment_id, &[&tenant.domain], 2)
        .run_once()
        .await
        .expect("first run must complete");
    assert_eq!(outcome.notices_attempted, 1);
    assert_eq!(outcome.messages_sent, 0);
    assert_eq!(outcome.messages_dead_lettered, 0);

    let rows = ledger_rows(&pool, &deployment_id, &tenant).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "queued");
    assert_eq!(rows[0].attempts, 1);
    assert_eq!(rows[0].recipient_count, 1);
    assert!(rows[0].outbound_transaction_id.is_none());
    let reason = rows[0]
        .reason
        .clone()
        .expect("failure reason must be recorded");
    assert!(
        !reason.contains('@') && !reason.contains("admin"),
        "the ledger reason must not leak a recipient: {reason}"
    );

    // The second poll must reuse the same row (the idempotency key is unique)
    // and exhaust the attempt budget, so it never stays open-ended.
    let outcome = worker(&pool, &deployment_id, &[&tenant.domain], 2)
        .run_once()
        .await
        .expect("second run must complete");
    assert_eq!(outcome.messages_dead_lettered, 1);

    let rows = ledger_rows(&pool, &deployment_id, &tenant).await;
    assert_eq!(
        rows.len(),
        1,
        "a retry must never add a second delivery row"
    );
    assert_eq!(rows[0].notification_id, notification);
    assert_eq!(rows[0].status, "dead_lettered");
    assert_eq!(rows[0].attempts, 2);

    // A terminal row is not re-claimed, so the notification cannot be mailed later.
    let outcome = worker(&pool, &deployment_id, &[&tenant.domain], 2)
        .run_once()
        .await
        .expect("third run must complete");
    assert_eq!(outcome.notices_attempted, 0);
    assert_eq!(ledger_rows(&pool, &deployment_id, &tenant).await.len(), 1);
}

#[tokio::test]
#[ignore = "requires local PostgreSQL migrated through 042_tenant_notification_settings.sql"]
async fn sibling_findings_coalesce_into_one_mailed_notice() {
    assert_outbound_is_refused();
    let pool = connect().await;
    let deployment_id = seed_deployment(&pool, "coalesce").await;
    let tenant = seed_tenant(&pool, &deployment_id, "coalesce").await;
    put_settings(
        &pool,
        &deployment_id,
        &tenant,
        true,
        &["admin@example.test"],
        0,
    )
    .await;
    for title in ["Spike one", "Spike two", "Spike three"] {
        seed_notification(&pool, &deployment_id, &tenant, "dmarc_failure_spike", title).await;
    }

    let outcome = worker(&pool, &deployment_id, &[&tenant.domain], 3)
        .run_once()
        .await
        .expect("run must complete");
    assert_eq!(outcome.notices_attempted, 1);
    assert_eq!(outcome.findings_suppressed, 2);

    let rows = ledger_rows(&pool, &deployment_id, &tenant).await;
    assert_eq!(rows.len(), 3);
    let mailed = rows
        .iter()
        .filter(|row| row.status == "queued")
        .collect::<Vec<_>>();
    assert_eq!(mailed.len(), 1, "one group mails exactly one notice");
    assert_eq!(mailed[0].recipient_count, 1);
    for row in rows.iter().filter(|row| row.status == "suppressed") {
        assert_eq!(row.reason.as_deref(), Some("coalesced_into_digest"));
        assert_eq!(row.recipient_count, 0);
    }
}

#[tokio::test]
#[ignore = "requires local PostgreSQL migrated through 042_tenant_notification_settings.sql"]
async fn a_notice_already_mailed_inside_the_digest_window_suppresses_the_next_poll() {
    assert_outbound_is_refused();
    let pool = connect().await;
    let deployment_id = seed_deployment(&pool, "digest").await;
    let tenant = seed_tenant(&pool, &deployment_id, "digest").await;
    put_settings(
        &pool,
        &deployment_id,
        &tenant,
        true,
        &["admin@example.test"],
        60,
    )
    .await;
    let mailed = seed_notification(
        &pool,
        &deployment_id,
        &tenant,
        "dmarc_failure_spike",
        "Mailed earlier",
    )
    .await;

    let mut transaction = scoped(&pool, &deployment_id, &tenant.customer_id).await;
    sqlx::query(
        "INSERT INTO notification_deliveries \
             (deployment_id, customer_id, notification_id, idempotency_key, status, \
              recipient_count, attempts, reason, content_sha256, outbound_transaction_id) \
         VALUES ($1, $2, $3, $4, 'sent', 1, 1, NULL, $5, 'AB1234CDEF')",
    )
    .bind(&deployment_id)
    .bind(&tenant.customer_id)
    .bind(mailed)
    .bind(format!("notification:{mailed}"))
    .bind(PLACEHOLDER_HASH)
    .execute(&mut *transaction)
    .await
    .expect("prior sent row must insert");
    transaction
        .commit()
        .await
        .expect("prior sent row must commit");

    let fresh = seed_notification(
        &pool,
        &deployment_id,
        &tenant,
        "dmarc_failure_spike",
        "Same spike",
    )
    .await;

    let outcome = worker(&pool, &deployment_id, &[&tenant.domain], 3)
        .run_once()
        .await
        .expect("run must complete");
    assert_eq!(outcome.notices_attempted, 0);
    assert_eq!(outcome.findings_suppressed, 1);
    assert_eq!(outcome.messages_sent, 0);

    let rows = ledger_rows(&pool, &deployment_id, &tenant).await;
    let fresh_row = rows
        .iter()
        .find(|row| row.notification_id == fresh)
        .expect("the new finding must have a ledger row");
    assert_eq!(fresh_row.status, "suppressed");
    assert_eq!(fresh_row.reason.as_deref(), Some("digest_window"));
    assert_eq!(rows.len(), 2, "the previously mailed row is untouched");
}

#[tokio::test]
#[ignore = "requires local PostgreSQL migrated through 042_tenant_notification_settings.sql"]
async fn a_worker_only_ever_works_its_own_deployment() {
    assert_outbound_is_refused();
    let pool = connect().await;
    let deployment_id = seed_deployment(&pool, "foreign").await;
    let other_deployment = seed_deployment(&pool, "foreign-other").await;
    let tenant = seed_tenant(&pool, &deployment_id, "foreign").await;
    put_settings(
        &pool,
        &deployment_id,
        &tenant,
        true,
        &["admin@example.test"],
        0,
    )
    .await;
    seed_notification(
        &pool,
        &deployment_id,
        &tenant,
        "dmarc_failure_spike",
        "Other region",
    )
    .await;

    let outcome = worker(&pool, &other_deployment, &[&tenant.domain], 3)
        .run_once()
        .await
        .expect("run must complete");
    assert_eq!(outcome.tenants_examined, 0);
    assert_eq!(outcome.notices_attempted, 0);
    assert!(ledger_rows(&pool, &deployment_id, &tenant).await.is_empty());
}

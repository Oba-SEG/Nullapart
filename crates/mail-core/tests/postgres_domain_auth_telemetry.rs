//! Local PostgreSQL coverage for Phase 5 live authentication telemetry.
//!
//! Requires PostgreSQL migrated through `024_domain_auth_telemetry.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_domain_auth_telemetry -- --ignored`.

use chrono::Utc;
use nullapart_mail_contracts::transaction::{
    CustomerId, DeploymentId, Disposition, EnvelopeSender, Recipient, TenantMessageId,
    TransactionId,
};
use nullapart_mail_core::domain_auth_telemetry::{
    project_handoff_auth_telemetry, DomainAuthTelemetryInput, DomainAuthTelemetryOutcome,
};
use nullapart_mail_core::handoff::{
    AfterQueueHandoffRequest, HandoffConnection, MilterObservations,
};
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

async fn seed_domain(
    pool: &PgPool,
    suffix: &str,
) -> (
    DeploymentId,
    CustomerId,
    Uuid,
    TransactionId,
    TenantMessageId,
) {
    let deployment_id = DeploymentId::new(&format!("phase5-auth-{suffix}"));
    let customer_id = CustomerId::new(&format!("C-PHASE5-AUTH-{suffix}"));
    let domain = format!("auth-{suffix}.example.test");
    let transaction_id = TransactionId(Uuid::new_v4());
    let tenant_message_id = TenantMessageId(Uuid::new_v4());
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name, lifecycle) \
         VALUES ($1, 'za', $2, 'active')",
    )
    .bind(&deployment_id.0)
    .bind(format!("Phase 5 Auth {suffix}"))
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind(&customer_id.0)
    .bind(&deployment_id.0)
    .bind(format!("Phase 5 Auth Customer {suffix}"))
    .execute(pool)
    .await
    .expect("customer fixture must insert");
    let domain_id: Uuid = sqlx::query_scalar(
        "INSERT INTO domains (customer_id, domain, verification_status, verified_at) \
         VALUES ($1, $2, 'verified', now()) RETURNING id",
    )
    .bind(&customer_id.0)
    .bind(&domain)
    .fetch_one(pool)
    .await
    .expect("verified domain fixture must insert");
    sqlx::query(
        "INSERT INTO smtp_transactions \
            (id, deployment_id, direction, envelope_sender, content_hash, mime_artifact_id, received_at) \
         VALUES ($1, $2, 'inbound', $3, 'sha256:auth', 'pending', now())",
    )
    .bind(transaction_id.0)
    .bind(&deployment_id.0)
    .bind(format!("sender@{domain}"))
    .execute(pool)
    .await
    .expect("transaction fixture must insert");
    sqlx::query(
        "INSERT INTO tenant_message_instances (id, transaction_id, customer_id, disposition) \
         VALUES ($1, $2, $3, 'hold')",
    )
    .bind(tenant_message_id.0)
    .bind(transaction_id.0)
    .bind(&customer_id.0)
    .execute(pool)
    .await
    .expect("tenant message fixture must insert");
    (
        deployment_id,
        customer_id,
        domain_id,
        transaction_id,
        tenant_message_id,
    )
}

fn handoff_request(from_domain: &str, source_ip: &str) -> AfterQueueHandoffRequest {
    AfterQueueHandoffRequest {
        postfix_queue_id: format!("AUTH-{from_domain}"),
        envelope_sender: EnvelopeSender::new(&format!("sender@{from_domain}")),
        recipients: vec![Recipient {
            address: "recipient@example.test".to_string(),
            orcpt: None,
            notify: None,
        }],
        connection: HandoffConnection {
            client_ip: source_ip.to_string(),
            client_hostname: Some("mail.example.test".to_string()),
            helo_domain: Some("mail.example.test".to_string()),
            authenticated: false,
            session_id: "auth-telemetry-session".to_string(),
        },
        milter_observations: MilterObservations {
            score: 0.0,
            actions: vec![],
            is_spam: false,
            dkim_result: Some("pass".to_string()),
            spf_result: Some("pass".to_string()),
            dmarc_result: Some("pass".to_string()),
            symbols: vec![],
            latency_ms: 3,
        },
        message_content: String::new(),
        content_hash: "sha256:auth".to_string(),
        trace_id: None,
        handoff_at: Utc::now(),
    }
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 024_domain_auth_telemetry.sql"]
async fn handoff_auth_telemetry_is_recorded_idempotently_for_owned_from_domain() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (deployment_id, customer_id, domain_id, transaction_id, tenant_message_id) =
        seed_domain(&pool, &suffix).await;
    let from_domain = format!("auth-{suffix}.example.test");
    let request = handoff_request(&from_domain, "203.0.113.99");
    let mime = format!("From: Sender <sender@{from_domain}>\r\nSubject: hi\r\n\r\nbody");

    let first = project_handoff_auth_telemetry(
        &pool,
        DomainAuthTelemetryInput {
            deployment_id: &deployment_id,
            customer_id: &customer_id,
            transaction_id: &transaction_id,
            tenant_message_id: &tenant_message_id,
            request: &request,
            raw_mime: mime.as_bytes(),
            disposition: Disposition::Allow,
        },
    )
    .await
    .expect("telemetry projection must succeed");
    assert_eq!(first, DomainAuthTelemetryOutcome::Recorded);
    let replay = project_handoff_auth_telemetry(
        &pool,
        DomainAuthTelemetryInput {
            deployment_id: &deployment_id,
            customer_id: &customer_id,
            transaction_id: &transaction_id,
            tenant_message_id: &tenant_message_id,
            request: &request,
            raw_mime: mime.as_bytes(),
            disposition: Disposition::Quarantine,
        },
    )
    .await
    .expect("telemetry replay must succeed");
    assert_eq!(replay, DomainAuthTelemetryOutcome::Recorded);

    let row = sqlx::query(
        "SELECT count(*)::bigint AS count, max(disposition) AS disposition, \
                max(host(source_ip)) AS source_ip, max(dmarc_result) AS dmarc_result \
         FROM domain_auth_telemetry \
         WHERE deployment_id = $1 AND customer_id = $2 AND domain_id = $3",
    )
    .bind(&deployment_id.0)
    .bind(&customer_id.0)
    .bind(domain_id)
    .fetch_one(&pool)
    .await
    .expect("telemetry row must be readable");
    assert_eq!(row.get::<i64, _>("count"), 1);
    assert_eq!(row.get::<String, _>("disposition"), "quarantine");
    assert_eq!(row.get::<String, _>("source_ip"), "203.0.113.99");
    assert_eq!(row.get::<String, _>("dmarc_result"), "pass");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 024_domain_auth_telemetry.sql"]
async fn handoff_auth_telemetry_skips_unowned_domains_and_invalid_source_ip() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (deployment_id, customer_id, _domain_id, transaction_id, tenant_message_id) =
        seed_domain(&pool, &suffix).await;
    let unowned = "attacker.example.test";
    let request = handoff_request(unowned, "203.0.113.100");
    let mime = format!("From: Sender <sender@{unowned}>\r\nSubject: hi\r\n\r\nbody");

    let outcome = project_handoff_auth_telemetry(
        &pool,
        DomainAuthTelemetryInput {
            deployment_id: &deployment_id,
            customer_id: &customer_id,
            transaction_id: &transaction_id,
            tenant_message_id: &tenant_message_id,
            request: &request,
            raw_mime: mime.as_bytes(),
            disposition: Disposition::Allow,
        },
    )
    .await
    .expect("unowned domain projection must not fail");
    assert_eq!(
        outcome,
        DomainAuthTelemetryOutcome::SkippedNoOwnedFromDomain
    );

    let bad_ip = handoff_request(unowned, "not-an-ip");
    let outcome = project_handoff_auth_telemetry(
        &pool,
        DomainAuthTelemetryInput {
            deployment_id: &deployment_id,
            customer_id: &customer_id,
            transaction_id: &transaction_id,
            tenant_message_id: &tenant_message_id,
            request: &bad_ip,
            raw_mime: mime.as_bytes(),
            disposition: Disposition::Allow,
        },
    )
    .await
    .expect("invalid IP projection must not fail");
    assert_eq!(outcome, DomainAuthTelemetryOutcome::SkippedInvalidSourceIp);
}

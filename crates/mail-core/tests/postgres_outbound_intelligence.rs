//! Local PostgreSQL coverage for Phase 6 outbound intelligence storage.
//!
//! Requires PostgreSQL migrated through `028_outbound_intelligence.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_outbound_intelligence -- --ignored`.

use axum::{
    body::{to_bytes, Body},
    extract::Extension,
    http::{Request, StatusCode},
};
use chrono::Utc;
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use nullapart_mail_contracts::ActorId;
use nullapart_mail_core::admin_rbac::{CUSTOMER_ADMIN_ROLE, SYSTEM_ADMIN_ROLE};
use nullapart_mail_core::outbound_intelligence::{
    evaluate_outbound_intelligence, OutboundBehaviorMetrics, OutboundBehaviorMetricsLookup,
    OutboundDecisionOutcome, OutboundIntelligenceInput, OutboundPolicyThresholds,
    OutboundRecipientDomainMetrics, OutboundSourceContext, OutboundSourceKind,
    OutboundThreatSignals, PostgresOutboundIntelligenceStore,
};
use nullapart_mail_core::outbound_intelligence_api::{
    outbound_intelligence_router, OutboundIntelligenceApiState,
    OUTBOUND_INTELLIGENCE_MANAGE_PERMISSION, OUTBOUND_INTELLIGENCE_VIEW_PERMISSION,
};
use nullapart_policy::{
    AuthenticationAssurance, ContextActor, CustomerLifecycle, RegionId, TenantContext,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row, Transaction};
use tower::ServiceExt;
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
        "GRANT SELECT, INSERT, UPDATE, DELETE ON approved_bulk_senders TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON outbound_behavior_rollups TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON outbound_campaign_fingerprints TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON outbound_security_events TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE ON outbox_events TO nullapart_local_request",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON policy_revisions TO nullapart_local_request",
    ] {
        sqlx::query(grant)
            .execute(&mut *transaction)
            .await
            .expect("grant must apply");
    }
    transaction.commit().await.expect("role setup must commit");
}

async fn begin_scoped<'a>(
    pool: &'a PgPool,
    deployment: Option<&str>,
    customer: Option<&str>,
) -> Transaction<'a, sqlx::Postgres> {
    let mut transaction = pool.begin().await.expect("scoped transaction must begin");
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
        .expect("scope GUCs must be set");
    }
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
    assert!(outcome.is_err(), "statement must be rejected by RLS");
}

struct Fixture {
    deployment_a: String,
    deployment_b: String,
    customer_a: String,
    customer_b: String,
    sender_a: String,
    sender_b: String,
}

async fn seed(pool: &PgPool) -> Fixture {
    let suffix = Uuid::new_v4().simple().to_string();
    let fixture = Fixture {
        deployment_a: format!("phase6-oi-a-{suffix}"),
        deployment_b: format!("phase6-oi-b-{suffix}"),
        customer_a: format!("phase6-oi-customer-a-{suffix}"),
        customer_b: format!("phase6-oi-customer-b-{suffix}"),
        sender_a: format!("bulk-a-{suffix}@example.test").to_lowercase(),
        sender_b: format!("bulk-b-{suffix}@example.test").to_lowercase(),
    };

    for (deployment, customer, label) in [
        (&fixture.deployment_a, &fixture.customer_a, "A"),
        (&fixture.deployment_b, &fixture.customer_b, "B"),
    ] {
        sqlx::query(
            "INSERT INTO deployments (id, region, display_name, lifecycle) \
             VALUES ($1, 'za', $2, 'active')",
        )
        .bind(deployment)
        .bind(format!("Phase 6 outbound intelligence {label}"))
        .execute(pool)
        .await
        .expect("deployment fixture must insert");
        sqlx::query(
            "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(customer)
        .bind(deployment)
        .bind(format!("Phase 6 customer {label}"))
        .execute(pool)
        .await
        .expect("customer fixture must insert");
    }

    insert_phase6_rows(
        pool,
        &fixture.deployment_a,
        &fixture.customer_a,
        &fixture.sender_a,
    )
    .await;
    insert_phase6_rows(
        pool,
        &fixture.deployment_b,
        &fixture.customer_b,
        &fixture.sender_b,
    )
    .await;

    fixture
}

fn threshold_rule(metadata: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": Uuid::new_v4(),
        "name": "phase 6 policy threshold",
        "priority": 1,
        "condition": {
            "sender": null,
            "recipient": null,
            "auth": null,
            "content": null,
            "finding": null,
            "scope": "transaction"
        },
        "action": {
            "disposition": "hold",
            "reason_code": "OUTBOUND_POLICY",
            "notify": ["admin"],
            "metadata": metadata
        },
        "enabled": true
    })
}

async fn insert_phase6_rows(pool: &PgPool, deployment: &str, customer: &str, sender: &str) {
    sqlx::query(
        "INSERT INTO approved_bulk_senders \
            (deployment_id, customer_id, sender_address, sending_domain, source_kind, source_id, \
             source_ip, max_messages_per_minute, max_messages_per_hour, max_recipients_per_message, \
             max_unique_recipients_per_hour, approved_by, reason) \
         VALUES ($1,$2,$3,'example.test','smtp_mta','mta-a','10.0.0.10',10,100,50,500,'system','phase 6 test approval')",
    )
    .bind(deployment)
    .bind(customer)
    .bind(sender)
    .execute(pool)
    .await
    .expect("approved sender row must insert");

    sqlx::query(
        "INSERT INTO outbound_behavior_rollups \
            (deployment_id, customer_id, source_kind, source_id, source_ip, sender_address, sending_domain, \
             campaign_fingerprint, recipient_domain, window_start, window_seconds, message_count, \
             recipient_count, unique_recipient_count, new_recipient_count) \
         VALUES ($1,$2,'smtp_mta','mta-a','10.0.0.10',$3,'example.test','fp-a','recipient.test', \
             date_trunc('minute', now()), 60, 7, 14, 10, 8)",
    )
    .bind(deployment)
    .bind(customer)
    .bind(sender)
    .execute(pool)
    .await
    .expect("rollup row must insert");

    sqlx::query(
        "INSERT INTO outbound_campaign_fingerprints \
            (deployment_id, customer_id, fingerprint, algorithm, sample_subject_hash, message_count, recipient_count) \
         VALUES ($1,$2,$3,'nullapart_v1','sha256:test',7,14)",
    )
    .bind(deployment)
    .bind(customer)
    .bind(format!("fp-{customer}"))
    .execute(pool)
    .await
    .expect("fingerprint row must insert");

    sqlx::query(
        "INSERT INTO outbound_security_events \
            (deployment_id, customer_id, event_key, event_type, severity, outcome, reason_code, \
             sender_address, source_id, campaign_fingerprint, message_count) \
         VALUES ($1,$2,$3,'unauthorized_bulk','warning','hold','OUTBOUND_UNAUTHORIZED_BULK', \
             $4,'mta-a','fp-a',7)",
    )
    .bind(deployment)
    .bind(customer)
    .bind(format!("{deployment}:{customer}:unauthorized-bulk"))
    .bind(sender)
    .execute(pool)
    .await
    .expect("security event row must insert");

    for (family, metadata) in [
        (
            "bulk_sending",
            serde_json::json!({
                "max_messages_per_minute": 2,
                "max_messages_per_hour": 5,
                "max_recipients_per_message": 8,
                "max_unique_recipients_per_hour": 13
            }),
        ),
        (
            "outbound_abuse",
            serde_json::json!({
                "campaign_min_messages_per_hour": 9,
                "rotating_recipient_new_ratio": 0.70,
                "event_cooldown_minutes": 45
            }),
        ),
        (
            "sender_reputation",
            serde_json::json!({
                "bounce_failures_per_hour": 4
            }),
        ),
    ] {
        sqlx::query(
            "INSERT INTO policy_revisions \
                (id, customer_id, deployment_id, family_id, scope_level, revision_number, rules, \
                 published_by, activated_at) \
             VALUES ($1,$2,$3,$4,'tenant',1,$5,'phase6-test',now())",
        )
        .bind(Uuid::new_v4())
        .bind(customer)
        .bind(deployment)
        .bind(family)
        .bind(sqlx::types::Json(serde_json::json!([threshold_rule(
            metadata
        )])))
        .execute(pool)
        .await
        .expect("policy threshold revision must insert");
    }
}

async fn visible_count(transaction: &mut Transaction<'_, sqlx::Postgres>, table: &str) -> i64 {
    let row = sqlx::query(&format!("SELECT count(*) AS count FROM {table}"))
        .fetch_one(&mut **transaction)
        .await
        .expect("count query must run");
    row.get("count")
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 028_outbound_intelligence.sql"]
async fn outbound_intelligence_tables_are_tenant_isolated() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let tables = [
        "approved_bulk_senders",
        "outbound_behavior_rollups",
        "outbound_campaign_fingerprints",
        "outbound_security_events",
    ];

    let mut unscoped = begin_scoped(&pool, None, None).await;
    for table in tables {
        assert_eq!(
            visible_count(&mut unscoped, table).await,
            0,
            "{table} must fail closed without tenant scope"
        );
    }
    unscoped
        .commit()
        .await
        .expect("unscoped transaction must commit");

    let mut tenant_a = begin_scoped(
        &pool,
        Some(&fixture.deployment_a),
        Some(&fixture.customer_a),
    )
    .await;
    for table in tables {
        assert_eq!(
            visible_count(&mut tenant_a, table).await,
            1,
            "{table} must expose only the scoped tenant row"
        );
    }

    expect_rejected(
        &mut tenant_a,
        sqlx::query(
            "INSERT INTO approved_bulk_senders \
                (deployment_id, customer_id, sender_address, sending_domain, source_kind, source_id, \
                 max_messages_per_minute, max_messages_per_hour, max_recipients_per_message, \
                 max_unique_recipients_per_hour, approved_by, reason) \
             VALUES ($1,$2,$3,'example.test','smtp_mta','mta-a',1,1,1,1,'system','cross tenant write')",
        )
        .bind(&fixture.deployment_b)
        .bind(&fixture.customer_b)
        .bind(&fixture.sender_b),
    )
    .await;

    expect_rejected(
        &mut tenant_a,
        sqlx::query(
            "INSERT INTO outbound_security_events \
                (deployment_id, customer_id, event_key, event_type, severity, outcome, reason_code) \
             VALUES ($1,$2,$3,'source_spoofing','critical','block_sender','REJECT_SPOOFING')",
        )
        .bind(&fixture.deployment_b)
        .bind(&fixture.customer_a)
        .bind(format!("{}:{}:spoof", fixture.deployment_b, fixture.customer_a)),
    )
    .await;

    tenant_a
        .commit()
        .await
        .expect("tenant transaction must commit");
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 028_outbound_intelligence.sql"]
async fn postgres_store_loads_approved_sender_and_deduplicates_events() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;
    let store = PostgresOutboundIntelligenceStore::new(pool.clone());
    let now = Utc::now();
    let source = OutboundSourceContext {
        deployment_id: DeploymentId::new(&fixture.deployment_a),
        customer_id: CustomerId::new(&fixture.customer_a),
        source_kind: OutboundSourceKind::SmtpMta,
        source_id: "mta-a".to_string(),
        source_ip: Some("10.0.0.10".to_string()),
    };

    let approvals = store
        .load_approved_senders(&source, &fixture.sender_a.to_uppercase(), now)
        .await
        .expect("approval lookup must succeed");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].sender_address, fixture.sender_a);
    let thresholds = store
        .load_policy_thresholds(&source)
        .await
        .expect("policy thresholds must load");
    assert_eq!(thresholds.unauthorized_messages_per_minute, 2);
    assert_eq!(thresholds.unauthorized_messages_per_hour, 5);
    assert_eq!(thresholds.unauthorized_recipients_per_message, 8);
    assert_eq!(thresholds.unauthorized_unique_recipients_per_hour, 13);
    assert_eq!(thresholds.campaign_min_messages_per_hour, 9);
    assert_eq!(thresholds.bounce_failures_per_hour, 4);
    assert_eq!(thresholds.event_cooldown_minutes, 45);

    let foreign_source = OutboundSourceContext {
        deployment_id: DeploymentId::new(&fixture.deployment_b),
        customer_id: CustomerId::new(&fixture.customer_b),
        source_kind: OutboundSourceKind::SmtpMta,
        source_id: "mta-a".to_string(),
        source_ip: Some("10.0.0.10".to_string()),
    };
    let foreign_approvals = store
        .load_approved_senders(&foreign_source, &fixture.sender_a, now)
        .await
        .expect("foreign approval lookup must succeed");
    assert!(
        foreign_approvals.is_empty(),
        "approval lookup must remain tenant scoped"
    );

    let input = OutboundIntelligenceInput {
        source,
        sender_address: format!("Burst-{}@Example.Test", Uuid::new_v4().simple()),
        sending_domain: "Example.Test".to_string(),
        metrics: OutboundBehaviorMetrics {
            messages_last_minute: 30,
            messages_last_hour: 120,
            recipients_this_message: 60,
            unique_recipients_last_hour: 300,
            new_recipients_last_hour: 280,
            recipient_domain_count_last_hour: 30,
            campaign_messages_last_hour: 45,
            bounce_failures_last_hour: 3,
        },
        recipient_domain_metrics: vec![OutboundRecipientDomainMetrics {
            recipient_domain: "recipient-a.test".to_string(),
            recipient_count: 40,
            unique_recipient_count: 35,
            new_recipient_count: 30,
        }],
        signals: OutboundThreatSignals {
            campaign_fingerprint: Some(format!("fp-store-{}", Uuid::new_v4().simple())),
            ..OutboundThreatSignals::default()
        },
        policy_thresholds: OutboundPolicyThresholds::default(),
        approved_senders: vec![],
        now,
        existing_event: None,
    };
    let decision = evaluate_outbound_intelligence(&input);
    store
        .persist_decision(&input, &decision)
        .await
        .expect("first persistence pass must succeed");
    let existing_event = store
        .load_existing_event(
            &input.source,
            decision.event_key.as_deref().expect("event key"),
            now,
        )
        .await
        .expect("existing event lookup must succeed")
        .expect("open event must be inside cooldown");
    assert_eq!(
        existing_event.event_key,
        decision.event_key.clone().expect("event key")
    );
    let mut repeated_input = input.clone();
    repeated_input.existing_event = Some(existing_event);
    let repeated_decision = evaluate_outbound_intelligence(&repeated_input);
    assert!(
        repeated_decision.aggregate_into_existing_event,
        "runtime decisions must mark repeated detections as aggregate events"
    );
    store
        .persist_decision(&repeated_input, &repeated_decision)
        .await
        .expect("second persistence pass must aggregate");
    let persisted_metrics = store
        .load_behavior_metrics(&OutboundBehaviorMetricsLookup {
            source: input.source.clone(),
            sender_address: input.sender_address.clone(),
            sending_domain: input.sending_domain.clone(),
            campaign_fingerprint: input.signals.campaign_fingerprint.clone(),
            now,
            current_recipient_count: input.metrics.recipients_this_message,
            current_recipient_domain_count: input.recipient_domain_metrics.len() as u32,
        })
        .await
        .expect("persisted behavior metrics must load");
    assert_eq!(persisted_metrics.messages_last_minute, 31);
    assert_eq!(persisted_metrics.messages_last_hour, 31);
    assert_eq!(persisted_metrics.recipients_this_message, 60);
    assert_eq!(persisted_metrics.recipient_domain_count_last_hour, 1);
    assert_eq!(persisted_metrics.campaign_messages_last_hour, 46);
    assert_eq!(persisted_metrics.bounce_failures_last_hour, 3);

    let row = sqlx::query(
        "SELECT \
            (SELECT count(*)::bigint FROM outbound_behavior_rollups \
             WHERE deployment_id = $1 AND customer_id = $2 AND sender_address = lower($3)) AS rollups, \
            (SELECT count(*)::bigint FROM outbound_behavior_rollups \
             WHERE deployment_id = $1 AND customer_id = $2 AND sender_address = lower($3) \
               AND recipient_domain = 'recipient-a.test') AS recipient_domain_rollups, \
            (SELECT count(*)::bigint FROM outbound_campaign_fingerprints \
             WHERE deployment_id = $1 AND customer_id = $2 AND fingerprint = $4) AS campaigns, \
            (SELECT message_count::bigint FROM outbound_security_events \
             WHERE deployment_id = $1 AND customer_id = $2 AND event_key = $5) AS event_messages, \
            (SELECT details->>'remediation_runbook' FROM outbound_security_events \
             WHERE deployment_id = $1 AND customer_id = $2 AND event_key = $5) AS remediation_runbook, \
            (SELECT COALESCE((details->>'credential_rotation_recommended')::boolean, false) \
             FROM outbound_security_events \
             WHERE deployment_id = $1 AND customer_id = $2 AND event_key = $5) AS credential_rotation_recommended, \
            (SELECT count(*)::bigint FROM outbox_events \
             WHERE deployment_id = $1 AND customer_id = $2 \
               AND event_type = 'outbound.security_event' \
               AND idempotency_key = $6) AS outbox_events",
    )
    .bind(&fixture.deployment_a)
    .bind(&fixture.customer_a)
    .bind(&input.sender_address)
    .bind(input.signals.campaign_fingerprint.as_deref())
    .bind(decision.event_key.as_deref())
    .bind(format!(
        "outbound-security:{}:{}:{}",
        fixture.deployment_a,
        fixture.customer_a,
        decision.event_key.as_deref().expect("event key")
    ))
    .fetch_one(&pool)
    .await
    .expect("persisted rows must be readable");
    assert_eq!(row.get::<i64, _>("rollups"), 2);
    assert_eq!(row.get::<i64, _>("recipient_domain_rollups"), 1);
    assert_eq!(row.get::<i64, _>("campaigns"), 1);
    assert_eq!(row.get::<i64, _>("event_messages"), 2);
    assert_eq!(
        row.get::<String, _>("remediation_runbook"),
        "docs/runbooks/OUTBOUND-ABUSE-RESPONSE.md"
    );
    assert!(
        !row.get::<bool, _>("credential_rotation_recommended"),
        "unauthorized-bulk events require support triage but not automatic credential rotation"
    );
    assert_eq!(row.get::<i64, _>("outbox_events"), 1);

    let mut suspended_input = input.clone();
    suspended_input.sender_address = format!("Spoof-{}@Example.Test", Uuid::new_v4().simple());
    suspended_input.signals = OutboundThreatSignals {
        source_spoofing_detected: true,
        auth_source_changed: true,
        ..OutboundThreatSignals::default()
    };
    suspended_input.recipient_domain_metrics.clear();
    let suspended_decision = evaluate_outbound_intelligence(&suspended_input);
    assert_eq!(
        suspended_decision.outcome,
        OutboundDecisionOutcome::SuspendOutbound
    );
    store
        .persist_decision(&suspended_input, &suspended_decision)
        .await
        .expect("source compromise suspension must persist");
    let suspension_row = sqlx::query(
        "SELECT outcome, details->>'remediation_runbook' AS remediation_runbook, \
                COALESCE((details->>'credential_rotation_recommended')::boolean, false) \
                    AS credential_rotation_recommended \
         FROM outbound_security_events \
         WHERE deployment_id = $1 AND customer_id = $2 AND event_key = $3",
    )
    .bind(&fixture.deployment_a)
    .bind(&fixture.customer_a)
    .bind(suspended_decision.event_key.as_deref().expect("event key"))
    .fetch_one(&pool)
    .await
    .expect("suspended outbound event must be readable");
    assert_eq!(
        suspension_row.get::<String, _>("outcome"),
        "suspend_outbound"
    );
    assert_eq!(
        suspension_row.get::<String, _>("remediation_runbook"),
        "docs/runbooks/OUTBOUND-ABUSE-RESPONSE.md"
    );
    assert!(
        suspension_row.get::<bool, _>("credential_rotation_recommended"),
        "source compromise events must recommend connector credential rotation"
    );
}

/// Sender approval is a tenant capability. The runtime lookup is already
/// keyed to `customer_id`, so a foreign approval could not raise another
/// tenant's limits, but it would still record a right the tenant does not
/// own. The API therefore requires the sending domain to be a verified
/// domain of the approving tenant.
#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 028_outbound_intelligence.sql"]
async fn approved_sender_domain_must_be_verified_for_the_approving_tenant() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let suffix = Uuid::new_v4().simple().to_string();
    let own_verified = format!("verified-{suffix}.example.test");
    let own_pending = format!("pending-{suffix}.example.test");
    let foreign_verified = format!("foreign-{suffix}.example.test");
    for (customer, domain, status) in [
        (&fixture.customer_a, &own_verified, "verified"),
        (&fixture.customer_a, &own_pending, "pending"),
        (&fixture.customer_b, &foreign_verified, "verified"),
    ] {
        sqlx::query(
            "INSERT INTO domains (customer_id, domain, verification_status) \
             VALUES ($1, $2, $3)",
        )
        .bind(customer)
        .bind(domain)
        .bind(status)
        .execute(&pool)
        .await
        .expect("the domain fixture must insert");
    }

    let state =
        OutboundIntelligenceApiState::new(pool.clone(), DeploymentId::new(&fixture.deployment_a));
    let app = outbound_intelligence_router(state).layer(Extension(approval_context(
        &fixture.deployment_a,
        &fixture.customer_a,
    )));

    for (case, domain) in [("pending", &own_pending), ("foreign", &foreign_verified)] {
        let response = app
            .clone()
            .oneshot(approval_request(
                &format!("approval-{case}-{}", fixture.customer_a),
                &format!("bulk@{domain}"),
                domain,
            ))
            .await
            .expect("the refusal must answer");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a {case} domain must be refused"
        );
        let body: serde_json::Value = serde_json::from_slice(
            &to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("the refusal body must read"),
        )
        .expect("the refusal must be JSON");
        assert_eq!(body["code"], "DOMAIN_NOT_VERIFIED");
    }

    let approved_at = format!("bulk@{own_verified}");
    let response = app
        .oneshot(approval_request(
            &format!("approval-own-{}", fixture.customer_a),
            &approved_at,
            &own_verified,
        ))
        .await
        .expect("the own-domain approval must answer");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a verified own domain must be approvable"
    );

    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM approved_bulk_senders \
         WHERE deployment_id = $1 AND customer_id = $2 AND sender_address = $3",
    )
    .bind(&fixture.deployment_a)
    .bind(&fixture.customer_a)
    .bind(&approved_at)
    .fetch_one(&pool)
    .await
    .expect("the approval row must read");
    assert_eq!(stored, 1, "the approval must persist for the owning tenant");

    let foreign_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM approved_bulk_senders \
         WHERE sender_address LIKE '%@' || $1",
    )
    .bind(&foreign_verified)
    .fetch_one(&pool)
    .await
    .expect("the refusal audit must read");
    assert_eq!(
        foreign_rows, 0,
        "a refused approval must not leave a row behind"
    );
}

fn approval_context(deployment: &str, customer: &str) -> TenantContext {
    console_context(deployment, customer, &[CUSTOMER_ADMIN_ROLE])
}

fn console_context(deployment: &str, customer: &str, roles: &[&str]) -> TenantContext {
    TenantContext {
        deployment_id: DeploymentId::new(deployment),
        region: RegionId::new("za"),
        actor: ContextActor {
            actor_id: ActorId::new(),
            login: "tenant-operator@example.test".to_string(),
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            authentication_assurance: AuthenticationAssurance::StepUp,
        },
        impersonation: None,
        customer_id: CustomerId::new(customer),
        customer_internal_key: 1,
        customer_display_name: "Approving tenant".to_string(),
        customer_lifecycle: CustomerLifecycle::Active,
        permissions: vec![
            OUTBOUND_INTELLIGENCE_VIEW_PERMISSION.to_string(),
            OUTBOUND_INTELLIGENCE_MANAGE_PERMISSION.to_string(),
        ],
        config_revision: 1,
        trace_id: "postgres-outbound-approval-trace".to_string(),
        correlation_id: "postgres-outbound-approval-correlation".to_string(),
        session_id: "postgres-outbound-approval-session".to_string(),
        authenticated_at: Utc::now(),
    }
}

fn approval_request(key: &str, sender_address: &str, sending_domain: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/outbound-intelligence/approved-senders")
        .header("content-type", "application/json")
        .header("x-idempotency-key", key)
        .body(Body::from(
            serde_json::json!({
                "sender_address": sender_address,
                "sending_domain": sending_domain,
                "source_kind": "smtp_mta",
                "source_id": "postfix-node-1",
                "max_messages_per_minute": 25,
                "max_messages_per_hour": 100,
                "max_recipients_per_message": 50,
                "max_unique_recipients_per_hour": 250,
                "active": true,
                "reason": "tenant-approved newsletter sender"
            })
            .to_string(),
        ))
        .expect("the approval request must build")
}

async fn read_console(
    pool: &PgPool,
    deployment: &str,
    context: TenantContext,
) -> serde_json::Value {
    let app = outbound_intelligence_router(OutboundIntelligenceApiState::new(
        pool.clone(),
        DeploymentId::new(deployment),
    ))
    .layer(Extension(context));

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/outbound-intelligence")
                .body(Body::empty())
                .expect("the console read must build"),
        )
        .await
        .expect("the console read must answer");

    assert_eq!(response.status(), StatusCode::OK, "console read failed");
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the console body must read"),
    )
    .expect("the console read must be JSON")
}

/// The campaign hash, the matcher that produced it and the same hash repeated on
/// a security event are how the platform recognises content it has already
/// grouped. A customer cannot quote or act on any of them, so the customer
/// console must not even show that the slots exist: the keys are absent, not
/// null. The volume, the disposition and the dates stay, because that is what the
/// customer reads and decides on.
#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 028_outbound_intelligence.sql"]
async fn outbound_campaign_identifiers_are_absent_from_a_customer_read() {
    let pool = connect().await;
    ensure_request_role(&pool).await;
    let fixture = seed(&pool).await;

    let customer = read_console(
        &pool,
        &fixture.deployment_a,
        console_context(
            &fixture.deployment_a,
            &fixture.customer_a,
            &[CUSTOMER_ADMIN_ROLE],
        ),
    )
    .await;
    let data = &customer["data"];

    assert!(
        data["deployment_id"].is_null(),
        "a customer read does not name the installation: {data}"
    );

    let campaign = &data["campaigns"][0];
    assert!(
        campaign.get("fingerprint").is_none(),
        "the content hash must be an absent key: {campaign}"
    );
    assert!(
        campaign.get("algorithm").is_none(),
        "the matcher name must be an absent key: {campaign}"
    );
    assert_eq!(campaign["message_count"], 7);
    assert_eq!(campaign["recipient_count"], 14);
    assert!(
        !campaign["disposition"].as_str().unwrap().is_empty(),
        "the customer keeps the decision: {campaign}"
    );

    let event = &data["security_events"][0];
    assert!(
        event.get("campaign_fingerprint").is_none(),
        "the event must not repeat the content hash: {event}"
    );
    assert!(
        event.get("remediation_runbook").is_none(),
        "the provider runbook stays withheld: {event}"
    );
    assert_eq!(event["reason_code"], "OUTBOUND_UNAUTHORIZED_BULK");

    let platform = read_console(
        &pool,
        &fixture.deployment_a,
        console_context(
            &fixture.deployment_a,
            &fixture.customer_a,
            &[SYSTEM_ADMIN_ROLE],
        ),
    )
    .await;
    let data = &platform["data"];

    assert_eq!(data["deployment_id"], fixture.deployment_a);
    assert_eq!(
        data["campaigns"][0]["fingerprint"],
        format!("fp-{}", fixture.customer_a)
    );
    assert_eq!(data["campaigns"][0]["algorithm"], "nullapart_v1");
    assert_eq!(data["security_events"][0]["campaign_fingerprint"], "fp-a");
}

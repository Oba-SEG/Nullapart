//! Local PostgreSQL coverage for Phase 6 outbound intelligence storage.
//!
//! Requires PostgreSQL migrated through `028_outbound_intelligence.sql` with
//! `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_outbound_intelligence -- --ignored`.

use chrono::Utc;
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use nullapart_mail_core::outbound_intelligence::{
    evaluate_outbound_intelligence, OutboundBehaviorMetrics, OutboundIntelligenceInput,
    OutboundPolicyThresholds, OutboundSourceContext, OutboundSourceKind, OutboundThreatSignals,
    PostgresOutboundIntelligenceStore,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row, Transaction};
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
    store
        .persist_decision(&input, &decision)
        .await
        .expect("second persistence pass must aggregate");

    let row = sqlx::query(
        "SELECT \
            (SELECT count(*)::bigint FROM outbound_behavior_rollups \
             WHERE deployment_id = $1 AND customer_id = $2 AND sender_address = lower($3)) AS rollups, \
            (SELECT count(*)::bigint FROM outbound_campaign_fingerprints \
             WHERE deployment_id = $1 AND customer_id = $2 AND fingerprint = $4) AS campaigns, \
            (SELECT message_count::bigint FROM outbound_security_events \
             WHERE deployment_id = $1 AND customer_id = $2 AND event_key = $5) AS event_messages, \
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
    assert_eq!(row.get::<i64, _>("rollups"), 1);
    assert_eq!(row.get::<i64, _>("campaigns"), 1);
    assert_eq!(row.get::<i64, _>("event_messages"), 2);
    assert_eq!(row.get::<i64, _>("outbox_events"), 1);
}

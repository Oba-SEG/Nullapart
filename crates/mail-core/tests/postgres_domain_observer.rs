//! Local PostgreSQL coverage for Phase 5 DNS observer/validator worker.
//!
//! Requires PostgreSQL migrated through `025_domain_source_classification_history.sql`
//! with `NULLAPART_TEST_DATABASE_URL` pointing at it. Run explicitly with:
//! `cargo test --test postgres_domain_observer -- --ignored`.

use std::net::SocketAddr;
use std::time::Duration;

use nullapart_mail_contracts::transaction::DeploymentId;
use nullapart_mail_core::dns_txt::DnsTxtResolver;
use nullapart_mail_core::domain_observer::{DomainObserverConfig, DomainObserverWorker};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tokio::net::UdpSocket;
use uuid::Uuid;

const DNS_HEADER_LEN: usize = 12;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_MX: u16 = 15;
const DNS_CLASS_IN: u16 = 1;

async fn connect() -> PgPool {
    let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
        .expect("NULLAPART_TEST_DATABASE_URL must point at migrated local PostgreSQL");
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("local PostgreSQL must be reachable")
}

async fn seed_fixture(pool: &PgPool, suffix: &str) -> (String, String, Uuid, String, String) {
    let deployment_id = format!("phase5-observer-{suffix}");
    let customer_id = format!("C-PHASE5-OBSERVER-{suffix}");
    let domain = format!("observer-{suffix}.example.test");
    let authorization_owner = format!("{}._report._dmarc", domain);
    sqlx::query(
        "INSERT INTO deployments (id, region, display_name, lifecycle) \
         VALUES ($1, 'za', $2, 'active')",
    )
    .bind(&deployment_id)
    .bind(format!("Phase 5 Observer {suffix}"))
    .execute(pool)
    .await
    .expect("deployment fixture must insert");
    sqlx::query(
        "INSERT INTO customers (id, deployment_id, display_name, lifecycle) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind(&customer_id)
    .bind(&deployment_id)
    .bind(format!("Phase 5 Observer Customer {suffix}"))
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
    .expect("domain fixture must insert");
    sqlx::query(
        "INSERT INTO dmarc_report_authorizations (\
             deployment_id, customer_id, domain_id, report_host, owner_name, expected_value, status, detail\
         ) VALUES ($1, $2, $3, 'reports.example.test', $4, 'v=DMARC1', 'unknown', 'not checked')",
    )
    .bind(&deployment_id)
    .bind(&customer_id)
    .bind(domain_id)
    .bind(&authorization_owner)
    .execute(pool)
    .await
    .expect("authorization fixture must insert");
    (
        deployment_id,
        customer_id,
        domain_id,
        domain,
        authorization_owner,
    )
}

async fn spawn_dns_responder(domain: String, authorization_owner: String) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("loopback UDP binds");
    let address = socket.local_addr().expect("bound socket has an address");
    tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        while let Ok((received, from)) = socket.recv_from(&mut buffer).await {
            if let Some((name, qtype)) = query_name_and_type(&buffer[..received]) {
                let response = response_for(
                    &buffer[..received],
                    &domain,
                    &authorization_owner,
                    &name,
                    qtype,
                );
                let _ = socket.send_to(&response, from).await;
            }
        }
    });
    address
}

fn query_name_and_type(query: &[u8]) -> Option<(String, u16)> {
    let mut labels = Vec::new();
    let mut offset = DNS_HEADER_LEN;
    loop {
        let length = *query.get(offset)? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        let end = offset.checked_add(length)?;
        labels.push(
            std::str::from_utf8(query.get(offset..end)?)
                .ok()?
                .to_ascii_lowercase(),
        );
        offset = end;
    }
    Some((
        labels.join("."),
        u16::from_be_bytes([*query.get(offset)?, *query.get(offset + 1)?]),
    ))
}

fn response_for(
    query: &[u8],
    domain: &str,
    authorization_owner: &str,
    name: &str,
    qtype: u16,
) -> Vec<u8> {
    if qtype == DNS_TYPE_MX && name == domain {
        return response(query, DNS_TYPE_MX, mx_rdata(10, &format!("mail.{domain}")));
    }
    if qtype != DNS_TYPE_TXT {
        return empty_response(query);
    }
    let txt = if name == domain {
        Some("v=spf1 include:_spf.example.test -all".to_string())
    } else if name == format!("_dmarc.{domain}") {
        Some("v=DMARC1; p=quarantine; rua=mailto:reports@example.test".to_string())
    } else if name == format!("default._domainkey.{domain}") {
        Some("v=DKIM1; k=rsa; p=test".to_string())
    } else if name == format!("_mta-sts.{domain}") {
        Some("v=STSv1; id=20261008".to_string())
    } else if name == format!("_smtp._tls.{domain}") {
        Some("v=TLSRPTv1; rua=mailto:tls@example.test".to_string())
    } else if name == format!("default._bimi.{domain}") {
        Some(
            "v=BIMI1; l=https://brand.example.test/logo.svg; a=https://brand.example.test/vmc.pem"
                .to_string(),
        )
    } else if name == authorization_owner {
        Some("v=DMARC1".to_string())
    } else {
        None
    };
    match txt {
        Some(value) => response(query, DNS_TYPE_TXT, txt_rdata(&value)),
        None => empty_response(query),
    }
}

fn empty_response(query: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    response.extend_from_slice(&query[DNS_HEADER_LEN..]);
    response
}

fn response(query: &[u8], record_type: u16, rdata: Vec<u8>) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    response.extend_from_slice(&query[DNS_HEADER_LEN..]);
    response.push(0xC0);
    response.push(0x0C);
    response.extend_from_slice(&record_type.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    response.extend_from_slice(&60u32.to_be_bytes());
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);
    response
}

fn txt_rdata(value: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.push(value.len() as u8);
    rdata.extend_from_slice(value.as_bytes());
    rdata
}

fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
    let mut rdata = preference.to_be_bytes().to_vec();
    for label in exchange.split('.') {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0);
    rdata
}

#[tokio::test]
#[ignore = "requires migrated local PostgreSQL through 025_domain_source_classification_history.sql"]
async fn domain_observer_persists_dns_posture_bimi_status_and_authorization_results() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (deployment_id, customer_id, domain_id, domain, authorization_owner) =
        seed_fixture(&pool, &suffix).await;
    let resolver_address = spawn_dns_responder(domain.clone(), authorization_owner).await;
    let worker = DomainObserverWorker::new(
        pool.clone(),
        DnsTxtResolver::with_server(resolver_address, Duration::from_secs(2)),
        DeploymentId::new(&deployment_id),
        DomainObserverConfig::default(),
    );

    let outcome = worker.run_once().await.expect("observer run succeeds");
    assert_eq!(outcome.domains_checked, 1);
    assert_eq!(outcome.authorizations_checked, 1);
    assert_eq!(outcome.notifications_created, 0);

    let observation_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint \
         FROM domain_security_observations \
         WHERE deployment_id = $1 AND customer_id = $2 AND domain_id = $3",
    )
    .bind(&deployment_id)
    .bind(&customer_id)
    .bind(domain_id)
    .fetch_one(&pool)
    .await
    .expect("observations must be readable");
    assert_eq!(observation_count, 8);

    let bimi = sqlx::query(
        "SELECT status, svg_status, certificate_status \
         FROM bimi_domain_status \
         WHERE deployment_id = $1 AND customer_id = $2 AND domain_id = $3",
    )
    .bind(&deployment_id)
    .bind(&customer_id)
    .bind(domain_id)
    .fetch_one(&pool)
    .await
    .expect("bimi status must be written");
    assert_eq!(bimi.get::<String, _>("status"), "ready");
    assert_eq!(bimi.get::<String, _>("svg_status"), "not_checked");
    assert_eq!(bimi.get::<String, _>("certificate_status"), "unknown");

    let authorization = sqlx::query(
        "SELECT status, actual_value \
         FROM dmarc_report_authorizations \
         WHERE deployment_id = $1 AND customer_id = $2 AND domain_id = $3",
    )
    .bind(&deployment_id)
    .bind(&customer_id)
    .bind(domain_id)
    .fetch_one(&pool)
    .await
    .expect("authorization status must be updated");
    assert_eq!(authorization.get::<String, _>("status"), "valid");
    assert_eq!(authorization.get::<String, _>("actual_value"), "v=DMARC1");
}

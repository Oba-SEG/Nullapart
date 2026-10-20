//! Thin Postfix pipe adapter.
//!
//! Reads the queued MIME message from stdin and submits it to the loopback Mail Core
//! handoff API using the canonical Nullapart HMAC contract. Any internal failure
//! returns EX_TEMPFAIL so Postfix retains responsibility for the accepted message.

use std::env;
use std::io::Read;
use std::process;
use std::sync::LazyLock;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::Utc;
use nullapart_mail_contracts::hmac::sign_http;
use nullapart_mail_contracts::transaction::{EnvelopeSender, Recipient};
use nullapart_mail_core::handoff::{AfterQueueHandoffRequest, HandoffConnection};
use sha2::{Digest, Sha256};

const EX_TEMPFAIL: i32 = 75;
const HANDOFF_PATH: &str = "/internal/handoff";
const SELFTEST_MARKER: &str = "nullapart-mailcore-filter-ready";

/// Shared HTTP client with connection pooling across invocations.
///
/// The handoff request is bounded so a stalled Mail Core endpoint cannot pin
/// the pipe process indefinitely: Postfix kills the pipe command after
/// `mailcore_time_limit` (300s, set in master.cf), while the 240s client
/// timeout fires first and lets the filter exit EX_TEMPFAIL cleanly, leaving
/// retry ownership with the Postfix queue (minimal_backoff_time).
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .pool_max_idle_per_host(4)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(240))
        .build()
        .expect("failed to create HTTP client")
});

#[derive(Debug)]
struct Args {
    queue_id: String,
    client_address: String,
    client_hostname: Option<String>,
    client_helo: Option<String>,
    sasl_username: Option<String>,
    sender: String,
    recipients: Vec<String>,
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| {
        eprintln!("required environment variable {name} is not configured");
        process::exit(EX_TEMPFAIL);
    })
}

fn parse_args() -> Result<Args, String> {
    let mut queue_id = None;
    let mut client_address = None;
    let mut client_hostname = None;
    let mut client_helo = None;
    let mut sasl_username = None;
    let mut sender = None;
    let mut recipients = Vec::new();

    let mut iter = env::args().skip(1).peekable();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            recipients.extend(iter);
            break;
        }

        let value = iter
            .next()
            .ok_or_else(|| format!("missing value for {arg}"))?;
        match arg.as_str() {
            "--queue-id" => queue_id = Some(value),
            "--client-address" => client_address = Some(value),
            "--client-hostname" => client_hostname = nonempty(value),
            "--client-helo" => client_helo = nonempty(value),
            "--sasl-username" => sasl_username = nonempty(value),
            "--sender" => sender = Some(value),
            _ => return Err(format!("unknown argument {arg}")),
        }
    }

    if recipients.is_empty() {
        return Err("no recipients supplied by Postfix".to_string());
    }

    Ok(Args {
        queue_id: queue_id.ok_or_else(|| "missing --queue-id".to_string())?,
        client_address: client_address.unwrap_or_else(|| "unknown".to_string()),
        client_hostname,
        client_helo,
        sasl_username,
        sender: sender.ok_or_else(|| "missing --sender".to_string())?,
        recipients,
    })
}

fn nonempty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "unknown" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[tokio::main]
async fn main() {
    // Pre-flight probe used by mailcore-filter-wrapper: reaching this point
    // proves the executable and every dynamic dependency load cleanly. A
    // glibc/libstdc++ mismatch (see docs/26-PACKAGE-COMPATIBILITY.md) fails
    // inside the dynamic loader before any Rust code runs, so this exit code
    // is never reached on a broken binary and the wrapper can map the
    // difference to EX_TEMPFAIL instead of accepting a permanent bounce.
    if env::args().nth(1).as_deref() == Some("--selftest") {
        // A marker prevents an empty or text file from being treated as a
        // successful shell script on platforms that fall back from exec(2)
        // to a command interpreter. The wrapper requires this exact value.
        println!("{SELFTEST_MARKER}");
        process::exit(0);
    }

    if let Err(error) = run().await {
        eprintln!("mailcore-filter: {error}");
        process::exit(EX_TEMPFAIL);
    }
}

async fn run() -> Result<(), String> {
    let args = parse_args()?;

    let max_bytes = env::var("NULLAPART_HANDOFF_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(52_428_800);

    let mut raw_message = Vec::with_capacity(1024 * 1024);
    let mut total = 0usize;
    let mut buf = [0u8; 8192];
    let mut stdin = std::io::stdin();
    loop {
        let n = stdin
            .read(&mut buf)
            .map_err(|e| format!("cannot read queued message: {e}"))?;
        if n == 0 {
            break;
        }
        total += n;
        if total > max_bytes {
            return Err(format!(
                "message exceeds handoff limit: > {max_bytes} bytes"
            ));
        }
        raw_message.extend_from_slice(&buf[..n]);
    }

    let content_hash = hex::encode(Sha256::digest(&raw_message));
    let event_id = format!("handoff-{}-{}", args.queue_id, &content_hash[..16]);
    let request = AfterQueueHandoffRequest {
        postfix_queue_id: args.queue_id.clone(),
        envelope_sender: EnvelopeSender::new(&args.sender),
        recipients: args
            .recipients
            .into_iter()
            .map(|address| Recipient {
                address,
                orcpt: None,
                notify: None,
            })
            .collect(),
        connection: HandoffConnection {
            client_ip: args.client_address,
            client_hostname: args.client_hostname,
            helo_domain: args.client_helo,
            authenticated: args.sasl_username.is_some(),
            session_id: format!("postfix-{}", args.queue_id),
        },
        // Bounded pre-queue Rspamd evidence parsed from the queued message.
        // The headers are trustworthy because Rspamd's lua strip+re-add
        // chain owns them at the milter stage (public SMTP path) and
        // Postfix strips them on the private reinjection path; the handoff
        // then carries them to Mail Core over the HMAC-authenticated
        // channel (see crates/mail-core/src/milter_evidence.rs).
        milter_observations: nullapart_mail_core::milter_evidence::parse_queued_evidence(
            &raw_message,
        ),
        message_content: STANDARD.encode(&raw_message),
        content_hash,
        trace_id: Some(uuid::Uuid::new_v4().to_string()),
        handoff_at: Utc::now(),
    };

    let body = serde_json::to_vec(&request).map_err(|e| format!("cannot encode handoff: {e}"))?;
    let secret = required_env("NULLAPART_HANDOFF_HMAC_SECRET");
    let key_id =
        env::var("NULLAPART_HANDOFF_HMAC_KEY_ID").unwrap_or_else(|_| "mail-handoff-v1".to_string());
    let signature = sign_http(
        &body,
        secret.as_bytes(),
        &key_id,
        &event_id,
        "POST",
        HANDOFF_PATH,
    )
    .map_err(|e| format!("cannot sign handoff: {e}"))?;

    let endpoint = env::var("NULLAPART_MAILCORE_HANDOFF_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081/internal/handoff".to_string());

    let response = HTTP_CLIENT
        .post(endpoint)
        .header("content-type", "application/json")
        .header("x-nullapart-signature", signature.to_header())
        .header("x-nullapart-event-id", event_id)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("Mail Core handoff unavailable: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("Mail Core handoff returned {}", response.status()));
    }

    Ok(())
}

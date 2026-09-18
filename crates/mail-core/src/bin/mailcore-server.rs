//! Loopback Mail Core HTTP runtime for mail-node internal APIs.
//!
//! The server binds to loopback by default. Handoff authentication is mandatory;
//! the process refuses to start without the per-deployment HMAC secret.

use std::env;

use nullapart_mail_contracts::transaction::DeploymentId;
use nullapart_mail_core::handoff::{handoff_router, HandoffConfig};
use nullapart_mail_core::trace::{trace_router, TraceConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let deployment_id =
        DeploymentId::new(&env::var("NULLAPART_DEPLOYMENT_ID").unwrap_or_else(|_| "CZA-1".into()));
    let node_id = env::var("NULLAPART_NODE_ID").unwrap_or_else(|_| "mail-node-1".into());
    let node_version = env!("CARGO_PKG_VERSION").to_string();

    let handoff_secret = env::var("NULLAPART_HANDOFF_HMAC_SECRET")
        .map_err(|_| "NULLAPART_HANDOFF_HMAC_SECRET is required")?;
    let handoff_key_id =
        env::var("NULLAPART_HANDOFF_HMAC_KEY_ID").unwrap_or_else(|_| "mail-handoff-v1".into());

    let handoff = handoff_router(HandoffConfig {
        deployment_id: deployment_id.clone(),
        node_id: node_id.clone(),
        max_message_size: 52_428_800,
        hmac_secret: Some(handoff_secret),
        hmac_key_id: handoff_key_id,
        signature_max_age_secs: 300,
        signature_future_skew_secs: 30,
    });

    let mut trace_config = TraceConfig {
        deployment_id,
        node_id,
        node_version,
        config_revision: env::var("NULLAPART_CONFIG_REVISION").ok(),
        workload_token_sha256: None,
    };
    if let Ok(token) = env::var("NULLAPART_TRACE_WORKLOAD_TOKEN") {
        if !token.is_empty() {
            trace_config.set_workload_token(&token);
        }
    }

    let app = handoff.merge(trace_router(trace_config));
    let bind = env::var("NULLAPART_MAILCORE_BIND").unwrap_or_else(|_| "127.0.0.1:8081".into());
    if !bind.starts_with("127.0.0.1:") && !bind.starts_with("[::1]:") {
        return Err("Mail Core internal server must bind to loopback".into());
    }

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(bind = %bind, "Mail Core internal server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

//! Runtime capture glue: configuration, panic hook and the tracing ERROR
//! bridge. All of it is best-effort and side-effect free for the mail path;
//! capture failures must never crash the caller.

use std::collections::BTreeMap;
use std::panic::PanicHookInfo;
use std::sync::Arc;

use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use crate::emitter::TelemetryEmitter;
use crate::envelope::{
    build_envelope, Breadcrumb, EventKind, EventSubmission, Level, TelemetryIdentity,
};

/// Where telemetry points. Operator-supplied configuration only: the
/// endpoint URL is treated like a secret at rest (env-injected), never a
/// hard-coded or request-derived value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryConfig {
    pub endpoint: Option<String>,
    pub identity: TelemetryIdentity,
}

impl TelemetryConfig {
    /// Reads env vars: `NULLAPART_TELEMETRY_ENDPOINT`,
    /// `NULLAPART_TELEMETRY_ENVIRONMENT`, `NULLAPART_DEPLOYMENT_ID`,
    /// `NULLAPART_NODE_ID`, `NULLAPART_TELEMETRY_RELEASE`. Missing endpoint
    /// disables telemetry (a deployment without the backend simply logs to
    /// stdout only — telemetry is additive, never an operating dependency).
    pub fn from_env() -> Self {
        let endpoint = std::env::var("NULLAPART_TELEMETRY_ENDPOINT")
            .ok()
            .filter(|value| value.starts_with("http"))
            .filter(|value| !value.trim().is_empty());
        let identity = TelemetryIdentity {
            environment: std::env::var("NULLAPART_TELEMETRY_ENVIRONMENT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "unset".to_string()),
            deployment_id: std::env::var("NULLAPART_DEPLOYMENT_ID")
                .ok()
                .unwrap_or_else(|| "unset".to_string()),
            node_id: std::env::var("NULLAPART_NODE_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(hostname),
            release: std::env::var("NULLAPART_TELEMETRY_RELEASE")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        };
        Self { endpoint, identity }
    }

    /// Fires and forgets an event when telemetry is enabled.
    pub fn capture(&self, submission: &EventSubmission) {
        if let Some(endpoint) = &self.endpoint {
            let emitter = Arc::new(TelemetryEmitter::new(endpoint.clone()));
            emitter.send(build_envelope(submission, &self.identity));
        }
    }
}

fn hostname() -> String {
    std::env::var("NULLAPART_NODE_HOST_OVERRIDE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| match std::fs::read_to_string("/etc/hostname") {
            Ok(content) => content.trim().to_string(),
            Err(_) => std::env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "unknown-node".to_string()),
        })
}

/// Installs the process panic hook that reports panics as envelopes. The
/// previous hook (if any) still runs first so stderr keeps its stdlib
/// panic output for local debugging.
pub fn install_panic_hook(config: TelemetryConfig) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
        previous(info);
        let location = info
            .location()
            .map(|location| format!("at {}", location))
            .unwrap_or_else(|| "at unknown location".to_string());
        let submission = EventSubmission {
            kind: EventKind::Panic,
            level: Level::Error,
            message: format!("panic: {}", message_from(info)),
            identifiers: BTreeMap::new(),
            exception: Some(("panic".to_string(), location)),
            breadcrumbs: vec![Breadcrumb::new("process", None)],
        };
        config.capture(&submission);
    }));
}

/// Converts a panic payload into a bounded string for the event message;
/// the panic hook call site is expected to pass shapeless payloads, so
/// non-string payloads get a fixed placeholder.
fn message_from(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    if let Some(text) = payload.downcast_ref::<&str>() {
        text.to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// A `tracing` Layer that mirrors ERROR-level events into telemetry.
/// Applied in the server binary so every existing `tracing::error!(...)`
/// call site (static messages by policy) becomes an envelope automatically.
#[derive(Clone)]
pub struct ErrorCaptureLayer {
    config: Arc<TelemetryConfig>,
}

impl ErrorCaptureLayer {
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for ErrorCaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::ERROR {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let submission = EventSubmission {
            kind: EventKind::HandlerError,
            level: Level::Error,
            message: visitor
                .message
                .unwrap_or_else(|| "<unnamed error>".to_string()),
            identifiers: visitor.identifiers,
            exception: None,
            breadcrumbs: vec![Breadcrumb::new("tracing", Some(event.metadata().target()))],
        };
        // Best-effort: capture on a spawned task is not needed here because
        // config.capture already spawns the transmission task.
        self.config.capture(&submission);
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
    identifiers: BTreeMap<String, String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            // Structured identifier fields become envelope identifiers; the
            // scrub gate bounds them at build time.
            self.identifiers
                .insert(field.name().to_string(), value.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Envelope;

    fn config() -> TelemetryConfig {
        TelemetryConfig::from_env()
    }

    #[test]
    fn missing_endpoint_disables_capture_safely() {
        // No NUL… endpoint in the test env by default; capture must neither
        // panic nor block.
        let configuration = config();
        let submission = EventSubmission {
            kind: EventKind::Startup,
            level: Level::Info,
            message: "service up".to_string(),
            identifiers: BTreeMap::default(),
            exception: None,
            breadcrumbs: vec![],
        };
        configuration.capture(&submission);
    }

    #[tokio::test]
    async fn envelope_endpoint_override_is_respected() {
        // Direct emitter check: an endpoint string must pass through
        // unchanged (no credential reinterpretation of any kind).
        let endpoint = "http://127.0.0.1:1/api/key/envelope/";
        let emitter = TelemetryEmitter::new(endpoint);
        assert_eq!(emitter.endpoint(), endpoint);
        emitter.send(Envelope(vec![]));
        // Give the spawn a chance to run: it must fail (unreachable) but
        // never panic the test runtime.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    }

    #[tokio::test]
    async fn error_capture_layer_drives_emitter() {
        // The layer drives capture via config; asserting the end-to-end
        // wiring needs an HTTP listener, covered by receiver tests. Here we
        // assert the layer composes into a subscriber without panicking.
        use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
        let configuration = ErrorCaptureLayer::new(config());
        let subscriber = tracing_subscriber::registry().with(configuration);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!("handler failed: {}", "synthetic");
            tracing::error!(target: "audit-target", "static failure message");
        });
    }
}

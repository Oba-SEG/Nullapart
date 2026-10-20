//! Sentry-compatible envelope construction (docs/11).
//!
//! Nullapart emits application telemetry to the regional SegLumberjack
//! backend as Sentry-compatible envelopes. This module builds the wire
//! format and the event payload itself, applying the scrub gate to every
//! free-form string.
//!
//! Envelope wire format (Sentry protocol, line-oriented, `\n` separated):
//!
//! ```text
//! {"event_id":"<uuid>","sent_at":"<iso8601>","sdk":{"name":…,"version":…}}
//! {"length":<n>,"type":"event"}
//! <event json>
//! ```
//!
//! Single-event envelopes only: Nullapart telemetry is error-bearing and
//! low volume; one item per envelope keeps the receiver trivial and each
//! transmission failure isolated.

use std::collections::BTreeMap;

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::scrub::{scrub_key, scrub_text};

/// The SDK section identifies the emitter to the backend without carrying
/// dynamic content.
const SDK_NAME: &str = "nullapart-observability";
const SDK_VERSION: &str = "0.1.0";

/// Maximum extra/identifier entries per event so a runaway call site
/// cannot turn one diagnostic into an unbounded transmission.
const MAX_IDENTIFIERS: usize = 24;
const MAX_BREADCRUMBS: usize = 48;

/// Severity levels supported by the backend. Names match the Sentry wire
/// vocabulary (`error`, `warning`, `info`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warning,
    Info,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

/// High-level event kinds so the backend can route and rate-limit by class
/// without parsing message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Panic,
    PipelineError,
    HandlerError,
    TransportError,
    Startup,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Panic => "panic",
            Self::PipelineError => "pipeline_error",
            Self::HandlerError => "handler_error",
            Self::TransportError => "transport_error",
            Self::Startup => "startup",
        }
    }
}

/// A bounded breadcrumb: short, scrubbed, ordered context explaining how
/// the current failure was reached (stage names and opaque ids), never
/// payload text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breadcrumb {
    /// Stage or component, e.g. `handoff`, `scanner_fabric`.
    pub category: String,
    /// Identifier correlation for that stage, when any.
    pub reference: Option<String>,
}

impl Breadcrumb {
    pub fn new(category: &str, reference: Option<&str>) -> Self {
        Self {
            category: category.to_string(),
            reference: reference.map(|value| value.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventSubmission {
    pub kind: EventKind,
    pub level: Level,
    /// Static message from the instrumented call site (scrubbed again).
    pub message: String,
    /// Correlation bundle: transaction/customer/message/deployment ids.
    pub identifiers: BTreeMap<String, String>,
    /// Optional exception shape for panics: (type name, bounded location).
    pub exception: Option<(String, String)>,
    pub breadcrumbs: Vec<Breadcrumb>,
}

/// Static identity of the env Zeug emitting telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryIdentity {
    pub environment: String,
    pub deployment_id: String,
    pub node_id: String,
    pub release: Option<String>,
}

/// A serialized Sentry-compatible envelope, ready to POST.
#[derive(Debug, PartialEq)]
pub struct Envelope(pub Vec<u8>);

/// Builds the envelope. Every free-form field passes the scrub gate; a
/// value that scrubs to `None` is dropped from transport while the
/// envelope itself stays valid.
pub fn build_envelope(submission: &EventSubmission, identity: &TelemetryIdentity) -> Envelope {
    let event_id = Uuid::new_v4();
    let sent_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

    // The message passed the gate; when it did not (dynamic content that
    // slipped in), emit a fixed placeholder so the failure stays visible
    // as a signal with zero content.
    let message = scrub_text(&submission.message)
        .unwrap_or_else(|| "<scrubbed>".to_string())
        .to_string();

    let mut identifiers = BTreeMap::new();
    for (key, value) in submission.identifiers.iter().take(MAX_IDENTIFIERS) {
        let Some(key) = scrub_key(key) else { continue };
        let Some(value) = scrub_text(value) else {
            continue;
        };
        identifiers.insert(key, value);
    }

    let breadcrumbs: Vec<Value> = submission
        .breadcrumbs
        .iter()
        .take(MAX_BREADCRUMBS)
        .filter_map(|item| {
            Some(json!({
                "category": scrub_key(&item.category)?,
                "reference": item
                    .reference
                    .as_deref()
                    .and_then(scrub_text),
            }))
        })
        .collect();

    let environment = scrub_text(&identity.environment).unwrap_or_default();
    let deployment_id = scrub_text(&identity.deployment_id).unwrap_or_default();
    let node_id = scrub_text(&identity.node_id).unwrap_or_default();

    let event_json = json!({
        "event_id": event_id.to_string(),
        "timestamp": Utc::now().timestamp_millis() as f64 / 1000.0,
        "platform": "rust",
        "logger": format!("nullapart.{}", submission.kind.as_str()),
        "level": submission.level.as_str(),
        "message": { "formatted": message },
        "tags": {
            "kind": submission.kind.as_str(),
            "deployment_id": deployment_id,
            "node_id": node_id,
        },
        "environment": environment,
        "contexts": {
            "runtime": { "name": "rust" },
            "nullapart": identifiers,
        },
        "breadcrumbs": breadcrumbs,
        "exception": submission
            .exception
            .as_ref()
            .map(|(ty, location)| json!({
                "values": [{
                    "type": ty,
                    "value": location,
                }]
            }))
            .unwrap_or(json!({ "values": [] })),
    });
    // `release` is optional: only add the field when identity carries a
    // valid one, so the wire keeps a flat, valid object.
    let event = match identity
        .release
        .as_ref()
        .and_then(|release| scrub_text(release))
    {
        Some(release) => {
            let mut object = event_json;
            object["release"] = json!(release);
            object
        },
        None => event_json,
    };
    let event_bytes = serde_json::to_vec(&event).expect("event json must serialize");

    let header = json!({
        "event_id": event_id.to_string(),
        "sent_at": sent_at,
        "sdk": { "name": SDK_NAME, "version": SDK_VERSION },
    });
    let item_header = json!({
        "length": event_bytes.len(),
        "type": "event",
    });

    let mut envelope = Vec::new();
    envelope.extend_from_slice(header.to_string().as_bytes());
    envelope.push(b'\n');
    envelope.extend_from_slice(item_header.to_string().as_bytes());
    envelope.push(b'\n');
    envelope.extend_from_slice(&event_bytes);
    envelope.push(b'\n');
    Envelope(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> TelemetryIdentity {
        TelemetryIdentity {
            environment: "local".to_string(),
            deployment_id: "LOCAL-TEST".to_string(),
            node_id: "node-local-1".to_string(),
            release: Some("nullapart@dev".to_string()),
        }
    }

    fn submission() -> EventSubmission {
        EventSubmission {
            kind: EventKind::PipelineError,
            level: Level::Error,
            message: "handoff rejected: signature mismatch".to_string(),
            identifiers: BTreeMap::from([(
                "transaction_id".to_string(),
                "5fe45b32-96df-5850-93f7-6081cbe715ba".to_string(),
            )]),
            exception: None,
            breadcrumbs: vec![
                Breadcrumb::new("pipeline", Some("stage-verify")),
                Breadcrumb::new("handoff", None),
            ],
        }
    }

    fn wire(envelope: &Envelope) -> Vec<&str> {
        std::str::from_utf8(&envelope.0)
            .expect("envelope must be UTF-8")
            .lines()
            .collect()
    }

    #[test]
    fn envelope_has_header_item_payload_lines() {
        let envelope = build_envelope(&submission(), &identity());
        let lines = wire(&envelope);
        assert_eq!(lines.len(), 3, "header, item header, event payload");
        let header: Value = serde_json::from_str(lines[0]).expect("header line");
        assert!(header["event_id"].as_str().is_some());
        assert_eq!(
            header["sdk"]["name"],
            json!(SDK_NAME),
            "sdk identity is fixed and static"
        );
        let item: Value = serde_json::from_str(lines[1]).expect("item header");
        assert_eq!(item["type"], json!("event"));
        assert_eq!(
            item["length"],
            lines[2].len() as i64,
            "length must match the payload bytes"
        );
    }

    #[test]
    fn event_carries_static_message_and_tags_only() {
        let envelope = build_envelope(&submission(), &identity());
        let lines = wire(&envelope);
        let event: Value = serde_json::from_str(lines[2]).expect("event line");
        assert_eq!(
            event["message"]["formatted"],
            *"handoff rejected: signature mismatch"
        );
        assert_eq!(event["level"], *"error");
        assert_eq!(event["tags"]["kind"], *"pipeline_error");
        assert_eq!(event["tags"]["deployment_id"], *"LOCAL-TEST");
        assert_eq!(event["platform"], *"rust");
        assert_eq!(
            event["contexts"]["nullapart"]["transaction_id"],
            *"5fe45b32-96df-5850-93f7-6081cbe715ba"
        );
    }

    #[test]
    fn scrubbed_message_becomes_placeholder() {
        let mut submission = submission();
        submission.message = "Subject: you have won a free prize".to_string();
        let envelope = build_envelope(&submission, &identity());
        let lines = wire(&envelope);
        let event: Value = serde_json::from_str(lines[2]).expect("event line");
        assert_eq!(event["message"]["formatted"], *"<scrubbed>");
    }

    #[test]
    fn identifier_that_fails_scrub_is_dropped() {
        let mut submission = submission();
        submission.identifiers.insert(
            "leak".to_string(),
            "BEGIN PRIVATE KEY-----this is not an id".to_string(),
        );
        let envelope = build_envelope(&submission, &identity());
        let lines = wire(&envelope);
        let event: Value = serde_json::from_str(lines[2]).expect("event line");
        let nullapart = &event["contexts"]["nullapart"];
        assert!(
            nullapart.get("leak").is_none(),
            "secret-shaped must be dropped"
        );
        assert!(nullapart.get("transaction_id").is_some(), "clean ids stay");
    }

    #[test]
    fn breadcrumbs_are_scrubbed_and_capped() {
        let mut submission = submission();
        for index in 0..80 {
            submission
                .breadcrumbs
                .push(Breadcrumb::new(&format!("stage-{index}"), None));
        }
        let envelope = build_envelope(&submission, &identity());
        let lines = wire(&envelope);
        let event: Value = serde_json::from_str(lines[2]).expect("event line");
        let crumbs = event["breadcrumbs"].as_array().expect("breadcrumbs array");
        assert_eq!(crumbs.len(), MAX_BREADCRUMBS, "breadcrumb count is capped");
    }

    #[test]
    fn panic_carries_exception_shape() {
        let mut submission = submission();
        submission.kind = EventKind::Panic;
        submission.exception = Some(("panic".to_string(), "at pipeline.rs:4711".to_string()));
        let envelope = build_envelope(&submission, &identity());
        let lines = wire(&envelope);
        let event: Value = serde_json::from_str(lines[2]).expect("event line");
        assert_eq!(event["exception"]["values"][0]["type"], *"panic");
        assert_eq!(
            event["exception"]["values"][0]["value"],
            *"at pipeline.rs:4711"
        );
    }

    #[test]
    fn release_is_optional_and_scrubbed() {
        let submission = submission();
        let mut identity = identity();
        identity.release = Some("nullapart@2026.10.2".to_string());
        assert!(
            std::str::from_utf8(&build_envelope(&submission, &identity).0)
                .map(|wire| wire.contains("nullapart@2026.10.2"))
                .expect("envelope is utf8"),
            "release must land in the event"
        );
        let mut no_release = submission;
        no_release.breadcrumbs.clear();
        let mut bare = identity;
        bare.release = Some("BEGIN PRIVATE KEY".to_string());
        assert!(
            !std::str::from_utf8(&build_envelope(&no_release, &bare).0)
                .expect("envelope is utf8")
                .contains("PRIVATE KEY"),
            "a secret-shaped release must not be transmitted"
        );
    }
}

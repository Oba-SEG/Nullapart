//! Local SegLumberjack-compatible envelope receiver (development and test
//! backend).
//!
//! The production SegLumberjack is a regional application-observability
//! service (docs/11); this binary implements its minimal local contract so
//! components can be wired end-to-end in `compose.local.yml` without the
//! real regional deployment:
//!
//! - `POST /api/:key/envelope/` accepts a Sentry-compatible envelope body
//!   (`application/x-sentry-envelope`), validates shape and size, and
//!   appends each envelope as one JSONL record (base64 of the raw bytes)
//!   to the configured data directory file;
//! - `GET /healthz` returns plain ok so the compose stack can gate on it.
//!
//! Security posture: no parse of envelope bodies beyond structure checks,
//! HTTP status replies never echo input, size-capped request bodies, and an
//! in-process accept rate cap just like the emitter's ceiling. Events are
//! scrubbed at the emitter — the receiver trusts component identity via
//! network position in the local compose stack, so it must never be bound
//! outside the compose-internal network.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use nullapart_observability::emitter::MAX_ENVELOPE_BYTES;

/// Accept ceiling per process lifetime window; roughly aligned with the
/// emitter's per-minute ceiling so a misbehaving sender cannot grow the
/// local store without bound.
const MAX_ENVELOPES: u64 = 100_000;
const MAX_BODY_BYTES: usize = MAX_ENVELOPE_BYTES + 4096;

#[derive(Clone)]
struct ReceiverState {
    store_path: Arc<PathBuf>,
    accepted_total: Arc<AtomicU64>,
    rejected_total: Arc<AtomicU64>,
    last_time: Arc<Mutex<()>>,
}

impl ReceiverState {
    fn open() -> Self {
        let data_dir = std::env::var("SEGLUMBERJACK_LOCAL_DATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("seglumberjack-local"));
        std::fs::create_dir_all(&data_dir).expect("local store directory must create");
        let store_path = data_dir.join("envelopes.jsonl");
        Self {
            store_path: Arc::new(store_path),
            accepted_total: Arc::new(AtomicU64::new(0)),
            rejected_total: Arc::new(AtomicU64::new(0)),
            last_time: Arc::new(Mutex::new(())),
        }
    }

    fn accept(&self, body: &[u8]) -> Result<(), (StatusCode, &'static str)> {
        if body.len() > MAX_BODY_BYTES {
            self.rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "envelope too large"));
        }
        if self.accepted_total.load(Ordering::Relaxed) >= MAX_ENVELOPES {
            self.rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err((StatusCode::TOO_MANY_REQUESTS, "receiver at capacity"));
        }
        if !validate_envelope_shape(body) {
            self.rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err((StatusCode::BAD_REQUEST, "envelope shape invalid"));
        }
        let mut encoded = String::with_capacity(4 * body.len() / 3 + 8);
        encoded.push_str(&base64_encode(body));
        encoded.push('\n');
        let _serial = self.last_time.lock();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&*self.store_path)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "store unavailable"))?;
        file.write_all(encoded.as_bytes())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "store write failed"))?;
        self.accepted_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// Structure check without deep parsing: first line must be a JSON object
/// carrying an `event_id`, and there must be at least three lines
/// (header, item header, payload), mirroring our sender's format.
fn validate_envelope_shape(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let mut lines = text.lines();
    let Some(header_line) = lines.next() else {
        return false;
    };
    let Ok(header) = serde_json::from_str::<serde_json::Value>(header_line) else {
        return false;
    };
    header
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .is_some()
        && lines.next().is_some()
        && lines.next().is_some()
}

/// Minimal base64 (no external dependency): the local store is debug data.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triplet = (b0 << 16) | (b1 << 8) | b2;
        output.push(ALPHABET[(triplet >> 18) as usize & 63] as char);
        output.push(ALPHABET[(triplet >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(triplet >> 6) as usize & 63] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[triplet as usize & 63] as char);
        } else {
            output.push('=');
        }
    }
    output
}

async fn healthz() -> &'static str {
    "ok"
}

async fn ingest(
    State(state): State<ReceiverState>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, &'static str) {
    // The key is just a coarse emitter label locally; bound it the same
    // way a real backend would bound project credentials.
    if key.is_empty() || key.len() > 64 {
        return (StatusCode::FORBIDDEN, "key rejected");
    }
    let content_type_is_envelope = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.contains("sentry-envelope"))
        .unwrap_or(false);
    if !content_type_is_envelope {
        state.rejected_total.fetch_add(1, Ordering::Relaxed);
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "content-type rejected");
    }
    match state.accept(&body) {
        Ok(()) => (StatusCode::OK, "accepted"),
        Err((status, message)) => (status, message),
    }
}

async fn stats(State(state): State<ReceiverState>) -> Json<serde_json::Value> {
    Json(json!({
        "accepted_total": state.accepted_total.load(Ordering::Relaxed),
        "rejected_total": state.rejected_total.load(Ordering::Relaxed),
    }))
}

#[tokio::main]
async fn main() {
    let bind_address =
        std::env::var("SEGLUMBERJACK_LOCAL_BIND").unwrap_or_else(|_| "0.0.0.0:9050".to_string());
    let state = ReceiverState::open();
    let app = receiver_router(state);
    let listener = tokio::net::TcpListener::bind(&bind_address)
        .await
        .expect("local seglumberjack bind");
    tracing::info!(%bind_address, "local seglumberjack listening");
    axum::serve(listener, app).await.expect("server runs");
}

fn receiver_router(state: ReceiverState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/:key/envelope/", post(ingest))
        .route("/api/:key/envelope", post(ingest))
        .route("/stats", get(stats))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use nullapart_observability::envelope::{
        build_envelope, EventKind, EventSubmission, Level, TelemetryIdentity,
    };

    fn state() -> ReceiverState {
        let data_dir = std::env::temp_dir().join(format!(
            "seglumberjack-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::env::set_var("SEGLUMBERJACK_LOCAL_DATA", &data_dir);
        ReceiverState::open()
    }

    fn identity() -> TelemetryIdentity {
        TelemetryIdentity {
            environment: "local".to_string(),
            deployment_id: "LOCAL-TEST".to_string(),
            node_id: "test-node".to_string(),
            release: None,
        }
    }

    #[tokio::test]
    async fn accepts_valid_envelope_and_stores_it() {
        let state = state();
        let app = receiver_router(state.clone());
        let envelope = build_envelope(
            &EventSubmission {
                kind: EventKind::PipelineError,
                level: Level::Error,
                message: "synthetic transport failure".to_string(),
                identifiers: Default::default(),
                exception: None,
                breadcrumbs: vec![],
            },
            &identity(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/test-key/envelope/")
                    .header("content-type", "application/x-sentry-envelope")
                    .body(Body::from(envelope.0))
                    .expect("build request"),
            )
            .await
            .expect("respond");
        assert_eq!(response.status(), StatusCode::OK);
        let stored = std::fs::read_to_string(&*state.store_path).expect("store file");
        assert_eq!(stored.lines().count(), 1, "one envelope per line");
    }

    #[tokio::test]
    async fn rejects_wrong_content_type_and_bad_shape() {
        let state = state();
        let app = receiver_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/test-key/envelope/")
                    .header("content-type", "application/json")
                    .body(Body::from("{\"event_id\":\"x\"}"))
                    .expect("build request"),
            )
            .await
            .expect("respond");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let app = receiver_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/test-key/envelope/")
                    .header("content-type", "application/x-sentry-envelope")
                    .body(Body::from("not an envelope"))
                    .expect("build request"),
            )
            .await
            .expect("respond");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // Both rejection paths above counted; a valid store never received
        // either.
        assert_eq!(state.rejected_total.load(Ordering::Relaxed), 2);
        assert_eq!(state.accepted_total.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn rejects_overlong_keys() {
        let app = receiver_router(state());
        let key = "k".repeat(80);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/{key}/envelope/"))
                    .header("content-type", "application/x-sentry-envelope")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("respond");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn base64_parity_on_known_vector() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        // Multi-chunk sanity: our encoder must round-trip through a decoder
        // we trust in tests only via a manual vector.
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}

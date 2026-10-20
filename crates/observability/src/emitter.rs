//! Best-effort telemetry emission to the regional SegLumberjack backend.
//!
//! Design rules (docs/11 + reliability posture):
//!
//! - telemetry is best-effort and fire-and-forget: a send failure never
//!   blocks, retries, or alters mail-path behavior; failures log once and
//!   drop;
//! - a sliding one-minute window caps transmission rate so a looping
//!   component cannot flood the backend, and a cap on concurrently
//!   spawned send tasks bounds socket pressure;
//! - bodies carry only scrubbed envelopes; no DSNs or credentials — the
//!   endpoint URL is configured by the operator and never lifted from a
//!   request path.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

use crate::envelope::Envelope;

/// Maximum envelope body size; larger submissions are refused outright —
/// a diagnostic must never look like an attachment transport.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

/// Rate ceiling across all transmitters in a process (one minute window).
pub const DEFAULT_MAX_PER_MINUTE: u32 = 120;

/// Cap on concurrently running send tasks; further sends drop instead of
/// queueing, so telemetry pressure stays proportional to capability.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 16;

/// Per-request timeout: telemetry must not hold sockets or tasks hostage.
const SEND_TIMEOUT: Duration = Duration::from_secs(3);

struct RateWindow {
    window_started: Instant,
    used: u32,
    max: u32,
}

impl RateWindow {
    fn new(max: u32) -> Self {
        Self {
            window_started: Instant::now(),
            used: 0,
            max,
        }
    }

    fn try_permit(&mut self) -> bool {
        if self.window_started.elapsed() >= Duration::from_secs(60) {
            self.window_started = Instant::now();
            self.used = 0;
        }
        if self.used >= self.max {
            return false;
        }
        self.used += 1;
        true
    }
}

pub struct TelemetryEmitter {
    endpoint: String,
    client: reqwest::Client,
    in_flight: Arc<Semaphore>,
    rate: Mutex<RateWindow>,
    overflow_total: AtomicU64,
    rate_limited_total: AtomicU64,
    in_flight_dropped_total: AtomicU64,
}

impl TelemetryEmitter {
    /// Creates the emitter. `endpoint` is the full envelope URL, e.g.
    /// `http://seglumberjack/api/<key>/envelope/`.
    pub fn new(endpoint: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(SEND_TIMEOUT)
            .connect_timeout(Duration::from_secs(2))
            .build()
            .expect("telemetry http client must build");
        Self {
            endpoint: endpoint.into(),
            client,
            in_flight: Arc::new(Semaphore::new(DEFAULT_MAX_IN_FLIGHT)),
            rate: Mutex::new(RateWindow::new(DEFAULT_MAX_PER_MINUTE)),
            overflow_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            in_flight_dropped_total: AtomicU64::new(0),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Counters for tests and introspection: how many envelopes were
    /// refused at each guard.
    pub fn dropped_counts(&self) -> TelemetryDropCounts {
        TelemetryDropCounts {
            overflow: self.overflow_total.load(Ordering::Relaxed),
            rate_limited: self.rate_limited_total.load(Ordering::Relaxed),
            in_flight: self.in_flight_dropped_total.load(Ordering::Relaxed),
        }
    }

    /// Fire-and-forget transmit. The synchronous gates (size, rate, spawn
    /// capacity) all decide here so drop accounting is deterministic; only
    /// the network transfer itself is asynchronous — the mail path never
    /// awaits telemetry.
    pub fn send(&self, envelope: Envelope) {
        if envelope.0.len() > MAX_ENVELOPE_BYTES {
            self.overflow_total.fetch_add(1, Ordering::Relaxed);
            warn!(
                size = envelope.0.len(),
                cap = MAX_ENVELOPE_BYTES,
                "telemetry envelope over size cap, dropped"
            );
            return;
        }
        {
            let mut rate = match self.rate.try_lock() {
                Ok(rate) => rate,
                Err(_) => {
                    // A contended window lock is itself a rate signal: drop
                    // instead of blocking the caller.
                    self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
                    return;
                },
            };
            if !rate.try_permit() {
                drop(rate);
                self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        let permit: OwnedSemaphorePermit = match self.in_flight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.in_flight_dropped_total.fetch_add(1, Ordering::Relaxed);
                return;
            },
        };
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        let bytes = envelope.0;
        // Spawning can fail only during runtime shutdown; the envelope is
        // dropped then and the permit release keeps the semaphore correct.
        tokio::spawn(async move {
            let outcome = client
                .post(&endpoint)
                .header("content-type", "application/x-sentry-envelope")
                .body(bytes)
                .send()
                .await;
            if let Err(error) = outcome {
                warn!(%error, "telemetry envelope send failed; dropped");
            }
            drop(permit);
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryDropCounts {
    pub overflow: u64,
    pub rate_limited: u64,
    pub in_flight: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{build_envelope, EventKind, EventSubmission, Level, TelemetryIdentity};

    fn submission() -> EventSubmission {
        EventSubmission {
            kind: EventKind::PipelineError,
            level: Level::Error,
            message: "detector test".to_string(),
            identifiers: Default::default(),
            exception: None,
            breadcrumbs: vec![],
        }
    }

    fn identity() -> TelemetryIdentity {
        TelemetryIdentity {
            environment: "local".to_string(),
            deployment_id: "LOCAL-TEST".to_string(),
            node_id: "node-local-1".to_string(),
            release: None,
        }
    }

    fn envelope() -> Envelope {
        build_envelope(&submission(), &identity())
    }

    fn endpoint() -> String {
        "http://127.0.0.1:1/api/unreachable/envelope/".to_string()
    }

    #[tokio::test]
    async fn oversized_envelopes_are_dropped_without_transmission() {
        let emitter = TelemetryEmitter::new(endpoint());
        let big = Envelope(vec![b'a'; MAX_ENVELOPE_BYTES + 1]);
        emitter.send(big);
        let counts = emitter.dropped_counts();
        assert_eq!(counts.overflow, 1);
        assert_eq!(counts.rate_limited, 0);
    }

    #[tokio::test]
    async fn rate_window_drops_over_ceiling() {
        let emitter = TelemetryEmitter::new(endpoint());
        // Exceed the ceiling quickly; every envelope past `max` must be
        // counted as rate-limited, synchronously, deterministically.
        for _ in 0..(DEFAULT_MAX_PER_MINUTE + 10) {
            emitter.send(envelope());
        }
        let counts = emitter.dropped_counts();
        assert_eq!(counts.rate_limited, 10);
        assert_eq!(counts.overflow, 0);
    }

    #[tokio::test]
    async fn deterministic_gates_accept_below_ceiling_volume() {
        let emitter = TelemetryEmitter::new(endpoint());
        // Comfortably under both the rate ceiling and the in-flight cap.
        for _ in 0..12 {
            emitter.send(envelope());
        }
        let counts = emitter.dropped_counts();
        assert_eq!(
            counts,
            TelemetryDropCounts {
                overflow: 0,
                rate_limited: 0,
                in_flight: 0
            }
        );
        // The endpoint is unreachable on purpose: the send tasks must fail
        // asynchronously without panicking the runtime.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn in_flight_cap_drops_spawn_overflow() {
        let emitter = TelemetryEmitter::new(endpoint());
        // Under the rate ceiling but past the in-flight cap: everything the
        // semaphore cannot take must be counted synchronously.
        for _ in 0..40 {
            emitter.send(envelope());
        }
        let counts = emitter.dropped_counts();
        assert_eq!(counts.rate_limited, 0);
        assert_eq!(
            counts.in_flight,
            40 - DEFAULT_MAX_IN_FLIGHT as u64,
            "spawn overflow drops deterministically"
        );
        // Let spawned tasks resolve against the unreachable endpoint.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

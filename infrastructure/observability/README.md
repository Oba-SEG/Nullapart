# Observability

Nullapart uses complementary telemetry paths.

## Application observability

Application components use Sentry-compatible SDKs/protocols and send sanitized telemetry to **regional SegLumberjack**.

SegLumberjack is the primary application observability backend for:

- application errors/exceptions;
- release/service/node correlation;
- traces/performance telemetry where supported;
- frontend/backend/scanner/worker diagnostics.

A separate hosted Sentry service is not required by the architecture. "Sentry" refers to the instrumentation/protocol standard unless explicitly stated otherwise.

## Native daemon telemetry

Postfix, Rspamd, ClamAV and similar daemons require a regional collector path because they do not naturally emit Sentry-compatible application events.

The eventual infrastructure here should include a collector such as Vector, Fluent Bit or an OpenTelemetry-compatible collector that can:

- parse syslog/native logs;
- add region/deployment/node/release context;
- redact customer content/secrets;
- preserve safe queue/transaction correlation identifiers;
- route appropriate application diagnostics toward SegLumberjack;
- coexist with CloudWatch infrastructure telemetry.

## Implemented client layer

The Rust and browser telemetry clients implemented for docs/11:

- `crates/observability/src/scrub.rs` — scrub gate: secret-shaped markers
  (private keys, AWS access keys, bearer/Azure-style tokens, auth headers,
  password fragments, spam-side headers), 512-byte truncation with an
  elision marker and control-character replacement. Reused by every
  envelope field;
- `crates/observability/src/envelope.rs` — serializes hand-built
  Sentry-compatible envelopes (3 lines: envelope header JSON, one event
  item, the event payload). Log messages become `"<scrubbed>"` when the
  gate refuses them; the non-string reason can still travel as an empty
  exception marker;
- `crates/observability/src/emitter.rs` — non-blocking emitter with
  bounded resources only: 256 KB per envelope, 120 envelopes per minute,
  16 in flight, all drops counted (overflow / rate-limited / in-flight);
- `crates/observability/src/capture.rs` — a `tracing::Layer` that mirrors
  ERROR events into envelopes plus a panic hook (the previous hook runs
  first), both fed by `TelemetryConfig::from_env`
  (`NULLAPART_TELEMETRY_ENDPOINT`, `NULLAPART_TELEMETRY_ENVIRONMENT`,
  `NULLAPART_TELEMETRY_RELEASE`, plus deployment/node identifiers);
- `crates/observability/src/bin/seglumberjack_local.rs` — the compose
  receiver: `POST /api/<key>/envelope[/]` (Rust client),
  `POST /<project>/envelope[/]` (Sentry browser SDK DSN form) and CORS
  preflight for the browser emitter only, with a JSONL envelope store and
  `/stats` + `/healthz`.
- `docker/Dockerfile.seglumberjack` — dedicated receiver image on the
  backend network, published for the browser on the operator's address.

The mailcore server wires the layer + panic hook at startup
(`crates/mail-core/src/bin/mailcore-server.rs`), and the console
initializes `@sentry/browser` from build-time `VITE_TELEMETRY_*`
variables (src/lib/telemetry.ts) — unset DSN keeps it inert.

Error boards themselves (aggregation, dashboards, retention) remain
collector-house work tracked above; this client layer guarantees that
what leaves is bounded and scrubbed.

## AWS infrastructure telemetry

**CloudWatch** is used separately for AWS infrastructure and managed-service telemetry such as EC2/ECS, load balancers, RDS, cache, S3, VPC/network and AWS alarms.

CloudWatch does not replace SegLumberjack's application-observability role.

## Authoritative records

Security audit records and product events remain authoritative in Nullapart databases/outbox/event stores. Observability systems are diagnostic, not the sole audit trail or durable event bus.

## Data handling

Message content, raw MIME, attachments, credentials and secrets must be scrubbed before application/native-daemon telemetry reaches SegLumberjack.

See:

- `SECURITY.md`
- `docs/11-OBSERVABILITY-SECRETS.md`
- `docs/20-EVENT-DURABILITY.md`
- `docs/diagrams/10-observability-architecture.mmd`

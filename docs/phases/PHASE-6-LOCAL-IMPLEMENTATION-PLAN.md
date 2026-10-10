# Phase 6 Local Implementation Plan — Outbound Intelligence

This checklist tracks the local implementation of
`docs/phases/PHASE-6-OUTBOUND-INTELLIGENCE.md`. Documentation is not accepted as
completion unless the code, tests and local deployment evidence match it.

## Scope guardrails

- Preserve approved legitimate bulk sending within configured tenant/source
  limits.
- Detect unauthorized bulk, compromised senders, source spoofing and outbound
  campaigns without storing raw message bodies, raw MIME, full recipient lists or
  unnecessary content samples.
- Derive customer/deployment/source identity from trusted server context and
  connector/MTA facts, not client-supplied tenant IDs.
- Keep malware, malicious URL and compromise controls above bulk approval.
- Aggregate events with cooldown/deduplication; do not create one incident per
  outbound message.
- Keep all local/dev deployment verification on `ob1@192.168.8.4`.

## Increment checklist

- [x] Foundation schema and pure evaluator.
  - Migration `028_outbound_intelligence.sql` adds tenant-scoped approved bulk
    senders, outbound behaviour rollups, campaign fingerprints and outbound
    security events with RLS policies.
  - `outbound_intelligence` evaluates approved bulk limits, unapproved burst
    behaviour, low-and-slow rotating recipients, source spoofing, malware
    precedence and event cooldown/deduplication.
- [x] PostgreSQL RLS coverage for Phase 6 tables.
  - `postgres_outbound_intelligence.rs` proves unscoped sessions fail closed,
    scoped tenants see only their rows, and cross-tenant/deployment writes are
    rejected for the new Phase 6 tables.
- [x] Runtime persistence for behaviour rollups, campaign fingerprints and
  aggregated outbound security events.
  - `PostgresOutboundIntelligenceStore` loads active approved senders under
    transaction-scoped RLS and persists rollups, campaign fingerprints and
    deduplicated security events without storing raw content.
- [x] Wire evaluator into the trusted outbound path after server-derived
  customer/source/domain validation and before delivery.
  - `validate_outbound_with_intelligence` runs existing connector/domain
    validation first, loads approved senders from trusted source context,
    evaluates/persists Phase 6 intelligence and maps containment decisions to
    outbound transport disposition.
- [ ] Policy administration payloads for `bulk_sending`, `outbound_abuse` and
  `sender_reputation` thresholds.
- [ ] Customer/system notifications and async incident/outbox linkage for
  compromised sender and suspended outbound capability.
- [ ] Control-plane API and UI for outbound volume, sender/source behaviour,
  approved bulk senders, held/blocked events, campaigns, failure/bounce trends,
  policy/action history and notification state.
- [ ] Local `.4` migrated runtime verification: approved bulk allowed,
  unauthorized burst held/throttled, source spoofing blocked, malware from
  approved sender held, event deduplication observed.
- [ ] Full local gates: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, frontend checks when UI is touched, and ignored
  PostgreSQL tests on `192.168.8.4`.

## Evidence log

- Started Phase 6 on 2026-10-09 after Phase 5 commit
  `053ecba Complete phase 5 DMARC domain security`.
- OpenCode (`opencode/mimo-v2.6-flash-free`) was invoked for the first bounded
  slice but stalled during discovery; implementation was completed directly
  rather than waiting on a failed model run.
- Local checks for the foundation slice:
  - `cargo fmt --all -- --check`
  - `cargo test -p nullapart-mail-core outbound_intelligence --lib`
  - `cargo test --test postgres_outbound_intelligence --no-run`
  - `cargo clippy -p nullapart-mail-core --lib --tests -- -D warnings`
- `192.168.8.4` verification:
  - `028_outbound_intelligence.sql` applied to
    `nullapart-local-postgres-1`.
  - `NULLAPART_TEST_DATABASE_URL=postgres://...@127.0.0.1:15533/nullapart cargo test --test postgres_outbound_intelligence -- --ignored --test-threads=1`
    passed via SSH tunnel to the `.4` PostgreSQL container.
- Added the Phase 6 Postgres persistence adapter after the first commit:
  approval loading is tenant-scoped, rollups/campaign fingerprints upsert, and
  security events deduplicate by a bounded hashed event key. The remote ignored
  suite now covers both RLS isolation and persistence/event aggregation.
- Added module-level outbound validation wiring:
  `cargo test -p nullapart-mail-core outbound --lib` and
  `cargo clippy -p nullapart-mail-core --lib --tests -- -D warnings` passed.

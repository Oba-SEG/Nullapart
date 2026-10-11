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
  - Recipient-domain rollups are populated from trusted outbound RCPT domains
    as aggregate counts only; full recipient addresses are not persisted, and
    control-plane summary/sender queries filter to aggregate rollup rows to
    avoid double-counting domain-specific rows.
- [x] Wire evaluator into the trusted outbound path after server-derived
  customer/source/domain validation and before delivery.
  - `validate_outbound_with_intelligence` runs existing connector/domain
    validation first, loads approved senders from trusted source context,
    evaluates/persists Phase 6 intelligence and maps containment decisions to
    outbound transport disposition.
- [x] Policy administration payloads for `bulk_sending`, `outbound_abuse` and
  `sender_reputation` thresholds.
- [x] Customer/system notifications and async incident/outbox linkage for
  compromised sender and suspended outbound capability.
- [x] Control-plane API and UI for outbound volume, sender/source behaviour,
  approved bulk senders, held/blocked events, campaigns, failure/bounce trends,
  policy/action history and notification state.
- [ ] Local `.4` migrated runtime verification: approved bulk allowed,
  unauthorized burst held/throttled, source spoofing blocked, malware from
  approved sender held, event deduplication observed.
  - Prepared repeatable remote gate:
    `SSHPASS=1234 scripts/phase6_remote_verify.sh` syncs the Phase 6 files to
    `ob1@192.168.8.4:/home/ob1/Nullapart`, applies migration `029`, runs the
    ignored Postgres suite through an SSH tunnel and checks the authenticated
    outbound-intelligence API projection.
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
- Added the Phase 6 Control Plane slice:
  - `outbound_intelligence_api` exposes an authenticated, tenant-scoped
    `/api/v1/outbound-intelligence` projection plus an audited,
    step-up/idempotency-protected approved bulk sender mutation route.
  - `029_outbound_intelligence_control_plane.sql` grants
    `outbound-intelligence:view|manage` to System/Support and view-only access
    to Customer Admin.
  - The React Control Plane now has an Outbound intelligence route with
    operator-facing volume, sender/source, events, campaigns, approvals,
    policy-history and notification-state sections; it is covered by
    `OutboundIntelligence.test.tsx`.
  - Phase 6 policy metadata for `bulk_sending`, `outbound_abuse` and
    `sender_reputation` is publish-validated and loaded by the outbound
    evaluator, so thresholds are no longer only hard-coded defaults.
  - Aggregated outbound security events enqueue `outbound.security_event`
    outbox events for async customer/support/system notification and incident
    handling without direct external calls on the mail path.
  - The ignored Postgres suite now also proves `load_policy_thresholds` reads
    the three Phase 6 policy families under tenant scope and that persisted
    warning/critical outbound events create one deduplicated
    `outbound.security_event` outbox notification.
- Local verification for this slice:
  - `cargo fmt --all -- --check`
  - `cargo clippy -p nullapart-mail-core --lib --tests -- -D warnings`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test -p nullapart-mail-core outbound_intelligence --lib`
  - `cargo test --test postgres_outbound_intelligence --no-run`
  - `cargo clippy -p nullapart-mail-core --test postgres_outbound_intelligence -- -D warnings`
  - `cargo test --workspace`
  - `pnpm --dir frontend check-all`
- Added `scripts/phase6_remote_verify.sh` so the remaining `.4` gate is
  repeatable once SSH returns. Local validation: `bash -n
  scripts/phase6_remote_verify.sh` and `git diff --check`.
- Closed a Phase 6 fidelity gap in behaviour persistence: recipient-domain
  rollup rows are now written alongside aggregate sender/source rollups, and
  the Control Plane excludes those domain rows from top-level totals to keep
  system-admin counts actionable. Focused verification:
  - `cargo fmt --all`
  - `cargo fmt --all -- --check`
  - `cargo test -p nullapart-mail-core outbound_intelligence --lib`
  - `cargo test -p nullapart-mail-core outbound --lib`
  - `cargo test --test postgres_outbound_intelligence --no-run`
  - `cargo clippy -p nullapart-mail-core --lib --tests -- -D warnings`
  - `cargo clippy -p nullapart-mail-core --test postgres_outbound_intelligence -- -D warnings`
- Full local gates after commit `15ec5a6`:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `pnpm --dir frontend check-all`
- Tightened runtime fidelity after the Phase 6 requirement audit:
  `validate_outbound_with_intelligence` now loads persisted content-free
  sender/source/campaign/domain rollup metrics and merges them with the
  trusted runtime snapshot before evaluating policy, so maintained rolling
  counters cannot be bypassed by an under-populated caller snapshot. Focused
  verification:
  - `cargo fmt --all -- --check`
  - `cargo test -p nullapart-mail-core outbound --lib`
  - `cargo test --test postgres_outbound_intelligence --no-run`
  - `cargo clippy -p nullapart-mail-core --lib --tests -- -D warnings`
  - `cargo clippy -p nullapart-mail-core --test postgres_outbound_intelligence -- -D warnings`
- Full local gates after commit `3226e88`:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `pnpm --dir frontend check-all`
- Closed the cooldown/dedup runtime wiring gap: the outbound intelligence path
  now loads an open matching `outbound_security_events` row inside its cooldown
  window and re-evaluates with `existing_event`, so repeated detections are
  marked for aggregation before persistence/outbox handling. Focused
  verification:
  - `cargo fmt --all -- --check`
  - `cargo test -p nullapart-mail-core outbound --lib`
  - `cargo test --test postgres_outbound_intelligence --no-run`
  - `cargo clippy -p nullapart-mail-core --lib --tests -- -D warnings`
  - `cargo clippy -p nullapart-mail-core --test postgres_outbound_intelligence -- -D warnings`
- Full local gates after commit `646a5e3`:
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `pnpm --dir frontend check-all`
- Remote verification is currently pending because this host cannot reach
  `192.168.8.4`: `ping` reported host down and `ssh -o ConnectTimeout=8`
  timed out on port 22 on 2026-10-11; later `nc -vz -G 5 192.168.8.4 22`
  checks also timed out, including after commits `15ec5a6`, `3226e88` and
  `646a5e3`.

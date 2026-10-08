# Phase 5 Local Implementation Plan — DMARC, BIMI and Domain Security

**Status:** started 2026-10-05. This document tracks local/dev implementation
evidence for `PHASE-5-DMARC-BIMI.md` and `docs/08-DMARC-BIMI.md`.

## Goal and boundaries

Deliver the Phase 5 domain-authentication platform in safe increments:

```text
increment 1: DMARC aggregate ingestion foundation
             (bounded parser, normalized storage, duplicate key, malformed
             quarantine metadata, exact verified-domain mapping helper)
increment 2: actionable domain-security read models, authenticated API and UI
increment 3: regional report mailbox/ingress worker
increment 4: live authentication telemetry aggregation
increment 5: source attribution and classification mutation/history
increment 6: external report-destination authorization validator
increment 7: domain observer history for MX/SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT
increment 8: BIMI validation, safe SVG handling, and readiness state
increment 9: notifications, security battery, local live evidence, and report
```

Out of scope for increment 1:

- no mailbox polling daemon;
- no new public endpoint;
- no autonomous DNS modification;
- no failure-report (`ruf`) content handling;
- no raw XML UI;
- no BIMI SVG rendering.

## Increment 1 — DMARC aggregate ingestion foundation

Implemented:

- Migration `021_dmarc_aggregate_reports.sql` adds:
  - `dmarc_aggregate_reports` for normalized report metadata and duplicate
    detection;
  - `dmarc_aggregate_records` for per-source aggregate rows;
  - `dmarc_report_quarantine` for bounded malformed/unmapped report metadata;
  - fail-closed RLS policies and guarded grants for `nullapart_mailcore`.
- Rust module `crates/mail-core/src/dmarc_aggregate.rs` adds:
  - direct XML and gzip input handling under compressed/decompressed limits;
  - explicit zip rejection until safe archive parsing is added;
  - pre-parse rejection for `DOCTYPE`/`ENTITY`, plus event-parser rejection
    for DTD/general-reference/CDATA constructs;
  - bounded text, XML depth, and record count;
  - typed normalized report/record structs;
  - stable SHA-256 duplicate key from reporter, report id, policy domain and
    date range;
  - exact verified-domain mapping helper only. No suffix/organizational-domain
    fallback is used in this increment;
  - `PostgresDmarcAggregateIngestor` for idempotent persistence of normalized
    reports/records and bounded quarantine metadata. It resolves policy
    domains through the reviewed verified-domain model, establishes
    transaction-local deployment/customer scope before tenant rows are written,
    and treats duplicate reports as replayed success rather than duplicating
    rows.
- Integration test `postgres_dmarc_aggregate.rs` proves:
  - first ingest inserts one report and one record;
  - replay of the same report returns `Duplicate` without inserting records;
  - unmapped policy domains are quarantined without records;
  - tenant RLS hides another customer’s rows.

Evidence:

- 2026-10-05 local: `cargo fmt --all -- --check` — pass.
- 2026-10-05 local: `cargo test -p nullapart-mail-core dmarc_aggregate`
  — pass, 8 DMARC aggregate unit tests.
- 2026-10-05 local: `cargo clippy --workspace --all-targets -- -D warnings`
  — pass.
- 2026-10-05 local: `cargo test --workspace` — pass.
- 2026-10-05 `.4`: migration `021_dmarc_aggregate_reports.sql` applied to
  the local/dev PostgreSQL volume — pass.
- 2026-10-05 `.4` via SSH tunnel:
  `cargo test --test postgres_dmarc_aggregate -- --ignored --nocapture`
  — pass, 2/2 database tests.
- 2026-10-05 `.4`: `docker compose --env-file .env.local -f compose.local.yml
  build mailcore` — pass; `quick-xml v0.38.4` downloaded and release image
  built.
- 2026-10-05 `.4`: `docker compose --env-file .env.local -f compose.local.yml
  up -d mailcore` — pass; rebuilt service started.
- 2026-10-05 `.4`: `GET /api/v1/trace/health` on
  `192.168.8.4:58081` — pass, returned `status=healthy`.
- 2026-10-05 `.4` post-restart via SSH tunnel:
  `cargo test --test postgres_dmarc_aggregate -- --ignored --nocapture`
  — pass, 2/2 database tests.

Known limitations:

- ZIP aggregate reports are explicitly unsupported until a bounded archive
  parser is added. Gzip is implemented.
- The module has parser and DB persistence only; the regional mailbox/ingress
  worker, API, UI, observer, BIMI, and notification increments are still
  pending.
- Exact-domain mapping is intentionally conservative; organizational-domain
  fallback requires a reviewed public-suffix strategy and tenant-boundary tests.

## Increment 2 — actionable domain-security read model, API and UI

Implemented:

- Migration `022_domain_security_read_models.sql` adds tenant-scoped Phase 5
  read models:
  - `domain_security_observations` for normalized observer history/status;
  - `dmarc_report_authorizations` for third-party report destination
    authorization state;
  - `bimi_domain_status` for BIMI readiness metadata without storing or
    rendering SVG bytes;
  - `domain_source_classifications` for source attribution state;
  - `domain_security_notifications` for actionable open domain-security alerts;
  - RLS policies plus guarded grants for `nullapart_mailcore`;
  - `domain-security:view` and `domain-security:manage` role permissions.
- Rust module `crates/mail-core/src/domain_security.rs` adds authenticated
  `GET /api/v1/domain-security`.
  - Requires an active `TenantContext`, deployment match and
    `domain-security:view`.
  - Establishes transaction-local RLS scope.
  - Also binds every read query explicitly to deployment and customer as
    defense in depth against mis-provisioned local roles.
  - Projects compliance summary, per-domain DMARC aggregate metrics, external
    authorization status, BIMI readiness status, latest observer checks, top
    source summaries and open notifications.
  - Does not expose raw aggregate XML, failure-report content, raw DNS
    resolver payloads, SVG bytes or message samples.
- The same module adds authenticated
  `POST /api/v1/domain-security/source-classifications`.
  - Requires an active `TenantContext`, deployment match,
    `domain-security:manage`, fresh step-up authentication and
    `x-idempotency-key`.
  - Server-validates the target domain against the caller’s customer scope and
    returns `404` for cross-tenant domain probes.
  - Upserts source attribution as one of: authorized, expected incomplete,
    unknown, suspicious, malicious or third-party.
  - Writes append-only audit evidence for classification changes and replays
    completed idempotent requests.
- `mailcore-server` wires the route into the authenticated control-plane API.
- Built-in admin roles now include:
  - `system_admin` and `support`: `domain-security:view`,
    `domain-security:manage`;
  - `customer_admin`: `domain-security:view`.
- Frontend adds `/domain-security` with RBAC-gated navigation and a structured
  system-admin page for:
  - DMARC volume/alignment and enforcement state;
  - external report authorization owner/value/status;
  - BIMI readiness blockers;
  - observer check history;
  - unknown/source-action tables;
  - inline source-classification controls for operators with
    `domain-security:manage`;
  - open operational alerts.
- Integration test `postgres_domain_security.rs` proves a seeded projection is
  actionable and does not include another customer’s domain in the response.
  It also covers source-classification mutation idempotency, audit evidence and
  cross-tenant rejection.

Evidence:

- 2026-10-06 local: `cargo test -p nullapart-mail-core domain_security`
  — pass, unauthenticated and missing-permission checks.
- 2026-10-06 local: `cargo test --test postgres_domain_security`
  — pass, ignored PostgreSQL projection test compiles and remains opt-in.
- 2026-10-06 local: `cargo clippy --workspace --all-targets -- -D warnings`
  — pass.
- 2026-10-06 local: `cargo test --workspace` — pass.
- 2026-10-06 local frontend: `pnpm check-all` from `frontend/` — pass, with
  only the existing Node engine warning because this shell uses Node 22 while
  the frontend declares Node 24.
- 2026-10-07 local: `cargo clippy --workspace --all-targets -- -D warnings`
  — pass after source-classification mutation.
- 2026-10-07 local: `cargo test --workspace` — pass after
  source-classification mutation.
- 2026-10-07 local frontend: `pnpm check-all` from `frontend/` — pass, with
  the same Node 22 vs declared Node 24 warning.

Known limitations:

- This increment creates the actionable read model/API/UI, but the background
  mailbox worker, DNS observer, report-authorization validator, BIMI secure-SVG
  validator and alert-generation worker are still pending Phase 5 increments.
- The frontend can display existing observations/status rows and classify
  existing report sources; it does not yet trigger observer refreshes or create
  new source observations without aggregate-report data.

## Increment 3 — regional aggregate-report ingress worker

Implemented:

- Migration `023_dmarc_report_ingress_jobs.sql` adds
  `dmarc_report_ingress_jobs`, a deployment-scoped durable queue for stored
  aggregate-report artifacts.
  - Raw XML/report bytes remain only in ArtifactStore.
  - Rows carry bounded worker status/error metadata, attempt counts,
    idempotency key, optional linked aggregate report row and record counts.
  - RLS is deployment-scoped and grants are limited to `SELECT`, `INSERT` and
    `UPDATE` for the local Mail Core runtime role.
- Rust module `crates/mail-core/src/dmarc_ingress.rs` adds
  `DmarcReportIngressWorker`.
  - Claims one pending/failed job with `FOR UPDATE SKIP LOCKED` semantics.
  - Reads bytes only through an exact short-lived ArtifactStore grant with the
    new `DmarcReportIngestion` purpose.
  - Invokes `PostgresDmarcAggregateIngestor` with automatic XML/gzip detection
    and the existing parser/resource limits.
  - Marks jobs terminally as `succeeded`, `duplicate`, `quarantined` or
    `dead_lettered`; missing/unreadable artifacts cannot starve later jobs.
  - Provides `enqueue_dmarc_report_artifact` for the later mailbox poller to
    create jobs idempotently after it stores each report artifact.
- `mailcore-server` now starts the ingress worker by default. It can be
  disabled in local/dev with `NULLAPART_DMARC_INGRESS_WORKER_ENABLED=false`.
- The runtime-role provisioning script now grants the worker table.
- Integration test `postgres_dmarc_ingress.rs` proves:
  - an enqueued stored report artifact is processed into one aggregate report;
  - a second queued job for the same artifact/report is marked `duplicate`
    rather than inserting rows again;
  - an unreadable artifact is dead-lettered with `ARTIFACT_UNAVAILABLE` and the
    queue becomes idle.

Evidence:

- 2026-10-07 local: `cargo fmt --all` — pass.
- 2026-10-07 local: `cargo test -p nullapart-mail-core dmarc_ingress --tests -- --nocapture`
  — pass; ignored PostgreSQL ingress tests compile.
- 2026-10-07 local: `cargo clippy --workspace --all-targets -- -D warnings`
  — pass.
- 2026-10-07 local: `cargo test --workspace` — pass.
- 2026-10-07 `.4`: migration `023_dmarc_report_ingress_jobs.sql` applied to
  the local/dev PostgreSQL volume — pass.
- 2026-10-07 `.4`: `docker compose --env-file .env.local -f compose.local.yml
  build mailcore` — pass after fixing the worker claim projection to decode
  `attempts::bigint` instead of leaving jobs stuck in `processing`.
- 2026-10-07 `.4`: `docker compose --env-file .env.local -f compose.local.yml
  up -d --force-recreate mailcore` — pass; rebuilt service started.
- 2026-10-07 `.4`: `GET /api/v1/trace/health` on
  `192.168.8.4:58081` — pass, returned `status=healthy`.
- 2026-10-07 `.4` via SSH tunnel:
  `cargo test --test postgres_dmarc_ingress -- --ignored --nocapture`
  — pass, 2/2 database tests.

Known limitations:

- This increment adds the durable worker boundary and enqueue API, not an IMAP
  or SMTP report-mailbox poller. The poller still needs to store each mailbox
  attachment as an artifact and call `enqueue_dmarc_report_artifact`.
- Report artifacts are currently read under the customer artifact scope carried
  by the ingress job. A future regional mailbox implementation should choose
  the reviewed customer mailbox/source mapping before enqueueing; system-scope
  report artifacts would require a separate platform-artifact recovery/RLS
  design.
- Live gateway telemetry, DNS observer, authorization validator, BIMI validator
  and alert generation remain pending increments.

## Increment 4 — live authentication telemetry aggregation

Implemented:

- Migration `024_domain_auth_telemetry.sql` adds `domain_auth_telemetry`, a
  tenant-scoped, content-free projection of live gateway authentication
  observations.
  - Stores deployment/customer/domain/message identity, source IP, normalized
    source/envelope/header domains, bounded SPF/DKIM/DMARC result labels,
    scanner disposition and observation time.
  - Does not store raw MIME, raw header text, `Authentication-Results` text,
    DNS payloads, message bodies or failure-report content.
  - Enforces deployment/customer RLS and grants the local Mail Core role
    `SELECT`, `INSERT` and `UPDATE` only.
- Rust module `crates/mail-core/src/domain_auth_telemetry.rs` adds
  `project_handoff_auth_telemetry`.
  - Runs after successful durable handoff scanning, using the server-derived
    tenant/customer context and verified owned `From` domain.
  - Skips unowned/malformed `From` domains and invalid source IPs without
    failing accepted mail.
  - Upserts by `(deployment_id, tenant_message_id, domain_id)` so retries are
    idempotent.
  - Uses explicit milter observations when present and falls back to trusted
    `Authentication-Results` header parsing when the after-queue producer has
    no structured auth fields; only normalized result labels are persisted.
- `domain_security.rs` now unions DMARC aggregate reports with live telemetry
  for volume/source inventory.
  - Telemetry contributes message/source volume and DMARC result pass/fail.
  - It deliberately does not count raw SPF/DKIM pass as SPF/DKIM alignment
    until selector/domain alignment fields are implemented.
  - It deliberately does not count scanner quarantine/reject disposition as
    DMARC policy quarantine/reject.
- `phase2_handoff.rs` wires telemetry projection into the durable handoff path.
  Projection errors log a warning and preserve the accepted-mail safety
  contract.
- Integration tests now cover:
  - idempotent telemetry recording;
  - invalid/unowned-domain skips;
  - domain-security projection of live telemetry source rows;
  - raw SPF/DKIM pass not inflating DMARC alignment when DMARC fails;
  - scanner quarantine not being reported as DMARC policy quarantine.

Evidence:

- 2026-10-08 local: `cargo fmt --all` — pass.
- 2026-10-08 local:
  `cargo test -p nullapart-mail-core domain_auth_telemetry --tests -- --nocapture`
  — pass, 4 unit tests.
- 2026-10-08 local:
  `cargo clippy --workspace --all-targets -- -D warnings` — pass.
- 2026-10-08 `.4`: migration `024_domain_auth_telemetry.sql` applied to the
  local/dev PostgreSQL volume — pass.
- 2026-10-08 `.4` via SSH tunnel:
  `cargo test --test postgres_domain_auth_telemetry -- --ignored --nocapture`
  — pass, 2/2 database tests.
- 2026-10-08 `.4` via SSH tunnel:
  `cargo test --test postgres_domain_security -- --ignored --nocapture`
  — pass, 2/2 database tests, including live telemetry source projection.
- 2026-10-08 `.4`: `docker compose --env-file .env.local -f compose.local.yml
  build mailcore` — pass.
- 2026-10-08 `.4`: `docker compose --env-file .env.local -f compose.local.yml
  up -d --force-recreate mailcore` — pass.
- 2026-10-08 `.4`: `GET /api/v1/trace/health` on
  `192.168.8.4:58081` — pass, returned `status=healthy`.
- 2026-10-08 `.4` live HMAC handoff smoke:
  structured milter auth fields were `None`, MIME carried
  `Authentication-Results`; Mail Core accepted the message and
  `domain_auth_telemetry` stored `phase2.test`, `203.0.113.56`,
  `spf=pass`, `dkim=fail`, `dmarc=pass` — pass.

Known limitations:

- SPF/DKIM alignment detail, DKIM selector/domain and ARC status are still
  pending because the current after-queue handoff contract has only normalized
  result labels. Until those fields are added, live telemetry does not claim
  SPF/DKIM alignment.
- The current projection is per-message and needs a retention/rollup policy
  before production-scale retention.
- Duplicate counting between aggregate reports and live telemetry is possible
  in a local/dev window because aggregate reports and live gateway telemetry
  are independent evidence sources.
- DNS observer, external report-destination authorization validator, BIMI
  validator and alert generation remain pending increments.

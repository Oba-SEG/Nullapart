# Phase 5 Local Implementation Plan — DMARC, BIMI and Domain Security

**Status:** started 2026-10-05. This document tracks local/dev implementation
evidence for `PHASE-5-DMARC-BIMI.md` and `docs/08-DMARC-BIMI.md`.

## Goal and boundaries

Deliver the Phase 5 domain-authentication platform in safe increments:

```text
increment 1: DMARC aggregate ingestion foundation
             (bounded parser, normalized storage, duplicate key, malformed
             quarantine metadata, exact verified-domain mapping helper)
increment 2: regional report mailbox/ingress worker
increment 3: live authentication telemetry aggregation
increment 4: source attribution and classification history
increment 5: external report-destination authorization status
increment 6: domain observer history for MX/SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT
increment 7: dashboard/UI and customer/support drill-downs
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

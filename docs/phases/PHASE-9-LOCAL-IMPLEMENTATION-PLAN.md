# Phase 9 Local Implementation Plan — Operations Hardening

Status: complete for local/dev Phase 9 implementation scope; production
readiness remains intentionally unsigned until the follow-up evidence below is
attached.

This plan maps `docs/phases/PHASE-9-OPERATIONS-HARDENING.md` to the local/dev
implementation. Phase 9 is a production-readiness phase: local/dev code can
create the evidence model, dashboard and repeatable checks, but production
readiness is not claimed until deployment-specific exercises, monitoring,
restore tests and approvals are attached.

## Implemented scope

- [x] Deployment-scoped operations-hardening schema:
  - migration `032_operations_hardening.sql`;
  - `operations_tier3_capabilities`;
  - `operations_alert_rules`;
  - `operations_readiness_checks`;
  - PostgreSQL RLS enabled and forced for every Phase 9 table.
- [x] Tier-3 capability register seeded for the initial production-critical
  capabilities from `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`:
  - inbound SMTP acceptance;
  - accepted-message durability;
  - mail processing;
  - required scanner path;
  - Control Backend;
  - administrative authentication;
  - audit persistence;
  - transactional outbox / required async workflows.
- [x] Burn-rate alert definitions:
  - fast page, 14.4x over 1h + 5m;
  - sustained page, 6x over 6h + 30m;
  - slow-burn ticket path.
- [x] Production-readiness evidence register:
  - security-program, source/CI, SLO, audit, zero-day, restore/DR, network and
    support-diagnostics checks;
  - rows deliberately preserve `partial` and `not_ready` states where real
    production evidence is still missing.
- [x] Authenticated Control Plane API projection:
  - `GET /api/v1/operations/hardening`;
  - uses the existing `operations:view` permission and deployment-scoped RLS.
- [x] UI:
  - `/operations` now shows Phase 9 hardening summary, Tier-3 SLO capability
    register, burn-rate alert definitions and production-readiness evidence;
  - no raw JSON UI and no production-ready claim without evidence.
- [x] Runbook:
  - `docs/runbooks/PHASE9-OPERATIONS-HARDENING.md`.
- [x] Tests:
  - Rust unit tests for hardening API auth/permission gating;
  - ignored PostgreSQL RLS test for fail-closed/deployment isolation;
  - frontend tests for Phase 9 hardening/evidence rendering.

## Non-goals preserved

- No autonomous production remediation.
- No modification of production secrets or live infrastructure.
- No weakening of SLO/alert/readiness thresholds to make the dashboard green.
- No claim of production readiness or external certification.
- No replacement of user-impact SLO paging with generic CPU/memory alerts.

## Evidence to keep current

Verified on 2026-10-13:

- Local:
  - `cargo fmt --all -- --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed.
  - `pnpm --dir frontend check-all` passed.
  - `bash -n scripts/phase9_remote_verify.sh && git diff --check` passed.
- Remote `.4`:
  - `SSHPASS=1234 scripts/phase9_remote_verify.sh` passed against
    `ob1@192.168.8.4:/home/ob1/Nullapart`.
  - The script rebuilt the remote Mail Core/frontend images, applied migration
    `032_operations_hardening.sql`, ran
    `postgres_operations_hardening` against the tunneled remote DB, checked
    authenticated `/api/v1/operations/hardening` and confirmed the remote
    `/operations` SPA is served.
  - The first remote run caught an ambiguous seed-column defect in the migration;
    the migration now qualifies all seeded values and re-applied cleanly after
    PostgreSQL rolled back the failed transaction.
  - A fresh remote temporary-database migration check applied
    `001_phase0_foundation.sql`, inserted one deployment, then applied
    `032_operations_hardening.sql`; it produced 8 Tier-3 capability rows,
    24 burn-rate alert rows and 9 readiness rows.

## Follow-up before production sign-off

- Attach live monitoring evidence for every enabled alert rule and mark tested
  only after a burn-rate alert/runbook exercise.
- Record restore/DR evidence for PostgreSQL, artifact storage, identity, audit
  archive and mail queue recovery.
- Complete a zero-day parser/dependency tabletop or technical exercise.
- Attach repository branch-protection and CI/security-scan evidence.
- Attach production firewall/port/ALB/WAF/SMTP commissioning validation.
- Record capacity baselines for SMTP, queues, scanners, database/cache,
  outbox/SQS, artifact store, UI and Deep AI where enabled.

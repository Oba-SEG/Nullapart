# Phase 2 Exit-Gate and Phase 3 Readiness Review

**Date:** 2026-09-22
**Scope:** Phase 2 (Scanner Fabric and Quarantine) exit criteria and Phase 3 (Control Plane) prerequisites, per `docs/phases/PHASE-2-SCANNER-FABRIC.md` and `docs/phases/PHASE-3-CONTROL-PLANE.md`.
**Inputs:** `AGENTS.md`, `SECURITY.md`, `docs/16-BUILD-ROADMAP.md`, prior `docs/reviews/2026-09-22-full-phase-review.md`, and working-tree evidence in `crates/`, `frontend/`, `migrations/`, `scanners/`.
**State reviewed:** branch `fix/security-foundation-hardening` at `377d592`, plus uncommitted working-tree changes (`infrastructure/aws/main.tf`, `docker/`, `docker-compose.yml`, `infrastructure/aws/templates/`). This review does not modify implementation.

## Disposition

**Phase 2 exit gate: NOT MET.** Contract/type layering exists for scanner findings, disposition, quarantine state and failure semantics, but there is no scanner orchestration, no scanner implementations, no quarantine persistence/release path, and no quarantine/findings UI. None of the seven Phase 2 exit criteria are satisfied end-to-end.

**Phase 3 readiness: NOT READY.** Two Phase 3 prerequisites fail: Phase 2 scanner/quarantine contracts are not stable as runtime capabilities (above), and the identity-platform security/license decision is still open (`docs/15-AWS-DEPLOYMENT.md`: "ZITADEL is the leading regional identity candidate, subject to licensing/security validation"). Phase 3 has supporting types only; no Control Backend, no `/api/v1/auth/*` implementation, no RBAC/impersonation runtime, no admin UI beyond placeholders.

## Phase 2 exit-gate assessment

| Exit criterion | Status | Evidence |
|---|---|---|
| Scanner orchestration is parallel/bounded | **Fail** | `crates/mail-core/src/pipeline.rs` defines `PipelineStage`, `PipelineResult`, `PipelineConfig` only — no execution loop, no concurrency bound, no deadline enforcement. No `Semaphore`/`JoinSet`/`buffer_unordered` anywhere in `crates/`. `scanners/README.md`: implementations "will live here when implementation begins". |
| Required failure semantics enforced | **Fail (contracts only)** | Contract types exist: `ScannerStatus::{Unknown, Error}`, `ScannerFailure`, `FailureType::{Unavailable, Timeout, Error, ResourceLimit}` (`crates/mail-contracts/src/finding.rs`); `PipelineConfig.quarantine_on_scanner_error = true` and `default_disposition = Disposition::Hold` (`pipeline.rs`); fail-safe Hold on no-match (`crates/mail-core/src/policy.rs:88`, test `no_rules_fail_safe_to_hold`). No runtime path invokes scanners, so UNKNOWN/ERROR can never be produced or observed. |
| Quarantine/release tenant-safe and audited | **Fail (contracts only)** | `QuarantineState` (`crates/mail-contracts/src/transaction.rs`), `Disposition::{Quarantine, Hold}`, `AuditAction::quarantine`/`release`, `EventType::MessageQuarantined`, `AppRateLimits::quarantine_release` exist. Missing: no quarantine table in `migrations/` (only a `disposition` CHECK on `tenant_message_instances`), no release history, no release endpoint, no release audit write path. `frontend/src/pages/Quarantine.tsx` and `MessageDetail.tsx` are 7-line placeholders. |
| Parser failure cannot take down Mail Core | **Not demonstrated** | No parsers/scanners execute in Mail Core; nothing to crash-isolate. |
| Resource-exhaustion tests pass | **Fail** | No archive-bomb, nested-archive, encrypted-file, scanner-timeout, or scanner-OOM tests exist anywhere in `crates/`. |
| UI shows normalized findings without engine leakage | **Fail** | No findings/quarantine UI beyond placeholders. `frontend/src/types/index.ts` still exposes `scanner: string` / `scanner_status: string` as free-form fields. |
| Artifacts regional and permission-controlled | **Partial** | `StorageBackend::S3` and `StorageLocation` (`crates/mail-contracts/src/artifact.rs`); `artifacts` table with `FORCE ROW LEVEL SECURITY` (`migrations/002_contract_isolation_hardening.sql`); S3 `aws:kms` SSE + KMS key in `infrastructure/aws/main.tf` (uncommitted). No `ArtifactStore` Rust trait or S3 client dependency exists in the workspace. |

## Contracts/types implemented vs missing capabilities

**Implemented (contract/type layer):**

- `SecurityFinding`, `ScannerStatus`, `FindingSeverity`, `ScannerFailure`, `FailureType` — `crates/mail-contracts/src/finding.rs`.
- `Scanner`, `ScannerFactory`, `ScannerId`, `ScanRequest`, `ScanResult`, `ScannerCapabilities`, `ScannerHealth` — `crates/scanner-sdk/src/trait_defs.rs`, `types.rs` (re-exports `FindingSeverity`/`ScannerStatus` from mail-contracts).
- `Disposition::{Allow, Quarantine, Reject, Hold, Defer}`, `QuarantineState` — `crates/mail-contracts/src/transaction.rs`.
- Audit actions/quarantine/release, `MessageQuarantined` events, quarantine-release rate-limit config — `crates/mail-contracts/src/audit.rs`, `event.rs`, `rate_limit.rs`.
- RLS `FORCE` on tenant/audit/artifact/domain/policy/config/outbox tables; append-only `audit_events` trigger `prevent_audit_mutation` — `migrations/002_contract_isolation_hardening.sql`.
- `TenantContext`/`ImpersonationContext` with reason/effective-actor rules — `crates/policy/src/tenant_context.rs`.
- Trace router with workload bearer auth (constant-time compare, loopback defense) — `crates/mail-core/src/trace.rs` (`trace_router`, `require_workload_auth`).
- Browser session boundary (HttpOnly cookie model, no browser token storage) — `frontend/src/auth/session.ts`, `frontend/src/api/client.ts` (CSRF + idempotency headers), route guards `requireAuth` in `frontend/src/lib/router.tsx`.

**Missing end-to-end capabilities (blockers, exact locations):**

1. **Scanner orchestration** — no bounded parallel executor, deadlines, REQUIRED/OPTIONAL classification, or finding aggregation into policy. Expected home: `crates/mail-core/src/pipeline.rs` / after-queue path (`crates/mail-core/src/handoff.rs`); nothing present.
2. **Scanner implementations** — `scanners/` contains only `README.md`. Zero `Scanner` trait implementors; `crates/scanner-sdk` has no `impl Scanner` outside tests.
3. **Quarantine persistence and release** — no migration table; no release API; no trusted reinjection-for-release flow (existing `crates/mail-core/src/reinjection.rs` covers delivery reinjection only, with loop validation `validate_reinjection`).
4. **Findings persistence** — `SecurityFinding` is never written to the database; no findings column/table in `migrations/`.
5. **Resource-limit/security tests** — none of the Phase 2 test list (bombs, nested archives, encrypted files, mislabeled MIME, scanner unavailable, artifact bypass, cross-tenant quarantine, release loops) exists.
6. **Quarantine/findings UI** — `frontend/src/pages/Quarantine.tsx` renders a heading only; `Dashboard.tsx` shows hardcoded metrics (`1,234`, `12`, `98.5%`); `Layout.tsx` shows static "Authenticated session".
7. **ArtifactStore runtime** — contract enum only; no retrieval/permission path to test.
8. **Phase 3 identity** — `session.ts` calls `/auth/session`, `/api/v1/auth/login`, `/auth/logout`; no backend routes exist (`trace_router` is the only router; its search handler `handle_trace_search` returns empty results with a "Phase 1: placeholder" comment at `crates/mail-core/src/trace.rs:335`).
9. **Phase 3 RBAC/audit UI/operations UI** — no users/sessions/roles tables in `migrations/`; no audit export; no runtime operations UI. Customer lifecycle values (`active`/`suspended`/`deprovisioned` in `migrations/001_phase0_foundation.sql`) do not match Phase 3's `ACTIVE/GRACE/SUSPENDED/TERMINATED`; no `INTERNAL`/`SEND_ONLY` domain types.
10. **RLS integration proof** — four tests in `crates/policy/tests/security_isolation.rs` are `#[ignore = "requires PostgreSQL with RLS policies enabled"]` with `todo!()` bodies.
11. **Control Backend** — workspace members (`Cargo.toml`): `mail-contracts`, `mail-core`, `policy`, `scanner-sdk`, `observability`. No control-plane service crate.

## Stale or disproven claims in the prior full-phase review

Claims in `docs/reviews/2026-09-22-full-phase-review.md` that current evidence contradicts (all were filed as open; remediation commit `377d592` and working-tree changes have since landed):

| Prior claim | Current evidence |
|---|---|
| C1: invalid Rspamd `symbols [...]` block | **Disproven.** `infrastructure/rspamd/rspamd.conf` contains no `symbols` block; uses `group`/`include` structure. (Service load not executed in this task.) |
| C2: CI Actions use floating tags | **Disproven.** `.github/workflows/ci.yml` pins full commit SHAs (e.g. `actions/checkout@11d5960a…`). |
| C3: RDS has no password configuration | **Disproven.** `infrastructure/aws/main.tf` has `random_password.rds_master`, Secrets Manager secret/version, and wired `password`. (Uncommitted.) |
| C4: no frontend auth route guards | **Disproven.** `requireAuth` `beforeLoad` guards routes in `frontend/src/lib/router.tsx`. |
| H1: missing WAF/ALB/SQS/KMS | **Mostly disproven.** `aws_wafv2_web_acl`, `aws_lb`, `aws_sqs_queue` (+DLQ), `aws_kms_key` all present. **Route53 still absent.** |
| H2: S3 uses SSE-S3 | **Disproven.** `sse_algorithm = "aws:kms"` with `aws_kms_key.artifacts`. |
| H3/H4/H5: sourcemaps on, no CSP, manual sanitization | **Disproven.** `sourcemap: false`; CSP meta in `frontend/index.html`; DOMPurify in `frontend/src/security/content.ts`. |
| H7 (partial): `FindingSeverity`/`ScannerStatus` duplication | **Partially disproven.** scanner-sdk re-exports canonical types. **Still true:** `FeatureId`/`FeatureValue` are separately (and differently) defined in `crates/mail-contracts/src/policy.rs` and `crates/policy/src/feature_evaluator.rs`. |
| H9: `MilterObservation` vs `MilterObservations` confusion | **Partially addressed.** Documented as per-source vs aggregated in `pipeline.rs:95-97`; both types remain. |
| H10: scanner-sdk has zero tests | **Disproven.** 8 serde roundtrip tests in `crates/scanner-sdk/src/types.rs`; executed successfully in this task. |
| M4/M5/M7/M10/M15/M16/M17/M18 | **Disproven/stale.** DMARC detail uses `format!` (not `{:?}`); `reqwest::Client` is a `LazyLock` static; `evaluator.rs` no longer exists; migration `003` adds idempotency cleanup; Vite `host: true` removed; `user_data` uses `templatefile`; VPC flow logs exist; `docker/Dockerfile.*` exist (untracked). |
| M12/M13/M14/M1/M2/M3/M6/M8/M9/M11 | **Still valid.** Placeholder pages with mock data; zero frontend test files; static Layout user; `HashAlgorithm::Md5` retained (now documented legacy-only); `trust_forwarded_ip` unused outside `rate_limit.rs`; `FeatureValue::Typed(String)` unvalidated; `classify_smtp_response` maps 1xx/3xx to `TransientFailure` via `_` arm (`delivery.rs`); `smtpd_tls_security_level = may`; RBL lines commented in `main.cf`; no DOWN migrations. |
| "Tests: 96 passed, 4 ignored" | **Stale.** Re-run in this task (see below): **104 passed, 4 ignored** for `cargo test --workspace`. Frontend still has **0 test files** (`pnpm test` exits 0 via `--passWithNoTests`). |
| "Phase 2: 5% — SDK contract only" | **Still accurate in substance:** scanner-sdk contract + tests only; no orchestration, scanners, quarantine runtime, or UI. |

## Ordered next actions with verification criteria

1. **Scanner orchestration in Mail Core** — implement bounded parallel scan execution with deadlines, REQUIRED vs OPTIONAL classification, and normalized finding aggregation into `PolicyEvaluationRequest.findings`. *Verify:* integration tests show concurrency ceiling respected, timeout/failure yields `ScannerStatus::Error`/`Unknown` (never `Clean`), and `cargo test --workspace` passes.
2. **First scanner implementations** — ClamAV, URL/domain, file-type, archive behind `scanner-sdk::trait_defs::Scanner` in `scanners/`. *Verify:* trait impls compile into the workspace; resource-limit tests (bomb, nested archive, encrypted, malformed) produce explicit unscannable/UNKNOWN evidence; parser panic does not kill Mail Core.
3. **Quarantine persistence and release path** — migration for quarantine records (raw MIME/artifact reference, tenant message ID, findings, policy reason, retention, release history); authenticated/authorized/audited release with idempotency and trusted reinjection. *Verify:* cross-tenant quarantine access denied; release writes audit + outbox atomically; release/reinjection loop test fails closed.
4. **Quarantine/findings UI** — list/search/filter, severity/category, findings summaries, release action, audit linkage; remove free-form `scanner` engine strings from customer-facing payloads. *Verify:* `pnpm lint && pnpm typecheck && pnpm test` with real test files present; no engine names in UI/API responses.
5. **Close still-open prior-review items** — canonical `FeatureId`/`FeatureValue` (single definition, re-export); typed IDs in `ScanRequest`; validate `FeatureValue::Typed`; remove/dead-code `trust_forwarded_ip`; fix 1xx/3xx delivery classification; record TLS (`may`) and RBL decisions; Route53 in IaC; secret scanning/SAST in CI; frontend test suite. *Verify:* each item has a passing lint/test or a documented decision in the owning doc.
6. **Identity platform decision (Phase 3 prerequisite)** — complete ZITADEL security/license validation or reject it. *Verify:* decision recorded in `docs/15-AWS-DEPLOYMENT.md` (or ADR) before any identity integration code.
7. **Prove RLS against real PostgreSQL** — implement the four `todo!()` tests in `crates/policy/tests/security_isolation.rs`. *Verify:* `cargo test -p nullapart-policy -- --ignored` passes with `docker compose up postgres` (or equivalent).
8. **Phase 1 live-pipeline stability evidence (Phase 3 prerequisite)** — run the uncommitted `docker-compose.yml` stack end-to-end. *Verify:* Postfix → Rspamd → Mail Core handoff → reinjection observed with no mail loss; results recorded in a follow-up review. Not claimed here — not executed in this task.

## Verification performed in this task

- `cargo test --workspace`: **104 passed, 0 failed, 4 ignored** (the 4 ignored are the RLS/PostgreSQL tests noted above).
- `pnpm test` (frontend): **0 test files found**, exit 0 (`vitest run --passWithNoTests`). The local runner emitted an engine warning because it used Node 22.22.3 while `frontend/package.json` requires Node >=24; this does not demonstrate the supported frontend runtime.
- No deployment, Terraform apply, Docker image build, or CI run was executed; no such claim is made.

---

## Addendum (2026-09-22, later): Scanner Fabric landed — personally-run evidence

**Scope of this addendum:** records only results of commands run in the implementing session that followed the review above. It supersedes the "104 passed" and "H10: 8 serde tests" counts where they conflict; it does not rewrite the original assessment of quarantine, UI, scanners, or identity.

### What was implemented

- **Bounded concurrent Scanner Fabric** at `crates/scanner-sdk/src/fabric.rs` (reusable SDK home, *not* `crates/mail-core/src/pipeline.rs` as the review's expected home suggested — Mail Core pipeline wiring remains open). Global semaphore (`max_parallel_scanners`) + per-scanner semaphore (`profile.max_concurrency`) + per-scan `min(wall_clock, overall_deadline)` timeout + JoinSet with task-ID failure attribution; deterministic status/disposition ladders; synthesized finding for every inconclusive outcome; no-silent-CLEAN enforced by tests.
- **Contracts:** `IndicatorType::{Certificate, Header, Raw}` added in `crates/mail-contracts/src/finding.rs`; `Scanner::scan` now returns `Result<ScanResult, ScanError>`; `ScanRequest` uses typed IDs (`TransactionId`, `TenantMessageId`, etc.) — resolving the review's "typed IDs in `ScanRequest`" open item (next-action 5).
- **Tests:** `crates/scanner-sdk/tests/fabric.rs` — deterministic test adapters (Barrier-gated wave tracker, `tokio::time::pause()` for timeouts) covering concurrency ceiling, per-scanner cap, required/optional failure, timeout, deterministic aggregation, panic containment, oversize/inapplicable fail-safe, empty-fabric fail-safe, unsafe-config rejection.

### Commands personally run (this session)

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | Clean (no diffs) |
| `cargo clippy --workspace --all-targets` | 0 warnings, 0 errors |
| `cargo test -p nullapart-scanner-sdk` | **24 passed, 0 failed** (9 unit + 15 integration) |
| `cargo test --workspace` | **120 passed, 0 failed, 4 ignored** (ignored = the 4 RLS/PostgreSQL tests above) |

### Effect on the exit-gate table (only where evidence changed)

| Exit criterion | Prior | Now |
|---|---|---|
| Scanner orchestration parallel/bounded | Fail | **Partial** — proven at SDK-library level (ceiling, caps, deadlines tested); not yet invoked from Mail Core's after-queue path. |
| Required failure semantics enforced | Fail (contracts only) | **Partial** — UNKNOWN/ERROR/timeout/oversize/panic all produce explicit non-CLEAN evidence in fabric tests; no live scanner in the pipeline yet. |
| Parser failure cannot take down Mail Core | Not demonstrated | **Partial** — scanner-task panics contained by JoinSet isolation in fabric tests; no parsers exist yet to crash. |
| Resource-exhaustion tests pass | Fail | Still **Fail** for bombs/nested/encrypted archives; oversize input now has an explicit-unscannable test. |

The disposition remains **Phase 2 exit gate: NOT MET** (quarantine persistence/release, scanner implementations, findings persistence, UI, and live-pipeline wiring are untouched) and **Phase 3: NOT READY**.

### What remains

1. Wire `ScannerFabric` into `crates/mail-core`'s after-queue path and aggregate into `PolicyEvaluationRequest.findings`.
2. Scanner implementations in `scanners/` (still README-only).
3. Quarantine migration + release API/audit path; findings persistence.
4. Quarantine/findings UI; resource-limit tests (bomb, nested, encrypted); frontend tests.
5. The remaining still-open items from next-actions 5–8 above (FeatureId canonicalization, FeatureValue validation, identity decision, RLS proof, live-pipeline evidence).

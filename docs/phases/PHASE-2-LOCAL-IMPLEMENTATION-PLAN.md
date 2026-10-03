# Phase 2 Local Implementation Plan — Scanner Fabric and Quarantine

**Status:** active implementation goal. This plan is the delivery checklist for
the Phase 2 exit criteria; checked work is evidence-backed, not inferred from
the presence of a module.

## Goal and boundaries

Deliver the complete post-queue security path locally:

```text
accepted MIME -> immutable artifact -> bounded parallel scanners
-> normalized findings + required-failure hold -> tenant policy
-> persisted quarantine/hold -> authorized release -> trusted reinjection
```

The Phase 2 Control Plane work is limited to the quarantine and scanner
operations slice required by the phase. It must use authenticated server-side
tenant context and does not replace the wider Phase 3 Control Plane programme.

Production S3/KMS infrastructure cannot be represented by the local
filesystem backend. The local backend is deliberately non-production and
must be rejected by a production runtime; the S3/KMS adapter, scoped IAM, and
regional deployment evidence remain production-environment delivery work.

## Work order

1. **Contracts and durable model**
   - [x] Define bounded scanner profiles, requirements, and normalized result
         mapping.
   - [x] Add a local-only immutable filesystem artifact boundary with a
         scanner-only reader.
   - [x] Add durable quarantine schema, RLS, release idempotency, audit, and
         outbox transaction.
   - [x] Persist artifact metadata, scan results, and quarantine creation as
         one mail-processing workflow.

2. **Security execution pipeline**
   - [x] Execute independent scanners concurrently with a bounded semaphore
         and per-scanner deadline.
   - [x] Require every scanner registration to declare a bounded expanded-byte,
         recursion, entry, CPU, memory, temporary-disk, OCR, and redirect
         resource profile.
   - [x] Make required timeout/resource/error outcomes hold the message.
   - [x] Implement the local file-type/MIME safety adapter.
   - [x] Add isolated adapters and resource profiles for malware, URL,
         archive, PDF, Office, static-rule, image, OCR, and QR analysis.
   - [x] Wire policy disposition and durable quarantine/hold creation to the
         scan aggregate.

3. **Authorized operations**
   - [x] Require active tenant, permission, step-up authentication, matching
         deployment/customer, idempotency, audit, and outbox for release.
   - [x] Establish request-scoped RLS context in the authenticated backend,
         provide scoped list/detail/result APIs, and dispatch release to the
         trusted reinjection boundary without a release loop.

4. **Operator UI**
   - [x] Replace the placeholder with a typed quarantine list/detail/filter,
         safe finding summaries, retention/audit state, and an authorized
         release flow.
   - [x] Add the scanner/node operations view without exposing engine details
         to customer users or raw content to support users.

5. **Local end-to-end proof and hardening**
   - [x] Run a real Postfix after-queue message through artifact storage,
         scan, policy, quarantine, authorized release, and reinjection.
   - [x] Test cross-tenant artifact/case bypass, duplicate releases, release
         loops, malformed MIME, active SVG/HTML, scanner unavailable/timeout,
         archive limits, and parser isolation.
   - [x] Run canonical format, lint, typecheck, workspace tests, compose and
         Postfix validation; fix phase-scoped defects found by that pass.

## Completion gate

Phase 2 is complete only when every unchecked item is implemented and the
end-to-end path has current local test evidence. A passing unit test alone is
not a completion claim.

## Evidence (2026-10-01 local stack on 192.168.8.4)

- **Gates**: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, and
  `pnpm check-all` all pass on the current worktree. The local frontend gate
  warns that the Mac runner is Node 22 while the project engine is Node 24+,
  but Docker uses the Node 24 image and the check itself passes: 14 Vitest
  files / 82 tests.
- **Remote build/deployment**: current sources are synced to
  `ob1@192.168.8.4:/home/ob1/Nullapart`. The frontend Docker build now copies
  `frontend/.npmrc` before `pnpm install --frozen-lockfile`, allowing
  `onlyBuiltDependencies[]=esbuild` / `allowBuilds.esbuild=true` to be honored;
  the slow-link PNPM retry/concurrency settings are project-local.
  `docker compose --env-file .env.local -f compose.local.yml build mailcore
  frontend` passed on the remote host; Postfix was rebuilt/reloaded with the
  Phase 2 null-sender wrapper fix.
- **Remote runtime posture**: `docker compose ... config -q` and `postfix check`
  are clean. `mailcore`, `postfix`, `frontend`, `postgres`, and `clamav` are up
  on `192.168.8.4`; `mailcore` is bound to `192.168.8.4:58081`, frontend to
  `192.168.8.4:53080`, and SMTP to `192.168.8.4:2525`. The application role is
  `nullapart_mailcore|false|false` (non-superuser, no BYPASSRLS). For Phase 2
  verification the remote stack is in `NULLAPART_IDENTITY_PROVIDER=proxy_header`;
  OIDC remains Phase 3.
- **Authenticated API proof**: through the local frontend proxy,
  `POST /api/v1/auth/login` returns `200` with the server-managed
  `nullapart_session` cookie and CSRF token; `GET /api/v1/auth/session` returns
  `200`; `GET /api/v1/quarantine` returns `200`; unauthenticated quarantine
  access returns `401`.
- **Live end-to-end proof after the null-sender fix**:
  - A clean message and an EICAR message submitted over SMTP
    (`192.168.8.4:2525`, HELO address literal, null reverse-path) were both
    accepted and handed to the after-queue `mailcore` filter.
  - The EICAR message was persisted, scanned by the four registered
    capabilities, projected one safe finding, and held as quarantine case
    `9234d5ff-fcf2-5392-89be-b9fb0f0ff778` with reason
    `QUARANTINE_MALWARE`. `GET /api/v1/quarantine/{id}` returned `200` with
    findings=1, scanner_results=4, `release_allowed=true`, and no raw content.
  - `POST .../release` without `X-Idempotency-Key` returned `400`; release
    with `X-CSRF-Token` and `X-Idempotency-Key` returned `200`; the identical
    repeat returned `200` with the same release timestamp.
  - The trusted reinjection path succeeded: the reinjection envelope now stores
    the SMTP null reverse-path canonically as `<>` (length 2), not the literal
    quoted Postfix pipe token `"<>"`; `reinjection_deliveries` recorded
    `succeeded|A483A6238EA|true`, the outbox event was published, and
    `reinjection_dead_letters` for that case remained `0`.
- **Defects fixed by the pass**:
  - Docker frontend install was not reliably seeing the esbuild allowlist during
    `pnpm install --frozen-lockfile`; `.npmrc` is now copied before install and
    project PNPM settings are tuned for the slow remote link.
  - Phase 3 policy-admin code that had already landed in the tree blocked
    Phase 2 workspace gates with Clippy failures; those large-error iterator
    collects and test cleanup issues were fixed without changing Phase 2
    behavior.
  - Live reinjection still failed after release because Postfix pipe expansion
    passed the null sender as the literal quoted token `"<>"`, which the
    reinjection worker correctly rejected as an invalid envelope. The trusted
    Postfix/filter boundary now normalizes only that exact token to canonical
    SMTP null reverse-path `<>`; arbitrary quoted sender strings remain invalid.
- **Known limitations of this local proof**: the local filesystem artifact
  backend is deliberately rejected for production runtimes; full production
  S3/KMS/IAM proof remains outside Phase 2 local scope.

## Review addendum (2026-10-03 local stack on 192.168.8.4)

- **Phase 2 review defect found and fixed**: after Phase 4 inline-ML work was
  enabled locally, the Phase 2 quarantine API still projected raw
  `security_findings.description` values. Live quarantine list responses could
  therefore expose model/scanner internals such as score and threshold text.
  The API projection now preserves category/severity and emits a normalized
  customer-safe finding summary instead of returning persisted raw diagnostic
  prose. The storage record remains intact for internal evidence paths.
- **Commit**: `af2ff70 Sanitize quarantine finding projections`.
- **Verification after the fix**:
  - `cargo fmt --all -- --check` passed.
  - `cargo clippy -p nullapart-mail-core --lib -- -D warnings` passed.
  - `cargo test -p nullapart-mail-core --lib
    finding_projection_does_not_expose_engine_or_model_details` passed after
    freeing rebuildable Rust target artifacts from the full local disk.
  - Phase 2 PostgreSQL suites over an SSH tunnel to the
    `192.168.8.4` database passed: quarantine release, quarantine detail,
    invalid reinjection event dead-lettering, scanner-pipeline atomic
    persist/rollback checks, and RLS isolation.
  - `docker compose --env-file .env.local -f compose.local.yml build mailcore`
    and `up -d --no-deps --force-recreate mailcore` passed on
    `ob1@192.168.8.4`.
- **Fresh live end-to-end proof**: an EICAR message submitted to
  `192.168.8.4:2525` with SMTP null reverse-path was accepted, scanned,
  quarantined as case `a75b5363-4a07-597d-9e7d-1f902240a3ec` with
  `QUARANTINE_MALWARE`, projected through
  `GET /api/v1/quarantine/{id}` with `leaks=[]` for model/scanner terms, then
  released through the authenticated API. Reinjection succeeded with Postfix
  queue id `43C7662246A`, the outbox event was published, and
  `reinjection_dead_letters` remained `0`.

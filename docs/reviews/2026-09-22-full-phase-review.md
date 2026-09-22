# Nullapart Full Phase 0/1/2 End-to-End Review

**Date:** 2026-09-22 12:00 SAST
**Reviewer:** 3 parallel code-reviewer agents + consolidation
**Branch:** `fix/security-foundation-hardening` (commit `020e552`)
**Scope:** All phases (Phase -1 through Phase 2), all crates, all infra, all frontend, all CI

---

## Executive Summary

The security foundations are strong: fail-closed defaults, constant-time comparison, HMAC canonical binding, RLS with FORCE, append-only audit. The gaps are operational — no live pipeline, broken Rspamd config, type duplication across crates, no frontend tests, no AWS deployment. ~60% of Phase 0 and ~55% of Phase 1 are built. Phase 2 has only the scanner SDK contract.

**Total issues found:** 4 CRITICAL, 10 HIGH, 18 MEDIUM
**Tests:** 96 passed, 4 ignored (RLS pending PostgreSQL)
**Code:** ~5,500 lines Rust, ~500 lines TypeScript, ~700 lines Terraform/Postfix

---

## Phase Completion Status

| Phase | Scope | Status |
|-------|-------|--------|
| Phase -1 Security Gate | Security governance, docs, compliance | **95%** — branch protection is policy-only |
| Phase 0 Foundations | Workspace, contracts, DB, IaC, frontend shell | **60-65%** — no Control Backend code |
| Phase 1 Mail Pipeline | Postfix → Rspamd → Mail Core → reinjection | **55-60%** — no live pipeline |
| Phase 2 Scanner Fabric | ClamAV, URL, archive, quarantine | **5%** — SDK contract only |

---

## Issues Found

### CRITICAL (4)

| # | File | Issue | Status |
|---|------|-------|--------|
| C1 | `infrastructure/rspamd/rspamd.conf` | Invalid Rspamd syntax — `symbols [...]` block doesn't exist. Service will fail to load. | TODO |
| C2 | `.github/workflows/ci.yml` | Third-party Actions use floating tags (`@v4`, `@stable`) — contradicts AGENTS.md SHA pinning requirement. | TODO |
| C3 | `infrastructure/aws/main.tf` | RDS has no password configuration — deployment will fail. | TODO |
| C4 | `frontend/src/lib/router.tsx` | No authentication route guards — all pages accessible without session check. | TODO |

### HIGH (10)

| # | File | Issue | Status |
|---|------|-------|--------|
| H1 | `infrastructure/aws/main.tf` | Missing WAF/ALB, Route53, SQS, KMS resources. | TODO |
| H2 | `infrastructure/aws/main.tf` | S3 uses SSE-S3 instead of SSE-KMS. | TODO |
| H3 | `frontend/vite.config.ts` | Production sourcemaps enabled. | TODO |
| H4 | `frontend/index.html` | No Content-Security-Policy. | TODO |
| H5 | `frontend/src/security/content.ts` | Manual HTML sanitization instead of battle-tested library. | TODO |
| H6 | `.github/workflows/ci.yml` | No secret scanning, SAST, SCA, license check, IaC scanning. | TODO |
| H7 | Multiple crates | Type duplication: `FeatureId`, `FeatureValue`, `ScannerStatus`, `FindingSeverity`. | TODO |
| H8 | `crates/scanner-sdk/src/types.rs` | `ScanRequest` uses `String` instead of typed IDs. | TODO |
| H9 | `crates/mail-core/src/pipeline.rs` | `MilterObservation` vs `MilterObservations` — confusing duplication. | TODO |
| H10 | `crates/scanner-sdk/` | Zero tests. | TODO |

### MEDIUM (18)

| # | File | Issue | Status |
|---|------|-------|--------|
| M1 | `crates/mail-contracts/src/finding.rs` | `HashAlgorithm::Md5` in security project. | TODO |
| M2 | `crates/mail-contracts/src/rate_limit.rs` | `trust_forwarded_ip` dead config. | TODO |
| M3 | `crates/policy/src/feature_evaluator.rs` | `FeatureValue::Typed(String)` unvalidated. | TODO |
| M4 | `crates/mail-core/src/auth.rs` | `DmarcEvaluation` uses `{:?}` debug format. | TODO |
| M5 | `crates/mail-core/src/bin/mailcore-filter.rs` | `reqwest::Client::new()` per invocation. | TODO |
| M6 | `crates/mail-core/src/delivery.rs` | 1xx codes classified as `TransientFailure`. | TODO |
| M7 | `crates/policy/src/evaluator.rs` | Empty file (3 lines doc comment). | TODO |
| M8 | `infrastructure/postfix/main.cf` | Opportunistic TLS (`may` not `encrypt`). | TODO |
| M9 | `infrastructure/postfix/main.cf` | RBL/DNSBL checks commented out. | TODO |
| M10 | `migrations/001_phase0_foundation.sql` | No idempotency_keys cleanup mechanism. | TODO |
| M11 | `migrations/` | No DOWN migrations. | TODO |
| M12 | `frontend/src/pages/` | All pages placeholder/empty — no API integration. | TODO |
| M13 | `frontend/` | Zero test files. | TODO |
| M14 | `frontend/src/components/Layout.tsx` | Static "Authenticated session" — no user data. | TODO |
| M15 | `frontend/vite.config.ts` | `host: true` binds to `0.0.0.0`. | TODO |
| M16 | `infrastructure/aws/main.tf` | `user_data` is placeholder comment. | TODO |
| M17 | `infrastructure/aws/main.tf` | No VPC flow logs. | TODO |
| M18 | Repository-wide | No Dockerfiles anywhere. | TODO |

---

## Remediation Plan

### Wave 1: Critical Fixes (blocking correctness)

1. **C1** — Fix Rspamd config syntax
2. **C2** — Pin CI Actions to commit SHAs
3. **C3** — Fix Terraform RDS password configuration
4. **C4** — Add frontend auth route guards

### Wave 2: High Security Fixes

5. **H3** — Disable production sourcemaps
6. **H4** — Add CSP meta tag to index.html
7. **H5** — Replace manual sanitization with DOMPurify
8. **H7** — Resolve type duplication (pick canonical, re-export)
9. **H8** — Use typed IDs in scanner-sdk
10. **H9** — Remove duplicate `MilterObservation` from pipeline.rs
11. **H10** — Add scanner-sdk serde roundtrip tests

### Wave 3: Infrastructure Hardening

12. **H1** — Add missing IaC resources (WAF/ALB, Route53, SQS, KMS)
13. **H2** — Switch S3 to SSE-KMS
14. **H6** — Add secret scanning + SAST/SCA to CI
15. **M8** — Document TLS level decision
16. **M16** — Add user_data bootstrap script
17. **M17** — Add VPC flow logs

### Wave 4: Code Quality

18. **M1** — Document Md5 as legacy-only
19. **M2** — Remove or implement `trust_forwarded_ip`
20. **M3** — Add validation for `FeatureValue::Typed`
21. **M4** — Fix debug format in DMARC detail string
22. **M5** — Add connection pooling to mailcore-filter
23. **M6** — Fix 1xx classification in delivery.rs
24. **M7** — Remove empty evaluator.rs or add redirect
25. **M10** — Add idempotency_keys cleanup to migration
26. **M11** — Document rollback strategy (even without DOWN SQL)

### Wave 5: Frontend Polish

27. **M12** — Wire Dashboard to API (or remove placeholder data)
28. **M13** — Add API client + session unit tests
29. **M14** — Add user context to Layout + logout button
30. **M15** — Remove `host: true` from Vite config

### Deferred (not blocking)

- **M18** — Dockerfiles (Phase 3+)
- **M9** — RBL/DNSBL enablement (after selection)
- **M14** — Full page implementations (Phase 3)

---

## Security Strengths Confirmed

- Fail-closed policy defaults (Hold on no match)
- Constant-time HMAC and content hash comparison
- Canonical HMAC binding (version, timestamp, event_id, method, path, body hash)
- Loop prevention on reinjection
- Server loopback binding enforced at startup
- Body size limits (DefaultBodyLimit)
- Feature evaluation: kill switch → mandatory floor → deployment → tenant
- RLS with FORCE ROW LEVEL SECURITY on all 9 tables
- Append-only audit trigger
- Trace auth with constant-time + loopback defense-in-depth
- Idempotent transaction IDs (UUID v5)
- Open redirect prevention on return_to
- CI minimal permissions
- SBOM + provenance + vulnerability scanning
- Event safe payloads (no internal data leakage)

---

## Test Coverage

| Area | Tests | Gap |
|------|-------|-----|
| mail-contracts | 13 | audit/event/finding/error/artifact/transaction/policy untested |
| mail-core | 49 | pipeline.rs untested |
| policy | 17 | Good coverage |
| scanner-sdk | 0 | No tests at all |
| observability | 1 | Minimal |
| Frontend | 0 | No test files |
| RLS integration | 4 (ignored) | Pending PostgreSQL |
| **Total** | **96 passed, 4 ignored** | |

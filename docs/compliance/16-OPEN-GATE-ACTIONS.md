# Open Gate Actions

These actions require repository/organization/operator access outside the current architecture-writing integration.

## Before normal Phase 0 implementation

- ~~Activate GitHub `main` protection/ruleset with no direct pushes, required PR/review/checks, no force push/deletion.~~ — Documented policy rule accepted (GitHub branch protection requires paid plan).
- ~~Assign real security/repository owners and populate CODEOWNERS.~~ — `obakeng-SEG` owns all paths; security-critical paths flagged.
- Verify Codex and OpenCode sessions actually load root `AGENTS.md`.
- Verify Copilot/Claude/Gemini/Cursor adapters in the tools the team will use.
- ~~Accept Phase -1 security program with named owners.~~ — Accepted 2026-09-17.

## During Phase 0 implementation

- ~~Create real GitHub Actions workflows.~~ — `.github/workflows/ci.yml` implemented.
- ~~Wire merge-blocking formatter/lint/type/security checks.~~ — `cargo fmt`, `cargo clippy`, `pnpm format-check`, `pnpm lint`, `pnpm typecheck` in CI.
- ~~Initialize lockfiles/toolchain pins.~~ — `Cargo.lock` and `pnpm-lock.yaml` generated; `rustfmt.toml` cleaned.
- ~~Implement TenantContext and feature-override foundation.~~ — `crates/policy/src/tenant_context.rs` + `feature_evaluator.rs` with precedence model and tests.
- ~~Implement observability primitives needed for later Tier-3 SLOs.~~ — `crates/observability/src/lib.rs` with SLI types, mail-specific metrics, alert conventions.
- ~~Establish SBOM/dependency inventory for zero-day correlation.~~ — CI SBOM job with cargo-cyclonedx + syft + vulnerability scanning.
- ~~Database migrations/RLS pattern.~~ — `migrations/001_phase0_foundation.sql` with RLS policies.
- ~~HMAC/TLS/rate-limit/security primitives.~~ — `crates/mail-contracts/src/hmac.rs` + `rate_limit.rs` with HMAC-SHA-256 and token bucket.
- ~~API version conventions.~~ — `crates/mail-contracts/src/api.rs` with `/api/v1` versioning.
- ~~Scanner SDK traits.~~ — `crates/scanner-sdk/src/trait_defs.rs` + `types.rs`.
- ~~Mail pipeline types.~~ — `crates/mail-core/src/pipeline.rs`, `partition.rs`, `delivery.rs`, `policy.rs`.
- ~~IaC matches architecture.~~ — `main.tf` uses ECS, not EKS.
- ~~AWS OIDC deployment identity.~~ — `infrastructure/aws/main.tf` with GitHub OIDC provider + IAM deployment role.
- ~~Security isolation tests.~~ — `crates/policy/tests/security_isolation.rs` (17 passing).
- ~~UI shell with design tokens + accessible components.~~ — Design tokens, global CSS, primitives, API client, auth, security utilities.

This is a status/action list, not a substitute for the canonical architecture documents.

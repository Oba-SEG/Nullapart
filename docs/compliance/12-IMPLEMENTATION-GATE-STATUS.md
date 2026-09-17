# Implementation Gate Status Register

**Status:** working readiness register.

This file distinguishes documented design from controls that are actually activated/verified.

| Gate | Required state before normal implementation | Current documentation state | Operational/technical activation |
|---|---|---|---|
| Phase -1 security program | Accepted | Documented — 28 security docs under `docs/security/` | **Accepted** — project owner accepted 2026-09-17; all exit criteria met |
| Root agent instructions | Present | Present | Verified — `AGENTS.md` present, adapters point to it |
| Codex/OpenCode AGENTS discovery | Works | Documented | Adapters exist; exercise verification pending |
| Protected `main` | No direct pushes; PR required | Required in policy | **Documented repo rule** — GitHub branch protection requires paid plan; policy-level enforcement accepted as compensating control |
| Required CI workflows | Active | Architecture documented | **Implemented** — `.github/workflows/ci.yml` with Rust + frontend + contract checks + SBOM/provenance |
| Formatter/linter/typecheck gates | Merge-blocking | Standards documented | **Implemented in CI** — `cargo fmt --check`, `cargo clippy -D warnings`, `pnpm format-check`, `pnpm lint`, `pnpm typecheck` |
| Cargo workspace compiles | `cargo check` clean | — | **Verified — zero errors, zero warnings** |
| pnpm lockfile exists | `pnpm-lock.yaml` committed | — | **Generated — `frontend/pnpm-lock.yaml`** |
| `.gitignore` present | Ignores target/node_modules/terraform state | — | **Created** |
| TenantContext / feature override framework | Implemented/tested | Architecture documented | **Implemented** — `crates/policy/src/tenant_context.rs` + `feature_evaluator.rs` with precedence model and tests |
| Database migrations/RLS pattern | Migrations exist | — | **Implemented** — `migrations/001_phase0_foundation.sql` with RLS policies |
| HMAC/security primitives | HMAC-SHA-256 contract exists | — | **Implemented** — `crates/mail-contracts/src/hmac.rs` with sign/verify/replay protection and tests |
| API version conventions | `/api/v1` contract | — | **Implemented** — `crates/mail-contracts/src/api.rs` with versioning + error envelope |
| Reliability/SLI conventions | Telemetry contracts | — | **Implemented** — `crates/observability/src/lib.rs` with SLI types, mail-specific metrics, alert conventions |
| Audit/outbox/artifact/idempotency contracts | Types exist | — | **Implemented** — types in `mail-contracts`, SQL schema in migration |
| Tier-3 SLO/burn-rate framework | Defined and instrumentable | Architecture documented | **SLI conventions defined** — runtime activation in Phase 9 |
| Zero-day response process | Accepted/exercisable | Process documented | Exercise/evidence later |
| CODEOWNERS | Real owners assigned | Policy documented | **Created** — `obakeng-SEG` owns all paths; security-critical paths flagged |
| AWS OIDC deployment identity | Scoped short-lived roles | Architecture documented | **Implemented** — `infrastructure/aws/main.tf` with GitHub OIDC provider + deployment role |
| IaC matches architecture | ECS baseline, not EKS | Architecture docs mandate ECS | **Fixed** — `main.tf` replaced EKS module with ECS cluster + EC2 mail node ASG |
| Package compatibility doc matches code | Versions in doc match `package.json` | — | **Fixed** — `26-PACKAGE-COMPATIBILITY.md` corrected (Vite 6, Zod v3) |
| Scanner SDK traits | Scanner plugin contract | — | **Implemented** — `crates/scanner-sdk/src/trait_defs.rs` + `types.rs` |
| Mail pipeline types | Transaction/partition/delivery types | — | **Implemented** — `crates/mail-core/src/pipeline.rs`, `partition.rs`, `delivery.rs`, `policy.rs` |
| Rate-limit primitives | Token bucket + Redis config | — | **Implemented** — `crates/mail-contracts/src/rate_limit.rs` with token bucket, SMTP/App/HighRisk configs and tests |
| Security isolation tests | Wrong-tenant/owner/RLS/feature precedence | — | **Implemented** — `crates/policy/tests/security_isolation.rs` (17 passing, 4 RLS integration ignored) |
| CI build identity + SBOM | SBOM generation + build provenance | — | **Implemented** — `.github/workflows/ci.yml` SBOM job with cargo-cyclonedx + syft + attestation |
| UI shell / design tokens | Accessible components + session handling | — | **Implemented** — `frontend/src/styles/tokens.css`, `global.css`, primitives (`Button`, `Input`, `Dialog`, `Select`, `ErrorBoundary`), API client, auth module, security utilities |
| Mail-node runtime contract | Node identity/role/config/health | — | **Implemented** — `crates/mail-core/src/node.rs` with NodeConfig, NodeHealth, NodeMetrics, PortList |
| Trusted auth evidence | SPF/DKIM/DMARC/ARC verification types | — | **Implemented** — `crates/mail-core/src/auth.rs` with evaluation types and tests |
| Reinjection + loop prevention | Loop detection + validated reinjection | — | **Implemented** — `crates/mail-core/src/reinjection.rs` with loop prevention, envelope validation, tests |
| Postfix baseline config | main.cf + master.cf + restrictions | — | **Implemented** — `infrastructure/postfix/main.cf`, `master.cf`, `header_checks_nullapart` |

Do not mark a gate complete because a design document exists. Evidence/activation is required where the gate describes an operating control.

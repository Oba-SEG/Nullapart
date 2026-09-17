# Phase 0 — Contracts and Foundations

## Objective

Create the stable contracts, schemas, repository controls, build tooling, tenant-context primitives, testing foundations and UI/security/reliability primitives required so later phases do not invent incompatible models independently.

Phase 0 fixes the implementation foundations before feature depth.

## Prerequisites

- Phase -1 explicitly accepted.
- Architecture review complete enough to define contracts.
- No unresolved Critical design issue around tenancy, identity, mail responsibility or content access.
- Repository administrators available to activate protected `main`.

## Required reading

- `AGENTS.md`
- `docs/ai/AGENT-DISCOVERY.md`
- `docs/ai/CODING-AGENT-OPERATING-MODEL.md`
- `docs/engineering/CODE-STANDARDS.md`
- `docs/18-MESSAGE-TRANSACTION-CONTRACT.md`
- `docs/05-SCANNER-FABRIC.md`
- `docs/06-POLICY-MODEL.md`
- `docs/17-ADMIN-AUDIT-LOGGING.md`
- `docs/19-SECURE-MESSAGE-RENDERING.md`
- `docs/20-EVENT-DURABILITY.md`
- `docs/11-OBSERVABILITY-SECRETS.md`
- `docs/23-FRONTEND-ARCHITECTURE.md`
- `docs/26-PACKAGE-COMPATIBILITY.md`
- `docs/27-API-VERSIONING-FEATURE-FLAGS.md`
- `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`
- `docs/29-TENANT-FEATURE-ROUTING.md`
- `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`
- `docs/security/19-VERSION-CONTROL-CICD.md`
- `docs/security/20-APPLICATION-SECURITY-CONTROLS.md`
- `docs/security/25-CERTIFICATE-TRUST-PINNING.md`
- `docs/security/26-HMAC-SIGNING-WEBHOOKS.md`
- `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`

# Core contracts

## Mail

Rust types/contracts for:

- SMTP Transaction;
- immutable content record;
- Tenant Message Instance;
- recipient delivery attempt;
- trace/correlation identity;
- Postfix queue correlation.

## Security findings

- `SecurityFinding`;
- finding scope: transaction/content/tenant/recipient;
- scanner status/result;
- explicit failure/resource-limit state;
- normalized severity/confidence.

## Policy/configuration

- policy revision;
- effective-policy snapshot;
- hierarchy/scope;
- disposition;
- stable reason code;
- freshness/staleness;
- versioned feature/tenant override metadata.

## Artifact

- artifact ID;
- region/deployment/customer scope;
- content type/size/hash;
- storage reference;
- retention class;
- encryption/access metadata;
- scanner/AI eligibility.

Raw S3 locations are never product identity.

## Event

Every independently consumed event has:

- event ID/type/version;
- deployment/region/customer where applicable;
- trace/transaction/tenant-message IDs;
- idempotency key;
- data classification;
- safe payload/artifact reference.

## Audit

- real actor;
- impersonated subject;
- customer;
- permission/action/resource/result;
- safe before/after changes;
- source/session/trace;
- transactional semantics.

## API

Initial Control Plane namespace:

- `/api/v1/...`.

Implement stable structured errors, additive-compatible v1 rules, API schema/compatibility tests and explicit breaking-change migration/version rules.

## HMAC

Provide one reviewed HMAC-SHA-256 contract/helper for applicable Nullapart-signed webhook/event use supporting:

- versioned signature format;
- deterministic raw-body canonicalization;
- timestamp/event ID;
- key ID/rotation;
- constant-time verification;
- replay/idempotency integration.

Provider-specific verification remains in provider adapters.

# TenantContext and feature override foundation

Implement `docs/29-TENANT-FEATURE-ROUTING.md` before proliferating tenant endpoints.

Create a typed server-owned `TenantContext` containing at least:

- deployment/region;
- authenticated real actor;
- impersonation context;
- active authorized customer;
- internal tenant/customer key;
- effective roles/permissions;
- authentication/step-up state;
- configuration/feature revision;
- trace identity.

Rules:

- client-provided tenant/customer IDs cannot construct/authorize context;
- active tenant selection is validated against server-known permissions;
- tenant switch clears/isolate tenant-sensitive caches;
- background events/jobs carry explicit deployment/customer scope;
- caches include deployment/customer scope;
- RLS tenant state is transaction-scoped and pool-safe.

## Feature evaluator

Implement server-authoritative feature evaluation inside the versioned configuration system.

Precedence:

```text
System emergency/kill disable
  -> System mandatory security floor
  -> deployment override
  -> tenant override
  -> default
```

Override model supports `INHERIT`, `ENABLED`, `DISABLED` and typed values where needed.

Return internal effective-value explanation: value, winning scope, revision and higher-level suppression where applicable.

Feature enabled never equals actor authorized.

# Database foundation

Create initial migrations/schema boundaries for:

- customer/deployment identity;
- domains;
- transaction/tenant-message metadata;
- policy/config revisions;
- feature definition/override metadata;
- Admin Audit;
- outbox;
- artifact metadata;
- authoritative idempotency records where required;
- node/runtime identity.

Do not over-model future features.

## RLS

Establish tenant-scoped RLS patterns:

- normal request role does not bypass RLS;
- transaction-scoped tenant context;
- no tenant leakage through pooled connections;
- privileged migration/maintenance role separated;
- explicit reviewed cross-tenant platform query paths.

# Rust workspace foundation

Create:

- workspace;
- `mail-contracts`;
- `mail-core`;
- `policy`;
- `scanner-sdk`;
- typed error/reason-code conventions;
- serialization/versioning rules;
- shared HMAC/crypto utility boundary where appropriate.

Prefer compile-time domain types over generic JSON/maps.

# Application-security foundation

Implement reusable primitives from `docs/security/20-APPLICATION-SECURITY-CONTROLS.md`:

- authenticated principal/request context;
- action + resource ownership authorization helper;
- tenant-scoped query/repository conventions;
- server validation framework;
- DB constraints for invariants;
- idempotency storage/helper;
- safe API error envelope + correlation ID;
- CSRF/session middleware;
- security headers;
- SSRF-safe outbound HTTP policy/client;
- wrong-user/wrong-tenant/wrong-owner test helpers.

Browser authentication/refresh credentials never use Local Storage, Session Storage or other JavaScript-readable persistent storage.

# TLS / trust foundation

Implement:

- normal public PKI validation;
- HSTS/CAA/renewal/monitoring;
- no HPKP;
- no disabled verification;
- private workload mTLS/PKI where justified;
- no hardcoded leaf pin without reviewed rotation/recovery threat model.

# Control/backend foundation

Establish a modular-monolith Control Backend with:

- authentication adapter;
- `TenantContext` resolver;
- authorization service;
- feature evaluator;
- audit transaction helper;
- scoped DB access conventions;
- `/api/v1` routing/contract boundary;
- centralized safe error mapping;
- authoritative validation;
- idempotency/HMAC primitives;
- Sentry-compatible instrumentation.

No public customer API.

# Frontend foundation

Implement `docs/23-FRONTEND-ARCHITECTURE.md` baseline:

- React + TypeScript;
- Vite;
- TanStack Router/Query/Table;
- React Hook Form + Zod;
- Radix Primitives;
- Nullapart CSS-token/CSS-Module design system;
- pnpm lockfile;
- Vitest/Testing Library/Playwright;
- Sentry-compatible browser SDK -> regional SegLumberjack.

Build application shell with:

- login/deployment selection;
- active tenant selector/context;
- navigation;
- typography/spacing/elevation tokens;
- accessible tables/forms/modal/drawer primitives;
- status/severity components;
- permission-aware routing/components;
- feature disabled/unavailable states;
- loading/empty/error states.

Route guards/feature flags are UX only; server re-evaluates authorization/feature state.

No raw JSON UI.

# Code standards / package compatibility

Implement:

- `docs/engineering/CODE-STANDARDS.md`;
- `docs/26-PACKAGE-COMPATIBILITY.md`;
- `docs/security/23-PATCHING-DEPENDENCY-VERSIONS.md`.

Establish actual pinned tooling/configuration for languages introduced:

- `.editorconfig` / `.gitattributes`;
- Rustfmt/Clippy;
- ESLint/Prettier/TypeScript;
- Stylelint where used;
- Ruff/type checker if Python introduced;
- ShellCheck/shfmt;
- SQL/IaC format/validate tools.

Create one obvious repository validation interface such as `format`, `format-check`, `lint`, `typecheck`, `test`, `security-check`, `check-all`.

Establish exact lockfiles/toolchains, frozen CI installs, peer compatibility checks, compatibility manifest and automated reviewed dependency update PRs.

# Infrastructure/network foundation

Represent `docs/24-CONTAINER-LOADBALANCING-NETWORK.md` in IaC:

- ECS ordinary container baseline;
- dedicated mail-node exception;
- public ALB/WAF for HTTPS;
- direct MX/Postfix baseline for SMTP;
- deny-by-default Security Groups;
- explicit port registry;
- no public SSH/database/cache/secrets/AI.

# Rate limiting foundation

Create reusable limiter primitives:

- principal/customer/action keys;
- Redis/Valkey distributed counters where appropriate;
- safe outage/fallback behavior;
- standard 429/error model;
- test helpers.

Do not rely only on WAF/IP limits.

# Reliability instrumentation foundation

Phase 0 does not prove production Tier-3 SLOs, but it establishes the telemetry/contracts required later.

Implement conventions for:

- service/capability SLI metrics;
- success/failure event counting;
- latency histograms;
- queue/backlog/oldest-age metrics;
- dependency outcome tagging;
- deployment/release/config revision dimensions;
- safe tenant/customer dimensions only where cardinality/privacy is acceptable;
- alert/runbook metadata conventions.

Do not hardwire one vague global uptime metric.

Production Tier-3 SLO/burn-rate activation is Phase 9.

# Zero-day / inventory foundation

Phase 0 establishes enough inventory/provenance to answer "are we affected?":

- SBOM by release;
- exact package/base-image/action versions;
- image/artifact digests;
- release/deployment mapping;
- scanner/parser version telemetry;
- dependency update/zero-day emergency PR path;
- kill-switch capability for risky optional features as they are introduced.

Do not wait until an incident to discover deployed component versions.

# Test foundation

Every resource endpoint pattern supports:

- unauthenticated;
- unauthorized role;
- wrong tenant;
- wrong owner;
- valid owner;
- malformed/boundary input;
- safe errors;
- idempotent retry where applicable;
- RLS isolation where applicable.

Add foundation tests for:

- unauthorized tenant selection;
- spoofed client tenant header/body/query;
- tenant switch cache isolation;
- RLS pooled-connection leakage;
- feature precedence/System floor;
- expired tenant override;
- API v1 compatibility;
- HMAC verification/replay;
- frontend session/no-local-storage behavior;
- controlled OAST harness;
- MIME/contract fuzz placeholders.

# Version control and GitHub Actions — hard activation gate

Implement:

- `docs/security/19-VERSION-CONTROL-CICD.md`;
- `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`.

## Protected `main`

Before normal implementation PRs begin, an authorized GitHub repository/organization administrator must activate and verify:

- protected `main`;
- **no direct pushes**;
- no force pushes;
- no branch deletion;
- PR required;
- required review;
- required status checks;
- stale approval/conversation controls where supported;
- CODEOWNERS/security review once real owners are assigned.

There is **no documentation-only compensating-control fallback for direct pushes to `main`**.

If the repository cannot enforce this, normal implementation does not proceed until an enforceable mechanism is available.

The current ChatGPT GitHub integration cannot administer/verify these settings. Follow `docs/compliance/13-BRANCH-PROTECTION-ACTIVATION-RUNBOOK.md` and record evidence.

## Pull-request CI

Implement at minimum:

- format/lint/typecheck;
- compile/build;
- frozen/locked dependency installs;
- unit + relevant integration/security/UI tests;
- tenant/RLS/feature tests for affected paths;
- API compatibility;
- dependency/SCA;
- secret scan;
- SAST where selected;
- SBOM;
- license checks;
- migration validation;
- IaC/container scan where applicable;
- docs/link consistency.

Use minimal workflow permissions and SHA-pinned third-party Actions where practical.

Untrusted PRs receive no production secrets/roles.

## Main/release/deploy

Establish:

- immutable artifact/image creation once;
- Git SHA + semantic version metadata;
- SBOM/provenance;
- same-digest environment promotion;
- GitHub OIDC -> scoped AWS roles;
- separate dev/staging/prod/region environments;
- production human approval;
- migration approval/rollback metadata;
- no mutable `latest` production identity.

# Coding-agent foundation

Canonical instruction source:

- root `AGENTS.md`.

Operating/discovery docs:

- `docs/ai/CODING-AGENT-OPERATING-MODEL.md`;
- `docs/ai/AGENT-DISCOVERY.md`.

Adapters:

- `.github/copilot-instructions.md`;
- `CLAUDE.md`;
- `GEMINI.md`;
- `.cursor/rules/nullapart.mdc`.

Codex and OpenCode use root `AGENTS.md` directly.

Verify selected coding-agent environments actually load the canonical rules using `docs/compliance/14-AGENT-DISCOVERY-VERIFICATION.md`.

Agent prose is not enforcement; CI/review/branch protection remains authoritative.

# Observability foundation

Standard safe context fields include:

- region/deployment;
- node/runtime identity;
- release;
- trace ID;
- transaction/tenant-message/customer where appropriate and privacy/cardinality safe;
- config revision.

Configure scrubbing before SegLumberjack.

# AI-agent implementation rules

AI agents must use project contracts rather than parallel schemas.

They must not:

- invent tenant-routing/feature/HMAC/API schemes locally;
- create generic JSON in place of typed contracts;
- expose internal DB IDs as customer identity;
- introduce network services without architecture justification;
- bypass auth/audit/RLS because a path is internal;
- broaden agent/tool permissions for convenience;
- bypass protected `main`/required CI;
- weaken reliability/security instrumentation to make tests pass.

# Exit criteria

Phase 0 is complete only when:

- protected `main` with no direct pushes is active and verified;
- required PR/CI/review path operates;
- agent discovery adapters exist and selected agents (including Codex/OpenCode) have been verified;
- code formatter/linter/typecheck gates operate;
- core Rust contracts compile/test;
- database migrations/RLS pattern exists;
- typed `TenantContext` + authorized tenant selection foundation exists;
- server feature evaluator + tenant/deployment override precedence exists;
- API/event/scanner/config version conventions exist;
- audit/outbox/artifact/idempotency contracts exist;
- UI shell/design/accessibility/session baseline exists;
- package compatibility/lockfiles/update process active;
- HMAC/TLS/rate-limit/security primitives exist;
- immutable CI build identity + SBOM/provenance foundation exists;
- OIDC-based AWS deployment identity exists before cloud deployment;
- infrastructure firewall/port/container baseline represented in IaC;
- zero-day affected-version inventory can be derived from release/SBOM metadata;
- reliability/SLI telemetry conventions exist for later Tier-3 SLO activation;
- wrong-user/wrong-tenant/wrong-owner/RLS/feature precedence tests pass;
- documentation matches implementation.

# Must not be built yet

- full SMTP delivery pipeline;
- full scanner engine set;
- production Deep AI;
- mailbox connectors;
- customer-facing DMARC analytics.

Only foundations required by later phases belong here.

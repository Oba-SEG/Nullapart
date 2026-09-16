# Phase 0 — Contracts and Foundations

## Objective

Create the stable contracts, schemas, build tooling, testing foundations and UI/security primitives required so later implementation does not invent incompatible models independently.

Phase 0 minimizes rework by fixing interfaces before feature depth.

## Prerequisites

- Phase -1 accepted.
- Architecture review complete enough to define contracts.
- No unresolved Critical design issue around tenancy, identity, mail responsibility or content access.

## Required reading

- `AGENTS.md`
- `docs/18-MESSAGE-TRANSACTION-CONTRACT.md`
- `docs/05-SCANNER-FABRIC.md`
- `docs/06-POLICY-MODEL.md`
- `docs/17-ADMIN-AUDIT-LOGGING.md`
- `docs/19-SECURE-MESSAGE-RENDERING.md`
- `docs/20-EVENT-DURABILITY.md`
- `docs/12-UI-DESIGN-SYSTEM.md`
- `docs/11-OBSERVABILITY-SECRETS.md`
- `docs/23-FRONTEND-ARCHITECTURE.md`
- `docs/26-PACKAGE-COMPATIBILITY.md`
- `docs/27-API-VERSIONING-FEATURE-FLAGS.md`
- `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`
- `docs/security/25-CERTIFICATE-TRUST-PINNING.md`
- `docs/security/26-HMAC-SIGNING-WEBHOOKS.md`

## Core contracts to implement

### Mail contracts

Rust types/contracts for:

- SMTP Transaction;
- immutable content record;
- Tenant Message Instance;
- recipient delivery attempt;
- trace/correlation identity;
- Postfix queue correlation.

### Security contracts

- `SecurityFinding`;
- finding scope: transaction/content/tenant/recipient;
- scanner result/status;
- scanner failure reason/resource-limit state;
- normalized severity/confidence.

### Policy contracts

- policy revision;
- effective-policy snapshot;
- hierarchy/scope;
- disposition;
- stable reason code;
- configuration freshness/staleness state.

### Artifact contract

- artifact ID;
- region/deployment/customer scope;
- content type/size/hash;
- storage reference;
- retention class;
- encryption/access metadata;
- eligibility for scanner/AI access.

Never expose raw S3 location as product identity.

### Event contract

- event ID/type/version;
- region/deployment/customer;
- trace/transaction/tenant-message IDs;
- idempotency key;
- classification;
- safe payload/artifact reference.

All independently consumed events include schema/version identity.

### Audit contract

- actor;
- impersonated subject;
- customer;
- permission context;
- action/resource/result;
- before/after redacted changes;
- source/session/trace;
- transactional semantics.

### API compatibility contract

Implement the initial Control Plane API namespace and compatibility rules from `docs/27-API-VERSIONING-FEATURE-FLAGS.md`.

Baseline:

- `/api/v1/...` for normal Control Plane API resources;
- stable structured error codes;
- additive compatible changes within v1;
- explicit major-version/coordinated migration for breaking changes;
- API schema tests and compatibility notes.

### Feature-switch contract

Implement feature switches inside the existing versioned configuration architecture rather than a new feature-flag microservice.

Support metadata for:

- flag ID/class;
- System/deployment/customer scope;
- owner;
- default;
- security impact;
- expiry/removal target;
- audit;
- revision/distribution.

Feature flags are never authorization.

### HMAC contract

Provide one reviewed HMAC-SHA-256 helper/contract for future Nullapart-signed webhook/event use rather than allowing each integration to invent a signature format.

The helper must support:

- versioned signature format;
- raw-body based deterministic canonicalization;
- timestamp;
- event ID;
- key ID/rotation;
- constant-time verification;
- replay/idempotency integration.

Provider-specific webhook verification remains in provider adapters.

## Database foundation

Create initial migrations/schema boundaries for:

- customer/deployment identity;
- domains;
- transaction/tenant-message metadata;
- policy revisions;
- feature-switch/versioned configuration metadata;
- admin audit;
- outbox;
- artifact metadata;
- idempotency records where authoritative persistence is required;
- node/runtime identity.

Do not over-model future features.

## Rust workspace foundation

Create:

- workspace;
- `mail-contracts`;
- `mail-core`;
- `policy`;
- `scanner-sdk`;
- shared error/reason-code approach;
- serialization/versioning rules;
- shared cryptographic/HMAC utility boundary where appropriate.

Prefer compile-time types over loosely structured maps.

## Application-security foundation

Implement reusable primitives from `docs/security/20-APPLICATION-SECURITY-CONTROLS.md` before feature endpoints proliferate.

Required foundations:

- authenticated Principal/RequestContext carrying deployment, actor, impersonation and customer scope;
- centralized authorization API/helper that checks action + resource ownership, not role alone;
- tenant/customer query helpers that require explicit scoped context;
- PostgreSQL RLS policy pattern for tenant-scoped tables;
- transaction-scoped RLS context compatible with connection pooling;
- normal application DB role without `BYPASSRLS`;
- privileged migration/maintenance roles separated from request handling;
- request validation framework with typed server validators;
- database constraints for core invariants;
- idempotency-key/result storage abstraction for retry-sensitive actions;
- standard safe API error envelope with stable code + correlation ID;
- CSRF/session middleware;
- security headers;
- SSRF-safe outbound HTTP client/policy for future URL fetchers;
- test helpers for wrong-user/wrong-tenant/object-owner cases.

Browser authentication/session design must not store auth/refresh tokens in Local Storage, Session Storage or other JavaScript-readable persistent storage.

## TLS / trust foundation

Implement certificate trust according to `docs/security/25-CERTIFICATE-TRUST-PINNING.md`.

Requirements:

- normal PKI validation for public/browser HTTPS;
- HSTS/CAA/renewal/monitoring strategy;
- no HPKP;
- no disabled certificate verification;
- private mTLS/workload PKI patterns where justified;
- no leaf-certificate hardcoding without an approved pinning threat/rotation design.

## Control/backend foundation

Establish a modular-monolith control backend boundary with:

- authentication adapter interface;
- authorization middleware/service;
- audit transaction helper;
- database access conventions;
- versioned `/api/v1` routing/contract boundary;
- error model;
- Sentry-compatible instrumentation;
- no public customer API;
- safe centralized error mapping;
- ownership-scoped repository/query conventions;
- authoritative server-side validation;
- feature-switch evaluation helper;
- idempotency/HMAC primitives as applicable.

## Frontend implementation baseline

Implement the stack and security architecture in `docs/23-FRONTEND-ARCHITECTURE.md`.

Baseline:

- React + TypeScript;
- Vite;
- TanStack Router/Query/Table;
- React Hook Form + Zod;
- Radix Primitives;
- custom CSS-token/CSS-Module neumorphic design system;
- pnpm lockfile;
- Vitest/Testing Library/Playwright;
- Sentry-compatible browser SDK -> regional SegLumberjack.

Use Node.js LTS for CI/build.

No browser Local Storage/Session Storage authentication tokens.

Frontend feature switches affect UX only; security-sensitive capability decisions are re-evaluated by the backend.

## Package compatibility foundation

Implement `docs/26-PACKAGE-COMPATIBILITY.md`.

Phase 0 must establish:

- pinned Node.js/toolchain/package-manager versions;
- exact `pnpm-lock.yaml`;
- exact `Cargo.lock`;
- React/ReactDOM compatibility;
- Vite/Node compatibility;
- TypeScript/library compatibility;
- peer-dependency checks;
- frozen CI installs;
- compatibility manifest;
- grouped automated dependency upgrades;
- reproducible ML environment approach for later phases.

Do not bypass peer incompatibilities with force flags as the default solution.

## Infrastructure/container/network baseline

Establish the IaC foundation described in `docs/24-CONTAINER-LOADBALANCING-NETWORK.md`:

- ECS baseline for normal containers;
- dedicated mail-node exception;
- public ALB/WAF for HTTPS Control Plane;
- direct MX/Postfix baseline for SMTP;
- deny-by-default Security Groups;
- explicit port registry;
- no public SSH/databases/cache/secrets/AI.

## Rate limiting foundation

Create reusable application rate-limiter primitives with:

- principal/customer/action keys;
- Redis/Valkey distributed counters where appropriate;
- safe fallback/failure behavior;
- standard 429/error response;
- test helpers.

Do not rely only on WAF/IP limiting.

## Dependency/patching foundation

Implement version policy from `docs/security/23-PATCHING-DEPENDENCY-VERSIONS.md`:

- lockfiles;
- automated dependency update PR mechanism;
- base-image pinning;
- action/IaC pinning;
- SBOM/version inventory;
- EOL monitoring process.

## UI foundation

Build the actual application shell:

- login/deployment-selection design;
- navigation;
- typography/spacing/elevation tokens;
- tables/forms/modal/drawer primitives;
- status/severity components;
- permission-aware route/component pattern;
- feature-disabled/unavailable states;
- accessibility baseline;
- loading/empty/error states.

No raw JSON inspector/editor.

## Test foundation

### Application-security test baseline

Every resource endpoint test pattern must support:

- unauthenticated;
- unauthorized role;
- wrong tenant;
- wrong owner;
- valid owner;
- malformed/boundary input;
- safe error response;
- idempotent retry where applicable;
- RLS isolation where applicable.

Establish controlled OAST test capability for later features that perform server-side DNS/HTTP/network access. OAST test infrastructure must not use customer production data.

Create:

- Rust unit/integration structure;
- SMTP integration harness;
- PostgreSQL test strategy;
- Redis/Valkey test strategy;
- S3-compatible test storage;
- authorization/tenant-isolation fixtures;
- API v1 contract/compatibility tests;
- feature-switch server-authority tests;
- HMAC verification/replay tests;
- frontend component/E2E framework;
- security regression test location;
- fuzzing harness placeholders for MIME/contracts.

## Version-control and CI/CD foundation

Implement:

- `docs/security/19-VERSION-CONTROL-CICD.md`;
- `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`.

### Repository controls

Establish:

- protected `main`;
- pull-request-only normal changes;
- required checks;
- required reviews;
- force-push protection;
- CODEOWNERS once actual owners are known;
- PR template;
- release/tag naming;
- GitHub environment structure.

### Repository-control activation gate

Before normal implementation PRs begin, activate and verify the repository controls permitted by the GitHub plan/organization:

- protected `main`;
- no normal direct pushes;
- no force pushes;
- required PR review;
- required CI checks;
- security-owner/CODEOWNERS review once maintainers are assigned;
- protected release-tag/ruleset controls where available.

If the current GitHub plan cannot provide a desired control, record the limitation and implement the strongest available compensating process rather than silently assuming protection exists.

The current ChatGPT GitHub integration cannot administer these repository settings, so activation is an explicit human/organization administration task.

### Pull-request CI

At minimum:

- formatting/lint/typecheck;
- compile/build;
- locked/frozen dependency installation;
- unit tests;
- relevant integration/security/UI tests;
- API compatibility tests;
- dependency/SCA;
- secret scan;
- SAST where selected;
- SBOM generation/validation;
- license checks;
- migration validation;
- IaC scan when infrastructure exists;
- container build/scan when image definitions exist;
- documentation/link consistency.

Third-party Actions should be pinned to reviewed full commit SHAs where practical.

Workflow permissions must be explicit/minimal.

Untrusted PR workflows do not receive production secrets/roles.

### Main/release build

Establish:

- immutable artifact/image creation;
- Git SHA + semantic version metadata;
- registry publishing;
- SBOM/provenance association;
- artifact signing/attestation where selected;
- no production deployment by mutable `latest`.

### AWS deployment identity

Prepare GitHub Actions OIDC trust with scoped AWS roles.

Do not introduce long-lived AWS access keys for routine deployment.

Roles/environments must separate development/staging/production and deployment regions.

### Environment promotion

The pipeline promotes the same immutable digest from lower environments to production. Environment configuration/secrets remain external.

### Migration/release controls

Implement:

- immutable migration files after use;
- migration validation;
- production migration approval;
- release notes/changelog mechanism;
- rollback/containment metadata.

Detailed policy: `docs/security/19-VERSION-CONTROL-CICD.md`.
Version contract: `docs/22-VERSIONING-RELEASE-MANAGEMENT.md`.

## Coding-agent foundation

Repository coding agents follow:

- root `AGENTS.md`;
- `docs/ai/CODING-AGENT-OPERATING-MODEL.md`.

Phase 0 should keep project instructions compact and discoverable so agents do not need to ingest the whole repository for routine tasks.

Agents use the minimum relevant skill/context set and do not optimize away required security context.

## Observability foundation

Standard context fields:

- region;
- deployment;
- stable node ID;
- runtime identity/IP;
- release;
- trace ID;
- transaction/tenant-message/customer ID where appropriate.

Configure scrubbing before SegLumberjack ingestion.

## AI-agent instructions

AI agents must use the contracts rather than creating parallel schemas.

Do not:

- create a new ID type casually;
- replace structured contracts with generic JSON;
- expose internal database IDs to UI;
- introduce new network services without architecture justification;
- bypass auth/audit because the endpoint is "internal";
- invent an API/feature-flag/HMAC scheme locally;
- broaden context/tool permissions just to simplify an implementation task.

## Exit criteria

Phase 0 is complete when:

- core Rust contracts compile and are tested;
- database foundations/migrations exist;
- policy/event/audit/artifact contracts are versioned;
- API v1/event/scanner/config versioning conventions exist;
- server-authoritative feature-switch foundation exists;
- UI shell/design tokens exist and pass accessibility baseline;
- authorization/audit infrastructure patterns are established;
- repository protection has been activated/verified (or a documented compensating control exists for unavailable plan features);
- GitHub Actions PR/main/release/deploy architecture is implemented sufficiently for safe development;
- CI security gates run;
- immutable build/release identity is established;
- CI AWS access uses scoped OIDC roles rather than long-lived deployment keys;
- observability context/scrubbing exists;
- architecture docs and contracts match implementation;
- frontend stack/package manager/lockfile baseline exists;
- package compatibility manifest/gates exist;
- rate-limiter primitives and safe failure tests exist;
- HMAC helper/replay test foundation exists;
- TLS trust/pinning policy is represented in implementation/config;
- infrastructure port/firewall/container baseline is represented in IaC;
- dependency-update and patch/version inventory process is active;
- tenant-scoped database tables selected for RLS have policies and bypass tests;
- browser auth does not use Local Storage/Session Storage for credentials;
- standardized server validation/error/idempotency patterns are implemented;
- wrong-owner/wrong-tenant security test helpers pass;
- root coding-agent instructions/context discipline are in place.

## Must not be built yet

- full SMTP delivery pipeline;
- full scanner engine set;
- production Deep AI;
- mailbox connectors;
- customer-facing DMARC analytics.

Only foundation necessary for later phases belongs here.

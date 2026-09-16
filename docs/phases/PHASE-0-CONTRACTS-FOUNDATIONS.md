# Phase 0 — Contracts and Foundations

## Objective

Create the stable contracts, schemas, build tooling, testing foundations and UI/security primitives required so later implementation does not invent incompatible models independently.

Phase 0 minimizes rework by fixing interfaces before feature depth.

## Prerequisites

- Phase -1 accepted.
- Architecture review complete enough to define contracts.
- No unresolved Critical design issue around tenancy, identity, mail responsibility or content access.

## Required reading

- `docs/18-MESSAGE-TRANSACTION-CONTRACT.md`
- `docs/05-SCANNER-FABRIC.md`
- `docs/06-POLICY-MODEL.md`
- `docs/17-ADMIN-AUDIT-LOGGING.md`
- `docs/19-SECURE-MESSAGE-RENDERING.md`
- `docs/20-EVENT-DURABILITY.md`
- `docs/12-UI-DESIGN-SYSTEM.md`
- `docs/11-OBSERVABILITY-SECRETS.md`

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

### Audit contract

- actor;
- impersonated subject;
- customer;
- permission context;
- action/resource/result;
- before/after redacted changes;
- source/session/trace;
- transactional semantics.

## Database foundation

Create initial migrations/schema boundaries for:

- customer/deployment identity;
- domains;
- transaction/tenant-message metadata;
- policy revisions;
- admin audit;
- outbox;
- artifact metadata;
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
- serialization/versioning rules.

Prefer compile-time types over loosely structured maps.

## Control/backend foundation

Establish a modular-monolith control backend boundary with:

- authentication adapter interface;
- authorization middleware/service;
- audit transaction helper;
- database access conventions;
- error model;
- Sentry-compatible instrumentation;
- no public customer API.

## UI foundation

Build the actual application shell:

- login/deployment-selection design;
- navigation;
- typography/spacing/elevation tokens;
- tables/forms/modal/drawer primitives;
- status/severity components;
- permission-aware route/component pattern;
- accessibility baseline;
- loading/empty/error states.

No raw JSON inspector/editor.

## Test foundation

Create:

- Rust unit/integration structure;
- SMTP integration harness;
- PostgreSQL test strategy;
- Redis/Valkey test strategy;
- S3-compatible test storage;
- authorization/tenant-isolation fixtures;
- frontend component/E2E framework;
- security regression test location;
- fuzzing harness placeholders for MIME/contracts.

## Version-control and CI/CD foundation

Implement the approved policy in `docs/security/19-VERSION-CONTROL-CICD.md`.

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

- formatting/lint;
- compile/build;
- unit tests;
- relevant integration/security/UI tests;
- dependency/SCA;
- secret scan;
- SAST where selected;
- SBOM generation/validation;
- license checks;
- migration validation;
- IaC scan when infrastructure exists;
- container build/scan when image definitions exist.

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
- bypass auth/audit because the endpoint is "internal".

## Exit criteria

Phase 0 is complete when:

- core Rust contracts compile and are tested;
- database foundations/migrations exist;
- policy/event/audit/artifact contracts are versioned;
- UI shell/design tokens exist and pass accessibility baseline;
- authorization/audit infrastructure patterns are established;
- repository protection has been activated/verified (or a documented compensating control exists for unavailable plan features);
- CI security gates run;
- immutable build/release identity is established;
- CI AWS access uses scoped OIDC roles rather than long-lived deployment keys;
- observability context/scrubbing exists;
- architecture docs and contracts match implementation.

## Must not be built yet

- full SMTP delivery pipeline;
- full scanner engine set;
- Deep AI;
- mailbox connectors;
- customer-facing DMARC analytics.

Only foundation necessary for later phases belongs here.

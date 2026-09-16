# Nullapart Build Roadmap

**Audience:** human developers, AI coding agents, reviewers, security engineers and operators.

**Status:** authoritative implementation sequencing document.

This roadmap defines **what must exist before implementation, what each phase is allowed to change, what each phase must deliver, and the evidence required before moving forward**.

It is not a delivery-date estimate.

## How to use this roadmap

Before starting any work:

1. AI coding agents read root `AGENTS.md` first;
2. identify the current phase;
3. read this document;
4. read the detailed phase specification under `docs/phases/`;
5. read all architecture/security documents referenced by that phase;
6. confirm Phase -1 security controls applicable to the work;
7. identify affected trust boundaries/data classes/contracts;
8. implement backend and UI together where the capability has an administrative UI;
9. add tests, audit, observability and documentation in the same change;
10. satisfy the phase exit criteria before beginning work that depends on it.

AI agents must not infer missing architectural decisions from convenience. If a phase specification says a decision is not yet made, preserve the abstraction and do not silently lock the implementation.

Human developers should treat phase exit criteria as release gates, not suggestions.

## Global implementation rules

These rules apply to every phase.

### Security

- Security Program Phase -1 controls are mandatory.
- Every network API is authenticated.
- Authorization is server-side.
- No shared global service secret.
- Secrets never enter source control/frontend bundles.
- Message content is treated as hostile.
- Support never receives message body/raw MIME/attachment content.
- Administrative changes are audited.
- Customer/tenant boundaries are enforced in storage, queries, APIs and UI.
- Unknown/failed security analysis never silently becomes CLEAN.
- New trust boundaries require threat-model review.

### Architecture restraint

Do not recreate NexusSEG-style synchronous microservice chains.

Create a new process/service/container only when justified by:

- isolation;
- failure-domain separation;
- independently different scaling;
- resource profile;
- incompatible dependencies/runtime;
- security boundary.

Prefer module boundaries inside the Rust Mail Core or Control Backend before introducing a new network service.

### Rate limiting and abuse controls

- use layered edge + application + SMTP limits;
- authenticated API limits key on actor/customer/action, not only IP;
- high-risk actions have dedicated stricter limits;
- limiter backend failure has explicit safe behavior;
- abuse-rate exemptions are scoped and audited.

### Patching, dependency lifecycle and compatibility

- production dependencies/runtimes are pinned/reproducible;
- lockfiles are committed;
- automated update PRs are reviewed/tested;
- unsupported/EOL critical runtimes require a time-limited exception;
- containers are rebuilt rather than interactively patched;
- mail nodes patch through safe drain/rolling procedures;
- package/runtime compatibility is validated as a stack, not package-by-package;
- peer dependency/toolchain conflicts are not hidden with force flags;
- frontend, Rust, container and ML dependency matrices are tested in CI.

See `docs/26-PACKAGE-COMPATIBILITY.md`.

### Frontend architecture

- React/TypeScript/Vite baseline from `docs/23-FRONTEND-ARCHITECTURE.md`;
- pnpm lockfile;
- no auth tokens in browser persistent storage;
- one typed API client boundary;
- client validation does not replace server validation;
- no raw JSON UI.

### API compatibility and feature switches

- initial Control Plane API follows `/api/v1` compatibility rules;
- independently consumed events/scanner/config/AI contracts are versioned;
- breaking changes require explicit version/migration strategy;
- feature switches are server-authoritative versioned configuration, not authorization;
- release/experiment flags have owner/removal lifecycle;
- operational kill switches produce explicit safe degraded behavior;
- new features define API/data/UI/audit/rate-limit/failure/rollback/compliance impact before implementation.

See `docs/27-API-VERSIONING-FEATURE-FLAGS.md`.

### TLS trust, mTLS and HMAC

- public browser HTTPS uses normal modern PKI validation, HSTS and CAA;
- HPKP/Public-Key-Pins is not used;
- internal high-value service communication may use workload mTLS/private regional PKI;
- TLS verification is never disabled for convenience;
- any future non-browser pinning requires threat/rotation/recovery design;
- HMAC-SHA-256 is the baseline Nullapart shared-secret integrity primitive where appropriate;
- HMAC verification includes versioning, constant-time comparison, replay protection, key rotation and idempotency;
- provider webhooks use provider-defined verification schemes.

See:

- `docs/security/25-CERTIFICATE-TRUST-PINNING.md`;
- `docs/security/26-HMAC-SIGNING-WEBHOOKS.md`.

### ML / LLM skills and tools

- production AI capability is expressed as versioned skills;
- each skill defines data classes, model requirements, input/output schema, tool allowlist, context/token limits, evaluation and rollback;
- tools are server-authorized adapters, not raw infrastructure credentials;
- read-only tools are preferred initially;
- prompt/message/tool content is untrusted data;
- models cannot self-authorize administrative/mail/remediation actions;
- training eligibility is separately governed.

See `docs/25-AI-LLM-SKILLS-TOOLS.md`.

### Coding agents and context discipline

- coding agents follow root `AGENTS.md` and `docs/ai/CODING-AGENT-OPERATING-MODEL.md`;
- load the minimum authoritative task context rather than the whole repository by default;
- reuse existing project abstractions before adding new ones;
- token/context optimization never skips security, tenant isolation, audit or tests;
- coding-agent permissions do not imply runtime Deep-AI permissions;
- AI agents may prepare but never self-approve production releases.

### Container/network/firewall baseline

- ECS is the ordinary container baseline;
- dedicated mail EC2 nodes are the stable-MTA exception;
- ALB/WAF for HTTPS;
- direct MX/Postfix baseline for SMTP;
- Security Groups are primary workload firewall;
- no public SSH/database/cache/secrets/AI;
- authoritative port registry must match IaC.

### Compliance documentation

- maintain `docs/compliance/` scope/control/evidence/data-processing/third-party/risk records;
- architecture changes with data/security impact require compliance-impact review;
- do not claim certification without verified audit/legal basis.

### Application-security invariants

- derive data scope from authenticated principal, not client-provided IDs;
- enforce server-side object ownership/BOLA/IDOR checks;
- client validation is UX only; server validation is authoritative;
- use PostgreSQL RLS where practical as defense in depth;
- browser auth/refresh credentials are not stored in Local Storage/Session Storage;
- retryable/destructive side effects define idempotency;
- outbound-fetch features require SSRF protections and OAST coverage;
- API errors are stable/safe and do not leak stack traces, secrets or tenant existence unnecessarily;
- writable fields are explicitly allowlisted against mass assignment;
- wrong-user/wrong-tenant/wrong-owner tests are required.

### Version control and GitHub Actions

- `main` is protected and remains releasable;
- normal changes use short-lived branches + reviewed pull requests;
- security-critical paths require appropriate owner/security review;
- CI security checks are mandatory and cannot be disabled to make a change pass;
- workflow permissions are explicit/minimal;
- third-party Actions are pinned to reviewed immutable commit SHAs where practical;
- untrusted PR code receives no privileged production secrets;
- CI uses short-lived workload/OIDC credentials rather than standing AWS deployment keys;
- artifacts are built once, identified by immutable digest, and promoted between environments;
- production deployment requires explicit target region/deployment and approval;
- database migrations are version-controlled and immutable after production application;
- release versions/tags follow the documented versioning contract;
- AI agents may prepare releases but cannot self-approve production.

See `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`.

### UI

If a feature is visible/manageable by an administrator, its UI is implemented at the same time as the backend.

No raw JSON UI.

Use the Nullapart neumorphic design system while preserving dense, accessible operational tables and timelines.

### Observability

- Application SDK telemetry -> regional SegLumberjack via Sentry-compatible protocol.
- Native Postfix/Rspamd/ClamAV telemetry -> regional collector -> appropriate observability path.
- AWS infrastructure telemetry -> CloudWatch.
- Admin Audit is authoritative and separate from observability.
- Sensitive message content/secrets are scrubbed.

### Data

- PostgreSQL is authoritative.
- Redis/Valkey is cache/runtime acceleration, not authoritative durable events.
- PostgreSQL transactional outbox + SQS is the preferred durable async path.
- S3 is the production artifact backend behind ArtifactStore.
- Customer content remains region/deployment bound unless explicitly approved otherwise.

### Required change evidence

Every material change should include, where applicable:

- design/architecture reference;
- threat-model update;
- API/event/schema compatibility impact;
- feature-switch/rollout decision;
- code/config;
- migrations;
- backend authorization;
- audit events;
- UI;
- package/toolchain compatibility evidence;
- unit tests;
- integration tests;
- security tests;
- HMAC/replay/contract tests where applicable;
- ML skill/tool evaluation where applicable;
- UI/E2E tests;
- observability;
- runbook/update notes;
- rollback/containment plan.

## Phase sequence

| Phase | Name | Primary outcome |
|---|---|---|
| -1 | Security Program Gate | Security governance/processes exist before code |
| 0 | Contracts and Foundations | Stable contracts, schemas, UI shell, testing/CI foundations |
| 1 | SMTP and Mail Foundation | Safe bidirectional mail movement without advanced scanners/AI |
| 2 | Scanner Fabric and Quarantine | Parallel security analysis, quarantine/hold and scanner UI |
| 3 | Control Plane and Administration | Identity, RBAC, tenants, policies, trace, audit and operations UI |
| 4 | Inline ML | Low-latency ML evidence integrated safely into policy |
| 5 | DMARC / BIMI / Domain Security | Report ingestion, telemetry, dashboards and domain-security monitoring |
| 6 | Outbound Intelligence | Bulk controls, behavioural detection and compromised-sender response |
| 7 | Regional Deep AI | Controlled deep analysis and model lifecycle outside normal mail hot path |
| 8 | Connectors and Remediation | M365/Google/directory/mailbox integration and retro-remediation |
| 9 | Operational Automation and Production Hardening | n8n/ClickUp workflows, production gates, resilience and operational maturity |

Detailed specifications:

- [Phase -1 — Security Program Gate](phases/PHASE--1-SECURITY-GATE.md)
- [Phase 0 — Contracts and Foundations](phases/PHASE-0-CONTRACTS-FOUNDATIONS.md)
- [Phase 1 — SMTP and Mail Foundation](phases/PHASE-1-MAIL-FOUNDATION.md)
- [Phase 2 — Scanner Fabric and Quarantine](phases/PHASE-2-SCANNER-FABRIC.md)
- [Phase 3 — Control Plane and Administration](phases/PHASE-3-CONTROL-PLANE.md)
- [Phase 4 — Inline ML](phases/PHASE-4-INLINE-ML.md)
- [Phase 5 — DMARC/BIMI/Domain Security](phases/PHASE-5-DMARC-BIMI.md)
- [Phase 6 — Outbound Intelligence](phases/PHASE-6-OUTBOUND-INTELLIGENCE.md)
- [Phase 7 — Regional Deep AI](phases/PHASE-7-DEEP-AI.md)
- [Phase 8 — Connectors and Remediation](phases/PHASE-8-CONNECTORS-REMEDIATION.md)
- [Phase 9 — Operational Automation and Production Hardening](phases/PHASE-9-OPERATIONS-HARDENING.md)

## Dependency rules

Phases express logical dependency, not necessarily a prohibition on preparatory research.

Allowed examples:

- benchmark Deep-AI candidates before Phase 7;
- prototype UI components before Phase 3;
- research DMARC parsing before Phase 5.

Not allowed:

- shipping a production subsystem whose prerequisites/gates have not passed;
- bypassing Phase -1 controls because work is "prototype";
- implementing customer-visible policy before authorization/audit contracts exist;
- introducing a network service whose trust/security model is not documented;
- introducing unversioned contracts or ungoverned LLM tools as a shortcut.

## Production-readiness gate

No deployment is production-ready merely because Phase 9 code exists.

Production readiness requires at minimum:

- Phase -1 security program accepted;
- implemented subsystem threat models reviewed;
- MFA/admin audit operational;
- tenant isolation tests passing;
- backup/restore tested;
- required runbooks exercised;
- SMTP commissioning complete;
- no unresolved Critical security finding;
- High findings resolved or formally time-limited with compensating controls;
- observability/alerting active;
- SQS/DLQ/outbox health visible;
- scanner failure semantics verified;
- regional data-residency controls verified;
- API/event/schema compatibility verified for rolling deployment;
- feature switches/kill switches reviewed and obsolete rollout flags removed/planned for removal;
- dependency/toolchain/runtime compatibility and support status verified;
- TLS/certificate rotation path verified;
- HMAC/webhook verification/replay controls tested where used;
- Deep-AI skill/tool permissions/evaluations verified where enabled;
- rollback/containment tested;
- external security testing completed as required.

## Definition of complete

A phase is complete only when:

1. its required deliverables exist;
2. acceptance tests pass;
3. documentation matches implementation;
4. security evidence exists;
5. UI/backend behaviour is consistent;
6. operational failure modes are observable;
7. exit criteria in the phase document are approved.

"Code works on a developer machine" is never sufficient phase completion.

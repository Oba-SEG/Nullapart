# Nullapart Build Roadmap

**Audience:** human developers, AI coding agents, reviewers, security engineers and operators.

**Status:** authoritative implementation sequencing document.

This roadmap defines **what must exist before implementation, what each phase may change, what each phase must deliver, and the evidence required before moving forward**.

It is not a delivery-date estimate.

## How to use this roadmap

Before starting work:

1. AI coding agents read root `AGENTS.md` first;
2. identify the current/owning phase;
3. read this roadmap;
4. read the detailed phase specification under `docs/phases/`;
5. read `docs/engineering/CODE-STANDARDS.md`;
6. read only architecture/security documents relevant to the task;
7. confirm applicable Phase -1 controls;
8. identify affected tenant/deployment scope, trust boundaries, data classes and contracts;
9. implement backend/UI/security/audit/tests/observability/docs together where applicable;
10. satisfy phase exit criteria before dependent work proceeds.

AI agents do not infer missing architecture from convenience. Preserve undecided abstractions until intentionally reviewed.

Human developers treat phase exit criteria as gates, not suggestions.

# Global implementation rules

## Security

- Phase -1 controls are mandatory.
- Every network API is authenticated unless an explicitly designed protocol trust model applies.
- Authorization/ownership are server-side.
- No shared global service secret.
- Secrets never enter source control/frontend bundles.
- Message content is hostile.
- Support never receives message body/raw MIME/attachments.
- Administrative/security changes are audited.
- Tenant boundaries are enforced in request context, storage, RLS, queries, APIs, caches, jobs/events and UI.
- UNKNOWN/failed security analysis never silently becomes CLEAN.
- New trust boundaries require threat-model review.

## Architecture restraint

Do not recreate NexusSEG-style service-per-feature synchronous HTTP chains.

Create a process/service/container only when isolation, failure domain, independent scaling, resource profile, incompatible runtime/dependency or security boundary justifies it.

Prefer module boundaries in Mail Core/Control Backend first.

## Tenant-aware routing and feature overrides

Canonical design: `docs/29-TENANT-FEATURE-ROUTING.md`.

Rules:

- regional/deployment boundary is established before tenant context;
- authenticated server/session state resolves `TenantContext`;
- client tenant/customer IDs never prove authorization;
- System/Support cross-customer work uses explicit platform permission + specific customer scope;
- tenant scope travels with background jobs/events/caches;
- PostgreSQL RLS context is transaction-scoped and pool-safe;
- feature precedence is System emergency/security floor -> deployment -> tenant -> default;
- tenant override cannot weaken a System security floor/kill switch;
- overrides have owner/reason/revision/expiry/audit.

## Tier-3 reliability / SRE

Canonical design: `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`.

Tier 3 is an internal Nullapart reliability class, not an external certification claim.

Production-critical capabilities require:

- SLI/SLO;
- error budget;
- burn-rate alerting;
- RTO/RPO;
- redundancy/failure-domain analysis;
- backpressure/load shedding;
- capacity thresholds;
- runbook/owner;
- failure/restore exercises.

Baseline burn alerts:

- fast: 14.4x on 1h + 5m;
- sustained: 6x on 6h + 30m;
- calibrated slow-burn ticket path.

Error budget never means accepted-mail loss/security-policy bypass is acceptable.

## Rate limiting and abuse

- layered edge + application + SMTP limits;
- authenticated API limits use actor/customer/action, not only IP;
- high-risk actions have stricter limits;
- limiter outage has explicit safe fallback;
- exemptions are scoped/audited.

## Patching / compatibility / zero-day

Canonical references:

- `docs/security/23-PATCHING-DEPENDENCY-VERSIONS.md`;
- `docs/26-PACKAGE-COMPATIBILITY.md`;
- `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`.

Rules:

- dependencies/runtimes are pinned/reproducible;
- lockfiles committed;
- automated update PRs reviewed/tested;
- EOL critical runtime requires time-limited exception;
- containers rebuilt, not interactively patched;
- mail nodes use safe drain/rolling patching;
- package/runtime compatibility is tested as a stack;
- no peer/toolchain conflict hidden with force flags;
- credible zero-day/active exploitation uses accelerated intake/containment/patch/hunt process;
- do not wait for finalized CVE/CVSS before containment when evidence warrants action;
- vulnerable security/parser paths can be kill-switched/held/deferred safely;
- emergency patches still use branch/PR/review/CI, never direct `main` push.

## Frontend architecture

From `docs/23-FRONTEND-ARCHITECTURE.md`:

- React/TypeScript/Vite baseline;
- pnpm lockfile;
- no auth/refresh tokens in browser persistent storage;
- one typed API client;
- client validation does not replace server validation;
- no raw JSON UI;
- accessibility and hostile-message isolation are mandatory.

## API compatibility and feature switches

From `docs/27-API-VERSIONING-FEATURE-FLAGS.md`:

- initial Control Plane `/api/v1` compatibility contract;
- independently consumed events/scanner/config/AI contracts versioned;
- breaking changes need version/migration strategy;
- feature switches server-authoritative, not authorization;
- tenant overrides follow canonical precedence;
- release/experiment flags have owner/removal lifecycle;
- kill switches cause explicit safe degraded behavior;
- new feature defines API/data/tenant/UI/audit/rate/failure/SLO/rollback/compliance/patchability impact before implementation.

## TLS / mTLS / HMAC

- public browser HTTPS uses modern PKI, HSTS and CAA;
- HPKP not used;
- internal high-value communication may use workload mTLS/private PKI;
- TLS verification is never disabled for convenience;
- non-browser pinning requires explicit threat/rotation/recovery design;
- HMAC-SHA-256 is baseline Nullapart shared-secret integrity primitive where appropriate;
- verification includes version, constant-time compare, replay protection, rotation and idempotency;
- provider webhooks use provider verification scheme.

References:

- `docs/security/25-CERTIFICATE-TRUST-PINNING.md`;
- `docs/security/26-HMAC-SIGNING-WEBHOOKS.md`.

## ML / LLM skills/tools

- production AI capabilities are versioned skills;
- skill defines data classes, model/input/output, tool allowlist, context/token limits, eval and rollback;
- tools are server-authorized adapters, never ambient infra credentials;
- read-only tools preferred initially;
- prompt/message/tool content is untrusted;
- model cannot self-authorize admin/mail/remediation action;
- training eligibility separately governed.

Reference: `docs/25-AI-LLM-SKILLS-TOOLS.md`.

## Coding agents / instruction discovery

Canonical rules:

- `AGENTS.md`;
- `docs/ai/CODING-AGENT-OPERATING-MODEL.md`;
- `docs/ai/AGENT-DISCOVERY.md`.

OpenAI Codex and OpenCode use root `AGENTS.md` directly. Copilot/Claude/Gemini/Cursor use thin adapters pointing to the canonical rules.

Agents load minimum authoritative context, but token optimization never skips security/tenant/audit/tests.

Agent instructions are guidance; enforcement remains compiler/types, RLS, tests, CI, reviews, protected `main` and production approvals.

## Container/network/firewall

- ECS ordinary container baseline;
- dedicated mail EC2 stable-MTA exception;
- ALB/WAF for HTTPS;
- direct commissioned Postfix MX baseline for SMTP;
- Security Groups primary workload firewall;
- no public SSH/database/cache/secrets/AI;
- authoritative port registry matches IaC.

## Compliance documentation

Maintain `docs/compliance/` scope/control/evidence/data-processing/third-party/risk/readiness records.

Architecture changes affecting data/security require compliance-impact review.

Never claim certification without verified legal/audit basis.

## Application-security invariants

- derive scope from authenticated principal, not client IDs;
- server-side ownership/BOLA/IDOR checks;
- server validation authoritative;
- RLS defense in depth;
- no browser Local/Session Storage credentials;
- retryable/destructive effects are idempotent;
- outbound fetch gets SSRF + OAST coverage;
- errors safe/stable;
- writable fields allowlisted;
- wrong-user/wrong-tenant/wrong-owner tests required.

## Version control / GitHub Actions

`main` is protected and remains releasable.

**No direct pushes to `main`, including routine administrator changes.**

Normal and emergency changes use reviewed PRs; emergency flow may be expedited but still preserves traceability/checks.

Additional rules:

- short-lived branches;
- required review/checks;
- no force push/deletion;
- security-critical paths get owner/security review;
- CI checks cannot be disabled to make work pass;
- minimum workflow permissions;
- third-party Actions SHA-pinned where practical;
- untrusted PR receives no production secrets;
- OIDC short-lived AWS roles;
- immutable build once/promote same digest;
- explicit deployment/region target + production approval;
- migrations immutable after production use;
- AI agents cannot self-approve production.

References:

- `docs/security/19-VERSION-CONTROL-CICD.md`;
- `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`.

## Code standards

Canonical standard: `docs/engineering/CODE-STANDARDS.md`.

Formatter/linter/type/static checks are automated merge gates; reviewers focus on correctness/security/architecture rather than whitespace.

## UI

If an administrative capability needs UI, implement/test UI with backend.

No raw JSON UI.

Use Nullapart neumorphism while preserving dense accessible operational tables/timelines.

## Observability

- application SDK -> Sentry-compatible protocol -> regional SegLumberjack;
- native daemons -> regional collector -> appropriate observability;
- AWS infra -> CloudWatch;
- Admin Audit is authoritative/separate;
- Restricted content/secrets scrubbed;
- Tier-3 SLIs/error-budget/burn-rate telemetry are first-class operational metrics.

## Data

- PostgreSQL authoritative;
- Redis/Valkey cache/runtime acceleration, not durable event authority;
- PostgreSQL outbox + SQS durable async baseline;
- S3 production ArtifactStore backend;
- customer content stays region/deployment bound absent explicit approved design.

## Required change evidence

Material changes include as applicable:

- architecture/threat reference;
- tenant/routing/feature-override impact;
- API/event/schema compatibility;
- reliability/SLO impact;
- code/config/migrations;
- auth/audit/UI;
- package/toolchain/zero-day exposure implications;
- unit/integration/security/UI tests;
- HMAC/replay/contract tests;
- ML skill/tool eval;
- observability;
- runbook/rollback/containment;
- docs.

# Phase sequence

| Phase | Name | Primary outcome |
|---|---|---|
| -1 | Security Program Gate | Governance/security/reliability/developer rules accepted before code |
| 0 | Contracts and Foundations | Contracts, tenant context, CI/repo controls, UI/testing/instrumentation foundations |
| 1 | SMTP and Mail Foundation | Safe bidirectional mail without advanced scanner/AI depth |
| 2 | Scanner Fabric and Quarantine | Parallel bounded analysis + quarantine/hold |
| 3 | Control Plane and Administration | Identity/RBAC/tenants/policies/trace/audit/operations UI |
| 4 | Inline ML | Low-latency ML evidence integrated safely into policy |
| 5 | DMARC / BIMI / Domain Security | Reporting/telemetry/domain-security monitoring |
| 6 | Outbound Intelligence | Bulk/behaviour/compromised-sender controls |
| 7 | Regional Deep AI | Controlled regional deep analysis outside normal hot path |
| 8 | Connectors and Remediation | Directory/mailbox integration + retro-remediation |
| 9 | Operational Automation and Production Hardening | Tier-3 SLOs, resilience, automation, production evidence |

Detailed phase specs live in `docs/phases/`.

# Dependency rules

Preparatory research may run ahead (e.g. AI benchmarks, UI prototypes, DMARC research), but production capability cannot bypass prerequisite phase/security gates.

Never ship:

- production subsystem before prerequisite gates;
- customer-visible policy before authorization/audit foundation;
- new network service without trust/security model;
- unversioned contracts;
- ungoverned LLM tools;
- tenant routing outside canonical boundary;
- Tier-3 production service without SLO/failure/runbook model.

# Production-readiness gate

No deployment is production-ready merely because Phase 9 code exists.

At minimum:

- Phase -1 accepted/current;
- protected `main` active with no direct pushes;
- CI/reviews/agent enforcement controls active;
- subsystem threat models reviewed;
- MFA/admin audit operational;
- tenant context/RLS/feature override tests pass;
- Tier-3 SLO/error-budget/burn-rate alerts active;
- backup/restore/failure exercises pass;
- zero-day process/tabletop evidence exists;
- SMTP commissioning complete;
- no unresolved Critical vulnerability;
- High risks resolved or time-limited formal exception;
- observability/alerting/SQS/DLQ/outbox health visible;
- scanner failure semantics verified;
- residency/API compatibility/feature-switch/dependency/TLS/HMAC/AI permissions verified as applicable;
- rollback/containment tested;
- external security testing completed as required.

# Definition of complete

A phase is complete only when deliverables exist, tests pass, docs match implementation, security/reliability evidence exists, UI/backend behavior agrees, failure modes are observable and phase exit criteria are approved.

"Code works on a developer machine" is never sufficient.

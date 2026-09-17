# Coding Agent Operating Model

**Audience:** AI coding agents, reviewers and humans delegating implementation tasks.

## Purpose

AI agents must work from Nullapart's architecture/security contracts without consuming the entire repository context or inventing missing design decisions.

The goal is **high signal per token/context unit**, not maximum file ingestion.

## Discovery

Root `AGENTS.md` is the canonical coding-agent instruction source.

Supported environments are described in `docs/ai/AGENT-DISCOVERY.md`.

Important current behavior:

- OpenAI Codex uses `AGENTS.md` directly;
- OpenCode uses `AGENTS.md` directly;
- Copilot/Claude/Gemini/Cursor adapters point back to the same canonical rules.

Do not create separate policy copies per agent vendor.

## Required context order

Before coding, load context in this order:

1. root `AGENTS.md`;
2. `SECURITY.md`;
3. `docs/16-BUILD-ROADMAP.md`;
4. owning detailed phase document under `docs/phases/`;
5. `docs/engineering/CODE-STANDARDS.md`;
6. only architecture/security docs directly relevant to the task;
7. implementation files being changed plus nearby tests/contracts.

Do not dump/read the entire repository unless a task genuinely requires a global audit.

## Task context manifest

At the start of a material task, establish a compact internal/task manifest:

- objective;
- owning phase;
- files/modules likely affected;
- contracts involved;
- tenant/deployment scope;
- data classes involved;
- auth/RBAC/audit implications;
- feature-switch/override impact;
- failure/idempotency requirements;
- reliability/SLO impact where applicable;
- dependency/zero-day exposure impact for new parsers/packages;
- tests required;
- docs to update.

This prevents repeated repo-wide rediscovery.

## Search before broad reads

Prefer:

1. targeted search by symbol/term;
2. fetch relevant file sections;
3. expand only if needed.

Avoid repeatedly loading large files whose relevant rule is already known.

## Reuse project abstractions

Before creating code, search for existing:

- ID types;
- `TenantContext` / request context / principal;
- authorization helpers;
- feature evaluator/tenant override patterns;
- error types;
- audit helpers;
- DB/RLS patterns;
- event/outbox code;
- ArtifactStore;
- scanner contracts;
- design-system components;
- API client utilities;
- rate-limiter/idempotency utilities;
- reliability/SLI instrumentation helpers.

Do not solve the same problem with a parallel abstraction.

## Coding-agent skill catalog

An agent may be assigned one or more project skills.

### `nullapart.architecture-navigation`

Required abilities:

- locate owning phase;
- identify authoritative architecture document;
- distinguish proposed vs locked decisions;
- avoid NexusSEG-style service proliferation.

### `nullapart.appsec-review`

Required abilities:

- principal/customer scoping;
- ownership/BOLA/IDOR;
- server validation;
- RLS;
- CSRF/session safety;
- idempotency;
- OAST/SSRF;
- safe errors;
- audit/rate-limit checks.

### `nullapart.tenant-routing`

Required abilities:

- resolve trusted `TenantContext` at application boundary;
- never authorize from client tenant IDs;
- preserve deployment/tenant scope in jobs/events/caches;
- implement feature override precedence;
- prevent tenant overrides weakening System security floors.

Canonical reference: `docs/29-TENANT-FEATURE-ROUTING.md`.

### `nullapart.mail-pipeline`

Required abilities:

- Postfix/Rspamd responsibility boundaries;
- SMTP acceptance/queue/reinjection;
- tenant message splitting;
- DSN/retry/backscatter semantics;
- trusted auth results.

### `nullapart.rust-contracts`

Required abilities:

- typed contracts;
- ownership/error boundaries;
- serialization/versioning;
- async/resource limits;
- no generic JSON shortcuts.

### `nullapart.control-plane`

Required abilities:

- modular backend;
- ZITADEL/session integration;
- server-side RBAC;
- audit/outbox transaction;
- versioned API;
- feature flags/business state.

### `nullapart.frontend`

Required abilities:

- React/TypeScript/Vite stack;
- Nullapart design-system reuse;
- central API client;
- no Local Storage auth;
- accessibility;
- hostile message rendering;
- role/tenant UI tests.

### `nullapart.database-security`

Required abilities:

- PostgreSQL migrations;
- RLS;
- transaction-scoped tenant context;
- locking/revisions;
- audit/outbox atomicity;
- no applied-migration rewrite.

### `nullapart.aws-infrastructure`

Required abilities:

- ECS/container baseline;
- dedicated mail EC2 exception;
- ALB/WAF vs SMTP direct MX;
- SG/port registry;
- IAM/OIDC/KMS/S3/SQS/RDS;
- no public sensitive services.

### `nullapart.reliability-sre`

Required abilities:

- Tier-3 capability classification;
- SLI/SLO/error-budget design;
- multi-window burn-rate alerting;
- backpressure/load shedding;
- RTO/RPO;
- failure testing/runbooks;
- no accepted-mail durability/security tradeoff for latency.

Canonical reference: `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`.

### `nullapart.testing-security`

Required abilities:

- wrong tenant/owner;
- malformed/boundary;
- idempotency/replay;
- OAST/SSRF;
- parser/fuzz/resource exhaustion;
- failure semantics;
- E2E role/session flows.

### `nullapart.zero-day-response`

Required abilities:

- advisory/SBOM/version correlation;
- exposure state tracking;
- emergency mitigation selection;
- focused patch/regression testing;
- retrospective hunt planning;
- no autonomous production patch/key rotation.

Canonical reference: `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`.

### `nullapart.ml-llm`

Required abilities:

- dataset/model provenance;
- skill/tool contracts;
- model version/evals;
- prompt injection/tool isolation;
- regional artifact access;
- no autonomous action.

### `nullapart.cicd-release`

Required abilities:

- GitHub Actions minimum permissions;
- protected `main` / no direct pushes;
- locked dependencies;
- action SHA pinning;
- OIDC AWS deployment;
- immutable artifacts;
- migration/release safety.

### `nullapart.docs-consistency`

Required abilities:

- update authoritative docs/diagrams;
- check links/stale terms;
- preserve one diagram source;
- keep phase/docs/code consistent.

## Skill invocation

A task should name the minimum necessary skill set.

Example:

```text
Task: add quarantine release API/UI
Skills:
- nullapart.control-plane
- nullapart.tenant-routing
- nullapart.appsec-review
- nullapart.frontend
- nullapart.database-security
- nullapart.testing-security
```

Do not preload ML/AWS/mail context if the task is a small isolated frontend component with no impact there.

## Context/token optimization

### Prefer authoritative summaries

Once a rule is established from an authoritative project doc, retain a concise task summary instead of repeatedly re-reading the full document.

### Load diffs, not entire histories

For review/change tasks, inspect changed files and dependencies first.

Do not load full Git history unless provenance/history is the task.

### Avoid duplicated vendor documentation

Use external official documentation only for facts that are current/version-specific or unclear.

Do not paste large external docs into project context.

### Keep outputs structured

Use compact checklists/tables for affected files, controls, tests and compatibility decisions.

### Do not optimize away security

Token/context optimization must never skip:

- authorization/ownership;
- tenant isolation/routing;
- audit;
- validation;
- failure semantics;
- required reliability/security tests;
- required threat-model review.

## Bounded change principle

Prefer the smallest coherent change that satisfies the phase/feature contract.

Do not perform unrelated refactors/package upgrades while implementing a feature unless required.

This improves reviewability and reduces agent context requirements.

## Escalation triggers

Stop and surface an architecture decision before coding if the task requires:

- a new public endpoint type;
- a new persistent datastore;
- a new network service;
- cross-region customer data movement;
- a new tenant-routing model;
- tenant override capable of weakening a System floor;
- a new LLM action/tool permission;
- weakening a System security floor;
- changing customer ID semantics;
- changing SMTP responsibility/acceptance semantics;
- bypassing RLS/auth/audit;
- incompatible API/event/schema change;
- introducing Kubernetes/EKS;
- sending Restricted data to a new third party;
- changing Tier-3 SLO/error-budget semantics;
- bypassing protected `main` or required CI checks.

## Enforcement

Instruction compliance is not trusted as the only control.

Repository/process enforcement must include, where applicable:

- types/compiler;
- RLS/database constraints;
- security/integration tests;
- formatter/linter/type checks;
- CI scans;
- required PR review;
- branch protection;
- production approvals.

An agent cannot self-approve production or disable enforcement to make a task pass.

## Completion report

When a coding agent completes a material task, report concisely:

- what changed;
- tests run/results;
- security controls exercised;
- tenant/feature/reliability impact;
- migrations/config/feature flags;
- docs updated;
- known limitations/follow-ups.

Do not claim a test/security control passed if it was not actually run/verified.

# Coding Agent Operating Guide

**Audience:** AI coding agents and humans supervising them.

## Goal

Use coding agents as disciplined contributors that preserve Nullapart architecture/security while minimizing context waste, token use and accidental scope expansion.

## Read order

Before coding, read only the minimum authoritative context needed, in this order:

1. `README.md`;
2. `SECURITY.md`;
3. `docs/16-BUILD-ROADMAP.md`;
4. owning `docs/phases/PHASE-*.md`;
5. referenced architecture/security docs;
6. exact files being changed;
7. nearby tests/interfaces.

Do not load the whole repository into context if targeted files/indexes answer the question.

## Context minimization

Prefer:

- targeted search by symbol/path;
- reading relevant line ranges;
- reading interfaces/contracts before implementations;
- using phase/security indexes;
- comparing only touched files;
- summarizing discovered invariants before coding.

Avoid:

- repeatedly re-reading large docs already summarized;
- loading generated/vendor/lock files unless needed;
- reading unrelated services;
- dumping full logs when one error block is enough.

## Token-efficient workflow

For a normal task:

1. identify phase and subsystem;
2. search exact symbol/path;
3. read contract/interface;
4. read implementation and tests;
5. state intended change in a compact internal plan;
6. make smallest coherent patch;
7. run focused tests first;
8. run broader required gates;
9. inspect diff;
10. update docs only where behavior/contract changed.

Prefer fixing root cause over producing many speculative alternatives.

## Scope discipline

Do not:

- refactor unrelated code during a security fix;
- upgrade broad dependencies casually;
- create a service/package because it feels cleaner;
- rename public contracts without migration;
- rewrite architecture to fit an implementation shortcut.

If a task reveals a foundational conflict, update/review the architecture first.

## Skill catalog for coding agents

A coding-agent **skill** is a reusable, documented procedure with narrow scope.

Recommended repository skills/processes include:

- Phase/context discovery;
- secure endpoint implementation;
- tenant/RLS query implementation;
- migration creation/review;
- scanner adapter implementation;
- SMTP/Postfix config review;
- frontend feature implementation;
- Admin Audit integration;
- feature-switch introduction/removal;
- dependency upgrade review;
- incident/security hotfix;
- CI workflow change review;
- architecture diagram/doc update.

Each skill should specify:

- required reading;
- allowed files/areas;
- security invariants;
- tests to run;
- output/evidence;
- stop/escalation conditions.

Skills are version-controlled and reviewed like development documentation.

## Secure endpoint skill baseline

When adding an endpoint, the agent checks:

- authentication;
- principal/tenant scope;
- ownership/BOLA;
- permission/action;
- RLS applicability;
- server validation/canonicalization;
- mass assignment;
- rate limit;
- idempotency;
- audit;
- safe errors;
- tests for wrong-user/wrong-tenant;
- UI behavior if applicable.

## Frontend skill baseline

When adding UI:

- reuse design system;
- use central API client;
- no auth token storage;
- no raw JSON;
- no frontend-only authorization;
- client validation + server validation;
- loading/empty/error/accessibility states;
- role/tenant tests;
- hostile-content boundary where relevant.

## Dependency-upgrade skill baseline

Before changing a dependency:

- inspect manifest/lockfile;
- verify peer/runtime compatibility;
- read security/release implications;
- avoid unrelated upgrades;
- update compatibility matrix for major changes;
- run build/type/test/security checks;
- inspect lockfile churn.

## GitHub Actions skill baseline

Workflow changes are security-sensitive.

Agent checks:

- minimal `permissions`;
- third-party action pinning;
- untrusted PR secret exposure;
- OIDC trust conditions;
- environment/region scoping;
- no long-lived AWS keys;
- artifact provenance;
- immutable deployment digest;
- production human approval.

## Test selection

Run tests in escalating order:

1. unit tests for changed module;
2. targeted integration/security tests;
3. relevant UI/E2E;
4. workspace/build/typecheck;
5. CI-equivalent gates when completing a PR.

Do not run an expensive whole-suite repeatedly when a targeted failing test can guide the fix, but do run required full gates before declaring completion.

## Failure handling

If blocked by missing infrastructure/credentials:

- do not weaken security;
- do not hard-code temporary secrets;
- implement/test mocks/contracts where appropriate;
- clearly identify what remains unverified.

## High-risk stop conditions

Stop and surface for review when a task requires:

- weakening authentication/authorization/audit;
- cross-region customer-data movement;
- public database/cache/secrets exposure;
- new privileged LLM tool;
- new public API;
- destructive migration without rollback strategy;
- disabling CI/security scan;
- production credential creation;
- broad port/firewall opening;
- accepting Critical/High security risk without formal process.

## Documentation discipline

Update documentation when changing:

- contract;
- trust boundary;
- data classification;
- API/event version;
- dependency/runtime baseline;
- feature flag lifecycle;
- deployment/network topology;
- security process.

Do not update docs solely to claim a feature exists before code/evidence exists.

## Output discipline

Agent-generated PR/commit descriptions should be concise but include:

- what changed;
- why;
- phase;
- security implications;
- tests/evidence;
- migrations/rollout;
- known limitations.

## Persistent agent instructions

`AGENTS.md` at repository root summarizes non-negotiable agent rules. This guide supplies the detailed operating method.
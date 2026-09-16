# Contributing to Nullapart

## Phase -1 security gate

Nullapart implementation must follow the accepted [Security Program](docs/security/README.md).

Before building a new subsystem or high-risk feature, confirm the applicable threat model, data classification, authorization/audit requirements, failure model, security tests and operational runbook expectations.

A change that violates a mandatory security baseline requires an approved, time-limited security exception. Security cannot be deferred as post-implementation cleanup.

## Human and AI developer execution protocol

Before modifying implementation, configuration, infrastructure or UI:

1. identify the owning phase in [Build Roadmap](docs/16-BUILD-ROADMAP.md);
2. read the matching detailed specification in [Phase Specifications](docs/phases/README.md);
3. read all architecture/security documents referenced by that phase;
4. identify affected trust boundaries, data classes, RBAC/audit requirements and failure semantics;
5. identify whether the change modifies an existing contract;
6. implement backend/UI/security/tests/documentation together where applicable;
7. verify the phase's exit criteria affected by the change.

### AI coding agents

AI agents must:

- preserve existing architecture unless explicitly asked to change it;
- avoid inventing new services, IDs, data models or public APIs for convenience;
- prefer established project contracts over generic JSON/dynamic structures;
- make tenant/customer scope explicit in every data/query/API path;
- treat email/message content as hostile;
- never weaken authentication, authorization, audit or failure semantics to complete a task;
- update tests and documentation when behaviour changes;
- stop implementation and surface the conflict if a request would violate a mandatory security rule unless the architecture/security rule is deliberately being revised.

AI agents must not infer that an undocumented shortcut is approved simply because it is technically easy.

### Human developers/reviewers

Human developers and reviewers must:

- validate that the implementation matches the owning phase;
- challenge unnecessary services/network boundaries;
- review security-sensitive changes against Phase -1;
- require evidence for exit criteria rather than relying on description alone;
- deliberately update architecture first when changing a foundational contract.

### Documentation/code disagreement

Documentation and implementation disagreement is a defect.

Resolve it by either:

- changing the implementation to match the architecture; or
- deliberately reviewing and updating architecture/threat models before changing implementation.

## Git and pull-request workflow

Normal development uses short-lived branches and pull requests into protected `main`.

Do not push directly to `main` or rewrite protected history.

Before opening a PR:

- identify owning phase;
- run relevant tests/checks locally where practical;
- update documentation when behaviour/contracts change;
- ensure no secrets/generated sensitive artifacts are present.

PRs must state:

- objective;
- phase;
- architecture/security impact;
- tests;
- UI impact;
- migration impact;
- audit/observability impact;
- rollback/containment.

Production artifacts are created by CI, not developer laptops.

Production deployments use immutable digests and approved GitHub/AWS identities.

See [Version Control, CI/CD and Release Security](docs/security/19-VERSION-CONTROL-CICD.md).

## Definition of Done

If a feature requires a UI, its UI is implemented and tested at the same time as the backend capability.

Expected completion includes, where applicable:

- backend implementation;
- persistence;
- authentication;
- authorization;
- audit events;
- UI;
- UI validation;
- loading/empty/error states;
- accessibility;
- Sentry-compatible instrumentation routed to SegLumberjack;
- operational logs;
- unit tests;
- integration tests;
- UI tests;
- security tests;
- documentation/help text.

## No raw JSON UI

Raw JSON editors, payload viewers and API dumps are not accepted as admin UI.

Structured data must be represented through intentionally designed controls, tables, forms, timelines or inspection views.

## Architecture restraint

Do not create a new service simply because a feature is conceptually distinct.

A new process/container must be justified by isolation, different dependencies/runtime, independent horizontal scaling, security boundary, failure-domain separation or resource profile.

## Open source first

Use established open-source solutions instead of rebuilding protocol/security infrastructure where a suitable maintained solution exists. AWS managed services may be used where there is no suitable open/free alternative or where operating the equivalent safely creates unnecessary risk.

## Naming

Product and canonical repository name: **Nullapart**.

Primary domain: `nullapart.com`.

Additional supported domains: `nullapart.io`, `nullapart.co`, `nullapart.co.za`.

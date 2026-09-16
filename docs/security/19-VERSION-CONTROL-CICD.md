# Version Control, CI/CD and Release Security

**Status:** mandatory Phase -1 / Phase 0 engineering baseline.

## Purpose

Nullapart must have a predictable, auditable path from source change to production deployment.

Version control and CI/CD are security boundaries. A compromised repository, workflow, build runner, registry or deployment role can compromise the product even when application code is secure.

## Repository model

Nullapart uses a monorepo unless a future architecture decision explicitly changes that.

The monorepo contains:

- Rust crates;
- mail configuration;
- scanners/adapters;
- control plane;
- frontend;
- ML lifecycle code/config;
- infrastructure-as-code;
- workflow definitions;
- tests;
- architecture/security documentation.

Do not create separate repositories merely to mirror conceptual services.

## Default branch

Canonical default branch:

- `main`

`main` must remain releasable.

Do not use a long-lived `develop` branch as a second source of truth.

Use short-lived branches such as:

- `feature/<description>`;
- `fix/<description>`;
- `security/<description>`;
- `docs/<description>`;
- `infra/<description>`.

Branches are temporary and deleted after merge unless there is a specific operational reason to retain one.

## Protected branch rules

`main` must be protected.

Required protections:

- pull request required;
- direct pushes disabled for normal developers/agents;
- force pushes disabled;
- branch deletion disabled;
- required status checks;
- required review(s);
- stale approvals dismissed when security-relevant code changes;
- CODEOWNERS/security-owner review for protected paths;
- conversation/resolution requirement where practical;
- merge only after current branch is up to date with required checks;
- administrator bypass restricted and audited.

Production release tags must also be protected from casual deletion/rewrite.

## Pull requests

Every material change describes:

- problem/objective;
- owning roadmap phase;
- architecture/security documents affected;
- trust-boundary/data-classification impact;
- implementation summary;
- tests;
- migration impact;
- UI impact;
- audit/observability impact;
- rollback/containment;
- security findings/exceptions;
- screenshots where meaningful for UI changes.

Small documentation-only corrections may use a lighter template but still require review when they change security/architecture requirements.

## Review requirements

At least one qualified reviewer is required.

Additional review is required for security-critical paths such as:

- authentication/authorization;
- tenant isolation;
- admin audit;
- secrets/PKI;
- AWS IAM/networking;
- Postfix/Rspamd;
- scanner sandboxing;
- artifact access;
- Deep AI permissions/tools;
- regional/data-residency controls;
- CI/CD workflows;
- release/deployment permissions;
- database migrations affecting security boundaries.

No author/self-approval should be sufficient for high-risk production changes.

## CODEOWNERS

Use CODEOWNERS (or equivalent review policy) for high-risk areas.

Ownership entries should cover:

- `.github/workflows/`;
- `infrastructure/`;
- `mail/`;
- `control/identity/`;
- `control/audit/`;
- security-sensitive Rust crates;
- `docs/security/`;
- security architecture;
- model/deep-AI security configuration.

Do not invent usernames in documentation; populate actual owners when maintainers are assigned.

## Commit policy

Commits should be attributable and traceable.

Prefer:

- signed commits/tags where practical;
- descriptive commit messages;
- no secrets;
- no generated build artifacts committed unless intentionally version-controlled;
- lockfiles committed where the ecosystem expects deterministic dependency resolution.

History rewriting on protected branches is prohibited.

## Merge strategy

Preferred default:

- squash merge for ordinary PRs, or
- rebase/linear history if the project later standardizes on it.

The important requirement is a clean, traceable mapping:

```text
PR -> reviewed source change -> merge commit/source SHA -> CI artifact -> release -> deployment
```

Do not mix merge strategies arbitrarily if it makes release provenance ambiguous.

## Versioning

### Product release

Use Semantic Versioning:

- `MAJOR.MINOR.PATCH`

Before first stable production release:

- `0.x.y`

Examples:

- `0.1.0`;
- `0.1.1`;
- `0.2.0`.

After stability:

- `1.0.0` onward.

### Git tags

Release tags:

- `v0.1.0`;
- `v1.0.0`.

Tags identify immutable source releases.

### Container/artifact versions

Every built artifact records:

- product/component version;
- Git SHA;
- build ID;
- build timestamp;
- SBOM;
- provenance/attestation where supported.

Production deploys use immutable image/artifact digests.

Never deploy production by mutable `latest` tag.

Human-readable tags may exist for convenience, but the deployed identity is the digest.

### Configuration and rules

Configuration has its own revision identity.

Examples:

- policy revision;
- scanner/ruleset revision;
- Rspamd configuration revision;
- deployment/IaC revision.

Do not overload the application Semantic Version to represent tenant policy/config changes.

### ML models

ML model versions are independent release artifacts and include:

- model ID/version;
- dataset version;
- training code/source revision;
- input schema version;
- evaluation;
- serving configuration;
- region rollout state.

## CI/CD stages

### 1. Pull-request validation

Every PR runs relevant checks.

Baseline:

- formatting;
- lint;
- compile/build;
- unit tests;
- integration tests appropriate to touched areas;
- frontend tests;
- secret scanning;
- SAST;
- dependency/SCA;
- license policy;
- SBOM generation/check;
- IaC scan when infrastructure changes;
- container build/scan when image definitions change;
- migration validation;
- architecture/document-link checks where possible;
- tenant-isolation/RBAC/security tests for affected areas.

PR CI must not have standing unrestricted production credentials.

### 2. Main-branch build

After merge:

- repeat required security/build checks;
- create immutable candidate artifacts;
- generate SBOM/provenance;
- sign/attest artifacts where supported;
- publish only to approved registry/storage;
- associate artifact with exact source SHA.

Artifacts are built once.

Do not rebuild different binaries/images separately for staging and production.

### 3. Environment promotion

Promote the **same immutable artifact digest**:

```text
source
  -> CI build
  -> immutable artifact
  -> development/test
  -> staging
  -> production
```

Environment-specific configuration/secrets remain external.

Do not compile customer/region secrets into images.

### 4. Production deployment

Production deployment requires:

- all mandatory checks passing;
- approved artifact digest;
- change/release record;
- migration plan;
- rollback/containment plan;
- production approval according to risk;
- region/deployment target explicitly selected.

No deployment should accidentally fan out to every region because a workflow omitted deployment scope.

## GitHub Actions / CI identity

The expected initial CI/CD platform is GitHub Actions because the repository is hosted on GitHub.

AWS access from CI/CD should use:

- GitHub OIDC;
- short-lived AWS role sessions;
- per-environment/per-region deployment roles;
- least privilege.

Do not store long-lived AWS access keys as GitHub repository secrets for normal deployments.

Separate roles for:

- read/build operations;
- development deployment;
- staging deployment;
- production deployment.

Production role assumption must require stronger controls than ordinary PR CI.

## GitHub environments

Use environment boundaries such as:

- `dev-za`;
- `staging-za`;
- `prod-za`;
- later `prod-zab`, `prod-eu`, etc.

Production environments should support:

- required reviewers/approval;
- environment-scoped secrets/variables;
- deployment history;
- restricted deployment branches/tags.

Region/deployment selection must be explicit.

## AWS deployment

Infrastructure is defined as code.

CI/CD should:

1. validate/format IaC;
2. security scan;
3. generate plan/change set;
4. require review for production-impacting changes;
5. apply using scoped OIDC role;
6. retain deployment evidence;
7. record result.

Avoid manual console drift.

Emergency console changes must be exceptional, audited and reconciled back into IaC immediately.

## Database migrations

Migrations are version-controlled.

Rules:

- migrations are immutable after production use;
- new change = new migration;
- backward-compatible rollout preferred;
- application/database compatibility considered during rolling deployment;
- destructive migration requires explicit review;
- backup/restore implications documented;
- migration failure has containment/recovery procedure.

Use expand/migrate/contract patterns where needed rather than destructive single-step changes.

## Secrets in CI/CD

CI/CD must never print:

- passwords;
- AWS credentials;
- OpenBao tokens;
- connector secrets;
- private keys;
- production session material.

Secrets are scoped to the minimum job/environment.

Prefer workload identity/OIDC and dynamic credentials.

## Build runners

Prefer ephemeral/managed runners initially.

If self-hosted runners are introduced:

- separate trust levels;
- do not share production-privileged runner with untrusted PR workloads;
- patch/harden;
- clean workspace;
- restrict network;
- monitor;
- treat runner compromise as credential compromise.

Fork/untrusted PRs must not receive privileged secrets.

## Artifact/registry security

Production images/artifacts:

- stored in approved registry;
- immutable by digest;
- vulnerability scanned;
- SBOM associated;
- provenance recorded;
- signed/attested where practical;
- retention policy defined.

Only approved CI identities may publish production artifacts.

## Release process

A release records:

- version;
- source SHA/tag;
- included PRs;
- artifact digests;
- SBOM/provenance;
- database migrations;
- configuration compatibility;
- known issues;
- security findings/exceptions;
- rollout plan;
- rollback plan.

Maintain a changelog/release notes appropriate to the stage of the project.

## Rollout strategy

Prefer staged deployment.

Examples:

- one non-production deployment;
- staging;
- one production deployment/node group;
- observe;
- continue.

Mail Plane changes require extra care because partial deployment can affect queue/transport behaviour.

Compatibility must be defined between:

- Postfix configuration;
- Mail Core;
- policy snapshots;
- scanner contract;
- database schema.

## Rollback

Rollback must restore a previously known-good artifact/configuration where safe.

Do not promise automatic rollback for irreversible database migrations.

For migrations, define forward-fix/restore strategy before deployment.

Rollback events are audited and observable.

## Production approvals

Risk-based approval is required.

Examples requiring explicit human approval:

- IAM/network/security-group change;
- authentication/RBAC change;
- production database migration;
- mail-routing/Postfix change;
- signing/DKIM changes;
- secrets/PKI changes;
- data-residency change;
- Deep AI permission/tool change;
- destructive operation.

AI agents may prepare changes and evidence but must not self-approve a production release.

## Emergency change process

Emergency production change:

- named incident/change owner;
- reason;
- limited scope;
- approval under emergency policy;
- audit/log evidence;
- rollback/containment;
- follow-up PR/IaC reconciliation;
- post-change review.

"Emergency" is not a bypass for traceability.

## CI/CD security monitoring

Alert/review:

- workflow file changes;
- failed protected checks;
- unexpected artifact publication;
- production deployment outside approved flow;
- OIDC role-assumption anomalies;
- secret-scanning findings;
- signing/provenance failure;
- branch-protection changes;
- production tag deletion/rewrite attempts.

## AI-agent rules

AI coding agents:

- work through branches/PRs when the environment supports it;
- do not push directly to protected `main`;
- do not modify branch protections to make work easier;
- do not disable failing security checks;
- do not add long-lived cloud credentials;
- do not deploy mutable `latest` artifacts;
- do not rewrite applied migrations;
- do not self-approve production;
- do not alter CI workflows without considering workflow-token/secret exposure;
- must update tests/docs when changing CI/CD behaviour.

## Human-review rules

Reviewers check:

- source change;
- workflow permission changes;
- artifact provenance;
- migration safety;
- region/deployment target;
- security findings;
- rollback/containment;
- Phase/architecture compliance.

## Phase -1 exit requirement

Before Phase 0 implementation begins, this policy must be accepted.

## Phase 0 implementation requirement

Phase 0 must implement the actual repository protections/workflows/tooling described here sufficiently for development to proceed safely.

## Production readiness

Production is blocked unless:

- protected branch/review controls are active;
- CI security gates run;
- OIDC/scoped AWS deployment identity is active;
- immutable artifact promotion is used;
- production approvals are configured;
- migration/rollback process is tested;
- release provenance/SBOM exists;
- production deployment history is auditable.

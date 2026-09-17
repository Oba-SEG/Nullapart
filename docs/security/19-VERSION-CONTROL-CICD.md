# Version Control, CI/CD and Release Security

**Status:** mandatory Phase -1 / Phase 0 engineering baseline.

## Purpose

Nullapart must have a predictable, auditable path from source change to production deployment.

Version control and CI/CD are security boundaries. A compromised repository, workflow, build runner, registry or deployment role can compromise the product even when application code is secure.

Detailed workflow implementation: `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`.

## Repository model

Nullapart uses a monorepo unless a future architecture decision explicitly changes that.

Do not create separate repositories merely to mirror conceptual services.

## Default branch

Canonical default branch:

- `main`

`main` remains releasable.

Do not use a long-lived `develop` branch as a second source of truth.

Use short-lived branches such as:

- `feature/<description>`;
- `fix/<description>`;
- `security/<description>`;
- `docs/<description>`;
- `infra/<description>`.

Branches are temporary and normally deleted after merge.

# Main branch protection — hard gate

## Rule

`main` must be protected before normal Phase 0 implementation PRs begin.

**No direct pushes to `main`.**

This applies to:

- human developers;
- AI coding agents;
- maintainers;
- administrators during normal operation.

Emergency changes still use an expedited reviewed PR/change path. Emergency status is not permission to push directly to `main`.

## Required protections

At minimum:

- pull request required before merge;
- direct pushes denied;
- force pushes denied;
- branch deletion denied;
- required status checks;
- at least one qualified review;
- security/CODEOWNERS review for protected paths once actual owners are assigned;
- stale approval dismissal for security-relevant changes;
- conversation resolution where supported;
- merge only after required checks reflect current source;
- no automation self-approval;
- administrator/bypass permissions not used for routine direct pushes.

Production release tags/rulesets are also protected against casual deletion/rewrite.

## Hard activation requirement

Unlike optional convenience controls, protected `main` is not satisfied by a documentation-only compensating process.

If the repository/organization plan cannot enforce no-direct-push protection, **normal implementation does not proceed until an equivalent enforceable repository-control mechanism is available**.

The current ChatGPT GitHub integration cannot administer the required repository ruleset/branch-protection setting. Activation therefore requires an authorized GitHub repository/organization administrator.

Record evidence of the active rule in Phase 0 / compliance production-readiness records.

## Protection monitoring

Alert/review unexpected:

- branch/ruleset protection changes;
- bypass use;
- force-push/deletion attempts;
- required-check removal;
- production tag/rule changes.

# Pull requests

Every material change describes:

- problem/objective;
- owning roadmap phase;
- architecture/security documents affected;
- trust-boundary/data-classification impact;
- API/event/schema compatibility;
- tenant/feature/reliability impact where relevant;
- implementation summary;
- tests;
- migration impact;
- UI impact;
- audit/observability impact;
- rollback/containment;
- security findings/exceptions.

Small documentation corrections may use a lighter description but still require review when they change security/architecture requirements.

## Review requirements

At least one qualified reviewer is required.

Additional/higher-confidence review is required for security-critical paths such as:

- authentication/authorization;
- tenant routing/RLS/isolation;
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
- database migrations affecting security boundaries;
- System security floors/kill switches;
- Tier-3 SLO/error-budget semantics.

No author/self-approval is sufficient for high-risk production changes.

## CODEOWNERS

Use CODEOWNERS or equivalent enforced review policy for high-risk areas after actual maintainers are assigned.

Expected ownership coverage includes:

- `.github/workflows/` and repository-agent instruction adapters;
- `infrastructure/`;
- `mail/`;
- `control/identity/`;
- `control/audit/`;
- tenant-routing/security-sensitive Rust crates;
- `docs/security/`;
- security architecture;
- model/Deep-AI security configuration.

Do not invent GitHub usernames before owners are assigned.

# Commit and merge policy

Commits are attributable and traceable.

Prefer:

- signed commits/tags where practical;
- descriptive commit messages;
- no secrets;
- no accidental generated build artifacts;
- committed lockfiles where required for deterministic builds.

History rewriting on protected branches is prohibited.

Preferred ordinary merge style is squash merge unless the project deliberately standardizes another traceable strategy.

Maintain a clear mapping:

```text
reviewed PR -> source SHA -> CI artifact -> release -> deployment
```

# Versioning and artifacts

Product versions follow `docs/22-VERSIONING-RELEASE-MANAGEMENT.md`.

Every built release artifact records:

- product/component version;
- Git SHA;
- build ID;
- build time;
- SBOM;
- provenance/attestation where supported.

Production deploys use immutable image/artifact digests.

Never deploy production by mutable `latest` identity.

Configuration/policy/rules/models keep independent revision/version identities.

# CI/CD stages

## Pull-request validation

Every PR runs relevant checks including:

- formatting;
- lint/typecheck;
- compile/build;
- unit tests;
- relevant integration/security/UI tests;
- secret scanning;
- SAST;
- dependency/SCA;
- license policy;
- SBOM generation/check;
- IaC scan where applicable;
- container build/scan where applicable;
- migration validation;
- documentation consistency;
- tenant-isolation/RBAC/feature/reliability tests for affected areas.

PR CI has no standing production deployment credentials.

## Main build

After merge:

- repeat mandatory validation;
- build immutable candidate artifacts once;
- associate exact source SHA/version;
- generate SBOM/provenance;
- sign/attest where adopted;
- publish only to approved registry/storage.

Do not rebuild a different artifact independently for staging/production.

## Environment promotion

Promote the same immutable digest:

```text
source -> trusted CI build -> immutable artifact -> dev/test -> staging -> production
```

Environment configuration/secrets remain external.

## Production deployment

Requires:

- all mandatory checks passing;
- approved immutable digest;
- release/change record;
- migration plan where applicable;
- rollback/containment;
- human production approval;
- explicit region/deployment target;
- Tier-3 health/SLO observation where relevant.

No workflow may accidentally fan out to every region because target scope was omitted.

# GitHub Actions and identity

GitHub Actions is the initial CI/CD execution platform.

Use:

- minimum explicit workflow permissions;
- third-party actions pinned to reviewed immutable commit SHAs where practical;
- frozen/locked dependency installs;
- GitHub OIDC for AWS;
- short-lived role sessions;
- separate environment/region deployment roles;
- environment protections for production.

Do not store long-lived AWS deployment access keys for routine deployment.

PR workflows cannot assume production roles.

Expected GitHub environments include deployment-scoped names such as:

- `dev-za`;
- `staging-za`;
- `prod-za`;
- later other deployment-specific environments.

# AWS / IaC deployment

Infrastructure is code.

Pipeline:

1. format/validate;
2. security scan;
3. generate plan/change set;
4. review production-impacting changes;
5. apply with scoped OIDC role;
6. verify;
7. retain deployment evidence.

Manual console drift is exceptional, audited and reconciled into IaC.

# Database migrations

Migrations are version-controlled and immutable after production application.

Rules:

- new change = new migration;
- backward-compatible rollout preferred;
- destructive migration gets explicit review/recovery design;
- application/database compatibility considered during rolling deployment;
- expand/migrate/contract patterns used where appropriate.

# Secrets / runners / supply chain

CI/CD never prints secrets or Restricted customer content.

Prefer managed/ephemeral runners initially.

Self-hosted runners, if required, separate trust levels and do not run untrusted PR code in a production-privileged context.

Production artifacts are:

- from approved CI identity;
- immutable by digest;
- vulnerability scanned;
- SBOM-associated;
- provenance-recorded;
- signed/attested where adopted.

# Release and rollout

A release records:

- version/source SHA/tag;
- included PRs;
- artifact digests;
- SBOM/provenance;
- migrations;
- compatibility;
- known issues/security exceptions;
- rollout/rollback plan.

Prefer staged deployment and observe before expanding rollout.

Mail Plane changes receive additional queue/compatibility/failure scrutiny.

# Emergency changes

Emergency changes use an expedited but still reviewable/traceable path:

- named incident/change owner;
- short-lived security branch/PR;
- focused required checks;
- authorized review/approval;
- limited deployment scope;
- rollback/containment;
- post-change review.

Emergency is **not** a direct-push exception for `main`.

Zero-day emergency changes follow `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`.

# AI-agent rules

AI coding agents:

- use branches/PRs;
- never push directly to `main`;
- never modify/disable branch protection to complete a task;
- never disable failing security checks;
- never add long-lived cloud credentials;
- never deploy mutable `latest` artifacts;
- never rewrite applied migrations;
- never self-approve production;
- review workflow-token/secret exposure when changing Actions;
- update tests/docs when changing CI/CD behavior.

# Phase gates

## Phase -1

Accept this policy before implementation.

## Phase 0

Before normal implementation proceeds through the repository:

- protected `main` with no direct pushes is active and verified;
- PR workflow exists;
- required checks/reviews are configured;
- locked/frozen dependency installs exist;
- release artifact identity is immutable;
- GitHub Actions permissions are minimal;
- AWS OIDC trust is implemented before cloud deployment;
- production environment approval is configured before production use.

## Production readiness

Production is blocked unless:

- branch/review controls remain active;
- CI security gates run;
- OIDC/scoped AWS deployment identity is active;
- immutable artifact promotion is used;
- production approvals are configured;
- migration/rollback process is tested;
- release provenance/SBOM exists;
- production deployment history is auditable.

# GitHub Actions Architecture

**Status:** Phase 0 CI/CD implementation specification.

## Purpose

GitHub Actions is the initial CI/CD execution platform for Nullapart.

Workflows are security-critical code because they can build release artifacts, access repository contents and assume AWS deployment roles.

## Workflow set

Phase 0 should implement a small reusable set rather than many duplicated workflows.

### `pr.yml`

Trigger:

- pull request to `main`.

Responsibilities:

- changed-path classification;
- formatting/lint/typecheck;
- Rust/frontend builds;
- unit tests;
- applicable integration/security/UI tests;
- secret scanning;
- dependency/SCA/license checks;
- migration validation;
- IaC/container scans when applicable;
- documentation link/consistency checks;
- SBOM generation/validation as implementation matures.

No production deployment credentials.

### `main.yml`

Trigger:

- merge/push to protected `main`.

Responsibilities:

- repeat mandatory validations;
- build immutable application/container artifacts once;
- attach source SHA/build/version metadata;
- generate SBOM/provenance;
- sign/attest where adopted;
- publish approved immutable artifacts.

### `release.yml`

Trigger:

- controlled release/tag creation or workflow dispatch under approved policy.

Responsibilities:

- validate release/version/tag;
- ensure source SHA is from approved `main` state;
- resolve immutable artifacts built from that SHA;
- generate release notes/evidence;
- never rebuild a different production artifact from the same tag.

### `deploy.yml` reusable workflow

Called with explicit:

- environment;
- region/deployment;
- artifact digest/version;
- migration mode where applicable.

Responsibilities:

- request GitHub OIDC token only in deployment job;
- assume scoped AWS role;
- verify artifact/provenance;
- deploy same immutable digest;
- run migrations in controlled step;
- verify health/security;
- record deployment result.

Production calls require GitHub Environment approvals/protections.

### `scheduled-security.yml`

Scheduled/manual checks such as:

- dependency vulnerability review;
- container/base-image refresh status;
- EOL/runtime checks;
- SBOM/security posture tasks;
- documentation/control drift checks where automation exists.

Scheduled workflow failures create actionable security/maintenance work rather than being silently ignored.

## Workflow permissions

Default to:

```yaml
permissions:
  contents: read
```

Each job/workflow requests only additional permissions it needs.

Examples:

- `id-token: write` only for jobs that actually need OIDC;
- package write only for artifact publishing;
- security-events write only for approved code-scanning upload steps.

Do not give every workflow `write-all`.

## AWS OIDC

Use GitHub OIDC for AWS access rather than long-lived AWS access keys.

AWS trust policy must constrain the GitHub OIDC subject/audience to the expected repository/environment/branch or immutable repository identity format supported by the repository.

Separate AWS roles for:

- non-production deployment;
- staging;
- production per region/deployment where appropriate.

A PR workflow must not be able to assume a production role.

## GitHub Environments

Expected environment model:

- `dev-za`;
- `staging-za`;
- `prod-za`;
- later `prod-zab`, `prod-eu`, etc.

Production environment should require authorized human review/approval and restrict deployable refs.

Environment-scoped secrets/variables must be minimized; prefer OIDC/dynamic credentials.

## Third-party Actions

Third-party actions must be reviewed and pinned to full immutable commit SHAs where practical.

Do not use floating `@main` references.

Tags may move; a full commit SHA provides the immutable reviewed action reference.

Automated dependency tooling can open reviewed PRs to update action SHAs.

## `GITHUB_TOKEN`

Use minimum permissions.

Do not allow automation to approve/merge its own sensitive PR simply because the token can be configured to do so.

## Untrusted pull requests

Untrusted/fork PR code must not receive production secrets or privileged tokens.

Avoid `pull_request_target` for running untrusted checked-out PR code with elevated repository secrets/permissions.

If such an event is ever required, it needs a separate threat model and must not execute attacker-controlled code in the privileged context.

## Checkout

When checkout credentials are not needed after source retrieval, disable persistent credentials.

Do not leave an unnecessarily writable repository token available to arbitrary build steps.

## Caching

CI caches improve performance but are a supply-chain boundary.

Rules:

- cache only appropriate build/dependency outputs;
- key using lockfile/toolchain/relevant inputs;
- do not treat cache contents as trusted executable release artifacts;
- privileged production deployment jobs should not consume an untrusted PR-poisoned cache without verification/rebuild;
- release artifacts are built/verified in the trusted main/release context.

## Artifacts

CI artifacts have:

- explicit retention;
- no secrets/Restricted customer data;
- source/build identity;
- integrity/provenance where needed.

Test artifacts/logs must be sanitized.

## Concurrency

Use workflow/job concurrency controls where duplicate execution could create conflicting deployment/migration operations.

Examples:

- one production deployment per deployment/environment at a time;
- migration serialization;
- newer superseding non-production build may cancel older pending work where safe.

Do not cancel an in-progress production deployment blindly without a defined rollback/containment model.

## Matrix builds

Use matrices deliberately for compatibility/security testing, not just to multiply cost.

Examples:

- supported Rust/toolchain target where required;
- frontend supported Node version plus optional next-version compatibility lane;
- targeted database/service versions during planned upgrade evaluation.

Production uses one explicitly approved runtime/toolchain version.

## Dependency installation

Use frozen/locked dependency installs.

Examples conceptually:

- `cargo ... --locked`;
- `pnpm install --frozen-lockfile`.

CI must fail on unexpected dependency resolution drift.

## Docker/container builds

Build once from reviewed source.

Record:

- source SHA;
- image digest;
- version;
- base image digest where applicable;
- SBOM;
- scan result.

Deploy by digest.

## Database migrations

Workflow sequence separates:

- migration validation in PR;
- approved migration execution in deployment;
- application rollout;
- post-deploy verification.

Destructive/irreversible migrations require explicit approval and recovery plan.

## Secrets

Never echo secrets.

Use masking and avoid command-line patterns that expose secrets in process/log output.

Production secrets belong in runtime secret systems, not copied into GitHub merely because Actions needs to deploy the application.

## Self-hosted runners

Use managed/ephemeral runners initially where possible.

If self-hosted runners are later required for private networking/GPU/special builds:

- isolate trust levels;
- never run untrusted PR code on a production-privileged runner;
- patch/harden;
- use ephemeral workers where possible;
- restrict network/credentials;
- wipe workspace/state;
- monitor runner registration/use.

## AI coding agents

AI agents may:

- propose/edit workflow files;
- add tests/checks;
- prepare release notes/config.

They must not:

- weaken permissions/checks to get green CI;
- add long-lived cloud credentials;
- self-approve production deployments;
- switch an action from pinned SHA to floating tag/branch without review;
- introduce `pull_request_target` privileged execution casually;
- make production environment approval optional.

## Phase 0 acceptance

Before normal feature implementation proceeds through CI:

- PR workflow exists;
- required checks are wired to branch protection/compensating governance;
- minimum workflow permissions are used;
- dependency installs are locked;
- release artifact identity is immutable;
- AWS OIDC deployment trust is designed/implemented before cloud deploys;
- production environment approvals are configured before production use.

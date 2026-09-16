# Patching and Dependency Version Management

**Status:** mandatory Phase -1/Phase 0 lifecycle control.

## Principle

Versions are deliberate, reproducible and continuously maintained.

"Latest" is not a production dependency version.

## Dependency inventory

Track at minimum:

- Rust crates;
- frontend/npm packages;
- OS/base images;
- Postfix;
- Rspamd;
- ClamAV;
- OpenBao;
- ZITADEL;
- n8n;
- scanner/parser binaries/libraries;
- model-serving dependencies;
- AWS/IaC providers/modules;
- GitHub Actions;
- model weights/adapters;
- scanner signatures/rulesets.

## Pinning

### Rust

- commit `Cargo.lock` for deployable applications/workspace;
- constrain dependency versions intentionally;
- review lockfile changes.

### Frontend

- use `pnpm`;
- commit `pnpm-lock.yaml`;
- pin the package-manager version through project metadata/tooling;
- use exact resolved versions from the lockfile;
- avoid unreviewed floating CDN dependencies.

### Containers

- pin base-image version;
- production release resolves to immutable image digest;
- rebuild images when security/base packages change.

### GitHub Actions

Pin third-party actions to reviewed immutable commit SHAs where practical, not floating branches such as `@main`.

### IaC

Commit provider/module lock files where supported.

### Models/rules

Pin model revisions/checksums and scanner/ruleset versions required for reproducibility.

## Automated update PRs

Use an automated dependency update mechanism such as Renovate or Dependabot.

Update PRs remain subject to:

- CI;
- tests;
- license checks;
- security scanning;
- review.

Do not auto-merge security-sensitive major upgrades without validation.

## Upgrade categories

### Emergency

Actively exploited/critical vulnerabilities.

Use incident/emergency-change process where needed.

### Security maintenance

Security patches within supported release lines.

Prioritize according to vulnerability-management SLAs.

### Routine

Regular patch/minor dependency refresh.

Set a recurring cadence so the project does not accumulate a large unmaintainable jump.

### Major

Major framework/runtime upgrades require compatibility testing and may require threat-model/architecture review.

## Runtime/OS patching

### Managed services

Use supported AWS maintenance mechanisms and controlled maintenance windows while preserving HA.

### Dedicated mail EC2

Patch using rolling/drained nodes:

1. stop taking new traffic where appropriate;
2. drain/verify queue safety;
3. patch/reboot;
4. health/security check;
5. return to service;
6. repeat other node.

Never patch all MX/outbound nodes simultaneously without tested failover.

### ECS capacity

Use supported managed/Fargate/EC2 capacity maintenance strategy.

Replace/recycle container hosts rather than relying on indefinitely in-place drift.

## Container patching

Do not `apt upgrade` a running production container as the normal strategy.

Rebuild a new immutable image from patched inputs, test it, and promote the new digest.

## Scanner signature/ruleset updates

ClamAV/signatures and other security rules may update more frequently than application releases.

Define:

- trusted source;
- signature verification where available;
- staging/canary validation;
- version telemetry;
- rollback/fallback;
- stale-signature alert.

## Support/EOL

Do not run EOL:

- Node.js;
- base OS;
- database engine;
- security scanner;
- major framework

in production without a documented time-limited exception.

## Patch evidence

Record:

- component;
- old/new version;
- reason/CVE;
- affected deployments;
- test result;
- rollout result;
- rollback;
- date/owner.

## CI checks

CI should detect:

- vulnerable dependencies;
- stale/EOL critical runtimes where tooling exists;
- unexpected lockfile changes;
- unpinned container/action dependencies;
- license changes.

## AI-agent rules

AI agents must:

- preserve lockfiles;
- avoid broad dependency upgrades unrelated to the task;
- explain security-sensitive version changes;
- not replace pinned dependencies with floating `latest`;
- not suppress vulnerability findings to make CI pass;
- update compatibility/tests/documentation for major upgrades.

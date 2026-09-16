# Supply Chain Security

## Dependency policy

Every dependency/component requires origin, version, license, material project-health review, vulnerability monitoring and upgrade strategy.

## SBOM

Generate and retain SBOMs by release.

## Build provenance

Production artifacts are built by controlled CI.

Record source commit, build workflow, dependency lockfiles, image digest and release version.

## Container images

Use minimal bases, pinned versions/digests where practical, non-root execution where possible, image scanning and registry access controls.

Sign/verify artifacts/images where supported.

## Registries

Only approved registries/sources feed production.

Prevent dependency confusion and typosquatting through package-source/namespace controls.

## Third-party binaries/rules/models

Scanner engines, signature/ruleset feeds and model weights are supply-chain inputs. Verify provenance/signatures/checksums where available.

## CI/CD

CI credentials are scoped and short-lived where possible.

Protect release workflows, deployment roles, signing keys, registries and IaC state.

Compromise of CI must not automatically grant unrestricted cross-region production access.

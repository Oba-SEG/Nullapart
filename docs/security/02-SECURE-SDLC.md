# Secure SDLC and Change Control

## Principle

Security controls are part of normal development, not a release-stage checklist.

## Source control

Require:

- protected default branch;
- pull requests for production code/config;
- review by at least one qualified reviewer;
- security review for sensitive areas;
- signed/traceable commits where practical;
- no direct production changes from developer workstations;
- CODEOWNERS or equivalent for security-critical paths.

Security-critical paths include:

- authentication/authorization;
- audit;
- secrets/PKI;
- Postfix/Rspamd/security policy;
- scanner sandboxing;
- artifact access;
- Deep AI tool permissions;
- regional/data-residency controls;
- infrastructure/IAM;
- CI/CD.

## CI security gates

Before merge/release:

- unit/integration/security tests;
- secret scanning;
- SAST;
- dependency/SCA scan;
- SBOM generation;
- container-image scan;
- IaC/security-policy scan;
- license-policy check;
- lint/format/build;
- tests for tenant isolation/RBAC where relevant.

Critical findings block release unless a documented exception exists.

## Environments

Separate:

- development;
- test/staging;
- production.

Production secrets/data must not be copied casually into lower environments.

Synthetic/sanitized data is preferred for development/testing.

## Change control

Production changes must record:

- change owner;
- reason;
- affected deployment/region;
- risk;
- test evidence;
- rollback plan;
- approval;
- execution result.

Emergency changes follow an expedited but auditable path and require post-change review.

## Rollback

Every production release/change must have a defined rollback or containment path.

Schema/data migrations must account for backward compatibility and rollback limitations.

## Definition of Done

Security-sensitive features require:

- threat model;
- backend;
- UI where required;
- server-side authorization;
- audit;
- observability;
- tests;
- failure handling;
- runbook;
- documentation.

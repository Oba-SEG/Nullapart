# Phase -1 — Security Program Gate

## Objective

Establish the mandatory security governance, engineering controls, operational processes and evidence model **before product implementation begins**.

This phase does not build product features. It defines the rules under which every later phase is designed, implemented, reviewed and operated.

## Required reading

- `SECURITY.md`
- `docs/security/README.md`
- all documents under `docs/security/`
- `docs/00-ARCHITECTURE.md`
- `docs/diagrams/09-trust-boundaries.mmd`
- `docs/diagrams/12-security-program-gate.mmd`

## Deliverables

### Governance

- named security/product/platform/data/incident owners;
- risk acceptance process;
- security exception process;
- security review checkpoints;
- production readiness security approval model.

### Engineering security

- threat-modeling process;
- secure SDLC/change-control process;
- source-control protections;
- CI security gates;
- dependency/SBOM/license controls;
- container/IaC scanning expectations;
- vulnerability management and remediation targets.

### Version control and delivery security

Define and accept:

- protected `main` branch policy;
- pull-request/review requirements;
- CODEOWNERS strategy for security-critical paths;
- signed/traceable release/tag policy;
- CI security gates;
- artifact/SBOM/provenance requirements;
- GitHub Actions permission model;
- GitHub OIDC -> AWS role model;
- environment promotion;
- production approval;
- database migration policy;
- release/versioning policy;
- rollback/emergency-change process.

See `docs/security/19-VERSION-CONTROL-CICD.md` and `docs/22-VERSIONING-RELEASE-MANAGEMENT.md`.

### Operational security

- incident-response process;
- access governance and break-glass process;
- secrets/key lifecycle;
- network baseline;
- backup/DR policy;
- mail trust/failure model;
- required runbook inventory;
- security monitoring/metrics.

### Data/privacy

- data-classification matrix;
- regional handling rules;
- retention/deletion rules;
- training-data governance;
- third-party data-transfer rules.

## AI-agent instructions

An AI developer operating before Phase -1 completion may assist with documentation, threat analysis, test design and architecture review.

It must not:

- create production feature implementations;
- silently choose weaker security defaults;
- create bypasses because security infrastructure is not yet implemented;
- invent risk acceptance;
- assume "internal" means trusted.

When a requested change conflicts with Phase -1 rules, the agent should surface the conflict and implement only after the architecture/security rule has been intentionally changed.

## Human-developer instructions

Human reviewers must ensure the security program is actionable rather than aspirational.

Every control should have:

- an owner;
- a trigger/frequency;
- expected evidence;
- enforcement point;
- exception process.

## Acceptance evidence

Phase -1 evidence includes:

- complete security documentation;
- named ownership;
- documented security gates;
- approved data-classification matrix;
- vulnerability SLAs;
- incident severity/process;
- access-review cadence;
- security-exception template/process;
- runbook inventory;
- production-readiness checklist;
- accepted version-control/CI/CD/release policy.

## Exit criteria

Phase -1 is complete when:

- all required security-program documents are reviewed/accepted;
- no major architecture area lacks a threat-modeling requirement;
- all administrative accounts are planned under mandatory MFA;
- message content/secrets/data classes have explicit handling rules;
- build/release security gates are defined;
- incident/vulnerability/access/backup processes have owners;
- mail dependency failure behaviour is documented;
- the project owner explicitly accepts Phase -1.

## Must not be built yet

- production Mail Core;
- production SMTP pipeline;
- customer administration features;
- production scanners;
- production AI integrations;
- production AWS deployment.

Research/prototypes may exist only if clearly non-production and compliant with security/data rules.

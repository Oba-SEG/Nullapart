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

See:

- `docs/security/19-VERSION-CONTROL-CICD.md`;
- `docs/22-VERSIONING-RELEASE-MANAGEMENT.md`;
- `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`.

### Operational security

- incident-response process;
- access governance and break-glass process;
- secrets/key lifecycle;
- network baseline;
- backup/DR policy;
- mail trust/failure model;
- required runbook inventory;
- security monitoring/metrics.

### Application-security invariants

Accept explicit standards for:

- authenticated-principal scoped filtering;
- object ownership/BOLA/IDOR checks;
- server-side authorization;
- client vs server validation;
- canonicalization;
- PostgreSQL RLS defense in depth;
- browser session/token storage;
- CSRF;
- idempotency;
- safe errors;
- SSRF protections;
- OAST;
- mass-assignment protection;
- bounded pagination/search/export.

See `docs/security/20-APPLICATION-SECURITY-CONTROLS.md`.

### Rate limiting, patching and business logic

Define and accept:

- web/API rate-limit layers and failure semantics;
- SMTP connection/message/bulk rate-control rules;
- high-risk action limits;
- dependency pinning/update policy;
- runtime/container/host patch process;
- EOL policy;
- business state-machine/policy-hierarchy invariants;
- concurrency/idempotency rules for business operations.

See:

- `docs/security/22-RATE-LIMITING-ABUSE-PROTECTION.md`;
- `docs/security/23-PATCHING-DEPENDENCY-VERSIONS.md`;
- `docs/security/24-BUSINESS-LOGIC-POLICY-SECURITY.md`.

### Cryptographic trust and message integrity

Define and accept:

- browser/public PKI strategy;
- internal mTLS/private-PKI strategy;
- explicit rule that browser HPKP is not used;
- approval/rotation/recovery requirements for any future non-browser pinning;
- HMAC-SHA-256 webhook/event signing pattern where shared-secret integrity is appropriate;
- replay protection, key rotation and constant-time verification rules.

See:

- `docs/security/25-CERTIFICATE-TRUST-PINNING.md`;
- `docs/security/26-HMAC-SIGNING-WEBHOOKS.md`.

### API compatibility and feature governance

Define and accept:

- initial `/api/v1` Control Plane compatibility contract;
- event/scanner/policy/AI skill schema versioning;
- deprecation/breaking-change process;
- server-authoritative feature-switch classes;
- kill-switch behavior;
- feature flag ownership/expiry/audit;
- feature-addition threat/data/API/UI/test checklist.

See `docs/27-API-VERSIONING-FEATURE-FLAGS.md`.

### Package compatibility

Define a stack-level compatibility process rather than selecting packages independently.

Require:

- exact implementation lockfiles;
- runtime/toolchain compatibility matrix;
- peer dependency review;
- frozen CI installs;
- grouped ecosystem upgrades;
- production ML/CUDA/model compatibility testing per target environment.

See `docs/26-PACKAGE-COMPATIBILITY.md`.

### ML / LLM capability and tool governance

Before production AI work, define:

- skill registry/versioning;
- allowed data classes;
- tool allowlists;
- read-only-first tool model;
- server-enforced authorization for every tool;
- prompt-injection boundaries;
- structured output schemas;
- model/skill evaluations;
- context/token budgets;
- training-data provenance/governance;
- rule that models cannot directly self-authorize administrative/remediation actions.

See `docs/25-AI-LLM-SKILLS-TOOLS.md`.

### Coding-agent governance

AI coding agents operate under:

- root `AGENTS.md`;
- `docs/ai/CODING-AGENT-OPERATING-MODEL.md`.

The coding-agent model defines project skills, minimal-context loading, token/context discipline, escalation triggers and completion evidence.

Coding-agent repository/cloud permissions are never treated as production LLM permissions.

### Compliance assurance

Define:

- control register/evidence model;
- applicability/ownership process;
- privacy/data-residency evidence;
- third-party review evidence;
- explicit prohibition on unverified certification/compliance claims;
- initial compliance documentation/register structure under `docs/compliance/`.

See `docs/security/21-COMPLIANCE-ASSURANCE.md`.

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
- assume "internal" means trusted;
- expand its own project/tool permissions into production AI capability assumptions.

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
- accepted version-control/CI/CD/release policy;
- accepted application-security baseline;
- accepted compliance assurance/evidence process;
- accepted TLS trust/pinning and HMAC/webhook policy;
- accepted API/versioning/feature-switch policy;
- accepted ML/LLM skill/tool governance;
- accepted coding-agent operating model;
- accepted package-compatibility process.

## Exit criteria

Phase -1 is complete when:

- all required security-program documents are reviewed/accepted;
- no major architecture area lacks a threat-modeling requirement;
- all administrative accounts are planned under mandatory MFA;
- message content/secrets/data classes have explicit handling rules;
- build/release security gates are defined;
- incident/vulnerability/access/backup processes have owners;
- mail dependency failure behaviour is documented;
- API/feature/AI/tool/cryptographic compatibility rules are explicit;
- the project owner explicitly accepts Phase -1.

## Must not be built yet

- production Mail Core;
- production SMTP pipeline;
- customer administration features;
- production scanners;
- production AI integrations;
- production AWS deployment.

Research/prototypes may exist only if clearly non-production and compliant with security/data rules.

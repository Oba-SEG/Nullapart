# Phase -1 — Security Program Gate

## Objective

Establish the mandatory security governance, engineering controls, operational processes and evidence model **before product implementation begins**.

This phase does not build product features. It defines the rules under which every later phase is designed, implemented, reviewed and operated.

## Required reading

- `SECURITY.md`
- `docs/security/README.md`
- all documents under `docs/security/`
- `docs/00-ARCHITECTURE.md`
- `docs/16-BUILD-ROADMAP.md`
- `docs/29-TENANT-FEATURE-ROUTING.md`
- `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`
- `docs/ai/AGENT-DISCOVERY.md`
- `docs/engineering/CODE-STANDARDS.md`
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
- code standards/formatting/static-analysis requirements;
- dependency/SBOM/license controls;
- container/IaC scanning expectations;
- vulnerability management and remediation targets.

### Version control and delivery security

Define and accept:

- protected `main` as a hard requirement;
- **no direct pushes to `main`**, including routine administrator work;
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

Emergency changes still use expedited PR/review/checks, not a direct push.

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

### Tenant context, routing and overrides

Accept a single application-boundary tenancy model:

- region/deployment is selected before customer scope;
- authenticated server/session state resolves `TenantContext`;
- client tenant IDs are navigation inputs, never authorization;
- jobs/events/caches carry explicit deployment/customer scope;
- RLS context is transaction-scoped;
- feature-switch precedence is System kill/security floor -> deployment -> tenant -> default;
- tenant override cannot weaken a higher security floor;
- override reason/owner/revision/expiry/audit are explicit.

See `docs/29-TENANT-FEATURE-ROUTING.md`.

### Reliability / SRE

Accept the Nullapart Tier-3 internal reliability model:

- critical capability classification;
- per-capability SLI/SLO;
- error budgets;
- multi-window burn-rate alerting;
- RTO/RPO;
- backpressure/load shedding;
- failure-domain testing;
- runbook/ownership requirements.

Tier 3 is an internal reliability classification, not an external certification claim.

See `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`.

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

### Zero-day intelligence and handling

Accept an accelerated process for newly disclosed/actively exploited vulnerabilities:

- intelligence sources;
- explicit exposure states;
- emergency severity/containment;
- feature/parser kill switches;
- emergency patch path;
- supply-chain compromise handling;
- retrospective hunt;
- rescanning/reprocessing;
- credential/session/key review;
- evidence/metrics/tabletop requirements.

Do not wait for CVE/CVSS finalization when credible exploitation warrants containment.

See `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`.

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
- deployment + tenant override semantics;
- kill-switch behavior;
- feature flag ownership/expiry/audit;
- feature-addition threat/data/API/UI/test/reliability checklist.

See:

- `docs/27-API-VERSIONING-FEATURE-FLAGS.md`;
- `docs/29-TENANT-FEATURE-ROUTING.md`.

### Package compatibility

Define a stack-level compatibility process rather than selecting packages independently.

Require exact lockfiles, runtime/toolchain compatibility matrix, peer dependency review, frozen CI installs, grouped ecosystem upgrades and production ML/CUDA/model compatibility testing per target environment.

See `docs/26-PACKAGE-COMPATIBILITY.md`.

### ML / LLM capability and tool governance

Before production AI work, define skill registry/versioning, allowed data classes, tool allowlists, read-only-first tools, server authorization for every tool, prompt-injection boundaries, structured outputs, evaluations, context/token budgets, training-data governance and the rule that models cannot directly self-authorize administrative/remediation actions.

See `docs/25-AI-LLM-SKILLS-TOOLS.md`.

### Coding-agent governance

AI coding agents operate under:

- root `AGENTS.md`;
- `docs/ai/CODING-AGENT-OPERATING-MODEL.md`;
- `docs/ai/AGENT-DISCOVERY.md`.

Required coverage includes OpenAI Codex and OpenCode through root `AGENTS.md`, plus thin adapters for other selected agent tools.

The coding-agent model defines project skills, minimal-context loading, token/context discipline, escalation triggers and completion evidence.

Coding-agent repository/cloud permissions are never treated as production LLM permissions.

Agent instructions are not enforcement: CI/tests/RLS/review/protected `main` remain mandatory.

### Compliance assurance

Define:

- control register/evidence model;
- applicability/ownership process;
- privacy/data-residency evidence;
- third-party review evidence;
- explicit prohibition on unverified certification/compliance claims;
- initial documentation/register structure under `docs/compliance/`.

See `docs/security/21-COMPLIANCE-ASSURANCE.md`.

### Data/privacy

- data-classification matrix;
- regional handling rules;
- retention/deletion rules;
- training-data governance;
- third-party data-transfer rules.

## AI-agent instructions

An AI developer operating before Phase -1 completion may assist with documentation, threat analysis, test design and architecture review.

It must not create production feature implementations, silently choose weaker security defaults, create bypasses because security infrastructure is absent, invent risk acceptance, assume internal means trusted, expand coding-agent permissions into production AI assumptions, weaken reliability gates or autonomously deploy zero-day fixes.

## Human-developer instructions

Human reviewers must ensure the security program is actionable rather than aspirational.

Every control should have an owner, trigger/frequency, expected evidence, enforcement point and exception process.

## Acceptance evidence

Phase -1 evidence includes:

- complete security documentation;
- named ownership;
- documented security gates;
- approved data-classification matrix;
- vulnerability and zero-day response process;
- incident severity/process;
- access-review cadence;
- security-exception process;
- runbook inventory;
- production-readiness checklist;
- accepted protected-main/CI/CD/release policy;
- accepted application-security baseline;
- accepted tenant context/routing/feature-override model;
- accepted Tier-3 reliability/SLO/burn-rate model;
- accepted compliance assurance/evidence process;
- accepted TLS/HMAC policy;
- accepted API/versioning/feature-switch policy;
- accepted ML/LLM skill/tool governance;
- accepted coding-agent operating/discovery model;
- accepted package-compatibility process;
- accepted code standards/formatting/static-analysis baseline.

## Exit criteria

Phase -1 is complete when:

- all required security/engineering program documents are reviewed/accepted;
- no major architecture area lacks a threat-modeling requirement;
- all administrative accounts are planned under mandatory MFA;
- message content/secrets/data classes have explicit handling rules;
- tenant routing/override rules are explicit;
- Tier-3 reliability/SLO/error-budget rules are explicit;
- zero-day intake/containment/patch/hunt process is explicit;
- build/release security gates are defined;
- incident/vulnerability/access/backup processes have owners;
- mail dependency failure behaviour is documented;
- API/feature/AI/tool/cryptographic compatibility rules are explicit;
- coding-agent discovery includes Codex and OpenCode;
- the project owner explicitly accepts Phase -1.

## Must not be built yet

- production Mail Core;
- production SMTP pipeline;
- customer administration features;
- production scanners;
- production AI integrations;
- production AWS deployment.

Research/prototypes may exist only if clearly non-production and compliant with security/data rules.

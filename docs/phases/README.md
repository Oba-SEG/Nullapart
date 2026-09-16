# Nullapart Phase Specifications

These documents are the execution specifications for Nullapart implementation.

They are written for both human engineers and AI coding agents.

## Required working method

For any implementation task:

1. if an AI coding agent is used, read root `AGENTS.md` first;
2. identify the owning phase;
3. read that phase specification completely;
4. read its referenced architecture/security documents;
5. list affected contracts/trust boundaries before coding;
6. preserve global architecture rules;
7. implement security/audit/UI/tests with the feature;
8. verify the phase exit criteria affected by the change.

Do not use a later-phase document as justification to bypass an earlier prerequisite.

## Phase index

- [Phase -1 — Security Program Gate](PHASE--1-SECURITY-GATE.md)
- [Phase 0 — Contracts and Foundations](PHASE-0-CONTRACTS-FOUNDATIONS.md)
- [Phase 1 — SMTP and Mail Foundation](PHASE-1-MAIL-FOUNDATION.md)
- [Phase 2 — Scanner Fabric and Quarantine](PHASE-2-SCANNER-FABRIC.md)
- [Phase 3 — Control Plane and Administration](PHASE-3-CONTROL-PLANE.md)
- [Phase 4 — Inline ML](PHASE-4-INLINE-ML.md)
- [Phase 5 — DMARC/BIMI and Domain Security](PHASE-5-DMARC-BIMI.md)
- [Phase 6 — Outbound Intelligence](PHASE-6-OUTBOUND-INTELLIGENCE.md)
- [Phase 7 — Regional Deep AI](PHASE-7-DEEP-AI.md)
- [Phase 8 — Connectors and Remediation](PHASE-8-CONNECTORS-REMEDIATION.md)
- [Phase 9 — Operational Automation and Production Hardening](PHASE-9-OPERATIONS-HARDENING.md)

## Cross-cutting baselines every phase inherits

Every phase inherits, as applicable:

- [Application Security Control Baseline](../security/20-APPLICATION-SECURITY-CONTROLS.md)
- [Rate Limiting and Abuse Protection](../security/22-RATE-LIMITING-ABUSE-PROTECTION.md)
- [Patching and Dependency Version Management](../security/23-PATCHING-DEPENDENCY-VERSIONS.md)
- [Business Logic and Policy Security](../security/24-BUSINESS-LOGIC-POLICY-SECURITY.md)
- [Certificate Trust, mTLS and Pinning](../security/25-CERTIFICATE-TRUST-PINNING.md)
- [HMAC Signing and Webhook Security](../security/26-HMAC-SIGNING-WEBHOOKS.md)
- [Version Control, CI/CD and Release Security](../security/19-VERSION-CONTROL-CICD.md)
- [GitHub Actions Architecture](../28-GITHUB-ACTIONS-ARCHITECTURE.md)
- [Compliance Assurance](../security/21-COMPLIANCE-ASSURANCE.md)
- [Frontend Architecture](../23-FRONTEND-ARCHITECTURE.md)
- [Container/Network Architecture](../24-CONTAINER-LOADBALANCING-NETWORK.md)
- [Package Compatibility and Upgrade Matrix](../26-PACKAGE-COMPATIBILITY.md)
- [API Versioning, Feature Flags and Feature Addition Governance](../27-API-VERSIONING-FEATURE-FLAGS.md)
- [ML / LLM Skills and Tool Governance](../25-AI-LLM-SKILLS-TOOLS.md) for ML/AI work;
- [Coding Agent Operating Model](../ai/CODING-AGENT-OPERATING-MODEL.md) for AI-assisted development.

Later phases do not get to redefine these controls casually.

## Cross-phase rule

A phase is an ownership/dependency boundary, not a reason to duplicate infrastructure.

Examples:

- authorization primitives belong in Phase 0/3 and are reused later;
- scanner contracts belong in Phase 0/2 and are reused by later scanners;
- durable events are one architecture reused by DMARC, notifications, AI and operations;
- one Admin Audit subsystem records later-phase administrative actions;
- one API-versioning convention is reused rather than invented per module;
- feature switches live in the versioned configuration architecture rather than a separate service;
- one HMAC/signature contract is reused where Nullapart-owned shared-secret signing is appropriate;
- one design system is extended, not reinvented per feature.

## When documentation and code disagree

Treat disagreement as a defect.

Do not let an AI agent or developer silently "update reality" by implementing something different.

Either:

1. change implementation to match architecture; or
2. deliberately review/update architecture and threat model first.

Record the decision.

# Nullapart Phase Specifications

These documents are the execution specifications for Nullapart implementation.

They are written for both human engineers and AI coding agents.

## Required working method

For any implementation task:

1. identify the owning phase;
2. read that phase specification completely;
3. read its referenced architecture/security documents;
4. list affected contracts/trust boundaries before coding;
5. preserve global architecture rules;
6. implement security/audit/UI/tests with the feature;
7. verify the phase exit criteria affected by the change.

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

## Cross-phase rule

A phase is an ownership/dependency boundary, not a reason to duplicate infrastructure.

Examples:

- authorization primitives belong in Phase 0/3 and are reused later;
- scanner contracts belong in Phase 0/2 and are reused by later scanners;
- durable events are one architecture reused by DMARC, notifications, AI and operations;
- one Admin Audit subsystem records later-phase administrative actions;
- one design system is extended, not reinvented per feature.

## When documentation and code disagree

Treat disagreement as a defect.

Do not let an AI agent or developer silently "update reality" by implementing something different.

Either:

1. change implementation to match architecture; or
2. deliberately review/update architecture and threat model first.

Record the decision.

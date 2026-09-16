# Nullapart Build Roadmap

**Audience:** human developers, AI coding agents, reviewers, security engineers and operators.

**Status:** authoritative implementation sequencing document.

This roadmap defines **what must exist before implementation, what each phase is allowed to change, what each phase must deliver, and the evidence required before moving forward**.

It is not a delivery-date estimate.

## How to use this roadmap

Before starting any work:

1. identify the current phase;
2. read this document;
3. read the detailed phase specification under `docs/phases/`;
4. read all architecture/security documents referenced by that phase;
5. confirm Phase -1 security controls applicable to the work;
6. identify affected trust boundaries/data classes;
7. implement backend and UI together where the capability has an administrative UI;
8. add tests, audit, observability and documentation in the same change;
9. satisfy the phase exit criteria before beginning work that depends on it.

AI agents must not infer missing architectural decisions from convenience. If a phase specification says a decision is not yet made, preserve the abstraction and do not silently lock the implementation.

Human developers should treat phase exit criteria as release gates, not suggestions.

## Global implementation rules

These rules apply to every phase.

### Security

- Security Program Phase -1 controls are mandatory.
- Every network API is authenticated.
- Authorization is server-side.
- No shared global service secret.
- Secrets never enter source control/frontend bundles.
- Message content is treated as hostile.
- Support never receives message body/raw MIME/attachment content.
- Administrative changes are audited.
- Customer/tenant boundaries are enforced in storage, queries, APIs and UI.
- Unknown/failed security analysis never silently becomes CLEAN.
- New trust boundaries require threat-model review.

### Architecture restraint

Do not recreate NexusSEG-style synchronous microservice chains.

Create a new process/service/container only when justified by:

- isolation;
- failure-domain separation;
- independently different scaling;
- resource profile;
- incompatible dependencies/runtime;
- security boundary.

Prefer module boundaries inside the Rust Mail Core or Control Backend before introducing a new network service.

### UI

If a feature is visible/manageable by an administrator, its UI is implemented at the same time as the backend.

No raw JSON UI.

Use the Nullapart neumorphic design system while preserving dense, accessible operational tables and timelines.

### Observability

- Application SDK telemetry -> regional SegLumberjack via Sentry-compatible protocol.
- Native Postfix/Rspamd/ClamAV telemetry -> regional collector -> appropriate observability path.
- AWS infrastructure telemetry -> CloudWatch.
- Admin Audit is authoritative and separate from observability.
- Sensitive message content/secrets are scrubbed.

### Data

- PostgreSQL is authoritative.
- Redis/Valkey is cache/runtime acceleration, not authoritative durable events.
- PostgreSQL transactional outbox + SQS is the preferred durable async path.
- S3 is the production artifact backend behind ArtifactStore.
- Customer content remains region/deployment bound unless explicitly approved otherwise.

### Required change evidence

Every material change should include, where applicable:

- design/architecture reference;
- threat-model update;
- code/config;
- migrations;
- backend authorization;
- audit events;
- UI;
- unit tests;
- integration tests;
- security tests;
- UI/E2E tests;
- observability;
- runbook/update notes;
- rollback/containment plan.

## Phase sequence

| Phase | Name | Primary outcome |
|---|---|---|
| -1 | Security Program Gate | Security governance/processes exist before code |
| 0 | Contracts and Foundations | Stable contracts, schemas, UI shell, testing/CI foundations |
| 1 | SMTP and Mail Foundation | Safe bidirectional mail movement without advanced scanners/AI |
| 2 | Scanner Fabric and Quarantine | Parallel security analysis, quarantine/hold and scanner UI |
| 3 | Control Plane and Administration | Identity, RBAC, tenants, policies, trace, audit and operations UI |
| 4 | Inline ML | Low-latency ML evidence integrated safely into policy |
| 5 | DMARC / BIMI / Domain Security | Report ingestion, telemetry, dashboards and domain-security monitoring |
| 6 | Outbound Intelligence | Bulk controls, behavioural detection and compromised-sender response |
| 7 | Regional Deep AI | Controlled deep analysis and model lifecycle outside normal mail hot path |
| 8 | Connectors and Remediation | M365/Google/directory/mailbox integration and retro-remediation |
| 9 | Operational Automation and Production Hardening | n8n/ClickUp workflows, production gates, resilience and operational maturity |

Detailed specifications:

- [Phase -1 — Security Program Gate](phases/PHASE--1-SECURITY-GATE.md)
- [Phase 0 — Contracts and Foundations](phases/PHASE-0-CONTRACTS-FOUNDATIONS.md)
- [Phase 1 — SMTP and Mail Foundation](phases/PHASE-1-MAIL-FOUNDATION.md)
- [Phase 2 — Scanner Fabric and Quarantine](phases/PHASE-2-SCANNER-FABRIC.md)
- [Phase 3 — Control Plane and Administration](phases/PHASE-3-CONTROL-PLANE.md)
- [Phase 4 — Inline ML](phases/PHASE-4-INLINE-ML.md)
- [Phase 5 — DMARC/BIMI/Domain Security](phases/PHASE-5-DMARC-BIMI.md)
- [Phase 6 — Outbound Intelligence](phases/PHASE-6-OUTBOUND-INTELLIGENCE.md)
- [Phase 7 — Regional Deep AI](phases/PHASE-7-DEEP-AI.md)
- [Phase 8 — Connectors and Remediation](phases/PHASE-8-CONNECTORS-REMEDIATION.md)
- [Phase 9 — Operational Automation and Production Hardening](phases/PHASE-9-OPERATIONS-HARDENING.md)

## Dependency rules

Phases express logical dependency, not necessarily a prohibition on preparatory research.

Allowed examples:

- benchmark Deep-AI candidates before Phase 7;
- prototype UI components before Phase 3;
- research DMARC parsing before Phase 5.

Not allowed:

- shipping a production subsystem whose prerequisites/gates have not passed;
- bypassing Phase -1 controls because work is "prototype";
- implementing customer-visible policy before authorization/audit contracts exist;
- introducing a network service whose trust/security model is not documented.

## Production-readiness gate

No deployment is production-ready merely because Phase 9 code exists.

Production readiness requires at minimum:

- Phase -1 security program accepted;
- implemented subsystem threat models reviewed;
- MFA/admin audit operational;
- tenant isolation tests passing;
- backup/restore tested;
- required runbooks exercised;
- SMTP commissioning complete;
- no unresolved Critical security finding;
- High findings resolved or formally time-limited with compensating controls;
- observability/alerting active;
- SQS/DLQ/outbox health visible;
- scanner failure semantics verified;
- regional data-residency controls verified;
- rollback/containment tested;
- external security testing completed as required.

## Definition of complete

A phase is complete only when:

1. its required deliverables exist;
2. acceptance tests pass;
3. documentation matches implementation;
4. security evidence exists;
5. UI/backend behaviour is consistent;
6. operational failure modes are observable;
7. exit criteria in the phase document are approved.

"Code works on a developer machine" is never sufficient phase completion.

# Nullapart Architecture Diagrams

Mermaid `.mmd` files in this directory are the **canonical architecture diagram sources**.

Do not duplicate Mermaid bodies manually in this README. If rendered SVG/PNG/embedded diagrams are added later, generate them automatically from these sources in CI.

Phase 0/1 conformance linkage is recorded in the
[2026-10-13 Phase 0/1 Authoritative Conformance Review](../reviews/2026-10-13-phase-0-1-conformance.md).
When a Phase 0/1 gate changes, update the relevant diagram source and the
dated conformance link instead of relying on prose-only claims.

## Diagram index

1. [System context](00-system-context.mmd)
   - Regional deployment, Mail/Control/Intelligence planes, Postfix reinjection, PostgreSQL/Redis/SQS/S3, audit and operations.

2. [Inbound mail flow](01-inbound-mail-flow.mmd)
   - SMTP restriction/Milter stages, durable queue, after-queue Mail Core handoff, shared scans, tenant-recipient partitioning, per-tenant policy and trusted reinjection.

3. [Outbound mail flow](02-outbound-mail-flow.mmd)
   - Tenant/source authorization, domain authorization, bulk/abuse controls, scanning, policy, signing and direct-MX/smart-host delivery.

4. [Regional AWS topology](03-regional-aws-topology.mmd)
   - Independent ZA/ZAB/EU-style deployments, regional control URLs and regional data/security infrastructure.

5. [Control-plane RBAC and impersonation](04-control-plane-rbac.mmd)
   - System/Support/Customer roles, ZITADEL boundary, product authorization and impersonation audit.

6. [Scanner fabric](05-scanner-fabric.mmd)
   - Expandable scanner capabilities and normalized SecurityFinding aggregation.

7. [Data and storage flow](06-data-storage-flow.mmd)
   - PostgreSQL source of truth, append-only audit, transactional outbox, Redis/Valkey cache, SQS durable async events, S3 artifacts and Postfix durable queue.

8. [Event and operations flow](07-event-operations-flow.mmd)
   - Transactional outbox -> SQS -> notifications/n8n/ClickUp/analytics, plus SegLumberjack and CloudWatch observability paths.

9. [Deep AI flow](08-deep-ai-flow.mmd)
   - Eligible security cases, scoped artifact access, regional OpenAI-compatible inference and structured AI findings.

10. [Security trust boundaries](09-trust-boundaries.mmd)
    - Public edge, private application/data/AI boundaries and external operational integrations.

11. [Observability architecture](10-observability-architecture.mmd)
    - Sentry-compatible application telemetry -> SegLumberjack, native daemon collector, CloudWatch infrastructure telemetry and authoritative audit/outbox separation.

12. [Administrative audit architecture](11-admin-audit-architecture.mmd)
    - Atomic mutation/audit/outbox pattern, RBAC-scoped UI, immutable audit checkpoints and diagnostic SegLumberjack correlation.

13. [Security program gate](12-security-program-gate.mmd)
    - Phase -1 governance/process controls before Phase 0, plus production-readiness/continuous-improvement feedback.

14. [CI/CD and release flow](13-cicd-release-flow.mmd)
    - Short-lived branch -> PR/review/security CI -> protected main -> immutable artifact -> same-digest environment promotion -> approved production deployment.

15. [Control-plane request security](14-control-plane-request-security.mmd)
    - HTTPS/session -> layered rate limit -> validation -> ownership authorization -> business logic -> RLS transaction/audit/outbox -> safe errors.

16. [Container/network topology](15-container-network-topology.mmd)
    - ALB/WAF web edge, direct Postfix MX nodes, ECS private workloads, private data/security services and controlled AI/network boundaries.

17. [Tenant context and feature routing](16-tenant-context-feature-routing.mmd)
    - Trusted TenantContext resolution, server-side feature evaluation, System/deployment/tenant/default precedence, authorization and RLS-protected data access.

18. [Tier-3 SLO and burn-rate flow](17-tier3-slo-burn-rate.mmd)
    - SLI -> SLO/error budget -> fast/sustained/slow burn alert paths -> runbook/containment -> recovery verification.

## Diagram rules

- Update the relevant `.mmd` whenever architecture changes.
- Treat diagram source as architecture contract, not presentation-only docs.
- Do not add a second hand-maintained copy.
- Review security/trust diagrams when adding integration, public endpoint, scanner, datastore, artifact access, tenant-routing change or cross-region flow.
- Review reliability diagram when changing Tier-3/SLO/error-budget semantics.
- AWS implementation details may evolve without logical diagram change unless they alter trust/data/reliability contracts.
- Product-facing diagrams may hide unnecessary engine names; internal diagrams may name them for engineering clarity.

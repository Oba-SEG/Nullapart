# Nullapart Architecture Diagrams

Mermaid `.mmd` files in this directory are the **canonical architecture diagram sources**.

Do not duplicate Mermaid bodies manually in this README. That previously allowed the rendered index to drift from the actual source files.

If rendered SVG/PNG/embedded Markdown diagrams are added later, they should be generated automatically from these sources in CI and never maintained by hand.

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
    - Sentry-compatible application telemetry -> SegLumberjack, native daemon collector path, CloudWatch infrastructure telemetry, and authoritative audit/outbox separation.

12. [Administrative audit architecture](11-admin-audit-architecture.mmd)
    - Atomic mutation/audit/outbox pattern, RBAC-scoped UI, immutable audit checkpoints and diagnostic SegLumberjack correlation.

## Diagram rules

- Update the relevant `.mmd` file whenever its architecture changes.
- Treat the source diagram as part of the architecture contract, not presentation-only documentation.
- Do not add a second hand-maintained copy of a diagram.
- Security/trust-boundary diagrams must be reviewed whenever adding a new integration, public endpoint, scanner type, data store, artifact-access path or cross-region flow.
- AWS-specific implementation details can evolve without changing the logical context diagram unless they change a trust/data boundary or product contract.
- Product-facing diagrams may hide unnecessary implementation/engine names, while internal architecture diagrams may name them for engineering clarity.

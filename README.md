# Nullapart

Nullapart is a security-first, bidirectional Secure Email Gateway (SEG) designed as a clean implementation informed by the lessons and product requirements developed in NexusSEG.

> **Status:** architecture and scaffold phase. The design is intentionally working/proposed rather than frozen.

## Product domains

Primary canonical domain:

- `nullapart.com`

Additional owned/supported domains:

- `nullapart.io`
- `nullapart.co`
- `nullapart.co.za`

The architecture treats `nullapart.com` as the canonical product/control domain. The additional domains are reserved, protected and deliberately routed/redirected according to the regional/domain strategy in [Regions, tenancy and naming](docs/02-REGIONS-TENANCY-NAMING.md).

## Security-first project gate

Before Phase 0 implementation, Nullapart requires acceptance of the [Security Program](docs/security/README.md).

This Phase -1 gate defines threat modeling, secure SDLC, vulnerability management, incident response, access governance, data classification, privacy/retention/deletion, cryptographic/network baselines, backup/DR, supply-chain controls, security testing, abuse response, third-party risk, exceptions, mail failure semantics, runbooks and security metrics.

Implementation does not outrun these security rules.

## Core direction

- AWS-hosted regional deployments.
- Rust for the custom mail core.
- Postfix as the containerized Internet-facing MTA and durable mail queue.
- Rspamd at bounded SMTP restriction/Milter stages.
- Explicit Postfix after-queue filter handoff and trusted reinjection path.
- One SMTP transaction may split into multiple customer-scoped Tenant Message Instances.
- ClamAV plus an expandable scanner fabric from day one.
- PostgreSQL as the source of truth and transactional-outbox store.
- Redis/Valkey for cache, greylisting, counters and runtime acceleration—not assumed durable messaging.
- Amazon SQS as the preferred AWS durable asynchronous event path.
- Local last-known-good policy/configuration snapshots on mail nodes.
- Lightweight inline ML for fast classification.
- Separate regional Deep AI over an authenticated OpenAI-compatible API.
- Qwen3.8-27B is a leading Deep-AI candidate under regional capacity evaluation, not a locked dependency.
- ZITADEL is the leading identity candidate subject to security/license validation.
- OpenBao is the leading open-source secrets/workload-identity candidate with HA/bootstrap design required before production.
- Amazon S3 is the expected production artifact backend behind a storage abstraction.
- n8n remains for internal orchestration and ClickUp workflows.
- SegLumberjack is the regional Sentry-compatible application observability platform; CloudWatch covers AWS infrastructure telemetry.
- Administrative actions are recorded in a first-class append-only/tamper-evident Admin Audit subsystem with RBAC-scoped UI views.
- Received message content is treated as hostile and rendered in an isolated/sanitized UI path.
- DMARC and BIMI are first-class product capabilities using the current DMARC RFC 9989/9990/9991 model.
- No public customer API in the initial implementation.
- No end-user portal; administrative access only.
- No billing subsystem in Nullapart.
- Neumorphic UI design with accessibility and dense operational views preserved.

## Administrative levels

1. **System Admin** — regional platform administration, complete policy visibility and audited impersonation.
2. **Support** — RBAC-restricted customer administration, Support policy access and audited Customer Admin impersonation. No message body/raw MIME/attachment access.
3. **Customer Admin** — tenant-level RBAC. Customer owners decide which tenant roles may access sensitive message/header/quarantine functions.

All administrative accounts require MFA; high-risk actions may require step-up authentication.

## Regional identity

Customer identifiers are region/deployment scoped and human-readable, for example:

- `CZA-1` — South Africa, primary deployment.
- `CZAB-1` — South Africa, deployment B.
- `CEU-1`, `CUK-1`, `CUS-1` — other regions.

Each deployment has its own URL, DNS, mail infrastructure, databases, caches, artifact storage, identity/security services, observability and AI infrastructure.

## Repository layout

- `docs/` — architecture and security documentation.
- `crates/` — Rust workspace boundaries for the future mail core and shared contracts.
- `mail/` — Postfix and Rspamd configuration.
- `scanners/` — scanner fabric and analyzer adapters.
- `ml/` — inline ML and Deep AI lifecycle.
- `control/` — control-plane backend, identity and audit modules.
- `frontend/` — neumorphic administration UI.
- `workflows/` — n8n internal operational workflows.
- `infrastructure/` — AWS, container, secrets and observability definitions.
- `tests/` — security, mail-flow, integration and UI test suites.

## Documentation

Start with:

1. [Security Program — Phase -1 gate](docs/security/README.md)
2. [Architecture](docs/00-ARCHITECTURE.md)
3. [Security principles](docs/01-SECURITY-PRINCIPLES.md)
4. [Regions, tenancy, naming and domains](docs/02-REGIONS-TENANCY-NAMING.md)
5. [Identity, RBAC and impersonation](docs/03-IDENTITY-RBAC-IMPERSONATION.md)
6. [Mail flows](docs/04-MAIL-FLOWS.md)
7. [Scanner fabric](docs/05-SCANNER-FABRIC.md)
8. [Policies and runtime configuration](docs/06-POLICY-MODEL.md)
9. [Message visibility, trace and audit](docs/07-MESSAGE-TRACE-VISIBILITY.md)
10. [DMARC and BIMI](docs/08-DMARC-BIMI.md)
11. [ML and Deep AI](docs/09-ML-DEEP-AI.md)
12. [AWS data and storage](docs/10-AWS-DATA-STORAGE.md)
13. [Observability and secrets](docs/11-OBSERVABILITY-SECRETS.md)
14. [UI design system](docs/12-UI-DESIGN-SYSTEM.md)
15. [SMTP response catalogue](docs/13-SMTP-RESPONSES.md)
16. [Notifications and remediation](docs/14-NOTIFICATIONS-REMEDIATION.md)
17. [AWS deployment topology](docs/15-AWS-DEPLOYMENT.md)
18. [Build roadmap](docs/16-BUILD-ROADMAP.md)
19. [Administrative audit logging](docs/17-ADMIN-AUDIT-LOGGING.md)
20. [SMTP transaction and tenant message contract](docs/18-MESSAGE-TRANSACTION-CONTRACT.md)
21. [Secure message rendering and artifact access](docs/19-SECURE-MESSAGE-RENDERING.md)
22. [Durable event architecture](docs/20-EVENT-DURABILITY.md)
23. [AWS SMTP deployment commissioning](docs/21-AWS-SMTP-COMMISSIONING.md)
24. [NexusSEG reference principles](docs/99-NEXUSSEG-REFERENCE.md)

## Security posture

Nullapart is a security product. Security controls are designed into every feature rather than applied afterward. Every network API is authenticated, administrative operations are audited, service identities are unique, message content is tightly access-controlled, regional boundaries are explicit, and untrusted email data is never treated as trusted instructions.

See [SECURITY.md](SECURITY.md).

## Architecture diagrams

See the [architecture diagram source index](docs/diagrams/README.md) for system context, inbound/outbound mail flow, regional AWS topology, RBAC, scanner fabric, data/storage, events, Deep AI, observability, admin audit and trust boundaries.

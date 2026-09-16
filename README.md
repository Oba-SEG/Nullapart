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

## Core direction

- AWS-hosted regional deployments.
- Rust for the custom mail core.
- Postfix as the containerized MTA.
- Rspamd at SMTP restriction and Milter stages.
- ClamAV plus an expandable scanner fabric from day one.
- PostgreSQL as the source of truth; Redis for cache, streams and runtime acceleration.
- Local last-known-good policy/configuration snapshots on mail nodes.
- Lightweight inline ML for fast classification.
- Separate regional Deep AI over an authenticated OpenAI-compatible API.
- ZITADEL is the leading identity candidate.
- OpenBao is the leading open-source secrets/workload-identity candidate.
- Amazon S3 is the expected production artifact backend behind a storage abstraction.
- n8n remains for internal orchestration and ClickUp workflows.
- DMARC and BIMI are first-class product capabilities.
- No public customer API in the initial implementation.
- No end-user portal; administrative access only.
- No billing subsystem in Nullapart.
- Neumorphic UI design with accessibility and dense operational views preserved.

## Administrative levels

1. **System Admin** — regional platform administration, complete policy visibility and audited impersonation.
2. **Support** — RBAC-restricted customer administration, Support policy access and audited Customer Admin impersonation.
3. **Customer Admin** — tenant-level RBAC. Customer owners decide which tenant roles may access sensitive message/header/quarantine functions.

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
- `control/` — control-plane backend and identity integration.
- `frontend/` — neumorphic administration UI.
- `workflows/` — n8n internal operational workflows.
- `infrastructure/` — AWS, container, secrets and observability definitions.
- `tests/` — security, mail-flow, integration and UI test suites.

## Documentation

Start with:

1. [Architecture](docs/00-ARCHITECTURE.md)
2. [Security principles](docs/01-SECURITY-PRINCIPLES.md)
3. [Regions, tenancy, naming and domains](docs/02-REGIONS-TENANCY-NAMING.md)
4. [Identity, RBAC and impersonation](docs/03-IDENTITY-RBAC-IMPERSONATION.md)
5. [Mail flows](docs/04-MAIL-FLOWS.md)
6. [Scanner fabric](docs/05-SCANNER-FABRIC.md)
7. [Policies and runtime configuration](docs/06-POLICY-MODEL.md)
8. [Message visibility, trace and audit](docs/07-MESSAGE-TRACE-VISIBILITY.md)
9. [DMARC and BIMI](docs/08-DMARC-BIMI.md)
10. [ML and Deep AI](docs/09-ML-DEEP-AI.md)
11. [AWS data and storage](docs/10-AWS-DATA-STORAGE.md)
12. [Observability and secrets](docs/11-OBSERVABILITY-SECRETS.md)
13. [UI design system](docs/12-UI-DESIGN-SYSTEM.md)
14. [SMTP response catalogue](docs/13-SMTP-RESPONSES.md)
15. [Notifications and remediation](docs/14-NOTIFICATIONS-REMEDIATION.md)
16. [AWS deployment topology](docs/15-AWS-DEPLOYMENT.md)
17. [Build roadmap](docs/16-BUILD-ROADMAP.md)
18. [NexusSEG reference principles](docs/99-NEXUSSEG-REFERENCE.md)

## Security posture

Nullapart is a security product. Security controls are designed into every feature rather than applied afterward. Every network API is authenticated, administrative operations are audited, service identities are unique, message content is tightly access-controlled, regional boundaries are explicit, and untrusted email data is never treated as trusted instructions.

See [SECURITY.md](SECURITY.md).
## Architecture diagrams

See the [rendered architecture diagram set](docs/diagrams/README.md) for system context, inbound/outbound mail flow, regional AWS topology, RBAC, scanner fabric, data/storage, events, Deep AI and trust boundaries.


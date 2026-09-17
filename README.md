# Nullapart

Nullapart is a security-first, bidirectional Secure Email Gateway (SEG) designed as a clean implementation informed by lessons and product requirements developed in NexusSEG.

> **Status:** architecture and scaffold phase. The design is intentionally working/proposed rather than frozen.

## Product domains

Primary canonical domain:

- `nullapart.com`

Additional owned/supported domains:

- `nullapart.io`
- `nullapart.co`
- `nullapart.co.za`

The architecture treats `nullapart.com` as the canonical product/control domain. Additional domains are reserved/protected/routed according to [Regions, tenancy and naming](docs/02-REGIONS-TENANCY-NAMING.md).

## Security-first project gate

Before Phase 0 implementation, Nullapart requires acceptance of the [Security Program](docs/security/README.md).

Phase -1 defines threat modeling, secure SDLC, vulnerability/zero-day handling, incident response, access governance, data classification/privacy, cryptographic/network baselines, backup/DR, supply-chain controls, security testing, abuse response, third-party risk, tenant routing/feature override rules, Tier-3 reliability/SLOs, agent/developer controls, exceptions, runbooks and evidence.

Implementation does not outrun these rules.

## Core direction

- AWS-hosted regional deployments.
- Amazon ECS ordinary container baseline; dedicated mail EC2 nodes are the stable SMTP exception.
- Public Control Plane HTTPS uses ALB/WAF; public SMTP uses direct commissioned Postfix MX identities by default.
- Rust custom mail core.
- Postfix Internet-facing MTA + durable mail queue.
- Rspamd bounded SMTP restriction/Milter stages.
- Explicit Postfix after-queue handoff + trusted reinjection.
- One SMTP transaction may split into multiple customer-scoped Tenant Message Instances.
- ClamAV + expandable scanner fabric.
- PostgreSQL source of truth + transactional outbox.
- Redis/Valkey cache, greylisting, counters and runtime acceleration—not durable event authority.
- Amazon SQS preferred AWS durable asynchronous path.
- Local last-known-good policy/config snapshots on mail nodes.
- Tenant context is resolved server-side at the application boundary; client tenant IDs are never authorization.
- Feature-switch precedence is System security/kill controls -> deployment -> tenant override -> default.
- Tier-3 production-critical capabilities have SLIs/SLOs, error budgets and burn-rate alerting.
- Lightweight inline ML for fast classification.
- Separate regional Deep AI over authenticated OpenAI-compatible API.
- Runtime ML/LLM capabilities use versioned skills, explicit tools, structured outputs and context budgets.
- Qwen3.8-27B is a leading Deep-AI candidate under regional capacity evaluation, not a locked dependency.
- ZITADEL leading identity candidate subject to security/license validation.
- OpenBao leading open-source secrets/workload-identity candidate with HA/bootstrap design required before production.
- Amazon S3 expected production artifact backend behind storage abstraction.
- n8n internal orchestration/ClickUp workflows only; not ordinary mail dependency.
- SegLumberjack regional Sentry-compatible application observability; CloudWatch AWS infrastructure telemetry.
- First-class append-only/tamper-evident Admin Audit with RBAC-scoped UI.
- Received message content treated as hostile and rendered through isolated/sanitized UI path.
- DMARC/BIMI first-class capabilities using RFC 9989/9990/9991 baseline.
- Initial Control Plane API `/api/v1`; event/scanner/config/AI contracts explicitly versioned.
- Feature switches server-authoritative versioned configuration with ownership/audit/lifecycle; never authorization.
- Browser TLS uses normal PKI/HSTS/CAA; HPKP not used.
- HMAC-SHA-256 baseline Nullapart shared-secret signing primitive for applicable webhook/event integrity.
- Package compatibility validated as a stack; exact implementation versions locked/reproducible.
- GitHub Actions minimum permissions, locked dependencies, immutable artifacts and OIDC to scoped AWS deployment roles.
- `main` must be protected with no direct pushes; reviewed PR + required checks is the source-change path.
- Zero-day response includes advisory/SBOM correlation, kill/containment, emergency PR/patch, retrospective hunt and credential review.
- Coding agents use root `AGENTS.md` as canonical instructions; Codex and OpenCode consume it directly, with thin adapters for other selected tools.
- No public customer API initially.
- No end-user portal; administrative access only.
- No billing subsystem in Nullapart.
- Neumorphic UI with accessibility and dense operational views preserved.

## Administrative levels

1. **System Admin** — regional platform administration, complete policy visibility and audited impersonation.
2. **Support** — RBAC-restricted customer administration, Support policy access and audited Customer Admin impersonation. No message body/raw MIME/attachment access.
3. **Customer Admin** — tenant-level RBAC. Customer owners decide which tenant roles may access sensitive message/header/quarantine functions.

All administrative accounts require MFA; high-risk actions may require step-up authentication.

## Regional identity

Customer identifiers are region/deployment scoped and human-readable, for example:

- `CZA-1` — South Africa primary deployment;
- `CZAB-1` — South Africa deployment B;
- `CEU-1`, `CUK-1`, `CUS-1` — other regions.

Each deployment has its own URL, DNS, mail infrastructure, databases, caches, artifact storage, identity/security services, observability and AI infrastructure.

## Repository layout

- `AGENTS.md` — canonical repository-wide coding-agent instructions.
- `.github/copilot-instructions.md`, `CLAUDE.md`, `GEMINI.md`, `.cursor/rules/` — thin agent adapters back to `AGENTS.md`.
- `docs/` — architecture, security, compliance, engineering, phase and AI documentation.
- `crates/` — Rust workspace boundaries.
- `mail/` — Postfix/Rspamd configuration.
- `scanners/` — scanner fabric/analyzer adapters.
- `ml/` — inline ML/Deep AI lifecycle.
- `control/` — Control Plane backend/identity/audit.
- `frontend/` — neumorphic administration UI.
- `workflows/` — n8n internal workflows.
- `infrastructure/` — AWS/container/secrets/observability definitions.
- `tests/` — security/mail-flow/integration/UI test suites.

## Documentation

Start with:

1. [Security Program — Phase -1 gate](docs/security/README.md)
2. [Build roadmap](docs/16-BUILD-ROADMAP.md)
3. [Detailed Phase Specifications](docs/phases/README.md)
4. [Architecture](docs/00-ARCHITECTURE.md)
5. [Security principles](docs/01-SECURITY-PRINCIPLES.md)
6. [Regions, tenancy, naming and domains](docs/02-REGIONS-TENANCY-NAMING.md)
7. [Identity, RBAC and impersonation](docs/03-IDENTITY-RBAC-IMPERSONATION.md)
8. [Mail flows](docs/04-MAIL-FLOWS.md)
9. [Scanner fabric](docs/05-SCANNER-FABRIC.md)
10. [Policies and runtime configuration](docs/06-POLICY-MODEL.md)
11. [Message visibility, trace and audit](docs/07-MESSAGE-TRACE-VISIBILITY.md)
12. [DMARC and BIMI](docs/08-DMARC-BIMI.md)
13. [ML and Deep AI](docs/09-ML-DEEP-AI.md)
14. [AWS data and storage](docs/10-AWS-DATA-STORAGE.md)
15. [Observability and secrets](docs/11-OBSERVABILITY-SECRETS.md)
16. [UI design system](docs/12-UI-DESIGN-SYSTEM.md)
17. [SMTP response catalogue](docs/13-SMTP-RESPONSES.md)
18. [Notifications and remediation](docs/14-NOTIFICATIONS-REMEDIATION.md)
19. [AWS deployment topology](docs/15-AWS-DEPLOYMENT.md)
20. [Administrative audit logging](docs/17-ADMIN-AUDIT-LOGGING.md)
21. [SMTP transaction and tenant message contract](docs/18-MESSAGE-TRANSACTION-CONTRACT.md)
22. [Secure message rendering and artifact access](docs/19-SECURE-MESSAGE-RENDERING.md)
23. [Durable event architecture](docs/20-EVENT-DURABILITY.md)
24. [AWS SMTP deployment commissioning](docs/21-AWS-SMTP-COMMISSIONING.md)
25. [Version Control, CI/CD and Release Security](docs/security/19-VERSION-CONTROL-CICD.md)
26. [Versioning and Release Management](docs/22-VERSIONING-RELEASE-MANAGEMENT.md)
27. [Frontend Architecture and Package Baseline](docs/23-FRONTEND-ARCHITECTURE.md)
28. [Container, Load-Balancing and Network Security](docs/24-CONTAINER-LOADBALANCING-NETWORK.md)
29. [ML / LLM Skills and Tool Governance](docs/25-AI-LLM-SKILLS-TOOLS.md)
30. [Package Compatibility and Upgrade Matrix](docs/26-PACKAGE-COMPATIBILITY.md)
31. [API Versioning, Feature Flags and Feature Additions](docs/27-API-VERSIONING-FEATURE-FLAGS.md)
32. [GitHub Actions Architecture](docs/28-GITHUB-ACTIONS-ARCHITECTURE.md)
33. [Tenant Context, Feature Overrides and Routing](docs/29-TENANT-FEATURE-ROUTING.md)
34. [Tier-3 Reliability, SLOs and Error Budgets](docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md)
35. [Application Security Control Baseline](docs/security/20-APPLICATION-SECURITY-CONTROLS.md)
36. [Compliance Assurance and Control Mapping](docs/security/21-COMPLIANCE-ASSURANCE.md)
37. [Rate Limiting and Abuse Protection](docs/security/22-RATE-LIMITING-ABUSE-PROTECTION.md)
38. [Patching and Dependency Version Management](docs/security/23-PATCHING-DEPENDENCY-VERSIONS.md)
39. [Business Logic and Policy Security](docs/security/24-BUSINESS-LOGIC-POLICY-SECURITY.md)
40. [Certificate Trust, mTLS and Pinning](docs/security/25-CERTIFICATE-TRUST-PINNING.md)
41. [HMAC Signing and Webhook Security](docs/security/26-HMAC-SIGNING-WEBHOOKS.md)
42. [Zero-Day Intelligence and Emergency Response](docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md)
43. [Engineering Standards](docs/engineering/README.md)
44. [Code Standards and Formatting](docs/engineering/CODE-STANDARDS.md)
45. [AI Engineering Index](docs/ai/README.md)
46. [Coding Agent Operating Model](docs/ai/CODING-AGENT-OPERATING-MODEL.md)
47. [Coding Agent Instruction Discovery](docs/ai/AGENT-DISCOVERY.md)
48. [Compliance Documentation Register](docs/compliance/README.md)
49. [NexusSEG reference principles](docs/99-NEXUSSEG-REFERENCE.md)

## Security posture

Nullapart is a security product. Security controls are designed into every feature rather than applied afterward. Network APIs are authenticated, administrative operations audited, service identities unique, tenant scope explicit, message content tightly controlled, regional boundaries explicit and untrusted email data never treated as trusted instructions.

See [SECURITY.md](SECURITY.md).

## Architecture diagrams

See the [architecture diagram source index](docs/diagrams/README.md) for system context, mail flow, regional AWS topology, RBAC, scanner fabric, storage/events, Deep AI, observability, audit, trust boundaries, CI/CD, request security, network topology, tenant routing and SLO/burn-rate architecture.

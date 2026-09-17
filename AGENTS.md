# Nullapart Coding Agent Instructions

This repository is architecture/security-first.

`AGENTS.md` is the canonical repository-wide coding-agent instruction source.

## Supported coding agents

These instructions are intentionally written to cover multiple coding-agent environments.

- **OpenAI Codex**: use this root `AGENTS.md` directly. Scoped `AGENTS.md` files may be added later for subtrees with genuinely local rules.
- **OpenCode**: use this root `AGENTS.md` directly. Do not rely on a parallel `OPENCODE.md` policy file.
- **GitHub Copilot**: `.github/copilot-instructions.md` is a thin adapter back to this file.
- **Claude-compatible agents**: `CLAUDE.md` is a thin adapter back to this file.
- **Gemini-compatible agents**: `GEMINI.md` is a thin adapter back to this file.
- **Cursor**: `.cursor/rules/nullapart.mdc` is a thin adapter back to this file.

See `docs/ai/AGENT-DISCOVERY.md` for the discovery model.

Tool-specific adapter files must not become independent architecture/security policy sources.

## Before modifying implementation

1. read `SECURITY.md`;
2. read `docs/16-BUILD-ROADMAP.md`;
3. identify and read the owning phase under `docs/phases/`;
4. read `docs/engineering/CODE-STANDARDS.md` for implementation/formatting rules;
5. read only the architecture/security documents directly relevant to the task;
6. inspect existing abstractions before creating new ones.

Detailed AI-agent operating rules: `docs/ai/CODING-AGENT-OPERATING-MODEL.md`.

## Non-negotiable rules

- Do not modify `obakeng-SEG/NexusSEG` unless explicitly requested.
- Do not touch the misspelled `obakeng-SEG/Nullappart` repository.
- The canonical repository/product is Nullapart.
- Do not recreate NexusSEG-style service-per-feature synchronous HTTP chains.
- Every network API is authenticated unless the protocol uses an explicitly designed alternative trust mechanism.
- Server-side authorization and resource ownership checks are mandatory.
- Tenant/customer scope derives from authenticated context, not client IDs.
- Tenant-aware routing and feature overrides follow `docs/29-TENANT-FEATURE-ROUTING.md`.
- PostgreSQL RLS is defense in depth where applicable.
- Client validation never replaces server validation.
- Auth/refresh tokens are not stored in browser Local Storage/Session Storage/IndexedDB.
- Secrets/auth credentials never go in URLs.
- Retryable/destructive side effects require idempotency.
- Administrative/security actions are audited.
- Support cannot access message body/raw MIME/attachments.
- Untrusted email content never executes in the trusted UI origin.
- Unknown/scanner/model failure never silently becomes CLEAN.
- No raw JSON admin UI.
- No public database/cache/secrets/scanner/Deep-AI management endpoints.
- Do not disable CI/security controls to complete a task.
- `main` accepts no direct normal or administrator pushes; changes merge through reviewed PRs with required checks once branch protection is activated.
- Follow `docs/engineering/CODE-STANDARDS.md`; do not suppress format/lint/type errors simply to make a change pass.
- Run/apply canonical formatters instead of manually imitating style.
- Do not introduce broad lint-disable directives or unrelated formatting churn.
- Third-party GitHub Actions use reviewed immutable full commit SHAs where practical; do not replace them with floating branches/tags casually.
- Do not introduce long-lived AWS deployment credentials; use scoped OIDC/workload identity.
- Package/runtime upgrades must respect `docs/26-PACKAGE-COMPATIBILITY.md` and lockfiles; do not force incompatible peer/toolchain combinations.
- Feature switches are server-authoritative configuration, never authorization or a shortcut around incomplete security work.
- Tenant overrides cannot defeat System security floors or emergency kill switches.
- Independently consumed API/event/scanner/config/AI contracts follow `docs/27-API-VERSIONING-FEATURE-FLAGS.md`.
- Reuse the reviewed HMAC/webhook contract instead of inventing per-endpoint signing schemes.
- Do not disable TLS validation or add browser certificate pinning/HPKP; follow the certificate trust policy.
- ML/LLM skills use explicit data/tool/context/output contracts and models do not receive ambient shell/browser/cloud authority.
- Tier-3 production-critical paths follow `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`; do not weaken burn-rate/SLO gates to make a system appear healthy.
- Zero-day handling follows `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`; do not suppress vulnerability evidence or automatically deploy emergency production fixes.
- Do not claim compliance/certification without verified evidence/audit basis.

## Architecture defaults

- Rust Mail Core.
- Postfix MTA/durable queue + Rspamd bounded SMTP/Milter work.
- PostgreSQL authoritative data + transactional outbox.
- SQS durable async path.
- Redis/Valkey runtime cache/counters.
- S3 ArtifactStore production backend.
- ECS ordinary container baseline.
- dedicated EC2 mail nodes for stable SMTP identity/queue lifecycle.
- ALB/WAF for HTTPS Control Plane.
- direct commissioned Postfix MX nodes for SMTP baseline.
- React/TypeScript/Vite frontend baseline.
- SegLumberjack receives Sentry-compatible application telemetry.
- CloudWatch covers AWS infrastructure telemetry.

## Change discipline

Do not introduce a new:

- service/process;
- datastore;
- public endpoint;
- API major version;
- persistent identifier type;
- third-party data export;
- LLM action tool;
- EKS/Kubernetes dependency;
- tenant-routing mechanism;
- reliability tier/SLO exception

without checking whether the architecture explicitly allows it.

## Required completion

For a feature, include as applicable:

- implementation;
- canonical formatting/lint/typecheck compliance;
- backend authorization/ownership;
- tenant/deployment routing context;
- validation;
- persistence/RLS;
- audit;
- rate limiting;
- idempotency;
- safe errors;
- API/event/schema compatibility;
- feature-switch/tenant-override/rollout behavior;
- package/toolchain compatibility;
- cryptographic signing/verification tests where applicable;
- reliability/SLO impact where applicable;
- zero-day/patchability implications for new dependencies/parsers;
- UI;
- observability;
- tests;
- docs/runbook updates.

When documentation and implementation disagree, treat it as a defect: either make code match, or deliberately update/review architecture first.

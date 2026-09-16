# Nullapart Security Requirements

These rules apply to architecture, implementation, operations, UI and testing.

## Phase -1 security program gate

No Nullapart implementation begins before the [Security Program](docs/security/README.md) is defined and accepted.

The security program establishes governance, threat modeling, secure SDLC, vulnerability management, incident response, access governance, data classification, privacy/retention/deletion, cryptographic/network baselines, backup/DR, supply-chain controls, security testing, abuse response, third-party risk, exceptions, mail trust/failure semantics, runbooks and security metrics.

Architecture and implementation changes must comply with these controls or use the formal time-limited security-exception process.

## Security-first engineering

Nullapart is a security product. Every feature is designed with explicit trust boundaries, least privilege, auditable administration, secure failure behaviour and regional data handling from the beginning.

## Authentication

- Every network-accessible HTTP/API call must be authenticated unless the protocol requires another trust mechanism.
- SMTP endpoints use SMTP/TLS/source/connector controls rather than web API authentication.
- Internal services must not share one platform-wide static secret.
- Each service/node receives an independent workload identity.
- Short-lived certificates or credentials are preferred.
- Management, metrics, health-detail and debug endpoints must not be publicly reachable.
- Public customer API access is not part of the initial product.
- All System, Support and Customer administrative accounts require MFA.
- System/Support should prefer phishing-resistant WebAuthn/passkey/security-key authentication where supported.
- High-risk operations may require step-up authentication.

## Application security invariants

All control-plane/API implementation follows the [Application Security Control Baseline](docs/security/20-APPLICATION-SECURITY-CONTROLS.md).

Mandatory rules include:

- derive tenant/user scope from authenticated server context;
- server-side object ownership/BOLA/IDOR checks for every resource action;
- client-side validation for UX only and authoritative server-side validation for security/business rules;
- PostgreSQL Row-Level Security for tenant-scoped tables where practical as defense in depth;
- transaction-safe tenant context when connection pooling is used;
- explicit idempotency for retryable/destructive/externally side-effecting operations;
- no authentication tokens/refresh tokens in browser Local Storage;
- CSRF protections for cookie-authenticated state-changing requests;
- safe structured errors with no stack trace/secret/internal-data leakage;
- OAST/SSRF/XXE testing for components capable of outbound network interaction;
- mass-assignment protection through explicit writable-field allowlists.

Compliance/security evidence mapping follows [Compliance Assurance](docs/security/21-COMPLIANCE-ASSURANCE.md). Nullapart does not claim a certification merely because controls are mapped.

## Rate limiting and business-logic protection

Rate limiting/abuse controls follow `docs/security/22-RATE-LIMITING-ABUSE-PROTECTION.md`.

Business logic/state/policy invariants follow `docs/security/24-BUSINESS-LOGIC-POLICY-SECURITY.md`.

Key rules:

- high-risk actions have dedicated principal/customer/action limits;
- limiter failure never silently becomes unlimited access;
- security state transitions are enforced server-side and transaction-safe;
- bulk operations re-check every resource;
- lower-level policy cannot weaken System security floors;
- stale/concurrent updates are detected.

## Authentication material in URLs

Do not put bearer credentials, access/refresh tokens, session IDs, API keys, passwords or secrets in URL paths/query strings/fragments.

Protocol-mandated short-lived OIDC authorization callback values are immediately exchanged server-side and the browser is redirected to a clean URL.

Restricted mail-artifact access should not expose reusable S3 presigned query credentials to the browser as the normal design.

## Patching and dependency versions

Patching/version management follows `docs/security/23-PATCHING-DEPENDENCY-VERSIONS.md`.

Dependencies, base images, actions, models and rulesets are pinned/reproducible; production containers are rebuilt and promoted rather than patched interactively.

## Authorization

Authorization is enforced server-side.

Administrative levels:

- System Admin.
- Support.
- Customer Admin.

Customer RBAC may further restrict message content, headers, attachments, quarantine release, audit access and remediation.

No frontend-only permission check is sufficient.

## Impersonation

System and Support administrators authenticate as themselves before impersonating a Customer Admin.

Every impersonated action retains:

- real actor identity;
- impersonated subject;
- customer ID;
- role;
- reason;
- session start/end;
- action history.

Impersonation cannot expand the real actor's platform permission set.

## Sensitive message content

System Admin may access complete message detail where explicitly permitted.

Support may access operational metadata, routing, scanner outcomes, policy decisions and transmission traces but must not receive message body, raw MIME or attachment content.

Customer Admin content access is controlled by customer RBAC.

Content access restrictions must apply to UI pages, APIs, search snippets, exports, audit records and direct artifact/download endpoints.

## Hostile message rendering

Received email content is attacker-controlled.

Nullapart must never render received HTML directly in the trusted administration DOM.

Required controls include:

- sanitization;
- isolated/sandboxed rendering;
- scripts/forms/event handlers removed;
- remote resources blocked by default;
- restrictive CSP;
- no access to Nullapart session cookies/storage;
- permission-checked attachment access;
- separate artifact/download origin where practical;
- mandatory audit for privileged content access.

See `docs/19-SECURE-MESSAGE-RENDERING.md`.

## Administrative audit

Administrative audit is a first-class authoritative security record, separate from application observability.

All security-relevant System Admin, Support and Customer Admin actions generate server-side audit entries.

Where possible, the administrative mutation, audit row and transactional-outbox row commit atomically in the same PostgreSQL transaction.

Requirements include:

- append-only application semantics;
- real actor identity;
- impersonated subject when applicable;
- customer ID;
- action/resource/result;
- source/session context;
- safe before/after change information;
- reason for high-risk actions where required;
- trace/correlation identifiers;
- retention and integrity controls;
- tamper-evident immutable checkpoints/archives.

Audit data must not contain secrets, message bodies, raw MIME or attachment contents.

Support audit access must not bypass Support message-content restrictions.

Audit-log access and export are themselves audited.

See `docs/17-ADMIN-AUDIT-LOGGING.md`.

## Secrets

Never store secrets in source code, Git, Docker images or frontend bundles.

Preferred design:

- OpenBao for open-source secrets/workload PKI;
- AWS KMS/Secrets Manager where managed AWS functionality is the safer or necessary option;
- short-lived workload certificates;
- per-service credentials;
- automatic rotation;
- scoped IAM roles.

OpenBao production deployment must include HA, bootstrap/unseal/recovery/backup and PKI-rotation design; it must not be a single-node dependency.

## Regional data handling

Each tenant belongs to one region/deployment.

Customer mail content and associated security records remain in that deployment unless an explicitly approved integration is permitted to receive a defined data class.

Third-party or externally hosted services such as ClickUp, threat intelligence and AI are treated as potential data-export paths. SegLumberjack is intended to be deployed/operated as the regional application observability backend; any deployment topology that would export customer telemetry outside the allowed region must be reviewed explicitly.

## Observability and logging

Nullapart applications use **Sentry-compatible SDK instrumentation** as the standard application telemetry interface.

The normal telemetry path is:

```text
Nullapart application
  -> Sentry SDK / Sentry-compatible protocol
  -> regional SegLumberjack
```

SegLumberjack is the primary regional application observability platform for application errors, exceptions, traces/performance telemetry where supported, release context and service/node correlation.

The architecture does **not** require a separate hosted Sentry service. "Sentry" in implementation guidance refers to the SDK/protocol standard unless a separate service is explicitly approved.

Native daemons such as Postfix/Rspamd/ClamAV use an explicit regional log/metrics collector path so their telemetry is not silently omitted.

AWS CloudWatch is complementary and is used primarily for AWS infrastructure and managed-service telemetry. CloudWatch is not a substitute for the SegLumberjack application-observability role.

Application telemetry should include region, deployment, node ID, hostname, node/runtime IP, service, release, trace ID, Nullapart transaction/tenant-message ID, customer ID, actor identity when administrative, event/reason code and timing where applicable.

Before telemetry leaves the application process/collector, scrub message bodies, raw MIME, attachment content, passwords, tokens, cookies, private keys, credentials and other sensitive fields.

## Durable events

Critical asynchronous events use an explicitly durable architecture.

Preferred AWS baseline:

- PostgreSQL transactional outbox;
- SQS;
- idempotent consumers;
- DLQs for critical consumers.

Redis/Valkey cache is not assumed to be a durable event bus.

See `docs/20-EVENT-DURABILITY.md`.

## Untrusted email input

Everything received from email is untrusted, including MIME, headers, URLs, filenames, HTML, documents, archives, embedded messages and text/images shown to AI.

Nullapart generates its own trusted authentication results.

Prompt text inside email is data, never AI instructions.

## Scanner/parser resource safety

Every parser/scanner must have explicit CPU, memory, time, nesting, decompression, artifact-count and temporary-storage limits.

Encrypted/unscannable content and scanner resource-limit failures must not be silently treated as clean.

## Open-source dependencies

Every dependency requires pinned versions, license review, SBOM inclusion, security-advisory monitoring, provenance/source records and an upgrade strategy.

Identity/platform candidates with copyleft licenses such as AGPL require explicit licensing review before final selection or modification.

## AWS SMTP commissioning

Each direct-to-MX regional deployment requires explicit AWS port-25 commissioning, stable outbound public IP identity, forward/PTR DNS, HELO identity, mail authentication and reputation warm-up before production.

See `docs/21-AWS-SMTP-COMMISSIONING.md`.

## Build completion

A security-sensitive feature is not complete until authorization, audit, UI states, tests, logging, failure behaviour and operational visibility are complete too.

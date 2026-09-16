# Identity, RBAC and Impersonation

## Identity platform

ZITADEL is the current leading identity candidate, subject to implementation, security and licensing validation.

ZITADEL is self-hostable and provides the multi-tenancy, MFA/passkey, OIDC/SAML and administrative capabilities needed by Nullapart. Its server repository is AGPL-3.0 with documented exceptions for some directories/components, so dependency/licensing review is required before it is locked as the production identity platform.

The architecture should avoid modifying/forking the identity server unless necessary; product authorization remains in Nullapart.

## Administrative levels

Nullapart has no normal end-user portal.

### System Admin

May manage regional platform settings, Support access, all tenants, all policy levels, scanners/capabilities, tenant lifecycle, cache refreshes, audited Customer Admin impersonation and full message content where explicitly permitted.

### Support

RBAC-controlled. Potential permissions include customer visibility, Customer/Support policy edits, send-only domain administration, routing/source IP groups, connector capabilities, tenant lifecycle, cache refresh and Customer Admin impersonation.

Support cannot view message body, raw MIME or attachment content.

### Customer Admin

Tenant-scoped. Customer RBAC roles may include owner, security admin, mail admin, DMARC admin and read-only admin.

The owner controls which roles may view headers/content/attachments, release quarantine, remediate, edit policies, view audit data and view reports.

## Authentication

MFA is required for **all administrative accounts**:

- System Admin;
- Support;
- Customer Admin.

System and Support should prefer phishing-resistant authentication such as WebAuthn/passkeys/security keys where supported.

High-risk actions may require step-up authentication even when the session is already MFA-authenticated.

Examples:

- impersonation;
- role/permission change;
- send-only domain creation;
- tenant suspension/termination;
- raw message/MIME access;
- quarantine release;
- retro remediation;
- secrets/security configuration;
- audit export.

## Sessions

Administrative sessions require:

- server-side/BFF session handling where practical;
- secure/HttpOnly/SameSite cookie controls where browser sessions are used;
- authentication/refresh credentials must not be persisted in Local Storage, Session Storage or other JavaScript-readable persistent browser storage;
- region/deployment binding;
- CSRF protection where applicable;
- idle and absolute expiry;
- explicit logout/revocation;
- session/device identity used in audit records;
- reauthentication/step-up for sensitive actions where configured.

## Impersonation

Audit retains actor, impersonated subject, customer ID, reason, requested role, start/end, source session and relevant actions.

The UI shows a persistent impersonation banner.

Impersonation must not grant permissions the real Support/System actor is not authorized to exercise. The effective authorization decision considers both impersonation scope and the real actor's platform permission.

## Resource ownership authorization

Role membership alone is insufficient.

For every resource read/write/action, Nullapart validates server-side:

- real actor;
- impersonation context;
- deployment;
- customer/tenant;
- resource ownership/scope;
- requested action;
- role/permission;
- step-up requirement where applicable.

Client-supplied customer/user IDs are filters, never proof of authorization.

Direct-object identifiers and guessed URLs must not bypass ownership checks.

PostgreSQL Row-Level Security is used where practical as database defense in depth, but it does not replace application authorization.

## Product authorization

Identity-provider roles do not replace Nullapart authorization.

Nullapart evaluates tenant/deployment, admin level, customer RBAC, resource, action, policy visibility, message-content permissions and impersonation constraints server-side.

## Policy visibility

Every policy family/setting declares one management level:

- `CUSTOMER`;
- `SUPPORT`;
- `SYSTEM`.

## Audit-log visibility

### System Admin

Can access the regional administrative audit log when granted the required System permission.

May inspect System, Support and Customer administrative actions, including impersonation chains.

### Support

Can access audit events only within Support RBAC/customer scope.

Support can inspect operational administrative changes but audit detail must never expose message body, raw MIME or attachment content.

### Customer Admin

Tenant audit access is customer-scoped.

The customer owner controls which tenant roles may view the tenant audit log or export it.

### Audit invariants

Every impersonated event retains both:

- real actor;
- impersonated subject.

Audit reads, filters, exports and high-risk views are themselves auditable.

See [Administrative Audit Logging](17-ADMIN-AUDIT-LOGGING.md).

## Tenant lifecycle

- ACTIVE;
- GRACE;
- SUSPENDED;
- TERMINATED.

Billing is external to Nullapart.

## RBAC diagram

See [Control-plane RBAC and Impersonation](diagrams/04-control-plane-rbac.mmd).

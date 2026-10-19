# Identity, RBAC and Impersonation

## Identity platform

**Decision (recorded 2026-09-29, owner decision): ZITADEL is the accepted
identity platform for Nullapart.** The AGPL-3.0 licensing terms of its server
repository (with documented component exceptions) are accepted for a
self-hosted deployment, and the security/licensing validation that was an open
prerequisite is closed by this decision. Operational obligations carried by
the decision: do not modify or fork the identity server, track upstream
security advisories, and patch per the package-compatibility and zero-day
policies (`docs/26-PACKAGE-COMPATIBILITY.md`,
`docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`).

ZITADEL is self-hostable and provides the multi-tenancy, MFA/passkey, OIDC/SAML and administrative capabilities needed by Nullapart.

Integration follows the recorded IdP-agnostic BFF model
(`docs/phases/PHASE-3-LOCAL-IMPLEMENTATION-PLAN.md`): OIDC authorization-code
with PKCE exchanges assertions at the existing authenticated boundary, browser
sessions stay server-side cookies, and Nullapart authorization (roles,
permissions, impersonation, audit scope) remains server-side in Nullapart —
identity-provider roles do not replace product authorization.

The architecture should avoid modifying/forking the identity server unless necessary; product authorization remains in Nullapart.

### Implemented OIDC relying party (Phase 3, 2026-09-29)

Mail Core is a server-side OIDC relying party selected by the
server-authoritative `NULLAPART_IDENTITY_PROVIDER` mode (`proxy_header` |
`oidc`); the mode is configuration, never authorization.

- `GET /api/v1/auth/login` starts an authorization-code flow with PKCE S256
  and `state`/`nonce`; `GET /api/v1/auth/oidc/callback` completes it. The
  callback is the protocol's explicitly designed alternative trust mechanism
  and mints no session until the flow row, PKCE verifier, issuer, redirect URI
  and ID token all verify. Flow rows hold no tokens, are claimed exactly once
  and expire in ten minutes.
- Additional ID-token audiences are accepted only when `azp` names this
  client. Profile/e-mail claims are read from the ID token, or — when the
  provider keeps them behind `userinfo` (OIDC Core 5.3) — from the UserInfo
  endpoint, bound to the ID token's subject so a substituted profile can never
  borrow another identity.
- `admin_users.auth_subject` binds one IdP subject to at most one local admin
  per deployment. Link-by-match links an existing unlinked local user; the
  empty-deployment bootstrap invariant is unchanged; an unknown or
  unprovisioned subject is refused with an audited `session_login` denial and
  never creates a user.
- Step-up re-authentication uses `prompt=login`
  (`GET /api/v1/auth/reauth`, audited as `session_step_up`). Logout revokes
  the local session first, then continues to the IdP end-session endpoint when
  the provider publishes one; local revocation is always the security control.
- Tokens are held server-side only; the browser keeps the opaque HttpOnly
  session cookie. Roles, permissions, impersonation, audit scope and
  row-level security are unchanged and remain Nullapart's own.

Live evidence for this increment is recorded in
`docs/phases/PHASE-3-LOCAL-IMPLEMENTATION-PLAN.md`.

## Administrative levels

Nullapart has no normal end-user portal.

### System Admin

May manage regional platform settings, Support access, all tenants, all policy levels, scanners/capabilities, tenant lifecycle, cache refreshes, audited customer entry (impersonation) and full message content where explicitly permitted.

### Support

RBAC-controlled. Potential permissions include customer visibility, Customer/Support policy edits, send-only domain administration, routing/source IP groups, connector capabilities, tenant lifecycle, cache refresh and audited customer entry (impersonation).

Support cannot view message body, raw MIME or attachment content.

### Customer Admin

Tenant-scoped. Customer RBAC roles may include owner, security admin, mail admin, DMARC admin and read-only admin.

The builtin `customer_admin` role operates one tenant end to end: its own administrators, quarantine and release, policy revisions for the families published at customer level, its own domain onboarding and security posture, its own outbound sender approvals, and its own notification settings. Platform-only capabilities stay out of it: scanner fleet health, customer lifecycle and identity minting, model registration, connector remediation, cross-customer audit and customer entry.

A tenant grant is bounded by the session's customer scope, never by the permission name. `in_scope()` refuses another tenant's `:customerId` with a 404, outbound writes bind `context.customer_id`, and an approved sender's domain must be a verified domain of the approving tenant.

The owner controls which roles may view headers/content/attachments, release quarantine, remediate, edit policies, view audit data and view reports.

## Role definitions

Each deployment seeds the three builtin roles above and may additionally define custom roles.

Builtin roles:

- `system_admin`, `support` and `customer_admin` are seeded idempotently per deployment;
- their keys, levels and permission sets are not mutable through the management API;
- the compiled-in builtin catalog is the authority for what a builtin role holds. Effective permissions are read from `admin_role_permissions`, so each login reconciles those rows in both directions: grants the catalog added appear, grants the catalog dropped are retired. Without the second half, a permission revoked from a builtin role would keep working on an already-seeded deployment.

Custom roles:

- are stored per deployment alongside the builtins and draw permissions only from the server-side permission catalog;
- are created, edited and deleted only by an identity holding the builtin `system_admin` role, with the `admin:users:manage` permission, a fresh step-up and the shared permission-change rate limit;
- are audited in the same transaction as the definition write, recording the permission set before and after a change;
- carry one of the three builtin levels (`system`, `support`, `customer`) and take that level's position in the grantor ordering;
- cannot be deleted while assigned to any user.

A custom role composes permissions; it does not create a new administrative level and it does not acquire behaviors that are reserved to a builtin role identity, such as creating platform-scope administrative users or listing every customer of the deployment.

### Granting and revoking

- A grantor may only assign or revoke roles at or below their own highest level, resolved from the stored role level rather than a compiled-in table.
- A custom role may additionally only be granted by an identity that already holds every permission inside it, so role composition cannot escalate laterally.
- An unknown role key is rejected. Granting never succeeds as a silent no-op.
- No identity may modify its own role membership.

## Authentication

MFA is required for **all administrative accounts**:

- System Admin;
- Support;
- Customer Admin.

System and Support should prefer phishing-resistant authentication such as WebAuthn/passkeys/security keys where supported.

High-risk actions may require step-up authentication even when the session is already MFA-authenticated.

Examples:

- customer entry (impersonation);
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

### Session projection

`GET /api/v1/auth/session` returns the server-resolved view the console renders
from, and nothing more:

- `roles` and `permissions` — the resolved membership and effective permission keys;
- `tier` — `system`, `support` or `customer`, taken from the stored role level of the highest-ranked role, or `null` when no role carries a known level. The console labels and places surfaces from this and never re-derives a tier from builtin role names, which mislabels a session holding an equivalent custom role. Presentation only: every route still authorizes on permissions;
- `platform` — installation facts, published only to a System-tier session;
- `capabilities` — server-resolved write gates for surfaces that publish no list payload of their own. `defineRoles` mirrors the predicate the role-definition routes run (`admin:users:manage` **and** the builtin `system_admin` identity), so a customer administrator who holds the permission reads a stated lock instead of a button that can only be refused. The published verdict and the enforced one come from the same function.

Write gates for surfaces that do publish a list keep their capabilities on that
payload (`admin_customers`, `notification_api`), not on the session. All of them
use the shared `Blocker`/`WriteCapability` shape in
`crates/mail-core/src/admin_capabilities.rs`, mirrored by
`frontend/src/api/capabilities.ts`.

## Customer entry (impersonation)

A customer-bound administrative identity resolves its default tenant from its
own customer binding, not from the deployment's seeded customer. The
deployment template customer applies only to platform-scope identities, which
carry no customer binding. Customer entry below overrides the default for the
duration of the interval.

System Admin and Support can enter ("log in to") a customer account for a
reasoned, step-up-gated, rate-limited interval. Entry switches the session's
customer scope to the entered customer; the real actor's roles and permissions
remain exactly their own. Entry never intersects, reduces or extends the
actor's permission set, so elevated rights (operations, cross-customer audit,
user management) stay fully available while entered.

Audit retains actor, entered customer, reason, start/end, source session and
relevant actions.

The UI shows a persistent banner naming the entered customer and the reason.

Impersonation must not grant permissions the real Support/System actor is not
authorized to exercise: during entry the effective permission set is precisely
the real actor's own platform permission, scoped to the entered customer's
tenant data.

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
- entered customer (impersonated customer).

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

# Identity, RBAC and Impersonation

## Identity platform

ZITADEL is the current leading identity candidate, subject to implementation validation.

## Administrative levels

Nullapart has no normal end-user portal.

### System Admin

May manage regional platform settings, Support access, all tenants, all policy levels, scanners/capabilities, tenant lifecycle, cache refreshes, audited Customer Admin impersonation and full message content where required.

### Support

RBAC-controlled. Potential permissions include customer visibility, Customer/Support policy edits, send-only domain administration, routing/source IP groups, connector capabilities, tenant lifecycle, cache refresh and Customer Admin impersonation.

Support cannot view message body/attachment content.

### Customer Admin

Tenant-scoped. Customer RBAC roles may include owner, security admin, mail admin, DMARC admin and read-only admin.

The owner controls which roles may view headers/content/attachments, release quarantine, remediate, edit policies and view reports.

## Authentication

System and Support require MFA.

Sensitive actions may require step-up authentication.

## Impersonation

Audit retains actor, impersonated subject, customer ID, reason, requested role, start/end, source session and relevant actions.

The UI shows a persistent impersonation banner.

## Product authorization

Nullapart evaluates tenant/deployment, admin level, customer RBAC, resource, action, policy visibility and message-content permissions server-side.

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

Support can inspect operational administrative changes but audit detail must never expose message body or attachment content.

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


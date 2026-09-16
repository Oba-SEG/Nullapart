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

## Tenant lifecycle

- ACTIVE;
- GRACE;
- SUSPENDED;
- TERMINATED.

Billing is external to Nullapart.
## RBAC diagram

See [Control-plane RBAC and Impersonation](diagrams/04-control-plane-rbac.mmd).


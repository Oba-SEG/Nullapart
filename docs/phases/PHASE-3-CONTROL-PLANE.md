# Phase 3 — Control Plane and Administration

## Objective

Deliver the regional administrative product: identity, RBAC, customers, domains, policies, mail trace, runtime operations, audit and secure content access.

The Control Plane remains a modular monolith unless a demonstrated security/scaling boundary requires separation.

## Prerequisites

- Phase 1 mail runtime stable;
- Phase 2 scanner/quarantine contracts stable;
- Phase -1 access/audit/data rules accepted;
- identity platform security/license decision made (satisfied 2026-09-29:
  ZITADEL accepted, `docs/03-IDENTITY-RBAC-IMPERSONATION.md`).

## Identity

Integrate the selected identity platform: ZITADEL (decision recorded
2026-09-29; `docs/03-IDENTITY-RBAC-IMPERSONATION.md`).

Implement:

- regional identity instance;
- MFA for all admins;
- WebAuthn/passkeys preferred for privileged staff;
- session security;
- logout/revocation;
- step-up authentication;
- deployment binding.

## Roles

### System Admin

- all regional customers;
- SYSTEM/SUPPORT/CUSTOMER settings;
- full authorized message view;
- node/platform operations;
- tenant lifecycle;
- impersonation;
- audit.

### Support

- scoped customer administration;
- CUSTOMER/SUPPORT controls;
- customer impersonation;
- operational trace;
- no body/raw MIME/attachments.

### Customer Admin

- tenant scope;
- customer owner-defined RBAC;
- configurable content/quarantine/remediation permissions.

### Deployment-defined roles

- custom roles stored per deployment beside the builtins;
- permissions drawn only from the server-side permission catalog;
- definition changes restricted to the builtin System Admin, step-up gated, rate limited and audited transactionally;
- grantor level ordering resolved from the stored role level;
- custom roles additionally grantable only by identities already holding every permission in them;
- builtin-only platform powers (platform-scope users, cross-customer listing) are not composable into custom roles.

See `docs/03-IDENTITY-RBAC-IMPERSONATION.md#role-definitions`.

## Impersonation

Implement:

- reason required;
- real actor retained;
- entered customer retained (customer-entry semantics, docs/03);
- visible persistent UI banner;
- start/end audit;
- every action audited under the real actor and the entered customer;
- effective authorization is the real actor's own roles/permissions and can
  never exceed them.

## Customer/domain administration

Build:

- customer creation;
- public customer IDs;
- ACTIVE/GRACE/SUSPENDED/TERMINATED;
- domains;
- verification;
- INTERNAL/SEND_ONLY;
- source IP groups;
- routing;
- notification groups;
- VIP records;
- bulk sender configuration foundation.

SEND_ONLY creation remains Support/System controlled.

## Policy UI/runtime administration

Build:

- policy families;
- CUSTOMER/SUPPORT/SYSTEM management level;
- inheritance/effective value display;
- security floors;
- version/revision;
- publish transaction + audit + outbox;
- node loaded revision/stale status;
- audited refresh at tenant/family/node/deployment scope.

## Mail trace/full-message UI

Build:

- search;
- transaction/tenant-message timeline;
- receipt/delivery transmissions;
- findings;
- policy;
- quarantine;
- delivery attempts;
- post-delivery state.

Secure content view follows hostile-rendering architecture.

## Admin Audit UI

Build:

- System/Support/Customer navigation;
- filterable table;
- actor/Acting As/customer/action/resource/result/source IP;
- detail drawer;
- safe before/after changes;
- export with RBAC/redaction;
- immutable checkpoint status.

Audit export is audited.

## Runtime operations UI

Show:

- mail nodes;
- scanner nodes;
- stable node ID;
- runtime IP/AWS identity;
- version;
- config revision;
- stale/current;
- queue/backlog;
- scanner health;
- SQS/outbox/DLQ health;
- SMTP commissioning status.

## Backend security

Every endpoint/action:

- authenticated;
- deployment/customer scoped from authenticated principal context;
- object ownership/BOLA/IDOR checked;
- server-side authorized;
- audit-aware;
- no raw database IDs exposed as customer identity;
- authoritative server-side input validation;
- explicit writable-field allowlists;
- safe structured errors with correlation IDs;
- idempotency for retry-sensitive mutations;
- no content leakage through errors/search/export.

Tenant-scoped PostgreSQL tables use RLS where practical as defense in depth. Request handling must use transaction-safe tenant context under connection pooling and must not normally run with RLS-bypass privileges.

## Rate limiting and business-logic controls

Apply:

- principal/customer/IP/action-aware rate limiting;
- stricter limits on impersonation, release, remediation, exports, config refresh and role changes;
- server-side state-machine validation;
- policy hierarchy/System floors;
- optimistic locking/revision checks;
- idempotency for retry-sensitive mutations;
- bulk per-resource authorization;
- trusted server timestamps.

URLs must not carry bearer auth/session/API secrets. OIDC callback parameters are cleaned after server-side exchange.

See `docs/security/22-RATE-LIMITING-ABUSE-PROTECTION.md` and `docs/security/24-BUSINESS-LOGIC-POLICY-SECURITY.md`.

## UI standard

Use established neumorphic design system.

Do not sacrifice:

- accessibility;
- table density;
- focus states;
- keyboard navigation;
- clear severity/status.

## Security tests

- IDOR/cross-tenant access;
- role escalation;
- Support direct artifact access;
- impersonation privilege escalation;
- CSRF;
- session fixation/revocation;
- stored XSS from mail/customer fields;
- audit bypass;
- policy security-floor bypass;
- export leakage;
- wrong-owner direct-object access;
- RLS bypass/pooled-connection context leakage;
- mass assignment;
- idempotency replay/duplicate side effects;
- unsafe error disclosure;
- browser token persistence/local-storage checks.

## Exit criteria

- all three admin levels function end-to-end;
- deployment-defined custom roles are creatable, assignable, revocable and audited without privilege escalation;
- MFA enforced;
- RBAC enforced server-side;
- impersonation fully audited;
- customers/domains/policies manageable;
- mail trace/quarantine integrated;
- hostile message rendering isolated;
- Support content restriction verified through API and artifact paths;
- admin audit searchable and immutable checkpoints functioning;
- runtime config revision/refresh operational;
- wrong-user/wrong-tenant/wrong-owner API tests pass;
- tenant RLS controls pass isolation tests where applied;
- browser authentication uses the approved non-Local-Storage session model;
- retry-sensitive actions demonstrate idempotency;
- external error responses contain no stack traces/secrets/internal SQL/provider leakage.

## Not in this phase

- advanced trained ML;
- DMARC analytics depth;
- Deep AI;
- mailbox remediation connectors.

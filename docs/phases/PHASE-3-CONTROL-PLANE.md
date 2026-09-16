# Phase 3 — Control Plane and Administration

## Objective

Deliver the regional administrative product: identity, RBAC, customers, domains, policies, mail trace, runtime operations, audit and secure content access.

The Control Plane remains a modular monolith unless a demonstrated security/scaling boundary requires separation.

## Prerequisites

- Phase 1 mail runtime stable;
- Phase 2 scanner/quarantine contracts stable;
- Phase -1 access/audit/data rules accepted;
- identity platform security/license decision made.

## Identity

Integrate selected identity platform (leading candidate ZITADEL).

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

## Impersonation

Implement:

- reason required;
- real actor retained;
- acting-as subject retained;
- visible persistent UI banner;
- start/end audit;
- every action audited under both identities;
- effective authorization cannot exceed real actor's platform rights.

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
- deployment/customer scoped;
- server-side authorized;
- audit-aware;
- no raw database IDs exposed as customer identity;
- no content leakage through errors/search/export.

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
- export leakage.

## Exit criteria

- all three admin levels function end-to-end;
- MFA enforced;
- RBAC enforced server-side;
- impersonation fully audited;
- customers/domains/policies manageable;
- mail trace/quarantine integrated;
- hostile message rendering isolated;
- Support content restriction verified through API and artifact paths;
- admin audit searchable and immutable checkpoints functioning;
- runtime config revision/refresh operational.

## Not in this phase

- advanced trained ML;
- DMARC analytics depth;
- Deep AI;
- mailbox remediation connectors.

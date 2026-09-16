# Administrative Audit Logging

**Status:** required first-class control-plane subsystem.

## Purpose

Nullapart must provide a durable, searchable and permission-controlled record of administrative activity.

Administrative audit logging is not ordinary application logging and is not delegated to SegLumberjack or CloudWatch.

SegLumberjack is diagnostic application observability.

CloudWatch is AWS infrastructure telemetry.

The **Admin Audit Store** is the authoritative history of administrative actions.

## Scope

Audit all security-relevant actions performed by:

- System Admins;
- Support Admins;
- Customer Admins;
- impersonated administrative sessions;
- privileged internal automation where it performs an administrative action.

Examples include:

- login/logout and authentication security events where appropriate;
- impersonation start/end;
- role/permission changes;
- customer creation/status changes;
- domain add/remove/verify;
- SEND_ONLY domain approval;
- routing changes;
- source-IP group changes;
- policy create/edit/delete/enable/disable;
- configuration revision publication;
- manual cache refresh;
- quarantine release/delete;
- retroactive remediation;
- message-content access where policy requires auditing;
- connector creation/permission changes;
- notification-contact changes;
- VIP changes;
- bulk-sender authorization changes;
- DMARC/BIMI configuration changes;
- scanner/system configuration changes;
- secrets/security configuration actions;
- service enable/disable;
- export actions;
- audit-log export itself.

## Audit record

A logical audit entry should include:

- audit event ID;
- timestamp;
- region;
- deployment;
- customer ID when applicable;
- actor user ID / login;
- actor administrative level;
- actor role(s);
- impersonated subject, when applicable;
- impersonated customer, when applicable;
- action;
- resource type;
- resource identifier;
- result: success / denied / failed;
- reason supplied for high-risk action where required;
- source IP;
- device/session identifier where available;
- authentication/session ID;
- permission/authorization context;
- trace/correlation ID;
- control-service/node identity;
- changed fields or safe before/after representation;
- failure/deny reason code when applicable.

## Before / after data

For configuration changes the audit record should capture enough information to answer:

> Who changed what, from which value to which value, when, for which customer, and under what permission context?

However, audit diffs must never store:

- passwords;
- access/refresh tokens;
- session cookies;
- private keys;
- OpenBao credentials/tokens;
- AWS credentials;
- message bodies;
- raw MIME;
- attachment contents;
- full sensitive AI prompts;
- other secrets.

Sensitive values are represented as:

- redacted;
- changed/not changed;
- secret identifier/version;
- cryptographic fingerprint where useful.

## Message-related administrative access

Viewing message content can itself be security-sensitive.

System policy may require audit events for:

- full message view opened;
- raw headers viewed;
- raw MIME downloaded;
- attachment downloaded;
- quarantine release;
- remediation action.

Support must never gain content access through the audit subsystem.

The audit record may state that content was viewed, but must not contain the content.

## Impersonation

Every impersonated audit event preserves both identities.

Example conceptual record:

```text
actor:
  support.agent@nullapart.com

actor_level:
  SUPPORT

impersonated_subject:
  admin@customer.example

customer_id:
  CZA-81

action:
  POLICY.UPDATE

resource:
  inbound_spam_policy

reason:
  Customer support case NUL-CASE-...

result:
  SUCCESS
```

No audit view may collapse the actor and impersonated subject into one identity.

## Storage design

The Admin Audit Store is authoritative and append-only from the application perspective.

Recommended initial design:

- dedicated PostgreSQL audit schema/tables;
- no UPDATE/DELETE permission for normal application roles;
- inserts only through an audit writer/service/module;
- strong database privileges;
- immutable event identifiers;
- timestamps generated/validated server-side;
- periodic integrity checkpoints.

For stronger tamper evidence, support:

- hash chaining or signed audit batches;
- periodic export/checkpoint to an immutable S3 location;
- S3 Object Lock/WORM retention where required;
- KMS signing/encryption where appropriate.

Exact mechanism will be selected during implementation, but ordinary administrators must not be able to edit or delete history.

## Retention

Audit retention is a System-level policy.

Retention should normally exceed ordinary application-log retention.

Deletion/expiration must be:

- policy-controlled;
- region-bound;
- auditable;
- performed only by a restricted lifecycle mechanism.

## UI: Admin Audit

Audit logging must have a dedicated UI surface.

Suggested navigation:

### System Admin

`System → Audit Log`

Can see regional administrative audit events subject to explicit high-risk permission.

### Support

`Operations → Audit Log`

Can see:

- own activity;
- permitted Support activity;
- activity for customers within scope;
- Customer Admin actions where support permissions allow.

Cannot see message content through audit detail.

### Customer Admin

`Administration → Audit Log`

Tenant-scoped only.

Customer owner determines which customer roles can access the tenant audit log.

## Audit table

The primary audit view should be a high-density table, not cards.

Suggested columns:

- Time;
- Actor;
- Acting As;
- Customer;
- Action;
- Resource;
- Result;
- Source IP;
- Reason;
- Trace ID.

Role/context determines which columns appear.

## Filters

Support:

- date/time range;
- actor;
- customer ID;
- action category;
- resource;
- result;
- impersonated-only;
- source IP;
- trace ID;
- high-risk action;
- export action.

Customer:

- date/time range;
- actor;
- action category;
- resource;
- result.

## Detail drawer

Selecting an entry opens a permission-controlled detail drawer/page with:

- event summary;
- actor identity;
- impersonation context;
- timestamp;
- source/session details;
- authorization context;
- affected resource;
- safe before/after values;
- reason;
- result;
- related trace/event IDs.

No raw JSON is shown.

## Exports

Audit export is permission-controlled and is itself audited.

Supported formats can include CSV and a human-readable signed report later.

Exports must obey:

- tenant scope;
- role scope;
- regional residency;
- field-level redaction.

## Search and performance

The audit store is written for durability first.

UI queries use indexed fields such as:

- timestamp;
- customer ID;
- actor;
- action;
- resource;
- result;
- trace ID.

Long-retention archives may be moved to region-local immutable storage while recent/searchable data remains online.

## Observability relationship

A sanitized copy of selected audit events may be sent to SegLumberjack for operational correlation.

That copy is not authoritative.

```text
Admin action
   |
   +--> Admin Audit Store  <-- authoritative
   |
   +--> Durable event stream
   |
   '--> sanitized Sentry-compatible event --> SegLumberjack
```

## Security requirements

- server-side audit generation;
- client cannot supply actor identity;
- audit write failure handling must be explicit;
- high-risk control-plane mutations should fail closed if the required audit record cannot be committed;
- audit reads require explicit RBAC;
- audit UI cannot bypass underlying data/content permissions;
- exports are audited;
- audit subsystem administration is itself audited.

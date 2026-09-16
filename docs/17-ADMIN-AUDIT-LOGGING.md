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

## Mandatory message-content access audit

The following access events are mandatory audit events, not optional policy choices:

- full message/body view opened;
- raw MIME viewed or downloaded;
- attachment preview/download;
- raw sensitive headers viewed where classified as restricted;
- remote email resources deliberately loaded by an administrator;
- quarantine release;
- retroactive remediation.

The audit record states that access occurred but never stores the message body, raw MIME or attachment content.

Support must never gain content access through the audit subsystem.

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

## Transactional correctness

Where the administrative resource and audit record are stored in PostgreSQL, the mutation, audit event and transactional outbox event should commit atomically.

Preferred pattern:

```text
BEGIN
  authorize operation
  mutate resource
  INSERT admin_audit_event
  INSERT outbox_event
COMMIT
```

This prevents:

- resource changed but audit record missing;
- audit record says success but resource mutation rolled back;
- event published before the authoritative transaction committed.

The asynchronous outbox publisher runs only after commit.

For a high-risk mutation, failure to persist the required audit record must fail the administrative mutation closed.

For actions against external systems that cannot be part of the same database transaction, record:

1. requested/authorized action;
2. external attempt identity;
3. success/failure completion event;
4. provider correlation ID where available.

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

Initial design:

- dedicated PostgreSQL audit schema/tables;
- no UPDATE/DELETE permission for normal application roles;
- inserts only through an audit writer/module or transaction helper;
- strong database privileges;
- immutable event identifiers;
- timestamps generated/validated server-side;
- indexed search fields;
- periodic integrity checkpoints.

## Tamper evidence

Tamper-evident archiving is part of the target architecture, not merely an optional future enhancement.

Use one or more mechanisms such as:

- hash chaining or signed audit batches;
- periodic signed integrity manifests;
- periodic export/checkpoint to a region-local immutable S3 bucket;
- S3 Object Lock/WORM retention;
- KMS signing/encryption where appropriate.

The online PostgreSQL audit store remains searchable; immutable checkpoints provide independent tamper evidence and long-retention protection.

Ordinary administrators must not be able to alter or delete audit history or immutable checkpoints.

## Retention

Audit retention is a System-level policy.

Retention should normally exceed ordinary application-log retention.

Deletion/expiration must be:

- policy-controlled;
- region-bound;
- auditable;
- performed only by a restricted lifecycle mechanism;
- compatible with any active Object Lock/retention obligation.

## UI: Admin Audit

Audit logging has a dedicated UI surface.

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
Admin transaction
   |
   +--> Admin Audit Store  <-- authoritative
   +--> transactional outbox
   |       '--> SQS / async consumers
   '--> sanitized Sentry-compatible event --> SegLumberjack
```

## Security requirements

- server-side audit generation;
- client cannot supply actor identity;
- audit write failure handling is explicit;
- high-risk mutations fail closed if the required audit record cannot be committed;
- audit reads require explicit RBAC;
- audit UI cannot bypass underlying data/content permissions;
- exports are audited;
- audit subsystem administration is itself audited;
- immutable audit archive/checkpoint access uses separate least-privilege credentials.

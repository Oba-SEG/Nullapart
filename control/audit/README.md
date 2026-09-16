# Control-Plane Audit Module

Future first-class Admin Audit subsystem.

Responsibilities:

- server-side generation of administrative audit events;
- append-only authoritative persistence;
- transactionally coupling administrative mutation + audit + outbox where possible;
- impersonation actor/subject preservation;
- mandatory auditing of privileged message-content access;
- safe before/after change capture;
- retention/integrity controls;
- periodic tamper-evident checkpoints / immutable S3 archive;
- RBAC-scoped audit search;
- audit export;
- UI-facing query contracts;
- sanitized correlation events to SegLumberjack.

The audit subsystem must never store secrets, message bodies, raw MIME or attachment contents in change diffs.

The online audit store is authoritative; SegLumberjack and SQS copies are diagnostic/asynchronous derivatives.

See `docs/17-ADMIN-AUDIT-LOGGING.md`.

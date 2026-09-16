# Control-Plane Audit Module

Future first-class Admin Audit subsystem.

Responsibilities:

- server-side generation of administrative audit events;
- append-only authoritative persistence;
- impersonation actor/subject preservation;
- safe before/after change capture;
- retention/integrity controls;
- RBAC-scoped audit search;
- audit export;
- UI-facing query contracts;
- sanitized correlation events to SegLumberjack.

The audit subsystem must never store secrets, message bodies, raw MIME or attachment contents in change diffs.

See `docs/17-ADMIN-AUDIT-LOGGING.md`.

# policy

Future Rust policy runtime/compiler primitives.

PostgreSQL remains authoritative. Runtime evaluates versioned snapshots/caches distributed through the transactional outbox + SQS refresh path.

Policy evaluation is scoped to the relevant Tenant Message Instance even when several tenants share one original SMTP transaction.

Policy visibility levels are:

- CUSTOMER
- SUPPORT
- SYSTEM

Customer settings cannot weaken System security floors.

Post-accept policy actions must respect SMTP state: once the original SMTP transaction has received `250`, policy cannot retroactively reject that session and instead uses delivery/quarantine/hold/remediation semantics.

See `docs/06-POLICY-MODEL.md`.

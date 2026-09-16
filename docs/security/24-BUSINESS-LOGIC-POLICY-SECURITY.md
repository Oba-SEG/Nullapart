# Business Logic and Policy Security

**Status:** mandatory product-security rules.

## Principle

A request can be authenticated, authorized and syntactically valid and still be malicious or invalid under product business rules.

Nullapart must enforce state, sequence, ownership and security-policy invariants server-side.

## Policy hierarchy

Management/security precedence:

```text
SYSTEM security floors
  -> SUPPORT-managed controls where applicable
  -> CUSTOMER controls within allowed bounds
```

A lower level cannot weaken a higher security floor.

The UI may show inherited/effective values, but the backend/compiler enforces precedence.

## State-machine enforcement

Resource actions are valid only from allowed states.

Examples:

- only QUARANTINED/appropriate HELD messages can be released;
- DELIVERED remains immutable historical truth;
- remediation cannot rewrite delivery history;
- terminated customers cannot create new mail/config activity;
- domain `verified=true` cannot be set directly by client input;
- SEND_ONLY domain creation requires allowed Support/System workflow;
- audit history cannot be edited;
- applied database migrations cannot be rewritten;
- released quarantine action is idempotent and cannot cause duplicate delivery.

State transition validation is server-side and transaction-safe.

## TOCTOU / concurrency

Authorization and state validation should occur as close as possible to mutation.

Use:

- transaction;
- row locking where necessary;
- revision/optimistic locking;
- conditional update;

so the checked state cannot silently change before the action commits.

## High-risk changes

Examples:

- System security-floor reduction;
- disabling a required scanner;
- broad third-party content export;
- cross-region data movement;
- break-glass privilege;
- audit-retention weakening;
- global allowlist;
- platform-wide outbound relay change.

Require:

- stronger permission;
- step-up authentication;
- reason;
- Admin Audit;
- optional/required second approval according to final governance policy.

Changes that disable core security evidence/audit require especially strong controls.

## Bulk operations

Bulk actions must not bypass per-object authorization/business rules.

Examples:

- bulk quarantine release;
- bulk policy change;
- bulk domain operation;
- bulk customer lifecycle action.

Validate every selected resource remains within scope.

Use bounded batch size, idempotency and partial-result reporting.

## Domain verification

Domain ownership/authorization is established through a defined verification process.

Do not allow:

- browser-supplied `verified` flag;
- arbitrary DNS result supplied by client;
- copied verification state from another tenant.

Verification evidence is bound to customer + domain + challenge/version.

## Tenant lifecycle

Transitions:

- ACTIVE;
- GRACE;
- SUSPENDED;
- TERMINATED.

Each transition defines:

- who can perform it;
- step-up/approval;
- mail-plane behavior;
- login/control behavior;
- connector behavior;
- retention/deletion;
- rollback/reactivation rules;
- notifications;
- audit.

## Quarantine/release

Before release:

- re-authorize actor;
- verify current tenant/resource state;
- verify item still eligible;
- enforce idempotency;
- record audit;
- use trusted reinjection.

A release request cannot choose another tenant's recipients/routing.

## Remediation

Retro-remediation requires:

- delivered historical state;
- authorized connector capability;
- exact customer/mailbox scope;
- safe matching;
- idempotency;
- audit;
- outcome state.

Do not blindly retry an external destructive action after an unknown timeout without provider reconciliation.

## Policy publication

Publishing policy:

1. validate schema/business rules;
2. enforce System floors;
3. compile;
4. assign revision;
5. atomically persist configuration + audit + outbox;
6. distribute;
7. report loaded/stale revisions.

Client cannot choose arbitrary published revision status.

## Anti-automation/business abuse

Protect workflows from:

- rapid repeated create/delete;
- resource exhaustion by huge rule sets;
- self-approval;
- circular group/policy relationships;
- duplicate notification/remediation;
- timing/order abuse;
- stale UI overwriting newer security settings.

## Time

Security rules involving time use server-side trusted timestamps.

Do not trust client clocks for:

- expiry;
- retention;
- exception validity;
- audit time;
- cooldown/rate windows;
- MFA/session age.

## Monetary/billing

Billing is out of scope. Do not introduce authorization/business decisions based on an internal billing subsystem.

## Testing

For each business workflow test:

- valid transition;
- invalid transition;
- stale/concurrent transition;
- duplicate request;
- unauthorized role;
- wrong tenant/owner;
- lower-level security-floor override;
- boundary values;
- partial external failure;
- rollback/compensation where applicable.

## AI-agent rules

AI agents must not:

- implement a UI state transition without backend invariant enforcement;
- trust hidden/disabled UI controls;
- add a client field that directly sets trusted server state;
- bypass policy hierarchy;
- update delivery history to simplify remediation;
- skip idempotency for destructive/retryable actions.

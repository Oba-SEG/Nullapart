# Policy Model and Runtime Configuration

## Policy families

Policies are separate families rather than one universal object.

Initial families:

- connection security;
- sender reputation;
- recipient controls;
- authentication;
- greylisting;
- geolocation;
- spam filtering;
- malware;
- attachments;
- URL security;
- content security;
- ML threat classification;
- VIP protection;
- impersonation;
- inbound routing;
- outbound routing;
- outbound abuse;
- bulk sending;
- quarantine;
- notifications;
- connectors/remediation;
- retention;
- DMARC/BIMI;
- transport security.

## Administrative visibility

Each setting declares:

- CUSTOMER;
- SUPPORT;
- SYSTEM.

Customer settings cannot weaken System-enforced minimum security bounds.

## Policy scope and recipient partitioning

Policy evaluation is customer/recipient scoped even when several customers received the same original SMTP transaction.

Shared content findings can be reused, but effective policy/disposition is calculated on the relevant Tenant Message Instance.

See [SMTP Transaction and Tenant Message Contract](18-MESSAGE-TRANSACTION-CONTRACT.md).

## Source of truth

PostgreSQL is authoritative.

Runtime flow:

```text
PostgreSQL transaction
  |-- policy/config change
  '-- transactional outbox row
          |
          v
        SQS
          |
          v
runtime refresh consumers
          |
          +--> Redis/Valkey shared cache
          '--> Mail/scanner node local snapshot
```

Redis/Valkey accelerates reads; it is not the source of truth and is not assumed to be the durable configuration event bus.

## Cache refresh

Normal update is event-driven and immediate through the durable event/outbox path.

Periodic reconciliation repairs missed events and regularly refreshes stale caches.

Support/System Admin have audited manual refresh actions for:

- tenant;
- policy family;
- specific node;
- deployment.

## Cache status

Support/System UI should display database/config revision vs node-loaded revision so stale nodes are visible.

## Last-known-good

Mail nodes persist the most recent valid runtime snapshot.

If control services, SQS or Redis/Valkey are temporarily unavailable, nodes can load the last-known-good snapshot where safe and clearly report stale configuration status.

A stale snapshot must not silently be presented as current.

## Transactional changes

Configuration mutation, audit and outbox creation should be one PostgreSQL transaction where applicable:

```text
BEGIN
  authorize
  update policy/config
  increment revision
  insert admin audit event
  insert outbox event
COMMIT
```

The outbox publisher delivers the event only after commit.

This prevents database state, audit history and runtime-refresh events from silently diverging.

## Policy actions

Core actions include:

- allow;
- allow with warning/header;
- quarantine;
- hold;
- reject;
- defer;
- throttle;
- redirect where explicitly permitted;
- require approval;
- temporarily suspend sender/tenant for outbound abuse where configured.

Each action carries a stable internal reason code.

SMTP-stage actions are only used at stages where SMTP semantics permit them. A policy evaluated after SMTP `250` cannot retroactively reject the original SMTP transaction.

See [Durable Event Architecture](20-EVENT-DURABILITY.md).

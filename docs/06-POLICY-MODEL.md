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

## Source of truth

PostgreSQL is authoritative.

Runtime flow:

```text
PostgreSQL
  -> policy/config compiler
  -> versioned snapshot
  -> Redis cache + durable change event
  -> Mail/scanner nodes
  -> local last-known-good snapshot
```

## Cache refresh

Normal update is event-driven and immediate.

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

If control services are temporarily unavailable, nodes can load the last-known-good snapshot where safe and clearly report stale configuration status.

## Transactional changes

Configuration updates should use the transactional outbox pattern so database commits and configuration-change events cannot silently diverge.

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

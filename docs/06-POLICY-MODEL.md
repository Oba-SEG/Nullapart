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

## Who publishes each family

Management level decides who may author and publish a revision for a scope. It
does not decide whether a delivery stage reads the result; the rule profile
below reports that.

Customer-managed families (a tenant administrator publishes these for their own
tenant):

- `attachments`;
- `connectors_remediation`;
- `inbound_routing`;
- `notifications`;
- `outbound_routing`;
- `quarantine`;
- `spam_filtering` (security floor remains enforced).

`spam_filtering` carries `security_floor = true` through the move, so a tenant
threshold revision cannot disable the platform floor. The remaining 17 families
are Support or System level.

The authoritative list is `POLICY_FAMILY_MANAGEMENT_LEVELS` in
`crates/mail-core/src/policy_admin.rs`, which the offline tier gate reads before
touching the database; an ignored test asserts it still mirrors the seeded
`policy_families` rows, and migration `041_customer_policy_levels.sql` records
the customer-level move.

## Rule profile per family

A published rule set only changes mail where a runtime stage reads it, so the
policy detail response carries a derived profile for the family and the console
builds its rule editor from that profile rather than from the shared rule
contract:

- the enforcement mode, which names the stage that reads the family's revisions,
  or states that none does;
- which condition predicates that stage evaluates, per fieldset;
- the exact `action.metadata` keys the publish validator accepts, with their
  bounds, built-in defaults and how several enabled rules merge.

`crates/mail-core/src/policy_profile.rs` is the registry, and its tests pin the
wired set to the constants the readers actually match on, so a family cannot be
presented as enforced unless a stage reads its rules. Today four families have a
reader (`ml_threat_classification`, `bulk_sending`, `outbound_abuse`,
`sender_reputation`), and both readers consume only enabled rules, rule order and
`action.metadata`. No family evaluates a condition predicate yet, and the console
says so instead of offering fields the delivery path would ignore.

Wiring a new family means adding its reader constant and profile fields in that
registry, which is what turns a stored revision into a delivery decision.

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

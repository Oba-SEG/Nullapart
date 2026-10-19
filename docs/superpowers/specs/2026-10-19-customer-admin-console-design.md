# Customer Admin Console — Design

**Date:** 2026-10-19
**Status:** approved by the owner for full implementation ("do everything, fully and completely")
**Branch:** `fix/security-foundation-hardening`

## The bet

A `customer_admin` today can see almost everything in the platform console and change almost nothing: the builtin role holds view permissions on ten surfaces, `policies:manage` over the 4 customer-level policy families, and `admin:users:manage` for their own tenant's administrators. The navigation is written for a platform operator, so the tenant admin's first screen offers them Scanner fleet health and a Customers directory containing exactly one row.

This arc gives the tenant admin real control over their own tenant, then re-shapes the interface around what they can actually touch. Capability first, presentation second.

## Decisions taken

| Decision | Outcome |
| --- | --- |
| Scope | Capability first, then IA |
| Tenant-owned controls | Own-domain self-service, more customer-level policy families, tenant notification settings, outbound sender approval |
| Reclassification | `quarantine`, `spam_filtering` (with `security_floor = true`) and `notifications` move to customer level |
| Notifications | In scope, including a real delivery path. A settings surface nothing reads was rejected as the same fake-control defect the per-family rule profile just removed. |

## Actor model

`customer_admin` builtin role after this arc:

| Permission | Before | After | Why |
| --- | --- | --- | --- |
| `admin:domains:manage` | no | **yes** | add and verify their own domains |
| `domain-security:manage` | no | **yes** | change their own domain posture and remediation state |
| `outbound-intelligence:manage` | no | **yes** | activate/approve their own senders |
| `notifications:manage` | n/a | **new, yes** | tenant notification settings |
| `scanner:operations:view` | yes | **no** | platform fleet health is not a tenant concern |
| `deep-ai:view` | yes | **no** | revised after live review: a release/artifact-grant console a tenant cannot act on is platform context, not customer value |
| `connectors:view` | yes | **no** | revised after live review: Phase 8 ships no provider worker, so the rows describe platform state the tenant cannot interpret or change |
| everything else | unchanged | unchanged | |

Still withheld: `admin:customers:manage`, `admin:impersonate`, `operations:*`, `models:*`, `audit:cross-customer`, `deep-ai:view|manage`, `connectors:view|manage`. Each new grant is tenant-bounded by the session's customer scope, not by the permission name: a `customer_admin` holding `admin:domains:manage` still gets a 404 for another tenant's `:customerId`, which is what `domain_management_refuses_a_foreign_customer_and_reaches_their_own` proves.

The first live pass of this console shipped with `deep-ai:view` and `connectors:view` left in place, which put a Deep AI console, a connector-remediation queue and the model registry in front of a customer administrator. Both grants were withdrawn and the boundary is now enforced twice: the Rust capability-set test lists the view permissions among the forbidden ones, and `frontend/src/test/tenant-console-boundary.test.tsx` renders each customer surface against a `tier: "customer"` session, failing on platform vocabulary or on any `/deep-ai`, `/connectors`, `/models`, `/features`, `/operations/runtime`, `/scanner-operations` or `/audit/checkpoint-status` request. `Policies` also stops offering the Feature overrides entry, and `FeatureOverrides` itself refuses to read `/features` at the customer level, because `list_features` authorizes on `policies:view` — a permission the tenant legitimately holds — so hiding the link alone still leaked the platform rollout catalog by URL.

### How the revocation reaches an existing deployment

Builtin roles resolve from the static `BUILTIN_ROLES` catalog in the in-memory store, but the Postgres store reads a session's effective permissions from `admin_role_permissions` (`permissions_for_user`), and the login seed was `INSERT … ON CONFLICT DO NOTHING`. An additive-only seed therefore propagates a *new* grant while a revoked one survives on every already-seeded deployment: `scanner:operations:view` would keep working for `customer_admin` on `.4` no matter what the catalog said.

`ensure_builtin_roles` now reconciles in both directions: it still seeds additively, and additionally deletes rows on a builtin role that the catalog no longer lists. This runs inside the login transaction, before `permissions_for_user`, so a session is built from the reconciled set. The catalog is the single authority; a hand-written migration would be a second copy of `BUILTIN_ROLES` able to drift from it. Builtin roles are immutable through the management API (`is_builtin_role` refuses edits), so nothing an operator granted can be silently deleted by this path. `login_reconciles_builtin_role_grants_with_the_catalog` proves it against PostgreSQL.

### Scope guarantees (proved, not assumed)

* `POST /admin/customers/:id/domains` and `…/domains/:id/verify` build their `Route` with `target: Some(&customer_id)`, so `in_scope()` denies any target outside the session's customer with a 404. A tenant admin holding the permission still cannot touch another tenant.
* Every outbound-intelligence statement binds `context.customer_id`; the upsert's conflict key is `(deployment_id, customer_id, sender_address, source_kind, source_id)`.
* `send_only` domain creation additionally requires `may_change_customer_identity`. A tenant admin is refused there. The console stops offering it and names the reason, rather than presenting a button that 403s.

## Policy family reclassification — migration `041_customer_policy_levels.sql`

```
quarantine            support  -> customer
spam_filtering        support  -> customer, security_floor stays true
notifications         system   -> customer
```

`security_floor` already exists on `policy_families` and `mandatory_security_floors_cannot_be_disabled` already enforces it, so a tenant publishing spam filtering cannot disable the platform floor. Feature overrides and tenant routing are untouched.

## Notification subsystem

### What exists

`domain_observer` (a running tokio worker) inserts into `domain_security_notifications`: 9 notification types, `info|warning|critical` severity, title, detail, `open|acknowledged|resolved`. The console renders them on `/domain-security`. Nothing delivers them to a customer. `notification_stationery::render_html/render_text` exists with zero callers.

### What gets built

```
domain_security_notifications (existing producer)
  -> notification_worker claims open rows past the tenant's floor
  -> outbox_events row ('notification.customer', idempotency_key)
  -> claim + submit_smtp() to the trusted internal submission endpoint
  -> notification_deliveries ledger (sent / dead-lettered)
```

Reuse, do not reinvent:

* the SMTP client is `submit_smtp()` in `crates/mail-core/src/quarantine_reinjection.rs`, already reviewed and already used for trusted internal submission;
* the claim/lease/dead-letter/ledger shape copies `claim_quarantine_reinjection_event`, `reinjection_deliveries` and `reinjection_dead_letters`;
* the worker loop copies the `reinjection_worker` / `domain_observer_worker` spawn pattern in `crates/mail-core/src/bin/mailcore-server.rs`;
* no new dependency. `tokio` and the hand-rolled SMTP path already cover it, so `docs/26-PACKAGE-COMPATIBILITY.md` is not in play.

### Settings store — migration `042_tenant_notification_settings.sql`

```
tenant_notification_settings
  deployment_id, customer_id      one row per tenant, unique
  enabled                         boolean, default true
  severity_floor                  info | warning | critical, default warning
  recipient_emails                text[], validated, capped, tenant addresses only
  digest_window_minutes           integer, coalesces repeats of the same type+domain
  updated_by, updated_at
```

Recipients are constrained to addresses inside the tenant's own verified domains, so a tenant cannot use Nullapart to mail another tenant or an arbitrary third party. That check is server-side and is the reason this is a security review item, not a form field.

### Idempotency, loop prevention, failure posture

* `idempotency_key = notification:<domain_security_notifications.id>`; a replayed claim cannot double-send.
* The digest window suppresses a second mail for the same `(customer, notification_type, domain)` inside the window; the row still records in the console.
* Notification mail carries the trusted internal submission context and a `X-Nullapart-Internal: notification` marker so it is excluded from the notification producer's own inputs. It cannot recursively generate notifications.
* Submission failure retries with the existing backoff and dead-letters with a reason. A notification failure never blocks or alters mail flow, and never silently reports success: the ledger row is the source of truth for what was sent.
* Content is the safe field set from `docs/14`: no raw MIME, no attachment content, no other tenant's recipients, no secrets.

### API

| Route | Permission | Notes |
| --- | --- | --- |
| `GET /api/v1/notifications/settings` | `notifications:view` | publishes `capabilities` in the same server-resolved shape as customers/policies |
| `PUT /api/v1/notifications/settings` | `notifications:manage` | idempotency key required, audited, tenant-scoped by authenticated context |

Both keyed off `context.customer_id`. No route takes a customer id from the client.

## Console IA for the tenant tier

The tier is read from the server-published session, never re-derived from role names.

| Surface | System actor | Tenant actor |
| --- | --- | --- |
| Section labels | System overview / Customer mail / Governance / Administration | Overview / Your mail / Your customer / Governance |
| `/` | platform metrics | own-customer metrics, same endpoint, already scoped |
| `/customers` | directory | "Your organisation": one customer card, domains, verification, source IP groups |
| `/domain-security` | view + manage | view their own findings; `acknowledge` becomes a real action (the `status` column exists with no route behind it today), plus the notification settings card |
| `/outbound-intelligence` | view + manage | now functional: activate, deactivate, approve their own senders |
| `/policies` | 24 families | 7 editable families, the rest shown as platform-controlled with the reason |
| `/admin-users`, `/roles` | platform | "Your administrators", "Your roles" |
| `/scanner-operations`, `/operations`, `/models` | shown | not shown, not reachable |

Every withheld action states which permission it needs, using the capability-lock pattern already in `frontend/src/api/capabilities.ts`.

## Testing

**Rust**

* builtin catalog: `customer_admin` holds exactly the tenant boundary — the new manage grants in, `scanner:operations:view` and the platform grants out (`customer_admin_capability_set_is_the_tenant_boundary`); catalog and permission list agree.
* cross-tenant refusal: a `customer_admin` context adding a domain on another customer gets 404 before any database work; the same call on their own customer reaches the store.
* outbound: tenant admin upsert writes only their own `customer_id` row, and a sender whose domain is not a verified domain of that tenant is refused with `DOMAIN_NOT_VERIFIED` (`approved_sender_domain_must_be_verified_for_the_approving_tenant`).
* login reconciliation: a grant left behind by the previous catalog is retired on the next login, and every builtin role's stored rows then equal the catalog (`login_reconciles_builtin_role_grants_with_the_catalog`).
* notification settings: recipient outside the tenant's domains is rejected; PUT requires an idempotency key; replay of the same key does not write twice.
* worker: claim leases one row, dead-letters after exhausted attempts, and the idempotency key prevents a second `outbox_events` row for the same notification.
* PostgreSQL `--ignored` suite for the store and migration paths.

**Frontend (vitest)**

* tier-aware sidebar: tenant sees no Scanner nodes/Runtime status/Models; system actor unchanged.
* `/customers` renders the single-tenant shape and the send_only refusal reason.
* notification settings: recipient validation, severity floor, save-and-confirm, capability lock when `notifications:manage` is absent.
* outbound: manage actions appear only with the capability.

**Live on `.4`**

As `ob2-customer-admin`: add and verify a domain, publish a quarantine policy rule, approve a sender, save notification settings, then deliberately attempt a cross-tenant domain add and confirm the 404. Confirm a real notification mail reaches the local Postfix queue and appears in `notification_deliveries`.

## Out of scope

* Per-user (not per-tenant) notification subscriptions.
* Slack/Teams/webhook channels. Email only, per `docs/14`.
* SMS or pager escalation.
* Making the 20 unwired policy families enforced. The rule profile states that honestly today; wiring readers is its own arc.
* DMARC aggregate report ingestion changes.

# Tenant Context, Feature Overrides and Application-Boundary Routing

**Status:** mandatory cross-cutting architecture for all tenant-scoped Control Plane work.

## Purpose

Nullapart is multi-tenant within each regional deployment. Tenant identity must be resolved once at the trusted application boundary and carried explicitly through authorization, database, feature, audit and background-work paths.

Client-supplied tenant identifiers are navigation inputs only. They are never proof of tenancy or authorization.

## TenantContext

Every authenticated Control Plane request that operates on customer data resolves a server-owned `TenantContext` before domain/business logic runs.

The context contains at minimum:

- deployment/region identity;
- real authenticated actor;
- customer-entry (impersonation) context where active;
- active customer public identity;
- internal customer/tenant key;
- effective roles/permissions;
- session/authentication assurance and step-up state;
- effective configuration/feature revision;
- trace/correlation identity.

`TenantContext` is constructed from trusted server/session state plus an authorized tenant-selection operation.

Do not construct it directly from:

- URL/query/path customer ID;
- `X-Tenant-ID` or similar arbitrary client header;
- request body tenant/customer fields;
- local/session browser storage;
- frontend feature state.

## Application-boundary routing

Regional routing occurs before tenant routing.

```text
Browser
  -> deployment hostname, e.g. za.nullapart.com
  -> regional ALB/WAF
  -> regional Control Backend/BFF
  -> authenticated session
  -> TenantContext resolver
  -> authorization / feature evaluation / business logic
  -> transaction-scoped PostgreSQL RLS context
```

A ZA deployment does not satisfy a request for an EU/UK/US tenant by querying another region's database.

Cross-deployment navigation is a deliberate user action to the target deployment boundary and requires authentication/session handling appropriate to that deployment.

## Active-tenant selection

A user who is authorized for more than one customer may select an active customer.

Selection flow:

1. authenticate user;
2. query server-authorized customer memberships/permissions;
3. user selects from that allowed set;
4. server validates membership and lifecycle state;
5. server records active tenant context in approved session/server state;
6. subsequent requests derive tenant scope from that state;
7. switching customer replaces the context and clears tenant-specific cached UI/server state as required.

The server must reject a selected customer that is not in the actor's authorized set even if the customer ID is syntactically valid.

## System and Support cross-tenant access

System/Support roles do not use an unrestricted global tenantless query path for ordinary customer operations.

Instead:

- cross-customer search/listing uses explicit platform permission and bounded query paths;
- opening/acting on a specific customer establishes explicit customer scope;
- impersonation preserves the real actor and the entered customer; the actor's own roles and permissions are unchanged;
- customer-sensitive actions remain tenant scoped and audited;
- Support content restrictions remain effective even when tenant scope is valid.

## Background work and durable events

Tenant-scoped background jobs/events carry explicit:

- deployment;
- customer/tenant identity;
- resource identity;
- event schema/version;
- authorization/purpose context where the consumer needs it;
- trace/correlation identity.

Workers never infer tenant identity only from an opaque object ID when authoritative scope can be carried explicitly.

No generic "tenantless" worker may scan all customers by default merely because it runs internally.

## Feature-switch model

Feature switches remain part of the versioned configuration architecture, not a new feature-flag microservice.

Supported scope levels:

- System/global within the deployment;
- deployment;
- tenant/customer.

### Override value

A tenant/deployment override should support an explicit inheritance model rather than duplicating defaults.

Conceptually:

- `INHERIT`;
- `ENABLED`;
- `DISABLED`;
- typed configuration value where the feature uses parameters rather than a boolean.

## Evaluation precedence

Security and emergency controls always win.

Baseline precedence, from strongest to weakest:

```text
SYSTEM emergency/kill disable
  -> SYSTEM mandatory security floor
  -> deployment override
  -> tenant override
  -> feature default
```

A lower level cannot weaken a higher security requirement.

Examples:

- tenant cannot enable Deep AI if System kill switch disables it;
- tenant cannot disable a mandatory malware scanner;
- deployment may disable a capability unavailable in that AWS region;
- tenant may enable an optional approved feature when System/deployment policy permits it.

## Override metadata

Every tenant/deployment override records:

- stable feature ID;
- scope type and scope identity;
- typed value;
- owner/actor;
- reason;
- created/updated timestamps;
- effective start/end/expiry where applicable;
- configuration revision;
- security impact classification;
- audit event;
- rollout/source metadata where applicable.

Temporary exceptions/experiments require expiry/removal targets.

## Effective-value explanation

The feature evaluator should return enough internal metadata to explain why a value is effective:

- effective value;
- winning scope;
- source revision;
- whether a higher-level security/kill rule suppressed a lower override.

Normal customer UI should display a designed explanation such as:

- Default;
- Deployment policy;
- Tenant override;
- Disabled by System security control.

Do not expose raw evaluation JSON.

## Authorization and feature flags

Feature flags are never authorization.

The correct order for a tenant action is conceptually:

1. authenticated session;
2. resolve authorized `TenantContext`;
3. server-side feature/capability evaluation;
4. server-side action/resource authorization;
5. business-state/policy validation;
6. transaction/RLS/audit.

A feature being enabled does not grant a role permission it does not possess.

## PostgreSQL / RLS

Tenant-scoped persistence uses the `TenantContext` internal key to establish transaction-scoped RLS context where applicable.

Connection-pool reuse must not preserve a previous tenant scope.

Cross-tenant platform queries use explicitly reviewed roles/functions/query paths and never globally disable RLS for ordinary request handling.

## Cache

Tenant-scoped cache keys include deployment + tenant identity + configuration revision where applicable.

Never cache a tenant-sensitive response under only a resource ID or URL path if another tenant could resolve the same cache key.

Switching active tenant must not expose cached data from the previous tenant.

## UI

Tenant selector/navigation:

- only shows server-authorized tenants;
- never trusts a hidden client list as authoritative;
- clears tenant-specific query caches on switch;
- keeps deployment/tenant context visible enough to prevent operator mistakes;
- preserves impersonation banner/context.

Feature administration should show:

- default;
- deployment value;
- tenant override;
- effective value;
- reason/owner/expiry where authorized.

## Testing

Required tests include:

- user cannot select unauthorized tenant;
- guessed tenant/customer ID rejected;
- client tenant header cannot change scope;
- tenant switch clears/isolate caches;
- tenant A cannot read/write tenant B;
- pooled DB connection cannot retain previous RLS scope;
- System/Support cross-tenant path requires explicit permission;
- Support content prohibition survives valid tenant context;
- tenant override cannot defeat System kill/security floor;
- deployment override precedence works;
- expired override no longer applies;
- feature value and audit revision remain reproducible;
- background event with wrong tenant/resource relationship is rejected/quarantined.

## AI-agent rules

AI agents must not:

- add tenant/customer IDs to a request and treat them as authorization;
- invent a tenantless repository/query helper for convenience;
- make frontend routing authoritative for tenancy;
- implement feature evaluation only in the browser;
- permit tenant overrides to weaken System security floors;
- omit deployment/customer scope from tenant-specific events/jobs/caches.

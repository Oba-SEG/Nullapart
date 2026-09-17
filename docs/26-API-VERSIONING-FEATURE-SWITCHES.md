# API Versioning and Feature Switches

**Status:** cross-cutting product/runtime contract.

## API versioning principle

Nullapart does not expose a general public customer API initially.

The frontend and regional Control Backend are deployed as a coordinated product, so do not add `/v1` to every internal route merely from habit.

Version an API/contract when independent consumers, compatibility windows or external integrations require it.

## Contract categories

### Coordinated frontend/BFF API

For same-release frontend + backend:

- stable typed contract;
- backward compatibility during rolling deployment where necessary;
- no mandatory URL version prefix initially.

Breaking changes still require coordinated rollout and compatibility testing.

### Internal service contracts

If components deploy independently, explicitly version breaking contracts.

Examples:

- scanner contract;
- event payload;
- model/skill tool schema;
- artifact broker contract.

### Events

Every durable event has an explicit schema/event version.

Consumers must:

- reject/park unsupported versions safely;
- tolerate documented additive changes;
- never silently reinterpret a breaking schema.

### Webhooks/external integrations

Webhooks have explicit signature + payload versioning.

The version may be represented through:

- header;
- media type;
- endpoint path;
- signature version,

according to the integration design.

### Future public API

If a public customer API is introduced, it requires a dedicated architecture/threat/documentation phase including:

- lifecycle policy;
- version/deprecation policy;
- rate limits;
- scopes;
- audit;
- SDK/documentation strategy.

## Version compatibility

Do not maintain old API versions with known authorization/security weaknesses merely for compatibility.

Security fixes may intentionally change behavior across supported versions.

## Deprecation

A versioned external contract defines:

- introduction date;
- supported versions;
- deprecation notice;
- end-of-support date;
- migration guidance;
- telemetry showing remaining use.

Do not remove a supported external contract without a deliberate migration process.

# Feature switches

## Purpose

Feature switches support:

- controlled rollout;
- canary/pilot customers;
- kill switches;
- regional capability differences;
- safe migration;
- operational containment.

They are not authorization and not a permanent substitute for product configuration.

## Switch types

### Release switch

Short-lived flag allowing incomplete/new code to be merged but not exposed until ready.

Must have owner and removal target.

### Operational kill switch

Allows an authorized operator to disable a failing/risky capability quickly.

Examples:

- Deep AI submissions;
- a problematic scanner enrichment;
- a connector provider integration;
- remote-content proxy.

A kill switch must fail toward the documented safe mode.

### Customer capability switch

Controls whether a capability is available for a specific customer/deployment when the commercial/security/product model permits it.

It does not grant underlying RBAC permission.

### Experiment/pilot switch

Allows controlled evaluation for specified tenants/users without changing global behavior.

Experiments involving security enforcement require especially careful review; users must not randomly receive weaker protection.

## Evaluation location

Security-sensitive feature switches are evaluated server-side.

The frontend may consume the resulting capability state for UX, but client-side flags alone never protect an endpoint or resource.

## Scope

A switch declares applicable dimensions such as:

- deployment;
- customer;
- role/capability;
- node/service;
- percentage cohort only where safe;
- environment.

Avoid ambiguous precedence.

## Configuration source

Feature-switch configuration belongs in the controlled configuration/policy system with:

- revision;
- actor;
- audit;
- outbox distribution;
- last-known-good semantics where Mail Plane use is allowed.

Do not create an unaudited separate database of magic booleans.

## Security floors

Feature switches must not disable mandatory controls such as:

- authentication;
- tenant authorization;
- Admin Audit;
- required encryption;
- System security floors;
- core data-residency restrictions.

A feature switch cannot turn a security requirement into optional behavior unless the security architecture explicitly defines that mode.

## UI

System/Support UI should show, where appropriate:

- switch name/purpose;
- scope;
- current state;
- owner;
- created/changed time;
- expiry/removal target;
- reason;
- impacted customers/deployments.

Customer-facing feature availability should be presented as product capability, not internal flag names.

No raw JSON switch editor.

## Change controls

High-risk switch changes require:

- permission;
- reason;
- audit;
- optional step-up/second approval depending on impact;
- observability/alerting.

Kill-switch use is audited.

## Lifecycle

Every non-permanent switch has:

- owner;
- creation date;
- intended removal date;
- default;
- safe fallback;
- test coverage.

CI/static checks should flag stale/expired release switches where practical.

## Database/schema interaction

Do not remove a flag until both enabled and disabled code/data paths are no longer needed.

For migrations:

1. deploy compatible schema;
2. deploy code behind switch;
3. enable gradually;
4. observe;
5. make behavior default;
6. remove legacy path;
7. remove switch in a later safe change.

## Testing

Test:

- enabled;
- disabled;
- stale/missing config;
- customer/deployment scope;
- unauthorized flag change;
- UI/backend agreement;
- kill-switch failure mode;
- rollout during mixed-version deployment.

## AI-agent rules

AI coding agents must not:

- use a feature flag as authorization;
- leave new release flags without owner/removal plan;
- create client-only security switches;
- weaken mandatory controls behind an emergency flag;
- silently introduce API breaking changes;
- create `/v2` simply to avoid designing a compatible migration.
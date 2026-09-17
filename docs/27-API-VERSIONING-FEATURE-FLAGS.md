# API Versioning, Feature Flags and Feature Addition Governance

**Status:** mandatory contract/change-management architecture.

## Purpose

Nullapart needs explicit compatibility rules so independently deployed components, browser UI, workers, scanners and future integrations do not break each other silently.

Feature switches exist to control rollout, tenant capability and emergency containment, not to bypass authorization or permanently hide unfinished architecture.

Tenant-context/routing details are defined in [Tenant Context, Feature Overrides and Application-Boundary Routing](29-TENANT-FEATURE-ROUTING.md).

## API scope

Nullapart has no public customer API in the initial product.

The Control Plane still has versioned internal/browser-facing API contracts because frontend/backend releases can overlap during deployment and operational tools may depend on stable behavior.

## HTTP API versioning

Initial Control Plane HTTP API namespace:

`/api/v1/...`

Authentication routes may use a dedicated `/auth/...` namespace where required by the session/OIDC flow.

### Compatible changes within v1

Allowed examples:

- add optional response field;
- add optional request field with safe default;
- add endpoint;
- add enum value only when consumers tolerate unknown/new values;
- add pagination/filter capability;
- improve safe error detail without changing existing error semantics.

### Breaking changes

Require a new major API version or coordinated migration if they:

- remove/rename required field;
- change field meaning/type;
- make optional input mandatory;
- change authorization/resource ownership semantics;
- change tenant-routing semantics;
- change idempotency semantics;
- change error meaning relied on by clients;
- alter path/resource identity incompatibly.

Do not silently break the API because frontend and backend are in the same repo.

## Deployment compatibility

Frontend and Control Backend release notes state supported API compatibility.

During rolling deployment, previous and next compatible versions must coexist for the defined rollout window.

Avoid requiring a perfectly simultaneous frontend/backend switch.

## Event versioning

Every durable event has:

- event type;
- event schema version;
- event ID;
- producer release;
- deployment/customer scope where applicable;
- timestamps/correlation.

Consumers tolerate additive compatible fields.

Breaking event changes use a new schema version/event type and migration strategy.

Old queued events must remain processable during rollout/rollback.

## Scanner contract versioning

Scanner SDK/request/response contracts are explicitly versioned.

Mail Core detects unsupported scanner contract versions rather than parsing unknown output optimistically.

## Policy/config snapshot versioning

Snapshots include:

- schema version;
- revision;
- compiler version/release;
- generation time.

Nodes reject unsupported future snapshot schema and keep the last-known-good compatible revision.

## AI skill/model APIs

The OpenAI-compatible serving protocol does not remove the need for Nullapart skill/input/output schema versions.

A model server upgrade must not silently redefine a skill contract.

## Deprecation

For any supported API/schema deprecation, document:

- replacement;
- first deprecated release;
- consumers affected;
- removal target;
- telemetry to confirm old use is gone.

Do not remove a contract while active supported clients/consumers still depend on it.

# Feature flags

## Principle

Feature flags are server-authoritative versioned configuration.

A frontend flag can hide/show UX, but it is never an authorization or tenant-routing boundary.

## Flag classes

### Release flag

Controls staged rollout of a new capability.

Expected to be temporary and removed after stable rollout.

### Operational kill switch

Allows authorized System operators to disable a risky/degraded capability quickly.

Examples:

- Deep AI analysis;
- a problematic scanner/parser;
- outbound remediation connector;
- new preview/remote-resource feature.

Kill switches preserve explicit safe failure behavior rather than pretending the disabled capability passed.

### Tenant capability switch

Enables/disables an optional approved capability for selected customers within a deployment.

This is not authorization and is not billing/entitlement unless a future external business system supplies that decision.

### Experiment flag

Permits controlled product/algorithm experimentation only when security/data handling remains within approved controls.

Do not experiment on Restricted content or security disposition without approved governance/evaluation.

## Scope levels

Supported feature-configuration scopes:

- System/global within deployment;
- deployment;
- tenant/customer.

Tenant context is resolved from authenticated server state before tenant-scoped evaluation.

A client cannot activate another customer's feature state by changing a URL/header/body field.

## Override model

Tenant/deployment overrides support explicit inheritance rather than copying defaults everywhere.

Conceptually:

- `INHERIT`;
- `ENABLED`;
- `DISABLED`;
- typed feature configuration value where required.

## Evaluation precedence

Baseline precedence from strongest to weakest:

```text
SYSTEM emergency/kill disable
  -> SYSTEM mandatory security floor
  -> deployment override
  -> tenant override
  -> feature default
```

A tenant override cannot defeat a System security floor/kill switch.

A deployment override may disable an unavailable capability in that regional deployment.

## Flag metadata

Every flag records:

- stable flag ID;
- description;
- class;
- owner;
- created date;
- default value;
- allowed scope(s);
- security impact;
- dependencies;
- rollout plan;
- rollback/kill behavior;
- expiry/removal target where temporary;
- audit requirement.

Every tenant/deployment override additionally records:

- scope identity;
- typed override value;
- actor/owner;
- reason;
- start/end/expiry where applicable;
- revision;
- audit event.

## Evaluation

Security-sensitive flags are evaluated server-side after trusted tenant/deployment context is resolved.

Client must not be able to send `feature=true` and activate a capability.

Evaluation considers:

- deployment;
- System security/kill state;
- tenant/customer scope;
- feature dependencies;
- actor permission where an action is involved;
- current configuration revision.

Feature enabled does not mean actor authorized.

## Effective-value explanation

Feature evaluation should be internally explainable:

- effective value;
- winning scope;
- revision;
- suppression by higher security/kill rule where applicable.

Normal UI shows designed concepts such as Default / Deployment / Tenant Override / Effective rather than raw JSON.

## Storage/distribution

Feature-switch configuration belongs in the versioned configuration/policy system and follows:

- PostgreSQL authoritative storage;
- revision;
- audit;
- transactional outbox;
- cache/distribution;
- last-known-good behavior where needed.

Do not create an unrelated feature-flag microservice during initial architecture unless requirements later justify one.

## UI

System/Support/Customer UI shows only switches the role is allowed to manage or observe.

Tenant override UI must show effective value and inheritance/override source.

A disabled feature has a designed disabled/unavailable state rather than broken navigation.

No raw feature-flag JSON editor.

## Audit

Audit:

- flag creation;
- default/scope change;
- deployment override;
- tenant override enable/disable/reset;
- emergency kill-switch action;
- expiry/removal;
- deletion.

## Flag lifecycle

Release/experiment flags are technical debt with an owner and removal target.

After rollout:

1. establish stable behavior;
2. remove old branch/code path;
3. remove obsolete flag;
4. update tests/docs.

Do not accumulate permanent nested feature-flag logic.

# New feature addition process

Every significant feature addition defines before implementation:

- owning roadmap phase;
- product/security objective;
- users/roles;
- data classes;
- trust boundaries;
- tenant/deployment routing impact;
- API/event/schema impact;
- UI;
- business-logic state/invariants;
- audit events;
- rate limits;
- failure semantics;
- feature flag/tenant override/rollout need;
- observability/SLO impact;
- migration;
- testing;
- rollback/kill switch;
- compliance/third-party impact;
- patch/zero-day exposure implications for new dependencies/parsers;
- runbook impact.

A feature that introduces a new external integration, public endpoint, parser, data store, cross-region path, LLM tool or privilege requires threat-model review.

## AI-agent rules

AI coding agents must not:

- create unversioned independently consumed contracts;
- remove v1 fields because current UI no longer uses them without deprecation review;
- use frontend feature flags as security controls;
- authorize tenancy from client-provided tenant IDs;
- allow tenant override to weaken System security floors/kill switches;
- add permanent flags with no owner/lifecycle;
- activate disabled features by bypassing server-side evaluation;
- create a new feature-flag service when existing versioned configuration is sufficient.

# API Versioning, Feature Flags and Feature Addition Governance

**Status:** mandatory contract/change-management architecture.

## Purpose

Nullapart needs explicit compatibility rules so independently deployed components, browser UI, workers, scanners and future integrations do not break each other silently.

Feature switches exist to control rollout and emergency containment, not to bypass authorization or permanently hide unfinished architecture.

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
- add enum value only when consumers are designed to tolerate unknown/new values;
- add pagination/filter capability;
- improve safe error detail without changing existing error semantics.

### Breaking changes

Require a new major API version or coordinated migration if they:

- remove/rename required field;
- change field meaning/type;
- make optional input mandatory;
- change authorization/resource ownership semantics;
- change idempotency semantics;
- change error meaning relied on by clients;
- alter path/resource identity incompatibly.

Do not silently break the API because frontend and backend are "in the same repo".

## Deployment compatibility

Frontend and Control Backend release notes state supported API compatibility.

During rolling deployment, the previous and next compatible versions must coexist for the defined rollout window.

Avoid requiring a perfectly simultaneous frontend/backend switch.

## Event versioning

Every durable event has:

- event type;
- event schema version;
- event ID;
- producer release;
- timestamps/scope.

Consumers must tolerate additive compatible fields.

Breaking event changes use a new schema version/event type and migration strategy.

Old queued events must remain processable during rollout/rollback.

## Scanner contract versioning

Scanner SDK/request/response contracts are explicitly versioned.

Mail Core must detect unsupported scanner contract versions rather than parsing unknown output optimistically.

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

Feature flags are server-authoritative configuration.

A frontend flag can hide/show UX, but it is never an authorization boundary.

## Flag classes

### Release flag

Controls staged rollout of a new capability.

Expected to be temporary and removed after stable rollout.

### Operational kill switch

Allows authorized System operators to disable a risky/degraded capability quickly.

Examples:

- Deep AI analysis;
- a problematic scanner;
- an outbound remediation connector;
- a new parser/preview feature.

Kill switches must preserve explicit safe failure behavior rather than pretending the disabled capability passed.

### Tenant capability switch

Enables an optional product capability for selected customers/deployments.

This is not billing/entitlement unless an external business system later supplies that decision.

### Experiment flag

Permits controlled product/algorithm experimentation only when security/data handling remains within approved controls.

Do not experiment on Restricted content or security disposition without approved governance/evaluation.

## Flag metadata

Every flag records:

- stable flag ID;
- description;
- class;
- owner;
- created date;
- default value;
- scope: System/deployment/customer;
- security impact;
- dependencies;
- rollout plan;
- rollback/kill behavior;
- expiry/removal target where temporary;
- audit requirement.

## Evaluation

Security-sensitive flags are evaluated server-side.

Client must not be able to send `feature=true` and activate a capability.

Evaluation considers:

- deployment;
- System policy;
- customer scope;
- feature dependency state;
- actor permission where an action is involved.

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

System/Support/Customer UI shows only switches that the role is allowed to manage or observe.

A disabled feature should have a designed disabled/unavailable state rather than broken navigation.

No raw feature-flag JSON editor.

## Audit

Audit:

- flag creation;
- scope/default change;
- customer enable/disable where administrative;
- emergency kill-switch action;
- deletion/removal.

## Flag lifecycle

Release/experiment flags are technical debt with an owner and removal target.

After rollout:

1. establish stable behavior;
2. remove old branch/code path;
3. remove obsolete flag;
4. update tests/docs.

Do not accumulate permanent nested feature-flag logic.

# New feature addition process

Every significant feature addition must define before implementation:

- owning roadmap phase;
- product/security objective;
- users/roles;
- data classes;
- trust boundaries;
- API/event/schema impact;
- UI;
- business-logic state/invariants;
- audit events;
- rate limits;
- failure semantics;
- feature flag/rollout need;
- observability;
- migration;
- testing;
- rollback/kill switch;
- compliance/third-party impact;
- runbook impact.

A feature that introduces a new external integration, public endpoint, parser, data store, cross-region path, LLM tool or privilege requires threat-model review.

## AI-agent rules

AI coding agents must not:

- create unversioned independently consumed contracts;
- remove v1 fields because current UI no longer uses them without deprecation review;
- use frontend feature flags as security controls;
- add permanent flags with no owner/lifecycle;
- activate disabled features by bypassing server-side evaluation;
- create a new feature-flag service when existing versioned configuration is sufficient.

# API Versioning, Feature Switches and Feature Addition Governance

**Status:** cross-cutting product/runtime contract.

## Principle

Nullapart must evolve without silently breaking independently deployed components, stale browser sessions, rolling deployments or persisted events/configuration.

Versioning and feature switches are deliberate compatibility mechanisms, not excuses to accumulate permanent dead code.

## API scope

Nullapart does not initially expose a public customer API.

The API versioning rules still apply to:

- frontend -> Control Backend/BFF contracts;
- internal service APIs where network boundaries exist;
- Deep AI OpenAI-compatible boundary extensions;
- scanner/network protocols where independently deployed;
- webhooks/connectors;
- event schemas;
- artifact-access endpoints.

Do not create network APIs where an in-process/module interface is sufficient.

## Versioning strategy

### Browser / Control Backend

Prefer backward-compatible API evolution within the current product generation.

Use additive changes first:

- add optional field;
- add endpoint/action;
- accept old and new request during migration;
- serve old response fields until frontend rollout is complete.

Do not add `/v1`, `/v2`, etc. to every internal endpoint preemptively.

Introduce an explicit major API version only when a real incompatible contract boundary must coexist.

### Independently deployed internal APIs

Use an explicit contract/schema version when caller and server can roll independently.

Requests/responses should support capability/version negotiation where that is safer than synchronized deployment.

### Events

Every durable event has an explicit event type + schema version.

Consumers:

- reject/route unsupported future versions safely;
- tolerate documented additive fields;
- remain idempotent;
- do not assume producer/consumer deploy simultaneously.

### Scanner contracts

SecurityFinding/scanner contracts are versioned.

A scanner upgrade must not silently reinterpret an existing status/category field incompatibly.

### ML/LLM contracts

Version independently:

- model input schema;
- structured output schema;
- skill version;
- prompt/instruction version;
- tool schema/toolset version.

## URL/header version location

Where an explicit API major version is needed, choose one consistent mechanism for that boundary.

Possible approaches include:

- path major version (`/api/v1/...`);
- media-type/content negotiation;
- explicit protocol version header.

Do not mix version mechanisms arbitrarily.

Auth credentials are never part of API-version URLs.

## Deprecation

A breaking-version transition documents:

- replacement;
- affected clients/components;
- introduction date;
- telemetry on old-version usage;
- migration plan;
- removal criteria/date;
- rollback/compatibility window.

Remove old versions only after verified consumers are migrated.

## Feature switches

A feature switch is a server-authoritative runtime decision controlling a capability without requiring an immediate binary rollback/rebuild.

Use feature switches for:

- staged rollout;
- region/deployment enablement;
- internal pilot;
- customer cohort rollout;
- safety kill switch;
- expensive/new scanner capability;
- experimental ML/Deep-AI skill;
- new connector/remediation capability;
- UI exposure tied to backend readiness.

## Feature switch ownership

Every switch has metadata:

- stable switch ID;
- description;
- owner;
- created date;
- owning roadmap phase/feature;
- default;
- allowed scopes;
- security classification;
- rollout plan;
- expiry/removal target;
- dependencies;
- audit requirements.

## Switch scopes

Possible scopes:

- SYSTEM global floor/kill switch;
- region/deployment;
- customer;
- role/internal cohort;
- percentage/hash cohort where safe.

Customer-scoped switches cannot override a SYSTEM security disable/floor.

## Security switches vs ordinary feature flags

Security controls are not ordinary convenience flags.

A switch that can weaken security must:

- default safe;
- require stronger permission;
- require reason;
- be audited;
- possibly require step-up/second approval according to governance;
- have a bounded lifetime/review;
- be visible in security operations/compliance evidence.

Do not create flags such as `disable_auth=true` or `ignore_tenant_scope=true` as normal product switches.

## Kill switches

High-risk integrations/capabilities need server-side kill switches where useful, including:

- Deep AI/model/tool execution;
- external threat-intelligence provider;
- problematic scanner/ruleset;
- mailbox remediation;
- new outbound behavior feature;
- third-party workflow export.

The kill switch should isolate the capability without unnecessarily stopping unrelated mail flow.

## UI behavior

The backend is authoritative.

The UI may use feature metadata to show/hide controls, but:

- hidden UI is not authorization;
- stale UI receiving a disabled-feature response must handle it safely;
- switches should not create broken navigation/empty dead screens;
- permission and feature availability are distinct checks.

## Persistence / migrations

Do not use a feature switch to pretend a database schema dependency does not exist.

For switched features:

1. deploy compatible schema/backend first;
2. deploy UI/consumers;
3. enable progressively;
4. observe;
5. complete rollout;
6. remove obsolete compatibility/flag code after stabilization.

## Flag storage and runtime

Initial preference:

- authoritative PostgreSQL configuration;
- compiled/versioned effective snapshot;
- Redis/Valkey runtime cache;
- outbox/SQS propagation;
- local last-known-good where Mail Plane depends on it.

Critical mail/security switches must work safely if Control Plane is unavailable.

## Feature addition process

Every material new feature follows this sequence:

1. identify roadmap phase/owner;
2. architecture impact review;
3. threat/data/compliance impact review;
4. define contract/API/event/schema changes;
5. define feature-switch/rollout need;
6. define migration/backward compatibility;
7. backend + UI + authz + audit + observability;
8. tests/security/OAST where applicable;
9. staged rollout;
10. evidence/exit criteria;
11. remove temporary switch/compatibility code when stable.

A feature is not complete if only backend code exists when administration/UI is required.

## Flag debt

Temporary rollout flags must not become permanent undocumented branches.

Track flag age and removal target.

CI/static checks may later detect expired flags.

Before deleting a flag:

- confirm rollout complete;
- choose permanent behavior;
- remove alternate branch;
- remove config/data;
- update tests/docs;
- audit/change record where security relevant.

## Testing

Test:

- default off/on;
- System floor vs tenant scope;
- region/deployment isolation;
- stale cache/local snapshot;
- frontend stale state;
- rolling old/new versions;
- switch propagation;
- kill-switch behavior;
- unauthorized flag mutation;
- expired/deprecated flags.

## AI-agent rules

AI agents must not:

- create feature flags to bypass incomplete security work;
- make flags client-authoritative;
- leave permanent hidden feature branches without documentation;
- introduce breaking API changes without compatibility/version plan;
- remove old schema fields before deployed consumers are compatible;
- expose experimental ML/LLM tools merely by enabling a UI flag.

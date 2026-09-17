# Package Compatibility and Version Matrix

**Status:** mandatory Phase 0 engineering control.

## Principle

Individual packages may be secure and supported yet incompatible with one another. Nullapart therefore treats dependency compatibility as a tested contract, not an assumption.

## Authoritative sources

The authoritative runtime versions are:

- lockfiles;
- container/IaC manifests;
- CI matrix;
- release metadata.

Architecture docs describe supported major-version families but do not replace lockfiles.

## Frontend compatibility matrix

Phase 0 maintains a tested compatibility matrix covering at least:

- Node.js LTS;
- pnpm;
- React;
- TypeScript;
- Vite;
- TanStack Router;
- TanStack Query;
- TanStack Table;
- React Hook Form;
- Zod;
- Radix primitives;
- browser observability SDK;
- Vitest;
- Testing Library;
- Playwright.

The matrix records:

| Component | Selected version | Supported peer range | Tested with | Notes |
|---|---|---|---|---|
| Node.js | Phase 0 lock | N/A | CI | LTS only |
| React | Phase 0 lock | package peer ranges | frontend suite | |
| TypeScript | Phase 0 lock | tooling ranges | typecheck/build | |
| Vite | Phase 0 lock | Node/plugin ranges | build/test | |

Populate real versions at initialization.

## Rust compatibility

Track:

- stable Rust toolchain version;
- minimum supported Rust version where relevant;
- crate feature combinations;
- native library/system dependencies;
- OpenSSL/rustls decisions;
- Postfix/scanner FFI/protocol compatibility.

CI must compile the workspace under the selected toolchain and intended feature sets.

## Native/service compatibility

Document/test compatibility among:

- Postfix;
- Rspamd;
- ClamAV;
- OS/base image;
- Mail Core handoff/reinjection contract;
- scanner protocol adapters;
- PostgreSQL major version;
- Redis/Valkey major/protocol behavior;
- OpenBao;
- ZITADEL;
- SegLumberjack/Sentry SDK protocol versions;
- n8n/workflow formats.

## AWS/IaC compatibility

Track compatibility among:

- Terraform/OpenTofu/CDK choice when selected;
- provider versions;
- module versions;
- AWS API/service features;
- ECS task/platform versions;
- base AMIs;
- GPU driver/runtime/CUDA stack where required.

## ML/LLM compatibility

For each model release record:

- model checkpoint/revision;
- tokenizer/processor revision;
- inference server version;
- CUDA/driver/runtime requirements;
- quantization format/runtime;
- OpenAI-compatible API behavior;
- multimodal dependencies;
- model input/output schema;
- skill/tool schema versions.

A model is not production-approved merely because it loads once.

## CI compatibility testing

CI should detect:

- peer dependency incompatibility;
- duplicate/conflicting frontend package families;
- Rust feature conflicts;
- migration/schema incompatibility;
- unsupported runtime combinations;
- API/event schema compatibility;
- frontend/backend generated type/schema drift where applicable.

## Upgrade process

For a package/runtime major upgrade:

1. open dedicated PR;
2. update compatibility matrix;
3. review release/security notes;
4. run full relevant CI/security/E2E suite;
5. benchmark where performance-sensitive;
6. update architecture/known limitations;
7. stage rollout;
8. preserve rollback path.

Avoid combining unrelated major upgrades in one PR unless required by peer-dependency constraints.

## Lockfile discipline

Lockfile changes must correspond to intentional manifest/dependency changes or documented resolver updates.

Unexpected large lockfile churn is a review signal.

## Dependency deduplication

Prefer one package/library for one responsibility unless different choices have a documented reason.

Examples:

- one schema-validation baseline;
- one primary date utility;
- one router;
- one server-state library;
- one component primitive family.

This reduces bundle/security/maintenance cost.

## AI-agent rules

AI coding agents must:

- inspect existing manifest + lockfile before suggesting a package;
- verify peer/runtime compatibility;
- avoid hallucinating package APIs/versions;
- avoid adding overlapping libraries;
- keep dependency upgrades scoped;
- update compatibility records for major/runtime changes;
- run/require build/type/security tests after dependency changes.
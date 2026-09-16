# Package Compatibility and Upgrade Matrix

**Status:** Phase 0 dependency-management contract.

## Purpose

Nullapart must not assemble a frontend/backend toolchain from individually current packages that are mutually incompatible.

Compatibility is established and tested as a **stack**, then exact resolved versions are pinned in lockfiles/artifact metadata.

## Frontend baseline

Architecture baseline:

- React 19 current major;
- TypeScript;
- Vite 8 supported line;
- TanStack Router;
- TanStack Query v5;
- TanStack Table;
- React Hook Form;
- Zod v4;
- Radix Primitives;
- Vitest;
- Testing Library;
- Playwright;
- pnpm;
- Node.js LTS build runtime.

The exact patch/minor versions are selected during Phase 0 initialization and pinned in `pnpm-lock.yaml`.

## Compatibility rules

### React / React DOM

`react` and `react-dom` must use matching compatible release versions.

Do not upgrade one independently.

### Vite / Node.js

The selected Vite release must support the pinned Node.js LTS build runtime.

CI validates the supported Node version explicitly rather than relying on the developer workstation.

### TypeScript

Choose a TypeScript release supported by the active frontend ecosystem.

TanStack Query's current guidance supports TypeScript releases from its supported window and recommends locking a specific package patch because type corrections can occur in patch releases.

### React libraries

For Router/Query/Table/Form/Radix/testing packages:

- verify React peer dependencies;
- verify TypeScript peer/minimum requirements;
- treat peer-dependency warnings as review items, not noise;
- do not use `--force`/legacy peer dependency bypass as the normal resolution strategy.

## Compatibility manifest

Phase 0 should maintain an implementation manifest such as:

| Component | Selected version | Required peers/runtime | Tested with | Owner | Last reviewed |
|---|---|---|---|---|---|
| Node.js | TBD | CI/build runtime | full frontend CI | TBD | TBD |
| pnpm | TBD | Node compatibility | install/build | TBD | TBD |
| React | TBD | ReactDOM same line | UI/E2E | TBD | TBD |
| React DOM | TBD | React same line | UI/E2E | TBD | TBD |
| Vite | TBD | supported Node | build/dev | TBD | TBD |
| TypeScript | TBD | ecosystem support | typecheck | TBD | TBD |
| TanStack Query | v5 exact TBD | React 18+ / supported TS | UI/integration | TBD | TBD |
| Zod | v4 exact TBD | TS/tooling | form/API schema tests | TBD | TBD |

The lockfile remains the authoritative exact dependency resolution.

## Rust compatibility

Rust dependencies follow the workspace/Cargo lockfile.

Maintain:

- pinned Rust toolchain/MSRV policy where needed;
- `Cargo.lock` for deployable workspace;
- feature flag review;
- native/OpenSSL/system-library compatibility where applicable;
- Postfix/Rspamd/ClamAV integration compatibility tests.

Avoid duplicate incompatible crate versions when they materially increase risk/binary size or create conflicting protocol behavior.

## Python / ML compatibility

ML training/inference environments must use a separately reproducible dependency definition.

Pin and test as a set:

- Python runtime;
- PyTorch/ONNX Runtime;
- CUDA/driver compatibility where GPU training/serving is used;
- transformers/tokenizers;
- vLLM or selected model server;
- model revision/weights;
- image/document libraries.

Do not assume a package that imports successfully on the development GTX 1050 Ti environment is production-compatible with AWS GPU drivers/runtime.

Production inference compatibility is benchmarked per regional target environment.

## OS / container compatibility

The compatibility matrix includes:

- base distribution/image;
- libc/system libraries;
- ClamAV/Postfix/Rspamd packages;
- native document/image parsers;
- OpenSSL/TLS library;
- CPU architecture.

Container builds fail if required native dependencies cannot be reproduced from pinned inputs.

## Dependency grouping

Automated update tooling should group related ecosystem upgrades where appropriate.

Examples:

- React + ReactDOM;
- Vite + official plugins;
- TanStack related packages;
- testing stack;
- AWS SDK family;
- observability SDK packages.

Do not create giant unrelated upgrade PRs.

## Major upgrade process

For a major ecosystem upgrade:

1. read official migration notes;
2. update compatibility manifest;
3. create dedicated branch/PR;
4. run typecheck/build/unit/integration/UI/E2E/security tests;
5. inspect bundle/runtime changes;
6. review security changes/deprecations;
7. update architecture only if capability/assumptions changed.

## CI compatibility gates

CI should validate:

- exact lockfile install (`--frozen-lockfile` equivalent);
- package-manager version;
- Node/toolchain version;
- peer-dependency correctness;
- TypeScript typecheck;
- frontend build;
- test suite;
- duplicate/problem dependency reporting where useful;
- Rust locked build/test;
- container/native dependency build.

## Unsupported combinations

Do not work around incompatibility by:

- disabling type checking;
- forcing peer dependencies;
- vendoring unreviewed forks;
- pinning an unmaintained vulnerable package indefinitely;
- downgrading security libraries merely to satisfy a UI package.

Escalate the incompatibility and select a maintained compatible alternative.

## Current architecture review notes

At the September 2026 architecture review:

- React 19.3 is the current React release line;
- Vite 8.3 is the current regular-patch supported Vite line;
- TanStack Query v5 is compatible with React 18+ and current documentation recommends locking exact package patches for predictable TypeScript behavior.

These observations guide Phase 0 selection but the repository lockfiles become the exact implementation truth.

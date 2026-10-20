# Package Compatibility and Upgrade Matrix

**Status:** Phase 0 dependency-management contract.

## Purpose

Nullapart must not assemble a frontend/backend toolchain from individually current packages that are mutually incompatible.

Compatibility is established and tested as a **stack**, then exact resolved versions are pinned in lockfiles/artifact metadata.

## Frontend baseline

Architecture baseline:

- React 19 current major;
- TypeScript;
- Vite 6 supported line;
- TanStack Router;
- TanStack Query v5;
- TanStack Table;
- React Hook Form;
- Zod v3;
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
| Node.js | >=24.0.0 | CI/build runtime | full frontend CI | TBD | TBD |
| pnpm | 11.5.0+ | Node compatibility | install/build | TBD | TBD |
| Rust toolchain | 1.96.0 (`rust-toolchain.toml`) | rustfmt + Clippy; Cargo workspace lockfile | workspace format, lint, test, release and security CI | TBD | 2026-10-20 |
| React | ^19.0.0 | ReactDOM same line | UI/E2E | TBD | TBD |
| React DOM | ^19.0.0 | React same line | UI/E2E | TBD | TBD |
| Vite | ^6.0.5 | supported Node | build/dev | TBD | TBD |
| Vitest / V8 coverage | ^5.0.3 | Node ^22.12.0 or ^24.0.0; Vite ^6.4.0+ | frontend check-all | TBD | 2026-10-20 |
| DOMPurify | ^3.4.17 | browser sanitizer types are bundled | frontend check-all | TBD | 2026-10-20 |
| TypeScript | ~5.6.2 | ecosystem support | typecheck | TBD | TBD |
| TanStack Query | ^5.62.8 | React 18+ / supported TS | UI/integration | TBD | TBD |
| Zod | ^3.24.1 | TS/tooling | form/API schema tests | TBD | TBD |
| openidconnect (Rust OIDC relying party) | 4.0.1 (`Cargo.lock`) | reqwest + rustls, default features off | mail-core OIDC unit tests, ignored PostgreSQL suite, local ZITADEL v4.19.2 login | TBD | 2026-09-29 |
| ort / ort-sys (Rust ONNX runtime) | 2.0.0-rc.13 (`Cargo.lock`, features `download-binaries`, `ndarray`) | downloads a pinned onnxruntime prebuilt; needs glibc ≥ 2.38 and a GCC-14 libstdc++ in the container image (Debian trixie) | mail-core inline ML unit/profile tests, tokenizer parity tests, live local compose smoke | TBD | 2026-10-02 |
| tokenizers | 0.23.2 (`Cargo.lock`) | esaxx-rs builds C++; the builder stage needs `g++` | Rust tokenizer parity + compose-contract tests | TBD | 2026-10-02 |

The lockfile remains the authoritative exact dependency resolution.

## Rust compatibility

Rust dependencies follow the workspace/Cargo lockfile. The repository pins Rust
1.96.0 in `rust-toolchain.toml`, and every Rust CI job requests that same
toolchain explicitly. This prevents a hosted-runner stable-channel update from
silently changing the lint contract; upgrades remain deliberate compatibility
changes with a full workspace/CI rerun.

Maintain:

- pinned Rust toolchain/MSRV policy where needed;
- `Cargo.lock` for deployable workspace;
- feature flag review;
- native/OpenSSL/system-library compatibility where applicable;
- Postfix/Rspamd/ClamAV integration compatibility tests.

Identity integration is deliberately a single reviewed crate: `openidconnect`
is pinned in `Cargo.lock` with `default-features = false` and only
`reqwest`/`rustls-tls`, so the relying party adds no second TLS stack and no
async-runtime duplication. It parses untrusted assertion input (ID tokens and
UserInfo responses) and is therefore covered by the upstream advisory and
zero-day tracking in `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`;
upgrade it through this compatibility process, never by an ad-hoc version bump
that changes TLS backends, HTTP clients or feature sets at the same time.

The inline ML native toolchain is one compatibility unit: `Dockerfile.mailcore`
builder and runtime stages run on Debian trixie (glibc 2.41, libstdc++ 14) with
`g++` installed, because the onnxruntime prebuilt shipped by `ort` 2.0.0-rc.13
references `__isoc23_*` glibc symbols (glibc ≥ 2.38) and GCC-14 libstdc++
symbols that bookworm (glibc 2.36, libstdc++ 12) can neither link nor run, and
`tokenizers` → `esaxx-rs` needs a C++ compiler. Upgrade the Debian release and
the `ort`/`tokenizers` pair together through this process with a container
build plus an inline ML profile/live smoke re-run — never by an ad-hoc version
bump.

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

- React 19 is the current React release line;
- Vite 6 is the current supported Vite line;
- TanStack Query v5 is compatible with React 18+ and current documentation recommends locking exact package patches for predictable TypeScript behavior.

**Known discrepancy (Phase 0):** This document previously referenced Vite 8 and Zod v4. The actual `frontend/package.json` uses Vite `^6.0.5` and Zod `^3.24.1`. This section has been corrected to match the implementation. If a future upgrade to Vite 8 or Zod v4 is planned, update both `package.json` and this document together.

These observations guide Phase 0 selection but the repository lockfiles become the exact implementation truth.

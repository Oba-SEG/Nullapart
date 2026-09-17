# Package, Runtime and Interoperability Compatibility

**Status:** mandatory Phase 0 engineering contract.

## Principle

Nullapart pins reproducible dependency versions, but it also needs a reviewed **compatibility set** so individually valid package upgrades do not break the system when combined.

The lockfile tells us exactly what was built. The compatibility matrix tells us which combinations are supported.

## Compatibility domains

Track compatibility across:

- Rust toolchain and workspace crates;
- Node.js / pnpm / Vite / React / TypeScript;
- frontend router/query/table/form/schema/testing packages;
- Postfix / Rspamd / ClamAV;
- PostgreSQL;
- Redis/Valkey;
- OpenBao;
- ZITADEL;
- n8n;
- scanner/parser native libraries;
- ONNX/runtime libraries;
- Python where ML training/serving uses it;
- vLLM/model runtime;
- CUDA/driver/accelerator stack where applicable;
- AWS provider/IaC tooling;
- GitHub Actions and build images.

## Authoritative version sources

Use the ecosystem-native lock/version mechanisms:

- Rust: `rust-toolchain.toml` plus `Cargo.lock`;
- frontend: `package.json`, pinned package-manager metadata, `pnpm-lock.yaml`;
- Python/ML: reviewed lockfile/constraints mechanism selected by the ML tooling;
- containers: Dockerfile/image references plus immutable production digest;
- IaC: tool/provider constraints and lockfiles;
- models: model revision/checksum + serving-runtime compatibility record.

Architecture documentation records supported major/minor compatibility, not every transitive patch version.

## Initial frontend compatibility family

Phase 0 initializes a tested set based on the approved frontend architecture:

- supported Node.js LTS line;
- pnpm version;
- React major;
- TypeScript version;
- Vite major;
- TanStack Router version family;
- TanStack Query version family;
- TanStack Table version family;
- React Hook Form;
- Zod;
- Radix primitives;
- Vitest;
- Playwright.

Exact versions are chosen together and committed to the lockfile.

Do not upgrade one central framework blindly without running the compatibility suite.

## Compatibility matrix template

Maintain an implementation-time table similar to:

| Compatibility set | Runtime | Core packages/services | Status | Evidence |
|---|---|---|---|---|
| frontend-set-001 | Node LTS + pnpm | React/Vite/TS/TanStack/Zod/RHF/Radix/Vitest/Playwright | TESTED | CI run / lockfile |
| mail-set-001 | OS/container | Postfix/Rspamd/ClamAV/Mail Core | TESTED | mail-flow integration suite |
| data-set-001 | managed/runtime | PostgreSQL/Redis/SQS adapters | TESTED | integration suite |
| ai-set-001 | GPU runtime | model/vLLM/CUDA-driver/quantization | REGION TESTED | benchmark/eval |

## Peer and engine constraints

CI must fail early on:

- unsupported Node engine;
- incompatible peer dependencies;
- duplicate incompatible framework copies where they create runtime risk;
- unsupported Rust toolchain/MSRV changes;
- mismatched native ABI/library requirements;
- incompatible model/runtime/CUDA combinations.

## Update process

Dependency update PRs should identify whether they change:

- patch only;
- minor feature behavior;
- major API behavior;
- runtime/ABI;
- license;
- security posture;
- transitive dependency graph.

Central framework/runtime upgrades must run the full relevant compatibility suite, not only unit tests for the changed package.

## Native library compatibility

Scanner/native packages require extra care because incompatible native libraries can fail only at runtime.

Record:

- OS/base-image compatibility;
- shared-library versions;
- architecture (`x86_64`/ARM where relevant);
- CPU instruction requirements;
- parser/engine version;
- runtime security restrictions.

## ML/LLM compatibility

Model compatibility is not only a Python package question.

Track:

- model revision;
- tokenizer/processor revision;
- serving runtime;
- quantization format;
- accelerator type;
- driver/runtime version;
- input/output schema;
- context configuration;
- tool/prompt schema version.

A model/runtime upgrade requires security/quality evaluation as well as a successful process start.

## Cross-version rolling deployments

Where two application versions may run during deployment, explicitly define compatibility for:

- database schema;
- event schema;
- policy snapshot schema;
- scanner protocol;
- cache entries;
- frontend/backend API.

Prefer additive/compatible transitions before removing old fields/behavior.

## Unsupported combinations

Unsupported combinations must fail fast or be blocked by CI/configuration.

Do not silently run an untested combination because each component starts successfully.

## Evidence

For each approved set retain:

- lockfiles;
- build/test run;
- security scans;
- integration tests;
- benchmark/evaluation where relevant;
- release/source SHA;
- artifact digest.

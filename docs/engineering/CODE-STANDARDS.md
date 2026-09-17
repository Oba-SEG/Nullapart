# Nullapart Code Standards and Formatting

**Status:** mandatory engineering baseline for humans and AI coding agents.

## Purpose

Nullapart code must be predictable, reviewable, secure and mechanically consistent.

Formatting is automated. Reviewers should spend time on correctness, security, architecture, failure semantics and maintainability rather than whitespace/style debates.

This document defines repository-wide standards. Language-native formatter/linter configuration committed to the repository is authoritative for exact formatting details.

## Global rules

All source/config/document text uses:

- UTF-8;
- LF line endings;
- final newline;
- no trailing whitespace;
- spaces rather than tabs except formats such as Makefiles that require tabs;
- deterministic formatter output;
- no secrets/credentials in source, comments, examples, fixtures or snapshots.

Do not manually fight the formatter.

If formatter output is undesirable, change the shared formatter configuration deliberately rather than hand-formatting one file differently.

## Repository canonical configuration

Phase 0 must establish/maintain language tooling such as:

- `.editorconfig`;
- `.gitattributes`;
- Rust `rustfmt` / Clippy configuration;
- frontend ESLint configuration;
- Prettier configuration;
- Stylelint configuration where CSS lint rules require it;
- Python Ruff/type-check configuration if Python is introduced;
- ShellCheck/shfmt configuration;
- SQL lint/format configuration where practical;
- IaC-native formatting/validation configuration.

Exact tool versions are pinned through the normal package/toolchain compatibility process.

## Naming

Use language-native naming conventions.

### Rust

- modules/functions/variables: `snake_case`;
- types/traits/enums: `UpperCamelCase`;
- constants/statics: `SCREAMING_SNAKE_CASE`;
- acronyms follow normal Rust style rather than all-caps type names.

### TypeScript / React

- variables/functions: `camelCase`;
- React components/types/interfaces: `PascalCase`;
- constants only use `SCREAMING_SNAKE_CASE` when they are genuinely constant configuration values;
- hooks start with `use`;
- files follow one consistent feature-oriented convention established by the frontend scaffold.

### SQL

- schemas/tables/columns/indexes/policies: `snake_case`;
- names should describe business meaning, not implementation accidents.

### Stable product identifiers

Use explicit domain types/names such as:

- `customer_id`;
- `transaction_id`;
- `tenant_message_id`;
- `delivery_id`;
- `audit_event_id`;
- `trace_id`.

Do not collapse distinct identifiers into a generic `id` when that makes security/ownership logic ambiguous.

## General code design

Prefer:

- small cohesive modules;
- explicit types;
- narrow interfaces;
- immutable data where practical;
- composition over hidden global state;
- dependency injection/interfaces at real external boundaries;
- explicit error/failure paths;
- typed enums instead of magic strings;
- named configuration structures instead of loose maps;
- shared project abstractions instead of duplicate helpers.

Avoid:

- giant utility modules;
- catch-all `helpers` containing unrelated behavior;
- generic JSON/dictionary structures where a stable typed contract exists;
- boolean parameters whose meaning is unclear at call sites;
- hidden global mutable state;
- clever/condensed code that is harder to audit than an explicit implementation;
- dead/commented-out code.

## Security-sensitive code

Security-sensitive logic should be easy to read and difficult to misuse.

Examples:

- authorization;
- ownership checks;
- RLS context;
- cryptography/HMAC;
- session handling;
- policy floors;
- mail acceptance/reinjection;
- scanner isolation;
- artifact access;
- audit;
- tenant routing.

For these paths:

- prefer explicit steps over dense abstractions;
- document security invariants;
- make unsafe/default-bypass behavior impossible or visibly exceptional;
- include negative tests;
- avoid implicit fallback that weakens security.

## Rust standards

### Formatting

Canonical formatter:

```text
cargo fmt
```

CI:

```text
cargo fmt --all -- --check
```

### Linting

Use Clippy for all workspace targets/features supported by the project.

With the repository-pinned Rust toolchain, CI should treat project-selected Clippy warnings as errors.

Do not add blanket `#[allow(...)]` attributes to silence warnings without a specific reason.

### Error handling

Runtime request/mail paths return typed `Result`/error types.

Do not use `unwrap()`/`expect()` on untrusted/runtime data paths.

Acceptable uses are limited to cases such as:

- tests;
- compile/startup invariants where failure must terminate and the invariant is clear;
- mathematically/impossible states with reviewer-approved justification.

Even then, include a useful message when `expect()` is used.

A malformed email, API request, scanner response or provider response must not panic the whole process.

### `unsafe`

`unsafe` Rust is prohibited by default.

If unavoidable:

- isolate it in the smallest module/function;
- document a `SAFETY:` invariant;
- add focused tests/fuzzing where appropriate;
- require heightened review;
- prefer a maintained safe abstraction first.

### Async

Do not block async executors with uncontrolled blocking I/O/CPU work.

Use explicit blocking pools/process isolation for:

- heavy parsers;
- compression;
- document conversion;
- native scanner work;
- CPU-heavy transformations.

Async operations should have cancellation/timeout semantics where external/untrusted work can hang.

### Types

Prefer newtypes/enums for security-relevant concepts rather than passing raw strings everywhere.

Examples:

- customer identity;
- region/deployment;
- policy revision;
- scanner status;
- disposition;
- permission/action;
- feature switch ID.

## TypeScript / React standards

### Formatting

Prettier is the canonical formatter for supported frontend/text formats.

Developers/agents should run formatting before submitting changes; CI checks that the committed output is already formatted.

### Linting

ESLint is the semantic JavaScript/TypeScript/React linter baseline.

TypeScript runs in strict mode.

### Types

Avoid `any`.

Prefer:

- `unknown` + validated narrowing;
- generated/shared typed API contracts where appropriate;
- discriminated unions;
- exhaustive handling of security/business states.

`@ts-ignore`, `@ts-nocheck` and unsafe type assertions require a documented justification and should be exceptional.

Do not use a non-null assertion merely to silence the compiler when the runtime value can actually be absent.

### React

Use function components/hooks.

Rules:

- hooks follow standard hook rules;
- server state uses the TanStack Query boundary rather than ad hoc `useEffect` fetching;
- API calls go through the central API client;
- permissions/feature switches returned to the UI improve UX but do not become authorization;
- avoid component-local copies of canonical server business state without a reason;
- use stable keys from real resource identifiers, not array indexes for mutable lists.

### Hostile content

`dangerouslySetInnerHTML` is forbidden in normal application components.

The only permitted HTML-email rendering path is the dedicated reviewed hostile-content renderer/isolation architecture.

### Frontend errors

Components consume the standard safe error model rather than parsing arbitrary backend/error JSON.

Loading, empty, denied, disabled-feature and error states are intentionally designed.

## CSS / design-system standards

Use the established design tokens/custom properties and CSS Modules/design-system components.

Avoid:

- repeated magic color/spacing/elevation values;
- unscoped global CSS;
- `!important` as a routine conflict-resolution mechanism;
- accessibility-breaking neumorphic effects;
- inline styles for static styling that belongs in the design system.

Inline styles are acceptable for genuinely calculated runtime values where a CSS variable/class is not the clearer solution.

## SQL and migration standards

SQL/migrations are production code.

Rules:

- PostgreSQL syntax is explicit and reviewable;
- parameterize application queries;
- never concatenate untrusted SQL;
- include tenant/RLS/ownership implications in schema review;
- use descriptive constraints/index names;
- add database constraints for invariants that belong in the database;
- migrations are monotonic and immutable after production application;
- destructive changes use staged expand/migrate/contract patterns where practical;
- indexes are added intentionally based on query/access patterns;
- RLS policies are readable and tested.

Avoid enormous migrations mixing unrelated schema changes.

## Python / ML standards

If Python is used for training/evaluation/model tooling:

- Ruff is the default formatter/linter baseline;
- type annotations are expected on public/project interfaces;
- use a project-selected static type checker for production Python interfaces;
- dependency environment is reproducible/locked;
- notebooks are not production pipelines;
- move reusable/production logic out of notebooks into tested modules;
- model/data/version metadata is explicit.

No Python service is introduced merely because a prototype notebook already exists.

## Shell standards

Shell scripts must:

- be small;
- use ShellCheck;
- use shfmt;
- quote variables;
- avoid parsing structured data with brittle grep/sed chains when a safer structured tool exists;
- use strict/error handling appropriate to the script (`set -euo pipefail` where semantics are correct);
- never echo secrets.

For complex logic, prefer Rust/Python/project tooling over an increasingly large shell script.

## YAML / JSON / TOML

Machine configuration should be deterministic and formatter-compatible.

Rules:

- no duplicate keys;
- no secrets;
- avoid clever YAML anchors/implicit typing when they reduce reviewability;
- quote values where YAML coercion could be ambiguous;
- stable ordering where tooling supports it;
- use schemas/validation where available.

## Infrastructure as Code

Use the selected IaC tool's native formatter and validator.

CI must fail if formatting/validation differs.

Infrastructure code follows the same standards as application code:

- small modules;
- explicit inputs/outputs;
- least privilege;
- no embedded secrets;
- meaningful names/tags;
- no broad wildcard IAM/network rules without documented justification.

## Dockerfiles / containers

Dockerfiles should:

- be deterministic;
- minimize layers/runtime packages where practical;
- use multi-stage builds where useful;
- run non-root where practical;
- pin/reproduce base dependencies;
- avoid copying secrets/build credentials into layers;
- clean package-manager metadata where appropriate.

Use Hadolint or equivalent Dockerfile linting where adopted by Phase 0.

## Comments and documentation

Comments explain **why**, invariants and non-obvious security/protocol behavior.

Do not narrate obvious syntax.

Security-sensitive comments should document assumptions such as:

- why an authorization check belongs here;
- why a specific SMTP state cannot be retried;
- why a tenant scope is safe;
- why an `unsafe` block is sound;
- why a crypto canonicalization is exact.

Public/shared interfaces should have useful API/doc comments.

### TODO/FIXME

Do not leave anonymous long-term TODOs in security-critical paths.

Use a trackable reference when work is intentionally deferred, for example:

```text
TODO(NULLAPART-123): remove compatibility path after v1 migration.
```

Temporary security exceptions reference the exception ID/expiry rather than a vague TODO.

## Logging and observability code

Use structured fields, not concatenated unstructured strings when the logging/telemetry API supports fields.

Never log:

- passwords;
- auth/session tokens;
- private keys;
- Restricted message bodies/raw MIME/attachments;
- full sensitive prompts.

Prefer stable event/reason codes for machine analysis.

## Tests

Test code follows normal code-quality standards.

Tests should be:

- deterministic;
- isolated;
- readable;
- explicit about tenant/principal context;
- independent of test execution order.

Avoid arbitrary sleeps for synchronization. Use observable conditions, clocks/fakes or bounded polling when required.

A test that depends on external Internet/provider availability must be explicitly classified as integration/external and not masquerade as a deterministic unit test.

Do not use production customer content as routine fixtures.

## Generated code

Generated code/artifacts must be:

- clearly identified;
- deterministically reproducible;
- produced from a versioned generator/schema;
- not manually edited.

CI may verify regeneration produces no unexpected diff.

## Formatting/lint gate matrix

Phase 0 should implement equivalent checks to:

| Area | Format | Lint / static checks |
|---|---|---|
| Rust | `cargo fmt --check` | Clippy + compiler |
| TypeScript/React | Prettier | ESLint + `tsc --noEmit` |
| CSS | Prettier | Stylelint where configured |
| Python/ML | Ruff format | Ruff + project type checker |
| Shell | shfmt | ShellCheck |
| Dockerfile | formatter if selected | Hadolint/equivalent |
| Markdown/YAML/JSON | Prettier/approved formatter | schema/link/markdown checks |
| SQL | approved deterministic formatter | SQL/schema/migration checks |
| IaC | native formatter | validate + security scan |

CI is the final authority: a PR with formatting/lint failures does not merge.

## Local developer workflow

Phase 0 should provide one obvious command or task runner entry point for common validation, conceptually:

```text
format
format-check
lint
typecheck
test
security-check
check-all
```

Do not require developers/agents to memorize ten unrelated commands when the repository can provide a stable wrapper.

The wrapper must invoke the real language-native tools rather than hiding failures.

## Review standards

Reviewers should focus on:

1. correctness;
2. security/tenant isolation;
3. business/protocol invariants;
4. failure/recovery behavior;
5. architecture fit;
6. test quality;
7. maintainability;
8. performance/resource impact.

Formatting disputes belong in formatter configuration, not PR comment threads.

## AI coding-agent rules

AI agents must:

- run/apply the canonical formatter rather than imitating style manually;
- follow lint/type rules rather than suppressing them;
- avoid broad lint-disable directives;
- avoid unrelated formatting churn;
- keep changes narrowly scoped;
- preserve generated-file conventions;
- not replace clear code with compressed/clever code to save tokens;
- update formatting/lint tooling intentionally when adding a new language/file type.

Token optimization does not justify lower code readability.

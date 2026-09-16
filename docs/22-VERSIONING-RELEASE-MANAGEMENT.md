# Versioning and Release Management

## Product version

Nullapart uses Semantic Versioning.

Before stable release:

`0.MINOR.PATCH`

After first stable release:

`MAJOR.MINOR.PATCH`

## What changes a version

### PATCH

Compatible fixes such as:

- bug fixes;
- security fixes without incompatible contract changes;
- internal optimizations;
- compatible UI corrections.

### MINOR

Backward-compatible product capability additions such as:

- new scanner capability;
- new policy family;
- new administration feature;
- new dashboard;
- compatible contract extension.

### MAJOR

Incompatible product/runtime contract change requiring coordinated migration.

Before 1.0, incompatible changes may occur between MINOR versions but must still be documented and migration-safe.

## Independent revisions

Do not use the product version for all mutable state.

Track separately:

- policy/config revision;
- database schema migration level;
- infrastructure revision;
- scanner ruleset/signature version;
- Rspamd configuration revision;
- ML model version;
- Deep AI model/serving revision;
- UI/backend release version.

## Compatibility matrix

Production release documentation should state compatibility across:

- Postfix configuration;
- Rspamd configuration;
- Mail Core;
- scanner contract;
- Control Backend;
- frontend;
- database schema;
- policy snapshot schema;
- event schema;
- model input schema.

## Release identity

Every runtime exposes internally:

- semantic release version;
- Git SHA;
- build ID;
- deployment time;
- config revision;
- region/deployment;
- node identity.

Customer-facing UI need not expose low-level build metadata unless useful, but System operations must be able to identify exactly what is running.

## Pre-release versions

Allowed for test/staging where useful:

- `0.3.0-alpha.1`;
- `0.3.0-beta.1`;
- `0.3.0-rc.1`.

Production should normally use final immutable releases unless an explicitly controlled pilot deployment is approved.

## Hotfixes

A production hotfix:

- branches from the relevant current release/main state according to project policy;
- receives required security/review checks;
- increments PATCH;
- generates new immutable artifacts;
- follows controlled production approval.

Do not mutate an existing release tag/image to "replace" its contents.

## Database versioning

Migrations are monotonic and immutable after production application.

Application startup must not perform uncontrolled destructive schema migration.

Migration execution is a controlled deployment step.

## API/event/schema versioning

Internal contracts are versioned where consumers can be deployed independently.

Avoid premature version prefixes everywhere, but do not make breaking changes silently.

Public customer API is not currently offered.

## Model versioning

A model release is independent from product version unless bundled deliberately.

Trace/security findings record the model/ruleset version needed for reproducibility.

## Release notes

Release notes should include:

- changes;
- security-relevant changes;
- migration requirements;
- configuration changes;
- known limitations;
- rollback considerations.

Sensitive vulnerability detail may be withheld until safe disclosure.

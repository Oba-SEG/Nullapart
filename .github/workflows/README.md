# GitHub Actions Workflow Directory

Production workflow files are introduced during Phase 0 according to:

- `docs/security/19-VERSION-CONTROL-CICD.md`
- `docs/22-VERSIONING-RELEASE-MANAGEMENT.md`
- `docs/26-PACKAGE-COMPATIBILITY.md`
- `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md`
- `docs/engineering/CODE-STANDARDS.md`
- `docs/phases/PHASE-0-CONTRACTS-FOUNDATIONS.md`

## Planned workflow classes

### `pr.yml`

Expected responsibilities:

- changed-path classification;
- canonical format checks;
- lint/static analysis;
- TypeScript/Python type checks where applicable;
- Rust/frontend compile/build;
- unit/integration/security/UI tests as applicable;
- API compatibility tests;
- frozen/locked dependency installation;
- secret scanning;
- SAST/SCA;
- license checks;
- migration validation;
- IaC/container scanning when applicable;
- SBOM generation/checks;
- documentation/link consistency checks.

Code-format/lint/type failures are merge-blocking. They are fixed in source/configuration, not bypassed in CI.

Expected tool classes include, as applicable:

- Rust: `cargo fmt --check`, Clippy, compiler;
- TypeScript/React: Prettier, ESLint, `tsc --noEmit`;
- CSS: Prettier + Stylelint where configured;
- Python/ML: Ruff + project type checker;
- shell: shfmt + ShellCheck;
- Dockerfile: Hadolint/equivalent;
- IaC: native formatter/validator + security scan;
- Markdown/YAML/JSON/SQL: deterministic formatter/lint/schema checks selected by Phase 0.

PR workflows must not receive production deployment credentials.

### `main.yml`

Expected responsibilities:

- repeat required validation;
- build immutable artifacts once;
- attach Git SHA/version/build metadata;
- generate SBOM/provenance;
- sign/attest where selected;
- publish to approved registry/storage.

### `release.yml`

Expected responsibilities:

- validate semantic version/tag;
- bind release to approved `main` source SHA;
- identify immutable artifacts built from that SHA;
- generate release notes/evidence;
- never rebuild a different artifact under the same release identity.

### reusable `deploy.yml`

Expected inputs:

- explicit environment;
- explicit region/deployment;
- immutable artifact digest/version;
- migration mode where applicable.

Expected responsibilities:

- request OIDC only in deployment job;
- assume scoped AWS role;
- verify artifact/provenance;
- promote existing immutable digest;
- production approval through GitHub Environment controls;
- migration orchestration;
- post-deploy verification;
- deployment evidence;
- rollback/containment support.

### `scheduled-security.yml`

Expected responsibilities:

- vulnerability/dependency maintenance checks;
- EOL/runtime checks;
- base-image refresh status;
- scheduled security/control drift jobs as tooling matures.

## Workflow security

Workflow files are security-critical code and require heightened review.

Baseline:

- explicit minimal `permissions`;
- `contents: read` default where possible;
- `id-token: write` only in AWS OIDC jobs;
- third-party Actions pinned to reviewed full commit SHAs where practical;
- locked/frozen dependency installs;
- no privileged secrets for untrusted PRs;
- no casual `pull_request_target` execution of untrusted code;
- managed/ephemeral runners initially where possible;
- no mutable `latest` production deploy identity;
- CI caches are not trusted release artifacts.

Do not:

- use long-lived AWS access keys for normal deployments;
- run untrusted PR code with production secrets;
- grant broad default workflow permissions;
- disable required formatting/lint/type/security checks to force a release through;
- let automation self-approve sensitive production changes.

See:

- `docs/28-GITHUB-ACTIONS-ARCHITECTURE.md` for the complete workflow contract;
- `docs/engineering/CODE-STANDARDS.md` for canonical language/style/lint rules.

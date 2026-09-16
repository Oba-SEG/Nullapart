# GitHub Actions Workflow Directory

Production workflow files will be introduced during Phase 0 according to:

- `docs/security/19-VERSION-CONTROL-CICD.md`
- `docs/22-VERSIONING-RELEASE-MANAGEMENT.md`
- `docs/phases/PHASE-0-CONTRACTS-FOUNDATIONS.md`

## Planned workflow classes

### Pull request validation

Expected responsibilities:

- format/lint;
- compile/build;
- unit/integration/security/UI tests as applicable;
- secret scanning;
- SAST/SCA;
- license checks;
- migration validation;
- IaC/container scanning when applicable;
- SBOM generation/checks.

PR workflows must not receive production deployment credentials.

### Main build

Expected responsibilities:

- repeat required validation;
- build immutable artifacts once;
- attach Git SHA/version/build metadata;
- generate SBOM/provenance;
- sign/attest where selected;
- publish to approved registry.

### Deployment/promotion

Expected responsibilities:

- promote existing immutable digests;
- explicit target environment/region;
- GitHub OIDC to scoped AWS role;
- production approval;
- migration orchestration;
- deployment evidence;
- rollback/containment support.

## Security

Workflow files are security-critical code.

Changes require heightened review.

Do not:

- use long-lived AWS access keys for normal deployments;
- run untrusted PR code with production secrets;
- grant broad default workflow permissions;
- use mutable `latest` as production deployment identity;
- disable required security checks to force a release through.

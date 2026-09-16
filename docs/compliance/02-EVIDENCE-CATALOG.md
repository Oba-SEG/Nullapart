# Compliance Evidence Catalog

## Purpose

Define where proof of control operation comes from.

## Evidence classes

### Identity/access

- MFA policy/configuration;
- privileged-role listing;
- access reviews;
- break-glass use;
- session/revocation configuration.

### SDLC/CI/CD

- PR/review history;
- required CI checks;
- SBOM;
- SAST/SCA results;
- image/IaC scans;
- artifact provenance/signatures;
- release/deployment records.

### Vulnerability/patching

- vulnerability findings;
- remediation tickets/commits;
- dependency update PRs;
- host/container patch evidence;
- scanner/ruleset versions.

### Audit/security operations

- Admin Audit entries;
- immutable audit checkpoints;
- exception approvals;
- incident exercises/postmortems;
- runbook exercises.

### Data/privacy

- data-classification matrix;
- storage/IAM design;
- retention lifecycle configuration;
- deletion evidence;
- third-party register;
- regional deployment evidence.

### Resilience

- backups;
- restore-test reports;
- RPO/RTO measurements;
- failover exercises;
- SMTP commissioning evidence.

## Evidence metadata

Record:

- evidence ID;
- control IDs;
- source system;
- region/deployment;
- owner;
- collection date;
- coverage period;
- retention;
- sensitivity;
- integrity/provenance;
- reviewer.

## Automation

Evidence collection should be automated where practical, but automation must not create broad read access to Restricted customer content.

Prefer metadata/configuration/control-status evidence over copying message data into compliance repositories.

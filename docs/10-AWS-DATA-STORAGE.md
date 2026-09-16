# AWS Data and Storage Architecture

## Hosting model

All production Nullapart deployments run in AWS and remain region/deployment scoped.

The architecture uses open-source software where suitable and AWS managed capabilities where they materially improve security, durability or operations.

## PostgreSQL

PostgreSQL is the authoritative relational data platform.

Production may use AWS-managed PostgreSQL (for example RDS PostgreSQL) while preserving PostgreSQL compatibility and clean domain ownership.

Stores include:

- customers;
- domains;
- roles/permissions;
- policy definitions/revisions;
- message/security metadata;
- quarantine metadata;
- DMARC/BIMI metadata;
- configuration;
- audit metadata;
- model release metadata;
- connector metadata.

Mail content itself should not be stored as large database blobs by default.

## Redis

Redis supports:

- policy/config caches;
- greylisting;
- rate/behaviour counters;
- runtime acceleration;
- durable streams/event consumers;
- cache-revision state.

Redis is not the source of truth for policy/customer configuration.

## ArtifactStore abstraction

Rust/application code uses an `ArtifactStore` contract rather than embedding S3 calls throughout business logic.

Supported environments:

### Development

- local filesystem;
- optional MinIO/S3-compatible development service.

### Production

- Amazon S3.

## S3 usage

Regional/deployment-specific buckets or strongly partitioned bucket strategy store:

- raw MIME when retention requires it;
- quarantine artifacts;
- attachment artifacts;
- extracted analysis artifacts;
- ML datasets/model artifacts where appropriate;
- DMARC ingestion artifacts where needed.

Recommended controls:

- SSE-KMS;
- strict IAM;
- VPC endpoints/private access;
- Block Public Access;
- versioning where useful;
- lifecycle/retention policies;
- CloudTrail/audit where needed;
- no default cross-region replication.

## Artifact references

Services exchange artifact references rather than base64 email/attachment blobs.

A reference includes enough information to authorize and locate the artifact without exposing unrestricted bucket access.

## Temporary scanner storage

Scanner nodes use tightly bounded temporary workspace.

Requirements:

- size quotas;
- time limits;
- cleanup after scan;
- no accidental persistence in container layers;
- encrypted volumes where required;
- archive/decompression protections.

## Quarantine

Quarantine includes:

- immutable message identity;
- raw MIME/artifact reference;
- findings;
- policy decision;
- customer;
- recipients;
- retention deadline;
- release/remediation audit.

Release uses trusted reinjection, never public MX ingress.

## Customer/deployment identity

Operational customer IDs such as `CZA-1` are used throughout product/logging.

Technical datastore keys must not become customer-facing identifiers.

## Data retention

Retention must be explicit by data class:

- SMTP transmission logs;
- message metadata;
- raw MIME;
- attachments;
- quarantine;
- DMARC reports;
- audit logs;
- AI analysis;
- model-training candidates.

System policy defines upper/lower bounds; tenant policy can adjust only where permitted.

## AWS IAM

AWS workloads use scoped roles rather than static access keys wherever possible.

Examples:

- scanner can read only its assigned artifacts and write findings;
- Deep AI can retrieve only authorized regional security artifacts;
- Control Backend does not automatically receive unrestricted mail-artifact access;
- backup/operations roles are separated.

## Encryption

Use:

- TLS in transit;
- KMS/S3 encryption at rest;
- encrypted database/storage;
- OpenBao-managed service credentials;
- isolated key policies by deployment.

Key-management decisions remain region-specific and auditable.

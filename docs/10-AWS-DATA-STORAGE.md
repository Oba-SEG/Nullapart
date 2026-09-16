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
- SMTP transaction metadata;
- tenant message/security metadata;
- quarantine metadata;
- DMARC/BIMI metadata;
- configuration;
- append-only administrative audit records;
- transactional outbox events;
- model release metadata;
- connector metadata.

Mail content itself should not be stored as large database blobs by default.

## PostgreSQL Row-Level Security

Tenant/customer-scoped tables should use PostgreSQL Row-Level Security where practical as defense in depth against application query mistakes.

Requirements:

- explicit deployment/customer ownership columns or equivalent internal keys;
- normal request-handling DB role does not bypass RLS;
- tenant scope derived from authenticated server context;
- transaction-scoped database context compatible with pooled connections;
- no long-lived tenant session variable that can leak between pooled requests;
- migrations/maintenance use separate privileged roles;
- automated wrong-tenant SELECT/UPDATE/DELETE tests;
- application authorization remains mandatory above RLS.

Tables and operations that legitimately cross tenants require explicit System/Support service paths and narrowly scoped authorization rather than disabling RLS globally.

## Redis / Valkey

Redis/Valkey supports low-latency runtime state such as:

- policy/config caches;
- greylisting;
- rate/behaviour counters;
- runtime acceleration;
- short-lived distributed coordination;
- cache-revision state;
- idempotency/deduplication acceleration where the authoritative record exists elsewhere.

Redis/Valkey is not the source of truth for policy/customer configuration and a cache-oriented deployment is not automatically considered a durable event bus.

## Durable events

The preferred AWS baseline is:

```text
PostgreSQL transaction
   |-- authoritative business/security change
   |-- audit row when applicable
   '-- transactional outbox row
          |
          v
      outbox publisher
          |
          v
       Amazon SQS
          |
          +--> notifications
          +--> n8n / ClickUp workflows
          +--> DMARC/reporting workers
          +--> analytics
          '-- other asynchronous consumers
```

Consumers assume at-least-once delivery and must be idempotent.

If a different Redis-compatible durable backend is selected, its persistence, acknowledgement, replay, failover and data-loss semantics must be explicitly documented rather than inferred from the Redis protocol.

See [Durable Event Architecture](20-EVENT-DURABILITY.md).

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
- DMARC ingestion artifacts where needed;
- immutable/tamper-evident audit checkpoints/archives where configured.

Recommended controls:

- SSE-KMS;
- strict IAM;
- VPC endpoints/private access;
- Block Public Access;
- versioning where useful;
- lifecycle/retention policies;
- S3 Object Lock where immutable retention is required;
- CloudTrail/audit where needed;
- no default cross-region replication.

## Artifact references

Services exchange artifact references rather than base64 email/attachment blobs.

A reference includes enough information to authorize and locate the artifact without exposing unrestricted bucket access.

Do not expose reusable unrestricted S3 URLs to browsers. Content access uses permission checks and short-lived access.

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

- immutable tenant message identity;
- parent SMTP transaction identity;
- raw MIME/artifact reference;
- findings;
- policy decision;
- customer;
- customer-scoped recipients;
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
- administrative audit logs;
- AI analysis;
- model-training candidates.

System policy defines upper/lower bounds; tenant policy can adjust only where permitted.

## AWS IAM

AWS workloads use scoped roles rather than static access keys wherever possible.

Examples:

- scanner can read only its assigned artifacts and write findings;
- Deep AI can retrieve only authorized regional security artifacts;
- Control Backend does not automatically receive unrestricted mail-artifact access;
- artifact/download service receives narrowly scoped access;
- backup/operations roles are separated.

## Encryption

Use:

- TLS in transit;
- KMS/S3 encryption at rest;
- encrypted database/storage;
- OpenBao-managed service credentials;
- isolated key policies by deployment.

Key-management decisions remain region-specific and auditable.

## Data diagram

See [Data and Storage Flow](diagrams/06-data-storage-flow.mmd).

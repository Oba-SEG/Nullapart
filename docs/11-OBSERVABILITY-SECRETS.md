# Observability, Operations and Secrets

## Objectives

Nullapart must make security, delivery and infrastructure behaviour explainable without leaking customer content.

## Application observability: Sentry-compatible instrumentation to SegLumberjack

SegLumberjack is Nullapart's primary regional application observability platform.

Nullapart application components use Sentry-compatible SDKs/protocols as the standard instrumentation interface.

```text
Frontend / Rust Mail Core / Control Backend / Scanner / Worker
                         |
                         | Sentry SDK / compatible envelope
                         v
                Regional SegLumberjack
                         |
          errors / exceptions / traces / releases
          node/service correlation / diagnostics
```

This architecture does not require events to be sent to a separate hosted Sentry service. References to "Sentry instrumentation" mean the SDK/protocol compatibility layer unless a separate Sentry service is explicitly introduced and approved.

Instrumentation must be included as features are built, not added later.

Before sending telemetry to SegLumberjack:

- remove message body/content;
- remove raw MIME;
- remove attachment content;
- remove tokens/cookies/passwords;
- remove secrets/private keys;
- classify and minimize email addresses/PII;
- avoid sending complete AI prompts when they contain message content;
- preserve only the trace/message/customer/node identifiers needed for diagnostics.

## Native daemon telemetry

Postfix, Rspamd, ClamAV and similar native daemons do not naturally emit Sentry-compatible application events.

Provide an explicit regional collection pipeline for their logs/metrics, using a suitable collector such as Vector, Fluent Bit or an OpenTelemetry-compatible collector.

The collector must:

- parse native syslog/log formats;
- add region/deployment/node/release context;
- redact message content/secrets;
- preserve queue/transaction correlation identifiers where safe;
- route appropriate application diagnostics to SegLumberjack when supported;
- route AWS infrastructure/platform telemetry to CloudWatch as appropriate;
- avoid making the collector a mail-path dependency.

Do not silently drop native daemon telemetry simply because it is not Sentry-native.

## AWS infrastructure telemetry: CloudWatch

CloudWatch has a separate responsibility from SegLumberjack.

Use CloudWatch primarily for AWS infrastructure and managed-service telemetry such as:

- EC2/ECS/container infrastructure;
- CPU/memory/disk/network;
- load balancers;
- RDS/PostgreSQL service metrics;
- Redis/Valkey cache service metrics;
- S3/AWS service metrics;
- VPC/network telemetry;
- AWS alarms and service health;
- infrastructure/platform logs where AWS-native collection is appropriate.

Do not describe CloudWatch as an interchangeable replacement for SegLumberjack application observability.

## Authoritative audit and product events

Observability data is not the authoritative audit record or durable event store.

Security/product events such as impersonation, policy changes, quarantine release, remediation and tenant-state changes are persisted in the dedicated Admin Audit Store and/or authoritative product tables plus the transactional outbox before asynchronous delivery.

A useful mental model is:

```text
security/product transaction
   |-- authoritative DB/audit record
   |-- transactional outbox
   |       '--> SQS / async consumers
   '--> sanitized observability event -> SegLumberjack
```

See [Durable Event Architecture](20-EVENT-DURABILITY.md).

## Node-level visibility

Every runtime records stable/logical node identity plus the observed runtime hostname/IP/AWS identity.

Operational trace should show exactly which runtime performed an action, while recognizing that private IPs can be ephemeral in containerized environments.

Internet-facing SMTP egress addresses remain stable commissioned identities.

## Metrics

Mail metrics include:

- SMTP connections/messages per second;
- queue depth;
- oldest queue age;
- receipt/delivery latency;
- scan latency p50/p95/p99;
- RBL/DNS/reputation latency;
- scanner failure/error/resource-limit rate;
- inline ML latency;
- reject/defer/quarantine rates;
- outbound rates/outbreak detections;
- after-queue filter/reinjection failures;
- SQS/outbox backlog and DLQ depth.

Security-product metrics include:

- false-positive release rate;
- reported false negatives;
- phishing/BEC/impersonation detection outcomes;
- model confidence/calibration;
- model version distribution;
- admin-audit write/checkpoint failures.

## OpenBao

OpenBao is the preferred open-source secrets/workload-identity platform, subject to deployment validation.

Use it for:

- PKI/service certificates;
- per-service credentials;
- short-lived credentials;
- automatic rotation;
- integration secrets;
- database credentials where appropriate.

AWS Secrets Manager/KMS may be used where managed AWS functionality is preferable/required.

## OpenBao availability and bootstrap

OpenBao cannot be a single-node dependency for the platform.

Before production, define per-deployment:

- HA topology;
- storage backend;
- bootstrap ceremony;
- unseal/auto-unseal approach;
- KMS integration where appropriate;
- root/recovery key custody;
- backup/restore;
- disaster recovery;
- PKI root/intermediate hierarchy;
- certificate renewal grace behaviour;
- root/intermediate/key rotation procedures.

Services should tolerate a short OpenBao outage by continuing to use still-valid short-lived credentials rather than immediately failing all mail processing, but they must not bypass certificate expiry or authentication checks.

## Per-service identity

Never use one shared service secret.

Examples:

- `mailcore-za-a-01`;
- `scan-doc-za-a-01`;
- `scan-malware-za-a-02`;
- `control-za-a-01`.

Compromise of one identity must not automatically authorize another service's actions.

## n8n and ClickUp

n8n remains an internal asynchronous orchestration platform.

Typical flow:

```text
PostgreSQL outbox
  -> SQS durable event
  -> n8n worker
  -> ClickUp / internal operational workflow
```

n8n/ClickUp never block mail delivery.

ClickUp receives minimized data such as:

- Nullapart incident/case ID;
- customer ID;
- category;
- severity;
- sanitized summary;
- regional console link.

Do not send raw MIME/attachments/body/secrets to ClickUp by default.

## Notifications

Customer security notifications are sent through Nullapart's own trusted outbound mail path using configured tenant postmaster/security identities.

Notifications require loop protection and are recorded in message/incident trace.

## Manual cache refresh

Support/System Admin can trigger audited cache/config refreshes.

The UI exposes node revision status so operators can see stale runtime configuration.

## Event and operations diagram

See [Observability Architecture](diagrams/10-observability-architecture.mmd), [Admin Audit Architecture](diagrams/11-admin-audit-architecture.mmd), and [Event and Operations Flow](diagrams/07-event-operations-flow.mmd).

# Durable Event Architecture

**Status:** required architecture contract.

## Principle

Do not call an event stream "durable" unless its persistence, acknowledgement, replay and failure semantics are explicitly defined.

Redis/Valkey remains excellent for low-latency cache, counters, greylisting and ephemeral coordination, but Nullapart must not assume a cache-oriented deployment automatically provides the durability required for security and operational events.

## Recommended AWS baseline

For production AWS deployments, use a transactional outbox in PostgreSQL and a dedicated AWS durable queue for asynchronous delivery.

Recommended default:

```text
PostgreSQL transaction
    |
    |-- business/security state
    |-- audit row when applicable
    '-- outbox row
          |
          v
      outbox publisher
          |
          v
        Amazon SQS
          |
          +--> n8n worker
          +--> notifications worker
          +--> DMARC/reporting worker
          +--> ClickUp workflow worker
          +--> analytics worker
          '-- other async consumers
```

SQS is the preferred baseline because Nullapart is AWS-hosted and it avoids forcing Redis to serve both cache and durable-bus roles.

## Redis / Valkey role

Use Redis/Valkey for:

- config/policy cache;
- greylisting state;
- rate counters;
- short-lived distributed coordination;
- realtime UI state where appropriate;
- deduplication/idempotency acceleration where the authoritative record exists elsewhere.

Do not use a non-durable cache instance as the sole source of critical events.

## Alternative durable implementations

A different event backend may be selected when justified, including a Redis-compatible service configured for documented durable persistence semantics, but the implementation must explicitly document:

- persistence mode;
- Multi-AZ/failover behaviour;
- acknowledgement semantics;
- replay/retention;
- consumer offsets/checkpoints;
- data-loss window;
- backup/recovery;
- maximum event size;
- dead-letter handling.

## Event contract

Every durable event contains at least:

- event ID;
- event type/version;
- timestamp;
- region/deployment;
- customer ID where applicable;
- transaction/tenant-message/trace IDs where applicable;
- source service/node;
- safe structured payload;
- idempotency key where needed;
- classification/sensitivity label.

Do not put raw MIME, attachment bytes or secrets into the event bus.

Large/sensitive artifacts are referenced through authorized ArtifactStore references.

## Delivery semantics

Assume at-least-once delivery unless a selected technology explicitly guarantees otherwise.

Consumers must therefore be idempotent.

A consumer records or derives an idempotency key so replay does not create duplicate customer notifications, ClickUp tasks, remediation attempts or DMARC records.

## Dead-letter queues

Critical consumers require DLQ/error handling.

The UI/operations plane should expose unresolved failed-event counts without exposing raw event JSON to normal users.

## Mail-path independence

SQS/n8n/ClickUp/analytics consumers must not block ordinary SMTP delivery.

The synchronous Mail Plane only waits for components explicitly defined as required for the current message disposition.

## Audit relationship

Admin Audit is written transactionally with the administrative mutation where possible.

The outbox/SQS event is a downstream notification/correlation copy and is not the authoritative audit record.

# Nullapart Architecture

**Status:** working/proposed architecture.

## Purpose

Nullapart is a bidirectional, multi-tenant Secure Email Gateway designed for low-latency email handling, regional data isolation, expandable scanning and security intelligence.

NexusSEG is a reference/foundation project. Nullapart does not blindly fork its runtime topology.

## Three planes

### Mail Plane

- Postfix inbound/outbound MTA nodes.
- Rspamd SMTP restriction/Milter integration.
- Rust Nullapart Mail Core.
- scanner fabric.
- lightweight inline ML.
- policy runtime.
- durable Postfix mail queue.
- quarantine/reinjection.

### Control Plane

- System/Support/Customer Admin UI.
- identity integration.
- customers/domains/groups.
- policies.
- notification configuration.
- connectors.
- runtime cache/version control.
- scanner configuration.
- region/deployment administration.
- first-class Admin Audit store and UI.

### Intelligence and Operations Plane

- DMARC/BIMI.
- message trace/reporting.
- cases.
- notifications.
- n8n.
- ClickUp.
- Deep AI.
- model feedback/training preparation.
- outbound campaign/outbreak analytics.

## Runtime principle

The Mail Plane must not require the Control Plane to remain continuously healthy to process ordinary email.

Configuration is persisted in PostgreSQL, versioned, cached and distributed to runtime nodes. Mail nodes retain a last-known-good snapshot.

## SMTP transaction model

One accepted SMTP transaction is not assumed to equal one customer message.

A single `DATA` transaction can contain recipients belonging to multiple Nullapart customers or policy scopes.

Nullapart therefore models:

```text
SMTP Transaction
  |- shared connection/auth/content/security evidence
  |
  +--> Tenant Message Instance / customer A
  |      -> customer-specific policy/disposition/delivery
  |
  '--> Tenant Message Instance / customer B
         -> customer-specific policy/disposition/delivery
```

Shared scans are reused where safe, while customer policy, recipient visibility, quarantine and delivery remain isolated.

See [SMTP Transaction and Tenant Message Contract](18-MESSAGE-TRANSACTION-CONTRACT.md).

## AWS

Production deployments run in AWS.

Open-source components are preferred where mature and suitable. AWS services are used where no suitable open/free alternative exists or where a managed service materially improves security/reliability.

Expected AWS-native capabilities include:

- S3;
- KMS;
- IAM;
- VPC/network isolation;
- regional DNS/load balancing;
- SQS for the preferred durable asynchronous event path;
- CloudWatch for AWS infrastructure telemetry;
- SegLumberjack as the regional Sentry-compatible application observability backend;
- managed PostgreSQL/cache where selected.

## Mail stack

Postfix owns Internet-facing SMTP and durable queueing.

Rspamd provides bounded SMTP/Milter-stage baseline reputation/spam/authentication/fuzzy evidence.

The Rust Mail Core owns Nullapart-specific after-queue orchestration: transaction creation, MIME normalization, scanner execution, findings, recipient/customer partitioning, inline ML, customer policy, disposition and trace/event emission.

Allowed mail is returned to Postfix through a dedicated trusted reinjection path with loop prevention. Rust Mail Core does not replace Postfix as the Internet MTA.

See [Inbound and Outbound Mail Flows](04-MAIL-FLOWS.md).

## Data authority

- PostgreSQL: authoritative configuration/security metadata, transactional outbox and append-only administrative audit schema/store.
- Redis/Valkey: cache, greylisting, realtime counters and short-lived runtime acceleration.
- SQS: preferred durable asynchronous event delivery in AWS.
- S3-compatible ArtifactStore: raw MIME, quarantine and artifacts.
- Postfix queue: durable SMTP message responsibility.

A cache deployment is never assumed to be a durable event bus merely because it speaks the Redis protocol.

See [Durable Event Architecture](20-EVENT-DURABILITY.md).

## Secure message viewing

Message bodies, HTML, attachments and raw MIME are hostile content.

The Control UI uses sanitized isolated rendering, remote-resource blocking, server-side RBAC and audited artifact access. Support cannot obtain restricted content via direct artifact URLs, search, exports or audit logs.

See [Secure Message Rendering and Artifact Access](19-SECURE-MESSAGE-RENDERING.md).

## AWS SMTP commissioning

Every regional deployment that sends direct-to-MX mail must explicitly commission stable public IP/PTR identity and AWS outbound port-25 access before production.

See [AWS SMTP Deployment Commissioning](21-AWS-SMTP-COMMISSIONING.md).

## No public customer API initially

Nullapart exposes an authenticated administration UI backed by its Control Backend.

There is no supported public customer API, API gateway product or customer API-key feature at launch.

## Anti-goals

Nullapart should not:

- reproduce a deep synchronous HTTP chain;
- put an LLM in every-message delivery;
- replace Postfix with a custom Internet-facing SMTP server;
- write custom mail cryptography where mature implementations exist;
- use one shared service secret;
- expose raw JSON in UI;
- include billing;
- depend on Control Plane availability for mail;
- treat Redis cache as automatically durable messaging;
- render hostile email HTML in the trusted UI DOM;
- create a container for every conceptual feature.

## Architecture diagrams

See [Architecture Diagrams](diagrams/README.md), especially the [system context](diagrams/00-system-context.mmd), [regional AWS topology](diagrams/03-regional-aws-topology.mmd), and [Admin Audit Architecture](diagrams/11-admin-audit-architecture.mmd).

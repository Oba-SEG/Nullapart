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
- durable mail queue.
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

## AWS

Production deployments run in AWS.

Open-source components are preferred where mature and suitable. AWS services are used where no suitable open/free alternative exists or where a managed service materially improves security/reliability.

Expected AWS-native capabilities include:

- S3;
- KMS;
- IAM;
- VPC/network isolation;
- regional DNS/load balancing;
- CloudWatch-equivalent logging integration;
- managed database/cache where selected.

## Mail stack

Postfix owns SMTP and durable queueing.

Rspamd provides baseline reputation/spam/authentication/fuzzy evidence.

The Rust Mail Core owns Nullapart-specific orchestration: message normalization, scanner execution, findings, inline ML, customer policy, disposition and trace/event emission.

## Data authority

- PostgreSQL: authoritative configuration/security metadata.
- Redis: cache, streams, realtime counters and greylisting.
- S3-compatible ArtifactStore: raw MIME, quarantine and artifacts.
- Postfix queue: durable SMTP responsibility.

## No public customer API initially

Nullapart exposes an authenticated administration UI backed by its Control Backend.

There is no supported public customer API, API gateway product or customer API-key feature at launch.

## Anti-goals

Nullapart should not reproduce a deep synchronous HTTP chain, put an LLM in every-message delivery, implement SMTP itself, write custom mail cryptography where mature implementations exist, use one shared service secret, expose raw JSON in UI, include billing, depend on Control Plane availability for mail, or create a container for every feature.

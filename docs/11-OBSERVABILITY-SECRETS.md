# Observability, Operations and Secrets

## Objectives

Nullapart must make security, delivery and infrastructure behaviour explainable without leaking customer content.

## Sentry

Sentry is the application error/exception telemetry platform.

Instrumentation must be included as features are built, not added later.

Before sending events:

- remove message body/content;
- remove raw MIME;
- remove attachment content;
- remove tokens/cookies/passwords;
- classify email addresses/PII;
- preserve trace/message/customer/node identifiers needed for diagnostics.

## Operational logging

Regional operational logging is sent to SegLumberjack and/or the AWS CloudWatch-equivalent selected for that deployment.

Every relevant record should contain:

- timestamp;
- region;
- deployment;
- node ID;
- hostname;
- node IP;
- service;
- trace ID;
- Nullapart message ID;
- customer ID;
- event/reason code;
- severity;
- duration where relevant.

## Node-level visibility

Because every mail/scanner node has a unique IP and numbered hostname, operational trace must show exactly which node performed each action.

## Metrics

Mail metrics include:

- SMTP connections/messages per second;
- queue depth;
- oldest queue age;
- receipt/delivery latency;
- scan latency p50/p95/p99;
- RBL/DNS/reputation latency;
- scanner failure/error rate;
- inline ML latency;
- reject/defer/quarantine rates;
- outbound rates/outbreak detections.

Security-product metrics include:

- false-positive release rate;
- reported false negatives;
- phishing/BEC/impersonation detection outcomes;
- model confidence/calibration;
- model version distribution.

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
durable Nullapart event
  -> n8n
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

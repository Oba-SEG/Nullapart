# Phase 9 — Operational Automation and Production Hardening

## Objective

Turn the implemented product into a supportable, recoverable production service with controlled automation, operational evidence and production-readiness gates.

## Prerequisites

All product phases needed for the intended launch scope are complete.

Not every optional feature must exist, but every enabled production capability must satisfy its phase exit criteria.

## Durable automation

Expand:

```text
PostgreSQL outbox
  -> SQS
  -> idempotent workers
  -> n8n where workflow orchestration is appropriate
  -> ClickUp / customer notification / reporting
```

n8n is asynchronous and non-critical to mail delivery.

## ClickUp

Define event categories such as:

- critical threat incident;
- customer outage;
- outbound outbreak;
- remediation failure;
- DMARC degradation;
- scanner/system failure;
- security configuration incident.

Send minimized metadata only.

Use deduplication/aggregation to avoid task storms.

## Operational dashboards

System/Support needs:

- regional deployment health;
- Postfix queues;
- scanner health/backlog;
- config revision/staleness;
- SQS/outbox/DLQ;
- RDS/Redis/S3 health;
- SegLumberjack/collector health;
- OpenBao/ZITADEL health;
- SMTP commissioning status;
- Deep AI capacity if enabled;
- security-control health.

## Alerting

Define actionable alerts with:

- severity;
- owner;
- threshold;
- suppression/cooldown;
- runbook link;
- escalation.

Avoid alerting on every individual malicious message.

## Backup/DR validation

Execute:

- PostgreSQL restore;
- audit recovery/checkpoint verification;
- S3 recovery scenario;
- OpenBao recovery;
- identity recovery;
- config/IaC reconstruction;
- node/AZ failure test;
- mail queue recovery scenario.

Measure actual RPO/RTO.

## Security exercises

Before production:

- privileged account compromise tabletop;
- cross-tenant incident tabletop;
- leaked key/cert rotation drill;
- queue/scanner outage drill;
- regional impairment exercise appropriate to architecture;
- external penetration test as required.

## Performance/capacity

Benchmark:

- SMTP connection/message throughput;
- queue behavior;
- scanner concurrency;
- latency p50/p95/p99;
- database/cache load;
- SQS/outbox throughput;
- S3 artifact rate;
- UI query/report performance;
- Deep AI separately.

Establish scaling thresholds for creating additional regional deployment iteration (e.g. ZAB).

## Release operations

Define:

- release versioning;
- changelog;
- staged rollout;
- database migration process;
- rollback;
- image provenance;
- SBOM retention;
- production approval;
- emergency change procedure.

## Production security gate

Must verify:

- Phase -1 accepted/current;
- MFA and break-glass controls;
- audit functioning;
- immutable audit checkpoint;
- tenant isolation;
- no Critical vulnerabilities;
- High risk resolved or formal exception;
- restore tests pass;
- required runbooks exercised;
- SMTP port25/PTR/DNS commissioning complete;
- logging/alerting active;
- data residency tested;
- secrets/cert rotation paths tested;
- scanner failure semantics validated;
- customer content rendering isolation tested.

## AI-agent instructions

AI agents working in operational hardening must not:

- auto-remediate production infrastructure without an approved workflow;
- weaken alert thresholds to make tests pass;
- silently disable failing security gates;
- modify production secrets directly;
- treat a passing happy-path test as resilience evidence.

## Exit criteria

Phase 9 is complete for a production scope only when:

- production-readiness checklist signed off;
- operational dashboards/alerts/runbooks exist;
- restore/security exercises have evidence;
- capacity baseline exists;
- release/rollback process tested;
- security monitoring is live;
- support operations can diagnose failures without message-content overreach.

## Ongoing operation

Production is not the end of the roadmap.

Continuously feed:

- incidents;
- vulnerabilities;
- false positives/negatives;
- abuse;
- capacity;
- audit/control failures;
- customer operational findings

back into threat models, tests, policies, runbooks and future roadmap revisions.

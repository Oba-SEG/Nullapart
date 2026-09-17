# Phase 9 — Operational Automation and Production Hardening

## Objective

Turn the implemented product into a supportable, recoverable production service with controlled automation, measured reliability, operational evidence and production-readiness gates.

## Prerequisites

All product phases needed for the intended launch scope are complete.

Not every optional feature must exist, but every enabled production capability must satisfy its phase exit criteria.

## Required reading

- `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`
- `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`
- `docs/security/19-VERSION-CONTROL-CICD.md`
- `docs/29-TENANT-FEATURE-ROUTING.md`
- `docs/compliance/README.md`

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

Define event categories such as critical threat incident, customer outage, outbound outbreak, remediation failure, DMARC degradation, scanner/system failure and security-configuration incident.

Send minimized metadata only.

Use deduplication/aggregation to avoid task storms.

## Tier-3 reliability implementation

Classify production-critical capabilities using `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`.

For each Tier-3 capability establish:

- owner;
- SLI;
- SLO;
- error budget;
- burn-rate alert rules;
- RTO/RPO;
- dependency/failure map;
- redundancy/failover design;
- capacity threshold;
- degraded-mode behavior;
- runbook.

Tier-3 is an internal Nullapart reliability classification, not an external certification claim.

## Burn-rate alerting

Implement multi-window SLO alerts.

Baseline:

- fast page: 14.4x burn on both 1h and 5m windows;
- sustained page: 6x burn on both 6h and 30m windows;
- calibrated low/slow burn ticket path for long-duration budget exhaustion.

Alerts include deployment, SLO, error-budget remaining, runbook and safe diagnostic links.

Do not replace user-impact SLO paging with generic CPU/memory alerts.

## Operational dashboards

System/Support operations need:

- regional deployment health;
- Tier-3 SLO compliance;
- error-budget remaining and burn rates;
- Postfix queues/oldest age;
- scanner health/backlog/UNKNOWN-ERROR rates;
- config revision/staleness;
- SQS/outbox/DLQ;
- RDS/Redis/S3 health;
- SegLumberjack/collector health;
- OpenBao/ZITADEL health;
- SMTP commissioning status;
- Deep AI capacity if enabled;
- security-control health.

## Alerting

Every actionable alert defines:

- severity;
- owner;
- threshold/SLO;
- suppression/cooldown;
- runbook;
- escalation.

Avoid one alert per malicious message or other task-storm patterns.

## Patching and dependency lifecycle

Production readiness verifies:

- supported runtime/framework versions;
- dependency/security update process operating;
- host/container patch process exercised;
- mail-node rolling patch/drain process;
- scanner signature/ruleset freshness;
- no unsupported/EOL critical platform without formal exception.

## Zero-day readiness

Before production, verify the zero-day process is operational:

- intelligence sources/ownership identified;
- SBOM/component-version correlation possible;
- emergency System kill switches exist for risky optional/parser/tool paths where needed;
- emergency branch/PR/release process works without direct pushes to `main`;
- vulnerable node/workload can be drained/isolated;
- credential/key/session rotation runbooks exist;
- retrospective hunt data/correlation is available;
- temporary mitigation ownership/expiry is tracked.

Exercise at least one tabletop or technical scenario for a hostile-content parser or Internet-facing dependency zero-day.

## Network/firewall/load-balancer validation

Verify:

- Security Group/port registry matches deployed reality;
- no unauthorized public listeners;
- ALB/WAF TLS/security/rate settings;
- SMTP public node source-IP/reputation behavior;
- no public SSH;
- scanner egress restrictions;
- private database/cache/secrets/AI;
- load/failover behavior under target capacity.

## Compliance evidence gate

Populate/review `docs/compliance/` records for actual production scope including:

- scope/applicability;
- control register;
- evidence catalog;
- data-processing register;
- third parties;
- risks/exceptions;
- branch-protection evidence;
- tenant-routing/feature-override evidence;
- Tier-3/SLO evidence;
- zero-day response evidence;
- production-readiness evidence.

Do not convert internal readiness into an unverified certification claim.

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

Measure actual RPO/RTO against Tier-3 expectations.

## Security/reliability exercises

Before production:

- privileged account compromise tabletop;
- cross-tenant incident tabletop;
- leaked key/cert rotation drill;
- queue/scanner outage drill;
- zero-day parser/dependency scenario;
- one-MX/node loss/failover exercise;
- burn-rate alert/runbook exercise;
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

Establish capacity/backpressure thresholds and scaling thresholds for additional regional deployment iteration such as ZAB.

## Release operations

Define and test:

- release versioning;
- changelog;
- staged rollout;
- database migration process;
- rollback;
- image provenance;
- SBOM retention;
- production approval;
- emergency/zero-day change procedure.

No direct push to `main`, including emergency changes.

## Production security/reliability gate

Must verify:

- Phase -1 accepted/current;
- protected `main` active with no direct pushes;
- required CI/reviews active;
- MFA and break-glass controls;
- audit functioning + immutable checkpoint;
- tenant routing/RLS/isolation tests;
- tenant feature override/System-floor precedence tests;
- no unresolved Critical vulnerabilities;
- High risk resolved or formal exception;
- zero-day response process exercisable;
- restore tests pass;
- required runbooks exercised;
- SMTP port25/PTR/DNS commissioning complete;
- logging/alerting active;
- Tier-3 SLO/error-budget/burn-rate alerts active;
- data residency tested;
- secrets/cert rotation paths tested;
- scanner failure semantics validated;
- customer-content rendering isolation tested;
- rate-limit failure/abuse behavior tested;
- supported-version/patch status verified;
- firewall/port registry verified;
- compliance evidence populated for launch scope.

## AI-agent instructions

AI agents working in operational hardening must not:

- auto-remediate production infrastructure without an approved workflow;
- weaken SLO/burn-rate/alert thresholds to make tests pass;
- exclude failures from SLIs without documented review;
- silently disable failing security gates;
- modify production secrets directly;
- deploy emergency zero-day fixes autonomously;
- bypass PR/branch protection;
- treat a passing happy-path test as resilience evidence.

## Exit criteria

Phase 9 is complete for a production scope only when:

- production-readiness checklist signed off;
- operational dashboards/alerts/runbooks exist;
- Tier-3 SLO/error-budget monitoring is active;
- burn-rate alerts have been tested;
- restore/security/reliability exercises have evidence;
- zero-day process has exercise/evidence;
- capacity baseline exists;
- release/rollback/emergency process tested;
- security monitoring is live;
- support operations can diagnose failures without message-content overreach.

## Ongoing operation

Production is not the end of the roadmap.

Continuously feed incidents, vulnerabilities/zero-days, SLO/error-budget burn, false positives/negatives, abuse, capacity, audit/control failures and customer operational findings back into threat models, tests, policies, runbooks and future roadmap revisions.

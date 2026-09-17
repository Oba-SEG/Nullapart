# Tier-3 Reliability, SLOs and Error Budgets

**Status:** mandatory production reliability architecture.

## Purpose

Nullapart needs explicit reliability objectives for the mail/security capabilities that customers depend on.

**Nullapart Tier 3** is an internal product reliability classification. It does not claim Uptime Institute Tier III certification or any external certification.

Tier 3 means a capability is production-critical and must be designed, operated and tested with redundancy, measured service objectives, bounded failure modes, recovery targets and actionable alerting.

## Reliability classes

### Tier 3 — production critical

Initial Tier-3 capabilities:

- inbound SMTP edge / queue acceptance;
- outbound SMTP relay/delivery path;
- durable accepted-message responsibility;
- Rust Mail Core processing;
- required scanner path;
- policy/config runtime used by Mail Plane;
- PostgreSQL authoritative state;
- S3 artifacts required for message/quarantine processing;
- Control Backend for administrative/security operations;
- identity required for administrative access;
- Admin Audit persistence for high-risk mutations;
- transactional outbox / SQS processing for required asynchronous security workflows.

### Tier 2 — operationally important, degradable

Examples:

- SegLumberjack application diagnostics;
- CloudWatch views/secondary operational dashboards;
- optional threat-intelligence enrichment;
- selected reporting/analytics paths;
- DMARC analytics that do not affect mail responsibility.

Loss degrades operations or enrichment but must not cause accepted mail loss or silent security bypass.

### Tier 1 — asynchronous/non-mail-critical

Examples:

- ClickUp automation;
- non-critical n8n workflows;
- optional reporting exports;
- other external workflow conveniences.

### Separate dependency class — Deep AI

Deep AI may itself require robust regional hosting, but ordinary mail processing must not depend on its availability unless a message is explicitly held for Deep AI analysis.

## Tier-3 design requirements

A Tier-3 capability requires, where technically applicable:

- no single application-process instance dependency;
- multi-AZ managed service configuration or redundant nodes;
- health/readiness checks;
- bounded queues/backpressure;
- capacity headroom and scaling thresholds;
- safe degraded behavior;
- last-known-good configuration where appropriate;
- explicit RTO/RPO;
- measurable SLIs/SLOs;
- error budget;
- multi-window burn-rate alerting;
- runbook and ownership;
- tested restore/failover/containment;
- deployment/rollback strategy;
- dependency/failure map.

For public SMTP, redundancy may be expressed through multiple commissioned MX nodes rather than a generic application load balancer.

## Reliability is per capability

Do not publish or operate from one vague "Nullapart uptime" number.

Different user-visible responsibilities need different indicators.

Examples:

- can a remote sender reach an MX and receive a correct SMTP response?;
- once Nullapart returns `250`, is the accepted message durably retained?;
- how long does an accepted message wait before security processing completes?;
- can permitted administrators authenticate and inspect security state?;
- can quarantine actions be executed and audited?;
- are required scanners producing valid results rather than UNKNOWN/ERROR?;
- are policy snapshots current enough to process safely?

## SLI model

Every production-critical capability defines:

- event population;
- success condition;
- failure condition;
- excluded events, if any;
- measurement source;
- aggregation window;
- target SLO;
- owning team/role;
- runbook.

Exclusions must be narrow and documented. Do not manipulate the denominator to create artificial reliability.

## Initial SLO design targets

These are initial engineering targets to validate during load/failure testing before production approval, not contractual SLA promises.

| Capability | Candidate SLI | Initial design target |
|---|---|---:|
| Inbound SMTP service | successful eligible SMTP connection/transaction handling | 99.95% monthly |
| Accepted-message durability | accepted messages not lost after Nullapart `250` | 99.9999% monthly |
| Mail processing | accepted tenant instances reaching a valid terminal/queued state within policy latency target | 99.9% monthly |
| Required scanner availability | required scan attempts yielding valid result or explicit policy-safe handling | 99.9% monthly |
| Control Backend | successful eligible administrative requests | 99.9% monthly |
| Administrative authentication | successful eligible login/session operations | 99.9% monthly |
| Audit persistence for required mutations | high-risk mutations with durable required audit | 100% by design; mutation fails closed if audit cannot persist |

Targets must be reviewed after real workload/error data exists.

## Latency objectives

Availability and latency are distinct.

Define latency SLIs such as:

- SMTP banner/command response;
- queue acceptance time;
- Mail Core handoff latency;
- scan completion p95/p99;
- message age in queue;
- control API p95/p99;
- quarantine release processing;
- policy/config propagation;
- outbox/SQS event age.

Security-sensitive work must not be dropped merely to satisfy latency targets.

## Error budget

For an SLO target `S`, the error-budget fraction is:

```text
1 - S
```

Examples over a 30-day period:

- 99.9% -> 0.1% error budget;
- 99.95% -> 0.05% error budget.

Error budgets guide release/risk decisions.

When a Tier-3 service is consuming budget too quickly:

- halt risky rollout;
- use kill switch/rollback where appropriate;
- prioritize reliability remediation;
- avoid shipping unrelated high-risk changes until the burn is understood.

Error budget is not permission to lose accepted mail or violate security invariants.

## Burn-rate alerting

Use multi-window, multi-burn-rate alerting for SLO breaches.

Baseline production pattern:

### Fast page

- burn rate: 14.4x;
- long window: 1 hour;
- short window: 5 minutes;
- both windows must breach.

This detects severe rapid budget consumption.

### Sustained page

- burn rate: 6x;
- long window: 6 hours;
- short window: 30 minutes;
- both windows must breach.

This detects slower but still urgent sustained consumption.

### Slow-burn ticket / planned response

- burn rate around 1x or another calibrated low threshold;
- multi-day long window plus shorter confirmation window;
- route to actionable maintenance rather than waking an operator for noise.

Exact low-burn windows may be tuned after production behavior is understood.

## Alert requirements

Every alert has:

- service/SLO;
- current burn rate;
- windows breached;
- error-budget remaining;
- deployment/region;
- likely failing dependency where known;
- owner/escalation;
- runbook link;
- safe correlation/dashboard links.

Avoid alerting directly on raw CPU/memory metrics when there is a better user-impact SLI.

Resource alerts still exist for capacity prevention but are distinct from SLO paging.

## Mail-specific reliability indicators

Track at minimum:

- SMTP reachability/transaction result rate;
- Postfix queue depth;
- oldest queue age;
- accepted-message handoff failures;
- reinjection failures;
- delivery retry/terminal failure rate;
- scanner required-result success rate;
- scanner UNKNOWN/ERROR rate;
- policy snapshot age/staleness;
- disk/spool capacity;
- S3 artifact operation failures;
- database transaction failures;
- outbox/SQS age/backlog/DLQ.

## Load shedding and backpressure

When capacity/security processing cannot keep up, prefer controlled backpressure before unsafe overload.

Examples:

- SMTP temporary deferral before local spool exhaustion;
- bounded scanner concurrency;
- hold/defer when a required security control cannot execute safely;
- rate-limit expensive administrative exports/searches;
- reject/defer new nonessential async work before required queues are exhausted.

Do not accept unbounded work and hope downstream recovers.

## Failure domains

Tier-3 design considers separately:

- process/container loss;
- node/EC2 loss;
- AZ impairment;
- database/cache/service degradation;
- dependency exhaustion;
- DNS failure;
- certificate/identity failure;
- bad deployment/config revision;
- malicious/abusive load;
- AWS regional impairment.

Routine architecture is region-local; regional disaster strategy must respect residency requirements.

## RTO / RPO

Every Tier-3 subsystem receives explicit RTO/RPO before production.

Accepted-mail durability and Admin Audit need tighter data-loss expectations than rebuildable caches/analytics.

Redis/Valkey runtime cache does not get treated as an authoritative RPO source.

## Release safety

Tier-3 deployments require:

- staged rollout;
- immutable artifact identity;
- compatibility checks;
- rollback/containment;
- health/SLO observation;
- migration safety;
- one deployment/region target at a time where appropriate.

Do not roll a mail-path change everywhere simultaneously before proving it in a controlled production slice.

## Reliability tests

Before production exercise:

- single process/node failure;
- one mail MX unavailable;
- Postfix/Mail Core restart with queued mail;
- scanner outage/timeout;
- database failover scenario;
- Redis loss;
- SQS/DLQ backlog;
- config distribution staleness;
- S3 errors;
- dependency latency;
- queue/spool pressure;
- AZ impairment where feasible;
- bad release rollback;
- high request/mail load;
- alert firing and runbook response.

## Dashboard/UI

System operations should show:

- SLO compliance;
- error-budget remaining;
- burn rate;
- active alerts;
- queue/backlog/age;
- major dependency health;
- deployment version/config revision;
- capacity saturation signals.

Support views must not expose Restricted customer content.

## AI-agent rules

AI agents must not:

- call a component Tier 3 without defining its SLI/SLO/failure behavior;
- weaken an SLO alert to make a noisy system appear healthy;
- exclude failures from SLI denominators without documented justification;
- trade accepted-mail durability/security correctness for latency;
- treat Deep AI/n8n/ClickUp availability as a dependency of ordinary SMTP processing;
- silently remove redundancy/health checks/rollback from Tier-3 paths.

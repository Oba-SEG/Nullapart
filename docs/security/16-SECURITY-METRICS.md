# Security and Reliability Metrics

Security/reliability metrics detect control degradation and improve decisions.

## Identity/access

Track MFA coverage, phishing-resistant MFA for privileged staff, System/Support admin counts, dormant privileged accounts, access-review completion and break-glass use.

## Vulnerability management

Track:

- open Critical/High findings;
- age;
- patch-SLA compliance;
- known-exploited vulnerabilities;
- scan coverage;
- time from zero-day intelligence receipt to triage;
- time to establish applicability;
- time to containment;
- time to patched deployment;
- components/deployments with UNKNOWN/POTENTIALLY_AFFECTED exposure;
- overdue temporary mitigations.

## Audit

Track audit write failures, checkpoint/archive failures, exports, high-risk admin actions and impersonation sessions.

## Mail security

Track required scanner availability, UNKNOWN/ERROR rate, malware/phishing/BEC detections, false-positive release rate, confirmed false negatives, queue depth/age, post-delivery threats and outbound-abuse incidents.

## Reliability / SLOs

For every Tier-3 capability track:

- current SLI/SLO performance;
- error-budget remaining;
- fast-window burn rate;
- sustained burn rate;
- queue/backlog age where relevant;
- major dependency failure contribution;
- RTO/RPO exercise result;
- active degraded mode/kill switch.

Use the multi-window burn-rate model defined in `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`.

Operational paging should prioritize user/security-impact SLIs rather than raw resource utilization alone.

## Tenant/feature controls

Track:

- tenant/deployment feature override counts;
- emergency System kill-switch use;
- expired temporary overrides;
- configuration revision/staleness;
- failed/denied tenant-context switches;
- tenant-routing/RLS isolation violations (expected zero).

## Secrets/crypto

Track certificates nearing expiry, secrets beyond rotation targets, failed rotations, revoked identities and DKIM/TLS/HMAC key age where applicable.

## Incident response

Track incident count/severity, time to detect, time to contain, time to recover, SLO/error-budget impact and overdue corrective actions.

## Backup/DR

Track backup success, restore-test success, last restore exercise and achieved RPO/RTO.

## Reporting

System Admin security/operations dashboards should surface relevant control-health, SLO and burn-rate metrics without exposing secrets or customer message content.

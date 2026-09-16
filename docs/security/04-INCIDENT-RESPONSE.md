# Security Incident Response

## Incident classes

Examples:

- admin/account compromise;
- tenant data exposure;
- cross-tenant access;
- leaked secret/private key;
- compromised scanner/node;
- malicious dependency/supply-chain event;
- S3 exposure;
- control-plane compromise;
- outbound spam/reputation incident;
- mail-routing outage/security bypass;
- Deep AI or training-data compromise;
- audit integrity failure;
- regional infrastructure compromise.

## Severity

Use documented severity levels based on:

- confidentiality impact;
- integrity impact;
- mail availability;
- affected tenants/regions;
- active exploitation;
- privileged compromise;
- regulatory/customer obligations.

## Process

1. detect;
2. validate/triage;
3. declare incident/severity;
4. contain;
5. preserve evidence;
6. eradicate;
7. recover;
8. validate monitoring;
9. notify stakeholders/customers where required;
10. postmortem;
11. track corrective actions.

## Evidence

Preserve:

- admin audit;
- SegLumberjack telemetry;
- CloudWatch/AWS logs;
- Postfix/queue logs;
- scanner records;
- IAM/CloudTrail records;
- relevant DB/S3 snapshots;
- affected binaries/config versions;
- timestamps/time source.

Evidence access is restricted and audited.

## Credential compromise

Have procedures to revoke/rotate:

- admin sessions;
- ZITADEL credentials/factors;
- OpenBao-issued credentials/certs;
- DKIM keys;
- TLS certs;
- AWS IAM credentials/roles where relevant;
- connector OAuth tokens;
- API/webhook secrets.

## Regional containment

Architecture must allow one deployment/region to be isolated without disabling unrelated deployments.

## Postmortem

Security incidents require:

- timeline;
- root cause;
- control failures;
- detection gaps;
- customer/data impact;
- corrective actions;
- owners/dates;
- threat-model/runbook updates.

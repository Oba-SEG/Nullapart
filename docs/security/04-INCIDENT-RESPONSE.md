# Security Incident Response

## Incident classes

Examples include admin/account compromise, tenant-data exposure, cross-tenant access, leaked keys/secrets, compromised scanner/node, supply-chain incident, S3 exposure, control-plane compromise, outbound spam/reputation incident, mail-security bypass, Deep AI/training compromise and audit integrity failure.

## Severity

Severity considers confidentiality, integrity, mail availability, tenants/regions affected, active exploitation, privileged compromise and notification obligations.

## Process

1. detect;
2. validate/triage;
3. declare severity;
4. contain;
5. preserve evidence;
6. eradicate;
7. recover;
8. validate monitoring;
9. notify where required;
10. postmortem;
11. track corrective actions.

## Evidence

Preserve relevant admin audit, SegLumberjack, CloudWatch/AWS, Postfix, scanner, IAM/CloudTrail, DB/S3, binary/config and timestamp evidence.

Evidence access is restricted and audited.

## Credential compromise

Procedures must support revocation/rotation of admin sessions, identity factors, OpenBao credentials/certs, DKIM keys, TLS certs, AWS credentials, connector OAuth tokens and webhook/API secrets.

## Regional containment

One deployment/region can be isolated without disabling unrelated deployments.

## Postmortem

Record timeline, root cause, control failures, detection gaps, customer/data impact, corrective actions, owners/dates and required threat-model/runbook updates.

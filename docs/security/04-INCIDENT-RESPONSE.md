# Security Incident Response

## Incident classes

Examples include admin/account compromise, tenant-data exposure, cross-tenant access, leaked keys/secrets, compromised scanner/node, supply-chain incident, S3 exposure, control-plane compromise, outbound spam/reputation incident, mail-security bypass, Deep AI/training compromise, audit integrity failure and active zero-day exploitation.

## Severity

Severity considers confidentiality, integrity, mail availability, tenants/regions affected, active exploitation, privileged compromise and notification obligations.

A credible zero-day affecting an Internet-facing or hostile-content parser path may require incident declaration before confirmed exploitation if the plausible impact is severe enough.

## Process

1. detect/intake;
2. validate/triage;
3. declare severity;
4. contain;
5. preserve evidence;
6. eradicate/patch;
7. recover;
8. validate monitoring/SLO behavior;
9. notify where required;
10. postmortem;
11. track corrective actions.

## Zero-day fast path

Use [Zero-Day Intelligence and Emergency Vulnerability Response](27-ZERO-DAY-INTELLIGENCE-RESPONSE.md) for:

- applicability/exposure tracking;
- emergency kill switches/containment;
- accelerated patching;
- retrospective hunt;
- rescanning/reprocessing;
- credential/key/session decisions.

Normal traceability/review is compressed during emergency handling, not removed.

## Evidence

Preserve relevant admin audit, SegLumberjack, CloudWatch/AWS, Postfix, scanner, IAM/CloudTrail, DB/S3, binary/config/SBOM, deployment digest and timestamp evidence.

Evidence access is restricted and audited.

## Credential compromise

Procedures must support revocation/rotation of admin sessions, identity factors, OpenBao credentials/certs, DKIM keys, TLS certs, AWS credentials, connector OAuth tokens and webhook/API/HMAC secrets.

Rotation scope should follow exposure analysis rather than blindly rotating unrelated global credentials.

## Regional containment

One deployment/region can be isolated without disabling unrelated deployments.

Regional containment must preserve accepted-message responsibility and data-residency requirements.

## Postmortem

Record timeline, root cause, control failures, detection gaps, customer/data impact, reliability/SLO impact, corrective actions, owners/dates and required threat-model/runbook updates.

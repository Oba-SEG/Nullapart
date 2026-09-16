# Network Security Baseline

## Segmentation

Separate at minimum:

- public SMTP edge;
- public web/control ingress;
- private application/scanner tier;
- data tier;
- secrets/identity tier;
- Deep AI tier;
- management/operations paths.

## Exposure

Publicly reachable services should be limited to required SMTP ingress and HTTPS control/login endpoints.

Do not publicly expose PostgreSQL, Redis/Valkey, OpenBao, scanner APIs, Deep AI, n8n management, metrics/debug endpoints or unnecessary identity-management interfaces.

## Firewall and port registry

AWS Security Groups are the primary stateful workload firewall.

- default deny by absence;
- use SG-to-SG references for internal service access;
- public `0.0.0.0/0` / `::/0` ingress only for explicitly documented edge ports;
- no public SSH;
- no public database/cache/secrets/AI/scanner management ports.

The authoritative baseline port registry is `infrastructure/aws/PORTS.md`.

Opening a new port requires security/architecture review and IaC + registry update.

## Load-balancing boundaries

- HTTPS Control Plane: public ALB + WAF.
- SMTP: direct MX/Postfix node identities by default.
- Never place SMTP behind an Application Load Balancer.
- NLB for SMTP requires explicit source-IP/STARTTLS/timeout validation before adoption.

## East-west traffic

Use restrictive security groups, workload identity/mTLS where practical and explicit service allowlists. Do not trust a flat private network.

## Egress

Control outbound network access.

Scanners/parsers that do not require Internet access should have none.

URL/threat-intelligence services use explicit egress paths and SSRF protections.

## Administration

Prefer AWS Systems Manager/controlled management paths instead of broad SSH exposure.

Break-glass interactive host access is exceptional, audited and tightly restricted.

## DNS

Use controlled regional DNS and monitor unauthorized DNS changes.

## DDoS/resource protection

Public endpoints require connection/rate controls, SMTP abuse throttling, web rate limiting/WAF where appropriate, queue/resource alarms and capacity protections.

## IPv6

IPv6 must not become an unmanaged bypass of IPv4 controls. Enable only with equivalent routing, logging and firewall policy.

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

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

Publicly reachable services should be limited to what is required, primarily:

- SMTP ingress;
- HTTPS control/login endpoints.

Do not publicly expose:

- PostgreSQL;
- Redis/Valkey;
- OpenBao;
- ZITADEL management interfaces beyond required auth endpoints;
- scanner APIs;
- Deep AI;
- n8n management;
- metrics/debug endpoints.

## East-west traffic

Use:

- restrictive security groups;
- workload identity/mTLS where practical;
- explicit service allowlists;
- no broad flat-network trust.

## Egress

Control outbound network access.

Scanners/parsers that do not require Internet access should have none.

URL/threat-intelligence services should use explicit egress paths and SSRF protections.

## Administration

Prefer AWS Systems Manager/controlled management paths instead of broad SSH exposure.

Break-glass interactive host access is exceptional, audited and tightly restricted.

## DNS

Use controlled regional DNS and protect internal/private service naming.

Monitor unauthorized DNS changes.

## DDoS/resource protection

Public endpoints need:

- connection/rate controls;
- SMTP abuse throttling;
- web rate limiting/WAF where appropriate;
- queue/resource alarms;
- capacity protections.

## IPv6

IPv6 must not become an unmanaged bypass of IPv4 security controls. Enable only with equivalent policy, routing, logging and firewall coverage.

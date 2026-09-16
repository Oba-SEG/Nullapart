# Nullapart Port and Exposure Registry

**Status:** baseline; production IaC must match this registry.

Opening a new port requires architecture/security review and an update here.

| Service / purpose | Protocol | Port | Source | Destination | Public? | Security/auth | Notes |
|---|---:|---:|---|---|---|---|---|
| Control Plane HTTPS | TCP | 443 | Internet | Public ALB | Yes | TLS + WAF + app auth | Only public web/admin entry |
| HTTP redirect | TCP | 80 | Internet | Public ALB | Optional | Redirect only | May remain closed |
| Inbound MX | TCP | 25 | Internet | Inbound Postfix nodes | Yes | SMTP/TLS/policy | Direct MX baseline |
| Customer relay | TCP | 25 | Approved sources | Outbound/relay Postfix | Conditional | source/connector auth | Only when configured |
| Customer submission | TCP | 587 | Approved customers | Relay Postfix | Conditional | authenticated/TLS submission | If product enables |
| SSH | TCP | 22 | Internet | Any node | **No** | SSM/break-glass instead | Never public baseline |
| PostgreSQL | TCP | 5432 | Authorized app/migration SGs | RDS/PostgreSQL | No | TLS + DB auth | Private only |
| Redis/Valkey | TCP | 6379 or selected TLS port | Authorized workloads | Cache | No | TLS/auth where supported | Private only |
| OpenBao | TCP | implementation-selected | Authorized workloads/admin path | OpenBao | No | mTLS/token/workload auth | Private only |
| Deep AI API | TCP | implementation-selected | Authorized AI clients | AI service | No | private + mTLS/workload auth | Never Internet-facing |
| Scanner APIs | TCP | implementation-selected | Mail Core only/as designed | Scanner workloads | No | workload auth | Prefer no network API when not needed |
| Metrics/debug | TCP | implementation-selected | Observability/ops SG only | Workloads | No | restricted | Never public |

## Rules

- Security Groups are the primary stateful workload firewall.
- Internal rules prefer SG-to-SG references over broad VPC CIDRs.
- No `0.0.0.0/0` or `::/0` ingress except explicitly public edge ports.
- IPv6 exposure must match IPv4 controls.
- New listeners require owner, justification, authentication, TLS/mTLS decision and threat review.
- IaC and this registry must not drift.

# Container, Load-Balancing and Network Security Architecture

**Status:** AWS implementation baseline; exact sizing remains benchmark-driven.

## Orchestration principle

Do not force every workload into Kubernetes or one compute model.

Initial AWS baseline:

- Amazon ECS as the primary container orchestrator for ordinary application/worker/scanner workloads;
- ECS capacity providers to select Fargate/EC2-style capacity where suitable;
- dedicated accelerated EC2/ECS capacity for GPU/specialized Deep AI/scanners;
- dedicated mail EC2 nodes as an intentional exception where stable SMTP IP, durable local queue and predictable MTA lifecycle are more important than generic task mobility.

EKS is not the initial baseline. Introduce Kubernetes only if a demonstrated requirement justifies the additional control-plane/operational complexity.

## Workload placement

### Fargate / serverless ECS candidates

Suitable stateless/lightweight workloads may include:

- frontend/static service;
- Control Backend;
- asynchronous workers;
- notifications;
- DMARC workers;
- selected n8n components where persistence is externalized.

### ECS EC2 capacity candidates

Use when workloads require:

- native scanner dependencies;
- high CPU/RAM;
- specialized kernel/runtime controls;
- local high-speed temp storage;
- GPU/accelerators;
- stronger host-level isolation profile.

### Dedicated mail nodes

Postfix/Rspamd/mail filter boundary may run as pinned containers on dedicated EC2 mail nodes managed by IaC/system service management.

Reasons:

- stable EIP/PTR/reputation;
- durable Postfix spool/EBS;
- simple failure ownership;
- controlled drain/patch lifecycle.

Do not move public MTA identity between arbitrary ephemeral tasks without a validated queue/IP/reputation design.

## Container baseline

Containers should:

- run non-root where possible;
- use read-only root filesystem where possible;
- drop unnecessary Linux capabilities;
- avoid privileged mode;
- use seccomp/runtime restrictions where supported;
- have CPU/memory/temp-storage limits;
- have explicit health/readiness checks;
- contain no baked secrets;
- use immutable image digests;
- use minimal runtime images.

High-risk parsers receive stricter isolation.

## Web/control load balancing

Regional control plane:

```text
Internet
  -> Route 53
  -> public ALB
  -> AWS WAF
  -> regional frontend / Control Backend targets
```

ALB terminates HTTPS with ACM-managed certificates and modern security policy.

Only trusted ALB/proxy headers are used for client IP/scheme information.

Direct access to backend target ports from the Internet is denied.

## SMTP load balancing

Baseline public SMTP uses normal MX/DNS directly to commissioned Postfix node identities.

This preserves:

- direct SMTP semantics;
- stable node identity;
- source IP visibility;
- simple PTR/reputation ownership.

A Network Load Balancer is optional, not the default.

If NLB is introduced for SMTP, validate:

- original client IP preservation;
- IPv4/IPv6 behavior;
- health checks;
- STARTTLS transparency;
- timeout behavior;
- proxy protocol if selected;
- RBL/rate-limit visibility;
- queue/failure semantics.

Do not place SMTP behind an HTTP/Application Load Balancer.

## Outbound SMTP

Outbound Postfix nodes send using stable commissioned public EIPs.

Do not SNAT all outbound mail through one generic NAT Gateway if individual MTA reputation/PTR identity is required.

## Internal load balancing/service discovery

Use private service discovery/private load balancing only where multiple targets genuinely require it.

Do not add an internal load balancer between every logical module.

Mail Core/scanners may use direct/private service discovery according to final topology.

Deep AI uses a private authenticated endpoint; its load-balancing choice depends on serving/mTLS requirements.

## Firewall model

### Security Groups

AWS Security Groups are the primary stateful workload firewall.

Rules should prefer SG-to-SG references instead of broad CIDRs inside the VPC.

Default pattern:

- deny by absence;
- explicitly allow required source SG -> target port;
- separate public edge, app, scanner, data, secrets, AI and management groups.

### Network ACLs

NACLs are coarse subnet-level guardrails, not the primary per-service authorization mechanism.

Keep them understandable; do not duplicate every SG rule into brittle NACL complexity.

### AWS Network Firewall

Introduce only when requirements justify centralized egress/inspection controls.

It is not required simply because the product is a security product.

## Public port baseline

### Control plane

- TCP 443 public -> ALB.
- TCP 80 may exist only to redirect to HTTPS if deliberately enabled; otherwise closed.

### Inbound MX

- TCP 25 public -> commissioned inbound Postfix nodes.

### Customer outbound relay

Supported submission ports are explicitly configured based on connector model.

Baseline candidates:

- TCP 25 from allowlisted/trusted customer sources where appropriate;
- TCP 587 for authenticated/authorized submission if product design enables it.

Do not expose arbitrary alternate SMTP ports.

TCP 465 is not enabled by default unless a defined customer requirement exists.

### Administration

- TCP 22 SSH is not publicly open.
- Use AWS Systems Manager Session Manager/controlled break-glass paths.

## Private service ports

PostgreSQL, Redis/Valkey, OpenBao, ZITADEL internals, scanner APIs, AI APIs, metrics and management ports are private and restricted by Security Group.

Do not document a private port as "safe" merely because it is in a VPC.

## Port registry

Maintain an authoritative port/service registry with:

- protocol;
- port;
- source;
- destination;
- public/private;
- TLS/mTLS;
- authentication;
- owner;
- justification.

Opening a new port requires architecture/security review.

## Database/cache

- no public RDS;
- no public Redis/Valkey;
- TLS where supported/required;
- SG access only from authorized workloads;
- separate migration/maintenance access.

## Secrets/identity

OpenBao administrative/service ports are private.

Identity public endpoints expose only what OIDC/admin UX requires; management/internal endpoints remain restricted.

## Scanner egress

Default deny unnecessary scanner egress.

URL/reputation scanner egress is explicit through controlled policy/proxy/NAT and includes SSRF protections.

Document/OCR/malware parsers normally do not need general Internet access.

## Metadata service

EC2 workloads require IMDSv2 and controls preventing untrusted scanner/fetcher content from reaching instance metadata.

Container/task credentials remain workload-scoped.

## Egress

Prefer VPC endpoints/private paths for AWS services such as S3 where practical.

NAT/Internet egress is granted by workload need, not by subnet convenience.

Monitor unexpected egress.

## Load-balancer/WAF limits

Control plane uses:

- request/body size limits;
- connection/request timeouts appropriate to endpoint;
- rate/abuse rules;
- TLS policy;
- health checks.

Do not allow WAF/ALB settings to become the only application rate-limiting/security layer.

## Health checks

Health endpoints:

- do not expose secrets/config internals;
- distinguish liveness/readiness where needed;
- are restricted if detailed;
- do not report healthy if critical dependencies make the service unsafe to receive work.

## Patch/drain lifecycle

Container/platform patching follows `docs/security/23-PATCHING-DEPENDENCY-VERSIONS.md`.

Mail-node patching drains safely and preserves Postfix queue responsibility.

## AI-agent rules

AI agents must not:

- open `0.0.0.0/0` ports without explicit public-edge requirement;
- expose databases/caches/secrets/AI directly to the Internet;
- add SSH because it is convenient;
- introduce EKS/Kubernetes without architecture approval;
- place SMTP behind ALB;
- route outbound SMTP through generic NAT if it breaks EIP/PTR identity;
- give scanner containers unrestricted egress by default.

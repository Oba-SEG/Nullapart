# AWS Regional Deployment Topology

**Status:** proposed topology; exact AWS instance/service sizing remains to be benchmarked.

## Deployment unit

A Nullapart deployment is a complete regional security boundary.

Examples:

- `ZA` — South Africa primary;
- `ZAB` — South Africa deployment B;
- `EU`;
- `UK`;
- `US`.

A new deployment is introduced when an existing deployment reaches defined capacity/operational limits, not as casual application sharding.

## Canonical domains

Primary product domain:

- `nullapart.com`

Additional protected domains:

- `nullapart.io`
- `nullapart.co`
- `nullapart.co.za`

Route 53 should manage production DNS as infrastructure code.

## Suggested DNS naming

Control:

- `za.nullapart.com`;
- `zab.nullapart.com`;
- `eu.nullapart.com`;
- `uk.nullapart.com`;
- `us.nullapart.com`.

Mail:

- `mx1.za.nullapart.com`;
- `mx2.za.nullapart.com`;
- `relay1.za.nullapart.com`;
- corresponding names for other deployments.

DMARC reporting:

- `dmarc.za.nullapart.com`;
- `dmarc.zab.nullapart.com`.

Deep AI internal service names should remain private DNS.

## AWS account/network design

Prefer strong regional/deployment isolation.

At minimum use:

- VPC;
- public subnets only for required SMTP/web ingress;
- private application/scanner subnets;
- private database/cache subnets;
- restrictive security groups;
- VPC endpoints for S3 and relevant AWS APIs;
- no public PostgreSQL/Redis/OpenBao/AI access.

A multi-account AWS model may be considered later for stronger isolation, but deployment design should not require it to function.

## SMTP nodes

Postfix nodes require:

- stable networking;
- predictable public egress identity for outbound;
- persistent mail queues;
- regional DNS/PTR planning;
- clear separation of inbound/outbound roles where beneficial.

Internet-facing outbound SMTP nodes require stable public IP identity because HELO/PTR/reputation are tied to those addresses.

AWS blocks public outbound port 25 from EC2 by default unless the restriction is removed. Every direct-to-MX deployment therefore requires an explicit commissioning process for port-25 approval, Elastic IP/public identity, forward DNS, PTR/rDNS, HELO, authentication and reputation warm-up.

See [AWS SMTP Deployment Commissioning](21-AWS-SMTP-COMMISSIONING.md).

## Node identity

Every mail/scanner runtime is identifiable, but application identity must not depend solely on an IP address.

Record:

- stable/logical node ID;
- numbered hostname;
- region/deployment;
- role;
- AWS instance/task/pod identity;
- current IP address;
- release/config revision.

Private IPs may be ephemeral in ECS/EKS-style environments. They remain useful observations but are not the canonical service identity.

Internet-facing SMTP egress IPs are a special case and require stable public identity.

## Application containers

Containers may run on EC2/ECS/EKS according to operational needs.

Do not force all workloads into one orchestration technology before benchmarking.

Rust Mail Core and scanners should remain portable containers.

## Databases

Preferred production baseline:

- PostgreSQL-compatible managed AWS service where operationally appropriate;
- Redis/Valkey-compatible managed service where operationally appropriate for cache/counters.

Open-source protocol/application compatibility remains important even when AWS hosts the service.

Critical asynchronous events use the durable event architecture described in [Durable Event Architecture](20-EVENT-DURABILITY.md), with PostgreSQL transactional outbox + SQS as the preferred baseline.

## S3

Use regional buckets/partitioning with:

- Block Public Access;
- KMS encryption;
- VPC endpoints;
- lifecycle policy;
- strict role access;
- Object Lock where immutable audit retention is required;
- no cross-region replication by default.

## Deep AI

Deep AI runs on regional AWS accelerated-compute capacity under Nullapart control.

Potential architecture:

```text
Mail/Control security event
   -> authenticated internal inference endpoint
   -> vLLM-compatible model server
   -> regional accelerated-compute node(s)
   -> Qwen3.8-27B candidate or validated replacement
```

AI servers have scoped access to eligible security artifacts only.

Do not assume instance-family availability is uniform across regions. `af-south-1` has a narrower accelerated-compute selection than major US/EU regions, so ZA requires its own inference capacity/quantization/concurrency benchmark before the 27B candidate is approved for production.

The OpenAI-compatible API contract is deliberately model/backend independent so a region can use a different validated model configuration if necessary.

## Identity and secrets

- ZITADEL is the leading regional identity candidate, subject to licensing/security validation.
- OpenBao is the leading regional secrets/workload-PKI candidate.
- AWS IAM roles are used for AWS resource access.
- AWS KMS is used for regional key/encryption needs where appropriate.

OpenBao must be deployed for HA rather than as a single-node dependency. Bootstrap/unseal/recovery/backup design must be documented before production; KMS-backed automated unseal/recovery mechanisms should be evaluated for AWS deployments.

## Observability

Application observability uses Sentry-compatible SDK instrumentation routed to the deployment's regional SegLumberjack instance/service.

CloudWatch remains separate and complementary for AWS infrastructure and managed-service telemetry.

Native daemons such as Postfix, Rspamd and ClamAV do not naturally emit Sentry envelopes. Their logs/metrics require an explicit regional collector pipeline (for example Vector, Fluent Bit or an OpenTelemetry-compatible collector) that performs parsing, enrichment/redaction and routes appropriate application diagnostics to SegLumberjack while AWS infrastructure telemetry remains in CloudWatch.

```text
Application SDKs
  -> Sentry-compatible protocol
  -> SegLumberjack

Postfix / Rspamd / ClamAV native telemetry
  -> regional log/metrics collector
  -> sanitized/enriched observability path

AWS infrastructure / managed services
  -> CloudWatch
```

SegLumberjack must receive deployment/node/release/trace context while message content and secrets are scrubbed before ingestion.

Both SegLumberjack and CloudWatch placement/retention must respect regional data rules.

## Alternate product domains

`nullapart.io`, `nullapart.co`, and `nullapart.co.za` should be provisioned deliberately:

- valid TLS certificates;
- HTTPS redirect to canonical product destinations unless assigned another explicit purpose;
- no accidental secondary authentication realm;
- monitored certificate/DNS expiry;
- DNSSEC where supported/selected;
- restrictive CAA;
- restrictive SPF/DMARC for domains not used to send mail;
- Null MX for domains/subdomains that intentionally must not receive email.

## Deployment diagram

See [Regional AWS Topology](diagrams/03-regional-aws-topology.mmd).

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

Every node receives a unique hostname and IP identity.

## Application containers

Containers may run on EC2/ECS/EKS according to operational needs.

Do not force all workloads into one orchestration technology before benchmarking.

Rust Mail Core and scanners should remain portable containers.

## Databases

Preferred production baseline:

- PostgreSQL-compatible managed AWS service where operationally appropriate;
- Redis-compatible managed service where operationally appropriate.

Open-source protocol/application compatibility remains important even when AWS hosts the service.

## S3

Use regional buckets/partitioning with:

- Block Public Access;
- KMS encryption;
- VPC endpoints;
- lifecycle policy;
- strict role access;
- no cross-region replication by default.

## Deep AI

Deep AI runs on regional AWS GPU capacity under Nullapart control.

Potential architecture:

```text
Mail/Control security event
   -> authenticated internal inference endpoint
   -> vLLM-compatible model server
   -> regional GPU node(s)
   -> Qwen3.8-27B candidate
```

AI servers have scoped access to eligible security artifacts only.

## Identity and secrets

- ZITADEL deployed regionally.
- OpenBao deployed regionally.
- AWS IAM roles used for AWS resource access.
- AWS KMS used for regional key/encryption needs where appropriate.

## Observability

Sentry routing and SegLumberjack/CloudWatch logging must respect the deployment's regional data rules.

## Alternate product domains

`nullapart.io`, `nullapart.co`, and `nullapart.co.za` should be provisioned deliberately:

- valid TLS certificates;
- restrictive DNS/mail posture;
- HTTPS redirect to canonical product destinations unless assigned another explicit purpose;
- no accidental secondary authentication realm;
- monitored certificate/DNS expiry.
## Deployment diagram

See [Regional AWS Topology](diagrams/03-regional-aws-topology.mmd).


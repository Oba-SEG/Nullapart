# AWS Infrastructure

Infrastructure-as-code for regional Nullapart deployments.

Phase 0/1 AWS and SMTP commissioning conformance is tracked in
[docs/reviews/2026-10-13-phase-0-1-conformance.md](../../docs/reviews/2026-10-13-phase-0-1-conformance.md).
This directory contains implementation structure; it is not itself proof that
the AWS production gate has been commissioned.

Primary domain: `nullapart.com`.
Additional protected domains: `nullapart.io`, `nullapart.co`, `nullapart.co.za`.

## Baseline

- Route 53 for regional/product DNS;
- public ALB + WAF for Control Plane HTTPS;
- direct commissioned Postfix MX/public mail identities as the SMTP baseline;
- Amazon ECS for ordinary application/container orchestration;
- Fargate and/or ECS EC2 capacity providers selected by workload;
- dedicated mail EC2 nodes where stable SMTP identity/durable spool requires it;
- private PostgreSQL/RDS;
- private Redis/Valkey;
- S3 + KMS;
- SQS;
- OpenBao/ZITADEL/SegLumberjack according to regional deployment design;
- CloudWatch infrastructure telemetry;
- Systems Manager rather than public SSH.

See:

- `docs/15-AWS-DEPLOYMENT.md`
- `docs/24-CONTAINER-LOADBALANCING-NETWORK.md`
- `infrastructure/aws/PORTS.md`

IaC must not create a public database/cache/secrets/AI endpoint.

# Nullapart Security Requirements

These rules apply to architecture, implementation, operations, UI and testing.

## Security-first engineering

Nullapart is a security product. Every feature is designed with explicit trust boundaries, least privilege, auditable administration, secure failure behaviour and regional data handling from the beginning.

## Authentication

- Every network-accessible HTTP/API call must be authenticated unless the protocol requires another trust mechanism.
- SMTP endpoints use SMTP/TLS/source/connector controls rather than web API authentication.
- Internal services must not share one platform-wide static secret.
- Each service/node receives an independent workload identity.
- Short-lived certificates or credentials are preferred.
- Management, metrics, health-detail and debug endpoints must not be publicly reachable.
- Public customer API access is not part of the initial product.

## Authorization

Authorization is enforced server-side.

Administrative levels:

- System Admin.
- Support.
- Customer Admin.

Customer RBAC may further restrict message content, headers, attachments, quarantine release and remediation.

## Impersonation

System and Support administrators authenticate as themselves before impersonating a Customer Admin.

Every impersonated action retains:

- real actor identity;
- impersonated subject;
- customer ID;
- role;
- reason;
- session start/end;
- action history.

## Sensitive message content

System Admin may access complete message detail where required.

Support may access operational metadata, routing, scanner outcomes, policy decisions and transmission traces but must not receive message body/attachment content.

Customer Admin content access is controlled by customer RBAC.

## Secrets

Never store secrets in source code, Git, Docker images or frontend bundles.

Preferred design:

- OpenBao for open-source secrets/workload PKI;
- AWS KMS/Secrets Manager where managed AWS functionality is the safer or necessary option;
- short-lived workload certificates;
- per-service credentials;
- automatic rotation;
- scoped IAM roles.

## Regional data handling

Each tenant belongs to one region/deployment.

Customer mail content and associated security records remain in that deployment unless an explicitly approved integration is permitted to receive a defined data class.

Third-party or externally hosted services such as ClickUp, threat intelligence and AI are treated as potential data-export paths. SegLumberjack is intended to be deployed/operated as the regional application observability backend; any deployment topology that would export customer telemetry outside the allowed region must be reviewed explicitly.

## Observability and logging

Nullapart applications use **Sentry-compatible SDK instrumentation** as the standard application telemetry interface.

The normal telemetry path is:

```text
Nullapart application
  -> Sentry SDK / Sentry-compatible protocol
  -> regional SegLumberjack
```

SegLumberjack is the primary regional application observability platform for application errors, exceptions, traces/performance telemetry where supported, release context and service/node correlation.

The architecture does **not** require a separate hosted Sentry service. "Sentry" in implementation guidance refers to the SDK/protocol standard unless a separate service is explicitly approved.

AWS CloudWatch is complementary and is used primarily for AWS infrastructure and managed-service telemetry such as EC2/ECS, load balancers, RDS, cache, network, platform metrics and AWS alarms. CloudWatch is not a substitute for the SegLumberjack application-observability role.

Application telemetry should include region, deployment, node ID, hostname, node IP, service, release, trace ID, Nullapart message ID, customer ID, actor identity when administrative, event/reason code and timing where applicable.

Before telemetry leaves the application process, scrub message bodies, raw MIME, attachment content, passwords, tokens, cookies, private keys, credentials and other sensitive fields.

## Untrusted email input

Everything received from email is untrusted, including MIME, headers, URLs, filenames, HTML, documents, archives, embedded messages and text shown to AI.

Nullapart generates its own trusted authentication results.

Prompt text inside email is data, never AI instructions.

## Open-source dependencies

Every dependency requires pinned versions, license review, SBOM inclusion, security-advisory monitoring, provenance/source records and an upgrade strategy.

## Build completion

A security-sensitive feature is not complete until authorization, audit, UI states, tests, logging, failure behaviour and operational visibility are complete too.

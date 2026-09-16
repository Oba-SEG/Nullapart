# Observability

Nullapart uses complementary telemetry paths.

## Application observability

Application components use Sentry-compatible SDKs/protocols and send sanitized telemetry to **regional SegLumberjack**.

SegLumberjack is the primary application observability backend for:

- application errors/exceptions;
- release/service/node correlation;
- traces/performance telemetry where supported;
- frontend/backend/scanner/worker diagnostics.

A separate hosted Sentry service is not required by the architecture. "Sentry" refers to the instrumentation/protocol standard unless explicitly stated otherwise.

## Native daemon telemetry

Postfix, Rspamd, ClamAV and similar daemons require a regional collector path because they do not naturally emit Sentry-compatible application events.

The eventual infrastructure here should include a collector such as Vector, Fluent Bit or an OpenTelemetry-compatible collector that can:

- parse syslog/native logs;
- add region/deployment/node/release context;
- redact customer content/secrets;
- preserve safe queue/transaction correlation identifiers;
- route appropriate application diagnostics toward SegLumberjack;
- coexist with CloudWatch infrastructure telemetry.

## AWS infrastructure telemetry

**CloudWatch** is used separately for AWS infrastructure and managed-service telemetry such as EC2/ECS, load balancers, RDS, cache, S3, VPC/network and AWS alarms.

CloudWatch does not replace SegLumberjack's application-observability role.

## Authoritative records

Security audit records and product events remain authoritative in Nullapart databases/outbox/event stores. Observability systems are diagnostic, not the sole audit trail or durable event bus.

## Data handling

Message content, raw MIME, attachments, credentials and secrets must be scrubbed before application/native-daemon telemetry reaches SegLumberjack.

See:

- `SECURITY.md`
- `docs/11-OBSERVABILITY-SECRETS.md`
- `docs/20-EVENT-DURABILITY.md`
- `docs/diagrams/10-observability-architecture.mmd`

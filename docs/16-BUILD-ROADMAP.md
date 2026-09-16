# Nullapart Build Roadmap

The roadmap is architectural sequencing, not a delivery-date promise.

## Phase -1 — security program gate

**No Phase 0 implementation starts until this gate is accepted.**

Required before implementation:

- security governance and named ownership;
- threat-modeling process;
- secure SDLC/change-control rules;
- vulnerability-management process and remediation SLAs;
- incident-response process;
- privileged-access governance;
- data-classification matrix;
- privacy/retention/deletion policy;
- cryptographic standards;
- network-security baseline;
- backup/restore/DR policy and restore-test plan;
- software supply-chain controls;
- penetration/security-testing strategy;
- abuse/misuse response;
- third-party risk process;
- security-exception process;
- mail trust/failure model;
- required security runbooks;
- security metrics/control-health requirements.

See [Security Program](security/README.md).

Phase -1 completion means the processes, ownership, evidence expectations and security gates are documented and accepted. Operational exercises such as restore tests, penetration tests and production runbook drills occur at the appropriate pre-production/production-readiness gates.

## Phase 0 — contracts, security and UI foundation

Define and test:

- regional/customer identity rules;
- authentication/RBAC/impersonation;
- MFA/step-up/session requirements;
- SMTP Transaction + Tenant Message Instance contract;
- SecurityFinding contract and scope;
- scanner contract;
- policy/config revision model;
- SMTP reason catalogue;
- durable event contract;
- PostgreSQL transactional outbox contract;
- SQS consumer/idempotency/DLQ contract;
- ArtifactStore contract;
- Admin Audit event/storage/query contract;
- transactional audit + mutation semantics;
- immutable audit-checkpoint/archive model;
- Admin Audit UI table/filter/detail design;
- secure hostile-message rendering/artifact-access contract;
- neumorphic design tokens/layout shell;
- Sentry-compatible SDK instrumentation routed to regional SegLumberjack;
- native daemon log/metrics collector path;
- CloudWatch infrastructure telemetry baseline;
- AWS SMTP commissioning checklist.

No feature is considered backend-only if it requires an administrative UI.

## Phase 1 — SMTP/mail foundation

Build:

- containerized Postfix;
- Rspamd restriction/Milter integration;
- explicit Postfix after-queue filter handoff;
- trusted reinjection listener/transport with loop prevention;
- Rust Mail Core foundation;
- inbound/outbound routing;
- durable queue semantics;
- SMTP Transaction + tenant-message recipient partitioning;
- tenant/domain/recipient resolution;
- source IP/connector authorization;
- greylisting;
- RBL/GeoIP;
- trusted auth results;
- transmission trace;
- initial policy runtime/cache;
- AWS outbound port-25/PTR/HELO commissioning for the first deployment.

Goal: a robust bidirectional SEG without advanced AI.

## Phase 2 — scanner fabric

Build the common scanner SDK/orchestrator and initial analyzers:

- malware;
- URL/domain;
- file type;
- archives;
- PDF;
- Office;
- OCR/QR/image;
- static/YARA.

Add:

- parser/container isolation;
- hard CPU/memory/time/decompression/nesting limits;
- encrypted/unscannable content handling;
- quarantine/hold;
- UI at the same time.

## Phase 3 — control plane

Build:

- ZITADEL integration after security/license validation;
- System/Support/Customer Admin RBAC;
- MFA and step-up controls;
- impersonation;
- customers;
- domains;
- source groups;
- policy management;
- runtime cache visibility/refresh;
- tenant lifecycle;
- node/scanner health;
- stable node identity plus runtime IP/AWS identity;
- full trace/message permission model;
- secure sanitized message/full-content view;
- append-only Admin Audit store, RBAC queries and UI;
- immutable audit checkpoint/archive job.

## Phase 4 — inline ML

Build:

- training/evaluation pipeline;
- compact encoder;
- ONNX/runtime integration;
- calibrated outputs;
- model registry/version reporting;
- feedback candidate workflow.

## Phase 5 — DMARC/BIMI

Build:

- RFC 9989/9990/9991-aware report ingestion;
- external report-destination authorization automation/validation;
- parser hardening;
- aggregate vs failure-report privacy controls;
- authentication source inventory;
- dashboards;
- DNS/domain observation;
- BIMI enforcement/readiness validation;
- secure BIMI SVG handling;
- MTA-STS/TLS-RPT views;
- alerts.

## Phase 6 — outbound intelligence

Build:

- rolling sender/tenant counters;
- approved bulk sender policy;
- campaign/fuzzy signals;
- recipient fanout;
- compromised sender detection;
- throttle/defer/block/hold actions;
- live dashboards/notifications.

## Phase 7 — Deep AI

Deploy regional inference and integrate:

- Qwen3.8-27B candidate or validated replacement;
- per-region capacity/quantization/concurrency benchmarks;
- authenticated OpenAI-compatible endpoint;
- scoped artifact-access broker;
- quarantined/blocked/reported analysis;
- complex BEC/impersonation;
- deep-analysis hold policy;
- analyst summaries;
- prompt-injection/tool restrictions;
- AI audit/retention/security controls.

## Phase 8 — connectors/remediation

Implement as required:

- Microsoft 365;
- Google Workspace;
- directory sync;
- VIP enrichment;
- mailbox search;
- retro remediation;
- IMAP/POP only if platform-enabled.

## Phase 9 — operational automation

Expand PostgreSQL outbox + SQS durable events, n8n and ClickUp workflows for incidents, outages, remediation, DMARC degradation and support operations.

## Continuous requirements

Across every phase:

- authenticated APIs;
- per-service identity;
- MFA for all admin accounts;
- Sentry-compatible instrumentation routed to SegLumberjack;
- native daemon telemetry collection;
- CloudWatch for AWS infrastructure telemetry;
- first-class Admin Audit subsystem and UI;
- transactional outbox + explicitly durable async delivery;
- regional isolation;
- UI with feature;
- secure hostile-content rendering where message content is displayed;
- tests with feature;
- no raw JSON UI;
- open-source/security/license review;
- dependency/SBOM management.

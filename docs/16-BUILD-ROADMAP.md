# Nullapart Build Roadmap

The roadmap is architectural sequencing, not a delivery-date promise.

## Phase 0 — contracts, security and UI foundation

Define and test:

- regional/customer identity rules;
- authentication/RBAC/impersonation;
- canonical message record;
- SecurityFinding contract;
- scanner contract;
- policy/config revision model;
- SMTP reason catalogue;
- event contract;
- ArtifactStore contract;
- audit contract;
- neumorphic design tokens/layout shell;
- Sentry/logging baseline.

No feature is considered backend-only if it requires an administrative UI.

## Phase 1 — SMTP/mail foundation

Build:

- containerized Postfix;
- Rspamd restriction/Milter integration;
- Rust Mail Core foundation;
- inbound/outbound routing;
- durable queue semantics;
- tenant/domain/recipient resolution;
- source IP/connector authorization;
- greylisting;
- RBL/GeoIP;
- trusted auth results;
- transmission trace;
- initial policy runtime/cache.

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

Add quarantine/hold and UI at the same time.

## Phase 3 — control plane

Build:

- ZITADEL integration;
- System/Support/Customer Admin RBAC;
- impersonation;
- customers;
- domains;
- source groups;
- policy management;
- runtime cache visibility/refresh;
- tenant lifecycle;
- node/scanner health;
- full trace/message permission model.

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

- report ingestion;
- parser hardening;
- authentication source inventory;
- dashboards;
- DNS/domain observation;
- BIMI;
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

- Qwen3.8-27B candidate;
- authenticated OpenAI-compatible endpoint;
- quarantined/blocked/reported analysis;
- complex BEC/impersonation;
- deep-analysis hold policy;
- analyst summaries;
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

Expand durable events, n8n and ClickUp workflows for incidents, outages, remediation, DMARC degradation and support operations.

## Continuous requirements

Across every phase:

- authenticated APIs;
- per-service identity;
- Sentry-compatible instrumentation routed to SegLumberjack;
- CloudWatch for AWS infrastructure telemetry;
- audit;
- regional isolation;
- UI with feature;
- tests with feature;
- no raw JSON UI;
- open-source/security review;
- dependency/SBOM management.

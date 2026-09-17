# Phase 1 Postfix Implementation Contract

This directory owns the Postfix configuration needed for Phase 1.

## Responsibilities

Postfix owns:

- Internet SMTP protocol handling;
- STARTTLS;
- relay restrictions;
- durable queue responsibility;
- SMTP-time restrictions/rate controls;
- after-queue handoff to Mail Core;
- trusted private reinjection;
- outbound SMTP delivery/retry/DSN semantics.

Postfix does **not** own:

- tenant-specific final security policy;
- slow document/OCR/Deep-AI analysis;
- customer RBAC;
- Admin Audit business logic.

## Required listeners

### Public inbound SMTP

- TCP 25;
- Internet-facing only on commissioned inbound nodes;
- no relay except intended local/tenant recipient domains;
- bounded SMTP restriction/Rspamd path;
- durable queue before heavy processing.

### Trusted reinjection

- private only;
- restricted to Mail Core/workload identity/network boundary;
- preserves required envelope/DSN metadata;
- loop-prevention marker/configuration;
- does not re-enter the same content-filter path.

### Outbound/relay

Only enabled on nodes/roles intended for outbound mail.

- trusted customer/source intake only;
- no open relay;
- downstream delivery uses stable commissioned public identity;
- delivery attempts correlate to Tenant Message Instance.

## Configuration structure

Phase 1 implementation should keep:

- base defaults;
- inbound role;
- outbound role;
- reinjection role;
- deployment-specific generated values

separate enough to review and test without creating duplicated full Postfix configurations.

Secrets/keys are not committed.

## Phase 1 tests

At minimum:

- open relay denied;
- unknown recipient/domain behavior;
- TLS negotiation;
- resource limits;
- Mail Core unavailable after acceptance;
- queue survives restart;
- reinjection authorization;
- reinjection loop prevention;
- downstream 4xx retry;
- downstream 5xx final handling;
- DNS failure;
- source-IP/rate controls.

See `docs/phases/PHASE-1-EXECUTION-PLAN.md`.

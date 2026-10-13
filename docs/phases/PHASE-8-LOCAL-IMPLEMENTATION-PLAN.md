# Phase 8 Local Implementation Plan — Connectors and Remediation

Status: complete for local/dev Phase 8 scope.

This plan maps `docs/phases/PHASE-8-CONNECTORS-REMEDIATION.md` to the local/dev
implementation. Phase 8 creates the tenant-safe connector control plane and
post-delivery remediation request ledger. It does not execute live Microsoft
365 or Google Workspace side effects from the Control Plane.

## Implemented scope

- [x] Tenant-scoped connector schema:
  - migration `031_connectors_remediation.sql`;
  - `connector_integrations`;
  - `connector_capability_grants`;
  - `connector_directory_sync_runs`;
  - `connector_mailbox_searches`;
  - `connector_remediation_actions`;
  - PostgreSQL RLS enabled and forced for every Phase 8 table.
- [x] Explicit capability model:
  - directory sync;
  - mailbox search;
  - retro remediation;
  - capabilities are independently grantable and audited.
- [x] Least-privilege provider scope validation:
  - Microsoft 365 and Google Workspace allowed scopes are capability-specific;
  - directory-only setup cannot carry mailbox or remediation scopes;
  - IMAP/POP remains disabled by default in the Control Plane.
- [x] Authenticated Control Plane API:
  - `GET /api/v1/connectors-remediation`;
  - `POST /api/v1/connectors-remediation/connectors`;
  - `POST /api/v1/connectors-remediation/remediations`;
  - permissions `connectors:view` and `connectors:manage`.
- [x] High-risk mutation controls:
  - connector and remediation writes require step-up authentication;
  - idempotency key required;
  - administrative audit records written in the same transaction.
- [x] Post-delivery remediation truthfulness:
  - remediation requests must reference a tenant-scoped delivered message;
  - the original message history is not rewritten;
  - provider side effects are explicitly recorded as
    `not_executed_in_control_plane` in the local/dev API response.
- [x] UI:
  - `/connectors-remediation`;
  - connector status, capability cards, auth state, expiry, directory sync
    status, mailbox search records, remediation action history, setup form and
    remediation request form;
  - no raw provider tokens or raw JSON UI.
- [x] Tests:
  - Rust unit tests for unauthenticated access, over-scoped capability
    rejection, independent capability acceptance and remediation validation;
  - ignored PostgreSQL test for fail-closed RLS and tenant isolation;
  - frontend tests for rendering, connector mutation controls and remediation
    request submission.

## Non-goals preserved

- No generic integration marketplace.
- No public customer connector API.
- No arbitrary third-party workflow execution.
- No provider refresh/access tokens accepted by or projected from the API/UI.
- No autonomous mailbox side effects from the Control Plane.

## Evidence to keep current

- Local:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `pnpm --dir frontend check-all`
- Remote `.4`:
  - `SSHPASS=1234 scripts/phase8_remote_verify.sh`
  - script applies migration `031_connectors_remediation.sql`, rebuilds and
    recreates Mail Core, runs `postgres_connectors_remediation` against the
    tunneled remote DB, checks the authenticated connector projection, exercises
    the CSRF/idempotency-protected connector upsert API and records an audited
    pending remediation request for a tenant-scoped delivered message fixture.

## Evidence log

- Local verification after the Phase 8 implementation:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `pnpm --dir frontend check-all`
- Remote `192.168.8.4` verification:
  - `SSHPASS=1234 scripts/phase8_remote_verify.sh`
  - Mail Core and frontend images rebuilt on `ob1@192.168.8.4`;
  - migration `031_connectors_remediation.sql` present on the remote database;
  - ignored `postgres_connectors_remediation` suite passed against the tunneled
    remote PostgreSQL database;
  - authenticated `/api/v1/connectors-remediation` projection returned;
  - CSRF/idempotency-protected Microsoft 365 connector upsert succeeded;
  - CSRF/idempotency-protected remediation request for a delivered
    tenant-scoped message returned
    `provider_side_effect = not_executed_in_control_plane`.
  - `/connectors-remediation` returned the built SPA through the remote
    basic-auth frontend container.
- Defect fixed during remote verification:
  - the API now accepts and serializes the canonical provider spelling
    `microsoft_365`, matching the database/UI contract rather than accepting
    the accidental Serde default `microsoft365`.

## Follow-up before production

- Add provider workers for Microsoft 365 and Google Workspace that perform
  directory sync, mailbox search and retro remediation using regional encrypted
  secret storage.
- Add provider token rotation/revocation health checks and alerting.
- Add customer notification workers for remediation failures and manual action
  required states.
- Extend Phase 9 observability for connector outage, stale directory sync,
  provider throttling, expired credentials and remediation failure SLOs.

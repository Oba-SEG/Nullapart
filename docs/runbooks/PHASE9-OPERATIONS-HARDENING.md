# Phase 9 Operations Hardening Runbook

Status: local/dev operational runbook. Production execution requires attached
environment-specific evidence and owner approval.

## Purpose

Use this runbook when the Phase 9 operations dashboard shows degraded Tier-3
readiness, burn-rate alert definitions that are not enabled, stale operational
evidence, outbox/DLQ backlog or a production-readiness gate that is not ready.

## First response

1. Confirm the deployment and region shown by the Control Plane.
2. Check `/operations` for runtime queue/config/node state.
3. Check the Phase 9 hardening sections:
   - Tier-3 SLO capabilities;
   - burn-rate alert definitions;
   - durable automation categories;
   - production-readiness evidence.
4. Open the referenced evidence path for the failing row.
5. Do not mark a readiness check as ready unless there is current evidence for
   that exact deployment.

## Burn-rate alerts

Phase 9 uses the baseline multi-window pattern from
`docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`:

- fast page: 14.4x burn on both 1h and 5m windows;
- sustained page: 6x burn on both 6h and 30m windows;
- slow-burn ticket: calibrated low burn, seeded locally as 1x over a multi-day
  window.

If a burn alert fires:

1. Identify the capability and SLO.
2. Check the current error-budget remaining and windows breached.
3. Follow the capability-specific degraded-mode behaviour.
4. Halt risky rollout work until the burn source is understood.
5. Prefer rollback/kill-switch/backpressure before unsafe overload.
6. Record the incident and update the evidence register after resolution.

## Durable automation

Phase 9 automation is driven from the durable outbox/SQS/worker path. n8n,
ClickUp, customer notifications and reports must remain asynchronous and
non-critical to mail delivery.

Before marking an automation category ready:

1. Confirm the category emits minimized metadata only.
2. Confirm the deduplication key and aggregation window prevent task storms.
3. Confirm workflow failure cannot block SMTP acceptance or required scanner
   handling.
4. Confirm retries are idempotent and auditable.
5. Exercise the destination workflow in local/dev and attach production evidence
   before production sign-off.

## Production-readiness evidence

Before a production deployment can be signed off, attach evidence for:

- live protected source workflow and CI/security gates;
- active SLO/burn-rate monitoring;
- immutable audit checkpoints/archive path;
- restore/DR exercises;
- zero-day parser/dependency exercise;
- firewall/port/load-balancer validation;
- support diagnostics that preserve message-content boundaries.

The local/dev dashboard may show some rows as `ready` or `partial`, but that is
not production approval. Production approval requires deployment-specific
records in `docs/compliance/` or the approved evidence system.

## Safety boundaries

- Do not weaken SLO, alert or readiness thresholds to make the page look green.
- Do not remove failures from SLIs without documented review.
- Do not auto-remediate production infrastructure without an approved workflow.
- Do not modify production secrets directly.
- Do not bypass branch protection, review or CI for emergency work.
- Do not use message body/raw MIME/attachments for support diagnosis unless an
  explicitly authorized content-access path grants it.

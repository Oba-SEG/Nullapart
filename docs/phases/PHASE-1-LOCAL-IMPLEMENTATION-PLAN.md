# Phase 1 Local Implementation Plan

**Status:** Phase 1 local hardening and verification sequence. This does not
authorize AWS commissioning or a production deployment, and does not expand
the current project scope into later phases.

**Conformance review:** [2026-10-13 Phase 0/1 Authoritative Conformance Review](../reviews/2026-10-13-phase-0-1-conformance.md).
Use that review to distinguish local/dev evidence from open production/AWS
Phase 1 gates.

## Exit target

One locally submitted SMTP message is durably accepted by Postfix, processed by
Mail Core, partitioned by tenant, policy-evaluated, reinjected through the
private listener, and represented in a tenant-safe trace. Dependency failure
and retry behavior are proven locally.

## Ordered work

1. **Durable state and test harness**
   - Run PostgreSQL and Redis through `compose.local.yml`.
   - Apply Phase 0 and handoff-idempotency migrations.
   - Test concurrent/repeated handoff creation against PostgreSQL.
   - Replace the process-local handoff store in the local Mail Core runtime.

2. **Mail Core runtime**
   - Add explicit startup configuration for deployment, bounded HMAC key ring,
     PostgreSQL pool, and local listener.
   - Reject startup without workload keys or durable idempotency storage.
   - Add liveness/readiness semantics that do not expose operational detail.

3. **Postfix integration**
   - Implement the `mailcore-filter` executable/adapter invoked by Postfix.
   - Preserve envelope, ORCPT/NOTIFY, queue ID, and trace metadata.
   - Sign handoffs and map failure to a Postfix retry, never discard accepted
     mail.
   - Implement the private reinjection client and confirm it bypasses the
     content filter.

4. **Trusted evidence and policy**
   - Convert Rspamd output into validated internal observations.
   - Record unavailable/timeout as explicit UNKNOWN/ERROR evidence.
   - Connect tenant partitioning and policy evaluation to the handoff flow.

5. **Trace persistence and Control Plane boundary**
   - Persist receipt, partition, policy, reinjection, and delivery states.
   - Implement server-derived tenant/RBAC trace queries through the Control
     Plane BFF, not direct browser access to Mail Core.
   - Add the React trace and message-detail views without raw JSON or content
     leakage to Support.

6. **Local end-to-end gate**
   - Test inbound/outbound delivery, cross-tenant recipients, duplicate
     handoffs, handoff/Rspamd/reinjection outage, downstream 4xx/5xx, loop
     prevention, queue pressure, and unauthorized access attempts.
   - Record commands and evidence in the local test runbook.

## Current status as of 2026-10-13

The earlier Docker-daemon blocker is stale. Local/dev deployment and verification
evidence now exists in later local implementation plans, including Phase 2/3
SMTP handoff, quarantine release/reinjection, trace UI and Phase 9 operations
hardening evidence on `ob1@192.168.8.4`.

This does not close the production Phase 1 gate. AWS SMTP commissioning,
production-like live security/reliability tests, branch/CI evidence and the
unchecked rows in
[Phase 1 Security/Reliability Gate](../compliance/19-PHASE-1-SECURITY-RELIABILITY-GATE.md)
remain open until dated evidence is attached.

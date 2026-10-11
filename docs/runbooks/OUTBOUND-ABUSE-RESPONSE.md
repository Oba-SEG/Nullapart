# Outbound Abuse and Connector Credential Compromise Response

## Trigger

Use this runbook when Phase 6 outbound intelligence raises unauthorized bulk,
compromised-sender, source-spoofing, malware-from-bulk-sender, campaign
outbreak or delivery-failure-spike events.

## Owner and escalation

- Customer-facing triage: Support.
- Security incident lead: System/Security operator for compromised sender,
  source spoofing or malware from an approved sender.
- Customer owner: affected customer administrator.

## Containment

1. Confirm the event is tenant-scoped to the affected deployment/customer in the
   Control Plane.
2. Preserve the outbound security event, campaign fingerprint, sender/source
   identifiers and audit trail.
3. If `credential_rotation_recommended` is true, disable or revoke the affected
   connector/API credential and issue a replacement through the approved
   customer-admin workflow.
4. Hold, throttle or block the sender/source according to the event outcome and
   policy floor.
5. Do not inspect message body, raw MIME, full recipient lists or attachment
   content unless a separate content-access permission and audit path applies.

## Recovery

1. Verify customer approval or policy updates for legitimate bulk sends.
2. Re-enable only the minimum sender/source capability required.
3. Monitor outbound behaviour rollups, campaign fingerprints, bounces/failures
   and reputation signals until the event is resolved.
4. Close the event only after customer notification and credential/policy
   recovery evidence are attached to the incident record.

## Post-incident

- Review whether approved bulk limits need adjustment.
- Record customer impact and any mailbox-provider reputation action.
- Feed confirmed abuse fingerprints into campaign and policy tuning.

# Notifications and Remediation

## Notification classes

Nullapart separates:

- customer security notifications;
- platform/internal operational notifications.

## Customer contacts

Each customer holds one notification preference row (`tenant_notification_settings`, migration `042_tenant_notification_settings.sql`): a severity floor (`info`, `warning`, `critical`), a digest window in minutes (0-1440) and up to 10 recipient addresses.

`GET`/`PUT /api/v1/notifications/settings` are gated by `notifications:view` and `notifications:manage`. Scope comes from the authenticated session: no route accepts a customer id from the client, so a Customer Admin can only read or write their own tenant's settings.

Recipient addresses must belong to a domain that tenant has verified. That is a server-side refusal, not a warning: without it Nullapart would be an open relay pointed at another tenant or an arbitrary third party.

## Events

Customer notifications may include:

- post-delivery threat discovered;
- outbound spam outbreak blocked;
- unauthorized bulk sending blocked;
- compromised account suspected;
- critical malicious attachment;
- domain authentication degradation;
- DMARC attack spike;
- retroactive remediation failure;
- connector/security failure requiring customer action.

## Durable delivery of notification work

```text
domain observer -> domain_security_notifications row
  -> notification worker (crates/mail-core/src/notification_delivery.rs)
  -> outbound submission authorization + ledger
  -> trusted private Postfix intake
```

The worker is a background task inside Mail Core, not an operator action: it polls on an interval (5 minutes by default), takes a bounded batch, and mails findings at or above the tenant's severity floor. It writes no `audit_events` rows; the delivery ledger is its audit trail. Settings changes are audited separately as `notification_settings_updated`.

Idempotency is per finding. The delivery key is `notification:<domain_security_notifications.id>`, so replay cannot produce a second customer alert, and a tenant's digest window coalesces later findings of the same `(customer, notification type, domain)` into the notice already sent.

Signing availability fails closed. A tenant whose sending domain has no provisioned DKIM signer is skipped without a ledger write: a `suppressed` row would burn the finding's one-time key and permanently prevent delivery once the domain is provisioned later.

A notification failure never blocks or alters mail flow, and never silently reports success.

## Delivery ledger

Every attempt ends in exactly one `notification_deliveries` row in a final state: `sent`, `suppressed` or `dead_lettered`.

- `sent` requires a recorded `outbound_transaction_id`, enforced by a table CHECK, so nothing is reported as sent without Postfix queue acceptance;
- an ambiguous submission is resolved through the durable outbound submission ledger rather than re-sent blindly;
- `content_sha256` is stored with the row, so a retry whose rendered content changed is recorded as `content_changed_before_retry` instead of mailing a different message under the same key;
- the ledger is published beside the settings (`GET /api/v1/notifications/settings`) so "was it sent" has one answer in the console.

## Sending path

Notices are rendered by `notification_stationery` (text plus HTML, no raw MIME, no attachment) and submitted through the reviewed outbound path: `authorize_outbound_submission`, then the durable outbound submission ledger, then the private Postfix intake. Trusted loopback/internal submission only, never public MX ingress.

The envelope sender is a verified domain of the same customer, built from the configured local part (`notifications` by default), and the outbound validator re-checks that binding with the DKIM signer set. Where appropriate the sender identity is the tenant-configured postmaster/security address.

## Acknowledging a finding

`POST /api/v1/domain-security/notifications/:notification_id/acknowledge` (`domain-security:manage`) closes a finding in place: `acknowledged_by` and `acknowledged_at` are written, the row is never deleted, and the console shows acknowledged findings beside the open queue. The route is idempotent and carries an idempotency key, and the change is audited as `domain_security_notification_acknowledged`.

## Loop prevention

Nullapart-generated notification messages carry trusted internal metadata and submission context so they cannot recursively generate the same notification.

They remain subject to essential safety controls.

## Post-delivery threat

If a message was already delivered:

- delivery remains `DELIVERED`;
- security state becomes `POST_DELIVERY_THREAT`;
- customer notification is generated;
- remediation is attempted only where a connector capability permits it.

## Notification content

Include useful safe fields:

- message receipt time;
- sender;
- recipient(s) within the relevant tenant scope;
- subject;
- Nullapart tenant-message tracking ID;
- threat category;
- severity;
- normalized reason/evidence;
- remediation status;
- recommended action.

Do not attach the malicious original message.

Do not include raw MIME, attachment content, secrets or another tenant's recipients.

## Retroactive remediation

Connector capabilities are explicit:

- directory sync;
- mailbox search;
- retro remediation.

Where enabled, Nullapart may:

- find the delivered message;
- move/delete/quarantine according to provider capability;
- record every attempt/result.

No connector receives more privilege than the enabled capabilities require.

Remediation requests and results are audited.

## VIP

VIP records are manually managed initially.

Fields can include:

- display name;
- email;
- aliases;
- role;
- department;
- risk profile.

VIP context contributes to BEC/impersonation policy and analysis.

## IMAP/POP

IMAP/POP is disabled by default and requires System Admin platform enablement.

Any message/mailbox storage created by these connectors follows regional storage, encryption, retention and audit rules.

## Internal operations

Serious security/operational events flow through PostgreSQL outbox + SQS and may be consumed by n8n for ClickUp/internal workflows.

n8n/ClickUp never block mail delivery.

ClickUp receives minimized metadata and a regional Nullapart link rather than raw message content.

See [Durable Event Architecture](20-EVENT-DURABILITY.md).

# Inbound and Outbound Mail Flows

## State model

Receipt state, security state and delivery state are distinct.

A message already delivered cannot later become quarantined. A later threat changes security/remediation state.

## Inbound SMTP

```text
Internet
  |
  v
Postfix SMTP restriction stage
  |- TLS / protocol
  |- connection rate
  |- RBL/DNSBL
  |- GeoIP
  |- HELO
  |- tenant/domain/recipient
  |- greylisting
  |- early policy
  |
  v
Rspamd Milter stage
  |- reputation
  |- spam/auth signals
  |- fuzzy/campaign signals
  |
  v
Postfix durable queue
  |
  v
Rust Mail Core
  |- MIME normalization
  |- scanner orchestration
  |- inline ML
  |- policy
  |
  +--> deliver
  +--> quarantine
  +--> hold
```

## SMTP responsibility boundary

Before Postfix returns SMTP `250`, the remote sender still owns delivery responsibility.

After Nullapart returns `250`, Nullapart owns the message.

Therefore post-accept analysis does not issue a retroactive SMTP rejection. It delivers, quarantines, holds, discards under explicit policy, or generates post-delivery remediation/notification.

## Inbound states

- CONNECTING
- SMTP_EVALUATING
- REJECTED
- DEFERRED
- QUEUED
- SCANNING
- SCAN_FAILED
- POLICY_EVALUATING
- QUARANTINED
- HELD
- DELIVERY_PENDING
- DELIVERING
- DELIVERY_DEFERRED
- DELIVERY_FAILED
- DELIVERED

## Post-delivery threat

Delivery history is immutable.

A later threat can set:

- POST_DELIVERY_THREAT
- NOTIFICATION_PENDING
- CUSTOMER_NOTIFIED
- REMEDIATION_PENDING
- REMEDIATION_SUCCEEDED
- REMEDIATION_FAILED
- MANUAL_ACTION_REQUIRED

## Outbound flow

```text
Customer mail system
  |
  v
Postfix Outbound
  |- identify tenant/source
  |- validate connector/source IP
  |- validate envelope/header sender
  |- validate tenant domain type
  |- rate/bulk checks
  |- early abuse controls
  |
  v
Queue
  |
  v
Security scanning / behaviour
  |
  v
Policy
  |
  v
DKIM / transport policy
  |
  v
Direct MX or smart host
```

## Outbound domain trust

Outbound sending domains must be tenant-authorized:

- `INTERNAL` — verified customer domain, inbound/outbound.
- `SEND_ONLY` — outbound-authorized domain, Support-created only.

Trusted Microsoft/XOORG context may contribute only when received through a validated configured Microsoft connector/path. An arbitrary external `X-OriginatorOrg` header is untrusted.

## Bulk sending

Approved bulk sender addresses are explicit policy entries.

Unapproved bulk-like behaviour is detected and blocked/deferred/throttled/held according to policy.

Bulk authorization never bypasses malware or malicious-content controls.

## SMTP error catalogue

Nullapart maintains a structured SMTP response catalogue covering connection/resource, TLS, protocol, authentication, relay, recipient, tenant, greylisting, rate, reputation, GeoIP, SPF, DKIM, DMARC, size, malware, attachments, content, outbound authorization, bulk, routing, DNS, downstream SMTP and internal security pipeline failures.

Remote errors are safe and concise; internal views contain permission-controlled diagnostic detail.

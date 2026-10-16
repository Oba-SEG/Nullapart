# Inbound and Outbound Mail Flows

## State model

Receipt state, security state and delivery state are distinct.

A message already delivered cannot later become quarantined. A later threat changes security/remediation state.

One SMTP transaction may contain recipients belonging to different Nullapart customers. The canonical mail model therefore uses a parent SMTP Transaction plus one or more customer-scoped Tenant Message Instances. See [SMTP Transaction and Tenant Message Contract](18-MESSAGE-TRANSACTION-CONTRACT.md).

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
  |- bounded reputation/spam/auth analysis
  |- fuzzy/campaign signals
  |
  v
Postfix durable queue
  |
  v
After-queue content-filter handoff
  |
  v
Rust Mail Core
  |- SMTP Transaction record
  |- MIME normalization
  |- shared scanner orchestration
  |- recipient partitioning by tenant/policy
  |- inline ML
  |- tenant-specific policy
  |
  +--> trusted reinjection -> delivery
  +--> quarantine
  +--> hold
```

## SMTP-stage latency rule

Before-queue SMTP restrictions and Milter work must be bounded and suitable for an open SMTP transaction.

Do not perform arbitrary-complexity document parsing, OCR, large archive expansion, deep AI or other long-running work before SMTP acceptance unless a deliberately bounded policy requires it.

Heavy analysis occurs after durable acceptance and before customer delivery.

## SMTP responsibility boundary

Before Postfix returns SMTP `250`, the remote sender still owns delivery responsibility.

After Nullapart returns `250`, Nullapart owns the message.

Therefore post-accept analysis does not issue a retroactive SMTP rejection to the original SMTP session. It delivers, quarantines, holds, discards under explicit policy, defers internal delivery, or generates appropriate post-accept DSN/notification behaviour.

Avoid backscatter: do not blindly generate non-delivery mail to an untrusted/forged envelope sender for internal scanning failures.

## After-queue filter and reinjection

The Internet-facing Postfix instance remains the MTA and durable SMTP queue.

The implementation must define an explicit after-queue transport/filter contract:

1. Postfix durably accepts the original transaction.
2. The complete message and envelope are passed to the Rust Mail Core/filter boundary.
3. Mail Core creates the SMTP Transaction and tenant-scoped child instances.
4. Shared scans run once where safe; tenant-specific policy runs per child instance.
5. Allowed instances are submitted through a dedicated trusted reinjection listener/transport.
6. Reinjection is private/restricted, preserves the appropriate envelope and trace identity, and is marked so Postfix does not send it through the same content filter again.
7. Quarantined/held instances are not reinjected.

Rust Mail Core is not an Internet-facing MTA. A narrowly scoped internal SMTP/LMTP endpoint is acceptable if selected as the safest Postfix handoff mechanism.

## Recipient isolation

A single accepted SMTP transaction can produce different outcomes for different customers or recipient groups.

Example:

```text
sender -> RCPT alice@customer-a -> CZA-1
       -> RCPT bob@customer-b   -> CZA-27
       -> DATA once

shared content/security analysis
        |
        +--> CZA-1 policy -> deliver
        '--> CZA-27 policy -> quarantine
```

Customer-facing trace/API access is always scoped to the relevant Tenant Message Instance; one customer must never see another customer's recipients or disposition.

## Inbound states

Transaction/tenant-message states include:

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
Private signed-outbound submission
  |- hash-bound message from authorized connector worker
  |- matching tenant-authorized signer required
  |- isolated Postfix listener; Rspamd key never enters Mail Core
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

The signed-outbound listener is an internal hop, not a customer submission
endpoint. It accepts only the Mail Core workload source and does not accept a
null envelope sender. DSN and quarantine reinjection use separate listeners
and must never be repurposed for customer outbound signing.

## Bulk sending

Approved bulk sender addresses are explicit policy entries.

Unapproved bulk-like behaviour is detected and blocked/deferred/throttled/held according to policy.

Bulk authorization never bypasses malware or malicious-content controls.

## SMTP error catalogue

Nullapart maintains a structured SMTP response catalogue covering connection/resource, TLS, protocol, authentication, relay, recipient, tenant, greylisting, rate, reputation, GeoIP, SPF, DKIM, DMARC, size, malware, attachments, content, outbound authorization, bulk, routing, DNS, downstream SMTP and internal security pipeline failures.

Remote errors are safe and concise; internal views contain permission-controlled diagnostic detail.

## Flow diagrams

See [Inbound Mail Flow](diagrams/01-inbound-mail-flow.mmd) and [Outbound Mail Flow](diagrams/02-outbound-mail-flow.mmd).

# SMTP Transaction and Tenant Message Contract

**Status:** required architecture contract before Rust implementation.

## Purpose

One SMTP `DATA` transaction can contain recipients belonging to different Nullapart customers and different recipient-level policies. Nullapart must not assume that one accepted message maps to one customer or one disposition.

## Parent / child model

The canonical model is split into two levels.

### SMTP Transaction

Represents the accepted SMTP submission and shared immutable message content.

Fields include:

- Nullapart transaction ID;
- direction;
- region/deployment;
- source connection/session identity;
- envelope sender;
- all originally accepted recipients;
- RFC Message-ID;
- trusted SPF/DKIM/DMARC/ARC observations;
- raw MIME artifact reference;
- normalized MIME structure;
- shared content hashes;
- shared scanner findings that are content-intrinsic;
- receipt timestamps;
- original Postfix queue ID(s) where applicable;
- trace ID.

### Tenant Message Instance

Represents the customer-scoped evaluation and disposition for one tenant/recipient group.

Fields include:

- tenant message ID;
- parent transaction ID;
- customer ID;
- customer-scoped recipients;
- effective policy revision;
- tenant/customer intelligence context;
- customer-specific findings;
- disposition;
- quarantine/hold state;
- delivery attempts and downstream SMTP results;
- security/remediation state;
- customer-visible trace.

## Recipient partitioning

After acceptance, recipients are partitioned by effective tenant/policy boundary before customer-specific policy evaluation.

Example:

```text
SMTP DATA transaction TX-123
  From: sender@example.net
  Recipients:
    alice@customer-a.example  -> CZA-1
    bob@customer-b.example    -> CZA-27

Shared immutable content/scans
          |
          +--> Tenant Message TM-1 / CZA-1
          |      -> Allow -> Deliver
          |
          '--> Tenant Message TM-2 / CZA-27
                 -> Quarantine
```

A customer must never see recipients, policies, findings or delivery state belonging to another customer merely because the mail arrived in the same SMTP transaction.

## Shared vs tenant-specific work

The following can normally be shared where safe:

- MIME parsing;
- file hashes;
- malware scanning;
- static file analysis;
- extracted URLs;
- basic document extraction;
- message-authentication observations.

The following are tenant/recipient scoped:

- allow/block lists;
- VIP/impersonation context;
- customer URL/domain reputation overrides;
- customer policy thresholds;
- mailbox/group policy;
- quarantine/disposition;
- customer notifications;
- delivery routing;
- remediation.

A scanner finding can therefore be transaction-scoped or tenant-message-scoped.

## Privacy boundary

Customer-facing APIs and UI query Tenant Message Instances, not the global SMTP recipient set.

System Admin may correlate the parent transaction and child instances when authorized.

Support sees only fields permitted by Support content/privacy rules.

## IDs

Keep distinct:

- trace ID;
- SMTP transaction ID;
- tenant message ID;
- RFC Message-ID;
- Postfix queue ID;
- downstream delivery attempt ID.

No one identifier should be overloaded to represent all of these concepts.

## Postfix after-queue handoff

The Internet-facing Postfix instance remains responsible for SMTP acceptance and durable queueing.

Complex Nullapart analysis happens through an explicit after-queue content-filter handoff.

The implementation contract must define:

1. Postfix accepts and durably queues the message.
2. A configured after-queue transport/filter hands the complete envelope + message to the Rust Mail Core/filter boundary.
3. Mail Core creates the transaction/tenant-message records and executes required scanning/policy.
4. Allowed tenant-message instances are submitted to a **dedicated trusted reinjection listener/transport**, not back through public MX ingress.
5. Reinjected mail carries an internal authenticated marker and original transaction identity.
6. Postfix routing prevents reinjected messages from being sent through the same content filter again.
7. Quarantined/held instances are not reinjected.

## Reinjection safety

The reinjection path must preserve:

- envelope sender;
- recipient set for that tenant instance;
- DSN/ORCPT/NOTIFY semantics where supported/needed;
- original message content except deliberate security headers;
- trace/correlation identity;
- delivery status correlation.

It must also enforce:

- private/trusted network path;
- workload or transport authentication;
- loop prevention;
- no public relay capability;
- explicit size/resource limits.

## Failure semantics after SMTP 250

After Nullapart has accepted responsibility with SMTP `250`, internal failures do not become retroactive SMTP rejections to the original sender.

Required security-pipeline failure can result in:

- hold;
- quarantine;
- delivery deferral within Nullapart;
- eventual DSN/NDR where SMTP semantics require it;
- customer/internal alerting.

Avoid backscatter: do not generate unsafe non-delivery messages for obviously forged/untrusted envelope senders simply because a post-accept scanner failed.

## Rust responsibility boundary

Rust Mail Core is **not an Internet-facing MTA** and does not replace Postfix.

It may implement an internal, narrowly scoped LMTP/SMTP/content-filter protocol endpoint if that is the safest Postfix integration mechanism. Such an endpoint is private, authenticated/restricted, and exists only for controlled handoff/reinjection semantics.

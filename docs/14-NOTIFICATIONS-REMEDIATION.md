# Notifications and Remediation

## Notification classes

Nullapart separates:

- customer security notifications;
- platform/internal operational notifications.

## Customer contacts

Customers can configure addresses/groups such as:

- postmaster;
- security;
- mail administrators;
- DMARC administrators;
- custom security notification groups.

Customer-configurable routing remains subject to platform constraints.

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

## Sending path

Security notifications are generated internally and submitted through Nullapart's own trusted outbound MTA path.

Use trusted loopback/internal submission, not public MX ingress.

Where appropriate the sender identity is the tenant-configured postmaster/security address.

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
- recipient(s);
- subject;
- Nullapart tracking ID;
- threat category;
- severity;
- normalized reason/evidence;
- remediation status;
- recommended action.

Do not attach the malicious original message.

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

Serious security/operational events can publish durable events consumed by n8n and sent to ClickUp.

ClickUp receives minimized metadata and a regional Nullapart link rather than raw message content.

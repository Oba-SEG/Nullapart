# SMTP Response Catalogue

## Purpose

Nullapart must maintain a complete, consistent SMTP response catalogue rather than returning generic 451/550 messages for unrelated failures.

The catalogue is informed by established SMTP/enhanced-status semantics and operational references such as Mimecast's published SMTP error catalogue.

Reference:
- https://mimecastsupport.zendesk.com/hc/en-us/articles/34000709564691-Policies-Mimecast-SMTP-Error-Codes

## SMTP responsibility boundary

The catalogue distinguishes **pre-accept SMTP responses** from **post-accept delivery/security outcomes**.

Before Nullapart/Postfix returns `250` for the message transaction, an SMTP-stage policy may return a standards-compatible temporary or permanent SMTP reply.

After `250`, the original SMTP transaction is complete and Nullapart owns responsibility. Later scanner/policy/internal failures do not become retroactive SMTP replies to that original session.

Post-accept failures use:

- internal Nullapart reason codes;
- delivery-state transitions;
- retry/queue semantics;
- downstream SMTP replies where delivery is attempted;
- DSN/NDR only where safe and appropriate;
- customer/internal notifications where configured.

Avoid backscatter to forged/untrusted envelope senders.

## Response record

Each pre-accept Nullapart SMTP response definition contains:

- internal reason code;
- SMTP stage;
- SMTP reply code;
- enhanced status code;
- temporary/permanent classification;
- safe sender-facing message;
- internal explanation;
- recommended operator resolution;
- retry behaviour;
- notification/escalation behaviour;
- policy family.

Post-accept reason definitions use the same stable internal reason-code system but do not require an original-session SMTP reply code.

## Example

```text
Internal code:
NUL-RBL-BLOCK

Stage:
CONNECT

SMTP:
550 5.7.1

Remote text:
Message rejected by security policy

Internal:
Connecting source matched a configured blocking reputation list.

Retry:
No

Customer notification:
Policy dependent
```

## Categories

The catalogue must cover:

- connection limits/resources;
- TLS;
- SMTP protocol;
- HELO/EHLO;
- relay authorization;
- recipient validation;
- customer/tenant state;
- greylisting;
- rate limiting;
- RBL/DNSBL/reputation;
- GeoIP;
- SPF;
- DKIM;
- DMARC;
- message size;
- MIME validity;
- malware;
- attachment policy;
- content/security policy;
- outbound source authorization;
- outbound sender/domain authorization;
- bulk-send policy;
- queue/resource exhaustion;
- DNS/MX resolution;
- downstream SMTP;
- routing;
- required scanner failure;
- policy/configuration failure.

Each category declares whether it can occur at a pre-accept SMTP stage, post-accept only, or both.

## Safe disclosure

Remote senders receive only enough information to understand SMTP disposition and normal remediation.

Do not disclose:

- exact security-rule implementation;
- scanner technology;
- private blocklists;
- model scores;
- internal hostnames;
- customer configuration detail.

Support/System operational views can display permission-controlled diagnostic detail.

## Enhanced status codes

Use standards-compatible enhanced status codes wherever possible.

Do not invent numerical status meanings simply to create product-specific error categories. Product-specific meaning lives in the internal `NUL-...` reason code.

## Downstream responses

When Nullapart attempts delivery to a destination MTA:

- preserve the destination SMTP code/text internally;
- classify/normalize it for product UI;
- keep full transmission trace for authorized operations;
- use destination retry semantics correctly;
- associate the attempt with the relevant Tenant Message Instance, not a cross-tenant parent recipient set.

## UI

Do not show a raw SMTP transcript as the default customer experience.

Present:

- status;
- delivery attempt time;
- destination;
- normalized reason;
- next retry if applicable;
- final/non-final state.

System/Support can expand to transmission-level diagnostics according to permissions.

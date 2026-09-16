# SMTP Response Catalogue

## Purpose

Nullapart must maintain a complete, consistent SMTP response catalogue rather than returning generic 451/550 messages for unrelated failures.

The catalogue is informed by established SMTP/enhanced-status semantics and operational references such as Mimecast's published SMTP error catalogue.

Reference:
- https://mimecastsupport.zendesk.com/hc/en-us/articles/34000709564691-Policies-Mimecast-SMTP-Error-Codes

## Response record

Each Nullapart response definition contains:

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
- use destination retry semantics correctly.

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

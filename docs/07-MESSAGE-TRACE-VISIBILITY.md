# Message Trace, Full Message View and Visibility

## Canonical mail identity

Nullapart does not model every accepted SMTP submission as one customer-owned message.

A single SMTP `DATA` transaction can contain recipients from multiple customers or policy scopes. The canonical model therefore has two levels.

### SMTP Transaction

Contains shared receipt/session and immutable content information:

- Nullapart transaction ID;
- region/deployment;
- direction;
- RFC Message-ID;
- receipt SMTP session/transmission;
- original envelope sender;
- original accepted recipient set, restricted to System/internal views;
- trusted authentication findings;
- raw MIME artifact reference;
- MIME structure;
- shared body/attachment artifact references;
- URLs/content hashes;
- shared scanner findings;
- receipt timestamps;
- Postfix queue ID(s);
- trace ID.

### Tenant Message Instance

Contains customer-scoped evaluation/delivery information:

- Nullapart tenant message ID;
- parent transaction ID;
- customer ID;
- only that customer's recipients;
- effective policy revision;
- tenant-scoped findings/context;
- policy result;
- quarantine/hold state;
- delivery SMTP transmission(s);
- receipt/scan/delivery timestamps;
- delivery state;
- security/remediation state.

This internal contract is not presented as JSON in the UI.

See [SMTP Transaction and Tenant Message Contract](18-MESSAGE-TRANSACTION-CONTRACT.md).

## Trace identity

Keep separate:

- trace ID;
- SMTP transaction ID;
- tenant message ID;
- RFC Message-ID;
- Postfix queue ID;
- delivery attempt ID.

## Product timeline

Customer/Support-facing timelines use technology-neutral descriptions such as:

- Connection received;
- Connection reputation passed;
- Customer domain identified;
- Recipient accepted;
- Sender authentication evaluated;
- Message safely queued;
- Malware scan completed — Clean;
- URL analysis completed — Clear;
- Document analysis completed — Clean;
- Threat analysis completed — Low Risk;
- Policy evaluated — Allow;
- Delivery started;
- Destination server accepted message.

Do not expose backend technology names in normal product trace.

## Internal trace

Platform telemetry may include exact node, engine, version, duration, queue ID and rule identifiers for engineering/System operations, subject to permissions.

## Recipient privacy

Customer-facing queries are based on Tenant Message Instances.

A customer must never see another customer's recipients, routing, policy, quarantine state or delivery state simply because both recipients were present in the same original SMTP transaction.

Support views follow the same tenant-boundary rules and additionally exclude message content.

## Visibility

### System Admin

May view, subject to explicit permissions and audit:

- full transaction/tenant trace;
- full receipt/delivery transmissions;
- full headers;
- full message content;
- raw MIME where required;
- attachments;
- scanner internals;
- security evidence;
- policy;
- remediation;
- cross-child correlation for a multi-tenant SMTP transaction.

Full-content access is audited.

### Support

May view:

- permitted operational trace;
- receipt/delivery transmissions;
- routing;
- policy results;
- security classifications;
- safe metadata;
- permitted headers/derived header values;
- node detail.

Support must not receive message body, raw MIME or attachment content, including through search snippets, audit data, exports or direct artifact URLs.

### Customer Admin

Tenant owner controls per-role access to:

- headers;
- message content;
- attachments;
- quarantine;
- release;
- security detail;
- remediation.

All enforcement is server-side.

## Hostile-content rendering

Received message content is hostile input and must never be injected directly into the trusted control-plane DOM.

HTML is sanitized and rendered through an isolated/sandboxed context with scripts/forms/active content removed and remote resources blocked by default.

Raw headers/MIME are escaped text. Attachment previews/downloads use a permission-checked artifact path, preferably on a separate origin without control-plane session cookies.

See [Secure Message Rendering and Artifact Access](19-SECURE-MESSAGE-RENDERING.md).

## Post-delivery

If a threat is discovered after delivery, the trace records the original `DELIVERED` state and then separate security/remediation events. Delivery history is never rewritten.

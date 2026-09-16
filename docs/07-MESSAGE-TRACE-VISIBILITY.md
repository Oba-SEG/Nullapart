# Message Trace, Full Message View and Visibility

## Canonical message record

Nullapart maintains one internal message model containing:

- Nullapart message ID;
- customer ID;
- region/deployment;
- direction;
- RFC Message-ID;
- receipt SMTP session/transmission;
- delivery SMTP session/transmission(s);
- envelope sender/recipients;
- headers;
- MIME structure;
- body-part references;
- attachment references;
- URLs;
- trusted authentication findings;
- scanner findings;
- inline/deep model findings;
- policy result;
- receipt/scan/delivery timestamps;
- delivery state;
- security/remediation state.

This contract is internal. It is not presented as JSON in the UI.

## Trace identity

Keep separate:

- trace ID;
- Nullapart message ID;
- RFC Message-ID.

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

Platform telemetry may include exact node, engine, version, duration and rule identifiers for engineering/support diagnostics, subject to permissions.

## Visibility

### System Admin

May view:

- full trace;
- full receipt/delivery transmissions;
- full headers;
- full message content;
- raw MIME where required;
- attachments;
- scanner internals;
- security evidence;
- policy;
- remediation.

### Support

May view:

- full operational trace;
- receipt/delivery transmissions;
- routing;
- policy results;
- security classifications;
- safe metadata;
- permitted headers/derived header values;
- node detail.

Support must not receive message body or attachment content.

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

## Post-delivery

If a threat is discovered after delivery, the trace records the original DELIVERED state and then separate security/remediation events. Delivery history is never rewritten.

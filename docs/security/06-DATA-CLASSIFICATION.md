# Data Classification and Handling

## Classes

### PUBLIC

Intended for public disclosure.

### INTERNAL

Operational information not intended for public release.

### CONFIDENTIAL

Customer/security/operational information requiring controlled access.

### RESTRICTED

Highest-sensitivity data such as message content, secrets, credentials, private keys and sensitive mailbox artifacts.

## Baseline matrix

| Data | Class | Support | System Admin | SegLumberjack | ClickUp | Deep AI |
|---|---|---|---|---|---|---|
| Customer ID | Confidential | Scoped | Yes | Yes | Minimal | When needed |
| SMTP metadata | Confidential | Scoped | Yes | Sanitized | Minimal | When needed |
| Message body | Restricted | No | Authorized + audited | No | No | Eligible cases only |
| Raw MIME | Restricted | No | Authorized + audited | No | No | Eligible cases only |
| Attachment | Restricted | No | Authorized + audited | No | No | Eligible cases only |
| Extracted document text | Restricted | No | Authorized | No | No | Eligible cases only |
| SecurityFinding | Confidential | Scoped | Yes | Sanitized | Minimal | Yes when relevant |
| Admin audit | Confidential | Scoped | Yes | Sanitized correlation | No | No |
| Password/token/private key | Restricted | No | Limited operational access | Never | Never | Never |
| Connector credential | Restricted | No | Limited operational access | Never | Never | Never |
| Training candidate data | Restricted | No | Authorized governance role | No | No | Training pipeline only |

## Handling

RESTRICTED data requires:

- encryption in transit/at rest;
- least-privilege access;
- explicit retention;
- access audit where applicable;
- no casual export;
- regional-residency enforcement;
- no use in development without approved sanitization.

## Training data

Operational content access does not imply training permission.

Training eligibility requires separate governance, provenance and retention decisions.

## Logging

Never log secrets or message content by default.

Observability fields must be explicitly classified/scrubbed.

## Export

Every export path must declare:

- data classes;
- authorized roles;
- destination;
- retention;
- regional implications;
- audit behaviour.

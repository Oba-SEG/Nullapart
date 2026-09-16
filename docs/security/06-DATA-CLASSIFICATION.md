# Data Classification and Handling

## Classes

- **PUBLIC** — intended for public disclosure.
- **INTERNAL** — operational information not intended for public release.
- **CONFIDENTIAL** — customer/security/operational information requiring controlled access.
- **RESTRICTED** — message content, credentials, private keys, secrets and sensitive mailbox artifacts.

## Baseline matrix

| Data | Class | Support | System Admin | SegLumberjack | ClickUp | Deep AI |
|---|---|---|---|---|---|---|
| Customer ID | Confidential | Scoped | Yes | Yes | Minimal | When needed |
| SMTP metadata | Confidential | Scoped | Yes | Sanitized | Minimal | When needed |
| Message body | Restricted | No | Authorized + audited | No | No | Eligible cases only |
| Raw MIME | Restricted | No | Authorized + audited | No | No | Eligible cases only |
| Attachment | Restricted | No | Authorized + audited | No | No | Eligible cases only |
| Extracted document text | Restricted | No | Authorized | No | No | Eligible cases only |
| SecurityFinding | Confidential | Scoped | Yes | Sanitized | Minimal | When relevant |
| Admin audit | Confidential | Scoped | Yes | Sanitized correlation | No | No |
| Password/token/private key | Restricted | No | Limited operational access | Never | Never | Never |
| Connector credential | Restricted | No | Limited operational access | Never | Never | Never |
| Training candidate data | Restricted | No | Authorized governance role | No | No | Training pipeline only |

## Handling

RESTRICTED data requires encryption, least privilege, explicit retention, access audit where applicable, regional-residency enforcement and no casual export.

## Training data

Operational content access does not imply training permission. Training eligibility has separate governance/provenance.

## Logging

Never log secrets or message content by default.

## Export

Every export path declares data classes, authorized roles, destination, retention, regional implications and audit behaviour.

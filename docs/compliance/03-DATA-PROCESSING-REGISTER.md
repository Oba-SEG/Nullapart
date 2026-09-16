# Data Processing Register

## Purpose

Track what Nullapart processes, why, where, how long and who can receive it.

## Template

| Processing ID | Data class | Purpose | Source | Region | Storage | Roles with access | Third parties | Retention | Deletion | Training eligible |
|---|---|---|---|---|---|---|---|---|---|---|
| MAIL-001 | Raw MIME / Restricted | SEG scanning/quarantine | SMTP | Tenant deployment | S3 | Authorized roles/services | None by default | Policy | Lifecycle + audit | No by default |
| MAIL-002 | Message metadata / Confidential | trace/security | SMTP | Tenant deployment | PostgreSQL | Scoped | Minimal ops only | Policy | DB lifecycle | No |
| AUD-001 | Admin audit / Confidential | accountability | Admin actions | Deployment | PostgreSQL/S3 checkpoint | Scoped | None | Security policy | controlled lifecycle | No |
| AI-001 | Eligible security content / Restricted | Deep analysis | Security cases | Tenant deployment | scoped transient/input artifacts | AI service + authorized roles | None external | Policy | lifecycle | Separate governance |

Rows are starting examples; production register must reflect actual implementation.

## Required fields

Every new data-processing path defines:

- data classification;
- purpose;
- lawful/contractual basis where applicable (legal review);
- source;
- region;
- stores;
- access;
- third-party sharing;
- retention;
- deletion;
- backup implications;
- AI/training eligibility.

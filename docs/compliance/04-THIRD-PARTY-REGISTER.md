# Third-Party / Subprocessor Register

## Purpose

Inventory external organizations/services that receive data or materially affect security.

## Template

| Provider | Purpose | Data shared | Region/endpoints | Auth | Retention | Security review | Contract/DPA | Exit/deletion | Owner | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| ClickUp | Internal operational workflow | minimized incident metadata | TBD | scoped integration | TBD | Required | TBD | Required | TBD | Planned |
| Threat intelligence provider | reputation enrichment | explicitly allowed indicators only | TBD | scoped API | TBD | Required | TBD | Required | TBD | TBD |

AWS should also be represented according to the compliance/legal treatment selected for hosting/subprocessing.

## Rules

No new third-party data export without:

- security review;
- data classification;
- regional/residency review;
- contractual/compliance review where applicable;
- retention/deletion understanding;
- documented failure/exit behavior.

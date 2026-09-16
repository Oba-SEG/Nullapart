# Compliance Control Register

## Purpose

Single register connecting Nullapart controls to ownership, implementation and evidence.

## Template

| Control ID | Domain | Control objective | Implementation reference | Owner | Scope | Evidence | Frequency | Status | Exception |
|---|---|---|---|---|---|---|---|---|---|
| IAM-001 | Access | MFA for all administrators | SECURITY.md / Identity docs | TBD | All deployments | IdP config + access review | Continuous/Quarterly | Designed | None |
| IAM-002 | Access | Server-side resource authorization | AppSec baseline | TBD | Control Plane | tests + code review | Every change | Designed | None |
| DATA-001 | Data | Regional customer-content isolation | Architecture/storage | TBD | Per deployment | IaC/IAM/storage evidence | Release/Annual | Designed | None |
| AUD-001 | Audit | Administrative actions are durable/audited | Admin Audit docs | TBD | Control Plane | audit tests/checkpoints | Continuous | Designed | None |
| CICD-001 | SDLC | Protected/reviewed production source | CI/CD baseline | TBD | Repository | branch/PR evidence | Continuous | Designed | None |
| VULN-001 | Vulnerability | Critical/High findings meet SLA | Vulnerability policy | TBD | All | scan/ticket history | Continuous | Designed | None |
| DR-001 | Resilience | Backup restore is tested | Backup/DR policy | TBD | Regional | restore evidence | Scheduled | Designed | None |

The initial rows are examples and do not represent an external audit conclusion.

## Status values

Suggested:

- PLANNED;
- DESIGNED;
- IMPLEMENTED;
- TESTED;
- OPERATING;
- EXCEPTION;
- NOT_APPLICABLE.

"IMPLEMENTED" and "OPERATING" require evidence, not intent.

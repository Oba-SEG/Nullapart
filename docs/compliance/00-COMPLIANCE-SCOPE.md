# Compliance Scope and Applicability

## Status

Populate before any external compliance/certification claim.

## Product scope

- Product: Nullapart Secure Email Gateway
- Hosting: AWS regional deployments
- Initial deployment: ZA
- Administrative users: System / Support / Customer Admin
- Customer message processing: regional/deployment scoped

## Scope fields

For each deployment/framework/regulatory requirement record:

| Field | Value |
|---|---|
| Scope ID | TBD |
| Region/deployment | TBD |
| Legal entity/operator | TBD |
| Customer population | TBD |
| Data subjects | TBD |
| Data categories | TBD |
| Processing purpose | TBD |
| Systems in scope | TBD |
| Third parties/subprocessors | TBD |
| Applicable requirement/framework | TBD / legal review |
| Owner | TBD |
| Review date | TBD |

## Boundary

Compliance scope must align with real technical boundaries:

- AWS accounts/VPCs;
- regional data stores;
- S3;
- PostgreSQL;
- identity;
- OpenBao;
- SegLumberjack;
- CloudWatch;
- Deep AI;
- n8n/ClickUp;
- connectors.

Do not describe a service as "out of scope" if it can access in-scope customer/security data.

## Certification language

External statements must distinguish:

- designed to support a control;
- mapped to a framework;
- internally assessed;
- externally audited;
- certified/attested.

Only the last categories may use corresponding verified external claim language.

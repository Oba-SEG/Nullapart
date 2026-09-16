# Third-Party Risk and Security Exceptions

## Third-party assessment

Before integration document:

- purpose;
- data classes shared;
- region/residency;
- authentication;
- encryption;
- retention;
- sub-processors/dependencies where material;
- breach/security-contact process;
- availability dependency;
- exit/replacement plan.

Examples include ClickUp, threat intelligence, DNS/RBL providers, identity dependencies and model/tooling dependencies.

## Data minimization

Send only required fields. Message bodies/attachments are denied by default unless the explicit purpose requires them.

## Failure behavior

Third-party failure has documented product behaviour. Non-critical third parties do not stop mail delivery.

## Security exceptions

A deviation requires:

- exception ID;
- owner;
- affected system/region;
- requirement waived;
- risk;
- compensating controls;
- approver;
- start/expiry;
- review date.

Exceptions are time-limited. Expired exceptions alert and become non-compliant.

## UI/audit

System Admin should be able to review active security exceptions and expiry. Creating/updating/closing an exception is audited.

# Compliance Assurance and Control Mapping

**Status:** mandatory governance process; this document does not claim certification.

## Principle

Nullapart should be designed so security/privacy controls produce evidence that can be mapped to applicable customer, contractual and regulatory requirements.

Compliance is not a substitute for security engineering.

Do not state that Nullapart is certified/compliant with a framework until the required legal/audit process has actually established that status.

## Applicability

Applicable requirements depend on:

- deployment region;
- customer type;
- data subjects;
- contracts;
- industry;
- processing purpose.

The legal/compliance owner determines applicability.

Potential frameworks/regimes to evaluate as the product matures include:

- South African privacy/data-protection requirements for ZA;
- EU/UK privacy/data-protection requirements for relevant deployments/customers;
- security assurance frameworks such as ISO/IEC 27001 and SOC 2;
- customer-specific contractual/security requirements.

This list is planning context, not a certification claim.

## Compliance record set

The working documentation/registers live under `docs/compliance/`:

- scope/applicability;
- control register;
- evidence catalog;
- data-processing register;
- third-party register;
- risk/exception register;
- production-readiness evidence.

These records are populated as implementation/operations evidence becomes real.

## Control register

Maintain a security/control register with:

- control ID;
- control objective;
- implementation;
- owner;
- systems/regions;
- evidence source;
- test/review frequency;
- status;
- exceptions;
- mapped frameworks/requirements.

## Evidence sources

Examples:

- access reviews;
- MFA configuration;
- Admin Audit;
- vulnerability scans/remediation;
- CI/CD security gates;
- SBOM/provenance;
- deployment history;
- backup/restore tests;
- incident exercises;
- security training/ownership;
- risk/exception approvals;
- key/certificate rotation;
- penetration tests;
- data-retention/deletion evidence;
- regional architecture/IAM/network configuration.

## Privacy records

Maintain appropriate records for:

- data classes/purpose;
- regional processing/storage;
- subprocessors/third parties;
- retention;
- deletion;
- security measures;
- incident/breach process;
- training-data governance.

## Data residency

Compliance rules must not be implemented as UI labels alone.

Residency controls are enforced through:

- regional storage;
- IAM;
- network architecture;
- artifact access;
- connector/third-party configuration;
- AI deployment boundaries;
- backup policy.

## Third parties

Before a third party receives customer/security data, record:

- purpose;
- fields/data classes;
- region;
- retention;
- security review;
- contract/DPA requirements where applicable;
- exit/deletion procedure.

## Audit readiness

The platform should be able to produce evidence of:

- who changed what;
- who accessed restricted content;
- what version was deployed;
- what security checks passed;
- where data is stored;
- when backups/restores were tested;
- how vulnerabilities were remediated;
- which exceptions were active.

## Compliance dashboard / internal UI

A future System Admin/security-governance view may show:

- control status;
- evidence freshness;
- overdue access reviews;
- expired exceptions;
- vulnerability SLA status;
- backup/restore status;
- certificate/key expiry;
- release provenance;
- audit checkpoint status.

Do not expose sensitive evidence to ordinary Customer Admin roles unless intentionally designed.

## Change impact

Architecture changes that alter data location, third-party sharing, identity, audit, retention or encryption require compliance-impact review.

## AI-agent rule

AI agents must not:

- claim certification/compliance;
- invent legal applicability;
- remove an evidence-producing control merely because it is operationally inconvenient;
- send customer data to a new external service without third-party/compliance review.

They may map technical controls to a framework only when the mapping is documented/reviewed.

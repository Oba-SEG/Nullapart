# Privacy, Retention and Deletion

## Principle

Nullapart stores security-sensitive customer communications. Retention must be explicit, minimal, region-aware and enforceable.

## Data inventory

Every data class must define:

- purpose;
- owner;
- region/deployment;
- storage locations;
- retention period;
- deletion method;
- backup implications;
- export/third-party paths;
- legal/compliance constraints.

## Retention

Define System-level minimum/maximum bounds for:

- message metadata;
- raw MIME;
- attachments;
- quarantine;
- SMTP transmissions;
- DMARC aggregate reports;
- DMARC failure reports;
- administrative audit;
- security cases;
- observability;
- AI analysis;
- training candidates;
- connector/mailbox data.

Tenant-configurable retention cannot weaken mandatory security/legal requirements.

## Deletion

Deletion workflows must:

- verify authorization;
- identify all authoritative and artifact locations;
- account for replicas/backups;
- remove access immediately where physical deletion is deferred;
- record the deletion action in audit;
- verify completion where feasible.

## Tenant termination

Termination does not imply instant destruction.

The lifecycle defines:

1. disable mail/control access according to policy;
2. revoke connectors/service credentials;
3. start retention/deletion schedule;
4. preserve legally/security-required audit evidence;
5. delete customer content when retention expires;
6. record completion.

## Backups

Backup retention and deletion behaviour must be documented. Deleted production data must not remain indefinitely restorable through uncontrolled backups.

## Legal hold

If legal-hold capability is introduced, it must:

- be restricted to authorized System roles;
- identify scope/reason/expiry;
- override normal deletion only for the covered data;
- be fully audited.

## Data subject/customer requests

Where applicable, Nullapart must have a documented process to locate/export/delete eligible customer administrative/account information without exposing another tenant's data.

Mail-security evidence that must be retained for security/legal reasons is handled according to applicable policy.

## AI/training

Deletion from operational mail does not automatically imply immediate removal from an independently governed training dataset, so training datasets must retain provenance and deletion/withdrawal procedures appropriate to the approved governance model.

Operational content is not eligible for training merely because Nullapart can technically access it.

## Verification

Security/privacy reviews should verify that configured retention matches actual S3/database/object lifecycle behaviour.

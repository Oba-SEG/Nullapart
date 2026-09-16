# Access Governance

## Principles

- least privilege;
- named users only;
- MFA for every admin;
- no shared admin accounts;
- explicit customer/region/deployment scope;
- privileged access is auditable;
- standing privilege minimized.

## Joiner / mover / leaver

Provisioning follows approved role requests.

Role/responsibility changes remove obsolete permissions immediately. Leavers lose access promptly and sessions/tokens are revoked.

## Privileged roles

System Admin and Support require stronger authentication, periodic review, documented justification, monitored impersonation and step-up for high-risk actions.

## Access reviews

Review System/Support admins, customer owners/admins where applicable, AWS/IAM privilege, OpenBao/ZITADEL admins, GitHub/release permissions, production access and n8n/ClickUp integrations.

Initial target: quarterly for privileged platform access.

## Break-glass

Emergency access uses a minimal number of accounts, strong hardware-backed MFA, controlled credentials, immediate alerting and mandatory post-use review.

## Service accounts

Every identity has an owner, purpose, allowed resources, rotation/expiry and region/deployment. Dormant/unused identities are removed.

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

Provisioning must follow approved role requests.

When role/employment/responsibility changes:

- remove obsolete roles immediately;
- revoke sessions/tokens;
- rotate shared integration credentials if exposure requires;
- validate ownership of automation/service accounts.

Leavers lose access promptly.

## Privileged roles

System Admin and Support access require:

- stronger authentication;
- periodic review;
- documented justification;
- monitored impersonation;
- step-up for high-risk actions.

## Access reviews

Perform periodic reviews of:

- System Admins;
- Support roles;
- customer owners/admins where platform responsibility applies;
- AWS/IAM privileged roles;
- OpenBao privileged identities;
- ZITADEL administrators;
- GitHub/release permissions;
- production access;
- n8n/ClickUp integrations.

Initial target: quarterly for privileged platform access.

## Break-glass

Maintain tightly controlled emergency access with:

- minimal number of accounts;
- strong hardware-backed MFA;
- sealed/controlled credentials;
- use only during defined emergencies;
- immediate alerting;
- mandatory audit/review after use.

## Service accounts

Every service identity has:

- owner;
- purpose;
- allowed resources;
- rotation/expiry;
- region/deployment;
- no interactive login unless explicitly required.

Dormant/unused identities are removed.

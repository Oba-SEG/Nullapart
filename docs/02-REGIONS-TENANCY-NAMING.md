# Regions, Tenancy, Naming and Product Domains

## Product domains

Primary canonical domain:

- `nullapart.com`

Additional protected domains:

- `nullapart.io`
- `nullapart.co`
- `nullapart.co.za`

## Domain policy

`nullapart.com` is the canonical product domain for control-plane URLs, product links and public identity unless a region-specific regulatory/business requirement later dictates otherwise.

The additional domains are defensive/brand domains and may be used for carefully defined regional/technical purposes, but should not create parallel cookie/authentication surfaces unnecessarily.

Default behaviour:

- HTTPS on each alternate root redirects to the canonical `nullapart.com` destination.
- no shared browser session cookies across unrelated root domains;
- HSTS enabled where appropriate;
- SPF/DKIM/DMARC configured deliberately for each domain;
- unused mail domains use restrictive SPF/DMARC policies;
- DNS changes are managed as infrastructure code.

## Regional deployments

Initial region codes:

- `ZA` — South Africa;
- `EU` — Europe;
- `UK` — United Kingdom;
- `US` — United States.

A region begins with a primary deployment.

If the deployment reaches operational/performance limits, another complete deployment is created in that region:

- `ZA`;
- `ZAB`;
- `ZAC`.

## Customer IDs

Examples:

- `CZA-1`;
- `CZA-2`;
- `CZAB-1`;
- `CEU-1`;
- `CUK-1`;
- `CUS-1`.

These are the identifiers shown in UI, URLs, logs and operations.

Do not surface UUIDs as customer identities.

## Regional URLs

Canonical control endpoints should follow one predictable naming model on `nullapart.com`.

Proposed form:

- `za.nullapart.com`;
- `zab.nullapart.com`;
- `eu.nullapart.com`;
- `uk.nullapart.com`;
- `us.nullapart.com`.

The public login landing page can exist at `nullapart.com` and route the administrator to the selected deployment.

## Mail DNS

Proposed host naming examples:

- `mx1.za.nullapart.com`;
- `mx2.za.nullapart.com`;
- `relay1.za.nullapart.com`;
- `mx1.zab.nullapart.com`.

Exact MX priority/topology remains a deployment decision.

## Login region/deployment selector

The main login experience selects the deployment before authentication.

If only one deployment exists within a region, the UI can collapse redundant choices while still resolving to a specific deployment.

## Node naming

Examples:

- `mxin-za-a-01`;
- `mxout-za-a-01`;
- `mailcore-za-a-01`;
- `scan-malware-za-a-01`;
- `scan-doc-za-a-02`;
- `scan-url-eu-a-01`.

Every mail/scanner node has a unique IP and numbered hostname.

## Regional independence

Each deployment has unique URL, DNS, mail infrastructure, database, Redis, S3 namespace/buckets, OpenBao, ZITADEL, logs/Sentry routing, Deep AI and n8n deployment as required.

Customer data is not routinely queried across deployments.

## Data residency and integrations

Before data leaves the deployment for any integration, configuration must define allowed data classification, endpoint region, exact fields transmitted, content/PII permission and retention expectations.

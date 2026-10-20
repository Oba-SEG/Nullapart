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

- HTTPS on each alternate root redirects to the canonical `nullapart.com` destination;
- no shared browser session cookies across unrelated root domains;
- HSTS enabled where appropriate;
- restrictive CAA;
- DNSSEC where supported/selected;
- SPF/DKIM/DMARC configured deliberately for each domain;
- unused sending domains use restrictive SPF/DMARC;
- domains/subdomains intentionally not receiving mail use Null MX;
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

The database stores structured region/deployment/sequence fields in addition to the visible customer ID so authorization and routing do not depend on parsing a string.

## Customer placement

A customer is created inside one deployment and inherits that deployment's region. Region is never a per-customer choice at creation time, and the visible customer ID encodes it.

The Control Plane surfaces placement (region code and sequence) through the customer administration API and the console so operators can see which deployment owns a customer.

Placement is fixed at creation. Moving a customer between deployments is not supported: the customer identity embeds the region, and residency rules forbid routine cross-deployment data movement. Any future re-placement requires an explicit, reviewed architecture and security decision covering identity semantics, data movement, backup/DR and audit continuity.

## Regional URLs

Canonical control endpoints should follow one predictable naming model on `nullapart.com`.

Proposed form:

- `za.nullapart.com`;
- `zab.nullapart.com`;
- `eu.nullapart.com`;
- `uk.nullapart.com`;
- `us.nullapart.com`.

The public corporate landing exists at `nullapart.com`. It carries no customer,
operator or runtime data. Administrator sign-in starts at `nullapart.com/login`
and routes the administrator to the selected deployment.

## Mail DNS

Proposed host naming examples:

- `mx1.za.nullapart.com`;
- `mx2.za.nullapart.com`;
- `relay1.za.nullapart.com`;
- `mx1.zab.nullapart.com`.

Exact MX priority/topology remains a deployment decision.

Public outbound SMTP node names/PTR identities may use more specific numbered hostnames where required for reputation and troubleshooting.

## Login region/deployment selector

The main login experience selects the deployment before authentication.

If only one deployment exists within a region, the UI can collapse redundant choices while still resolving to a specific deployment.

The selected deployment determines the identity/control endpoint; it does not create a cross-region data session.

## Node naming

Examples:

- `mxin-za-a-01`;
- `mxout-za-a-01`;
- `mailcore-za-a-01`;
- `scan-malware-za-a-01`;
- `scan-doc-za-a-02`;
- `scan-url-eu-a-01`.

Every runtime records a unique logical node identity and numbered hostname.

Also record the current AWS runtime identity and IP address. Private IP addresses may change in container/orchestrated environments, so IP is an observed network attribute rather than the sole canonical identity.

Internet-facing outbound SMTP nodes require stable public IP identity and PTR/rDNS planning.

## Regional independence

Each deployment has unique URL, DNS, mail infrastructure, database, Redis/Valkey cache, S3 namespace/buckets, OpenBao, ZITADEL, SegLumberjack routing, CloudWatch infrastructure telemetry, Deep AI and n8n deployment as required.

Customer data is not routinely queried across deployments.

## Data residency and integrations

Before data leaves the deployment for any integration, configuration must define allowed data classification, endpoint region, exact fields transmitted, content/PII permission and retention expectations.

Cross-region replication of customer mail/content is disabled by default and requires an explicit architecture/security decision rather than convenience configuration.

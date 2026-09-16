# DMARC and BIMI Platform

## Scope

DMARC/BIMI is a first-class Nullapart product subsystem, not merely an SMTP authentication checkbox.

It combines:

- live Nullapart authentication telemetry;
- customer DMARC aggregate reports;
- DMARC failure reports where available/appropriate;
- customer domain inventory;
- known legitimate sending sources;
- DNS observation;
- BIMI validation;
- MTA-STS/TLS-RPT observation.

## Standards baseline

Target the current DMARC standards:

- RFC 9989 — DMARC policy/authentication model;
- RFC 9990 — aggregate reporting;
- RFC 9991 — failure reporting.

Do not implement new behaviour against obsolete RFC 7489 assumptions where the newer RFCs define different/current behaviour.

## Regional report ingestion

Reports must remain regional.

Suggested regional report addresses use the canonical `nullapart.com` domain, for example:

- `rua@dmarc.za.nullapart.com`;
- `ruf@dmarc.za.nullapart.com` where failure reporting is explicitly enabled;
- `rua@dmarc.zab.nullapart.com`;
- `rua@dmarc.eu.nullapart.com`.

Exact aliases may be adjusted during implementation.

DMARC report mail is routed to the regional DMARC ingestion pipeline rather than ordinary customer delivery.

## External report destination authorization

Nullapart is a third-party Report Consumer for customer domains.

When a customer publishes an external `rua`/report destination on a Nullapart reporting domain, receiving systems may require the RFC-defined external destination authorization lookup.

Nullapart DNS automation must therefore publish the appropriate authorization record for each onboarded customer domain, or use a deliberately reviewed wildcard authorization policy.

Conceptual example:

```text
customer.example._report._dmarc.dmarc.za.nullapart.com TXT "v=DMARC1"
```

The exact owner name is derived from the customer DMARC policy domain and the selected Nullapart report-destination host according to RFC 9990.

Onboarding UI must validate/report whether external report authorization is correctly published rather than simply telling a customer to add `rua=`.

## Ingestion

Use an established maintained open-source parser where suitable rather than writing report parsing from scratch.

All report input is untrusted.

Requirements:

- safe compressed-attachment handling;
- decompression/size limits;
- XML parser hardening;
- duplicate report detection;
- report/source validation;
- tenant/domain mapping;
- idempotent ingestion;
- parser version telemetry;
- malformed report quarantine.

## Aggregate vs failure reports

Aggregate reports primarily contain structured authentication/source statistics.

Failure reports can contain substantially more sensitive message/header/content information depending on the reporting implementation and policy.

Therefore failure-report (`ruf`) handling has stricter controls:

- explicit tenant/System feature policy;
- regional storage only;
- restricted RBAC;
- shorter/dedicated retention where appropriate;
- no body/header content in SegLumberjack/ClickUp;
- no automatic Deep-AI training use;
- secure hostile-content rendering rules if administrators inspect supplied message samples.

## Live telemetry

For mail observed by Nullapart record at least:

- source IP;
- ASN/country where permitted;
- envelope sender domain;
- header From domain;
- SPF result/alignment;
- DKIM result/domain/selector/alignment;
- DMARC result/policy;
- ARC validation where applicable;
- disposition;
- customer ID;
- region/deployment.

## Dashboard

Customer-facing views should present understandable data rather than raw XML.

Core metrics:

- DMARC compliance;
- SPF alignment;
- DKIM alignment;
- message volume;
- authorized vs unknown sending sources;
- failing sources;
- top sender IPs/ASNs/countries;
- failure reasons;
- spoofing/abuse trends;
- current DMARC policy;
- policy readiness/progression;
- external report authorization health.

## Domain source inventory

Nullapart should help customers classify observed sources:

- authorized;
- expected but not yet authorized;
- unknown;
- suspicious;
- malicious;
- third-party sender.

Support/System Admin can assist customers with source classification and policy progression.

## BIMI

Per domain track:

- BIMI DNS record;
- selector;
- logo URL;
- SVG validation;
- DMARC enforcement prerequisite status;
- certificate/authority state where applicable;
- last validation time;
- errors/warnings.

BIMI readiness requires DMARC enforcement rather than `p=none` or partial policy application. The dashboard should verify the relevant organizational/subdomain DMARC policy is at `quarantine` or `reject` and is fully applied as required by current BIMI guidance.

BIMI SVG validation must treat the logo as untrusted active content and enforce the appropriate secure BIMI SVG profile rather than displaying arbitrary SVG directly in the trusted control-plane DOM.

BIMI is shown with SPF, DKIM and DMARC in the Domain Security experience.

## Domain observer

Periodically observe:

- MX;
- SPF;
- known DKIM selectors;
- DMARC;
- DMARC external report authorization;
- BIMI;
- MTA-STS;
- TLS-RPT.

Persist configuration history so administrators can see when security posture changed.

## Notifications

Examples that can generate customer/internal notifications:

- DMARC failure spike;
- new high-volume unknown sender;
- known source loses alignment;
- DMARC record becomes invalid;
- external report authorization becomes invalid;
- BIMI breaks;
- DKIM selector stops resolving;
- MTA-STS/TLS-RPT configuration degrades.

Notification routing follows the standard Nullapart notification matrix and regional data rules.

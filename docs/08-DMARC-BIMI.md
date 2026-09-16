# DMARC and BIMI Platform

## Scope

DMARC/BIMI is a first-class Nullapart product subsystem, not merely an SMTP authentication checkbox.

It combines:

- live Nullapart authentication telemetry;
- customer DMARC aggregate reports;
- failure/forensic-style reports where applicable;
- customer domain inventory;
- known legitimate sending sources;
- DNS observation;
- BIMI validation;
- MTA-STS/TLS-RPT observation.

## Regional report ingestion

Reports must remain regional.

Suggested regional report addresses use the canonical `nullapart.com` domain, for example:

- `rua@dmarc.za.nullapart.com`;
- `ruf@dmarc.za.nullapart.com`;
- `rua@dmarc.zab.nullapart.com`;
- `rua@dmarc.eu.nullapart.com`.

Exact aliases may be adjusted during implementation.

DMARC report mail is routed to the regional DMARC ingestion pipeline rather than ordinary customer delivery.

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
- policy readiness/progression.

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
- DMARC prerequisite status;
- certificate/authority state where applicable;
- last validation time;
- errors/warnings.

BIMI is shown with SPF, DKIM and DMARC in the Domain Security experience.

## Domain observer

Periodically observe:

- MX;
- SPF;
- known DKIM selectors;
- DMARC;
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
- BIMI breaks;
- DKIM selector stops resolving;
- MTA-STS/TLS-RPT configuration degrades.

Notification routing follows the standard Nullapart notification matrix and regional data rules.

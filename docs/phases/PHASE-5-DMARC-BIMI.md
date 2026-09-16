# Phase 5 — DMARC, BIMI and Domain Security

## Objective

Deliver a first-class domain-authentication and reporting platform combining live gateway telemetry, DMARC reports, DNS observations, source attribution and BIMI/domain-security status.

## Prerequisites

- customer/domain Control Plane exists;
- trusted SPF/DKIM/DMARC observations are generated;
- regional mail/report ingestion exists;
- tenant/RBAC/data retention rules exist.

## Standards baseline

Implement current standards:

- RFC 9989;
- RFC 9990;
- RFC 9991;
- BIMI guidance/current specification set;
- MTA-STS/TLS-RPT where supported.

Do not build against obsolete assumptions from RFC 7489 where superseded.

## Report ingestion

Implement regional:

- aggregate report mailbox/ingress;
- safe compressed attachment handling;
- size/decompression limits;
- hardened XML parser;
- duplicate detection;
- idempotency;
- report/domain mapping;
- malformed report quarantine.

Use maintained open-source parsing where suitable.

## External destination authorization

Because Nullapart is a third-party report consumer:

- generate/maintain required authorization DNS;
- validate authorization;
- show status in UI;
- alert when broken.

Do not merely tell a customer to publish `rua` and assume reports will arrive.

## Failure reports

Treat failure reports as potentially content-bearing RESTRICTED data.

Requirements:

- explicit feature policy;
- stricter RBAC;
- regional storage;
- dedicated retention;
- hostile-content rendering controls;
- no raw content in SegLumberjack/ClickUp;
- no automatic training use.

## Live authentication telemetry

Store/aggregate:

- source IP;
- ASN/country if permitted;
- envelope/header domains;
- SPF/alignment;
- DKIM domain/selector/alignment;
- DMARC policy/result;
- ARC status;
- disposition;
- volume/time;
- customer/domain.

## Source attribution

Allow source classification:

- authorized;
- expected but incomplete;
- unknown;
- suspicious;
- malicious;
- third-party service.

Maintain history of source classification changes.

## Dashboard/UI

Build:

- compliance overview;
- SPF/DKIM alignment;
- DMARC volume;
- known/unknown sources;
- failure reasons;
- top IP/ASN/country;
- trend charts;
- policy state/readiness;
- source drill-down;
- external authorization state.

No raw XML as normal UI.

## BIMI

Validate:

- selector/record;
- logo URL;
- secure SVG profile;
- DMARC enforcement prerequisite;
- certificate/evidence state where applicable;
- validation errors;
- last check.

Never render arbitrary SVG in trusted DOM.

## Domain observer

Continuously/periodically inspect:

- MX;
- SPF;
- DKIM selectors;
- DMARC;
- report authorization;
- BIMI;
- MTA-STS;
- TLS-RPT.

Persist history and generate meaningful change events.

## Notifications

Examples:

- DMARC failure spike;
- new high-volume unknown source;
- known source loses alignment;
- DMARC invalid/changed;
- report authorization broken;
- DKIM selector failure;
- BIMI invalid;
- MTA-STS/TLS-RPT degraded.

## Security tests

- XML bombs/entity attacks;
- compressed report bombs;
- duplicate reports;
- cross-tenant domain mapping;
- malicious filenames/MIME;
- failure-report hostile content;
- malicious SVG;
- DNS poisoning/stale responses within resolver model;
- external authorization errors.

## Exit criteria

- regional ingestion reliable/idempotent;
- current RFC model implemented;
- external report authorization validated;
- aggregate/failure privacy differences enforced;
- dashboards/source classification useful;
- BIMI rendering safe;
- domain observer/history/alerts functional.

## Not in this phase

- general customer API;
- autonomous DNS modification outside explicitly authorized infrastructure;
- Deep AI required for report processing.

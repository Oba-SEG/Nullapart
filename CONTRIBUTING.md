# Contributing to Nullapart

## Definition of Done

If a feature requires a UI, its UI is implemented and tested at the same time as the backend capability.

Expected completion includes, where applicable:

- backend implementation;
- persistence;
- authentication;
- authorization;
- audit events;
- UI;
- UI validation;
- loading/empty/error states;
- accessibility;
- Sentry instrumentation;
- operational logs;
- unit tests;
- integration tests;
- UI tests;
- security tests;
- documentation/help text.

## No raw JSON UI

Raw JSON editors, payload viewers and API dumps are not accepted as admin UI.

Structured data must be represented through intentionally designed controls, tables, forms, timelines or inspection views.

## Architecture restraint

Do not create a new service simply because a feature is conceptually distinct.

A new process/container must be justified by isolation, different dependencies/runtime, independent horizontal scaling, security boundary, failure-domain separation or resource profile.

## Open source first

Use established open-source solutions instead of rebuilding protocol/security infrastructure where a suitable maintained solution exists. AWS managed services may be used where there is no suitable open/free alternative or where operating the equivalent safely creates unnecessary risk.

## Naming

Product and canonical repository name: **Nullapart**.

Primary domain: `nullapart.com`.

Additional supported domains: `nullapart.io`, `nullapart.co`, `nullapart.co.za`.

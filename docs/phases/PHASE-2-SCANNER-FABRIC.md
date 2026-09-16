# Phase 2 — Scanner Fabric and Quarantine

## Objective

Add parallel, resource-bounded security analysis and first-class quarantine/hold without turning scanning into a synchronous microservice chain.

## Prerequisites

- stable Phase 1 after-queue flow;
- SecurityFinding/scanner contract;
- ArtifactStore;
- tenant-message isolation;
- policy disposition contract.

## Scanner orchestration

Mail Core must:

1. normalize MIME once;
2. create immutable artifact references;
3. determine applicable scanners;
4. execute independent scanners concurrently within bounded concurrency;
5. enforce deadlines/resource budgets;
6. aggregate normalized findings;
7. distinguish REQUIRED vs OPTIONAL scanners;
8. pass evidence to policy.

Avoid serial URL/document/OCR chains unless one result is a genuine dependency of another.

## Initial scanner capabilities

Implement/adapt:

- ClamAV malware;
- URL/domain reputation;
- file-type verification;
- archive inspection;
- PDF analysis;
- Office/document analysis;
- static/YARA-like rules;
- image processing;
- OCR;
- QR extraction.

Do not expose engine names in normal customer UI.

## Scanner topology

For each scanner decide:

- in-process/library;
- local subprocess;
- shared container/node.

Document justification based on:

- parser risk;
- dependencies;
- CPU/RAM;
- isolation;
- independent scaling;
- failure impact.

Do not create a network service solely for conceptual neatness.

## Resource safety

Per-scanner profiles define:

- max input;
- expanded bytes;
- recursion/nesting;
- entry/attachment count;
- CPU;
- wall clock;
- memory;
- temp disk;
- OCR pixels/pages;
- URL/redirect count.

Encrypted/password-protected or malformed artifacts produce explicit unscannable/unknown evidence.

## Artifact security

- regional S3 only;
- KMS encryption;
- least-privilege scanner roles;
- short-lived/scoped artifact retrieval;
- cleanup of temp files;
- no base64 attachment movement between services.

## Quarantine

Implement:

- raw MIME/content reference;
- tenant message ID;
- customer-scoped recipients;
- findings;
- policy reason;
- retention;
- release history;
- immutable delivery history;
- trusted reinjection for release.

Release must be authenticated, authorized and audited.

## Hold

Differentiate:

- quarantine: security/policy disposition before delivery;
- operational/security hold;
- optional future HELD_FOR_DEEP_ANALYSIS.

## UI obligations

Build:

- quarantine list/search/filter;
- threat/category/severity;
- message metadata;
- scanner result summaries;
- permitted full-content view;
- release action;
- retention state;
- audit linkage;
- scanner/node operations page.

Customer role permissions control content/release.

Support cannot see body/raw MIME/attachments.

## Security tests

- zip/archive bombs;
- nested archives;
- malformed MIME;
- parser crashes;
- encrypted files;
- mislabeled MIME;
- SVG/HTML active content;
- scanner timeout;
- scanner OOM;
- scanner unavailable;
- direct artifact authorization bypass;
- quarantine cross-tenant access;
- release/reinjection loops.

## Observability

Track:

- per-scanner latency;
- result counts;
- UNKNOWN/ERROR;
- resource-limit violations;
- crash/restart;
- backlog/concurrency;
- quarantine/release counts.

## Exit criteria

- scanner orchestration is parallel/bounded;
- required failure semantics are enforced;
- quarantine/release is tenant-safe and audited;
- parser failure cannot take down Mail Core;
- resource-exhaustion tests pass;
- UI accurately shows normalized findings without engine leakage;
- artifacts remain regional and permission-controlled.

## Not in this phase

- trained inline ML;
- Deep AI;
- mailbox remediation;
- advanced outbound behavioural intelligence.

# Phase 2 — Scanner Topology Decisions

This document records the per-scanner topology decisions required by
[Phase 2 — Scanner Fabric and Quarantine](PHASE-2-SCANNER-FABRIC.md)
(§ Scanner topology) and the justification rules in
[Scanner Fabric architecture](../05-SCANNER-FABRIC.md) (§ Topology rule,
§ Parser isolation).

It is an implementation record, not a new policy source. It must be updated
in the same change that moves an adapter between topologies.

## Decision rule applied

Each capability was placed using the architecture rule: separate only when
justified by isolation, heavy dependencies, independent scaling, security
boundary, parser risk or resource profile; do not create a network service
solely for conceptual neatness.

## Registered runtime topology

Runtime registrations are built in `local_scanner_fabric()`
(`crates/mail-core/src/bin/mailcore-server.rs`).

| Capability | Adapter | Topology | Process boundary | Justification |
| --- | --- | --- | --- | --- |
| Malware | `ClamAvScanner` (`crates/mail-core/src/scanner_adapters.rs`) | shared container/node | separate container, TCP to the ClamAV service | native signature engine with its own memory footprint, update cadence and failure domain; a signature-engine crash or stall must not be attributable to Mail Core |
| MIME normalization, file type, archive, PDF, Office, image, QR, OCR orchestration | `AttachmentAnalysisScanner` (same file) | in-process library | `spawn_blocking` + `catch_unwind` | one normalized MIME parse and one shared resource envelope for every derived check; splitting it into several registrations would re-parse the same MIME tree repeatedly and double-count the same evidence |
| Text extraction (OCR) | `TesseractOcr` inside `AttachmentAnalysisScanner` | local subprocess | one bounded external process per page, `kill_on_drop`, wall-clock timeout, diagnostics discarded | native image decoder with a memory-safety history; the program name is private to the module and can never reach findings, health text or the operations projection |
| Static / YARA-like rules | `StaticRuleScanner` (same file) | in-process library | none required | deterministic byte matching with no unsafe parser, no dependency and no allocation risk beyond the input bound |
| URL / domain reputation | `UrlReputationScanner` (same file) | in-process library | none; `requires_network: false` in the local profile | local denylist comparison only, bounded by `max_url_count`; no egress is required, so no network boundary is opened for it |
| Rspamd milter verdicts | not a Mail Core scanner in Phase 2 | Postfix milter | separate container | the milter runs in the SMTP path; `mailcore-filter` deliberately reports no fabricated milter observations |

## Library-only adapters

`ArchiveSafetyScanner`, `DocumentSafetyScanner`, `ImageSafetyScanner` and
`FileTypeScanner` are implemented and unit-tested in
`crates/mail-core/src/scanner_adapters.rs`, but they are **not** registered at
runtime.

`AttachmentAnalysisScanner` subsumes all four: it performs file-type
verification, archive inspection, PDF analysis, Office/document analysis and
image analysis under one shared budget, and declares that scope in its
scanner capabilities `extra.analysis` field
(`file_type`, `archive`, `pdf`, `office`, `image`, `ocr`, `qr`).

Registering the four alongside the composite would parse the same MIME tree
up to five times per message and emit duplicate findings for the same
evidence, which violates the Phase 2 requirement to normalize MIME once.

They stay in the crate as the reviewed single-purpose alternatives that a
later topology change can register instead of the composite, with no policy
or contract change.

## Resource profiles

Every registration declares, in `local_scanner_fabric()`:

| Field | Local value |
| --- | --- |
| `max_input_bytes` | 50 MiB |
| `timeout` | 10 s wall clock per scanner |
| `max_concurrency` | 2 per scanner instance |
| `limits` | `ScannerResourceLimits::bounded_default(max_input_bytes)` |
| fabric `max_concurrent_scans` | 4 |

The fabric overall deadline is derived from the sum of the per-scanner wall
clocks, so a scan can never outlive the sum of its reviewed deadlines
(`fabric_config` in `crates/mail-core/src/scanner_fabric.rs`).

Within `AttachmentAnalysisScanner` the shared envelope additionally bounds
expanded bytes, nesting depth, attachment/entry count, image pixels, OCR
pages/pixels and URL candidates (`analysis_budget` in
`crates/mail-core/src/scanner_adapters.rs`).

Fail-safe dispositions are server-authoritative: `on_inconclusive` and
`on_suspicious` are `Hold`, `on_threat` is `Quarantine`, and the default
disposition for a failed aggregate is `Hold`
(`crates/mail-core/src/scanner_fabric.rs`, `crates/mail-core/src/scanner_pipeline.rs`).

## Honest isolation limits

- Only ClamAV and OCR run outside the Mail Core process.
- MIME, archive, PDF, Office, image and QR parsing run in-process. They are
  contained by `spawn_blocking` plus `catch_unwind`, so a parser panic becomes
  a typed scanner error, the aggregate becomes inconclusive, and the message
  is held — never classified clean
  (`scanner_panic_is_contained_as_error_evidence`,
  `crates/scanner-sdk/tests/fabric.rs`).
- In-process parsing is **not** a separate failure domain. Moving any adapter
  into its own container is the documented production step from
  [Scanner Fabric architecture](../05-SCANNER-FABRIC.md) § Parser isolation,
  and the common scanner contract allows that relocation without redesigning
  policy or Mail Core.
- The local Phase 2 environment cannot represent production seccomp,
  capability reduction or per-parser cgroups; that evidence remains
  production-environment delivery work, in the same way the S3/KMS artifact
  backend does.

## Network and authority exposure

- No scanner exposes a public or browser-reachable endpoint.
- The ClamAV endpoint is an internal compose service address only.
- Scanner health projections discard adapter-provided messages, so engine
  versions, endpoints and backend failure details never reach the operations
  API (`operation_statuses` in `crates/mail-core/src/scanner_fabric.rs`).
- The operations API returns capability labels, never scanner identifiers.

## Evidence

- Registration and profiles: `crates/mail-core/src/bin/mailcore-server.rs`
  (`local_scanner_fabric`).
- Composite scope declaration:
  `attachment_analysis_identity_capability_labels_composite_scope`,
  `crates/mail-core/src/scanner_adapters.rs`.
- Capability labels:
  `operation_statuses_map_every_known_capability_to_a_customer_safe_label`,
  `crates/mail-core/src/scanner_fabric.rs`.
- Bounded concurrency, deadlines, required-coverage and panic containment:
  `crates/scanner-sdk/tests/fabric.rs`, `crates/mail-core/src/scanner_fabric.rs`.
- Resource limits: `crates/scanner-sdk/src/types.rs` (`bounded_defaults`).

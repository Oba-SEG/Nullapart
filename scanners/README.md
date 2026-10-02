# Scanner Fabric

Scanner implementations do not live in this directory. This directory is
retained only as a pointer so the capability list is not lost.

## Where the scanners are

- Reviewer-facing contract and SDK (profiles, fabric, resource limits,
  coverage rules): `crates/scanner-sdk/`.
- Local adapters and analysis (ClamAV, static rules, URL reputation,
  composite attachment analysis with file-type/archive/PDF/Office/image/OCR/QR):
  `crates/mail-core/src/scanner_adapters.rs`.
- Orchestration, aggregation and fail-safe disposition:
  `crates/mail-core/src/scanner_fabric.rs` and
  `crates/mail-core/src/scanner_pipeline.rs`.
- Runtime registration and profiles: `local_scanner_fabric()` in
  `crates/mail-core/src/bin/mailcore-server.rs`.

## Topology decisions

Per-scanner topology decisions and their justification are recorded in
`docs/phases/PHASE-2-SCANNER-TOPOLOGY.md`.

## Initial logical capabilities

malware, static/YARA-like rules, URL/domain reputation, file-type
verification, archive inspection, PDF analysis, Office/document analysis,
image processing, OCR, QR extraction, and future sandbox/threat-intelligence
adapters.

See `docs/05-SCANNER-FABRIC.md`.

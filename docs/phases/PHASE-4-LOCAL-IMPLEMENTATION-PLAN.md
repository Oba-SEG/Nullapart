# Phase 4 Local Implementation Plan — Inline ML

**Status:** plan active (started 2026-10-01); increments 1, 2 and 3 complete
and evidence-backed below (increment 3 closed 2026-10-02: stage wired behind
`inline_ml_classification`, gates green, profiled, live smoke positive +
fail-closed negative on `.4`).
Increment 2 was resequenced by owner direction:
model fine-tuning comes first (executed on the local workstation `.4`),
inference wiring follows as increment 3. Increment 2 was then redefined by
owner rulings (decisions 13–16): multi-label training over all 13 canonical
`FindingCategory` labels, DistilBERT-class encoder, permissive-only real
sources plus Nullapart-owned synthetic fixtures for the 8 classes without
permissive data, and five agreed baseline targets. Source survey is
complete and approved; dataset fetch/prepare/train/eval/export under the
new architecture is complete (evidence in increment 2 below). Next up:
model registry and audited admin API (increment 4).
Increments are completed and
evidence-backed one at a time; checked work is evidence-backed, not
inferred from the presence of a module.

## Prerequisite check (from `PHASE-4-INLINE-ML.md`)

| Prerequisite | State |
| --- | --- |
| scanner fabric stable | met (Phase 2, fabric/SDK contracts) |
| canonical message/security representation stable | met (Phase 0 contracts: `SecurityFinding`, `ScannerType::InlineMl`) |
| policy accepts normalized findings/evidence | met (`FindingCondition`, `ml_threat_classification` policy family) |
| training-data governance defined | met (`docs/security/06-DATA-CLASSIFICATION.md`, `docs/25-AI-LLM-SKILLS-TOOLS.md`) |
| model registry/versioning approach available | **built in this phase** (increment 4) |

Pre-seeded, unused assets this phase must activate rather than reinvent:

- `ScannerType::InlineMl` (`crates/mail-contracts/src/finding.rs`);
- feature switch `inline_ml_classification`
  (`migrations/014_policy_administration.sql`, scopes
  `system/deployment/tenant`, `kill_switch=true`, server-authoritative);
- policy family `ml_threat_classification` (support-managed);
- `ml/inline/` asset directory (currently README-only).

## Goal and boundaries

Deliver Inline ML exactly as `PHASE-4-INLINE-ML.md` scopes it: a low-latency,
deterministic-to-operate evidence layer. Model output is evidence for policy,
never policy itself, never an autonomous action, never a silent substitution,
never an implicit allow.

```text
increment 1: versioned canonical ML input representation (bounded, deterministic)
increment 2: multi-label threat model — DistilBERT-class encoder fine-tuned on
              the approved permissive dataset mix (+ Nullapart-owned synthetic
              fixtures for the 8 classes with no permissive real data), all
              13 canonical FindingCategory labels, per-class evaluation vs
              agreed targets, exported/quantized to ONNX (all on .4)
increment 3: inference stage + adapter wired behind the inline_ml feature switch
              (explicit unavailable/unknown evidence on any model failure)
increment 4: model registry persistence + audited system admin API
              (approval, activation, rollback)
increment 5: thresholds as policy/config + evidence-to-policy wiring and
              threat-band semantics (Low/Medium/High, no hard-coded thresholds)
increment 6: quarantine release/report/adjudication -> candidate feedback
              records (never direct training; curation required)
increment 7: shadow evaluation + version comparison + rollback rehearsal
increment 8: UI (product-level threat analysis; model evidence diagnostics-only)
increment 9: security test battery + canonical gates + local live evidence + report
```

## Design decisions (recorded)

1. **Input contract — `InlineMlRepresentation` v1.** A bounded, versioned,
   deterministic serialization built from canonical sources only: selected
   normalized headers (From/Reply-To/Return-Path/Subject and friends),
   sender/domain + authentication results, cleaned body text, extracted URLs,
   attachment metadata/findings, bounded OCR/QR text where already available,
   deterministic scanner findings from pass 1, and VIP/tenant context only
   where authorized. Every section size-capped with an explicit truncation
   strategy; representation carries `representation_version`; builder is pure
   and testable without any model.

2. **Two-stage execution, no SDK contract change.** `ScannerFabric::scan`
   runs every registered scanner in one pass, but the phase input contract
   includes deterministic scanner findings — so inference needs pass-1 output.
   Sequence: fabric pass 1 (deterministic scanners) → build representation →
   **second, dedicated single-scanner fabric pass** for the inline-ML adapter
   (own profile, deadline, concurrency, failure synthesis) → merged findings →
   policy. Deterministic scanners are never re-run; the scanner-sdk contract
   stays unchanged.

3. **Optional-enrichment semantics.** Inline ML failure (model missing,
   load/infer error, timeout, malformed output, version mismatch) becomes
   explicit `Unknown`/`Error` evidence via the fabric's existing sanitized
   failure synthesis — never clean, never a substitute model, never blocking
   the deterministic path. Feature switch **off** is a different state: ML
   simply is not evaluated (documented configuration, not failure).

4. **Feature switch is server-authoritative.** `inline_ml_classification`
   (already seeded) resolves per effective scope (system/deployment/tenant per
   `docs/29-TENANT-FEATURE-ROUTING.md`); tenant overrides cannot defeat System
   kill-switch floors. The switch gates capability only — never authorization
   or a shortcut around incomplete security work.

5. **Model runtime is pluggable; ONNX is the deployment path.** An
   `InlineModelRuntime` trait isolates load/infer/health. The ONNX runtime
   implementation (crate added per `docs/26-PACKAGE-COMPATIBILITY.md`, native
   library added to the mailcore image per `docs/23-PATCHING-DEPENDENCY-VERSIONS.md`)
   runs compact quantized CPU inference with bounded latency and no GPU
   dependency. The registry model is a compact encoder fine-tuned on the
   owner-approved data architecture of decision 15 (permissive real data +
   Nullapart-owned synthetic fixtures) — no production or customer message
   data ever enters training (production messages are never automatically
   training data).

6. **Model registry = one audited, system-scoped table + admin API.**
   Migration creates `inline_ml_models` (model ID/version, input schema
   version, training dataset version, code/config commit, metrics,
   approval state, approver, deployment regions, rollout time, rollback
   model). Approval/activation/rollback are system-scoped, RBAC-checked,
   Admin-Audited state transitions (one Admin Audit subsystem — no new one).
   Restricted-role grants follow the established migration guard pattern.

7. **Feedback creates candidates only.** Quarantine release, report and
   adjudication insert `ml_feedback_candidates` rows (source, proposed label,
   curator state). There is no code path from a candidate to training data or
   model state; curation/label validation is a prerequisite for any future
   dataset inclusion (`docs/security/06`). Tests enforce non-self-training.

8. **UI shows product security outcomes.** Customer trace shows threat
   analysis Low/Medium/High, classification/category, confidence band and
   policy consequence with product-neutral labels (`docs/05`). Model names,
   versions and skill metadata appear only in System/internal diagnostics.
   No internal model name in normal customer trace.

9. **Observability is safe metadata only.** Inference duration, model
   version, result category and validation/error state are recordable;
   raw message content never enters telemetry (`docs/25` Observability).

10. **Sequencing — model first (owner direction).** Fine-tune the model
    before wiring inference: training pipeline, evaluation against the
    deterministic baseline, and ONNX export come as increment 2; the
    fabric-stage inference wiring consumes the resulting artifact as
    increment 3. This keeps the stage honest — the wired runtime loads a
    real, evaluated model rather than a placeholder.

11. **Execution locality (owner direction).** All training, data
    preparation, evaluation, and ONNX export run on the local workstation
    `.4` (192.168.8.4) inside `ml/inline/`; no cloud training, no hosted
    training APIs, no external data uploads. Artifacts stay local until
    registered through the audited registry API (increment 4).

12. **Training data (superseded by decisions 13–15 below).** Original
    owner direction: public, GitHub-sourced, license-recorded data only;
    primary candidate `angelfonsecar/phishing-compilation` (MIT, 63,518
    labeled rows `tipo ∈ {phishing, ham}`). That single-source binary setup
    was piloted (see Superseded work) and replaced by the multi-label
    architecture the owner ruled on subsequently.

13. **Label space — all 13 canonical classes (owner ruling).** The model
    is multi-label over every `FindingCategory` variant in
    `crates/mail-contracts/src/finding.rs` (`Malware, Phishing, Spam,
    Spoofing, BusinessEmailCompromise, CredentialHarvest, MaliciousUrl,
    MaliciousAttachment, SuspiciousContent, PolicyViolation, AuthFailure,
    Reputation, Unknown`): sigmoid 13-dim output head; evaluation reports
    precision/recall/F1 per class as `PHASE-4-INLINE-ML.md` requires.
    The owner explicitly rejected splitting the taxonomy into
    trained/untrained tiers.

14. **Encoder — DistilBERT class (owner-approved nomination).** Small,
    efficient threat-detection encoder per `docs/09-ML-DEEP-AI.md`
    (compact encoder, fine-tuned, ONNX, CPU). The earlier
    MiniLM-L12-H384 pilot was **rejected by the owner** as the wrong
    model class; its checkpoint is retained on `.4` only as a measured
    binary reference and is never registered or wired.

15. **Data architecture — permissive-only + Nullapart-owned synthetic
    (owner ruling).** Real training data comes only from license-clean
    sources (verified SPDX-equivalent per source, recorded in
    `ml/inline/DATASET.md`):
    bulk phishing/spam/ham = MeAJOR (Zenodo, CC-BY-4.0, 108,685) +
    angelfonsecar (MIT, 63,518) + zero-day phishing (Kaggle, CC0) +
    isuranga SPAM+Genuine (Kaggle, Apache-2.0, 100,000 incl.
    SPF/DKIM/DMARC columns); Malware seed = `zenodo.15235123`
    (CC-BY-4.0, 624 messages incl. explicit Malware label).
    Copyleft/ShareAlike/no-license sources are **excluded entirely**
    (EPVME GPL-3.0, r-dube BEC AGPL-3.0, Kaggle adversarial-BEC and
    naserabdullahalam CC-BY-SA, Wooyun unlicensed, HF mamtakumar
    "other"). The classes with no permissive real data anywhere —
    `CredentialHarvest`, `MaliciousUrl`, `Spoofing`, `AuthFailure`,
    `MaliciousAttachment`, `PolicyViolation`, `Reputation`, `Unknown`
    — train on **Nullapart-owned synthetic fixtures** (plan decision 5
    mechanism, explicitly revived by the owner; deterministic generator,
    provenance manifest, no customer/production content ever), and the
    two small real seeds `BusinessEmailCompromise` (Pretexting rows) and
    `SuspiciousContent` (Scareware rows) receive fixture augmentation for
    viable evaluation volume. Corrected 2026-10-01: the initial gap list
    omitted `CredentialHarvest`/`MaliciousUrl` and overstated
    BEC/SuspiciousContent as sourceless (their real seeds are small but
    present).

16. **Agreed baseline targets (owner-approved, five).**
    (a) trained classes: per-class P/R/F1 + macro-F1 ≥ 0.90, per-class
    ROC-AUC ≥ 0.97; (b) ham false-positive rate ≤ 1% at the operating
    threshold; (c) beat one-vs-rest TF-IDF/LogReg on the same deduped
    splits by ≥ +0.02 macro-F1; (d) latency p95 ≤ 50 ms CPU (batch 1,
    seq 128, on `.4` i7-4790), artifact ≤ 100 MB int8. Synthetic-supplied
    classes are reported honestly in the model card with their fixture
    counts. Minority/majority class counts recorded per split; dedup =
    ordered global train→validation→test normalized-text dedup.

## Exit criteria mapping

| `PHASE-4-INLINE-ML.md` exit criterion | Where evidenced |
| --- | --- |
| benchmark beats agreed baseline targets | increment 7 harness + honest report of registry model vs deterministic baseline (baseline comparison first measured in increment 2) |
| latency/resource targets | increment 3 profiling (p50/p95 recorded), bounded profile deadlines; export-side CPU latency in increment 2 |
| input/output contract versioned | increments 1–3 |
| runtime failure safe | increment 3 failure battery |
| model registry/rollback works | increment 4 |
| policy treats ML as evidence | increment 5 |
| feedback does not self-train | increment 6 + adversarial test |
| security/privacy evaluation passes | increment 9 battery (adversarial text, HTML noise, prompt-like text, truncation, Unicode/obfuscation, QR/OCR lure, unavailable, malformed representation, version mismatch, tenant-context leakage, training-data authorization) |

## Gates (every increment)

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cd frontend && pnpm check-all`
- ignored DB suite against local Postgres (46 tests today; grows with this phase)

## Increment 1 evidence — versioned input representation

Complete (2026-10-01).

- New module `crates/mail-core/src/inline_ml/representation.rs` (registered
  as `pub mod inline_ml` in `lib.rs`): pure builder
  `build(RepresentationSources) -> InlineMlRepresentation` with
  `representation_version = 1`.
- Contract: allowlisted normalized headers only (subject carried
  separately), sender/domain signals (strict domain label validation,
  whitespace rejection), cleaned text (control-character stripping,
  deterministic HTML stripping with `<script>`/`<style>` content removal and
  entity decoding), bounded URL candidates (case-insensitive scheme/host
  normalization, dedupe, nothing fetched), bounded attachment metadata
  (parity with the trace attachment rule: filename or attachment
  disposition), bounded pass-1 finding summaries, and `vip` context that
  exists only when a caller passes it as authorized.
- Bounds (all explicit consts, truncation recorded): headers 16 × 1024
  chars, subject 256, text 8192 chars (char-boundary safe, `truncated` +
  `original_chars`), URLs 64 × 2048, attachments 32, findings 64, VIP
  principals 8, MIME walk 128 parts / depth 16 / 1 MiB per-part body
  decode (transfer-decoded bytes only — charset-free, no mojibake path),
  65536 chars scanned per part.
- Malformed MIME never panics: `parse_mail` failure is caught via
  `catch_unwind` and recorded as `mime_parsed = false` with an empty-but-
  versioned structure (test uses a leading-space header line, which
  `mailparse` rejects).
- 11 unit tests green, covering: happy-path extraction + allowlist
  exclusion, determinism, char-boundary truncation, control-character
  stripping, URL/header/attachment/finding bounds, malformed MIME,
  HTML noise + entity cleaning, strict email-domain extraction, and
  VIP-context presence semantics.
- Gates (this increment): `cargo fmt --all -- --check` OK;
  `cargo clippy --workspace --all-targets -- -D warnings` OK;
  `cargo test --workspace` OK (mail-core lib 361 passed / 0 failed);
  `pnpm check-all` OK (82/82). No DB-touching change (ignored suite
  unchanged at 46).

## Increment 2 evidence — multi-label model, evaluation, ONNX export

Complete (2026-10-01, all on `.4`, decisions 13–16 honored).

- **Dataset** (`ml/inline/DATASET.md`): five permissive sources fetched and
  SHA-256 pinned; copyleft/ShareAlike/unlicensed sources excluded with
  rulings recorded; `synthetic_fixtures.py` generated 12,000
  Nullapart-owned fixture rows (seed 42, `--per-class 1200`, unique-text
  ratio 1.0); `prepare_dataset.py` produced ordered-global-dedup splits
  train 264,814 / validation 33,101 / test 33,103 (13,809 dropped) with
  per-label, per-source and real-vs-synthetic counts in `stats.json`.
- **Training** (`train.py` defaults: 3 epochs, batch 16, lr 3e-5, seed 42):
  best validation **macro-F1 0.9775**, macro-AUC 0.9999, clean FPR 0.0042,
  train loss 0.0019 (`train-v2.log`, `best_val_metrics.json`); train-time
  per-class thresholds preserved at `thresholds_pre_sweep.npy`.
- **Threshold re-selection (tune-first, validation only):**
  `tune_sweep.py` re-selected `thresholds.npy` on validation across four
  schemes (coarse 0.01–0.99 grid, fine, plateau); the pre-declared tie
  rule chose **S1 coarse** (validation macro-F1 0.9801;
  `tune_sweep_report.json`); test data never participated in selection.
  The run also exposed a defect — `evaluate.py` compared raw logits
  against probability-space thresholds (training and the baseline
  already used sigmoid probabilities). Fixed at the evaluation call
  site and re-measured; the superseded logits-space report is retained
  on `.4` as `eval_report_pre_sweep.json`.
- **Evaluation vs the five agreed targets** (`evaluate.py`,
  `eval_report.json`, corrected run 2026-10-02): macro-F1 **0.9862**
  ≥ 0.90 ✅; per-class AUC min **0.9997** ≥ 0.97 ✅ (no unscorable
  classes); clean FPR **0.0042** ≤ 0.01 ✅; baseline delta
  **+0.0210 ≥ +0.02 ✅** (TF-IDF/LogReg baseline test macro-F1 0.9652,
  unchanged) — **all five targets met**, margin 0.0010 on the baseline
  target disclosed in the model card; latency/artifact targets met on
  the deployment path via export below.
- **Export** (`export_onnx.py`, `export_report.json`): opset 17; int8
  dynamic quantization **64.2 MB ≤ 100 MB ✅**, CPU p95 **41.01 ms ≤ 50 ms
  ✅** (batch 1, seq 128, `.4`, 300 iters), int8 parity mean abs diff
  0.00015 ≤ 0.05 with argmax agreement ✅ — all export targets met. The
  fp32 torch-eager evaluation path (p95 69.37 ms corrected run,
  255.53 MB) is an offline harness and is disclosed as non-compliant on
  both counts.
- **Model card:** `ml/inline/MODEL-CARD.md` — per-class P/R/F1/AUC tables,
  split/fixture counts (12,000 fixtures disclosed with the 8 synthetic-only
  classes flagged), baseline comparison, the tune-first re-measurement
  (target (c) closed at +0.0210 with the evaluation defect fixed and the
  margin disclosed), and all §7 limitations stated honestly. Linked from
  `ml/inline/README.md`.
- **Data-integrity check:** a deploy-time rsync of `ml/` used an incorrect
  exclude (`ml/data` instead of `ml/inline/data`) and overwrote the remote
  fixtures file with a 500-row local test copy. Detected by cross-checking
  `prepare-v2.log` (`load_synthetic: 12000`) against the current file;
  regenerated with the deterministic generator — label counts byte-match
  the training log, proving the trained/evaluated/exported artifacts were
  produced from the correct 12,000-row fixture set. Processed splits,
  metrics and reports were never affected (only `ml/inline/data/**` is
  rsync-reachable; checkpoints are excluded). The local divergent copy was
  removed; future `ml/` syncs must exclude `ml/inline/data/`.
- **Toolchain fixes recorded:** `export_onnx.py` needed `QuantType`
  import, `wrapper.eval()` and `dynamo=False` (dynamo graph fails
  onnxruntime's quantizer shape inference); `onnxscript==0.7.2` installed
  and pinned in `ml/inline/requirements.txt`.
- **Not claimed/next:** artifact is not registered (increment 4),
  no customer data, no external benchmark. Inference wiring is increment 3,
  evidence-backed separately below.

## Increment 3 evidence — inference stage, feature switch, adapter

Complete (2026-10-02). Scope as planned: pass-2 inline ML stage behind
`inline_ml_classification`, one extra single-scanner fabric pass merged
before policy evaluation (owner-confirmed two-stage shape), explicit
unavailable/unknown evidence on model failure.

- **Wiring:** `crates/mail-core/src/inline_ml/` — `model_text.rs`
  (training-parity `compose_model_text`/`clean_text`), `runtime.rs`
  (ort session + tokenizer, fixed 1×128 input contract, sigmoid over the 13
  canonical labels, typed `ModelError`s with `UnavailableRuntime` when the
  model/tokenizer is missing or unloadable), `adapter.rs`
  (`InlineMlScanner`, request params contract key `inline_ml`, provenance
  `inline-ml-v1/{model_version}`, versioned `details` payload), `switch.rs`
  (`FeatureEvaluator`-backed; any switch-read error fails to OFF), `stage.rs`
  (switch gate, pass-2 fabric, `merge_pass2` keeping pass-1 `requires_hold`
  authoritative). Pipeline: `ScanArtifact.params` now carried into every
  `ScanRequest`; `DurableScannerPipeline::with_inline_ml`; the stage runs
  after the pass-1 fabric scan and before `evaluate_policy`.
  `mailcore-server` always constructs the stage from environment — a missing
  model becomes an explicit unavailable runtime, never a silent skip.
- **Compose/deploy:** `compose.local.yml` mailcore env
  (`NULLAPART_INLINE_ML_MODEL_PATH`, `…_TOKENIZER_PATH`, `…_MODEL_ID`,
  `…_MODEL_VERSION`) plus two read-only volume mounts of
  `ml/inline/checkpoints/multilabel-v1/{onnx,model}`. Toolchain: the
  builder gained `g++` (tokenizers → esaxx-rs) and both Dockerfile stages
  moved bookworm → trixie because the ort-prebuilt onnxruntime needs
  glibc ≥ 2.38 (`__isoc23_*`) and a GCC-14 libstdc++; recorded in
  `docs/26-PACKAGE-COMPATIBILITY.md`.
- **Evidence boundary (decided and tested):** successful inference emits
  **no findings** — probabilities land in the versioned
  `ScanResult.details` (not persisted by the Phase-2 scanner-evidence
  schema; persisted success evidence = scanner result row `clean` + duration
  + stage logs). Turning scores into findings/policy is increment 5 by
  design. Any model/runtime failure produces the fabric's Unknown/Medium
  failure finding; the local finding policy then quarantines (fail-closed) —
  reviewed intent; `requires_hold` stays false because the stage is an
  Optional scanner.
- **Text-contract parity:** `compose_model_text` reproduces
  `prepare_dataset.compose_text` exactly (part order, per-part clean+limit,
  `Authentication-Results: ` prefix, final collapse/strip/10,240-char
  truncate). Representation sanitization maps control characters to spaces
  (training `clean_text` parity) while keeping `\n`/`\t`, instead of
  dropping them — evidence test renamed to
  `control_characters_are_neutralized_to_spaces_in_headers_and_text`.
  **Python↔Rust parity run (2026-10-02):** same fixture text, 62 tokens,
  onnxruntime-python vs Rust `ort` — argmax identical (Spam 0.9999560 vs
  0.9999571), all 13 probabilities within 2.2e-8 absolute.
- **Gates:** `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` — all green
  (workspace includes 38 inline-ml unit tests); ignored PostgreSQL suite
  5/5 via SSH tunnel against the `.4` scratch DB: the two Phase-2
  baselines plus `inline_ml_stage_merges_pass2_evidence_when_feature_enabled`,
  `inline_ml_stage_skips_when_deployment_override_disables_feature`,
  `inline_ml_stage_unavailable_runtime_surfaces_explicit_unknown_failure`.
- **Profiling:** ignored harness `tests/inline_ml_profile.rs` (debug build,
  local workstation, real int8 model, n=200) — **p50 8.97 ms, p95 9.21 ms,
  max 9.44 ms** for tokenize + inference, far inside the 750 ms stage
  budget and the 500 ms assertion. Live release container on `.4`: inline
  pass-2 wall time **68 ms** per message (stage log), also inside budget.
  Export-side CPU p95 41.01 ms recorded in increment 2.
- **Live smoke on `.4` (2026-10-02, HMAC-signed `POST /internal/handoff`):**
  - positive (model present): handoff 200, all five scanner rows present,
    `inline-ml-classifier` **clean, required=false, 68 ms**, **0 findings,
    disposition allow, 0 quarantine cases** — scoring alone never changes
    disposition; stage log `pass2_results=1 pass2_findings=0
    pass2_failures=0`;
  - negative (model artifact removed, container restarted): startup WARN
    `model failed to load; runtime is unavailable`, handoff still 200,
    inline row status **unknown**, finding **inline_ml / unknown / medium**,
    disposition **quarantine** + 1 quarantine case (local policy
    fail-closed), stage log `pass2_findings=1 pass2_failures=1`;
  - restored: `inline ml model loaded` again, container healthy.
- **Not claimed (increment 3):** no thresholds/bands or score→policy wiring
  (increment 5), no registry (4), no UI (8), probability vectors not
  persisted (schema change considered with increment 5), profiling is a
  debug build on the local workstation unless stated, no customer data.

## Superseded work — binary pilot (not counted as increment 2)

Before the owner rulings in decisions 13–16, a single-label
phishing-vs-ham pilot was built and run on `.4` against the MIT
`angelfonsecar` corpus only, with a MiniLM-L12-H384 encoder
(`ml/inline/train.py`, `evaluate.py`, dataset prep; checkpoint
`checkpoints/inline-phish-v1`): deduped splits 42,371 / 8,512 / 8,333,
best val F1 0.9886 (AUC 0.9993, epoch 3), test F1 0.9877 vs TF-IDF/LogReg
0.9737. Owner rejected the MiniLM class (decision 14) and superseded the
single-label scope (decision 13) and the single-source dataset (decision
15). The pilot is retained on `.4` only as a measured binary reference;
its tooling is rewritten for the multi-label architecture; nothing from it
is registered, wired, or claimed as an increment-2 result. `export_onnx.py`
was never run in the pilot.

## Not claimed (updated per increment)

- no production-trained or customer-data-derived model in this phase;
- no Deep AI / LLM in the mail hot path (Phase 7 boundary);
- no autonomous remediation or model-driven disposition;
- external benchmark/leaderboard claims — only local harness evidence.

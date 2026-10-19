# Phase 4 Local Implementation Plan — Inline ML

**Status:** complete for the Phase 4 local evidence-layer scope (started
2026-10-01; closed 2026-10-04). Increments 1–9 are implemented and
evidence-backed below. Increment 9 closed on `.4` with migration
`020_inline_ml_feedback_shadow.sql`, release-created feedback candidates,
shadow-evaluation registry evidence, customer-safe threat-analysis trace
projection, Models diagnostics UI, canonical workspace gates, full ignored
PostgreSQL gate, rebuilt `mailcore`/`frontend`, and live API/UI proof.
Increment 5 closed 2026-10-02: thresholds as policy data with publish
validation, scan-time resolution, evidence-to-policy wiring proven end to
end in the ignored suite **and live on `.4`** (authenticated publish 201 →
band findings → quarantine → WARN restored), full ignored PostgreSQL gate
58/58, workspace gates green. Increment 4 closed 2026-10-02: registry table
and audited system admin API with approval/activation/rollback, full ignored
PostgreSQL gate 56/56, workspace gates green. Increment 3 closed
2026-10-02: stage wired behind `inline_ml_classification`, gates green,
profiled, live smoke positive + fail-closed negative on `.4`.
Increment 2 was resequenced by owner direction:
model fine-tuning comes first (executed on the local workstation `.4`),
inference wiring follows as increment 3. Increment 2 was then redefined by
owner rulings (decisions 13–16): multi-label training over all 13 canonical
`FindingCategory` labels, DistilBERT-class encoder, permissive-only real
sources plus Nullapart-owned synthetic fixtures for the 8 classes without
permissive data, and five agreed baseline targets. Source survey is
complete and approved; dataset fetch/prepare/train/eval/export under the
new architecture is complete (evidence in increment 2 below). Increments
were completed and evidence-backed one at a time; checked work is
evidence-backed, not inferred from the presence of a module.

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
   training data). The permissive-only half of that gate was reversed by the
   owner on 2026-10-17 so every catalogued corpus is fetched; the recorded
   license is provenance, not an approval filter. See `ml/inline/DATASET.md`.

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

17. **Thresholds live in policy data (owner ruling, increment 5).**
    Operating points are rows in the existing `ml_threat_classification`
    policy family: one `thresholds` key inside a rule's
    `action.metadata`, published through the existing audited policy API
    (no new endpoint, no schema change, no feature-switch auth
    shortcuts). The stage resolves the active revision at scan time with
    the FeatureSwitchResolver pattern (transaction, server-side RLS
    scope, fail-closed `None`).

18. **Unconfigured is explicit, never invented (owner ruling, feature
    ON, no thresholds).** When the feature runs but no valid threshold
    payload resolves for the scope, the stage logs an explicit `WARN`
    and scores stay evidence-only — no numeric defaults are synthesized
    from anywhere. The runbook step is to publish thresholds through the
    policy API.

19. **All bands feed the existing binary local policy (owner ruling).**
    Thresholds map scores to `Low`/`Medium`/`High` bands (severity on
    the finding, with the score, band and operating points in the
    bounded `details` JSONB), and every non-false-positive finding —
    regardless of band — flows into the reviewed binary
    `local_finding_policy` (finding → quarantine). Bands are severity
    metadata, not a second disposition engine.

## Exit criteria mapping

| `PHASE-4-INLINE-ML.md` exit criterion | Where evidenced |
| --- | --- |
| benchmark beats agreed baseline targets | increment 7 harness + honest report of registry model vs deterministic baseline (baseline comparison first measured in increment 2) |
| latency/resource targets | increment 3 profiling (p50/p95 recorded), bounded profile deadlines; export-side CPU latency in increment 2 |
| input/output contract versioned | increments 1–3 |
| runtime failure safe | increment 3 failure battery |
| model registry/rollback works | increment 4 |
| policy treats ML as evidence | increment 5 (evidenced below) |
| feedback does not self-train | increment 6 + adversarial test |
| security/privacy evaluation passes | increment 9 battery (adversarial text, HTML noise, prompt-like text, truncation, Unicode/obfuscation, QR/OCR lure, unavailable, malformed representation, version mismatch, tenant-context leakage, training-data authorization) |

## Gates (every increment)

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cd frontend && pnpm check-all`
- ignored DB suite against local Postgres (58 tests across 15 suites after
  increment 5; grows with this phase; run serially via SSH tunnel)

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

## Increment 4 evidence — model registry persistence + audited system admin API

Complete (2026-10-02).

- **Persistence:** `migrations/019_inline_ml_models.sql` — one system-scoped
  registry table carrying the tracking fields required by
  `PHASE-4-INLINE-ML.md` (model id/version, input schema version, training
  dataset version, code commit, metrics, approval state/actor/timestamps/
  note, deployment regions, activation actor/timestamps, rollback target,
  deactivation actor/timestamp/reason), CHECK constraints enforcing the
  approval/activation/deactivation/rollback invariants, `UNIQUE
  (deployment_id, model_id, model_version)`, a partial unique index enforcing
  **exactly one active model per deployment**, `ENABLE + FORCE ROW LEVEL
  SECURITY` with a deployment-isolation policy, and the guarded
  `GRANT ... TO nullapart_mailcore` role pattern (mirrored in
  `provision-local-runtime-role.sh`). Applied on `.4` to both the live
  `nullapart` and `nullapart_scratch` databases with `ON_ERROR_STOP=1`;
  the mailcore role's INSERT privilege was verified after the grant.
- **Admin API** (`crates/mail-core/src/model_registry.rs`; router mounted in
  `mailcore-server` after `policy_admin_router`):
  - `GET /api/v1/admin/models` (list), `GET .../:model_id/:model_version`,
    `POST /api/v1/admin/models` (register), `POST .../:model_id/:model_version/approve|reject|activate|rollback`;
  - permissions `models:view` (system_admin + support) and `models:manage`
    (system_admin only) added to `BUILTIN_ROLES` (regenerated on every
    login with `ON CONFLICT DO NOTHING`, so no permission migration is
    needed), plus an explicit `SYSTEM_ADMIN_ROLE` check on every mutation;
  - request order: body + validation → route → idempotency key required on
    every POST → authorize (permission → lifecycle → deployment) →
    `require_system_admin` → step-up plus the shared fail-closed
    permission-change bucket (`HighRiskLimits::permission_change()`, 5
    tokens + burst/min) for approve/activate/rollback only → transaction;
  - idempotency operations `model:register:<id>:<version>`,
    `model:approved|rejected:<id>:<version>`,
    `model:activate:<id>:<version>`, `model:rollback:<deployment>`; a
    completed claim replays the stored response without re-executing;
  - state machine: pending → approved | rejected (terminal); approved →
    activated (records the previous active as `rollback_model_id/version`
    with deactivation reason `superseded`); rollback re-activates only the
    active model's recorded rollback target (409 if the active model has
    none or the requested pair differs), deactivating it with reason
    `rollback`; all other transitions are 409 conflicts;
  - concurrency: transaction-scoped advisory locks
    `inline_ml_models:<deployment>` (activate/rollback) and
    `inline_ml_model:<id>:<version>` (register/approve/reject) plus the
    partial one-active unique index;
  - audit: `AuditEventRecord` + `PostgresAuditStore::insert_record` written
    **in the same transaction** as the mutation for
    `model_registered|model_approved|model_rejected|model_activated|model_rolled_back`,
    and stateless `denied` events for permission/lifecycle/deployment/role/
    step-up refusals; resource `inline_ml_model`, customer id from the
    authenticated context, outcome `success|denied`, safe error codes only.
- **Tests:** 8 unit tests in `model_registry.rs` (transition matrix,
  permission matrices, validation bounds, idempotency operation shapes) plus
  6 ignored PostgreSQL tests (`tests/postgres_model_registry.rs`) covering:
  register→approve→activate lifecycle with in-transaction audit counts and
  idempotent replay (stored response, no duplicate audit), activation
  predecessor recording + rollback restoration, every transition conflict
  (pending activate, approve-after-reject, duplicate register, first
  activation rollback, re-activation), RBAC denials (2 audited denied rows,
  zero side effects), deployment scope fail-closed + cross-deployment list
  separation, and missing-idempotency-key rejection.
- **Gates (2026-10-02):** `cargo fmt --all -- --check` green;
  `cargo clippy --workspace --all-targets -- -D warnings` green;
  `cargo test --workspace` green (398 mail-core lib tests, 0 failures);
  `cd frontend && pnpm check-all` green (84 tests);
  **full ignored PostgreSQL gate 56/56** across all 15 suites, run serially
  via SSH tunnel against the `.4` scratch database.
- **Defects found and fixed during this increment:** the approval/rejection
  UPDATE ran with an unreplaced `{cols}` placeholder (surfaced as HTTP 503;
  fixed); a test fixture used a non-hex digest character (validation
  correctly rejected it); the registry-count test helper now filters by
  deployment explicitly because the owner/superuser test pool bypasses RLS;
  the transition-guard test continues on a fresh router state after the
  deliberately tiny high-risk budget (5/state, shared across conflict-path
  calls) is exhausted.
- **Not claimed (increment 4):** no outbox events (the registry is not yet
  consumed by the runtime; shadow evaluation is increment 7), no live
  authenticated HTTP smoke (the admin API requires a real bearer + session
  pair; the ignored PostgreSQL suite is the established evidence pattern),
  rollback does not move artifacts on disk, no thresholds or score→policy
  wiring (increment 5), no UI (increment 8).

## Increment 5 evidence — thresholds as policy + evidence-to-policy wiring

Complete (2026-10-02).

- **Owner rulings applied:** decisions 17–19 above (policy-data storage,
  explicit-unconfigured semantics, binary local policy for all bands).
- **Payload and validation** (`crates/mail-core/src/inline_ml/thresholds.rs`):
  exactly one metadata key `thresholds` with
  `{"version":1,"classes":{"<snake_case category>":{"low","medium","high"}}}`;
  keys must be canonical `FindingCategory` names (PascalCase labels are
  lowered through `label_to_category`/`category_key` so model labels and
  policy keys can never drift), every value in `(0,1]` and
  `low ≤ medium ≤ high`, version must be the current one. The family
  publish path validates `ml_threat_classification` rules before the
  idempotency claim and before the high-risk bucket:
  invalid payloads → `400 INVALID_THRESHOLDS` with no revision, no audit
  success, no token consumption; a publish **without** threshold metadata
  stays legal (that is the explicit unconfigured state from decision 18).
  Enabled rules win by descending priority (mirrors the rule evaluator
  sort), first definition of a class applies.
- **Scan-time resolution:** `MlThresholdResolver` runs one transaction,
  sets the RLS scope through `policy_admin::set_scope`, reads the active
  tenant revision (`deactivated_at IS NULL`, deployment + customer bound,
  newest revision), and returns `None` for every failure mode (absent
  family revision, invalid payload, scope/database error) — the stage
  logs `inline ml thresholds are not configured for this scope; scores
  remain evidence only...` in that case.
- **No scanner-sdk/fabric contract change:** thresholds ride
  `InlineMlScanParams.thresholds` (stage resolves async → params →
  adapter converts synchronously). `threshold_findings` builds one
  normalized finding per above-threshold configured class: severity =
  band, `description` carries the score and operating points, `details`
  JSONB is bounded (model id/version, category, band, score, thresholds,
  full score vector); the fabric's `escalate_definite_status` promotes
  the scanner row to `threat`. Scores below every operating point and
  classes without a payload never flag — they stay in the result
  details as evidence.
- **Evidence-to-policy proof:** `local_finding_policy` is now `pub` so
  integration tests assert the real production consequence instead of a
  stub. `tests/postgres_scanner_pipeline.rs::inline_ml_scores_become_
  findings_and_quarantine_via_local_policy` seeds the actual
  `ml_threat_classification` revision for the message's scope, runs a
  0.96 malware score through the durable pipeline with
  `process_with_policy(..., |scan| local_finding_policy(scan, ...))`,
  and asserts: disposition `Quarantine`, `quarantine_created`, one
  (`inline_ml`,`malware`) finding with severity/band `high` and the
  score round-tripped in details, scanner row status `threat`, and
  scoped counts (artifact 1, scanner rows 2, findings 1, quarantine 1,
  reinjection envelope 1, disposition `quarantine`).
- **Tests:** 8 resolver/validation/band unit tests + 4 adapter unit
  tests (above-threshold findings with both configured classes,
  below-threshold evidence-only, unconfigured class never flags even at
  0.99, params round-trip without thresholds) + 2 ignored PostgreSQL
  tests (publish validation matrix with no-write-on-refusal and
  success-only audit counts; the end-to-end evidence-to-policy proof
  above). Stage skip/override/unavailable-runtime paths keep their
  existing evidence-only guarantees.
- **Runbook step (decision 18):** publish thresholds through the normal
  audited policy API before relying on findings, e.g.
  `POST /api/v1/policies/ml_threat_classification/revisions` with an
  idempotency key and body `{"rules":[{"...","action":{"disposition":
  "quarantine","reason_code":"QUARANTINE_MALWARE","metadata":
  {"thresholds":{"version":1,"classes":{"malware":{"low":0.4,
  "medium":0.7,"high":0.9}}}}}}]}`; a later publish without the
  metadata key intentionally clears active thresholds (stage returns to
  WARN / evidence-only).
- **Live smoke on `.4` (2026-10-02, HMAC-signed `POST /internal/handoff`
  plus the real authenticated publish API through the local proxy):**
  - unconfigured: handoff 200, explicit stage WARN
    `inline ml thresholds are not configured for this scope; scores
    remain evidence only...`, `pass2_findings=0`, allow — decision 18 at
    runtime;
  - publish #1 (realistic operating points) via `POST /api/v1/
    policies/ml_threat_classification/revisions` as the logged-in
    `system_admin` (session carries `policies:manage` and customer
    `CZA-3`, matching the message scope): **201, revision_number 1**;
  - configured/below-threshold: handoff 200, **no WARN**, `pass2_findings=0`
    — scores stay evidence only under realistic operating points;
  - publish #2 (all 13 classes at `0.001/0.002/0.003`): **201,
    revision_number 2**; handoff 200 with `pass2_findings=3` →
    finding rows `(inline_ml, phishing, high, band=high, score 0.1404)`,
    `(inline_ml, spam, high, band=high, score 0.0170)`,
    `(inline_ml, auth_failure, low, band=low, score 0.0013)`, inline
    scanner row **threat** (required=false), disposition
    **quarantine** + 1 quarantine case — evidence-to-policy proven live;
  - cleanup: smoke revisions removed (family restored to empty), final
    handoff 200 returns to WARN + `pass2_findings=0`; audit rows from the
    two publishes are retained as the truthful record.
- **Gates (2026-10-02):** `cargo fmt --all -- --check` green;
  `cargo clippy --workspace --all-targets -- -D warnings` green;
  `cargo test --workspace` green (410 mail-core lib tests, 0 failures);
  `cd frontend && pnpm check-all` green (84 tests);
  **full ignored PostgreSQL gate 58/58** across all 15 suites, run
  serially via SSH tunnel against the `.4` scratch database.
- **Not claimed (increment 5):** no threshold editing UI (increment 8 —
  including the explicit confirmation needed when a UI rules publish
  would clear thresholds), no per-class threshold tuning workflow
  (increment 7), no feedback-driven retraining (increment 6), no new
  public endpoint, schema change, or disposition logic beyond the
  existing reviewed binary local policy.

## Increment 6 evidence — feedback candidates, not self-training

Complete (2026-10-04).

- **Persistence:** `migrations/020_inline_ml_feedback_shadow.sql` creates
  `ml_feedback_candidates` with deployment/customer scope, optional
  tenant-message and transaction references (`ON DELETE SET NULL`, so
  feedback evidence does not block message retention), source enum
  (`quarantine_release`, `user_report`, `admin_adjudication`), canonical
  proposed labels plus `false_positive`, curation state
  (`pending|accepted|rejected`), reason/actor fields, curation integrity
  CHECK, deployment/customer RLS with `ENABLE + FORCE ROW LEVEL SECURITY`,
  and a partial unique index for one tenant-message/source candidate.
- **Runtime writer:** `PostgresQuarantineRepository::release` sets both
  `app.current_deployment_id` and `app.current_customer_id`, writes the
  release audit row, inserts a `quarantine_release` candidate with
  proposed label `false_positive`, then writes the release outbox event in
  the same transaction. Idempotent release replay returns the existing case
  without duplicating feedback.
- **Tests:** `tests/postgres_quarantine_release.rs` now asserts the
  feedback row (`quarantine_release`, `false_positive`, `pending`, release
  reason) and count=1. `tests/postgres_quarantine_detail.rs` cleanup covers
  the feedback candidate, and the full ignored suite caught and closed the
  retention FK issue.
- **Security boundary:** there is still no code path from
  `ml_feedback_candidates` to training data, registry state, thresholds, or
  model artifacts. Candidates remain curation inputs only. The table allows
  future `user_report`/`admin_adjudication` producers, but the current
  product flow implemented in this phase is quarantine release; the missing
  user-report/adjudication product workflows are not silently claimed.

## Increment 7 evidence — shadow evaluation, comparison and rollback controls

Complete (2026-10-04).

- **Persistence:** `020_inline_ml_feedback_shadow.sql` creates
  `inline_ml_shadow_evaluations` with deployment RLS, candidate model
  reference, optional active model pair, input schema version, evaluation
  set id, bounded JSON object metrics/comparison, result enum
  (`candidate_better|candidate_worse|inconclusive|rollback_rehearsed`),
  creator and timestamp.
- **Admin API:** `model_registry.rs` adds
  `GET|POST /api/v1/admin/models/:model_id/:model_version/shadow-evaluations`.
  Reads require `models:view`; writes require idempotency,
  `models:manage`, system-admin role and a valid candidate model/input
  schema. If an active model pair is supplied, it must exist and currently
  be active. Writes are audited as `model_shadow_evaluation_recorded`.
- **Rollback controls:** the increment-4 rollback state machine remains in
  force (approved active model records predecessor; rollback reactivates
  only that target), and the shadow result enum can record
  `rollback_rehearsed` evidence. Activation still remains an explicit
  system-admin action; this increment records comparison evidence and does
  not auto-activate candidates.
- **Tests:** `tests/postgres_model_registry.rs` adds
  `shadow_evaluation_records_comparison_evidence_only`, proving live route
  insert/list behavior, active-model reference validation, audit count and
  persisted row count.

## Increment 8 evidence — UI and customer-safe trace projection

Complete (2026-10-04).

- **Customer-safe API projection:** `trace.rs` projects customer-visible
  finding sources to product capability labels (`threat_analysis`,
  `link_analysis`, `malware_analysis`, etc.) and replaces scanner/model
  diagnostic prose with product-level descriptions such as
  `high phishing evidence was recorded for this message.` The trace response
  no longer exposes inline scanner ids, raw scanner engine labels, model
  versions, scores or thresholds in normal customer trace. Unit coverage
  asserts the projection serializes without `inline_ml`, raw scanner IDs,
  score text or model identifiers.
- **Message UI:** `MessageDetail.tsx` adds a Threat analysis card that
  shows band/severity, category and product-level description. The findings
  list labels customer-safe finding sources as product capabilities rather
  than scanner engines. Raw MIME remains behind the existing content
  permission boundary.
- **Model diagnostics UI:** new `/models` route, guarded by `models:view`,
  lists model approval/activation state, rollback target, safe metric
  summaries and latest shadow-evaluation result. Sidebar navigation appears
  only when the session has `models:view`.
- **Threshold publish safeguard:** the policy client now preserves
  `action.metadata` during structured rule edit/publish round-trips, so ML
  thresholds are not silently stripped by the UI. The publish dialog warns
  when a `ml_threat_classification` draft would clear threshold metadata and
  return inline analysis to evidence-only WARN behavior.
- **Tests:** frontend `check-all` now includes 85 tests, including the new
  pure policy metadata preservation test.

## Increment 9 evidence — security battery, gates, local deployment and live proof

Complete (2026-10-04).

- **Workspace gates:** `cargo fmt --all -- --check` green;
  `cargo clippy --workspace --all-targets -- -D warnings` green;
  `cargo test --workspace` green (mail-core lib 413 passed, 1 ignored;
  workspace default suite green); `pnpm --dir frontend check-all` green
  (15 files, 85 tests).
- **Ignored DB gate on `.4`:** full ignored PostgreSQL suite run serially
  through an SSH tunnel against `nullapart_scratch` after migration 020:
  artifact recovery 1, inline ML profile 1, admin/audit/RBAC/customer/OIDC/
  operations/policy/quarantine/reinjection/RLS/scanner-pipeline/trace
  suites all green; model registry now 7/7 with shadow evaluation; scanner
  pipeline 6/6; trace 5/5.
- **Deployment on `.4`:** synced implementation and migration files to
  `ob1@192.168.8.4:/home/ob1/Nullapart`, applied migration 020 to live
  `nullapart` and `nullapart_scratch`, altered the feedback FKs to
  `ON DELETE SET NULL`, refreshed `nullapart_mailcore` grants via
  `provision-local-runtime-role.sh`, rebuilt `mailcore` and `frontend`, and
  recreated both services.
- **Live UI/API proof:** `GET /models` through the local frontend proxy
  returns 200 with basic auth and 401 without it. Local proxy-header login
  projects `models:view` and `models:manage`. The page now exposes the
  existing audited registry operations instead of a read-only dashboard:
  register model, record shadow evaluation, approve, reject, activate and
  rollback. Live registry flow: register active `multilabel-v1/1` 201,
  approve 200, activate 200; register candidate `multilabel-v2/2` 201,
  approve 200; record shadow evaluation 201; list models shows 2 rows with
  `multilabel-v1/1` active; list shadow evaluations for candidate shows
  `candidate_better`.
- **Runtime registry gate proof:** the inline ML stage now verifies that
  `NULLAPART_INLINE_ML_MODEL_ID`/`NULLAPART_INLINE_ML_MODEL_VERSION` names
  the active approved registry row and that the mounted ONNX SHA-256 matches
  `inline_ml_models.artifact_sha256` before loading ONNX Runtime. A missing,
  inactive or mismatched row degrades to the explicit unavailable runtime so
  switch-enabled evaluation surfaces Unknown/Error evidence instead of
  running an unapproved artifact.
- **Live feedback proof:** a live CZA-3 quarantine release returned 200 for
  tenant message `e722273c-6b67-5a29-9737-d22627a28759`; database evidence
  shows feedback candidate
  `quarantine_release|false_positive|pending|Phase 4 live feedback candidate proof`
  and one release outbox event for the idempotency key.
- **Live leak proof:** `GET /api/v1/mail-trace/transaction/
  2b92716d-4c64-5ecb-8196-79491b0df595` returned 200 with three findings,
  each source `threat_analysis`; the JSON contained no `inline_ml`,
  `model_version`, or threshold text.

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
- external benchmark/leaderboard claims — only local harness evidence;
- no per-class threshold tuning wizard; the structured policy UI preserves
  threshold metadata and warns before clearing it, but threshold authoring
  still happens through the reviewed policy payload path;
- no new end-user report/adjudication workflow was invented in this phase;
  the feedback table supports those sources, while the implemented product
  producer is quarantine release.

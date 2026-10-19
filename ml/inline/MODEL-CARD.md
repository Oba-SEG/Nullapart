# MODEL-CARD — mail inline multi-label threat classification

Status: trained, evaluated, and exported on 2026-10-17 — local Apple Silicon Mac (PyTorch MPS),
all 12 catalogued sources, license gate lifted by owner directive (see [DATASET.md](DATASET.md) header).

Machine-readable sources of truth for this release:

- [data/fetch_manifest.json](data/fetch_manifest.json) — 12 pinned sources with digests, byte
  sizes, and file counts for this run.
- `run-logs/mac-fetch-20261017.log` — full fetch log (12 sources).
- `run-logs/mac-prepare-20261017-all.log` — full prepare log (loader counts, dedup, splits).
- `run-logs/mac-train-20261017.log` — full training log (3 epochs, MPS, best val macro-F1 0.9566).
- `run-logs/mac-post-20261017.log` — evaluate → tune_sweep → threshold swap → evaluate → export
  chain log (POST_DONE, all gates green).
- `checkpoints/multilabel-v1/train_metrics.json` — training history and per-epoch validation.
- `checkpoints/multilabel-v1/eval_report.json` — final evaluation with train-time and swept
  thresholds, TF-IDF/LogReg baseline, CPU latency, and target verdicts.
- `checkpoints/multilabel-v1/tune_sweep_report.json` — validation-only threshold sweep (S0–S3,
  chosen scheme, per-scheme test deltas for transparency; test was never used for selection).
- `checkpoints/multilabel-v1/export_report.json` — fp32/int8 ONNX sizes, CPU latency, parity.

## 1. Intended use

Inline classification of inbound mail for Nullapart's security pipeline. The model emits one
probability per threat label; a CPU-side scoring path consumes these probabilities for
downstream policy decisions. It is trained only on labeled historical corpora and synthetic
fixtures — it does not claim detection of novel zero-day content.

## 2. Model details

- Architecture: `distilbert-base-uncased` encoder + 13-label multi-label classification head
  (BCEWithLogits, per-label `pos_weight`).
- Training device: Apple Silicon MPS (`device: mps` in `train_metrics.json`); evaluation export
  path is CPU (ONNX Runtime).
- Epochs 3, batch size 16, learning rate 3e-5, seed 42.
- Best checkpoint: epoch 3, train loss 0.0214, val macro-F1 0.9566
  (`best_val_metrics.json`, `model/`).
- Thresholds: validation-only sweep chose scheme **S1 coarse**
  (`thresholds.npy` = swept values; train-time values preserved as `thresholds_pre_sweep.npy`).
  Chosen per-label thresholds: `[0.010, 0.780, 0.820, 0.940, 0.760, 0.010, 0.010, 0.010, 0.970,
  0.010, 0.950, 0.010, 0.010]` (label order = `stats.json` label order).

## 3. Training data

Twelve sources pinned in `data/fetch_manifest.json` (sizes and digests there). License strings
in the manifest are **provenance only** — the former permissive-only admission gate (Decision-15
of the security foundation hardening work) was lifted by owner directive on 2026-10-17 so that
all catalogued sources could be used for this training run. Sources still excluded: GT malware
feed (owner withdrew it), and URL-only feeds (PhishTank, URLhaus, ISCX URL2016) which are not
email corpora. Full source table, per-source label mappings, EML parsing counts, loader order,
and the strengthened dedup key are documented in [DATASET.md](DATASET.md).

Final splits (seed 42; 275,509 duplicate rows dropped at dedup):

| Split | Rows | Clean | Multi-label | Synthetic-fixture |
| --- | ---: | ---: | ---: | ---: |
| train | 503,968 | 243,786 | 244,000 | 9,598 |
| validation | 62,996 | 30,606 | 31,194 | 1,196 |
| test | 62,996 | 30,465 | 31,325 | 1,206 |

Per-label train counts (real + synthetic): Spam 158,543; Phishing 61,012; AuthFailure 25,089;
Spoofing 24,648; BEC 8,072; SuspiciousContent 1,689; CredentialHarvest 969; MaliciousUrl 958;
PolicyViolation 945; MaliciousAttachment 945; Reputation 940; Unknown 977; Malware 62.

**Synthetic-only labels (disclosure):** CredentialHarvest, MaliciousUrl, MaliciousAttachment,
PolicyViolation, Reputation, and Unknown appear only in the synthetic fixture set (12,000 rows,
generated for this run) — no real labeled seeds exist for them. Perfect test-set scores for
these classes reflect fixture separability, not field performance. Spoofing and AuthFailure
now have large real seeds (EPVME); BEC and SuspiciousContent have small real seeds plus
augmentation.

**Malware is rare** (62/8/7 train/val/test) — single-digit test support; treat its metrics as
directional only.

## 4. Training run (2026-10-17, local Mac)

Validation trajectory (all epochs, train-time thresholds):

| Epoch | Val macro-F1 | Train loss |
| ---: | ---: | ---: |
| 1 | 0.9507 | 0.0961 |
| 2 | 0.9520 | 0.0344 |
| 3 | **0.9566** | 0.0214 |

Final val metrics with swept (S1 coarse) thresholds: macro-F1 0.9588, macro-AUC 0.9990,
clean FPR 0.0027.

## 5. Evaluation (final, swept thresholds; `eval_report.json`)

| Metric | Validation | Test | Gate |
| --- | ---: | ---: | --- |
| Macro-F1 | 0.9588 | **0.9576** | ≥ 0.90 ✅ |
| Macro-AUC | 0.9990 | 0.9995 | per-class ≥ 0.97 ✅ (no violations, no unscorable labels) |
| Clean FPR | 0.0027 | 0.0031 | ≤ 0.01 ✅ |
| vs TF-IDF/LogReg baseline (macro-F1) | 0.9089 | 0.8945 | model beats baseline by ≥ 0.02 ✅ (+0.0631) |
| Torch-eager CPU latency (batch 1, seq 128, fp32) | — | p95 12.16 ms | informational |
| Artifact (fp32 checkpoint) | — | 256.14 MB | informational |

Per-class test metrics (swept thresholds):

| Label | Support | Precision | Recall | F1 | AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| AuthFailure | 3,153 | 0.9686 | 0.9575 | 0.9630 | 0.9995 |
| BusinessEmailCompromise | 1,051 | 0.9264 | 0.9467 | 0.9365 | 0.9997 |
| CredentialHarvest | 116 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| MaliciousAttachment | 111 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| MaliciousUrl | 138 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Malware | 7 | 0.8571 | 0.8571 | 0.8571 | 1.0000 |
| Phishing | 7,709 | 0.8827 | 0.9862 | 0.9316 | 0.9979 |
| PolicyViolation | 122 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Reputation | 135 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Spam | 19,670 | 0.9876 | 0.9399 | 0.9632 | 0.9980 |
| Spoofing | 3,085 | 0.9663 | 0.9579 | 0.9621 | 0.9995 |
| SuspiciousContent | 237 | 0.9615 | 0.7384 | 0.8353 | 0.9987 |
| Unknown | 101 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

## 6. Export (`export_report.json`)

| Artifact | Size | p95 latency (CPU, batch 1, seq 128) |
| --- | ---: | ---: |
| fp32 ONNX (opset 17) | 255.53 MB | (informational) |
| int8 dynamic-quantized ONNX | **64.2 MB** | **7.3 ms** (300 iterations) |

Gates (all ✅): int8 size ≤ 100 MB; int8 p95 ≤ 50 ms; fp32↔int8 parity mean abs diff ≤ 0.01
(observed mean 0.00021, max 0.17806, argmax agreement 253/256 rows — see limitations).

## 7. Honest limitations and risks

- Six labels (CredentialHarvest, MaliciousUrl, MaliciousAttachment, PolicyViolation, Reputation,
  Unknown) are synthetic-only; their perfect scores overstate field capability.
- Malware test support is 7 rows — metrics are not statistically meaningful.
- SuspiciousContent recall is 0.7384 (hardest real class after Phishing/BEC); Phishing
  precision is 0.8827 — some Spam→Phishing confusion remains.
- Reformatted duplicates from `phishing_email.csv` partially escape exact dedup (documented in
  DATASET.md); test contamination is possible but bounded by the strengthened dedup key.
- int8 quantization flips the argmax on 3 of 256 parity rows (max abs diff 0.17806); the mean
  diff is well inside the gate, but downstream consumers should not treat int8 outputs as
  bit-identical to fp32.
- The model is trained only on the listed corpora; novel threats and distribution shift are out
  of scope. This card makes no compliance or certification claim.

## 8. Reproduction (local Mac)

Environment: `/Users/ob/mlvenv` (uv venv, Python 3.14.6; torch MPS wheel). Run from `ml/inline/`
with `~/mlvenv/bin/python`:

```bash
~/mlvenv/bin/python -u fetch_dataset.py > run-logs/mac-fetch.log 2>&1
~/mlvenv/bin/python -u prepare_dataset.py > run-logs/mac-prepare.log 2>&1
nohup ~/mlvenv/bin/python -u train.py > run-logs/mac-train.log 2>&1 < /dev/null &
~/mlvenv/bin/python -u evaluate.py        # baseline + train-time thresholds
~/mlvenv/bin/python -u tune_sweep.py --recompute-probs
# swap chosen_thresholds into thresholds.npy (old → thresholds_pre_sweep.npy)
~/mlvenv/bin/python -u evaluate.py        # final report with swept thresholds
~/mlvenv/bin/python -u export_onnx.py     # CPU export + int8 quantization + parity
```

Lint gate: `~/mlvenv/bin/python -m ruff check .` in `ml/inline/` (config: `pyproject.toml`,
line-length 100; no `ruff format`).

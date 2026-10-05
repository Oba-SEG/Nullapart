# Inline ML

Training/evaluation/export assets for the low-latency Nullapart
multi-label threat classifier (13 canonical `FindingCategory` labels).

The inline model is evidence for policy, not an autonomous mail-disposition
engine.

## Workflow (all executed on `.4`)

| Step | Script | Output |
| --- | --- | --- |
| 1. Fetch + pin | `fetch_dataset.py` | `data/raw/<source>/`, `data/fetch_manifest.json` (per-source SHA-256 pins) |
| 2. Synthetic fixtures | `synthetic_fixtures.py` | `data/synthetic/fixtures.jsonl`, `fixtures_stats.json` |
| 3. Prepare + dedup + split | `prepare_dataset.py` | `data/processed/{train,validation,test}.jsonl`, `stats.json` |
| 4. Fine-tune (DistilBERT-class) | `train.py` | `checkpoints/multilabel-v1/model/`, `train_metrics.json`, `thresholds.npy`, `best_val_metrics.json` |
| 5. Evaluate vs baseline | `evaluate.py` | `eval_report.json` (per-class P/R/F1/AUC, macro-F1, clean FPR, TF-IDF/LogReg delta, CPU latency) |
| 6. Export + quantize | `export_onnx.py` | `checkpoints/multilabel-v1/onnx/{model.onnx, model_int8.onnx}`, `export_report.json` |

Honest results for this run (targets, per-class tables, synthetic
disclosure, known misses): **[`MODEL-CARD.md`](MODEL-CARD.md)**.

Environment: `mlvenv` venv at `/home/ob1/mlvenv` (Python 3.14), packages
pinned in `requirements.txt`. Lint: `ruff check .` (config in
`pyproject.toml`).

## Rules

- Training data is permissive-only public corpora (MIT, CC-BY-4.0, CC0,
  Apache-2.0) plus Nullapart-owned synthetic fixtures, exactly as
  catalogued in `DATASET.md` (plan decision 15). Copyleft/ShareAlike/
  unlicensed corpora are excluded. No customer or production message data
  ever enters training.
- All 13 labels are trained; per-class results are reported in
  `eval_report.json` — never a single headline number. Synthetic-supplied
  classes are disclosed with fixture counts in the model card.
- Artifact stays on `.4`; registration, activation and rollback are
  audited through the model registry API (phase 4 increment 4). The
  local/dev runtime consumes explicit `NULLAPART_INLINE_ML_*` mounted
  artifact paths.
- Model output is evidence for policy — never policy, never an autonomous
  disposition.

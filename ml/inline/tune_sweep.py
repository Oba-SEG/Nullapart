"""Validation-only threshold sweep for multilabel-v1 (target (c) tune-first gate).

Selection uses the validation split ONLY; the test split is scored once per
scheme and reported for transparency, never used to choose. Schemes:

  S0 current   thresholds.npy as trained (reference)
  S1 coarse    per-class val-F1 greedy, grid 0.01..0.99 step 0.01
  S2 fine      per-class val-F1 greedy, grid 0.01..0.99 step 0.005
  S3 plateau   per-class F1 within 0.002 of the per-class best on the S2
               grid -> median candidate (stability-regularized)

The clean-FPR constraint is applied exactly like `train.tune_thresholds`
(global scale on the union of thresholds, only if validation clean FPR
exceeds 1%). The winning scheme is argmax validation macro-F1 (ties go to
the coarser scheme). Writes `checkpoints/multilabel-v1/tune_sweep_report.json`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from evaluate import predict_batched
from train import (
    CLEAN_FPR_TARGET,
    LABELS,
    load_split,
    per_class_metrics,
    sigmoid,
)

ROOT = Path(__file__).resolve().parent
CHECKPOINTS = ROOT / "checkpoints" / "multilabel-v1"


def targets_matrix(rows: list[dict]) -> np.ndarray:
    matrix = np.zeros((len(rows), len(LABELS)), dtype=np.float32)
    for i, row in enumerate(rows):
        for label_index in row["labels"]:
            matrix[i, label_index] = 1.0
    return matrix


def greedy_thresholds(
    probs: np.ndarray,
    targets: np.ndarray,
    grid: np.ndarray,
    plateau_epsilon: float = 0.0,
) -> np.ndarray:
    chosen = np.full(len(LABELS), 0.5, dtype=np.float64)
    for c in range(len(LABELS)):
        support = int(targets[:, c].sum())
        if support < 5:
            continue
        f1s = []
        for t in grid:
            pred = (probs[:, c] >= t).astype(np.float32)
            tp = float(((pred == 1) & (targets[:, c] == 1)).sum())
            fp = float(((pred == 1) & (targets[:, c] == 0)).sum())
            fn = float(((pred == 0) & (targets[:, c] == 1)).sum())
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall)
                else 0.0
            )
            f1s.append(f1)
        f1s = np.asarray(f1s)
        best = float(f1s.max())
        if plateau_epsilon > 0.0:
            candidates = grid[f1s >= best - plateau_epsilon]
            chosen[c] = float(np.median(candidates))
        else:
            chosen[c] = float(grid[int(np.argmax(f1s))])
    return chosen


def apply_fpr_scale(
    probs: np.ndarray, targets: np.ndarray, base: np.ndarray
) -> tuple[np.ndarray, dict]:
    clean_mask = targets.sum(axis=1) == 0
    scale = 1.0
    for scale in np.linspace(1.0, 3.0, 81):
        thresholds = np.minimum(base * scale, 0.99)
        preds = (probs >= thresholds[None, :]).astype(np.float32)
        if not clean_mask.any():
            break
        if float(preds[clean_mask].any(axis=1).mean()) <= CLEAN_FPR_TARGET:
            break
    thresholds = np.minimum(base * scale, 0.99)
    return thresholds.astype(np.float32), {
        "global_scale": round(float(scale), 3),
        "clean_fpr_target": CLEAN_FPR_TARGET,
    }


def load_or_compute_probs(tag: str, rows: list[dict], args) -> np.ndarray:
    cache = CHECKPOINTS / f"probs_{tag}.npy"
    if cache.exists() and not args.recompute_probs:
        print(f"loading cached {cache.name}", flush=True)
        return np.load(cache)
    print(f"computing {tag} probabilities ({len(rows)} rows)...", flush=True)
    import torch
    from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast

    device = torch.device("cpu")
    tokenizer = DistilBertTokenizerFast.from_pretrained(args.model_name)
    model = DistilBertForSequenceClassification.from_pretrained(
        CHECKPOINTS / "model"
    ).to(device)
    logits = predict_batched(model, rows, tokenizer, device, args.batch_size)
    probs = sigmoid(logits).astype(np.float32)
    np.save(cache, probs)
    return probs


def main() -> int:
    parser = argparse.ArgumentParser(description="Validation-only threshold sweep")
    parser.add_argument("--model-name", default="distilbert-base-uncased")
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--recompute-probs", action="store_true")
    args = parser.parse_args()

    val_rows = load_split("validation")
    test_rows = load_split("test")
    val_targets = targets_matrix(val_rows)
    val_probs = load_or_compute_probs("val", val_rows, args)
    test_probs = load_or_compute_probs("test", test_rows, args)

    eval_report = json.loads(
        (CHECKPOINTS / "eval_report.json").read_text(encoding="utf-8")
    )
    baseline_test_f1 = eval_report["baseline"]["test"]["macro_f1"]

    grids = {
        "coarse": np.round(np.arange(0.01, 0.991, 0.01), 4),
        "fine": np.round(np.arange(0.01, 0.991, 0.005), 4),
    }
    schemes: dict[str, np.ndarray] = {}
    schemes["S0 current"] = np.load(CHECKPOINTS / "thresholds.npy").astype(np.float64)
    base_coarse = greedy_thresholds(val_probs, val_targets, grids["coarse"])
    schemes["S1 coarse"], _ = apply_fpr_scale(val_probs, val_targets, base_coarse)
    base_fine = greedy_thresholds(val_probs, val_targets, grids["fine"])
    schemes["S2 fine"], _ = apply_fpr_scale(val_probs, val_targets, base_fine)
    base_plateau = greedy_thresholds(
        val_probs, val_targets, grids["fine"], plateau_epsilon=0.002
    )
    schemes["S3 plateau"], _ = apply_fpr_scale(val_probs, val_targets, base_plateau)

    results = {}
    for name, thresholds in schemes.items():
        val_metrics = per_class_metrics(val_probs, val_rows, thresholds)
        test_metrics = per_class_metrics(test_probs, test_rows, thresholds)
        results[name] = {
            "thresholds": [round(float(t), 4) for t in thresholds],
            "val_macro_f1": val_metrics["macro_f1"],
            "val_clean_fpr": val_metrics["clean_fpr"],
            "test_macro_f1": test_metrics["macro_f1"],
            "test_clean_fpr": test_metrics["clean_fpr"],
            "test_delta_vs_baseline": round(
                test_metrics["macro_f1"] - baseline_test_f1, 4
            ),
            "test_per_class_f1": {
                label: (test_metrics["per_class"][label]["f1"])
                for label in LABELS
            },
        }
        print(
            f"{name:14s} val {val_metrics['macro_f1']:.4f} "
            f"(fpr {val_metrics['clean_fpr']:.4f}) | test "
            f"{test_metrics['macro_f1']:.4f} "
            f"(fpr {test_metrics['clean_fpr']:.4f}) | delta "
            f"{results[name]['test_delta_vs_baseline']:+.4f}",
            flush=True,
        )

    # Selection: highest validation macro-F1; ties within 1e-4 prefer the
    # earlier (coarser / current) scheme. Test results never decide.
    order = list(schemes)
    best_val = max(results[name]["val_macro_f1"] for name in order)
    chosen = next(
        name
        for name in order
        if best_val - results[name]["val_macro_f1"] <= 1e-4
    )
    chosen_result = results[chosen]
    verdict = chosen_result["test_delta_vs_baseline"] >= 0.02

    report = {
        "selection_rule": "argmax validation macro-F1 (ties -> earlier scheme); test never selects",
        "baseline_test_macro_f1": baseline_test_f1,
        "schemes": results,
        "chosen_scheme": chosen,
        "chosen_thresholds": chosen_result["thresholds"],
        "target_c_delta_min": 0.02,
        "target_c_pass": bool(verdict),
        "val_rows": len(val_rows),
        "test_rows": len(test_rows),
    }
    (CHECKPOINTS / "tune_sweep_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(f"chosen: {chosen} | target (c) {'PASS' if verdict else 'FAIL'}", flush=True)
    print(f"report: {CHECKPOINTS / 'tune_sweep_report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

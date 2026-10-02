"""Evaluate the multi-label Inline ML checkpoint against the agreed targets.

Reports per-class P/R/F1/AUC, macro-F1, clean-row FPR, the one-vs-rest
TF-IDF/LogReg baseline on identical splits, target pass/fail flags, and a
CPU latency benchmark (plan decision 16).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast

from train import (
    LABELS,
    MAX_SEQ_LENGTH,
    load_split,
    per_class_metrics,
    sigmoid,
    tune_thresholds,
)

ROOT = Path(__file__).resolve().parent
CHECKPOINTS = ROOT / "checkpoints" / "multilabel-v1"

TARGETS = {
    "macro_f1_min": 0.90,
    "per_class_auc_min": 0.97,
    "clean_fpr_max": 0.01,
    "baseline_delta_min": 0.02,
    "latency_p95_ms_max": 50.0,
    "artifact_mb_max": 100.0,
}


def predict_batched(model, rows, tokenizer, device, batch_size) -> np.ndarray:
    model.eval()
    outputs = []
    with torch.no_grad():
        for start in range(0, len(rows), batch_size):
            chunk = rows[start : start + batch_size]
            texts = [r["text"] for r in chunk]
            encoded = tokenizer(
                texts,
                truncation=True,
                max_length=MAX_SEQ_LENGTH,
                padding=True,
                return_tensors="pt",
            )
            logits = model(
                input_ids=encoded["input_ids"].to(device),
                attention_mask=encoded["attention_mask"].to(device),
            ).logits
            outputs.append(logits.cpu().numpy())
    return np.concatenate(outputs, axis=0)


def run_baseline(train_rows, val_rows, test_rows) -> dict:
    vectorizer = TfidfVectorizer(
        max_features=50_000,
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True,
    )
    x_train = vectorizer.fit_transform([r["text"] for r in train_rows])
    x_val = vectorizer.transform([r["text"] for r in val_rows])
    x_test = vectorizer.transform([r["text"] for r in test_rows])

    def targets_matrix(rows) -> np.ndarray:
        matrix = np.zeros((len(rows), len(LABELS)), dtype=np.float32)
        for i, row in enumerate(rows):
            for label_index in row["labels"]:
                matrix[i, label_index] = 1.0
        return matrix

    y_train = targets_matrix(train_rows)
    classifier = OneVsRestClassifier(
        LogisticRegression(max_iter=1000, class_weight="balanced", C=1.0),
        n_jobs=-1,
    )
    classifier.fit(x_train, y_train)

    def probs(x) -> np.ndarray:
        raw = np.asarray(classifier.decision_function(x))
        if raw.ndim == 1:
            raw = raw[:, None]
        return sigmoid(raw)

    val_probs = probs(x_val)
    thresholds, _ = tune_thresholds(val_probs, val_rows)
    val_metrics = per_class_metrics(val_probs, val_rows, thresholds)
    test_probs = probs(x_test)
    test_metrics = per_class_metrics(test_probs, test_rows, thresholds)
    return {
        "vectorizer_features": int(x_train.shape[1]),
        "val_macro_f1": val_metrics["macro_f1"],
        "test": test_metrics,
    }


def latency_benchmark(model, tokenizer, rows, device, iterations) -> dict:
    model.to("cpu")
    model.eval()
    sample = rows[0]["text"]
    encoded = tokenizer(
        sample,
        truncation=True,
        max_length=MAX_SEQ_LENGTH,
        padding="max_length",
        return_tensors="pt",
    )
    durations = []
    with torch.no_grad():
        for i in range(iterations + 20):
            started = time.perf_counter()
            model(
                input_ids=encoded["input_ids"],
                attention_mask=encoded["attention_mask"],
            )
            if i >= 20:
                durations.append((time.perf_counter() - started) * 1000)
    model.to(device)
    array = np.asarray(durations)
    return {
        "iterations": iterations,
        "p50_ms": round(float(np.percentile(array, 50)), 2),
        "p95_ms": round(float(np.percentile(array, 95)), 2),
        "mean_ms": round(float(array.mean()), 2),
        "device": "cpu",
        "batch": 1,
        "seq_len": MAX_SEQ_LENGTH,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate 13-label Inline ML checkpoint")
    parser.add_argument("--checkpoint", default=str(CHECKPOINTS / "model"))
    parser.add_argument("--thresholds", default=str(CHECKPOINTS / "thresholds.npy"))
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--skip-baseline", action="store_true")
    parser.add_argument("--latency-iters", type=int, default=200)
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    train_rows = load_split("train")
    val_rows = load_split("validation")
    test_rows = load_split("test")
    print(f"rows: train {len(train_rows)} val {len(val_rows)} test {len(test_rows)}")

    tokenizer = DistilBertTokenizerFast.from_pretrained(args.checkpoint)
    model = DistilBertForSequenceClassification.from_pretrained(args.checkpoint).to(device)

    val_logits = predict_batched(model, val_rows, tokenizer, device, args.batch_size)
    val_probs = sigmoid(val_logits)
    thresholds = np.load(args.thresholds)
    val_metrics = per_class_metrics(val_probs, val_rows, thresholds)

    test_logits = predict_batched(model, test_rows, tokenizer, device, args.batch_size)
    test_probs = sigmoid(test_logits)
    test_metrics = per_class_metrics(test_probs, test_rows, thresholds)

    latency = latency_benchmark(model, tokenizer, test_rows, device, args.latency_iters)

    baseline = None
    if not args.skip_baseline:
        print("running TF-IDF/LogReg baseline...", flush=True)
        baseline = run_baseline(train_rows, val_rows, test_rows)
        print(f"baseline val macro-F1: {baseline['val_macro_f1']}", flush=True)

    auc_violations = [
        name
        for name, metrics in test_metrics["per_class"].items()
        if metrics["auc"] is not None and metrics["auc"] < TARGETS["per_class_auc_min"]
    ]
    unscorable = [
        name for name, metrics in test_metrics["per_class"].items() if metrics["auc"] is None
    ]
    baseline_delta = None
    if baseline is not None:
        baseline_delta = round(test_metrics["macro_f1"] - baseline["test"]["macro_f1"], 4)

    artifact_mb = round(
        sum(p.stat().st_size for p in Path(args.checkpoint).rglob("*") if p.is_file())
        / (1024 * 1024),
        2,
    )

    report = {
        "targets": TARGETS,
        "label_order": LABELS,
        "val": val_metrics,
        "test": test_metrics,
        "baseline": baseline,
        "baseline_delta_macro_f1": baseline_delta,
        "latency_cpu": latency,
        "artifact_mb": artifact_mb,
        "auc_violations": auc_violations,
        "auc_unscorable_support_too_small": unscorable,
        "targets_met": {
            "macro_f1_ge_0.90": test_metrics["macro_f1"] >= TARGETS["macro_f1_min"],
            "per_class_auc_ge_0.97": not auc_violations,
            "clean_fpr_le_0.01": test_metrics["clean_fpr"] <= TARGETS["clean_fpr_max"],
            "beats_baseline_by_0.02": (
                baseline_delta is not None
                and baseline_delta >= TARGETS["baseline_delta_min"]
            ),
        },
        "notes": [
            "AUC is unscorable where a class has fewer than 2 test positives or "
            "fewer than 2 negatives; such classes are listed, never silently passed.",
            "Ham/clean FPR uses the union of per-class tuned thresholds with the "
            "clean-row constraint applied on validation.",
        ],
    }
    out = CHECKPOINTS / "eval_report.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["targets_met"], indent=2))
    print(f"test macro-F1 {test_metrics['macro_f1']} | clean FPR "
          f"{test_metrics['clean_fpr']} | delta {baseline_delta} | "
          f"p95 {latency['p95_ms']}ms | artifact {artifact_mb}MB")
    print(f"written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

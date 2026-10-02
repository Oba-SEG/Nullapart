"""Fine-tune a DistilBERT-class encoder for 13-label email threat classification.

Multi-label BCE with capped per-class pos_weight, validation macro-F1 model
selection, per-class threshold tuning with a clean-row FPR constraint, and
JSON metrics for the agreed baseline targets (plan decision 16).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import roc_auc_score
from torch.utils.data import DataLoader, Dataset
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
    get_linear_schedule_with_warmup,
)

ROOT = Path(__file__).resolve().parent
PROCESSED = ROOT / "data" / "processed"
CHECKPOINTS = ROOT / "checkpoints" / "multilabel-v1"

LABELS = [
    "Malware",
    "Phishing",
    "Spam",
    "Spoofing",
    "BusinessEmailCompromise",
    "CredentialHarvest",
    "MaliciousUrl",
    "MaliciousAttachment",
    "SuspiciousContent",
    "PolicyViolation",
    "AuthFailure",
    "Reputation",
    "Unknown",
]

MAX_SEQ_LENGTH = 128
POS_WEIGHT_CAP = 50.0
CLEAN_FPR_TARGET = 0.01


class TextLabelDataset(Dataset):
    def __init__(self, rows: list[dict], tokenizer: DistilBertTokenizerFast) -> None:
        self.rows = rows
        self.tokenizer = tokenizer

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> dict:
        row = self.rows[index]
        encoded = self.tokenizer(
            row["text"],
            truncation=True,
            max_length=MAX_SEQ_LENGTH,
            padding="max_length",
            return_tensors="pt",
        )
        labels = torch.zeros(len(LABELS), dtype=torch.float32)
        for label_index in row["labels"]:
            labels[label_index] = 1.0
        return {
            "input_ids": encoded["input_ids"].squeeze(0),
            "attention_mask": encoded["attention_mask"].squeeze(0),
            "labels": labels,
        }


def load_split(name: str) -> list[dict]:
    path = PROCESSED / f"{name}.jsonl"
    with path.open() as fh:
        return [json.loads(line) for line in fh]


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def compute_pos_weight(train_rows: list[dict]) -> torch.Tensor:
    counts = torch.zeros(len(LABELS))
    for row in train_rows:
        for label_index in row["labels"]:
            counts[label_index] += 1
    total = len(train_rows)
    weight = (total - counts) / counts.clamp(min=1.0)
    return weight.clamp(max=POS_WEIGHT_CAP)


def sigmoid(logits: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(logits, -50, 50)))


@torch.no_grad()
def predict(model, loader: DataLoader, device: torch.device) -> np.ndarray:
    model.eval()
    outputs = []
    for batch in loader:
        logits = model(
            input_ids=batch["input_ids"].to(device),
            attention_mask=batch["attention_mask"].to(device),
        ).logits
        outputs.append(logits.cpu().numpy())
    return np.concatenate(outputs, axis=0)


def per_class_metrics(
    probs: np.ndarray, rows: list[dict], thresholds: np.ndarray
) -> dict:
    targets = np.zeros_like(probs, dtype=np.float32)
    for i, row in enumerate(rows):
        for label_index in row["labels"]:
            targets[i, label_index] = 1.0
    preds = (probs >= thresholds[None, :]).astype(np.float32)
    per_class = {}
    aucs = []
    f1s = []
    for c, name in enumerate(LABELS):
        support = int(targets[:, c].sum())
        if support == 0:
            per_class[name] = {
                "support": 0,
                "f1": None,
                "auc": None,
                "precision": None,
                "recall": None,
            }
            continue
        tp = float(((preds[:, c] == 1) & (targets[:, c] == 1)).sum())
        fp = float(((preds[:, c] == 1) & (targets[:, c] == 0)).sum())
        fn = float(((preds[:, c] == 0) & (targets[:, c] == 1)).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        auc = None
        if support > 1 and (targets[:, c] == 0).sum() > 1:
            auc = float(roc_auc_score(targets[:, c], probs[:, c]))
            aucs.append(auc)
        f1s.append(f1)
        per_class[name] = {
            "support": support,
            "predicted_positive": int(preds[:, c].sum()),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "auc": round(auc, 4) if auc is not None else None,
        }
    clean_mask = targets.sum(axis=1) == 0
    clean_fpr = float(preds[clean_mask].any(axis=1).mean()) if clean_mask.any() else 0.0
    macro_f1 = float(np.mean(f1s)) if f1s else 0.0
    macro_auc = float(np.mean(aucs)) if aucs else None
    return {
        "rows": len(rows),
        "clean_rows": int(clean_mask.sum()),
        "macro_f1": round(macro_f1, 4),
        "macro_auc": round(macro_auc, 4) if macro_auc is not None else None,
        "clean_fpr": round(clean_fpr, 4),
        "per_class": per_class,
    }


def tune_thresholds(probs: np.ndarray, rows: list[dict]) -> tuple[np.ndarray, dict]:
    targets = np.zeros_like(probs, dtype=np.float32)
    for i, row in enumerate(rows):
        for label_index in row["labels"]:
            targets[i, label_index] = 1.0
    base = np.full(len(LABELS), 0.5, dtype=np.float64)
    for c in range(len(LABELS)):
        support = int(targets[:, c].sum())
        if support < 5:
            continue
        candidates = np.linspace(0.05, 0.95, 91)
        best_t, best_f1 = 0.5, -1.0
        for t in candidates:
            pred = (probs[:, c] >= t).astype(np.float32)
            tp = float(((pred == 1) & (targets[:, c] == 1)).sum())
            fp = float(((pred == 1) & (targets[:, c] == 0)).sum())
            fn = float(((pred == 0) & (targets[:, c] == 1)).sum())
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            if f1 > best_f1:
                best_f1, best_t = f1, float(t)
        base[c] = best_t
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
    info = {"global_scale": round(float(scale), 3), "clean_fpr_target": CLEAN_FPR_TARGET}
    return thresholds.astype(np.float32), info


def main() -> int:
    parser = argparse.ArgumentParser(description="Train 13-label Inline ML model")
    parser.add_argument("--model-name", default="distilbert-base-uncased")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=3e-5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--limit-train", type=int, default=0)
    parser.add_argument("--limit-val", type=int, default=0)
    args = parser.parse_args()

    set_seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"device: {device}")

    train_rows = load_split("train")
    val_rows = load_split("validation")
    if args.limit_train:
        train_rows = train_rows[: args.limit_train]
    if args.limit_val:
        val_rows = val_rows[: args.limit_val]
    print(f"train rows: {len(train_rows)} | val rows: {len(val_rows)}")

    tokenizer = DistilBertTokenizerFast.from_pretrained(args.model_name)
    model = DistilBertForSequenceClassification.from_pretrained(
        args.model_name,
        num_labels=len(LABELS),
        problem_type="multi_label_classification",
    ).to(device)

    pos_weight = compute_pos_weight(train_rows).to(device)
    print("pos_weight:", [round(w, 1) for w in pos_weight.tolist()])
    criterion = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    train_loader = DataLoader(
        TextLabelDataset(train_rows, tokenizer),
        batch_size=args.batch_size,
        shuffle=True,
        num_workers=2,
        drop_last=True,
    )
    val_loader = DataLoader(
        TextLabelDataset(val_rows, tokenizer),
        batch_size=args.batch_size * 2,
        shuffle=False,
        num_workers=2,
    )

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    total_steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer, int(total_steps * 0.06), total_steps
    )

    CHECKPOINTS.mkdir(parents=True, exist_ok=True)
    best_score = -1.0
    history = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        started = time.time()
        for step, batch in enumerate(train_loader, start=1):
            optimizer.zero_grad()
            logits = model(
                input_ids=batch["input_ids"].to(device),
                attention_mask=batch["attention_mask"].to(device),
            ).logits
            loss = criterion(logits, batch["labels"].to(device))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            running += float(loss.item())
            if step % 200 == 0:
                print(
                    f"epoch {epoch} step {step}/{len(train_loader)} "
                    f"loss {running / step:.4f} "
                    f"({time.time() - started:.0f}s)",
                    flush=True,
                )

        val_logits = predict(model, val_loader, device)
        val_probs = sigmoid(val_logits)
        thresholds, fpr_info = tune_thresholds(val_probs, val_rows)
        val_metrics = per_class_metrics(val_probs, val_rows, thresholds)
        record = {
            "epoch": epoch,
            "val_macro_f1": val_metrics["macro_f1"],
            "val_macro_auc": val_metrics["macro_auc"],
            "val_clean_fpr": val_metrics["clean_fpr"],
            "train_loss": round(running / max(len(train_loader), 1), 4),
            "fpr_tuning": fpr_info,
        }
        history.append(record)
        print(json.dumps(record), flush=True)
        if val_metrics["macro_f1"] > best_score:
            best_score = val_metrics["macro_f1"]
            model.save_pretrained(CHECKPOINTS / "model")
            tokenizer.save_pretrained(CHECKPOINTS / "model")
            np.save(CHECKPOINTS / "thresholds.npy", thresholds)
            (CHECKPOINTS / "best_val_metrics.json").write_text(
                json.dumps(val_metrics, indent=2, sort_keys=True) + "\n"
            )
            print(f"saved best (macro_f1 {best_score})", flush=True)

    train_report = {
        "model_name": args.model_name,
        "seed": args.seed,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "lr": args.lr,
        "max_seq_length": MAX_SEQ_LENGTH,
        "pos_weight_cap": POS_WEIGHT_CAP,
        "label_order": LABELS,
        "train_rows": len(train_rows),
        "val_rows": len(val_rows),
        "best_val_macro_f1": best_score,
        "history": history,
        "device": str(device),
    }
    (CHECKPOINTS / "train_metrics.json").write_text(
        json.dumps(train_report, indent=2, sort_keys=True) + "\n"
    )
    print(f"best val macro-F1: {best_score}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

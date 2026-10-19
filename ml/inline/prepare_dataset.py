"""Assemble the approved sources into multi-label train/validation/test splits.

Reads only sources pinned in data/fetch_manifest.json, composes training text
in representation-parity shape, applies ordered global dedup train ->
validation -> test, and writes per-split JSONL plus stats.json with
per-class, per-source, and real-vs-synthetic counts.

The permissive-only gate from decision 15 was lifted by the owner on
2026-10-17 (recorded in DATASET.md): every catalogued email corpus is
prepared regardless of license. Label mappings for the newly included
sources are declared in DATASET.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from email import policy as email_policy
from email.parser import BytesParser
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
MANIFEST = ROOT / "data" / "fetch_manifest.json"
PROCESSED = ROOT / "data" / "processed"
FIXTURES = ROOT / "data" / "synthetic" / "fixtures.jsonl"

REQUIRED_SOURCES = [
    "phishing-compilation", "zero-day-phishing", "spam-genuine-auth",
    "meajor", "multiclass-social-engineering",
    "epvme", "wooyun-xss", "bec-r-dube", "bec-adversarial",
    "phishing-email-dataset", "seven-phishing", "curated-email-corpora",
]

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

MAX_BODY_CHARS = 8192
MAX_URLS = 8
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: str, limit: int) -> str:
    try:
        if value is None or pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    text = CONTROL_CHARS.sub(" ", str(value))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def normalize_for_dedup(row: dict) -> str:
    # Case-fold, strip punctuation, and collapse whitespace so that the same
    # message arriving in a differently packaged corpus (re-punctuated or
    # re-spaced upstream merges) still collides and drops.
    joined = f"{row['subject']} {row['body']}".lower()
    joined = re.sub(r"[^\w\s]", " ", joined)
    return re.sub(r"\s+", " ", joined).strip()


def empty_record(source: str, source_detail: str) -> dict:
    return {
        "source": source,
        "source_detail": source_detail,
        "subject": "",
        "body": "",
        "from_display": "",
        "auth": "",
        "urls": [],
        "attachment": None,
        "labels": [],
    }


def apply_labels(record: dict, positive: list[str]) -> None:
    record["labels"] = [name for name in LABELS if name in positive]


def load_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_text())
    missing = [n for n in REQUIRED_SOURCES if n not in manifest["sources"]]
    if missing:
        raise RuntimeError(f"unpinned sources: {missing}")
    return manifest


def load_compilation() -> list[dict]:
    path = RAW / "phishing-compilation" / "PhishFinderDatasetID.unique.csv"
    frame = pd.read_csv(path, low_memory=False)
    rows = []
    for _, r in frame.iterrows():
        record = empty_record("phishing-compilation", str(r.get("dataset", "")))
        record["body"] = clean_text(r["mensaje"], MAX_BODY_CHARS)
        apply_labels(record, ["Phishing"] if r["tipo"] == "phishing" else [])
        if record["body"]:
            rows.append(record)
    return rows


def load_zero_day() -> list[dict]:
    path = RAW / "zero-day-phishing" / "extracted" / "Zero-Day_Phishing_Emails_Corpus.csv"
    frame = pd.read_csv(path, low_memory=False)
    rows = []
    for _, r in frame.iterrows():
        record = empty_record("zero-day-phishing", "corpus")
        record["subject"] = clean_text(r["Subject"], 256)
        record["body"] = clean_text(r["Body"], MAX_BODY_CHARS)
        apply_labels(record, ["Phishing"] if int(r["Label"]) == 1 else [])
        if record["subject"] or record["body"]:
            rows.append(record)
    return rows


def load_spam_genuine() -> list[dict]:
    path = RAW / "spam-genuine-auth" / "extracted" / "email_dataset_100k.csv"
    frame = pd.read_csv(path, low_memory=False)
    rows = []
    for _, r in frame.iterrows():
        record = empty_record("spam-genuine-auth", "simulated-ham-spam")
        record["subject"] = clean_text(r["subject"], 256)
        record["body"] = clean_text(r["body_plain"], MAX_BODY_CHARS)
        record["from_display"] = clean_text(r["from_address"], 256)
        record["auth"] = (
            "Authentication-Results: mx.example.test; "
            f"spf={r['spf_result']}; dkim={r['dkim_result']}; "
            f"dmarc={r['dmarc_result']}"
        )
        apply_labels(record, ["Spam"] if int(r["label"]) == 1 else [])
        if record["subject"] or record["body"]:
            rows.append(record)
    return rows


def load_meajor() -> list[dict]:
    path = RAW / "meajor" / "meajor_cleaned_preprocessed.csv"
    frame = pd.read_csv(path, low_memory=False, usecols=["subject", "body", "label", "source"])
    rows = []
    for _, r in frame.iterrows():
        record = empty_record("meajor", str(r["source"]))
        record["subject"] = clean_text(r["subject"], 256)
        record["body"] = clean_text(r["body"], MAX_BODY_CHARS)
        apply_labels(record, ["Spam"] if float(r["label"]) == 1.0 else [])
        if record["subject"] or record["body"]:
            rows.append(record)
    return rows


MULTICLASS_MAP = {
    "Malware": "Malware",
    "Phishing": "Phishing",
    "Scareware": "SuspiciousContent",
    "Baiting": "Phishing",
    "Pretexting": "BusinessEmailCompromise",
    "NOT-Malicious General Class": "",
}


def load_multiclass() -> list[dict]:
    path = RAW / "multiclass-social-engineering" / "phishing_nlp_dataset.xlsx"
    frame = pd.read_excel(path)
    rows = []
    unparsed = 0
    for _, r in frame.iterrows():
        pieces = []
        for column in ("Corpus", "Labels"):
            value = r.get(column)
            if value is not None and not pd.isna(value):
                pieces.append(str(value))
        joined = "".join(pieces)
        if "\t" not in joined:
            unparsed += 1
            continue
        text, label = joined.rsplit("\t", 1)
        label = label.strip()
        if label not in MULTICLASS_MAP:
            unparsed += 1
            continue
        record = empty_record("multiclass-social-engineering", label)
        record["body"] = clean_text(text, MAX_BODY_CHARS)
        mapped = MULTICLASS_MAP[label]
        apply_labels(record, [mapped] if mapped else [])
        if record["body"]:
            rows.append(record)
    if unparsed:
        raise RuntimeError(f"multiclass rows failed tab parse: {unparsed}")
    return rows


def load_synthetic() -> list[dict]:
    if not FIXTURES.exists():
        raise RuntimeError("synthetic fixtures missing; run synthetic_fixtures.py first")
    rows = []
    with FIXTURES.open() as fh:
        for line in fh:
            raw = json.loads(line)
            record = empty_record("synthetic", raw["source_detail"])
            record["subject"] = clean_text(raw["subject"], 256)
            record["body"] = clean_text(raw["body"], MAX_BODY_CHARS)
            record["from_display"] = clean_text(raw["from_display"], 256)
            record["auth"] = clean_text(raw["auth"], 512)
            record["urls"] = [str(u)[:2048] for u in raw.get("urls", [])][:MAX_URLS]
            record["attachment"] = raw.get("attachment")
            record["labels"] = [n for n in LABELS if n in raw["labels"]]
            rows.append(record)
    return rows


XSS_MARKERS = (b"<script", b"javascript:", b"onerror=", b"onload=", b"<svg")


def load_eml_corpus(source: str, positive: list[str], detect_xss: bool = False) -> list[dict]:
    root = RAW / source / "extracted"
    if not root.is_dir():
        raise RuntimeError(f"extracted EML tree missing for {source}")
    rows = []
    failed = 0
    for path in sorted(root.rglob("*.eml")):
        try:
            data = path.read_bytes()
            msg = BytesParser(policy=email_policy.default).parsebytes(data)
            subject = str(msg.get("subject") or "")
            chosen = None
            for part in msg.walk():
                if part.get_content_maintype() != "text":
                    continue
                if chosen is None or part.get_content_type() == "text/plain":
                    chosen = part
                if part.get_content_type() == "text/plain":
                    break
            body = ""
            if chosen is not None:
                try:
                    body = chosen.get_content()
                except Exception:
                    payload = chosen.get_payload(decode=True) or b""
                    body = payload.decode("utf-8", "replace")
                if isinstance(body, bytes):
                    body = body.decode("utf-8", "replace")
                if chosen.get_content_type() == "text/html":
                    body = re.sub(r"<[^>]+>", " ", body)
        except Exception:
            failed += 1
            continue
        record = empty_record(source, str(path.relative_to(root)))
        record["subject"] = clean_text(subject, 256)
        record["body"] = clean_text(body, MAX_BODY_CHARS)
        labels = list(positive)
        if detect_xss and any(marker in data.lower() for marker in XSS_MARKERS):
            labels.append("SuspiciousContent")
        apply_labels(record, labels)
        if record["subject"] or record["body"]:
            rows.append(record)
    if failed:
        print(f"load_{source}: {failed} unparseable EML files skipped")
    return rows


def load_epvme() -> list[dict]:
    # EPVME attacks forge sender identity and break SPF/DMARC/S-MIME checks;
    # the XSS-payload subset is detected from planted script markers.
    return load_eml_corpus("epvme", ["Spoofing", "AuthFailure"], detect_xss=True)


def load_wooyun() -> list[dict]:
    return load_eml_corpus("wooyun-xss", ["SuspiciousContent"])


def load_bec_r_dube() -> list[dict]:
    root = RAW / "bec-r-dube" / "extracted" / "bec-main" / "data"
    rows = []
    for name in ("BEC-1-human.csv", "BEC-2-human.csv"):
        frame = pd.read_csv(root / name, low_memory=False)
        for _, r in frame.iterrows():
            record = empty_record("bec-r-dube", name)
            record["subject"] = clean_text(r.get("subject", ""), 256)
            record["body"] = clean_text(r.get("body", ""), MAX_BODY_CHARS)
            human = str(r.get("Human", "")).strip().lower()
            apply_labels(record, ["BusinessEmailCompromise"] if human == "positive" else [])
            if record["subject"] or record["body"]:
                rows.append(record)
    return rows


def load_bec_adversarial() -> list[dict]:
    rows = []
    for name in ("synthetic_emails.csv", "synthetic_emails_poisoned.csv"):
        frame = pd.read_csv(RAW / "bec-adversarial" / "extracted" / name, low_memory=False)
        for _, r in frame.iterrows():
            if pd.isna(r["label"]) or int(float(r["label"])) != 1:
                continue
            record = empty_record("bec-adversarial", name)
            record["subject"] = clean_text(r.get("subject", ""), 256)
            record["body"] = clean_text(r.get("body", ""), MAX_BODY_CHARS)
            apply_labels(record, ["BusinessEmailCompromise"])
            if record["subject"] or record["body"]:
                rows.append(record)
    return rows


def load_phishing_email_flat() -> list[dict]:
    # Phish-No-More final merge: single flat spam/legit label over mixed
    # Enron/Ling/CEAS/Nazario/Nigerian/SpamAssassin content. Sampled positives
    # are dominated by classic spam and 419-fraud text -> declared mapping
    # Spam on data evidence (same ruling style as the MeAJOR TREC decision).
    path = RAW / "phishing-email-dataset" / "extracted" / "phishing_email.csv"
    frame = pd.read_csv(path, low_memory=False)
    rows = []
    for _, r in frame.iterrows():
        record = empty_record("phishing-email-dataset", "phish-no-more-final")
        record["body"] = clean_text(r["text_combined"], MAX_BODY_CHARS)
        apply_labels(record, ["Spam"] if int(r["label"]) == 1 else [])
        if record["body"]:
            rows.append(record)
    return rows


SEVEN_PHISHING_MAP = {
    "Assassin": ["Spam"],
    "Enron": ["Spam"],
    "Ling": ["Spam"],
    "TREC-05": ["Spam"],
    "TREC-06": ["Spam"],
    "TREC-07": ["Spam"],
    "CEAS-08": ["Phishing"],
}


def load_seven_phishing() -> list[dict]:
    rows = []
    for split in ("train", "test", "eval"):
        frame = pd.read_parquet(RAW / "seven-phishing" / f"{split}.parquet")
        for _, r in frame.iterrows():
            dataset = str(r["dataset_name"])
            if dataset not in SEVEN_PHISHING_MAP:
                raise RuntimeError(f"unmapped seven-phishing dataset: {dataset}")
            record = empty_record("seven-phishing", f"{split}:{dataset}")
            record["subject"] = clean_text(r.get("subject", ""), 256)
            record["body"] = clean_text(r.get("text", ""), MAX_BODY_CHARS)
            sender = r.get("sender")
            if sender is not None and not pd.isna(sender):
                record["from_display"] = clean_text(sender, 256)
            apply_labels(
                record, SEVEN_PHISHING_MAP[dataset] if int(r["label"]) == 1 else []
            )
            if record["subject"] or record["body"]:
                rows.append(record)
    return rows


CURATED_MAP = {
    "TREC_05.csv": ["Spam"],
    "TREC_06.csv": ["Spam"],
    "TREC_07.csv": ["Spam"],
    "SpamAssasin.csv": ["Spam"],
    "Enron.csv": ["Spam"],
    "Ling.csv": ["Spam"],
    "CEAS_08.csv": ["Phishing"],
    "Nazario.csv": ["Phishing"],
    "Nazario_5.csv": ["Phishing"],
    "Nigerian_5.csv": ["BusinessEmailCompromise"],
    "Nigerian_Fraud.csv": ["BusinessEmailCompromise"],
}


def load_curated() -> list[dict]:
    rows = []
    for filename, positive in CURATED_MAP.items():
        path = RAW / "curated-email-corpora" / filename
        if not path.exists():
            raise RuntimeError(f"curated file missing: {filename}")
        try:
            frame = pd.read_csv(path, low_memory=False)
        except pd.errors.ParserError:
            # TREC_05/06 carry pathological 2MB+ unquoted lines that overflow
            # the C tokenizer; the python tokenizer parses them correctly.
            frame = pd.read_csv(path, engine="python", on_bad_lines="skip")
        kept = 0
        dropped_label = 0
        for _, r in frame.iterrows():
            try:
                label = int(float(r["label"]))
            except (TypeError, ValueError):
                dropped_label += 1
                continue
            record = empty_record("curated-email-corpora", filename)
            record["subject"] = clean_text(r.get("subject", ""), 256)
            record["body"] = clean_text(r.get("body", ""), MAX_BODY_CHARS)
            sender = r.get("sender")
            if sender is not None and not pd.isna(sender):
                record["from_display"] = clean_text(sender, 256)
            apply_labels(record, positive if label == 1 else [])
            if record["subject"] or record["body"]:
                rows.append(record)
                kept += 1
        print(f"  curated {filename}: kept {kept}, dropped unlabeled/misaligned {dropped_label}")
    return rows


def compose_text(row: dict) -> str:
    parts = []
    if row["subject"]:
        parts.append(f"Subject: {row['subject']}")
    if row["from_display"]:
        parts.append(f"From: {row['from_display']}")
    if row["auth"]:
        parts.append(row["auth"])
    if row["urls"]:
        parts.append("URLs: " + " ".join(row["urls"][:MAX_URLS]))
    if row["attachment"]:
        name = row["attachment"].get("filename", "")
        kind = row["attachment"].get("content_type", "")
        parts.append(f"Attachment: {name} ({kind})")
    parts.append(row["body"])
    return clean_text("\n".join(parts), MAX_BODY_CHARS + 2048)


def label_key(row: dict) -> str:
    return ",".join(row["labels"])


def split_counts(rows: list[dict]) -> dict:
    per_label: dict[str, int] = {}
    per_source: dict[str, int] = {}
    synthetic = 0
    multi = 0
    for row in rows:
        if row["source"] == "synthetic":
            synthetic += 1
        per_source[row["source"]] = per_source.get(row["source"], 0) + 1
        for label in row["labels"]:
            per_label[label] = per_label.get(label, 0) + 1
        if len(row["labels"]) > 1:
            multi += 1
    return {
        "rows": len(rows),
        "clean_rows": sum(1 for r in rows if not r["labels"]),
        "multi_label_rows": multi,
        "synthetic_rows": synthetic,
        "per_label": dict(sorted(per_label.items())),
        "per_source": dict(sorted(per_source.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare multi-label Inline ML splits")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--train-frac", type=float, default=0.8)
    parser.add_argument("--val-frac", type=float, default=0.1)
    parser.add_argument(
        "--limit", type=int, default=0, help="cap total rows after shuffle (0 = no cap)"
    )
    args = parser.parse_args()

    load_manifest()

    real_rows: list[dict] = []
    loaders = (
        load_compilation, load_zero_day, load_spam_genuine, load_meajor,
        load_multiclass, load_epvme, load_wooyun, load_bec_r_dube,
        load_bec_adversarial, load_phishing_email_flat, load_seven_phishing,
        load_curated,
    )
    for loader in loaders:
        batch = loader()
        print(f"{loader.__name__}: {len(batch)} rows")
        real_rows.extend(batch)
    synthetic_rows = load_synthetic()
    print(f"load_synthetic: {len(synthetic_rows)} rows")

    seen: set[str] = set()
    deduped: list[dict] = []
    dropped = 0
    for row in real_rows + synthetic_rows:
        key = normalize_for_dedup(row)
        if not key:
            dropped += 1
            continue
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        deduped.append(row)
    print(f"dedup: kept {len(deduped)}, dropped {dropped}")

    rng = random.Random(args.seed)
    rng.shuffle(deduped)
    if args.limit:
        deduped = deduped[: args.limit]

    total = len(deduped)
    n_train = int(total * args.train_frac)
    n_val = int(total * args.val_frac)
    splits = {
        "train": deduped[:n_train],
        "validation": deduped[n_train : n_train + n_val],
        "test": deduped[n_train + n_val :],
    }

    ordered_seen: set[str] = set()
    for name in ("train", "validation", "test"):
        kept = []
        for row in splits[name]:
            key = normalize_for_dedup(row)
            if key in ordered_seen:
                dropped += 1
                continue
            ordered_seen.add(key)
            row["text"] = compose_text(row)
            kept.append(row)
        splits[name] = kept

    missing_labels = {}
    for name, rows in splits.items():
        counts = split_counts(rows)
        absent = [
            label
            for label in LABELS
            if counts["per_label"].get(label, 0) == 0
        ]
        if absent:
            missing_labels[name] = absent

    if missing_labels:
        raise RuntimeError(f"labels missing from splits: {missing_labels}")

    PROCESSED.mkdir(parents=True, exist_ok=True)
    stats = {
        "seed": args.seed,
        "train_frac": args.train_frac,
        "val_frac": args.val_frac,
        "limit": args.limit,
        "label_order": LABELS,
        "dropped_rows": dropped,
        "splits": {name: split_counts(rows) for name, rows in splits.items()},
    }
    (PROCESSED / "stats.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    for name, rows in splits.items():
        out = PROCESSED / f"{name}.jsonl"
        with out.open("w") as fh:
            for row in rows:
                fh.write(
                    json.dumps(
                        {
                            "id": hashlib.sha256(
                                f"{row['source']}|{row['subject']}|{row['body']}".encode()
                            ).hexdigest()[:24],
                            "text": row["text"],
                            "labels": [LABELS.index(lbl) for lbl in row["labels"]],
                            "label_names": row["labels"],
                            "source": row["source"],
                            "source_detail": row["source_detail"],
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
        print(f"{name}: {len(rows)} rows -> {out.name}")
    print(json.dumps(stats["splits"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

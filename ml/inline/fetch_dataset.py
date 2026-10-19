"""Fetch and pin every approved Inline ML training source.

Each source is downloaded once, checksummed into data/fetch_manifest.json,
and verified on every later run. The prepare step refuses sources without a
pin.

The permissive-only license gate from decision 15 was lifted by the owner on
2026-10-17 (recorded in DATASET.md): every catalogued email corpus is fetched
regardless of license so training coverage is complete. License strings below
are SPDX identifiers declared by the operator for each source as provenance
records. They are review-time claims recorded in this pin file, not anything
fetched or verified from the upstream host; a reviewer confirms each
declaration against the upstream page.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
MANIFEST = ROOT / "data" / "fetch_manifest.json"

SOURCES = [
    {
        "name": "meajor",
        "url": "https://zenodo.org/api/records/18471483",
        "kind": "zenodo-record",
        "license": "CC-BY-4.0",
        "description": "MeAJOR merged email assets (TREC05/06/07, Nazario, Nigerian fraud)",
    },
    {
        "name": "phishing-compilation",
        "url": (
            "https://raw.githubusercontent.com/angelfonsecar/"
            "phishing-compilation/master/PhishFinderDatasetID.unique.csv"
        ),
        "kind": "file",
        "license": "MIT",
        "description": "PhishFinder compilation (6 upstream public corpora)",
    },
    {
        "name": "zero-day-phishing",
        "url": (
            "https://www.kaggle.com/api/v1/datasets/download/"
            "mutahirshaukat/zero-day-phishing-emails-corpus"
        ),
        "kind": "zip",
        "license": "CC0",
        "description": "Zero-day phishing emails corpus",
    },
    {
        "name": "spam-genuine-auth",
        "url": (
            "https://www.kaggle.com/api/v1/datasets/download/"
            "isuranga/spam-genuine-mail-contents-dataset"
        ),
        "kind": "zip",
        "license": "Apache-2.0",
        "description": "SPAM + Genuine 100k with SPF/DKIM/DMARC result columns",
    },
    {
        "name": "multiclass-social-engineering",
        "url": "https://zenodo.org/api/records/15235123",
        "kind": "zenodo-record",
        "license": "CC-BY-4.0",
        "description": "Multiclass NLP social-engineering set incl. Malware label",
    },
    {
        "name": "epvme",
        "url": "https://codeload.github.com/sunknighteric/EPVME-Dataset/zip/refs/heads/main",
        "kind": "github-zipball",
        "license": "GPL-3.0-only",
        "description": "EPVME protocol/UI attack EML corpus (49,136 malicious samples)",
    },
    {
        "name": "wooyun-xss",
        "url": "https://codeload.github.com/WhiteRabbitc/Wooyun-Email-XSS-Dataset/zip/refs/heads/master",
        "kind": "github-zipball",
        "license": "NOASSERTION",
        "description": "Wooyun Email XSS malicious EML samples (168, no upstream license)",
    },
    {
        "name": "bec-r-dube",
        "url": "https://codeload.github.com/r-dube/bec/zip/refs/heads/main",
        "kind": "github-zipball",
        "license": "AGPL-3.0-only",
        "description": "BEC-1/BEC-2 human-labeled business email compromise corpus",
    },
    {
        "name": "bec-adversarial",
        "url": (
            "https://www.kaggle.com/api/v1/datasets/download/"
            "yoadjei/adversarial-bec-email-dataset"
        ),
        "kind": "zip",
        "license": "CC-BY-SA-4.0",
        "description": "Adversarial BEC email dataset (4,211)",
    },
    {
        "name": "phishing-email-dataset",
        "url": (
            "https://www.kaggle.com/api/v1/datasets/download/"
            "naserabdullahalam/phishing-email-dataset"
        ),
        "kind": "zip",
        "license": "CC-BY-SA-4.0",
        "description": "Phish No More (Enron/Ling/CEAS/Nazario/Nigerian/SpamAssassin, 82.5k)",
    },
    {
        "name": "seven-phishing",
        "url": "https://huggingface.co/datasets/mamtakumar/seven-phishing-email-datasets",
        "kind": "hf-tree",
        "license": "NOASSERTION",
        "description": "Seven phishing email datasets merged (HF license 'other', ~203k)",
    },
    {
        "name": "curated-email-corpora",
        "url": "https://zenodo.org/api/records/8339691",
        "kind": "zenodo-record",
        "license": "CC-BY-4.0",
        "description": (
            "Curated email corpora CSVs (Enron, SpamAssassin, TREC, CEAS, "
            "Nazario, Ling, Nigerian)"
        ),
    },
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest() -> dict:
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text())
    return {"sources": {}}


def save_manifest(manifest: dict) -> None:
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def download(url: str, dest: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "nullapart-ml-fetch/2"})
    with urllib.request.urlopen(request, timeout=300) as response, dest.open("wb") as out:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)


def extract_zip(zip_path: Path, dest_dir: Path) -> list[str]:
    members = []
    dest_resolved = dest_dir.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (dest_dir / info.filename).resolve()
            if not str(target).startswith(str(dest_resolved)):
                raise RuntimeError(f"zip slip blocked: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                out.write(src.read())
            members.append(str(target.relative_to(dest_dir)))
    return sorted(members)


def fetch_zenodo_files(source: dict, dest_dir: Path) -> list[str]:
    descriptor = dest_dir / "record.json"
    if not descriptor.exists():
        download(source["url"], descriptor)
    record = json.loads(descriptor.read_text())
    fetched = []
    for entry in record.get("files", []):
        name = entry["key"]
        out_path = dest_dir / name
        if not out_path.exists():
            download(entry["links"]["self"], out_path)
        fetched.append(name)
    if not fetched:
        raise RuntimeError(f"zenodo record {source['name']} has no files")
    return sorted(fetched)


def fetch_github_zipball(source: dict, dest_dir: Path) -> list[str]:
    zip_path = dest_dir / "archive.zip"
    if not zip_path.exists():
        download(source["url"], zip_path)
    extracted_dir = dest_dir / "extracted"
    extract_zip(zip_path, extracted_dir)
    # Some repos ship their payload as .zip files inside the zipball (EPVME).
    # Extract nested archives in place, depth-capped against archive bombs.
    for _ in range(3):
        nested = sorted(extracted_dir.rglob("*.zip"))
        if not nested:
            break
        for nested_zip in nested:
            extract_zip(nested_zip, nested_zip.parent)
            nested_zip.unlink()
    else:
        raise RuntimeError(f"nested zip depth exceeded for {source['name']}")
    members = sorted(
        str(p.relative_to(extracted_dir))
        for p in extracted_dir.rglob("*")
        if p.is_file()
    )
    if not members:
        raise RuntimeError(f"github zipball {source['name']} extracted no files")
    return ["archive.zip"] + [f"archive.zip!{m}" for m in members]


def fetch_hf_tree_files(source: dict, dest_dir: Path) -> list[str]:
    dataset_id = "/".join(source["url"].rstrip("/").split("/")[-2:])
    descriptor = dest_dir / "tree.json"
    if not descriptor.exists():
        download(
            f"https://huggingface.co/api/datasets/{dataset_id}/tree/main"
            "?recursive=true",
            descriptor,
        )
    tree = json.loads(descriptor.read_text())
    fetched = []
    for entry in tree:
        if entry.get("type") != "file":
            continue
        path = entry["path"]
        if not path.endswith((".parquet", ".csv", ".jsonl")):
            continue
        out_path = dest_dir / path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if not out_path.exists():
            download(
                f"https://huggingface.co/datasets/{dataset_id}/resolve/main/{path}",
                out_path,
            )
        fetched.append(path)
    if not fetched:
        raise RuntimeError(f"hf tree {source['name']} has no data files")
    return sorted(fetched)


def fetch_source(source: dict, manifest: dict) -> dict:
    dest_dir = RAW / source["name"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    recorded = manifest["sources"].get(source["name"])

    if source["kind"] == "zenodo-record":
        files = fetch_zenodo_files(source, dest_dir)
    elif source["kind"] == "github-zipball":
        files = fetch_github_zipball(source, dest_dir)
    elif source["kind"] == "hf-tree":
        files = fetch_hf_tree_files(source, dest_dir)
    elif source["kind"] == "zip":
        zip_path = dest_dir / "archive.zip"
        if not zip_path.exists():
            download(source["url"], zip_path)
        extracted = extract_zip(zip_path, dest_dir / "extracted")
        files = ["archive.zip"] + [f"archive.zip!{m}" for m in extracted]
    else:
        filename = source["url"].rsplit("/", 1)[-1]
        file_path = dest_dir / filename
        if not file_path.exists():
            download(source["url"], file_path)
        files = [filename]

    # Every file/member is hashed, not just the first. A multi-file source
    # used to be pinned by its first member alone, so a changed second member
    # would go undetected. Zip members live under dest_dir / "extracted" /
    # <relative member path>.
    file_sha256 = {}
    for name in files:
        base, _, member = name.partition("!")
        path = dest_dir / "extracted" / member if member else dest_dir / base
        file_sha256[name] = sha256_file(path)

    digest = file_sha256[files[0]]
    entry = {
        "url": source["url"],
        "license": source["license"],
        "description": source["description"],
        "files": files,
        "primary_sha256": digest,
        "file_sha256": file_sha256,
    }
    if recorded is not None:
        if recorded.get("primary_sha256") != digest:
            raise RuntimeError(
                f"pin mismatch for {source['name']}: "
                f"{recorded.get('primary_sha256')} != {digest}"
            )
        recorded_map = recorded.get("file_sha256") or {}
        for name, want in file_sha256.items():
            have = recorded_map.get(name)
            if have is not None and have != want:
                raise RuntimeError(
                    f"pin mismatch for {source['name']} file {name}: {have} != {want}"
                )
        entry["pinned_at"] = recorded["pinned_at"]
        status = "verified"
    else:
        entry["pinned_at"] = datetime.now(UTC).isoformat()
        status = "pinned"
    manifest["sources"][source["name"]] = entry
    print(f"{source['name']}: {status} {digest[:16]} ({len(files)} files)")
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch and pin Inline ML training sources")
    parser.add_argument("--only", action="append", default=None, help="source name(s) to fetch")
    args = parser.parse_args()

    wanted = [s for s in SOURCES if args.only is None or s["name"] in args.only]
    manifest = load_manifest()
    for source in wanted:
        fetch_source(source, manifest)
        save_manifest(manifest)
    missing = [s["name"] for s in SOURCES if s["name"] not in manifest["sources"]]
    if missing:
        print(f"still unpinned: {', '.join(missing)}")
    else:
        print(f"all {len(SOURCES)} approved sources pinned")
    return 0


if __name__ == "__main__":
    sys.exit(main())

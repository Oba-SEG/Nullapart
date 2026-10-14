"""Fetch and pin every approved Inline ML training source (decision 15).

Each source is downloaded once, checksummed into data/fetch_manifest.json,
and verified on every later run. The prepare step refuses sources without a
pin. Licenses are permissive-only: MIT, CC-BY-4.0, CC0, Apache-2.0.

License strings below are SPDX identifiers declared by the operator for each
approved source. They are review-time claims recorded in this pin file, not
anything fetched or verified from the upstream host; a reviewer confirms each
declaration against the upstream page before the source is approved.
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


def fetch_source(source: dict, manifest: dict) -> dict:
    dest_dir = RAW / source["name"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    recorded = manifest["sources"].get(source["name"])

    if source["kind"] == "zenodo-record":
        files = fetch_zenodo_files(source, dest_dir)
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

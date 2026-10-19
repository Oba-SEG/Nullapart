# Training dataset manifest — Inline ML multi-label threat model (v2)

**Architecture (owner-approved, `PHASE-4-LOCAL-IMPLEMENTATION-PLAN.md`
decisions 13–16):** multi-label over all 13 canonical `FindingCategory`
labels; public third-party corpora + Nullapart-owned synthetic fixtures
for classes without real-world data.

**License gate reversal (owner, 2026-10-17):** decision 15's
permissive-only ruling was lifted by the owner so training coverage is
complete. Every catalogued public email corpus is fetched regardless of
license (copyleft/ShareAlike/unlicensed included); SPDX license strings
are recorded per source as provenance, not as an admission gate. The
withdrawn GT Malware feed and the URL-only feeds stay excluded on
availability/fitness grounds (table below). No customer or production
message data ever enters training.

## Real sources (12, all pinned; license recorded as provenance)

| # | Dataset | Source | License (recorded) | Size | Role | State |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | MeAJOR cleaned corpus | Zenodo `10.5281/zenodo.18471483` | CC-BY-4.0 | 108,685 (label 1: 48,034) | bulk **spam**/benign — verified contents are trec5/6/7 only (Zenodo metadata calls label 1 "phishing"; data evidence says TREC spam corpus → mapped Spam) | **pinned** `5bf5371897ab4e4a` (CSV) |
| 2 | PhishFinder compilation | `github.com/angelfonsecar/phishing-compilation` | MIT | 63,518 (phishing 24,825) | bulk phishing/ham | **pinned** `c9285bf852504f82` |
| 3 | Zero-Day Phishing Emails Corpus | Kaggle `mutahirshaukat/zero-day-phishing-emails-corpus` | CC0 | 60,000 (phishing 30,194 / legit 29,806) | bulk phishing + legit | **pinned** `853094590bd2a40f` |
| 4 | SPAM + Genuine mail contents | Kaggle `isuranga/spam-genuine-mail-contents-dataset` | Apache-2.0 | 100,000 (spam 50,000 / genuine 50,000) | spam/ham + SPF/DKIM/DMARC auth columns (spf=fail share: spam 50% vs genuine 10%) | **pinned** `122c43aa8d482f9a` |
| 5 | Multiclass social-engineering NLP | Zenodo `10.5281/zenodo.15235123` | CC-BY-4.0 | 624 | **Malware** label seed (+ declared mapping below) | **pinned** `651fb58e1a3ff780` |
| 6 | EPVME protocol/UI attack EML | GitHub `sunknighteric/EPVME-Dataset` | GPL-3.0-only | 49,081 rows parsed of 49,136 EML (55 empty) | **Spoofing + AuthFailure** real seed; planted-script rows add SuspiciousContent | **pinned** `d96e71b5e8cbcfd6` |
| 7 | Wooyun Email XSS EML | GitHub `WhiteRabbitc/Wooyun-Email-XSS-Dataset` | NOASSERTION (no upstream license) | 167 of 168 EML | **SuspiciousContent** real seed (email XSS payloads) | **pinned** `db19d37bad574dd7` |
| 8 | BEC-1/BEC-2 human-labeled | GitHub `r-dube/bec` | AGPL-3.0-only | 299 (Human=positive 296 / neutral 3) | **BusinessEmailCompromise** human seed | **pinned** `e5ba53acfe981b8c` |
| 9 | Adversarial BEC email set | Kaggle `yoadjei/adversarial-bec-email-dataset` | CC-BY-SA-4.0 | 8,362 labeled rows (4,181 × 2 files; 60 unlabeled dropped) | **BusinessEmailCompromise** + adversarial perturbation variants | **pinned** `36c3dc54e5d0b0b5` |
| 10 | Phish No More final merge | Kaggle `naserabdullahalam/phishing-email-dataset` | CC-BY-SA-4.0 | 82,485 (label 1: 42,891) | flat spam/legit merge of Enron/Ling/CEAS/Nazario/Nigerian/SpamAssassin → **Spam** on sampled data evidence | **pinned** `3a21343518a3a5e7` |
| 11 | Seven phishing datasets merged | HF `mamtakumar/seven-phishing-email-datasets` | NOASSERTION (license `other`) | 203,017 (train 162,413 / test 20,304 / eval 20,300) | per-corpus Spam (TREC/Enron/Ling/Assassin) + Phishing (CEAS-08) | **pinned** `1e5c6e4d787143c9` |
| 12 | Curated email corpora CSVs | Zenodo `10.5281/zenodo.8339691` | CC-BY-4.0 | 217,231 kept (3,862 unlabeled/misaligned dropped of 221,093) | per-corpus Spam / Phishing / BEC (Nigerian) — adds Enron/SpamAssassin/Ling/CEAS beyond MeAJOR's TREC set | **pinned** `22375e7d5f5a8229` |

Kaggle sources download unauthenticated via
`https://www.kaggle.com/api/v1/datasets/download/<ref>` (302 → signed URL);
no API token required. GitHub sources are fetched as codeload zipballs
(nested `.zip` payloads such as EPVME's eight packages are extracted
recursively, depth-capped at 3). The HF source is fetched file-by-file
from the dataset tree API. Fetch state is machine-recorded in
`ml/inline/data/fetch_manifest.json`; prepare refuses unpinned sources.

### Excluded sources (rulings recorded)

| Source | Why excluded |
| --- | --- |
| GT Malware Unsolicited Email Feed | withdrawn upstream (Quasi-Restricted) — unobtainable |
| PhishTank / URLhaus / ISCX URL2016 | URL-only feeds, not email corpora; terms not clearly commercial-safe |

**Re-included on 2026-10-17** when the owner lifted the decision-15
permissive-only gate (formerly excluded rows, now sources 6–12 above):
EPVME (GPL-3.0), r-dube/bec BEC-1/BEC-2 (AGPL-3.0), Kaggle
`yoadjei/adversarial-bec-email-dataset` (CC-BY-SA-4.0), Kaggle
`naserabdullahalam/phishing-email-dataset` (CC-BY-SA-4.0), Wooyun Email
XSS (no license), HF `mamtakumar/seven-phishing-email-datasets`
(license `other`), Zenodo curated collection `10.5281/zenodo.8339691`
(formerly also ruled "not primary source").

## Synthetic fixtures (Nullapart-owned)

Two groups, both generated by `ml/inline/synthetic_fixtures.py`
(fixed seed, template-composed, no customer/production content):

1. **8 classes that had no real-world source at fixture-generation time
   (plan decision 15):** `CredentialHarvest`, `MaliciousUrl`,
   `Spoofing`, `AuthFailure`, `MaliciousAttachment`, `PolicyViolation`,
   `Reputation`, `Unknown` (earlier list corrected: MaliciousUrl and
   CredentialHarvest were initially missed). After the 2026-10-17
   license-gate reversal, `Spoofing` and `AuthFailure` gained large real
   seeds (EPVME, sources 6) and fixtures remain only as
   augmentation/balance; `CredentialHarvest`, `MaliciousUrl`,
   `MaliciousAttachment`, `PolicyViolation`, `Reputation` and `Unknown`
   still have no real-world source anywhere and remain synthetic-only.
2. **Augmentation of two small real seeds:** `BusinessEmailCompromise`
   and `SuspiciousContent` receive fixtures for viable per-class
   evaluation volume (decision 15's real seeds were Pretexting rows 78
   and Scareware rows 100; both classes now also have substantial real
   rows — BEC from sources 8/9/12, SuspiciousContent from sources 6/7).

- Output: `data/synthetic/fixtures.jsonl` (+ `fixtures_stats.json`),
  rows carry the same record shape as real rows (multi-label vector over
  13 classes); a row may be multi-label (e.g. Spoofing + AuthFailure).
- Every fixture body carries a class-agnostic detail line (reference,
  date, department, city) from shared pools so texts stay distinct under
  the global dedup; the generator fails if unique-text ratio < 0.98.
- Provenance: authorship = Nullapart; license = project-owned; synthetic
  origin flagged per row (`source: "synthetic"`) and disclosed in the
  model card with per-class counts.

## Label mapping (source label → 13-class vector)

Canonical order (`crates/mail-contracts/src/finding.rs`):
`Malware(0), Phishing(1), Spam(2), Spoofing(3),
BusinessEmailCompromise(4), CredentialHarvest(5), MaliciousUrl(6),
MaliciousAttachment(7), SuspiciousContent(8), PolicyViolation(9),
AuthFailure(10), Reputation(11), Unknown(12)`

| Source label | Vector |
| --- | --- |
| MeAJOR `1` (TREC spam positive) | Spam |
| MeAJOR `0` (TREC ham) | all-zero (clean) |
| angelfonsecar `tipo=phishing` | Phishing |
| angelfonsecar `tipo=ham` | all-zero (clean) |
| zero-day `Label=1` (verified phishing subjects) | Phishing |
| zero-day `Label=0` (verified legit subjects) | all-zero (clean) |
| isuranga `label=1` (verified spam subjects) | Spam |
| isuranga `label=0` (verified genuine subjects) | all-zero (clean) |
| zenodo.15235123 `Malware` | Malware |
| zenodo.15235123 `Phishing` | Phishing |
| zenodo.15235123 `Scareware` | SuspiciousContent (declared taxonomy mapping) |
| zenodo.15235123 `Baiting` | Phishing (declared taxonomy mapping) |
| zenodo.15235123 `Pretexting` | BusinessEmailCompromise (declared taxonomy mapping) |
| zenodo.15235123 `NOT-Malicious` | all-zero (clean) |
| EPVME any row | Spoofing + AuthFailure (declared taxonomy mapping: sender-identity forgery that breaks SPF/DMARC/S-MIME checks) |
| EPVME row whose raw EML contains planted script markers (`<script`, `javascript:`, `onerror=`, `onload=`, `<svg`) | + SuspiciousContent (data-driven XSS subset detection; EPVME's six attack types include payload injection) |
| Wooyun any row | SuspiciousContent (email XSS payloads — declared taxonomy mapping) |
| r-dube `Human=positive` | BusinessEmailCompromise |
| r-dube `Human=neutral` (3 rows) | all-zero (clean) |
| bec-adversarial `label=1` (both files; 60 unlabeled rows dropped) | BusinessEmailCompromise |
| phishing-email-dataset `label=1` (42,891) | Spam — sampled positives are dominated by classic spam and 419-fraud text (declared on data evidence, same ruling style as MeAJOR; the upstream itself conflates "spam (phishing)") |
| phishing-email-dataset `label=0` (39,595) | all-zero (clean) |
| seven-phishing `label=1` × {Assassin, Enron, Ling, TREC-05, TREC-06, TREC-07} | Spam |
| seven-phishing `label=1` × CEAS-08 | Phishing |
| seven-phishing `label=0` | all-zero (clean) |
| curated TREC_05/06/07, SpamAssasin, Enron, Ling `label=1` | Spam |
| curated CEAS_08, Nazario, Nazario_5 `label=1` | Phishing |
| curated Nigerian_5, Nigerian_Fraud `label=1` | BusinessEmailCompromise (advance-fee/wire-fraud social engineering — declared taxonomy mapping) |
| curated `label=0` | all-zero (clean) |
| curated rows with missing or misaligned labels (3,862: TREC_05 3,805, TREC_06 57) | dropped — never guessed, never silently labeled clean |
| synthetic fixture generator | per-template class vector |

Notes:
- MeAJOR's cleaned CSV contains only `trec5/trec6/trec7` sources; its
  positives are spam-corpus messages despite Zenodo metadata calling the
  label "phishing" — mapped **Spam** on data evidence. Phishing-class signal
  comes from sources 2, 3, and 5 (verified subject sampling) plus curated
  Nazario/CEAS and seven-phishing CEAS rows (source 12, 11).
- Source 5 parses as tab-separated `text<TAB>label` across two shifted
  xlsx columns; prepare rejects the whole file if any row fails the tab
  parse (all 624 must parse).
- isuranga's SPF/DKIM/DMARC result columns feed an `Authentication-Results:`
  line in the composed training text, mirroring the allowlisted
  `authentication-results` header of `InlineMlRepresentation` (plan decision
  1). Composition order: Subject, From, auth line, URLs, Attachment, body.
- Real rows are combined with synthetic rows only after per-source
  normalization; class balance targets and per-split counts are recorded
  in `data/processed/stats.json` at prepare time (see the prepare-run
  section below).
- EML parsing (sources 6, 7): stdlib `email` policy-default parser;
  first `text/plain` part preferred over `text/html` (tags stripped).
  EPVME yielded 49,081 rows of 49,136 EML (55 files had neither subject
  nor body); Wooyun yielded 167 of 168 (1 file content-free). Files
  that fail to parse are counted and printed, never labeled clean.
- Curated source 12: TREC_05/TREC_06 contain pathological 2MB+
  unquoted lines that overflow pandas' C tokenizer; prepare falls back
  to the python tokenizer for exactly those files. Unlabeled or
  column-misaligned rows (3,862) are dropped with a per-file count.
- Sources 1, 6, 11, 12 (and source 10's packaging) all contain
  overlapping upstream corpora (TREC/Enron/Nazario/...). Ordered dedup
  keeps the first-loaded occurrence, so loader order decides which
  declared mapping survives for a duplicated message; the order is:
  compilation, zero-day, spam-genuine, meajor, multiclass, epvme,
  wooyun, bec-r-dube, bec-adversarial, phishing-email-dataset,
  seven-phishing, curated.
- Known limitation: source 10 (`phishing_email.csv`) ships texts
  reformatted (lowercased, punctuation-stripped) from the same upstream
  corpora, so many of its rows escape exact dedup against sources 1/11/12
  and enter training with the flat Spam mapping. The strengthened dedup
  key (below) collapses punctuation-only differences but cannot collapse
  reworded merges.

## Leakage controls

- Ordered global dedup on normalized text, train → validation → test
  (a row is dropped if its normalized text was already seen in an earlier
  split or earlier in the same split), applied across all real sources
  jointly. The dedup key case-folds, strips punctuation, and collapses
  whitespace, so the same message in differently packaged corpora
  (re-punctuated or re-spaced upstream merges) still collides.
- Synthetic fixtures are checked against the same normalized-text
  dedup (a fixture colliding with a real row is dropped).
- Per-split class counts (minority/majority, real vs synthetic) written
  to `data/processed/stats.json` and reproduced in the model card.

## Held file checksums (source 2, SHA-256)

| File | Rows | SHA-256 |
| --- | --- | --- |
| `PhishFinderDatasetID.unique.csv` | 63,518 | `c9285bf852504f8295d04aa7d784034e61f55f35dd4be9d832c7cee0c2baaee0` |
| `PhishFinderDatasetID.unique.train.csv` | 44,462 | `9af9fc694c3198ded2b879c307fada0035aa0c7375ad8a96d718a2a4fb202da1` |
| `PhishFinderDatasetID.unique.validation.csv` | 9,527 | `25073ce643bfc4aa755311e7d0849c68320c7532b0bcf948c98467ab23cae57b` |
| `PhishFinderDatasetID.unique.test.csv` | 9,529 | `3a1a4cb39cb78a36383c5366188bf46546823338f34045d40d6979c5542043d8` |

Pre-dedup full-file stats (source 2): 63,518 rows; ham 38,693 /
phishing 24,825; 4,302 normalized duplicates (6.8%). Post-dedup pilot
splits (42,371 / 8,512 / 8,333) belong to the superseded binary pilot
and are recomputed jointly for the multi-label prepare run.

## Prepare run 2026-10-17 (all 12 sources, seed 42)

- Loaded: 893,469 real rows + 12,000 synthetic = 905,469.
- Dedup: kept 629,960, dropped 275,509 (30.4% — cross-package
  duplicates of shared upstream corpora).
- Splits (80/10/10, seed 42): train 503,968 (clean 243,786,
  multi-label 24,400, synthetic 9,598) / validation 62,996
  (clean 30,606) / test 62,996 (clean 30,465).
- All 13 labels present in every split (rarest: Malware 62/8/7
  train/val/test). Per-source and per-label counts per split:
  `data/processed/stats.json`.
- Train-split label counts: Spam 158,543; Phishing 61,012;
  AuthFailure 25,089; Spoofing 24,648; BusinessEmailCompromise 8,072;
  SuspiciousContent 1,689; CredentialHarvest 969; MaliciousUrl 958;
  PolicyViolation 945; MaliciousAttachment 945; Reputation 940;
  Unknown 977; Malware 62. Synthetic-only classes (disclosed in the
  model card): CredentialHarvest, MaliciousUrl, MaliciousAttachment,
  PolicyViolation, Reputation, Unknown.
- Log: `ml/inline/run-logs/mac-prepare-20261017-all.log`.

## Data governance

- Public, third-party, license-recorded data only + Nullapart-owned
  synthetic fixtures; no customer or production message data ever
  (`docs/security/06-DATA-CLASSIFICATION.md`,
  `docs/25-AI-LLM-SKILLS-TOOLS.md`).
- License strings are provenance records, not admission gates: the
  permissive-only exclusion was lifted by the owner on 2026-10-17
  (reversal recorded at the top of this file). Exclusions now rest only
  on availability/fitness (withdrawn upstream) or source type
  (URL-only feeds).
- Raw files live under `ml/inline/data/` (git-ignored); nothing in
  `data/` is committed.
- Every fetched file is SHA-256 pinned here before first use; the
  prepare step refuses unpinned inputs.

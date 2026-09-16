# Scanner Fabric

## Day-one architecture

The scanner fabric exists from the start. Do not design scanning as one monolithic function.

Initial logical capabilities:

- MIME normalization;
- malware scanning;
- static/YARA analysis;
- URL/domain analysis;
- archive analysis;
- PDF analysis;
- Office/document analysis;
- image analysis;
- OCR;
- QR;
- file-type verification;
- Rspamd evidence;
- inline ML.

## Common scanner result

Each scanner produces a normalized result containing:

- scanner type;
- scanner node;
- scanner profile;
- engine/ruleset version internally;
- start/end/duration;
- status;
- findings.

Customer-facing UI uses product-neutral labels such as:

- Malware scan — Clean;
- Document analysis — Clean;
- URL analysis — Clear.

Backend technology names are not shown in normal customer/support-facing product views.

## SecurityFinding

Common logical fields:

- finding ID;
- Nullapart message ID;
- artifact reference;
- category;
- subtype;
- severity;
- confidence;
- source;
- evidence reference;
- scanner node;
- timestamp.

Categories include malware, phishing, spam, impersonation, credential lure, suspicious URL, macro, executable, archive, QR, authentication, reputation and policy.

## Scanner states

- CLEAN
- THREAT
- SUSPICIOUS
- UNKNOWN
- ERROR
- NOT_APPLICABLE

UNKNOWN/ERROR are never silently converted to CLEAN.

## Execution classes

- FAST_REQUIRED
- STANDARD_REQUIRED
- OPTIONAL_ENRICHMENT
- DEEP_ANALYSIS

Every scanner defines timeout, concurrency, required/optional state and failure semantics.

## Node identity

Every scanner node has a unique IP and numbered hostname.

Internal telemetry records the exact node for every scan.

## Topology rule

Do not prematurely force every scanner into its own container, and do not prematurely combine them all.

Separate when justified by isolation, heavy dependencies, independent scaling, security boundary or resource profile.

The common scanner contract allows later relocation without redesigning policy or Mail Core.
## Scanner diagram

See [Scanner Fabric](diagrams/05-scanner-fabric.mmd).


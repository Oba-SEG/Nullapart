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
- findings;
- resource-limit/timeout reason where applicable.

Customer-facing UI uses product-neutral labels such as:

- Malware scan — Clean;
- Document analysis — Clean;
- URL analysis — Clear.

Backend technology names are not shown in normal customer-facing product views. Support/System engineering diagnostics may expose implementation details only where their role permits it.

## SecurityFinding

Common logical fields:

- finding ID;
- SMTP transaction ID and/or tenant message ID;
- artifact reference;
- scope: shared transaction or tenant-specific;
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

Resource limits/timeouts produce explicit UNKNOWN/ERROR/SUSPICIOUS results according to scanner policy; they do not masquerade as successful scans.

## Execution classes

- FAST_REQUIRED
- STANDARD_REQUIRED
- OPTIONAL_ENRICHMENT
- DEEP_ANALYSIS

Every scanner defines timeout, concurrency, required/optional state and failure semantics.

## Resource-exhaustion protection

Email scanning is an adversarial workload. Every parser/scanner must have explicit hard limits.

At minimum define limits for:

- MIME nesting depth;
- number of MIME parts/attachments;
- maximum artifact/message size;
- archive recursion depth;
- total expanded/decompressed bytes;
- compression ratio;
- number of archive entries;
- nested archive count;
- parser CPU/wall-clock time;
- process/container memory;
- temporary disk usage;
- document page count;
- OCR image dimensions/pixel count;
- extracted text length;
- URL/QR count;
- macro/object count where applicable.

Encrypted/password-protected archives/documents return an explicit state that policy can handle; they are never treated as clean merely because content could not be inspected.

## Parser isolation

High-risk native parsers should run with strong process/container isolation:

- non-root;
- minimal filesystem access;
- no unnecessary network access;
- CPU/memory/time limits;
- bounded temporary storage;
- seccomp/capability reduction where practical;
- separate failure domain for parsers with a history of memory-safety vulnerabilities.

A parser crash should fail the scanner request, not the entire Mail Core.

## Resource-exhaustion and parser safety

Every scanner profile defines hard resource limits. At minimum, relevant scanners constrain:

- MIME nesting depth;
- attachment count;
- archive recursion depth;
- total decompressed bytes;
- compression ratio;
- per-artifact and per-message expanded size;
- document page/sheet/slide count;
- OCR image dimensions/pixel count;
- URL count and redirect depth;
- parser CPU time;
- wall-clock timeout;
- memory usage;
- temporary disk usage.

Password-protected/encrypted, malformed or otherwise unscannable artifacts receive an explicit `UNKNOWN`/`UNSCANNABLE`-type finding and are handled by policy; they are never silently considered clean.

Archive bombs, parser crashes and resource-limit violations must be isolated to the scanner worker/process and must not destabilize Mail Core.

## Node identity

Every scanner runtime records:

- stable/logical node ID;
- numbered hostname;
- region/deployment;
- current IP;
- AWS runtime/task/instance identity;
- scanner release/ruleset.

The current IP is useful telemetry but may be ephemeral in container environments; it is not the sole canonical node identity.

Internal telemetry records the exact runtime that handled every scan.

## Topology rule

Do not prematurely force every scanner into its own container, and do not prematurely combine them all.

Separate when justified by isolation, heavy dependencies, independent scaling, security boundary, parser risk or resource profile.

The common scanner contract allows later relocation without redesigning policy or Mail Core.

## Scanner diagram

See [Scanner Fabric](diagrams/05-scanner-fabric.mmd).

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

## Pre-queue Rspamd/milter evidence

Rspamd runs as a Postfix milter before the message is queued; Mail Core owns the durable scan and
the final disposition afterwards. The after-queue `mailcore-filter` therefore has to carry the
milter's verdict across the authenticated handoff without ever trusting an attacker-supplied
header. The chain is owned by `crates/mail-core/src/milter_evidence.rs`:

- `infrastructure/rspamd/lua.d/nullapart_evidence.lua` strips every inbound `X-Spam*`, `X-Rspamd*`
  and Nullapart evidence header at prefilter, so the queued message can only carry headers this
  deployment's Rspamd wrote;
- at postfilter it re-adds bounded `X-Rspamd-Score`, `X-Rspamd-Action`, `X-Rspamd-Is-Spam` and
  `X-Rspamd-Symbols` only when the default metric action is at least `add_header`
  (`infrastructure/rspamd/local.d/actions.conf`, with `reject` and `greylist` deliberately
  unreachable so disposition stays with Mail Core);
- the public SMTP listener disables cleanup-stage `header_checks`
  (`receive_override_options=no_header_body_checks`) because those run after the milter and would
  strip Rspamd's own evidence along with forgeries;
- the private reinjection listener runs with no milters, so `header_checks_reinjection` strips the
  evidence names there instead: reinjected mail never carries stale or forged evidence;
- `mailcore-filter` parses those headers with bounded limits (header scan bytes, score range,
  symbol/action count and length), and `process_handoff` re-validates the observation bounds at the
  trust boundary even though the producer is our own filter;
- the pipeline records one `rspamd` scanner row of class `OPTIONAL_ENRICHMENT` (`required: false`)
  whenever evidence was observed, plus a `Spam` finding when Rspamd's action was a spam action.
  Absent or clean evidence adds no finding and can never change a disposition to clean;
  SPF/DKIM/DMARC results are derived from symbol names with failure classes taking precedence over
  passes.

`local_networks` is restricted to loopback (`local.d/options.inc` + `local_networks.map`) so the
packaged RFC1918/docker skip list cannot silently disable SPF/DKIM/DMARC checks inside the lab
network, which would leave domain-authentication evidence permanently empty.

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

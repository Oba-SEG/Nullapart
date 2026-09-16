# Phase 7 — Regional Deep AI

## Objective

Deploy a regional, self-controlled Deep AI capability for complex security analysis without making it a mandatory dependency for ordinary mail delivery.

## Prerequisites

- data classification/training governance accepted;
- regional ArtifactStore/access broker exists;
- quarantine/report/case sources exist;
- durable events and audit exist;
- model evaluation/security process defined.

## Architecture

Deep AI is:

- regional;
- private-network only;
- authenticated;
- OpenAI-compatible at the API contract;
- model/backend replaceable;
- separate from normal Mail Core hot path.

Candidate: Qwen3.8-27B or validated replacement.

## Regional capacity validation

For each deployment class benchmark:

- available accelerator family;
- quantization;
- VRAM;
- GPU count/topology;
- model load time;
- tokens/sec;
- concurrent requests;
- context target;
- multimodal workload;
- availability/failover;
- cost.

ZA must be benchmarked independently due narrower accelerated-compute availability.

## Eligible content

Deep AI may access explicitly eligible:

- quarantined;
- blocked;
- reported phishing;
- confirmed threat;
- selected false positive/negative review;
- messages held for deep analysis.

No unrestricted S3/database access.

## Artifact access broker

Enforce:

- region/deployment;
- customer;
- eligibility/purpose;
- artifact type;
- expiration;
- audit/correlation.

Use short-lived scoped access.

## Input

Can include:

- selected message content;
- headers;
- trusted auth;
- URLs;
- attachment findings;
- extracted text;
- OCR;
- inline model result;
- VIP/context;
- historical campaign evidence where authorized.

All input is untrusted.

## Prompt-injection model

Email/document/image text cannot override system instructions or authorization.

If tools/functions are ever introduced:

- explicit allowlist;
- server-side auth;
- least privilege;
- no arbitrary network/filesystem access;
- separate threat model.

## Output

Strict structured finding:

- classification;
- attack type;
- severity;
- confidence;
- impersonated entity;
- evidence references;
- observations;
- recommended action;
- analyst summary.

The model never directly executes mail/remediation actions.

## Use cases

- BEC;
- executive/VIP impersonation;
- ambiguous financial lure;
- complex phishing;
- investigation;
- campaign correlation;
- analyst assistance;
- optional HELD_FOR_DEEP_ANALYSIS.

## Model lifecycle

Track:

- model version;
- serving config;
- quantization;
- dataset/adapter provenance;
- evaluation;
- release/rollback;
- region deployment;
- security approval.

## Fine-tuning

Training corpus may include curated:

- quarantined;
- blocked;
- reported;
- confirmed BEC/phishing/malware;
- false positives/negatives;
- remediation cases;
- outbound abuse.

Operational access != training permission.

Require curated labels and versioned datasets.

## UI

Deep AI results should be surfaced as product findings/case analysis.

Customer UI should not expose model/backend names unless explicitly intended.

System/internal diagnostics may show model release/version.

## Security tests

- prompt injection;
- data exfiltration attempts;
- unauthorized artifact access;
- cross-tenant case context;
- adversarial documents/images;
- long-context abuse;
- model unavailable;
- malformed output;
- hallucinated evidence references;
- tool abuse if tools exist;
- training-data poisoning.

## Failure semantics

Normal mail continues if Deep AI is unavailable.

Messages explicitly held for deep analysis remain held/timeout according to policy and alert operators.

## Exit criteria

- one target region benchmarked/approved;
- authenticated private API operational;
- scoped artifact access verified;
- structured outputs validated;
- model cannot directly execute actions;
- prompt-injection/security tests pass;
- failure does not stop ordinary mail;
- model rollback works;
- training governance enforced.

## Not in this phase

- autonomous agent actions;
- unrestricted web/browser/tool access;
- live self-training from production mail.

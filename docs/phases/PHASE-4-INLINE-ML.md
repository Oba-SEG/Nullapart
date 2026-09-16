# Phase 4 — Inline ML

## Objective

Add a low-latency, deterministic-to-operate ML evidence layer for threat classification without making the model the mail policy engine.

## Prerequisites

- scanner fabric stable;
- canonical message/security representation stable;
- policy accepts normalized findings/evidence;
- training-data governance from Phase -1 defined;
- model registry/versioning approach available.

## Model role

Inline ML provides evidence for categories such as:

- phishing;
- BEC;
- impersonation;
- credential lure;
- scam;
- spam;
- malware lure;
- suspicious financial/urgency patterns.

Policy remains the final decision layer.

## Input contract

The model receives a bounded canonical security representation, not arbitrary full raw MIME.

Candidate input fields:

- selected normalized headers;
- sender/domain/authentication;
- subject;
- cleaned text;
- extracted URLs;
- attachment metadata/findings;
- OCR/QR text where bounded;
- VIP/tenant context only where authorized;
- deterministic scanner findings.

Inputs must be size-bounded and versioned.

## Training pipeline

Define:

- label taxonomy;
- dataset provenance;
- allowed data classes;
- regional constraints;
- train/validation/test split;
- duplicate/campaign leakage controls;
- imbalance handling;
- annotation quality;
- benchmark baseline;
- evaluation protocol.

Production messages are not automatically training data.

## Candidate model

Start with a compact encoder class suitable for CPU inference.

Expected deployment:

- ONNX where appropriate;
- quantized/optimized CPU path;
- no GPU dependency in ordinary mail processing;
- bounded latency.

## Outputs

At minimum:

- model version;
- class probabilities/scores;
- multi-label security signals;
- confidence/calibration information;
- inference duration;
- representation/schema version.

Do not output an autonomous action like "delete mail".

## Calibration and thresholds

Thresholds are policy/configuration, not hard-coded into the model artifact.

Evaluate:

- precision/recall by threat class;
- false positives;
- false negatives;
- calibration;
- performance by language/domain/message type where relevant;
- latency p50/p95/p99;
- degradation on unseen campaigns.

## Runtime failure

If inline ML is unavailable:

- emit explicit ML unavailable/unknown evidence;
- deterministic scanning/policy continues if System policy permits;
- do not silently substitute a different model;
- do not treat unavailable as benign.

## Model registry

Track:

- model ID/version;
- training dataset version;
- code/config commit;
- metrics;
- approval;
- deployment regions;
- rollout time;
- rollback model;
- input schema version.

## Rollout

Support:

- shadow evaluation;
- limited deployment;
- version comparison;
- rollback.

Do not immediately allow a new model version to cause destructive policy changes without controlled evaluation.

## UI obligations

Show product-level results such as:

- Threat analysis — Low/Medium/High;
- classification/category;
- confidence band where useful;
- policy consequence;
- model evidence version in System/internal diagnostics only.

Do not expose internal model names to customer-facing normal trace.

## Feedback workflow

Quarantine release/report/adjudication can create a **candidate feedback record**.

It must not directly train/update the live model.

Feedback requires curation/label validation before dataset inclusion.

## Security tests

- adversarial text;
- HTML noise;
- prompt-like text;
- long-message truncation;
- Unicode/obfuscation;
- QR/OCR lure;
- model unavailable;
- malformed representation;
- model version mismatch;
- tenant-context leakage;
- training data authorization.

## Exit criteria

- benchmark beats agreed deterministic/baseline targets sufficiently to justify use;
- inference meets latency/resource targets;
- model input/output contract versioned;
- runtime failure is safe;
- model registry/rollback works;
- policy treats ML as evidence;
- feedback does not self-train;
- security/privacy evaluation passes.

## Not in this phase

- large decoder/LLM in mail hot path;
- Deep AI analyst reasoning;
- autonomous remediation.

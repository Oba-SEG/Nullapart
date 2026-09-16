# Phase 7 — Regional Deep AI

## Objective

Deploy a regional, self-controlled Deep AI capability for complex security analysis without making it a mandatory dependency for ordinary mail delivery.

## Prerequisites

- data classification/training governance accepted;
- regional ArtifactStore/access broker exists;
- quarantine/report/case sources exist;
- durable events and audit exist;
- model evaluation/security process defined;
- ML/LLM skill/tool governance from `docs/25-AI-LLM-SKILLS-TOOLS.md` accepted;
- skill/input/output schema versioning available.

## Architecture

Deep AI is:

- regional;
- private-network only;
- authenticated;
- OpenAI-compatible at the serving API contract;
- model/backend replaceable;
- skill-contract driven;
- separate from normal Mail Core hot path.

Candidate: Qwen3.8-27B or validated replacement.

## Skill registry

Production analysis is invoked through explicit versioned skills rather than arbitrary free-form prompts.

Initial skill candidates:

- `security.message.deep_analysis`;
- `security.bec_analysis`;
- `security.impersonation_analysis`;
- `security.case_summary`;
- `security.campaign_correlation`;
- `security.false_positive_review`;
- `security.false_negative_review`.

Each skill records:

- skill/version;
- allowed input/data classes;
- allowed tools;
- context/output budget;
- model requirements;
- prompt/template version;
- input/output schema;
- evaluation suite;
- timeout/concurrency;
- release/rollback state.

A model upgrade does not silently change a skill contract.

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
- skill;
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

## Context/token limits

Each skill defines a maximum context budget and deterministic evidence-selection strategy.

Large context capacity is not permission to send every artifact/customer record.

Prefer the minimum relevant structured evidence and content needed for the security question.

## Prompt-injection model

Email/document/image text cannot override system instructions or authorization.

Controls include:

- tool authorization outside prompt text;
- input/output schema validation;
- evidence/tool provenance;
- no arbitrary network/filesystem/shell/browser tool;
- unknown evidence/tool references rejected;
- message content explicitly treated as untrusted data.

## Tool architecture

Tools are exposed through server-enforced adapters, not raw infrastructure clients.

Initial tools should be read-only where possible, such as:

- retrieve scoped authorized message artifact;
- retrieve trusted auth findings;
- retrieve scanner findings;
- retrieve authorized customer/VIP context;
- retrieve authorized campaign/security history;
- query approved threat intelligence through a controlled adapter.

Every tool enforces:

- skill allowlist;
- service identity;
- region/deployment/customer;
- resource authorization;
- parameter schema;
- rate/resource limits;
- trace/audit as required.

The model does not receive broad S3/PostgreSQL/AWS credentials.

## Action tools

State-changing LLM tools are disabled by default and are **not part of the initial Phase 7 deliverable**.

If a future action tool is proposed, it requires separate threat-model/architecture approval and normal product authorization, state validation, idempotency, audit, rate limiting and human/step-up controls outside the model.

The model cannot self-authorize mail/remediation/policy/account actions.

## Output

Strict structured finding:

- skill/version;
- model release;
- classification;
- attack type;
- severity;
- confidence;
- impersonated entity;
- evidence references;
- observations;
- recommended action;
- analyst summary;
- processing duration.

The model never directly executes mail/remediation actions.

Schema-invalid output is UNKNOWN/ERROR, not a clean finding.

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
- skill compatibility;
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

System/internal diagnostics may show model/skill/tool release/version for reproducibility.

## Security tests

- prompt injection;
- data exfiltration attempts;
- unauthorized artifact access;
- cross-tenant case context;
- adversarial documents/images;
- long-context abuse;
- context-budget/truncation behavior;
- model unavailable;
- malformed/schema-invalid output;
- hallucinated evidence references;
- unauthorized/unknown tool request;
- tool parameter tampering;
- tool result containing prompt injection;
- training-data poisoning.

## Failure semantics

Normal mail continues if Deep AI is unavailable.

Messages explicitly held for deep analysis remain held/timeout according to policy and alert operators.

Tool denial/failure is represented explicitly in the finding/evidence; the model may not assume a denied tool result succeeded.

## Exit criteria

- one target region benchmarked/approved;
- authenticated private API operational;
- versioned skill registry operational;
- scoped artifact/tool access verified;
- read-only-first tool adapters enforce region/tenant/purpose;
- structured outputs validated;
- model cannot directly execute actions;
- prompt-injection/tool-security tests pass;
- context/token budgets are enforced;
- failure does not stop ordinary mail;
- model/skill rollback works;
- training governance enforced.

## Not in this phase

- autonomous administrative/remediation agents;
- unrestricted web/browser/shell/filesystem tools;
- unrestricted database/S3/AWS credentials;
- live self-training from production mail.

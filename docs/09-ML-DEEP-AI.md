# Machine Learning and Deep AI

## Two different model roles

Nullapart intentionally separates fast inline ML from deep security analysis.

## Inline classifier

Purpose:

- low-latency threat classification;
- phishing/BEC/impersonation signals;
- semantic features that deterministic scanners may miss.

Expected deployment:

- compact encoder model;
- fine-tuned for Nullapart;
- exported to ONNX where appropriate;
- CPU inference;
- located inside or immediately adjacent to Rust Mail Core;
- no per-message external AI dependency.

Model output is evidence, not policy.

## Deep AI

Deep AI is a separate regional service under Nullapart control.

It is not an external SaaS model dependency.

### Current leading candidate

`Qwen/Qwen3.8-27B` is the current leading candidate under evaluation.

The official model is a 27B-class multimodal model released under Apache-2.0 and can be served through vLLM/OpenAI-compatible APIs.

The model choice remains replaceable and is not part of the Mail Core contract.

## Regional capacity requirement

A model choice is not considered production-ready until benchmarked in every intended AWS region/deployment class.

AWS accelerated-compute availability differs materially by region. In particular, the available GPU/accelerator families in `af-south-1` may be much narrower than in large US/EU regions.

Therefore the ZA inference design must be benchmarked explicitly for:

- selected quantization;
- VRAM requirement;
- GPU count/topology;
- tokens/second;
- concurrent requests;
- context-window target;
- multimodal/image workload;
- model load/start time;
- failover/capacity reservation;
- cost per analyzed message/case.

Do not assume the same Qwen serving topology can be copied unchanged across ZA, EU, UK and US.

If the candidate cannot meet a region's security/latency/cost targets on available regional infrastructure, the OpenAI-compatible contract allows Nullapart to use a different regional model or quantization while preserving product behaviour.

## Deep AI functions

Deep AI is intended for:

- complex BEC analysis;
- impersonation analysis;
- quarantined message investigation;
- blocked message investigation;
- user/customer-reported phishing analysis;
- confirmed threat review;
- post-delivery threat analysis;
- campaign correlation;
- analyst summaries;
- ambiguous high-risk messages;
- training-data assistance/label review;
- optional image/document reasoning when useful.

## Content access

Deep AI may require message content for security work.

Access is limited to explicitly eligible security records such as:

- quarantined;
- blocked;
- reported;
- confirmed malicious;
- selected false-positive/false-negative review;
- messages explicitly held for deep analysis.

The AI service does **not** receive broad unrestricted database/S3 access.

Use a scoped artifact-access broker or short-lived authorized artifact retrieval mechanism.

The access broker must enforce region/deployment, customer scope, case eligibility, purpose and expiry.

## Regionality

Every production Deep AI service is regional/deployment-bound.

Examples:

- ZA AI cannot retrieve EU customer artifacts;
- ZAB uses its own endpoint/credentials/storage permissions;
- inference requests do not cross regions by convenience.

Model weights may be distributed to regions, but customer message data and inference payloads remain within the assigned region/deployment unless a separately approved data-residency rule explicitly permits otherwise.

## API contract

Deep AI exposes an authenticated OpenAI-compatible API behind internal network/security controls.

The serving implementation may use vLLM or another compatible engine.

Do not expose the inference server directly to the Internet.

Preferred controls:

- private VPC networking;
- mTLS/workload identity;
- request authentication;
- rate limits;
- request-size limits;
- explicit model allowlist;
- audit trail;
- regional logging;
- no public management endpoints.

## Evidence input

The model may receive:

- selected message content;
- selected headers;
- trusted authentication results;
- sender/domain/network intelligence;
- URL findings;
- attachment/document findings;
- OCR/extracted text;
- inline classifier result;
- customer/VIP context where authorized;
- historical campaign evidence where authorized.

Raw binary artifacts should only be passed when the model capability requires them.

## Output contract

Deep AI returns a strict internal structure containing fields such as:

- classification;
- attack type;
- severity;
- confidence;
- impersonated entity;
- evidence references;
- key observations;
- analyst summary;
- recommended action.

It never directly executes mail actions.

Policy or an authorized human determines disposition/remediation.

## Prompt-injection stance

All message text, images, documents and extracted content are untrusted model input.

Content inside an email must never be treated as system/tool instructions.

Model tools, if introduced later, require an explicit allowlist, server-side authorization and security review.

## Fine-tuning strategy

The long-term objective is a Nullapart-specialized security model.

Candidate training sources:

- quarantined mail;
- blocked mail;
- reported phishing;
- confirmed BEC;
- confirmed impersonation;
- confirmed malware;
- false positives;
- false negatives;
- remediation cases;
- outbound abuse;
- campaign clusters.

Production traffic is not automatically used for training.

Training data requires:

- authorization/governance;
- regional handling;
- sanitization as required;
- analyst-quality labels;
- train/validation/test separation;
- versioned datasets;
- model registry;
- security evaluation;
- rollback capability.

Customer message data selected for model development must have explicit governance and residency rules; operational content access does not automatically imply training consent or eligibility.

## Training/inference infrastructure

Production inference is expected to run on AWS accelerated-compute infrastructure within the region/deployment where suitable capacity exists.

Fine-tuning can use dedicated GPU training infrastructure separate from the mail runtime, subject to training-data regional/governance rules.

Model weights, adapters, datasets and evaluation artifacts should use regional encrypted storage with controlled IAM/workload access.

## Optional pre-delivery Deep AI

Deep AI is not mandatory for normal delivery.

A policy may explicitly put a high-risk message into `HELD_FOR_DEEP_ANALYSIS`, such as:

- suspected VIP BEC;
- financial-transfer lure;
- executive impersonation;
- ambiguous high-risk document.

This path may take longer and is intentionally exceptional.

## Deep AI diagram

See [Deep AI Flow](diagrams/08-deep-ai-flow.mmd).

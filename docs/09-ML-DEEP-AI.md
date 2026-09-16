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

At the time of this architecture revision the official checkpoint is approximately 28B parameters, multimodal, Apache-2.0 licensed and compatible with common self-hosted serving stacks including vLLM.

The model choice remains replaceable.

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

Use a scoped artifact-access broker or short-lived signed/authorized artifact retrieval mechanism.

## Regionality

Every production Deep AI service is regional/deployment-bound.

Examples:

- ZA AI cannot retrieve EU customer artifacts;
- ZAB uses its own endpoint/credentials/storage permissions;
- inference requests do not cross regions by convenience.

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

All message text is untrusted model input.

Content inside an email must never be treated as system/tool instructions.

Model tools, if introduced later, require an explicit allowlist and server-side authorization.

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

## Training/inference infrastructure

Production inference is expected to run on AWS GPU infrastructure within the region/deployment.

Fine-tuning can use dedicated GPU training infrastructure separate from the mail runtime.

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


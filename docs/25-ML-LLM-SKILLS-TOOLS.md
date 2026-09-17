# ML / LLM Skills and Tooling Architecture

**Status:** mandatory design contract for model-assisted security capabilities.

## Purpose

Nullapart uses ML and LLM capabilities as bounded security-analysis components, not as unconstrained autonomous agents.

A model capability is separated into:

- model/runtime;
- skill/prompt contract;
- tool permissions;
- input schema;
- output schema;
- data-access policy;
- evaluation;
- release/version.

## Skill model

A **skill** is a versioned, testable capability definition such as:

- classify phishing/BEC/impersonation;
- summarize a security case;
- extract evidence from message/document content;
- compare sender/entity behavior;
- correlate campaign indicators;
- explain a policy/security finding;
- assist analyst adjudication;
- produce candidate training labels.

A skill is not a free-form prompt stored only in source code comments.

Each skill declares:

- skill ID/version;
- purpose;
- eligible data classes;
- required model capability;
- allowed tools;
- system instructions;
- input schema;
- structured output schema;
- maximum context/input sizes;
- timeout/token limits;
- evaluation set/metrics;
- failure behavior;
- security owner.

## Tool model

Tools are server-defined functions. The model never gains arbitrary operating-system, shell, browser, database or network access merely because it can request a tool call.

Potential controlled tools include:

- scoped artifact retrieval;
- trusted message/security metadata retrieval;
- threat-intelligence lookup;
- customer/VIP lookup within authorized scope;
- campaign/case context lookup;
- safe URL reputation lookup;
- analyst-note retrieval where allowed.

Every tool declares:

- tool ID/version;
- request/response schema;
- data classification;
- authorization rule;
- customer/region scope;
- rate limit;
- timeout;
- idempotency requirement;
- audit requirement;
- egress/network requirements.

## Tool authorization

Tool authorization is evaluated by the server, not by model text.

A tool call is allowed only when:

- the originating security case is authorized;
- the artifact/customer/region scope matches;
- the skill is permitted to use the tool;
- the caller/model runtime identity is permitted;
- data-classification policy allows the data;
- requested operation is within explicit parameters.

Prompt text cannot expand tool permissions.

## No arbitrary execution

Deep AI must not receive unrestricted:

- shell;
- Python/code execution;
- filesystem;
- SQL;
- browser;
- arbitrary HTTP;
- cloud credentials.

If any execution tool is introduced later, it requires a new threat model, sandbox, allowlist, resource limits, egress policy and approval.

## Prompt injection

Message, attachment, URL, OCR and document content is always untrusted data.

Security rules:

- system/tool policy is out-of-band from message text;
- content cannot redefine tools/permissions;
- tool arguments are validated server-side;
- model output is validated against strict schemas;
- referenced evidence IDs must exist and belong to the authorized case;
- instructions inside analyzed content are never treated as privileged instructions.

## Structured outputs

Prefer strict structured outputs over prose-only decisions.

Example fields:

- classification;
- threat subtype;
- severity;
- confidence;
- evidence references;
- impersonated entity;
- observations;
- analyst summary;
- recommended action.

The model does not directly execute the recommended action.

## Context construction

Construct context from least necessary information.

Order of preference:

1. deterministic findings/metadata;
2. extracted/normalized text;
3. bounded relevant body sections;
4. selected attachments/images only when necessary;
5. historical/campaign context only when authorized.

Do not blindly send complete historical mailboxes or tenant datasets to a model.

## Token/context budgets

Each skill declares maximum:

- input characters/tokens;
- message body slices;
- attachments/pages/images;
- historical examples;
- output tokens;
- tool calls.

Oversized content uses deterministic truncation/chunking/summarization rules with evidence traceability.

Never allow an attacker-controlled message to consume an unbounded model context/cost budget.

## Skill/version registry

Track:

- skill version;
- prompt/system-instruction hash/version;
- model version;
- tool schema versions;
- input schema;
- output schema;
- evaluation version;
- deployment/region;
- rollout state.

A finding should be reproducible enough to determine which model + skill + configuration produced it.

## Evaluation

Every production skill has an evaluation set including:

- representative legitimate mail;
- known phishing/BEC;
- adversarial/prompt-injection samples;
- multilingual/obfuscated content where relevant;
- malformed/partial extraction;
- tool-denial scenarios;
- hallucinated evidence attempts;
- unauthorized cross-tenant context attempts.

Measure:

- precision/recall as appropriate;
- evidence-grounding quality;
- hallucination/error rate;
- schema validity;
- tool-call correctness;
- latency;
- token/context use;
- failure behavior.

## Rollout

Support:

- offline evaluation;
- shadow mode;
- limited pilot;
- regional rollout;
- rollback to prior model/skill.

Changing a prompt/skill can materially change security behavior and must be versioned/reviewed like code.

## Observability and audit

Record safe metadata such as:

- skill/model version;
- case/message IDs;
- latency;
- token counts;
- tool names/status;
- structured result status.

Do not log Restricted message content, complete prompts containing mail content, credentials or tool secrets to SegLumberjack.

Privileged tool/data access is auditable where required.

## Training/fine-tuning

Training data is governed separately from inference eligibility.

A skill may generate candidate labels, but those labels do not automatically enter training data.

Curated training requires provenance, authorization, region, dataset version and evaluation.

## AI-agent rules

Coding agents must not:

- add arbitrary tools to Deep AI;
- give models unrestricted network/database access;
- hide a new tool inside a generic `execute` interface;
- treat model output as trusted authorization;
- increase context/tool budgets without resource/security review;
- change production prompt/skill behavior without versioning/tests.
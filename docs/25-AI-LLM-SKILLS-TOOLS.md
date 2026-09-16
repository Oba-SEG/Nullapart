# ML / LLM Skills and Tool Governance

**Status:** mandatory architecture for inline ML, regional Deep AI and any future model-assisted workflow.

## Purpose

Nullapart models are security-analysis components, not autonomous administrators.

Every ML/LLM capability is expressed as a versioned **skill** with an explicit input contract, output contract, allowed tools, data classes, model requirements, limits, evaluation set and failure behavior.

## Skill registry

Every production skill records:

- skill ID;
- version;
- owner;
- purpose;
- eligible regions/deployments;
- eligible data classes;
- model/backend requirements;
- prompt/system-template version where applicable;
- input schema version;
- output schema version;
- allowed tools;
- tool permissions;
- context/token/input limits;
- timeout/concurrency limits;
- evaluation suite/version;
- approval/release state;
- rollback version.

A model upgrade does not silently change a skill contract.

## Initial inline-ML skills

Examples:

- phishing classification;
- BEC classification;
- executive/VIP impersonation signal;
- credential-lure signal;
- scam/payment-lure signal;
- spam classification;
- malicious-attachment lure signal;
- QR-phishing signal.

Inline ML remains low-latency, deterministic to operate and non-agentic.

## Initial Deep-AI skills

Examples:

### `security.message.deep_analysis`

Analyze an eligible quarantined/blocked/reported/held message and return structured security findings.

### `security.bec_analysis`

Assess business-email-compromise indicators using authorized message, identity and historical context.

### `security.impersonation_analysis`

Assess executive/brand/person impersonation evidence.

### `security.case_summary`

Produce an analyst-facing summary from already-authorized evidence.

### `security.campaign_correlation`

Compare authorized cases/messages/findings to identify campaign-level relationships.

### `security.false_positive_review`

Assist an authorized analyst in reviewing a release/false-positive case.

### `security.false_negative_review`

Assist an authorized analyst in reviewing a confirmed miss/report.

Skills produce evidence/recommendations. They do not directly execute mail, policy, account, connector or remediation actions.

## Tool model

Tools are capabilities exposed to a skill through a policy-enforced server layer.

A tool is not an unrestricted SDK/client object handed to the model.

Every tool declares:

- tool ID/version;
- purpose;
- allowed skills;
- allowed actor/service identity;
- required customer/region scope;
- accepted parameters;
- returned data classification;
- rate/resource limits;
- audit/trace behavior;
- network/data side effects;
- idempotency where applicable.

## Read-only tools first

Initial Deep-AI tools should be primarily read-only, such as:

- retrieve scoped message/security artifact;
- retrieve trusted authentication findings;
- retrieve scanner findings;
- retrieve authorized VIP/customer context;
- retrieve campaign/security history;
- query approved threat-intelligence sources through a controlled adapter.

The model never receives broad database/S3 credentials.

## Action tools

Action tools are **disabled by default**.

If future architecture introduces a tool capable of changing state, it requires a separate threat model and must enforce normal product controls outside the model:

- server-side authorization;
- object ownership/tenant scope;
- business-state validation;
- idempotency;
- step-up/human approval where required;
- Admin Audit;
- rate limiting;
- safe rollback/containment.

The model cannot self-authorize a tool call.

## Tool-result trust

Tool output is data, not instructions.

A malicious email, document, threat-intelligence response or retrieved text must never be allowed to redefine system/tool policy.

Tool results carry provenance/evidence references so a model cannot invent a valid-looking evidence source.

## Prompt injection

Mandatory controls:

- system policy is outside message content;
- message/document text is explicitly tagged/treated as untrusted data;
- tool permissions are enforced by server policy rather than prompt language;
- tool arguments are schema validated;
- model output is schema validated;
- unknown tool/evidence references are rejected;
- no arbitrary shell, browser, filesystem or network tool in production Deep AI by default.

## Context minimization

Do not send a complete customer history merely because context space exists.

For each skill, retrieve the minimum evidence required.

Prefer:

1. structured auth/scanner metadata;
2. relevant text excerpts/parts;
3. selected artifacts;
4. narrowly relevant historical cases.

Context assembly must preserve tenant/region restrictions.

## Token / context budgets

Every LLM skill declares:

- maximum input tokens/context;
- maximum output tokens;
- maximum attachments/images/pages;
- truncation/selection strategy;
- timeout;
- concurrency.

Large model context is a capacity, not a target.

## Structured output

Deep-AI production skills return strict structured findings rather than arbitrary prose as the source of truth.

Typical fields:

- skill/version;
- model release;
- classification;
- attack type;
- severity;
- confidence;
- evidence references;
- observations;
- recommended action;
- analyst summary;
- processing duration.

Schema-invalid output is an error/unknown result, not silently coerced to clean.

## Evaluation

Every production skill has an evaluation set covering:

- benign mail;
- phishing/BEC/scam;
- multilingual/obfuscated content where relevant;
- prompt injection;
- adversarial artifacts/images;
- false-positive cases;
- known false negatives;
- malformed/partial context;
- tool denial/failure;
- hallucinated evidence/tool references.

Skill release requires regression thresholds and rollback criteria.

## Training / fine-tuning

Operational access does not imply training permission.

Training datasets require:

- provenance;
- allowed data class;
- region;
- labeling process;
- approval;
- dataset version;
- deletion/withdrawal process;
- evaluation split protections.

## Observability

Record safe metadata such as:

- skill ID/version;
- model version;
- latency;
- token counts;
- tool calls by ID/status;
- result category;
- validation/error state.

Do not log raw Restricted prompts/content to SegLumberjack.

## UI

Customer-facing UI describes product security capability, not backend model/tool implementation details.

System/internal diagnostics may show skill/model/tool versions for reproducibility.

## AI-agent rule

Coding agents must not confuse this runtime tool architecture with their own development-tool permissions. A coding agent having repository access does not imply the production LLM can have repository, shell, AWS or browser access.

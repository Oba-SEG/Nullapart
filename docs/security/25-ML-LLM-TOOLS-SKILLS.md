# ML / LLM Skills, Tools and Agent Security

**Status:** mandatory security and engineering baseline for all ML/LLM functionality.

## Principle

Models produce evidence, analysis and assistance. They do not inherit authority merely because they can reason about a task.

Every model capability is explicitly separated into:

- input data access;
- inference/model capability;
- tool capability;
- action authority;
- human/policy approval;
- audit.

## Skill model

A **skill** is a documented capability boundary, not unrestricted model freedom.

Examples:

- classify phishing/BEC;
- summarize a security case;
- correlate campaign indicators;
- inspect selected message evidence;
- explain a policy decision;
- propose remediation steps;
- assist with training-data labeling.

Each skill declares:

- purpose;
- permitted roles/callers;
- permitted data classes;
- input schema;
- output schema;
- model(s) allowed;
- tools allowed;
- maximum resource/context budget;
- region/deployment restrictions;
- audit requirements;
- failure/fallback behavior;
- evaluation suite;
- security owner.

A skill does not automatically gain every tool exposed to the model host.

## Tool model

Tools are server-side capabilities invoked through an explicit broker/dispatcher.

A model never receives ambient infrastructure authority.

Tool examples may later include:

- scoped artifact retrieval;
- threat-intelligence lookup;
- safe DNS lookup;
- case/history lookup;
- read-only message metadata lookup.

High-risk or mutating tools such as:

- quarantine release;
- mailbox remediation;
- customer/policy changes;
- connector operations;
- role changes;
- arbitrary HTTP/browser access;
- shell/command execution

are **not enabled by default** and require separate architecture/threat-model approval.

## Tool authorization

Every tool invocation is re-authorized server-side using:

- real actor/service identity;
- deployment/region;
- customer scope;
- case/message/artifact scope;
- action;
- tool-specific policy;
- model/skill identity.

Model-generated arguments are untrusted input and are validated exactly like client input.

The model cannot grant itself additional customer scope, artifact access or tool permission.

## Prompt injection

All email, document, image, OCR, URL content and external threat-intelligence text is untrusted model data.

Controls:

- system instructions remain separate from content;
- content cannot redefine tool permissions;
- tools have server-side authorization;
- tool inputs are allowlisted/validated;
- retrieved content is labeled as untrusted evidence;
- no hidden fallback to unrestricted shell/browser/network access;
- outputs requiring security action go through policy/human approval.

## Tool output trust

Tool responses can also be hostile or malformed.

Validate and bound:

- size;
- schema;
- URLs;
- encoding;
- redirects;
- external text rendered to humans;
- binary/document output.

Do not feed arbitrary tool output back into privileged tool execution without policy controls.

## Model routing

Model routing is server-owned.

A client/message cannot choose an arbitrary model endpoint or override safety/security policy.

Routing considers:

- skill;
- region;
- approved model version;
- data eligibility;
- capacity;
- modality;
- cost/performance policy.

## Context construction

Construct the minimum useful context.

Prefer:

- structured findings;
- selected headers/text;
- scoped artifact excerpts;
- evidence references;
- bounded campaign history.

Avoid copying entire databases/cases/mailboxes into prompts.

## Context and token budgets

Every skill defines:

- maximum input tokens;
- maximum output tokens;
- maximum number/size of retrieved artifacts;
- truncation/summarization strategy;
- time/compute budget;
- maximum tool calls.

When context must be reduced, preserve security evidence and provenance before prose repetition.

Do not optimize token use by omitting required authorization/audit/security context.

## Structured output

Security-critical model output uses a strict versioned schema.

Reject/handle:

- malformed JSON/structure;
- unsupported enum values;
- unknown evidence references;
- hallucinated message/artifact IDs;
- impossible confidence/range values.

Model output is not trusted simply because it parses.

## Evaluation

Each production skill has an evaluation suite covering:

- task accuracy;
- false positives/negatives;
- adversarial/prompt injection;
- cross-tenant leakage;
- hallucinated evidence;
- tool misuse;
- unavailable tool/model;
- long/truncated context;
- malicious attachment/image/OCR input;
- regional/model-version compatibility.

## Model/tool versioning

Record for every result:

- skill version;
- model version;
- serving/runtime version;
- prompt/instruction version;
- toolset version;
- input schema version;
- output schema version;
- relevant ruleset/config revision.

This supports reproducibility and incident investigation.

## Training and skills

Training/fine-tuning data is separate from runtime skill permission.

A model trained on a data class is not automatically authorized to retrieve that data class at runtime.

## Observability

Record safe metadata such as:

- skill;
- model version;
- latency;
- token counts;
- tool calls/result classes;
- failure reason;
- trace/case/message ID;
- customer ID where permitted.

Do not send full Restricted prompts/responses to SegLumberjack.

## Kill switches

Every model/tool skill can be disabled regionally without stopping ordinary mail delivery unless the explicit policy intentionally holds mail for that skill.

Tool kill switches and model disablement are server-side and auditable.

## AI-agent development rules

Coding agents implementing ML/LLM functionality must not:

- expose arbitrary tools to a model;
- add shell/browser/network access for convenience;
- pass unrestricted S3/database credentials;
- make model output directly execute destructive actions;
- expand context/data scope without data-classification review;
- silently change model/prompt/tool schema without version/evaluation updates.

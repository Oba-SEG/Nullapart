# Nullapart AI Engineering Index

Two different AI domains exist in this repository and must not be conflated.

## Product ML / Deep AI

Runtime security-analysis capabilities used by Nullapart.

Read:

- `docs/09-ML-DEEP-AI.md`
- `docs/25-AI-LLM-SKILLS-TOOLS.md`
- `docs/phases/PHASE-4-INLINE-ML.md`
- `docs/phases/PHASE-7-DEEP-AI.md`

These documents govern model skills, tool permissions, data access, evaluation and training.

## Coding agents

AI systems used to develop/review Nullapart source and documentation.

Read:

- root `AGENTS.md`;
- `docs/ai/CODING-AGENT-OPERATING-MODEL.md`;
- `CONTRIBUTING.md`;
- owning phase specification.

Coding-agent repository/cloud permissions do **not** imply runtime Deep-AI permissions.

## Context discipline

Coding agents should load the minimum authoritative context required for the task rather than ingesting the entire repository on every change.

Security/architecture rules are never skipped merely for token savings.

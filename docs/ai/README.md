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

Canonical repository instructions:

- root `AGENTS.md`.

Detailed operating model:

- `docs/ai/CODING-AGENT-OPERATING-MODEL.md`.

Cross-agent discovery/adapters:

- `docs/ai/AGENT-DISCOVERY.md`;
- `.github/copilot-instructions.md`;
- `CLAUDE.md`;
- `GEMINI.md`;
- `.cursor/rules/nullapart.mdc`.

OpenAI Codex and OpenCode use root `AGENTS.md` directly; they do not require a separate duplicated policy file.

Coding-agent repository/cloud permissions do **not** imply runtime Deep-AI permissions.

## Required coding-agent context

Read in this order:

1. root `AGENTS.md`;
2. `SECURITY.md`;
3. `docs/16-BUILD-ROADMAP.md`;
4. owning phase specification;
5. `docs/engineering/CODE-STANDARDS.md`;
6. only task-relevant architecture/security documents;
7. target implementation/tests/contracts.

## Context discipline

Coding agents should load the minimum authoritative context required for the task rather than ingesting the entire repository on every change.

Security/architecture rules are never skipped merely for token savings.

Adapters remain short so instruction policy does not drift between coding-agent vendors.

## Enforcement

Agent instructions guide behavior but do not replace enforcement.

Compiler/types, database constraints/RLS, tests, formatting/lint/type checks, CI security gates, PR review, protected `main` and production approvals must stop invalid changes even when an agent fails to follow prose correctly.

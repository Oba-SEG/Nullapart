# Coding Agent Instruction Discovery

**Status:** canonical cross-agent instruction-discovery contract.

## Principle

`AGENTS.md` is the canonical repository-wide coding-agent instruction source for Nullapart.

Vendor/tool-specific files are thin adapters only. They must point agents to `AGENTS.md` and the normal phase/security/engineering documents rather than duplicating the full policy set.

This prevents instruction drift across different coding agents.

## Canonical instruction chain

Every coding agent should follow this logical chain before modifying implementation:

1. root `AGENTS.md`;
2. `SECURITY.md`;
3. `docs/16-BUILD-ROADMAP.md`;
4. owning `docs/phases/PHASE-*.md`;
5. `docs/engineering/CODE-STANDARDS.md`;
6. only task-relevant architecture/security documents;
7. implementation files + nearby tests/contracts.

Detailed execution/context rules live in `docs/ai/CODING-AGENT-OPERATING-MODEL.md`.

## OpenAI Codex

Codex is covered directly by root `AGENTS.md`.

Codex supports scoped `AGENTS.md` files, so future component-specific rules may be added near the relevant subtree when they provide real value.

Do not create a `CODEX.md` and assume Codex consumes it.

## OpenCode

OpenCode V2 is covered directly by root `AGENTS.md`.

OpenCode discovers `AGENTS.md` project guidance and can load additional scoped `AGENTS.md` files as it explores subdirectories.

Do not create an `OPENCODE.md` as a parallel policy source.

## GitHub Copilot

Repository adapter:

- `.github/copilot-instructions.md`

The adapter points to the canonical instruction chain.

GitHub Copilot agents can also consume `AGENTS.md`; the adapter exists to cover Copilot surfaces that use repository-wide `.github/copilot-instructions.md` guidance.

Future path-specific `.github/instructions/*.instructions.md` files may be used when a component needs genuinely local rules.

## Claude-compatible agents

Root adapter:

- `CLAUDE.md`

It contains no independent policy. It directs the agent to `AGENTS.md` and canonical project documents.

## Gemini-compatible agents

Root adapter:

- `GEMINI.md`

It contains no independent policy. It directs the agent to `AGENTS.md` and canonical project documents.

## Cursor

Cursor is covered by both root `AGENTS.md` and an always-applied project rule:

- `.cursor/rules/nullapart.mdc`

The Cursor rule remains intentionally small and points to the same canonical instruction chain.

Do not use legacy `.cursorrules` as the primary source.

## Scoped AGENTS.md files

Scoped `AGENTS.md` files are appropriate when a subtree has important additional invariants that would create noise in the root file.

Potential future scopes:

- `mail/AGENTS.md` — SMTP responsibility, queue/reinjection, protocol safety;
- `frontend/AGENTS.md` — session storage, central API client, accessibility, hostile content;
- `crates/AGENTS.md` — Rust contracts, errors, unsafe policy, serialization;
- `ml/AGENTS.md` — model/data/tool governance;
- `infrastructure/AGENTS.md` — IaC, IAM, networking, deployment boundaries;
- `tests/security/AGENTS.md` — negative/adversarial testing requirements.

Keep scoped files focused. Do not copy the entire root `AGENTS.md` into them.

## Instruction precedence

Direct task/system/operator instructions take precedence according to the coding-agent platform's instruction hierarchy.

Within repository guidance:

- root `AGENTS.md` provides global rules;
- scoped rules add more specific constraints for their subtree;
- scoped guidance must not silently weaken a global security requirement;
- if a true conflict is required, update/review the canonical architecture/security policy rather than hiding an override in a nested agent file.

## Token/context discipline

Adapters should be short.

Do not preload every architecture file into every agent request.

The adapter should teach the agent where to find authoritative context; the agent then loads only the phase/task-relevant documents.

Security, tenant isolation, audit, validation and required tests are never omitted for token savings.

## Enforcement boundary

Agent instructions guide behavior but are not the security boundary.

Enforcement remains in:

- compiler/types;
- database constraints/RLS;
- automated tests;
- formatter/linter/type checker;
- CI/security scans;
- required reviews;
- protected `main`;
- production environment approvals.

An agent ignoring an instruction must not be able to merge/deploy an invalid change simply because its prompt was imperfect.

## Review rule

Whenever a tool-specific instruction adapter is changed, review whether the canonical `AGENTS.md` or operating model should change instead.

Do not let vendor-specific adapters become divergent policy documents.

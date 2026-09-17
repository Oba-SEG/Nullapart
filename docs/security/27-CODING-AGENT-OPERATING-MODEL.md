# Coding Agent Operating Model and Context Discipline

**Status:** mandatory operating rules for AI coding agents.

## Purpose

AI coding agents are development tools, not autonomous architecture owners or production approvers.

This document defines how coding agents should read the repository, select relevant context, apply changes and control token/context usage without dropping security-critical information.

## Agent capabilities / skill catalog

An agent may perform skills such as:

- architecture-aware code changes;
- Rust implementation/review;
- frontend implementation/review;
- SQL/migration work;
- tests/fuzzing/security regression;
- Postfix/Rspamd configuration work;
- scanner integration;
- AWS/IaC changes;
- CI/CD workflow changes;
- documentation maintenance;
- ML/LLM evaluation/tooling changes;
- dependency/version updates.

A skill is exercised only after reading the owning phase and relevant cross-cutting baselines.

## Context loading order

Agents should load context deliberately instead of repeatedly reading the whole repository.

Recommended order:

1. current user/task instruction;
2. `README.md` only if project orientation is needed;
3. `docs/16-BUILD-ROADMAP.md`;
4. owning `docs/phases/PHASE-*.md`;
5. the specific architecture/security documents referenced by that phase;
6. target source/config/test files;
7. nearby interfaces/callers only as needed.

Do not scan the whole repository when a focused dependency graph is sufficient.

## Token/context optimization

Optimize context by removing repetition, not by removing controls.

Preferred techniques:

- read targeted files/ranges;
- use search to locate symbols/contracts first;
- keep a concise working summary of established invariants;
- reference canonical documents rather than copying them repeatedly;
- inspect interfaces and tests before implementation details;
- group related edits;
- avoid re-reading unchanged large files;
- use diff/patch review after edits;
- stop loading context that is unrelated to the owning phase.

Never optimize tokens by omitting:

- tenant/customer scope;
- authentication/authorization rules;
- audit requirements;
- data classification;
- failure semantics;
- idempotency;
- security tests;
- migration/compatibility requirements.

## Canonical-source rule

When duplicated descriptions disagree, prefer the declared canonical source and treat drift as a defect.

Examples:

- Mermaid `.mmd` files are canonical diagram sources;
- package lockfiles are canonical exact package versions;
- migration files are canonical applied schema history;
- phase docs own implementation sequencing;
- security baseline docs own cross-cutting security rules.

Do not invent a resolution silently.

## Plan before editing

For material changes an agent should identify:

- owning phase;
- files/contracts affected;
- trust/data boundary impact;
- tests needed;
- migrations/config changes;
- UI impact;
- compatibility/release implications.

Then make the smallest coherent change satisfying the requirement.

## Change discipline

Agents should:

- prefer small reviewable commits/PRs;
- avoid unrelated refactors;
- preserve lockfiles and formatting conventions;
- avoid dependency additions without justification;
- update tests/docs with behavior;
- run/inspect relevant validation;
- review the resulting diff for accidental scope expansion.

## Security escalation

If a task would require:

- weakening authentication;
- bypassing ownership/RLS;
- exposing a new public port;
- moving Restricted data cross-region;
- adding an unrestricted LLM tool;
- disabling audit/security CI;
- storing credentials in browser persistence;
- creating a permanent security exception

then the agent must treat it as an architecture/security change rather than a local coding shortcut.

## Agent-written migrations

Before creating a migration:

- inspect current schema/migrations;
- preserve monotonic history;
- consider rolling compatibility;
- add constraints/RLS/indexes deliberately;
- avoid destructive changes unless phase/change plan explicitly calls for them.

Never rewrite a migration known to have been applied in production.

## Agent-written GitHub Actions

Before changing workflows:

- inspect permissions;
- consider untrusted PR/fork behavior;
- pin third-party actions to reviewed full commit SHAs;
- avoid `pull_request_target` with checkout/execution of untrusted PR code unless a reviewed design safely isolates it;
- minimize `GITHUB_TOKEN` permissions;
- use OIDC for AWS rather than long-lived credentials;
- protect production environments/approvals;
- review cache/artifact trust boundaries.

## Agent-written frontend

Agents must:

- use the central API client;
- avoid local/session-storage auth;
- implement server errors/loading/empty states;
- not rely on route visibility for authorization;
- reuse design-system primitives;
- add role/tenant tests;
- keep hostile content isolated.

## Agent-written ML/LLM code

Agents must:

- preserve model/tool authorization boundaries;
- version prompt/tool/output schemas;
- limit context/tool calls;
- add evaluation/security tests;
- never give a model arbitrary shell/browser/cloud credentials;
- not turn model recommendations directly into destructive actions.

## Verification summary

At task completion the agent should be able to state:

- what changed;
- why;
- tests/evidence;
- security implications;
- remaining assumptions/limitations.

Do not claim checks passed unless they actually ran or were otherwise verified.

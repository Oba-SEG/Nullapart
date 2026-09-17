# Nullapart Engineering Standards

This directory contains mandatory implementation standards for human and AI developers.

## Canonical standards

- [Code Standards and Formatting](CODE-STANDARDS.md)

## Phase sequencing

### Phase -1

The project accepts the code-quality principles and required tool classes before implementation begins.

This includes:

- formatter-first style policy;
- language-specific safety/quality rules;
- lint/type/static-analysis expectations;
- generated-code rules;
- review standards;
- CI enforcement requirements.

### Phase 0

Phase 0 implements the actual repository tooling/configuration for the languages/file types introduced, including the relevant formatter, linter, type checker and CI commands.

At minimum, Phase 0 must ensure:

- local and CI formatting are identical;
- CI rejects unformatted code;
- lint/type failures are merge-blocking;
- language/tool versions are pinned through the package compatibility policy;
- developers/agents have an obvious common validation command/task;
- no feature PR is expected to debate formatting manually.

## Feature phases

Every later phase inherits these standards.

A feature is not complete if its code only functions but fails canonical formatting, linting, type checks or required static analysis.

## Relationship to security

Code quality is part of security engineering.

In particular, the standards deliberately require explicit readable implementations around:

- authorization and tenant scoping;
- RLS;
- cryptography/HMAC;
- session/auth handling;
- policy/state transitions;
- SMTP responsibility;
- parser boundaries;
- artifact access;
- audit.

Security-critical code should be easier to audit, not optimized for brevity.

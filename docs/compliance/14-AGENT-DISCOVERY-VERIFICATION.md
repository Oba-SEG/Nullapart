# Coding-Agent Discovery Verification

Verify the repository instruction chain before relying on each coding-agent platform for implementation.

## Canonical expectation

Every supported coding agent must ultimately receive root `AGENTS.md` and therefore be directed to the same Security/Roadmap/Phase/Code-Standards chain.

## Codex

Verify a Codex session in the repository can identify root `AGENTS.md` and summarize its non-negotiable rules before editing.

Do not create a separate `CODEX.md` policy file.

## OpenCode

Verify an OpenCode session launched at repository root loads root `AGENTS.md` and reports the same canonical rules.

Do not create a separate `OPENCODE.md` policy file.

## Copilot

Verify `.github/copilot-instructions.md` is active on the intended Copilot surfaces and points back to `AGENTS.md`.

## Claude / Gemini / Cursor

Verify the respective adapter/rule files are recognized in the chosen tooling and do not contradict root `AGENTS.md`.

## Test prompt

A useful verification prompt is conceptually:

```text
Before changing files, list the repository instruction sources/rules you are following and summarize the Nullapart requirements for tenant scope, main-branch changes, code standards and security tests. Do not edit anything.
```

The expected answer should reflect:

- tenant scope derives from authenticated context;
- no direct push to `main`;
- canonical formatting/lint/type checks;
- Security/Phase/Code-Standards reading order;
- no weakening security controls for convenience.

Record evidence in `docs/compliance/10-AGENT-INSTRUCTION-EVIDENCE.md`.

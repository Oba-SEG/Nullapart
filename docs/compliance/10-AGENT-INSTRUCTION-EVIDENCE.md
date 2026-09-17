# Coding-Agent Instruction Evidence

**Status:** engineering-control evidence template.

## Canonical source

- `AGENTS.md`

## Supported adapter/discovery files

- `.github/copilot-instructions.md`
- `CLAUDE.md`
- `GEMINI.md`
- `.cursor/rules/nullapart.mdc`
- `docs/ai/AGENT-DISCOVERY.md`

OpenAI Codex and OpenCode are intentionally covered directly through root `AGENTS.md` rather than separate duplicated policy files.

## Evidence checklist

| Control | Status/evidence |
|---|---|
| Root `AGENTS.md` present | TBD/verify |
| Codex discovery verified | TBD |
| OpenCode discovery verified | TBD |
| Copilot adapter present | TBD/verify |
| Claude adapter present | TBD/verify |
| Gemini adapter present | TBD/verify |
| Cursor rule present | TBD/verify |
| Adapters point to canonical policy | TBD |
| CI/testing prevents agent bypass of required controls | TBD |
| Protected `main` prevents direct agent push | TBD |

This is not complete until the relevant agent/tool behavior and repository enforcement have been exercised.

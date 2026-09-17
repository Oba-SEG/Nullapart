# Agent Discovery Adapter Verification

**Status:** structural verification complete. Exercise verification requires running actual coding-agent sessions.

## Adapter inventory

| Agent | Adapter file | Lines | Points to AGENTS.md | No independent policy |
|-------|-------------|-------|---------------------|----------------------|
| OpenAI Codex | (uses root AGENTS.md directly) | — | ✅ | ✅ |
| OpenCode | (uses root AGENTS.md directly) | — | ✅ | ✅ |
| GitHub Copilot | `.github/copilot-instructions.md` | 16 | ✅ | ✅ |
| Claude-compatible | `CLAUDE.md` | 13 | ✅ | ✅ |
| Gemini-compatible | `GEMINI.md` | 13 | ✅ | ✅ |
| Cursor | `.cursor/rules/nullapart.mdc` | 17 | ✅ | ✅ |

## Structural verification results

### 1. All adapters point to AGENTS.md as canonical
- ✅ Copilot: "The canonical coding-agent rules for this repository are in root `AGENTS.md`."
- ✅ Claude: "The canonical coding-agent instructions are in root `AGENTS.md`."
- ✅ Gemini: "The canonical coding-agent instructions are in root `AGENTS.md`."
- ✅ Cursor: "The canonical coding-agent instructions are in root `AGENTS.md`."

### 2. All adapters are short (< 20 lines)
- ✅ Copilot: 16 lines
- ✅ Claude: 13 lines
- ✅ Gemini: 13 lines
- ✅ Cursor: 17 lines

### 3. All adapters include the instruction chain
Every adapter includes:
1. Read `AGENTS.md`
2. Read `SECURITY.md`
3. Identify owning phase
4. Follow `CODE-STANDARDS.md`
5. Use `CODING-AGENT-OPERATING-MODEL.md`

### 4. No adapter duplicates policy
- ✅ Copilot: "Do not treat this file as a separate policy source."
- ✅ Claude: "This file intentionally contains no separate architectural or security policy."
- ✅ Gemini: "This file intentionally contains no separate architectural or security policy."
- ✅ Cursor: "This rule is an adapter only. Do not duplicate or override the canonical architecture/security policy here."

### 5. No legacy files present
- ✅ No `.cursorrules` file exists
- ✅ No `CODEX.md` or `OPENCODE.md` parallel policy files

## Exercise verification (requires running agents)

The following tests require running actual coding-agent sessions:

- [ ] **Codex**: Start a Codex session in this repo → verify it reads AGENTS.md and follows the instruction chain
- [ ] **OpenCode**: Start an OpenCode session → verify it discovers AGENTS.md and loads phase docs
- [ ] **Copilot**: Open in VS Code with Copilot → verify it references the adapter
- [ ] **Cursor**: Open in Cursor → verify the always-applied rule loads
- [ ] **Claude**: Start a Claude Code session → verify CLAUDE.md adapter is consumed

These cannot be automated from the CLI — they require human-driven sessions with each agent.

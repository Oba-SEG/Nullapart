# Implementation Gate Status Register

**Status:** working readiness register.

This file distinguishes documented design from controls that are actually activated/verified.

| Gate | Required state before normal implementation | Current documentation state | Operational/technical activation |
|---|---|---|---|
| Phase -1 security program | Accepted | Documented | TBD acceptance |
| Root agent instructions | Present | Present | Verify with coding agents |
| Codex/OpenCode AGENTS discovery | Works | Documented | Verify exercise |
| Protected `main` | No direct pushes; PR required | Required in policy | **Not verifiable/activatable via current ChatGPT GitHub integration** |
| Required CI workflows | Active | Architecture documented | Not yet implemented |
| Formatter/linter/typecheck gates | Merge-blocking | Standards documented | Not yet implemented |
| TenantContext / feature override framework | Implemented/tested | Architecture documented | Not yet implemented |
| Tier-3 SLO/burn-rate framework | Defined and instrumentable | Architecture documented | Runtime evidence later |
| Zero-day response process | Accepted/exercisable | Process documented | Exercise/evidence later |
| CODEOWNERS | Real owners assigned | Policy documented | TBD owners |
| AWS OIDC deployment identity | Scoped short-lived roles | Architecture documented | Phase 0 implementation |

Do not mark a gate complete because a design document exists. Evidence/activation is required where the gate describes an operating control.

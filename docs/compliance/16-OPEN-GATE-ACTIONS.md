# Open Gate Actions

These actions require repository/organization/operator access outside the current architecture-writing integration.

## Before normal Phase 0 implementation

- Activate GitHub `main` protection/ruleset with no direct pushes, required PR/review/checks, no force push/deletion.
- Assign real security/repository owners and populate CODEOWNERS.
- Verify Codex and OpenCode sessions actually load root `AGENTS.md`.
- Verify Copilot/Claude/Gemini/Cursor adapters in the tools the team will use.
- Accept Phase -1 security program with named owners.

## During Phase 0 implementation

- Create real GitHub Actions workflows.
- Wire merge-blocking formatter/lint/type/security checks.
- Initialize lockfiles/toolchain pins.
- Implement TenantContext and feature-override foundation.
- Implement observability primitives needed for later Tier-3 SLOs.
- Establish SBOM/dependency inventory for zero-day correlation.

This is a status/action list, not a substitute for the canonical architecture documents.

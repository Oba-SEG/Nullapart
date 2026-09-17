# Repository Administrator Handoff

## Branch protection — documented policy rule

GitHub branch protection for `main` (no direct pushes, PR required, required reviews) requires GitHub Pro or a public repository, which is not available for this private repository.

**Decision:** Protected `main` is enforced as a documented policy-level rule rather than a GitHub branch protection setting. The rule is:

- **No direct pushes to `main`** — all changes go through reviewed PRs.
- Emergency changes still use expedited PR/review/checks, not direct pushes.
- CODEOWNERS and CI required checks enforce review quality.
- All contributors are expected to follow this rule; violations are treated as policy exceptions.

This compensating control is recorded in `docs/compliance/12-IMPLEMENTATION-GATE-STATUS.md`.

If the repository plan changes to support branch protection, activate the GitHub-enforced setting and remove this compensating-control language.

## Actions requiring GitHub repository/organization administration

When available:

1. Configure production GitHub Environments and human approvals before production use.
2. Add maintainers/security owners and update CODEOWNERS with real GitHub identities.
3. Record evidence in the compliance gate files.

Architecture reference: `docs/security/19-VERSION-CONTROL-CICD.md`.

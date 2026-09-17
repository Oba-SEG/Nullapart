# Repository Administrator Handoff

Actions requiring GitHub repository/organization administration:

1. Enable/enforce protected `main` with no direct pushes.
2. Deny force pushes and branch deletion.
3. Require PR review and required checks.
4. Configure stale-approval/conversation requirements where supported.
5. Configure production GitHub Environments and human approvals before production use.
6. Assign maintainers/security owners and add CODEOWNERS with real GitHub identities.
7. Record evidence in the compliance gate files.

Architecture reference: `docs/security/19-VERSION-CONTROL-CICD.md`.

This handoff exists because the current GitHub app connection cannot administer branch protection/rulesets.

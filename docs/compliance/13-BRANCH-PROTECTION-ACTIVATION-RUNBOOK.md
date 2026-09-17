# Branch Protection Activation Runbook

**Owner:** repository/organization administrator — assign before Phase 0 implementation.

## Target

Repository: `obakeng-SEG/Nullapart`

Branch: `main`

## Required configuration

Configure GitHub branch protection/ruleset so that:

- direct pushes to `main` are denied;
- force pushes are denied;
- deletion is denied;
- pull request is required;
- at least one qualified approval is required;
- required status checks are enforced;
- stale approvals are dismissed for changed security-sensitive content where supported;
- conversation resolution is required where supported;
- security/CODEOWNERS review becomes required once actual owners are assigned;
- no automation can self-approve/merge a sensitive change;
- routine administrator bypass/direct push is not allowed.

Emergency changes still use expedited PR/review/checks.

## Verification

After activation:

1. attempt a direct push using a normal contributor identity and verify denial;
2. verify an unreviewed PR cannot merge;
3. verify a PR with failing required check cannot merge;
4. verify force push/deletion are denied;
5. record the rule/ruleset screenshots/export/settings evidence in `docs/compliance/07-MAIN-BRANCH-PROTECTION-EVIDENCE.md` or the chosen evidence system;
6. update `docs/compliance/12-IMPLEMENTATION-GATE-STATUS.md`.

## Current limitation

The ChatGPT GitHub integration used during architecture work does not have GitHub repository administration permission to activate or verify branch protection. An authorized human/organization-admin action is required.

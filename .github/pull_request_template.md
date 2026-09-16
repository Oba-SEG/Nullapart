## Objective

Describe the problem/change and expected outcome.

## Roadmap phase

Owning phase:

- [ ] Phase -1
- [ ] Phase 0
- [ ] Phase 1
- [ ] Phase 2
- [ ] Phase 3
- [ ] Phase 4
- [ ] Phase 5
- [ ] Phase 6
- [ ] Phase 7
- [ ] Phase 8
- [ ] Phase 9

Detailed phase specification reviewed:

- [ ] Yes

## Architecture / security impact

Affected architecture/security documents:

Trust boundaries changed?

- [ ] No
- [ ] Yes — threat model updated

Data classification affected?

- [ ] No
- [ ] Yes — handling reviewed

Tenant/customer isolation affected?

- [ ] No
- [ ] Yes — tests included

## Implementation

Summarize code/config/schema/UI changes.

## Authentication / authorization

- [ ] No auth impact
- [ ] Server-side authorization reviewed
- [ ] New privileged action includes step-up/permission handling where required

## Audit

- [ ] No administrative/security action added
- [ ] Required Admin Audit events implemented/tested

## UI

- [ ] No UI required
- [ ] UI implemented with backend
- [ ] No raw JSON exposed
- [ ] Accessibility/loading/empty/error states covered
- [ ] Support message-content restrictions verified where applicable

Screenshots/evidence:

## Database / migrations

- [ ] No schema change
- [ ] Migration added
- [ ] Backward compatibility considered
- [ ] Rollback/forward-fix plan documented

## Tests

- [ ] Unit
- [ ] Integration
- [ ] Security
- [ ] UI/E2E where applicable
- [ ] Tenant isolation where applicable
- [ ] Failure-path tests

Test evidence:

## Observability

- [ ] SegLumberjack/Sentry-compatible telemetry updated where required
- [ ] Native daemon telemetry updated where required
- [ ] CloudWatch/infrastructure telemetry updated where required
- [ ] Sensitive content/secrets are scrubbed

## CI/CD / release impact

- [ ] No workflow/release impact
- [ ] CI workflow permissions reviewed
- [ ] No long-lived cloud credentials introduced
- [ ] Artifact/version compatibility considered
- [ ] Production target/rollout implications documented

## Security findings / exceptions

Known security findings:

Security exception ID/expiry, if any:

## Rollback / containment

Describe how this change can be rolled back or safely contained.

## Documentation

- [ ] Architecture/docs updated where behaviour changed
- [ ] Runbook/help text updated where required
- [ ] Documentation and implementation agree

## Reviewer checklist

- [ ] Phase scope is correct
- [ ] No unnecessary new service/network boundary
- [ ] Security Program requirements are met
- [ ] CI checks pass without bypass
- [ ] Exit criteria impacted by this change remain satisfiable

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

## Application security

- [ ] Tenant/user scope derives from authenticated server context, not client IDs
- [ ] Object ownership/BOLA/IDOR checks exist for reads/writes/actions
- [ ] Wrong-user / wrong-tenant / wrong-owner tests included
- [ ] Client validation is backed by authoritative server validation
- [ ] PostgreSQL RLS considered/applied where appropriate
- [ ] RLS pooled-connection context tested where applicable
- [ ] Retryable/destructive operations define idempotency
- [ ] No auth/refresh credentials stored in Local Storage / Session Storage
- [ ] CSRF considered for cookie-authenticated mutations
- [ ] OAST/SSRF tests included if server-side outbound network access exists
- [ ] Writable fields are allowlisted against mass assignment
- [ ] Client-facing errors are safe and structured

## Authentication / authorization

- [ ] No auth impact
- [ ] Server-side authorization reviewed
- [ ] New privileged action includes step-up/permission handling where required
- [ ] No bearer/session/API secrets introduced in URLs
- [ ] TLS/mTLS/certificate trust assumptions reviewed where applicable
- [ ] No browser HPKP/Public-Key-Pins introduced

## API / schema / feature flags

- [ ] No API/event/schema compatibility impact
- [ ] API v1 compatibility reviewed
- [ ] Event/scanner/config/AI schema version updated where needed
- [ ] Breaking change uses explicit migration/version strategy
- [ ] Feature switch required for safe rollout/kill behavior
- [ ] Feature switch is server-authoritative, audited and has owner/removal lifecycle
- [ ] Feature flag is not being used as authorization

## HMAC / webhook integrity

- [ ] Not applicable
- [ ] Existing provider verification scheme followed
- [ ] Nullapart HMAC helper/contract reused where applicable
- [ ] Replay protection/idempotency tested
- [ ] Key rotation/key ID considered
- [ ] Constant-time verification used

## ML / LLM skills and tools

- [ ] No runtime ML/LLM impact
- [ ] Skill/input/output schema updated
- [ ] Allowed data classes reviewed
- [ ] Tool permissions/tenant/region scope reviewed
- [ ] Prompt-injection/tool-result handling tested
- [ ] Context/token limits defined
- [ ] Model/tool cannot directly self-authorize state changes

## Audit

- [ ] No administrative/security action added
- [ ] Required Admin Audit events implemented/tested

## UI

- [ ] No UI required
- [ ] UI implemented with backend
- [ ] No raw JSON exposed
- [ ] Accessibility/loading/empty/error states covered
- [ ] Support message-content restrictions verified where applicable
- [ ] Feature-disabled/unavailable states designed where applicable

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
- [ ] API/schema compatibility tests where applicable
- [ ] Feature flag/idempotency/replay tests where applicable

Test evidence:

## Observability

- [ ] SegLumberjack/Sentry-compatible telemetry updated where required
- [ ] Native daemon telemetry updated where required
- [ ] CloudWatch/infrastructure telemetry updated where required
- [ ] Sensitive content/secrets are scrubbed

## Business logic / abuse / dependency lifecycle

- [ ] Business state/policy invariants reviewed
- [ ] Stale/concurrent update behavior reviewed
- [ ] Rate-limit/abuse impact reviewed
- [ ] High-risk action limits added/updated where needed
- [ ] Dependency/runtime versions remain pinned/supported
- [ ] Package/toolchain peer compatibility verified
- [ ] Frozen lockfiles remain reproducible
- [ ] No unrelated broad dependency upgrade
- [ ] Firewall/port/egress impact reviewed
- [ ] Compliance/data-processing/third-party records updated where required

## CI/CD / GitHub Actions / release impact

- [ ] No workflow/release impact
- [ ] CI workflow permissions reviewed
- [ ] Third-party Actions remain pinned to reviewed immutable SHAs where practical
- [ ] Untrusted PR code receives no privileged secrets
- [ ] No long-lived cloud credentials introduced
- [ ] Artifact/version compatibility considered
- [ ] Production target/rollout implications documented
- [ ] AI/automation does not self-approve production

## Security findings / exceptions

Known security findings:

Security exception ID/expiry, if any:

## Rollback / containment

Describe how this change can be rolled back or safely contained.

## Documentation

- [ ] Architecture/docs updated where behaviour changed
- [ ] Runbook/help text updated where required
- [ ] Coding-agent/project instructions updated where needed
- [ ] Documentation and implementation agree

## Reviewer checklist

- [ ] Phase scope is correct
- [ ] No unnecessary new service/network boundary
- [ ] Security Program requirements are met
- [ ] CI checks pass without bypass
- [ ] Exit criteria impacted by this change remain satisfiable

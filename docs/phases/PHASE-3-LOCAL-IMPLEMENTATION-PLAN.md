# Phase 3 Local Implementation Plan — Control Plane

**Status:** all four increments are complete and evidence-backed (see the
*Evidence* section that follows each increment). Checked work is
evidence-backed, not inferred from the presence of a module.

## Recorded identity decision (IdP-agnostic BFF first)

The identity decision is **recorded (2026-09-29, owner decision): ZITADEL is
the accepted identity platform** (`docs/03-IDENTITY-RBAC-IMPERSONATION.md`,
`docs/15-AWS-DEPLOYMENT.md`). Constraints that remain in force for the
integration work this unblocks:

1. ZITADEL/OIDC integration code is written only from this accepted decision —
   no second or accidental identity mechanism
   (`docs/ai/CODING-AGENT-OPERATING-MODEL.md` change discipline).
2. Control Plane surfaces stay **IdP-agnostic**: server-side session context
   injected by the authenticated boundary (today the local reverse proxy +
   workload token), plus admin user/role/permission data behind a
   provider-neutral interface. ZITADEL plugs into that boundary as the
   OIDC login/assertion source instead of replacing it; product authorization
   stays in Nullapart.
3. Browser sessions stay cookie-only; auth/refresh tokens are never stored in
   Local Storage, Session Storage or IndexedDB.

## Goal and boundaries

Deliver the Control Plane in reviewable increments, each end-to-end (contract,
authorization, persistence, UI, tests, docs):

```text
increment 1: Admin Audit API + UI   (scoped list/detail/export, audited reads)
increment 2: admin sessions + RBAC foundation (user/role/permission model,
             step-up + logout semantics, permission-aware UI)
increment 3: impersonation + support access model on top of increments 1-2
increment 4: ZITADEL OIDC identity integration (login, identity mapping,
             IdP-backed step-up) — complete, see Increment 4 evidence
```

Increment 1 is deliberately read-only: it proves the authorization/RLS/audit
plumbing that every later Control Plane surface reuses, without an identity
dependency.

## Work order

### Increment 1 — Admin Audit API + UI

- [x] Record the IdP-agnostic BFF decision and the increment boundary in this
      plan; no identity-provider code.
- [x] Add the audit read-scope RLS policy (tenant / platform / own) with
      fail-closed missing settings, narrow write authority per scope, and a
      deployment-bounded search index (`migrations/009_admin_audit_scope.sql`).
- [x] Implement `crates/mail-core/src/admin_audit.rs`: server-authorized
      `AuthorizedAuditAccess` from `TenantContext`, validated/bounded filters,
      keyset pagination, redacted key/value detail rendering (never raw JSON),
      and scoped list/detail/export handlers that audit every read and export
      in the same transaction (fail closed).
- [x] Rate-limit CSV export with the reviewed high-risk `TokenBucket`
      (`HighRiskLimits::audit_export()`), require `audit:export` plus step-up,
      and neutralize spreadsheet formula injection in export cells.
- [x] Mount the router behind the authenticated local boundary and grant the
      local server context `audit:view` / `audit:export`
      (`crates/mail-core/src/bin/mailcore-server.rs`).
- [x] Project server-derived permissions through the session endpoint for UI
      affordances only; every call re-authorizes server-side
      (`crates/mail-core/src/local_control.rs`).
- [x] Add DB-backed tests for the RLS scopes, write authority, store scoping,
      cross-tenant probe denial, deployment bounding, and export audit rows
      (`crates/mail-core/tests/postgres_admin_audit.rs`).
- [x] Deliver the Audit Log UI: scoped list with filters and load-more,
      redacted detail drawer, permission-gated audited CSV export, route and
      navigation (`frontend/src/pages/AuditLog.*`).
- [x] Run canonical format/lint/typecheck/workspace tests and the ignored
      database suite against the local PostgreSQL; fix phase-scoped defects
      found by that pass.
- [x] Rebuild the local stack and verify the API and UI live.

### Increment 2 — admin sessions and RBAC foundation (complete; evidence below)

- [x] Admin user, role and permission persistence with server-side
      authorization and audit for every grant/revoke: migration
      `010_admin_rbac_sessions.sql` (deployment-RLS on `admin_users`,
      `admin_roles`, `admin_role_permissions`, `admin_user_roles`,
      `admin_sessions`), `PostgresAdminRbacStore` writes every mutation and its
      `audit_events` row in one transaction (`crates/mail-core/src/admin_rbac.rs`).
- [x] Session lifecycle (login, logout, expiry, step-up) behind the
      provider-neutral boundary: opaque SHA-256-hashed cookie sessions,
      idle/absolute expiry, step-up freshness for permission changes, CSRF
      token minted per session, bootstrap of the first identity of an empty
      deployment; no tokens in browser storage (only the HttpOnly cookie plus
      an in-memory CSRF token, `frontend/src/auth/csrf.ts`).
- [x] Permission-aware navigation and route guards driven by the session
      projection, still re-authorized on every request: `requirePermission`
      guards in `frontend/src/lib/router.tsx`, permission-gated navigation and
      sign-out in `frontend/src/components/Layout.tsx`.
- [x] Boundary middleware replaces the interim local session router:
      `authenticated_local_router` / `require_local_auth` in
      `crates/mail-core/src/admin_rbac.rs`; `local_control.rs` removed;
      quarantine routes moved onto the same boundary
      (`crates/mail-core/src/quarantine_api.rs`).
- [x] Reverse-proxy identity handoff: only the exact local `POST /auth/login`
      endpoint accepts HTTP Basic credentials, consumes them at Nginx, forwards
      `X-Nullapart-Local-User $remote_user` behind the private workload bearer,
      and exchanges it for the server-side session. Every other proxied request
      clears that caller-controlled header; the branded login and OIDC `GET`
      entrypoint never produce a browser-native credential prompt
      (`frontend/nginx.conf`, `frontend/src/auth/session.ts`).
- [x] Runtime role grants for the new tables in
      `infrastructure/containers/provision-local-runtime-role.sh`.
- [x] Tests: 20 unit tests in `admin_rbac.rs` (bootstrap, CSRF, expiry,
      suspend, permission/step-up/rate-limit denials with audited outcomes,
      idempotent grants, self/cross-customer refusal), frontend
      `session.test.ts` / `client.test.ts`, and the ignored database suite
      `crates/mail-core/tests/postgres_admin_rbac.rs` (RLS fail-closed,
      bootstrap/session lifecycle audit, cross-deployment isolation).

### Increment 3 — impersonation and support access (complete; evidence below)

> **Superseded design detail (2026-10-01):** the acting-as subject-intersection
> design described below was replaced by customer entry — the session switches
> customer scope only and the actor's own roles/permissions are unchanged
> (canonical: `docs/03-IDENTITY-RBAC-IMPERSONATION.md`, migration
> `017_customer_entry_impersonation.sql`). Lifecycle/audit/rate-limit
> scaffolding, the escalation guard and logout-implicit end carry over
> unchanged; routes and audit action names were kept.

- [x] Impersonation/supervision model with explicit support permissions,
      end-actor visibility, and audited start/end (`docs/03`): migration
      `011_admin_impersonation.sql` (one active interval per session via
      partial unique index, 10–500 char reason `CHECK`, deployment RLS);
      `start_impersonation`/`end_impersonation` in
      `crates/mail-core/src/admin_rbac.rs` write the start/end `audit_events`
      row in the same transaction; logout closes the interval
      (`ended_reason='session_revoked'`) without an extra end row.
- [x] Acting-as overlay: `resolve_session` joins the active interval, keeps
      the real actor identity/roles, and intersects actor ∩ subject
      permissions; `build_context` publishes `ImpersonationContext`, so
      `POST /api/v1/admin/impersonations` is gated by `admin:impersonate`, a
      fresh step-up, the dedicated `HighRiskLimits::impersonation_start`
      budget, reason validation, and refusals for self / non-customer /
      suspended / non-`customer_admin` subjects (409 when an interval is
      already active). `POST /api/v1/admin/impersonations/end` is idempotent
      and deliberately skips step-up and rate limits so stopping always works.
- [x] End-actor visibility: start/end rows carry `impersonated_subject` /
      `impersonated_customer` and the impersonated customer's `customer_id`;
      audit reads during an interval are narrowed to
      `Customer(impersonated)` regardless of the real actor's role scope
      (`crates/mail-core/src/admin_audit.rs::from_context`).
- [x] Support defaults to own activity; cross-customer reads require the
      explicit `audit:cross_customer`-style permission
      (`docs/03`): `support` keeps `AuditScope::Own` by default (covered by
      `admin_audit.rs` tests); the user directory accepts either
      `admin:users:manage` or `admin:impersonate` for targeting.
- [x] Role-escalation defect from increment 2 fixed:
      `role_level_rank`/`roles_within_grantor_level` deny creating, granting
      or revoking a role above the grantor's level (audited). The bootstrap of
      an empty deployment now yields `system_admin` (deliberate decision: one
      local operator can provision below-level roles without escalation).
- [x] UI: persistent `ImpersonationBanner` (subject, reason, Stop without
      extra gates) in the shell, `/admin-users` directory with the Act-as
      dialog (reason ≥ 10 characters), permission-gated route and navigation
      (`frontend/src/pages/AdminUsers.*`,
      `frontend/src/components/ImpersonationBanner.tsx`,
      `frontend/src/lib/router.tsx`, `frontend/src/components/Layout.tsx`,
      `frontend/src/auth/session.ts`).
- [x] Tests: unit coverage for the lifecycle and dual-identity audit,
      permission/step-up/reason denials, subject refusals, the dedicated rate
      budget, logout's implicit end, both escalation denials, and the
      impersonated audit scope; frontend `AdminUsers.test.tsx` and
      `session.test.ts`; ignored database suite
      `crates/mail-core/tests/postgres_admin_impersonation.rs` (RLS
      fail-closed, start/end/resolve overlay with intersection, one active
      interval per session, logout end).

### Increment 4 — ZITADEL OIDC identity integration (complete)

**Status:** complete with live evidence (2026-09-29). Every item below carries
the same evidence standard as increments 1–3; the run itself, including the
two defects it exposed, is recorded under *Increment 4 evidence* at the end of
this document.

Scope decisions embedded in this increment (unchanged from the draft):

- **Local verification runs a real ZITADEL container** in `compose.local.yml`
  on the private network only (`docs/24` treats ZITADEL internals as private),
  so the increment finishes with the same live-evidence standard as 1–3.
- **The BFF boundary stays.** ZITADEL is the login/assertion source only;
  opaque cookie sessions in `admin_sessions`, server-side authorization, RLS,
  impersonation and audit semantics from increments 1–3 are untouched.
- **Product RBAC stays local.** No role/permission mirroring from the IdP;
  ZITADEL enforces MFA/passkeys for its users, Nullapart enforces what they
  may do.
- **Single IdP, no SCIM/SAML/self-signup in this increment.**

- [x] Local `zitadel` service and its private datastore `zitadel-db` added to
      `compose.local.yml`; first-run machine key and PATs are written to the
      git-ignored `infrastructure/containers/.zitadel-bootstrap/` (never to
      container logs); the control-plane project, OAuth client and redirect
      allow-list come from the idempotent
      `infrastructure/containers/provision-local-zitadel.sh` (ids in
      `.zitadel-bootstrap/provision.json`); MFA is forced, self-registration
      is disabled; runbook documented in
      `infrastructure/containers/LOCAL-DEVELOPMENT.md` and the missing
      identity block added to `.env.local.example`.
- [x] Server-side OIDC relying party in Mail Core: authorization-code flow
      with PKCE S256, `state`/`nonce` validation, issuer/redirect-URI checks,
      one-shot flow rows in `oidc_login_flows`; `GET /api/v1/auth/login`
      starts the flow and `GET /api/v1/auth/oidc/callback` completes it — the
      callback is the protocol's explicitly designed alternative trust
      mechanism and creates no session until every check verifies. Extra
      ID-token audiences are accepted only when `azp` names this client, and
      profile/e-mail claims fall back to the UserInfo endpoint bound to that
      subject when the provider withholds them. Tokens never reach browser
      storage; the browser holds only the existing HttpOnly session cookie.
- [x] Identity mapping on first successful callback: IdP `sub` →
      `admin_users.auth_subject`, unique per deployment (partial unique index
      from `012_oidc_identity_integration.sql`); link-by-match for existing
      unlinked local users; the empty deployment bootstrap invariant survives
      (first IdP identity becomes `system_admin`); unknown/unprovisioned
      subjects are refused and audited without creating a user.
- [x] Server-authoritative mode switch `identity_provider = proxy_header |
      oidc` (configuration, never authorization): `proxy_header` remains the
      default so CI and IdP-less development keep working, the local stack is
      flipped to `oidc`, and the flip is verified in both directions.
- [x] Step-up gains an IdP-backed option (`GET /api/v1/auth/reauth` forces
      `prompt=login`) while the local freshness flag remains the floor;
      idle/absolute expiry, CSRF guard and revocation are unchanged; logout
      revokes locally first and then continues to the provider's end-session
      endpoint when one is published.
- [x] Audit: `session_login` rows carry the IdP subject and auth method;
      failed callbacks (verification failure, unknown subject) write audited
      denials; a completed step-up writes `session_step_up`; impersonation
      and audit-scope attribution are untouched.
- [x] Frontend: hybrid login. In proxy-header mode a deliberate local-console
      form sends Basic credentials only on the exact login POST; credentials
      are never persisted and Nginx removes the header before Mail Core. The
      separate configured-identity-provider action performs a real top-level
      `GET /api/v1/auth/login`, so OIDC flow cookies, authorization redirect
      and IdP UI behave like any other authorization-code client. The callback
      returns to the app with the session already established, logout performs
      RP-initiated logout, and the session projection, banner and permission
      guards are unchanged.
- [x] Tests: unit coverage (flow state machine, PKCE/nonce/state and
      signature failures, audience/`azp` handling, UserInfo fallback and
      subject binding, mode switch, mapping/bootstrap/link/refusal paths) and
      the ignored PostgreSQL suite, extended by
      `crates/mail-core/tests/postgres_oidc_identity.rs` (`auth_subject`
      uniqueness per deployment plus cross-deployment rebind refusal, and
      `oidc_login_flows` fail-closed/one-shot claim/cross-deployment
      isolation). Live verification drives the real IdP at HTTP level
      (login with MFA → session → audited `session_login` → step-up → logout
      killing both sessions) rather than an interactive browser session; the
      proxy-header regression is re-run after the flip.
- [x] Docs/compat: `openidconnect 4.0.1` recorded per
      `docs/26-PACKAGE-COMPATIBILITY.md` (lockfile, rustls-only features,
      zero-day patchability), `docs/03-IDENTITY-RBAC-IMPERSONATION.md`
      updated from plan to implemented, redirect/callback surface reviewed
      (allow-listed same-origin `return_to`, hashed one-shot state, PKCE,
      issuer/redirect checks, `azp`-bound audiences, subject-bound UserInfo,
      no open redirect, no token in browser storage), and gate status
      recorded in the evidence below.

### Increment 5 — Customer and domain administration (complete)

**Status:** complete with offline gate evidence; live evidence recorded under
*Increment 5 evidence* below.

Scope decisions:

- **Lifecycle is a server-side state machine**: `active ↔ grace`,
  `active|grace|suspended → terminated`, `suspended → active|terminated`,
  `terminated → active`; every transition requires a ≥10-character reason and
  is validated before authorization, rate limiting and execution, with the
  audit row written in the same transaction. `Deprovisioned` maps to
  `Terminated`; `Grace` is the new billing/suspension buffer state.
- **Ownership is strict**: `system_admin` may target any customer;
  `support` and `customer_admin` only their authenticated
  `context.customer_id`; a foreign target returns `404 NOT_FOUND` (never an
  existence leak) and is audited as denied.
- **Domain verification is offline-DNS**: a hand-rolled UDP TXT lookup
  (`dns_txt.rs`, no new dependency) validates the challenge record;
  verification attempts (success and failure) are audited
  (`domain_added`, `domain_verified`, `domain_verification_failed`).
- **Duplicate guarded inserts surface as `409`**, not `503`
  (`unique_violation_or_unavailable`), including cross-customer duplicates.
- **Idempotency reuses the reviewed contract**: the existing
  `idempotency_keys` table with `x-idempotency-key`; every mutation requires
  the header and replays return the original outcome without duplicate side
  effects.

- [x] Migration `013_customer_domain_administration.sql`: customer lifecycle
      (incl. `Grace`), domains with TXT verification state, `source_ip_groups`
      and `idempotency_keys` with RLS + guarded grants.
- [x] `crates/mail-core/src/admin_customers.rs`: nine routes under
      `/api/v1/admin/customers...` (create/get/list/update, lifecycle
      transitions, domains add/list/verify, source-IP groups) with explicit
      writable-field allowlists, `deny_unknown_fields` bodies, permissions
      `admin:customers:view|manage` and `admin:domains:manage` in
      `BUILTIN_ROLES` (support gets view+manage on customers but cannot add
      `send_only` domains; customer_admin is restricted to its own customer).
- [x] Frontend: `Customers` list/create, `CustomerDetail` (domains, DNS
      verification, lifecycle transitions, source-IP groups) with route +
      Layout nav gating through the established permission helpers.
- [x] Tests: offline unit tests per route/permission/state-machine path, the
      ignored PostgreSQL suite `postgres_customer_admin.rs` (RLS, ownership
      cross-customer 404, idempotent replay, audit rows), plus fresh-volume
      runtime-role grants fixed in
      `infrastructure/containers/provision-local-runtime-role.sh` (migrations
      run before the provision script on empty volumes, so the script carries
      the full grant list).

### Increment 6 — Policy and feature administration (complete)

**Status:** complete with offline gate evidence; live evidence recorded under
*Increment 6 evidence* below.

Scope decisions:

- **Policy families are the unit of publication**: a seeded static catalog of
  24 families carries `management_level` (`system` floors vs `customer`
  families) and `security_floor`; revisions are immutable rows activated by
  swap (partial unique index on the active revision), never edited in place.
- **System security floors are non-negotiable**: mandatory families cannot be
  disabled and tenant overrides cannot defeat System floors
  (`mandatory_security_floors_cannot_be_disabled`, RLS
  `rls_feature_overrides_cannot_self_escalate`); `FeatureValue` DB encoding
  is the closed `inherit|enabled|disabled|typed:<raw>` text form.
- **Feature overrides are three-level** (system → tenant → customer) over the
  seeded `feature_definitions` (9 rows: floors `tenant_authorization`,
  `admin_audit`, `required_encryption`, `data_residency_enforcement`;
  switches `deep_ai_analysis`, `inline_ml_classification`,
  `outbound_remediation_connector`; features `remote_resource_preview`,
  `quarantine_digest_notifications`) and a feature switch is configuration,
  never authorization.
- **Publication writes evidence**: activating a revision also inserts a
  `config_revisions` row (scope `system`/`tenant`, source `policy_publish`)
  so runtime refresh and audit can observe what changed.

- [x] Migration `014_policy_administration.sql`: `policy_families` + 24-family
      seed, `policy_revisions` (`deployment_id`/`family_id`/`scope_level`,
      partial unique active index), `feature_definitions` seed, RLS rewrite
      for `policy_revisions`/`feature_overrides`/`config_revisions`.
- [x] `crates/mail-core/src/policy_admin.rs`: routes `GET/POST
      /api/v1/policies`, `GET/PUT /api/v1/policies/:family_key...`
      (detail, revisions, refresh), `GET /api/v1/features`,
      `PUT /api/v1/features/:feature_id/overrides` with permissions
      `policies:view|manage` (customer_admin only at
      `management_level='customer'`), optimistic revision checks, audit rows
      `policy_published`, `policy_refresh_requested`,
      `feature_override_changed`.
- [x] Frontend: `Policies` list, `PolicyFamilyDetail` (structured rule
      dialogs, publish/refresh with revision checks), `FeatureOverrides`
      (three-level table) + router/nav gating; `ScannerType` contract values
      match the Rust `lowercase` serde form (`urlanalysis`, `inlineml`,
      `deepai`).
- [x] Tests: offline unit tests (validation, floors, unknown family before
      DB, injected-field rejection), ignored suite
      `postgres_policy_admin.rs` (revision scoping, three-level override
      model, publish → revision + audit + outbox + config revision),
      static catalog mirroring the seed.

### Increment 7 — Runtime operations (complete)

**Status:** complete with offline gate evidence; live evidence recorded under
*Increment 7 evidence* below.

Scope decisions:

- **Read-only status plus an audited refresh**: `GET /api/v1/operations/runtime`
  projects outbox backlog and reinjection dead letters with real counts;
  `POST /api/v1/operations/refresh` requests a runtime config refresh,
  audited (`runtime_refresh_requested`) and idempotent under the same
  `x-idempotency-key` contract. No new service, queue or public endpoint.
- **Permissions**: `operations:view|manage` for `system_admin` and `support`
  only; customer_admin has no operations access.
- **RLS defense in depth**: the widened read policy on
  `outbox_events`/`reinjection_dead_letters` (`customer match OR deployment
  match`, `WITH CHECK` unchanged) lets deployment-level operators read while
  the existing platform-mint block and isolation tests keep holding.

- [x] Migration `015_runtime_operations.sql`.
- [x] `crates/mail-core/src/operations_api.rs` + offline tests (10) + ignored
      suite `postgres_operations_api.rs` (4).
- [x] Frontend `Operations` page (status table, refresh action with
      confirmation + idempotency key) routed behind `operations:view`.
- [x] Tests: fmt/clippy/workspace green; injected fields rejected; refresh
      side effects bounded by idempotency and audit.

### Increment 8 — Mail trace and hostile-content isolation (complete)

**Status:** complete with offline gate evidence; live evidence recorded under
*Increment 8 evidence* below.

Scope decisions:

- **Two honest surfaces, no fabricated data.** The Phase-1 workload contract
  stays (`POST /api/v1/trace/search`, `GET /api/v1/trace/transaction/:id`,
  `GET /api/v1/trace/health`) and is now backed by real queries against
  `smtp_transactions`/`smtp_transaction_recipients` (the non-RLS tables),
  deployment-scoped, with `flow_stages` derived only from real timestamps;
  fabricated fields (`node_id`/`node_version`/synthetic stages) were removed.
  Health reports real uptime/version and `queue_depth: null` when no honest
  source exists. The workload token (`NULLAPART_TRACE_WORKLOAD_TOKEN`) fails
  closed when unset and is wired through `compose.local.yml`/
  `.env.local.example`.
- **Session surface for the UI** lives inside the authenticated chain:
  `POST /api/v1/mail-trace/search`, `GET /api/v1/mail-trace/transaction/:id`
  with uniform customer scope (every role sees only rows with a
  `tenant_message_instances` row for its authenticated customer — matching
  the impersonation model), explicit `set_config` of
  `app.current_deployment_id`/`app.current_customer_id` inside each read
  transaction, and `flow_stages` built from real received/instance/attempt
  timestamps only. Permission `trace:view` for all three roles.
- **Full-message access is separately gated and audited**: `GET
  /api/v1/mail-trace/transaction/:id/content` requires `trace:content`
  (system_admin + customer_admin only — support is denied 403 and the denial
  is audited), ownership (≥1 instance of the authenticated customer, else
  404 + audited denial), a per-actor fail-closed rate limit (429 + audited),
  and reads the MIME artifact through the store with a new closed purpose
  `ArtifactAccessPurpose::ContentReview` (customer scope, exact artifact id,
  5-minute TTL, `can_read_content`); server response is JSON only (parsed
  subject/headers/plain/HTML/attachment metadata, capped at 512K/1M chars,
  100 headers, 50 attachments with a `truncated` flag) — raw bytes never
  leave the API, and audit rows (`trace_content_accessed`) never contain
  content.
- **Hostile rendering is isolated client-side**: the full-message view
  renders plain text and headers as React text nodes; the HTML part is
  sanitized with the trusted library (`sanitizeHtml`, DOMPurify allow-list
  with no `src`/event attributes) and displayed only inside
  `<iframe sandbox="">` (no scripts, no same-origin, no popups, no
  top-navigation) whose document carries a restrictive CSP
  (`default-src 'none'; style-src 'unsafe-inline'; img-src data:;
  base-uri 'none'; form-action 'none'`), so remote resources and scripts
  cannot run and the parent document is unreachable;
  `dangerouslySetInnerHTML` appears nowhere in the frontend. Attachment
  downloads are honestly marked unavailable in this environment.

- [x] `crates/mail-core/src/trace.rs` rewritten (workload + session +
      content surfaces, 21 offline unit tests) and
      `crates/mail-core/tests/postgres_trace.rs` (5 ignored: cross-customer
      search scoping, ownership 404, content success for system_admin and
      customer_admin, support 403 with audit row, RLS intact).
- [x] `artifact_store.rs` `ContentReview` purpose + grant tests (bound id,
      wrong id, expired, missing `can_read_content` all denied).
- [x] `admin_rbac.rs`: `trace:view`/`trace:content` constants and
      `BUILTIN_ROLES` grants (support has `trace:view`, never
      `trace:content`).
- [x] Frontend: real `Messages` trace search, `MessageDetail` (transaction,
      recipients, auth results, queue ids, instances, delivery attempts,
      findings, real flow timeline, permission-gated content button),
      `MessageContent` secure renderer; routes/nav gated on `trace:view`;
      three new test files (XSS corpus, sandbox/CSP assertions, no
      `dangerouslySetInnerHTML` source assertion).

### Security-test closure (phase-level §193)

- [x] IDOR/cross-tenant, wrong-owner, role escalation, impersonation
      escalation, CSRF, session fixation/revocation, audit correctness:
      covered by the admin RBAC/impersonation/audit suites (offline +
      ignored PostgreSQL) and the cross-customer 404s in increments 5–8.
- [x] **Support direct artifact access**: support has no `trace:content`
      (403 + audited denial) and artifact reads require a server-minted
      purpose-bound grant; `ContentReview` cannot read foreign/expired/
      unbound artifacts.
- [x] **Stored XSS from mail/customer fields**: mail-content XSS corpus in
      `MessageContent.test.tsx`; customer/domain name injection tests in
      `Customers.test.tsx`/`CustomerDetail.test.tsx`.
- [x] **Policy security-floor bypass**: `mandatory_security_floors_cannot_be_
      disabled` + `rls_feature_overrides_cannot_self_escalate`.
- [x] **Mass assignment**: every request body carries
      `deny_unknown_fields`; tests POST/PUT injected privileged fields on
      customer create/update, policy publish, feature override and both
      trace searches → `400` with a static error and a before/after
      snapshot proving no side effect.
- [x] **Unsafe error disclosure**: failure responses (unknown UUID, non-UUID
      path segment, malformed JSON, validation errors) are asserted to be
      exactly `{code,message}` JSON without SQL/provider/stack/secret
      markers.
- [x] **RLS bypass / pooled-connection context leakage**: RLS isolation
      suite plus `pooled_connection_guc_context_does_not_leak_across_
      transactions` (one pooled connection, GUC set transaction-locally;
      the context-free read fails closed).
- [x] **Idempotency replay/duplicate side effects**:
      `mutations_require_an_idempotency_key` + `idempotency_claims_replay_
      complete_and_mismatch`.
- [x] **Browser token persistence**: `session-storage.test.tsx` asserts
      authenticated API calls write nothing to `localStorage`/
      `sessionStorage`, API client sources never reference browser storage,
      and `verifySecureSession()` detects planted token keys.
- [x] **Export leakage**: the only Phase 3 export surface is Admin Audit CSV.
      It requires `audit:export`, fresh step-up and the high-risk limiter,
      writes an `audit_export` row, excludes free-form `details`, and
      neutralizes spreadsheet formula injection in exported cells.
- [x] **Immutable checkpoint status**: Admin Audit exposes a read-only
      checkpoint-status surface backed by append-only `audit_checkpoints`
      metadata. Local/dev honestly reports `not_configured` until an
      independent checkpoint writer records a signed/hash checkpoint; WORM/S3
      archive operation and checkpoint verification remain Phase 9 hardening.

## Completion gate

An increment is complete only when its unchecked items are implemented and the
end-to-end path has current local test evidence. A passing unit test alone is
not a completion claim. Phase 3 as a whole additionally requires the identity
decision to be recorded before any identity-provider integration; that decision
is recorded (ZITADEL, 2026-09-29).

Phase 3 meets this gate: increments 1–8 are checked, each carries its own
current local test evidence, the phase-level §193 security tests are closed,
the Admin Audit checkpoint-status surface is implemented, and the identity
decision required before any identity-provider integration is recorded.

## Evidence (2026-09-29 local stack on 192.168.8.4)

- **Gates**: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` (22 test binaries,
  0 failures) and `pnpm check-all` (format, lint, typecheck, 4 test files /
  6 tests) all pass.
- **Database suite** (`NULLAPART_TEST_DATABASE_URL` over an SSH tunnel to the
  local PostgreSQL): 15 ignored tests pass, including the five new admin-audit
  tests — unscoped sessions fail closed, tenant/platform/own read scopes,
  write authority per scope, store scoping with a self-audited cross-tenant
  probe denial, deployment bounding and export audit rows.
- **Migrations applied to the running volume**: `009_admin_audit_scope.sql`
  and, defect found by the suite, `008_local_runtime_boundaries.sql`, which had
  never been applied to the long-lived local volume — without it
  `claim_quarantine_reinjection_event(...)` did not exist and the reinjection
  worker (and its test) failed with `Persistence`. Fresh volumes already run it
  through `postgres-local-init.sh`.
- **Live verification**: through the local reverse proxy
  (`http://192.168.8.4:53080`, HTTP basic auth; `401` without credentials) —
  `GET /api/v1/auth/session` projects `audit:view` and `audit:export` for the
  local customer-admin context; `GET /api/v1/audit/events` returned the
  scoped page (`{data: {events, next_cursor}}`) and wrote an
  `audit_access_list` row; event detail returned redacted key/value pairs
  (never the raw filter JSON as a single blob) while an unknown id returned
  `404` with an `audit_access_denied` row; `POST /api/v1/audit/events/export`
  returned `text/csv` with `Content-Disposition` and wrote an `audit_export`
  row; the Audit Log page and its route bundle are served at
  `http://192.168.8.4:53080/audit-log`.
- **Runtime role (this pass)**: `mailcore` now starts as `nullapart_mailcore`
  (NOSUPERUSER, NOBYPASSRLS, no protected-table ownership) — startup logs
  `Mail Core database role posture verified` — so row-level security is active
  for the running application, not only for the request-role tests. Live proof:
  an unscoped `SELECT` on `audit_events` as that role returns 0 rows (fail
  closed) and a tenant-scoped read returns the customer's rows.
- **Defects fixed by the pass**:
  - `provision-local-runtime-role.sh` granted no `UPDATE` on
    `smtp_transactions`, so artifact linking after the scan failed; and no
    `UPDATE` on `handoff_idempotency`, so the durable handoff's
    `SELECT … FOR UPDATE` was refused (`permission denied for table
    handoff_idempotency`, HTTP 503 to Postfix). Both grants were added and
    the idempotent provision script re-run.
  - The live volume was missing `migrations/008_local_runtime_boundaries.sql`
    (applied by this pass); without it `claim_quarantine_reinjection_event`
    did not exist.
- **End-to-end re-proof after the role switch**: an SMTP submission to
  `192.168.8.4:2525` was accepted, scanned by the four capabilities, persisted
  (`artifacts`/`smtp_transactions` 20 → 21 with `mime_artifact_id` linked), and
  Postfix logged `status=sent (delivered via mailcore service)`; the quarantine
  list (`200`, 2 cases) and scanner operations (`200`, node healthy) still work
  under the scoped role with no PostgreSQL errors.
- **Known limitations of this local proof**: the local server context is a
  single customer-admin session, so the platform scope is proven by tests and
  by direct store calls rather than by a live system-admin session; audit rows
  and test fixtures created by the suite remain in the local database because
  `audit_events` is append-only by design; the Audit Log UI is verified over
  HTTP (route served, bundle contains the route) and by its unit tests rather
  than by an interactive browser session.

### Increment 2 evidence (2026-09-29)

- **Gates (this pass)**: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` (23 test binaries,
  0 failures, including the 20 new `admin_rbac.rs` unit tests) and
  `pnpm check-all` (format, lint, typecheck, 6 test files / 14 tests including
  `session.test.ts` and `client.test.ts`) all pass.
- **Database suite (this pass)**: `NULLAPART_TEST_DATABASE_URL` over an SSH
  tunnel, `cargo test --workspace -- --ignored` — 18 ignored tests pass. New
  `crates/mail-core/tests/postgres_admin_rbac.rs` (3): `admin_*` RLS fails
  closed without `app.current_deployment_id` and rejects cross-deployment
  writes; bootstrap → session create → resolve → expiry → revoke with
  `session_login`/`session_logout` audit rows and cross-deployment resolution
  denial; user creation/idempotent grant/revoke auditing (including a refused
  cross-deployment grant writing no audit row).
- **Migrations (this pass)**: `010_admin_rbac_sessions.sql` applied to the
  running volume; `provision-local-runtime-role.sh` re-run with the new grants
  (`admin_users`/`admin_sessions` SELECT,INSERT,UPDATE; `admin_roles`
  SELECT,INSERT; `admin_role_permissions`/`admin_user_roles`
  SELECT,INSERT,DELETE) and verified through
  `information_schema.table_privileges`.
- **Live verification (this pass)**, through the reverse proxy at
  `http://192.168.8.4:53080` with HTTP basic auth (identity handed to Mail
  Core as `X-Nullapart-Local-User`): `GET /auth/session` without a cookie →
  `401`; `POST /auth/login` → `200` with the `nullapart_session` HttpOnly
  cookie (bootstrap of the empty deployment as `customer_admin`, CSRF token
  returned in the projection); `GET /auth/session` with the cookie → `200`
  projecting `ob1`, 6 permissions and active step-up; `POST /admin/users` with
  the CSRF header → `201` (support-role user created) plus `admin_user_created`
  audit row; `GET /audit/events` → `200` listing `session_login`,
  `admin_user_created` (and the prior increment's rows); `POST /auth/logout` →
  `200`; `GET /auth/session` after logout → `401` (revoked). The database
  confirms `session_login`, `session_logout` and `admin_user_created` rows with
  the admin's `actor_id`.
- **Not claimed**: identity-provider integration (the identity decision is now
  recorded — ZITADEL, 2026-09-29 — but the integration is not implemented in
  this increment), step-up re-authentication UX
  beyond the freshness flag, and password-based fallback login remain out of
  scope (`docs/03-IDENTITY-RBAC-IMPERSONATION.md`).

### Increment 3 evidence (2026-09-29)

> **Historical:** this evidence records the pre-redesign acting-as design
> (subject intersection, `/admin-users` Act-as). The capability now uses
> customer-entry semantics (see the supersede note on increment 3 above).

- **Gates (this pass)**: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` (24 test binaries,
  356 tests, 0 failures) and `pnpm check-all` (format, lint, typecheck, 7 test
  files / 19 tests including `AdminUsers.test.tsx` and the extended
  `session.test.ts`) all pass.
- **Database suite (this pass)**: `NULLAPART_TEST_DATABASE_URL` over an SSH
  tunnel, `cargo test --workspace -- --ignored` — 21 ignored tests pass (18
  prior plus the new `crates/mail-core/tests/postgres_admin_impersonation.rs`
  (3): `admin_impersonations` RLS fails closed without or against the wrong
  `app.current_deployment_id`; start/end/`resolve_session` overlay with
  permission intersection, duplicate-start refusal and logout-implicit end
  with dual-identity audit rows; revoking the session closes the interval
  without an extra end audit row).
- **Defect found by this pass**: the PostgreSQL `start_impersonation`
  `INSERT … SELECT` had no `RETURNING`, so `fetch_optional` always reported
  "no row" — the transaction rolled back and both the DB suite and the live
  API surfaced `PersistenceFailed` as HTTP 503 (`Service is unavailable`).
  Unit tests could not catch it because they use the in-memory store. Fixed
  with `RETURNING id`; reproduced and diagnosed through PostgreSQL statement
  logging (`log_statement`).
- **Migrations (this pass)**: `011_admin_impersonation.sql` applied to the
  running volume; `provision-local-runtime-role.sh` re-run (grants
  `SELECT, INSERT, UPDATE` on `admin_impersonations` to `nullapart_mailcore`);
  Mail Core rebuilt.
- **Bootstrap role (this pass)**: the `LOCAL-TEST` admin state was reset so
  the empty deployment bootstrapped `ob1` as `system_admin` (`admin:impersonate`
  projected, 8 permissions); `ob2-customer-admin`, `ob2-support` and (while
  acting) `ob3-while-acting` were created through the API.
- **Live verification through the reverse proxy** (HTTP basic auth →
  `X-Nullapart-Local-User`): `POST /admin/impersonations` → 200 with the
  subject/reason/`startedAt` view; `GET /auth/session` while acting projects
  the impersonation banner data, keeps `admin:users:manage` but drops
  `admin:impersonate` (intersection), and still reports the real
  `system_admin` roles; a user created while acting → 201; `POST
  /admin/impersonations/end` → `{"ended":true}` and idempotently
  `{"ended":false}` on the second call; the session is restored with
  `admin:impersonate` back and `impersonation: null`. `/admin-users` serves
  200 and the served chunks contain "Act as" (AdminUsers) and "Stop acting"
  (Layout banner).
- **Dual-identity audit (database rows)**: `impersonation_started` and
  `impersonation_ended` rows for both `ob1` and `ob2-support`, plus the
  `admin_user_created` and `audit_access_list` rows written while acting, all
  carry `impersonated_subject = ob2-customer-admin`,
  `impersonated_customer = local-customer`, and `customer_id = local-customer`;
  rows written before/without impersonation have those columns null.
- **Support scope (direct Mail Core :58081, bearer + local-user header)**:
  login 200 as `support` with `admin:impersonate` + `audit:view` but without
  `admin:users:manage`; user list 200 (impersonate permits targeting), single
  user detail 403; audit list 200 with only its own rows; a requested other
  customer returns 403 with an audited `audit_access_list` denied row;
  support start/end impersonation 200/200; logout 200 (CSRF header required —
  its absence returns a bare 403 from the boundary, as designed).
- **Not claimed**: identity-provider integration (the identity decision is now
  recorded — ZITADEL, 2026-09-29 — but the integration is not implemented)
  and an interactive browser session of the banner
  (verified via served bundles plus unit tests rather than a scripted
  browser).

### Increment 4 evidence (2026-09-29)

- **Gates (this pass)**: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` (0 failures) and
  `pnpm check-all` (prettier, eslint, `tsc --noEmit`, 7 test files / 27 tests)
  all pass.
- **Database suite (this pass)**: `NULLAPART_TEST_DATABASE_URL` over an SSH
  tunnel to the local PostgreSQL, `cargo test --workspace -- --ignored` — 24
  ignored tests pass, including the new
  `crates/mail-core/tests/postgres_oidc_identity.rs` (3): one IdP subject
  binds exactly one local user per deployment while the same subject is usable
  in a second deployment and null subjects stay outside the partial index;
  another deployment cannot rebind that subject (RLS, 0 rows affected);
  `oidc_login_flows` is invisible and unwritable without or against the
  deployment GUC, is claimed exactly once by `DELETE … RETURNING`, and a
  step-up flow must be bound to a session, which then cascades it away.
- **Migration (this pass)**: `012_oidc_identity_integration.sql` applied to the
  running volume and `infrastructure/containers/provision-local-runtime-role.sh`
  re-run, so the running Mail Core uses the scoped role against the new index
  and table.
- **Two defects found by live traffic** (both fixed and unit-tested):
  - ZITADEL issues ID tokens with a second audience (its project id) while
    openidconnect 4.0.1's default claim verifier rejects any audience other
    than the client id and deliberately skips the `azp` check, so every real
    login failed with `ID token verification failed`. The relying party now
    accepts extra audiences only when `azp` names this client (accepted,
    missing-`azp` and foreign-`azp` cases each have a test) and logs the
    underlying verification error instead of only the summary.
  - The same provider withholds `preferred_username`/`email` from the ID token
    (ZITADEL only asserts them there when a per-app option is enabled), so
    `login_candidates` fell back to the raw subject and the login was refused
    with `Account is not provisioned`. Profile claims are now read from the
    UserInfo endpoint when the ID token is silent, bound to the ID token's
    subject; a profile answering as a different subject is never adopted.
- **Live verification (driven at HTTP level through the reverse proxy at
  `http://192.168.8.4:53080`, which adds its own HTTP basic auth)**:
  - `POST /api/v1/auth/login` → `303` → `GET /api/v1/auth/login` → `303` to
    the ZITADEL authorize URL carrying PKCE S256, `state` and `nonce`, plus the
    `nullapart_oidc_flow` cookie (path-scoped to the callback, 600s).
  - The full ZITADEL Login V1 flow (login name → password → OTP MFA) → `302`
    back to `/api/v1/auth/oidc/callback` → `303` setting
    `nullapart_session`; `GET /api/v1/auth/session` → `200` projecting `ob1`,
    `system_admin` and 8 permissions. `admin_users.auth_subject` for `ob1` now
    holds the IdP subject, written by link-by-match (the subject is a mapping
    key, never authorization).
  - **Audited outcomes** in `audit_events`: `session_login success actor=ob1`;
    the two earlier attempts appear as `session_login denied` with `ID token
    verification failed` and `identity is not provisioned`.
  - **Step-up**: `GET /api/v1/auth/reauth?return_to=/` → `303` with
    `prompt=login` → a second full IdP login → callback `303` → the same
    user's session, audited as `session_step_up success` on the same session
    id.
  - **Logout**: `POST /api/v1/auth/logout` with the session CSRF header → `200`
    carrying `idpLogoutUrl` at ZITADEL's `end_session` endpoint; the next
    `GET /api/v1/auth/session` → `401`; audited `session_logout success`.
  - **Unprovisioned identity**: a second ZITADEL human user with no local row
    → callback `403 {"code":"FORBIDDEN","message":"Account is not
    provisioned"}`, no session cookie, `GET /api/v1/auth/session` → `401`,
    audited `session_login denied` with that reason and the IdP subject as
    actor, and zero `admin_users` rows created — the empty-deployment
    bootstrap invariant is not violated by a refusal.
  - **Mode regression both ways**: `NULLAPART_IDENTITY_PROVIDER=proxy_header`
    → `POST /api/v1/auth/login` → `200` with the header-exchange session
    (with and without the local-user header), then restored to `oidc` → `303`.
- **Not claimed**: an interactive browser session (the IdP login, MFA,
  callback, step-up and logout were driven programmatically over HTTP), WebAuthn
  or passkey login (OTP MFA only), SCIM/SAML or user provisioning, and any
  identity-provider availability, backup or high-availability behaviour.

### Increments 5–8 evidence (2026-09-30)

- **Gates (this pass)**: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` (29 suites, 0
  failures; mail-core 349 tests) and `pnpm check-all` (prettier, eslint,
  `tsc --noEmit`, 14 test files / 82 tests) all pass.
- **Database suite (this pass)**: `NULLAPART_TEST_DATABASE_URL` over an SSH
  tunnel to the local PostgreSQL, `cargo test --workspace --no-fail-fast --
  --ignored` — 46 ignored tests pass (customer/domain administration, policy
  administration, runtime operations, RBAC, trace flows and artifact-index
  restart recovery against the live schema with RLS).
- **Live evidence probe (this pass)**: one scripted HTTP session against the
  reverse proxy at `http://192.168.8.4:53080` — **31/31 checks pass**:
  session established with `system_admin`; all 17 phase-5–8 permissions
  projected; customer create `201` plus idempotent replay `200` with the same
  id and a customer list containing it; lifecycle `active → grace → active`;
  domain create `201`; domain verify `200` with
  `verification_status=verified`, `verification_method=dns_txt`,
  `verification_attempts=1`; source-ip group create `201` / delete `200`
  (the shared high-risk limiter returned `429` and the probe backed off and
  retried — refill at 0.05/s is by design); policy families listed (24),
  policy publish `201`, family detail showing the published revision and an
  idempotent publish replay returning an identical body; feature definitions
  (9), feature override write then revert to inherit; runtime status,
  refresh `200` and idempotent refresh replay; mail-trace session search,
  transaction detail with recipients/instances/flow stages/auth, a
  **full-message content read `200`** (subject, plain body, 9 headers) for a
  real transaction, wrong-id detail `404`, unauthenticated search `401`;
  frontend index served and the shipped asset bundle containing the
  hostile-content isolation markers (`default-src 'none'`, empty `sandbox`,
  message-content frame class).
- **Audited outcomes (`audit_events`, live volume)**: `domain_verified
  success` ×4; `domain_verification_failed failed` ×3 with the honest reasons
  `verification record not found` (no resolver configured yet) and
  `resolver unavailable` (resolver configured but the reply source did not
  match); `trace_content_accessed` `success` ×9 / `denied` ×44 across the
  live-evidence window; plus `customer_created`, `domain_added`,
  `policy_published` ×5, `feature_override_changed` ×10,
  `runtime_refresh_requested` ×6 and
  `source_ip_group_created`/`source_ip_group_deleted` ×5/×5.
- **Real mail path for the content evidence**: SMTP submission to the local
  Postfix at `192.168.8.4:2525` → `relay_domains` (recorded local value
  `phase2.test`; a parent-domain entry also matches subdomains) →
  after-queue handoff accepted by Mail Core with `recipient_count=1` →
  `smtp_transactions` row, `smtp_transaction_recipients` row, a
  `tenant_message_instances` row scoped to the domain-owning customer, and
  artifact bytes in the artifact volume → session trace search → detail →
  content `200`.
- **Defects found by live probing (production code; fixed, gated, and covered
  by new tests where the guard is code-level)**:
  - `verify_domain` and `delete_source_ip_group` bound `domain_id`/`group_id`
    as text against the UUID columns `domains.id` and `source_ip_groups.id`
    (sqlx binds a Rust `String` with an explicit text OID, so PostgreSQL
    raised `operator does not exist: uuid = text` and the handler answered
    `503`). Both now parse the id to `Uuid` and bind UUID — non-UUID input is
    `400` before authorization, with two new router tests.
  - `policy_admin::get_family` decoded the two-column revision-counts query
    with `query_scalar::<_, i64>`; the first family-detail call failed
    client-side decoding and surfaced as a silent `503` (statement executed,
    no server error). It now uses `query_as::<_, CountRow>` and takes the
    first row.
  - `infrastructure/containers/provision-local-runtime-role.sh` — the
    canonical grant source named by migration 014 — was missing `GRANT
    SELECT ON delivery_attempts, nodes TO nullapart_mailcore`; added and
    re-run against the running volume (config/feature write grants confirmed
    live).
- **Local-runtime configuration and tooling (dev-only; recorded so the next
  pass can reproduce or remove it)**:
  - `NULLAPART_DNS_RESOLVER` is plumbed through `compose.local.yml` and
    documented in `.env.local.example`; the live value is
    `172.30.0.1:15353`, answered by a local TXT stub that reads the pending
    `verification_token` from PostgreSQL for `_nullapart-verify.<domain>`
    queries. The full `dns_txt` path was exercised: query, TXT match, status
    `verified`, audited `domain_verified success`; both failure arms are
    evidenced above. Binding must be the Docker backend gateway
    (`172.30.0.1`) because Mail Core compares the UDP reply source with the
    configured server address.
  - **Artifact index restart recovery (defect fixed this pass)**: the
    Filesystem artifact store keeps its metadata index in process memory and
    `try_new` started empty, so bytes persisted across a Mail Core restart
    were unreadable (audited fail-closed `404`, `artifact bytes are
    missing`) until the quarantine-reinjection path re-recovered a specific
    artifact. Mail Core now rebuilds the index at startup from PostgreSQL
    (`nullapart_mail_core::artifact_recovery`, wired into
    `bin/mailcore-server.rs` right after `FilesystemArtifactStore::try_new`):
    for each customer of the deployment, artifact rows are selected under
    the transaction-local `app.current_customer_id` plus an explicit
    `customer_id` filter, and a row re-enters the store only after
    `recover_existing` re-verifies the on-disk file's server-derived name,
    size and SHA-256 — rows whose bytes are absent or corrupt are skipped
    with a warning and stay fail-closed, and recovery never fabricates
    metadata the schema does not store (no expiry; `standard` retention and
    `sha256:`-prefixed 64-hex digests only). Live evidence: after
    `docker compose up -d --build mailcore`, the boot log records
    `artifact index recovered from database` with `candidates=20,
    recovered=20, skipped=0`, and a scripted session read the full message
    for pre-restart transaction `ee014b51-fcc5-56d4-8e80-72f7333a97b6`
    (artifact `692b8508-1730-5822-90ff-43eb35433aa1`) with `HTTP 200`
    (`plain_len=72`, 6 headers). Covered by 5 mapping unit tests and an
    ignored PostgreSQL test (put → drop → reopen → `NotFound` before
    recovery → report `candidates=2, recovered=1, skipped=1` → bytes
    readable after; the missing-file row stays `NotFound`), bringing the
    database suite to 46.
  - `NULLAPART_IDENTITY_PROVIDER`: the live `.env.local` value observed at
    the start of this pass was `proxy_header` (file last modified 2026-09-30
    21:32 +0200) and login was re-verified in that mode (`POST
    /api/v1/auth/login` → `303` with a directly minted session; the
    content read above ran against that session). The previous pass recorded
    a restore to `oidc`; that claim is not re-verified in this pass because
    the locally stored OTP secret for MFA no longer exists, so proving
    `oidc` again would require an OTP reset at the IdP first.
    `log_statement` logging (used to root-cause the `uuid = text` error) is
    reset to `none`.
  - The probe created fixture customers during successive runs (the customer
    list showed 8 at the final run); there is deliberately no customer
    delete endpoint — `lifecycle` is the terminal-state mechanism — so the
    fixtures remain as evidence records.
- **Not claimed**: production S3 `ArtifactStore` behaviour (local filesystem
  store only), an interactive browser session of the trace pages (all
  evidence was driven programmatically over HTTP), readability of artifacts
  whose database rows or on-disk bytes are absent (those stay fail-closed
  by design), artifact-index recovery for backends other than the local
  `filesystem` store or for rows outside the restarted deployment's
  customers, an end-to-end `oidc` login re-run in this pass (see the
  identity note above), DNS verification
  against public authoritative DNS (a configured local resolver was used),
  message delivery to an external MTA, or customer-deletion behaviour.

### Phase 3 completion review evidence (2026-10-01)

- **OpenCode-assisted review**: OpenCode with `opencode/mimo-v2.6-flash-free`
  was used for the first Phase 3 review pass. It re-read the canonical agent,
  roadmap, Phase 3 and code-standard docs, ran `cargo fmt --all -- --check`,
  `cargo test --workspace`, `cargo clippy --workspace --all-targets --
  -D warnings`, and `pnpm check-all`, and found no broad feature gap before
  stalling during its internal audit fan-out. Codex completed the manual review
  and implementation.
- **Defect found and fixed by the completion review**: Phase 3 claimed
  immutable checkpoint status, but the current tree had audit export only and
  no checkpoint-status surface. Added migration
  `016_audit_checkpoints.sql`, an append-only checkpoint metadata table with
  deployment RLS, `GET /api/v1/audit/checkpoint-status`, an Audit Log status
  card, frontend coverage, and a PostgreSQL ignored test
  `checkpoint_status_reads_deployment_checkpoint_metadata`.
- **Defect found during DB coverage**: the new checkpoint RLS policy uses
  `app.current_deployment_id`; the initial store scope helper did not set that
  GUC, so a real checkpoint row would have been invisible and falsely reported
  as `not_configured`. `PostgresAuditStore::apply_scope` and the external
  audit-event writer now set `app.current_deployment_id` transaction-locally.
- **Local gates after the final fix**: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` (mail-core 361 passed, 1 ignored; workspace green),
  and `pnpm --dir frontend check-all` (14 files / 82 tests) all pass.
- **DB-backed evidence**: over an SSH tunnel to `ob1@192.168.8.4` PostgreSQL,
  `cargo test -p nullapart-mail-core --test postgres_admin_audit
  checkpoint_status_reads_deployment_checkpoint_metadata -- --ignored`
  passes against the live migrated schema.
- **Remote deployment evidence on 192.168.8.4**: migration 016 was applied to
  the running volume, `provision-local-runtime-role.sh` was rerun, and the
  `mailcore` and `frontend` images were rebuilt/recreated on the remote Docker
  host. Live proxy proof: `POST /api/v1/auth/login` → `200`,
  `GET /api/v1/audit/checkpoint-status` → `200` with
  `state="stale"`, `checkpoint_sequence=999001`, and
  `signer_key_id="local-live-proof"` after seeding a local proof checkpoint;
  `/audit-log` serves `200`; the shipped `AuditLog-*.js` asset contains
  `checkpoint-status` and `Checkpoint status`; and the runtime DB role reports
  `has_table_privilege(SELECT)=true`, `has_table_privilege(INSERT)=false`,
  `rolbypassrls=false`.
- **OIDC mode regression evidence**: the remote stack was temporarily flipped
  from `proxy_header` to `oidc`, `mailcore` was recreated, and
  `GET /api/v1/auth/login` through the reverse proxy returned `303` to
  ZITADEL at `192.168.8.4:53090` with `state`, `nonce`, PKCE
  `code_challenge_method=S256`, and a path-scoped HttpOnly
  `nullapart_oidc_flow` cookie. The stack was then restored to
  `NULLAPART_IDENTITY_PROVIDER=proxy_header`, `mailcore` was recreated again,
  and `POST /api/v1/auth/login` returned `200`. This refresh verifies the
  relying-party start path and the reversible mode switch; it deliberately
  does not replace the 2026-09-29 full OTP-MFA callback proof because the
  local OTP seed is no longer available.
- **Still not claimed**: S3/Object Lock/WORM archive operation, independent
  checkpoint writer scheduling, and checkpoint verification drills remain
  Phase 9 operations-hardening work. Phase 3 now implements and verifies the
  Control Plane status surface and least-privilege read path.

### Local control-login and system-admin UX correction (2026-10-16)

- **Problem corrected**: the prior global Nginx Basic-auth boundary caused a
  browser-native credential prompt before the branded login experience, while
  the console shell presented a system administrator like an ordinary customer
  operator. The remote checkout also contained only 7 of the 57 verified
  branded asset files, so image URLs fell back to the SPA document instead of
  serving artwork.
- **Implemented boundary**: only `POST /api/v1/auth/login` accepts local
  Basic credentials. Nginx validates and consumes that header, forwards the
  trusted local user only for the exact exchange while overwriting upstream
  `Authorization` with the private workload bearer, and clears the local-user
  header from all other API requests. `GET /api/v1/auth/login` remains the
  top-level OIDC entrypoint. The React local form holds credentials only in
  component memory and receives the existing opaque HttpOnly session; it does
  not write credentials or tokens to browser storage.
- **Implemented system mode**: a verified `system_admin` is labelled
  `System-wide authority` and receives a grouped System command / Tenant
  security / Governance / Platform access navigation and a System command
  center. A customer entry is separately labelled `Customer entry active` so
  it cannot be mistaken for platform authority. These are affordances only;
  Mail Core continues to authorize every route and mutation.
- **Gates**: `pnpm --dir frontend check-all` passed (127 tests, asset manifest
  30/30 categories). The pre-existing `Models.tsx` fast-refresh ESLint warning
  remains a warning only and was not suppressed or changed by this work.
- **Live evidence on `192.168.8.4`**: frontend rebuilt/recreated and
  `nginx -t` passed. `GET /login` returned 200 without `WWW-Authenticate`;
  unauthenticated `GET /auth/session` and a forged local-user header both
  returned 401; unauthenticated local login POST returned 401 with the Basic
  challenge; valid local credentials returned 200 and the HttpOnly session
  cookie, which then authorized `/auth/session`. All 57 local brand files were
  synchronized to the remote checkout and the logo response is `image/png`.
  A live browser visual check confirmed the complete artwork, system-admin
  navigation and light-theme header contrast.

# Nullapart Console Redesign: Operation-First

Status: frontend conversion complete. This document is the working map for
converting the console from display-only telemetry into an operation-first
work surface, per the redesign brief confirmed on 2026-10-16 (full console,
full functional vision, backend gaps flagged).

## Objective

Every screen answers "what can I do about this", not only "what is the state".
Every list row carries its legal actions, every panel links to its next step,
and every high-risk action flows through the existing step-up + audit
machinery. No raw API forms: forms become named tasks with server-authorized
outcomes. The visual system is the flat enterprise-admin palette in
`tokens.css` (light canvas, hairline rules, one cool accent, fixed status
scale, WCAG AA in both themes) per `DESIGN.md` and
`docs/12-UI-DESIGN-SYSTEM.md`.

## Landed in this pass

- **Admin users** (`AdminUsers.tsx`): full management surface. Create
  administrator (login, display name, optional customer, initial roles),
  per-row role grant/revoke with pending-change review, self-modification
  warning, step-up surfacing. Uses the existing backend endpoints
  (`POST /admin/users`, `POST/DELETE .../roles`); the previous "API-only"
  restriction is removed.
- **Quarantine** (`Quarantine.tsx`): bulk disposition. Select-all over
  release-eligible cases, one audited reason applied per case with per-case
  idempotency keys, step-up aborts the batch cleanly, released cases show a
  release stamp.
- **Messages / Message detail**: the triage loop is closed. Quarantined
  tenant instances link directly to their quarantine case from search results
  and the transaction view (`isQuarantineLinked` in `lib/status.ts`), a
  "Linked cases" signal counts them, and the transaction ID is copyable.
- **Dashboard**: an ordered "Needs attention" queue (dead letters, stale
  outbox, quarantine cases, degraded scanner) with direct links, replacing
  scan-the-metrics triage; clear state is stated explicitly.

## Landed in the second pass

- **Feature overrides** (`FeatureOverrides.tsx`): stored overrides are now
  first-class rows in the table (scope, decoded value, owner, expiry) with a
  per-override "Clear override" action that writes an explicit `inherit`
  through the existing PUT contract, requires an audited reason, and is
  hidden for scopes the viewer's role cannot write. The shared `Dialog`
  primitive now generates unique title ids (duplicate-id fix).
- **Outbound intelligence** (`OutboundIntelligence.tsx`): the approved-sender
  list is managed. Per-approval Deactivate/Reactivate runs through the
  existing upsert POST with preserved limits/expiry and a required reason
  (server-side `changed` flag drives the notice); "Edit limits" prefills the
  approval form from server state; approvals accept an optional expiry.
  Hard delete of an approval remains a backend gap (G1).
- **Deep AI** (`DeepAi.tsx`): rollback targets prefill from the skill
  registry and model-release list ("Roll back" per released skill, "Roll
  back release" per approved release) instead of free-text re-entry; grant
  and rollback forms have independent error state; revoked grants render
  their revoked stamp from server data.
- **Connectors & remediation** (`ConnectorsRemediation.tsx`): the remediation
  `purpose` field is now selectable (it was unreachable in the UI despite
  being part of the contract); "Edit capability" prefills the connector
  upsert from the server record (credential reference intentionally
  requires re-entry, since stored hashes are never rendered back);
  remediation history shows provider outcome codes and error summaries.

## Landed in the third pass (editability, wording, tooltips)

This pass answered five specific complaints: edits are not discoverable,
wording is unclear, there are no tooltips, backend language still reaches the
UI, and some sections cannot be changed at all.

- **Tooltips reach both primitives.** `Select` gained the `hint` prop `Input`
  already had, and both now render it (`Select.tsx` was wiring
  `aria-describedby` at a node that did not exist). `.input-hint` /
  `.select-hint` got a global rule, so an explanation is legible everywhere
  rather than only where a page happened to style it.
- **Form groups stack.** `.input-group` / `.select-group` had no CSS at all, so
  every label sat inline beside its control and a long label squeezed the field.
  The stacking convention already committed in `Models.css` is now global
  (`global.css`), which is what made the Deep AI finding form readable at all.
- **Deep AI: recording a finding is a console affordance.** The endpoint
  `POST /api/v1/deep-ai/analysis-results` previously had no UI. Each live grant
  card now offers "Record a finding", which prefills and scrolls to a full-width
  panel. The form mirrors the server contract: only accepted enum values, the
  server's own length and range bounds, evidence references taken from the
  chosen grant rather than typed. The two states that make recording impossible
  say so in operator terms ("A finding has to cite an open artifact grant..."),
  and a viewer without `deep-ai:manage` gets a read-only explanation instead of
  a form that would fail.
- **Provenance is server-derived and visible.** Each finding carries
  `recorded_by` from the route, never from the request body, and the card shows
  "Entered by an administrator" or "Produced by the model" with the recommended
  action in words.
- **Copy sweep.** "Tenant message ID" became "Message it came from (optional)";
  the rollback subtitle stopped saying "audited and requires an idempotency
  key"; training-dataset data classes render through `tokenLabel` with a "data
  in it:" lead-in; the administrator lifecycle column stops showing raw
  `active` (`lifecycleLabel`). Raw ids survive only as secondary evidence.
- **Card layout defects fixed live**: grant/dataset labels no longer run into
  their id (`strong + span` needed the block rule), and action buttons no
  longer break their own label into three lines inside a narrow card.

## Verified live on `192.168.8.4`

Deployed through the review proxy at 1440x900+ with a fresh `system_admin`
session, against the rebuilt `mailcore` and `frontend` images:

- `POST /api/v1/deep-ai/artifact-grants` -> `201` with a 30-minute expiry.
- `POST /api/v1/deep-ai/analysis-results` with an unapproved `model_release`
  -> `400 MODEL_RELEASE_NOT_APPROVED`.
- Same request with the approved release -> `201`, `recorded_by` is
  `administrator`, `validation_state` is `valid`.
- A body that tries to self-declare `"recorded_by": "model_runtime"` parses
  (the field is not part of the contract) and is still stored as
  `administrator`. Provenance cannot be minted by a caller.
- `GET /api/v1/deep-ai` returns `recorded_by` on each result, and the summary
  counts move (`active_artifact_grants` 0 -> 1, `valid_results_24h` 0 -> 1).
- Screenshots confirm the "Record a finding" panel, the per-grant action, the
  origin pill, the stacked form labels, and the dataset/rollback copy.
- The Roles page shows `System Administrator` holding 28 permissions against a
  27-entry catalog, which is the live shape of the orphan grant reported below.

## Landed in the fourth pass (the last seven routes)

Screenshotted the routes the third pass had converted but not re-checked since
the global form-group rule landed: Messages, Quarantine, Customer detail,
Domain security, Connectors, Audit log, Settings. Messages, Quarantine and
Domain security came back clean. The other four carried real defects.

- **Settings stopped quoting its own keys.** The theme signal showed `dark` and
  the runtime signal `permitted` / `restricted`; both now read "Light" (or
  "Dark") and "Allowed" / "Not available". The role chip showed `system_admin`
  and now goes
  through `roleLevelLabel`. "Re-authentication: Active" became "Verified" /
  "Not verified", which is what the state actually means next to its tooltip.
- **Audit log filters are labelled.** The three controls carried `sr-only`
  labels only, so on screen the row read as two placeholders and a bare select
  showing "All results". They are now `Input` / `Select` primitives with visible
  labels, example placeholders, and a line explaining that the action filter
  matches the recorded internal name (it does; the server filters on it).
- **Audit rows no longer repeat the wire token.** Every row printed the human
  action label with `deep_ai_analysis_result_recorded` under it. The label
  stays; the token is evidence, so it now appears once, in the event detail
  drawer. Actor roles read "System admin" instead of `system_admin`, and the
  64-character checkpoint root hash is styled as secondary mono instead of
  wrapping over three lines at body size.
- **A whole field cannot live inside a tooltip.** Customer detail wrapped the
  domain-type `Select` in `Hint`, whose `<span>` shrink-wraps, so the control
  rendered at content width while every other field filled the column. It now
  uses the primitive's own `hint`, so the rule is a permanently visible line
  and the select is full width.
- **Connector submit buttons stopped shouting.** Both forms stretched their
  action across the full column; they are right-aligned at natural width now,
  matching the rest of the console.
- **`humanizeToken` keeps acronym caps.** `deep_ai_...` humanized to "Deep ai
  analysis result recorded". Acronyms (AI, ID, DMARC, DKIM, SPF, MTA/STS, BIMI,
  RUF, SMTP, TLS, URL, API, CSV, MX, DNS, IP, LLM, MFA, SSO, HTTP/S, TTL) now
  keep their caps wherever they land, which fixes labels on every page that
  derives them from a token.
- New tests: `lib/text.test.ts` for the acronym pass, `Settings.test.tsx` for
  the wording and the permission-gated deployment card, and the audit test now
  asserts the row shows words while the drawer holds the token.

## Verified live on `192.168.8.4` (fourth pass)

Rebuilt and redeployed the frontend image, then re-screenshotted at 1440 wide
with a fresh session: the four changed routes show the new labels, the
un-touched three are pixel-identical or unchanged in content, and the deployed
route chunks carry the copy (`Any result`, the action-filter explanation, `Not
verified`, `audit-hash`, `justify-self:end`, the domain-type rule from the
shared `labels` chunk).

## Landed in the fifth pass (the two blocking gaps)

### G15 Deep AI artifact-grant revocation

**No migration was required.** The grant table already carried the revocation
triple (`revoked_at`, `revoked_by`, `revoke_reason`) with an all-or-nothing
`CHECK`, and the visible state was already derived from
`revoked_at IS NULL AND expires_at > now()` in `030_deep_ai.sql`. What was
missing was only the route that could write that triple, so this gap closed
with an endpoint plus the console affordance, not schema.

- `POST /api/v1/deep-ai/artifact-grants/{grant_id}/revoke` with a `reason`. The
  handler runs the standard mutation contract: `deep-ai:manage` authorization,
  a `STEP_UP_REQUIRED` check before the write, a required idempotency key, then
  a single transaction that scopes to the authenticated deployment/customer,
  claims the idempotency operation, updates the grant, writes the audit event
  and completes the claim. `revoked_by` is the authenticated administrator id,
  never a body field.
- Reason bounds match the table: 12 to 500 characters, rejected before the
  transaction with `INVALID_REQUEST`.
- The idempotency table keys on `(deployment_id, customer_id, key)` with no
  body fingerprint, so a resource-scoped mutation has to put the resource in
  the operation string. The claim operation is `revoke:` plus the grant id,
  which is what stops one key from closing two different grants.
- A grant id that belongs to another tenant is `NOT_FOUND`, not `FORBIDDEN`.
  A second call under a fresh key on an already-revoked grant succeeds with
  `changed: false` and leaves the original record untouched; a replay under the
  same key returns the stored outcome.
- The update is all-or-nothing in SQL, so a part-filled triple cannot be
  written by any path in the service.
- Console: an unrevoked grant gets a `Revoke grant` action with a tooltip that
  names the consequence. It opens an inline reason form inside the same card
  ("Reason this access ends", with the 12-to-500 rule visible and the reason
  described as staying on the record), a danger submit, a cancel, the
  `StepUpPrompt` on refusal, and a client-side block before a thin reason ever
  reaches the network. Revoked cards read `Revoked by <name>: <reason>`, and
  the finding action disappears with the grant's liveness. A grant that expired
  without ever being revoked still offers revocation, because the record should
  say the access ended and why.

### G16 Human actor names on write history

`admin_users` (`id`, `login`, `display_name`, `deployment_id`) is the only
resolution source, so the console read models now resolve the id server-side
instead of handing the UI a bare UUID.

- `policy_admin.rs` carries `ACTOR_DISPLAY_NAMES_SQL`, `load_actor_display_names`
  and `actor_display_name`. It is a separate SQL constant used only by the
  console read paths, so the runtime policy evaluator never carries presentation
  data on its hot path.
- Missing display data degrades to the stored id rather than failing the
  request. An operator reading overrides should not get a 503 because one
  administrator row has no `display_name`.
- Additive compatibility per `docs/27`: the API gained `owner_display_name` on
  feature overrides and `registered_by_name`, `approved_by_name`,
  `activated_by_name`, `deactivated_by_name` on inline models. The existing
  `owner` / `*_by` fields are unchanged, because audit records name ids and
  the console still needs the identifier for evidence.
- Console wording: override rows read `set by Lerato Mokoena` instead of
  `set by 32e35eba-a628-...`; the model card shows who approved, activated and
  retired it next to each timestamp, and an undecided row stays a plain em-dash
  rather than inventing an actor.

New coverage: `deep_ai.rs` unit tests for the permission, the malformed
identifier, the missing idempotency key, and both reason-length rules; the
ignored `postgres_deep_ai.rs` test
`grant_revocation_is_all_or_nothing_and_stays_inside_the_tenant` for the real
write; `DeepAi.test.tsx` drives the full loop (thin reason blocked locally,
revocation posted with an idempotency key, the closed record rendered on the
refetch, step-up offered on refusal, and the reason still visible to a reader
without `deep-ai:manage`); `FeatureOverrides.test.tsx` and `Models.test.tsx`
assert the names appear and the UUIDs do not.

## Verified live on `192.168.8.4` (fifth pass)

Rsynced the tree, rebuilt and restarted both `mailcore` and `frontend` compose
services, then probed the deployed API with a real authenticated session
(bearer token plus `nullapart_session` cookie, `X-CSRF-Token`, `X-Idempotency-Key`)
and screenshotted the console through the local review proxy at 1440 wide.

**No migration was applied, because none was needed.** Confirmed against the
running database: `deep_ai_artifact_access_grants` already has `revoked_at`,
`revoked_by` and `revoke_reason` (from `030_deep_ai.sql`) and `admin_users`
already has `display_name`. The latest migration file is
`040_deep_ai_result_origin.sql`; nothing was added to `migrations/`.

G15 probe outcomes on the live stack:

- fresh revoke → `200` with `{"changed": true, "revoked_by": "ob1"}`;
- replay of the same idempotency key → the identical stored envelope, no second
  write;
- second key on the already-revoked grant → `200` with `changed: false` and the
  **original** reason retained;
- reason shorter than 12 characters → `400 INVALID_REQUEST`;
- missing idempotency key → `400 IDEMPOTENCY_REQUIRED`;
- malformed grant identifier → `400 INVALID_REQUEST`;
- a grant belonging to another deployment → `404 NOT_FOUND`;
- `GET /api/v1/deep-ai` afterwards returns `revoked_at`, `revoked_by`,
  `revoke_reason` on the record and `active_artifact_grants: 0`;
- `GET /api/v1/audit` shows `deep_ai_artifact_grant_revoked` with
  `actor_login: ob1` and `result: success`.

G16 probe outcomes: `/api/v1/features` returns both `owner` (UUID) and
`owner_display_name`; `/api/v1/admin/models` returns
`registered_by_name` / `approved_by_name` / `activated_by_name` with
`deactivated_by_name: null` on a model that was never retired. Screenshots show
`set by ob1 · Sep 30, 2026, 6:18 PM · no expiry` on `/policies/features` and the
model card naming the person beside each decision timestamp.

In the browser (not only headless) the revoke loop ran end to end: a thin
reason was stopped client-side with no POST on the wire, and a valid reason
produced two `Revoked by ob1: …` records and removed the finding action from
both cards. Two leftover verification grants on this dev stack were revoked as
part of the exercise.

Not verified live: the `STEP_UP_REQUIRED` refusal and the permission-denied path
on `.4`, because the local single-administrator stack cannot present a
step-down session or a session without `deep-ai:manage`. Both are covered by
unit tests (`grant_revocation_requires_manage_permission`,
`grant_revocation_requires_an_idempotency_key`) and by the console's
`StepUpPrompt` wiring, not by a live refusal.

## Landed in the sixth pass (platform settings)

Settings was the last route that described itself better than it delivered. It
offered a theme picker, a session card and a deployment card that printed a bare
id, while everything an operator actually needs to know about the installation
they are standing on (which deployment, how sign-in is proved, how long a
session lasts) was only readable out of band.

**The facts come from the session, not from a new endpoint.** `/auth/session`
and the login exchange now carry a `platform` block, populated server-side only
when the authenticated actor's own role keys resolve to a system role level
through the stored `admin_roles.role_level`, so a custom system-level role
counts and a client cannot ask for the block. No new route, no new permission,
no write path, no migration. `resolve_session` is untouched: the extra reads
happen on the two session-shaped responses, not on every authenticated request.

- What is published: the deployment id, its `deployments` row (name, region,
  lifecycle, provisioned date), the identity mode, the OIDC issuer when OIDC is
  the mode in use, and the three session windows that govern the caller.
- What is deliberately not published: rate-limit budgets. An abuse threshold
  does not belong in a payload a browser can read.
- Failure behavior: a role level that cannot be resolved fails closed to no
  block at all; a `deployments` row that cannot be read degrades to
  `deploymentRecordAvailable: false` with the region taken from the configured
  template, so the console says the record is unavailable instead of inventing
  a name.
- Console: a read-only Platform card, in words. Seconds are what the server
  enforces, so `sessionWindowLabel` renders "1 hour without activity", "8 hours
  from sign-in", "10 minutes"; lifecycle and identity mode go through their own
  label maps; `Hint` tooltips carry the three rules (why the readout exists,
  what the sign-in method is for, what each session window means). The runtime
  card was renamed Runtime and lost its duplicate id row, because the Platform
  card is now where the installation is named.
- The `published_by` leak on Operations: `ConfigScopeResponse` gained
  `published_by_name`, resolved inside the snapshot transaction through the same
  `policy_admin::load_actor_display_names` read model the override and model
  histories use, degrading to the stored id when display data is missing.
  `published_by` stays, because audit records name ids; the table cell now shows
  the name with the id as its `title`, and the column header explains that.

New coverage: `admin_rbac` unit tests for the system-tier gate (a customer
session sees nothing), the published values, the identity provider without any
client credential in the payload, and the missing-record path; `Settings.test.tsx`
asserts the card renders for a published session, is absent when the server
published nothing, says the record could not be read rather than naming it, and
never shows a raw second count; `Operations.test.tsx` asserts the publisher
renders as a name with the identifier kept as hover evidence.

## Verified live on `192.168.8.4` (sixth pass)

Rsynced, rebuilt and restarted `mailcore` and `frontend`. **No migration was
applied, because none was needed:** the `deployments` table already exists and
already holds the running deployment (`LOCAL-TEST`, region `ZA`, display name
"Nullapart local development", `active`).

API probes against the published mailcore port with the local control bearer and
a real `nullapart_session` cookie, checked on both the login response and a
follow-up `GET /api/v1/auth/session`:

- `ob1` (builtin `system_admin`, stored level `system`) → the `platform` block,
  with `deploymentName: "Nullapart local development"`, `deploymentRegion: "ZA"`,
  `deploymentLifecycle: "active"`, `identityProvider: "proxy-header"`,
  `identityIssuer: null`, `idleTtlSecs: 3600`, `absoluteTtlSecs: 28800`,
  `stepUpTtlSecs: 600`, `deploymentRecordAvailable: true`;
- `ob2-customer-admin` (`customer_admin`, level `customer`) → `platform: null`;
- `ob2-support` (`support`, level `support`) → `platform: null`.

`GET /api/v1/operations/runtime` returned the system scope with
`published_by: "32e35eba-…"` and `published_by_name: "ob1"`.

In the browser at 1440 wide the Platform card reads "Nullapart local
development / LOCAL-TEST / ZA / In service / 9/27/2026 / This installation's
sign-in boundary / 1 hour without activity / 8 hours from sign-in / 10 minutes",
with no raw second count anywhere on the page, and the Config versions row shows
`ob1` with the UUID reachable only as the cell's `title`.

Not verified live: the unavailable-record branch (this stack has a readable
deployment row), a custom system-level role receiving the block (only the three
builtin roles exist in `LOCAL-TEST`), and the OIDC issuer path (this stack runs
`NULLAPART_IDENTITY_PROVIDER=proxy_header`). All three are covered by unit tests.

Two things observed on this stack while verifying, neither caused by nor fixed
in this pass: the frontend logs `The Content Security Policy directive
'frame-ancestors' is ignored when delivered via a <meta> element`, so that
directive needs a response header to have any effect; and `mailcore` logs
`inline ml registry gate failed; runtime is unavailable` because the ONNX
artifacts the compose file mounts read-only from
`ml/inline/checkpoints/multilabel-v1/{model,onnx}` are not present on the host,
which leaves inline ML gated off (fail-closed, not silently CLEAN) until the
model is re-exported with `ml/inline/export_onnx.py`.

## Landed in the seventh pass (flat enterprise register)

The neumorphic language is gone. The console now reads in the register of the
Mimecast admin console and Proofpoint Enterprise Privacy: a light canvas, hairline
rules instead of elevation, one cool accent, and dense data surfaces.

- **Tokens rewritten.** Light is the default theme (`color-scheme: light`) with
  dark as a peer theme for low-light sessions. Canvas `#eef1f5`, panels white,
  ink `#1b2733`, single accent `#1a6ba1`. Radii dropped to 3-10px, the type
  scale to 11-30px, and `--shadow-inset`, `--shadow-panel` and the glow tokens
  are deliberate `none` no-ops so page CSS cannot reintroduce wells or halos.
  `--color-border-lime` became `--color-border-accent`; `--spacing-7` and
  `--color-surface-subtle`, both previously referenced but never defined, now
  exist.
- **Depth removed everywhere.** Deleted the gradient/`rgba(250,250,250,...)`
  sheens, `inset` shadows, lime glows, `backdrop-filter` glass and the globe
  hero artwork from Operations, Login, Models, Quarantine, Policies, Dashboard,
  Settings, StatusPill, ControlRail, Layout and Toasts. Interaction feedback is
  a colour or border shift only; no `translateY` lift.
- **Typography flattened.** Display/serif titles and `clamp(...rem)` hero
  numerals are replaced by Inter at the type scale with `tabular-nums` on data;
  uppercase tracked eyebrows are sentence-case labels. Uppercase survives only
  in short status badges.
- **Login and rail keep a dark ink ground** (`--color-rail-*`) because the
  approved wordmark artwork is white; the content canvas next to it is light.
- **Side-stripe accents removed.** The 3px lime rail boundary, the lime inset
  metric stripe, the lime toast/alert edges and the glowing section markers are
  gone; selection uses a tint plus a 1px border.
- **Inter is self-hosted** via `@fontsource/inter` (400/500/600/700, latin +
  latin-ext), which keeps CSP at `font-src 'self'`.
- **CSP delivery fixed.** `frame-ancestors`, `base-uri` and `form-action` moved
  to the nginx response header (`frontend/nginx.conf`, `docker/nginx.conf`);
  the `<meta>` policy now carries only the directives a `<meta>` can enforce,
  which removes the browser's "ignored via meta" console error. Verified live on
  `192.168.8.4:53080` with `curl -I`.
- `index.html` theme-color and `site.webmanifest` now say `#eef1f5`, not
  `#050505`.
- **Docs reconciled** (AGENTS.md treats doc/code disagreement as a defect):
  `docs/12-UI-DESIGN-SYSTEM.md`, `docs/23-FRONTEND-ARCHITECTURE.md`,
  `docs/00-ARCHITECTURE.md`, `docs/16-BUILD-ROADMAP.md`,
  `docs/phases/PHASE-3-CONTROL-PLANE.md`,
  `docs/engineering/BRAND-UI-ASSET-SYSTEM.md`, `docs/engineering/CODE-STANDARDS.md`,
  two diagrams, plus `DESIGN.md` and `PRODUCT.md`. The board pack still governs
  brand assets and the status icon chips; it no longer governs surface treatment.

## Landed in the eighth pass (density and the last flat-contract leftovers)

Verified live at 1440x900 across 14 routes, then fixed what the screenshots
exposed:

- **Rail density.** The sidebar footer fell below the fold at 900px. The rail
  now uses one smaller spacing step, a 152px wordmark, 29px nav rows at the
  `md` type step, and a tighter boundary card. `Sign out` is visible on every
  route at 900px.
- **Settings grid.** Panels no longer stretch to the tallest sibling
  (`align-items: start`), which removes the dead space under `Appearance`.
- **Hint affordance.** A 1px dashed border under a hinted label read as a
  broken rule wherever a whole row label carried a hint (the platform readout
  hinted five labels in one card). The term now uses a dotted text underline
  that darkens on hover and focus.
- **Governance rail squeeze.** Deep AI release cards share a 300px column with
  a status pill and a rollback button that refused to shrink, so the model name
  wrapped one character per line. Those cards stack instead.
- **Last violations.** Removed the 24px/18px panel radii, the `--color-bg-glass`
  surfaces and the 2px rule drawn above every Deep AI panel; the workflow-guide
  description column widened from 34ch to 52ch so it stops inflating its strip.

- **Rail rebuilt, then corrected.** The dark rail was the last surface still
  reading as an afterthought. It carried a boxed session card that duplicated
  the scope the command bar already states, and a foot of three unrelated
  widgets. Navigation now starts directly under the wordmark, and the operator's
  identity, boundary label, display-mode control and sign out sit together as
  one account block. Below 980px that block stays visible instead of being
  hidden, which removes the previous dead end where a narrow screen offered no
  way to sign out.

  The first attempt at this regressed the rail and the fix had to be walked
  back: the commit deleted `--color-rail-active-bg` from `tokens.css` while
  `.nav-link.active` kept referencing it, so the selected row rendered with no
  fill at all, and it replaced that fill with a 2px inset accent bar, which is
  the side-stripe pattern this design bans. Selection is now the fill alone
  (`--color-rail-active-bg` restored in both theme blocks, `--color-rail-accent`
  deleted) with white semibold type; section labels went back to semibold; and
  the foot's two controls became borderless 30px rows that match the nav
  geometry instead of small bordered chips.

Deferred, not fixed: the Overview control rail restates the metric strip below
it, and `--color-bg-glass` / `--color-bg-glass-strong` still exist as flat
aliases of the surface colours. Renaming them is a cross-file sweep that should
ride along with a component pass, not a styling commit.

## Landed in the ninth pass (the tenant console stops describing the platform)

The tenant console was documented as done, then browsed as a customer
administrator and found to be wrong in four ways: it still carried
system-administrator context, it showed the model registry the tenant cannot
open, its Feature overrides entry was a dead end, and its copy was written in
the platform's voice rather than the customer's.

- **Two grants removed, not two menu entries hidden.** `customer_admin` held
  `deep-ai:view` and `connectors:view`, so the nav showed a Deep AI console and
  a connector-remediation queue to an operator who owns neither. Both are gone
  from `BUILTIN_ROLES`, and because login reconciles `admin_role_permissions` in
  both directions the revocation reaches an already-seeded deployment on the
  next sign-in. `customer_admin_capability_set_is_the_tenant_boundary` now
  forbids the _view_ permissions too, plus `models:view` and `operations:view`:
  a tenant console that shows platform state it cannot act on is a support
  queue, not a customer product.
- **Feature overrides closed at the page, not the link.** Hiding the entry was
  not enough: `list_features` authorizes on `policies:view`, which the tenant
  holds, so the URL still painted the platform's rollout catalog into a customer
  console. `/policies/features` is now hidden for the customer tier and the
  page itself refuses to fetch `/features` when the server-published tier is
  `customer`, stating that feature availability is decided by the provider. The
  API stays the authorization boundary; this removes the leak, not the gate.
- **Unreachable readouts are not advertised.** Settings used to render a
  "Platform facts: System role only" and "Runtime: Not available" signal, which
  tells a customer administrator about two readouts they cannot open. Those
  signals, their workflow-guide steps and the header sentence now appear only
  when the session actually carries them. AuditLog is the same call: the
  integrity checkpoint describes the whole append-only ledger of the
  installation, not the events inside a customer scope, so the tenant console
  neither reads `/audit/checkpoint-status` nor renders its card.
- **A race the guard caught.** Gating that read on `enabled: !tenant` still
  issued it, because a pending session query reads as "not a tenant". It is
  gated on `session.isSuccess && !tenant`, and the boundary test settles on the
  shell's resolved session chip before scanning, which is the same distinction
  between "the tier is customer" and "the tier is not yet known".
- **Customer voice across the reachable surfaces.** `Policies` (description,
  table caption, empty state, and the Feature overrides entry), `Roles`
  (the role-definition refusal, `ROLE_BUILTIN`, the custom-role detail, both
  captions), `PolicyFamilyDetail` ("ask your provider", not "ask a system
  administrator"), `Dashboard` (title, the unverified-domain detail, the
  mail-flow note that named scanner nodes and model registries),
  `OutboundIntelligence` (header, the approval hint, the incident paragraph),
  `CustomerDetail` (the region/sequence hints and both rail summaries),
  `DomainSecurity` ("how the mail system judges"), `AdminUsers` (the
  out-of-scope sentence), `NotificationSettings` ("the security floor still
  applies"), and `frontend/src/api/capabilities.ts`, where a `deployment`
  blocker now names "a different Nullapart service" because a customer operator
  has no deployment to compare against.
- **The guard is a test, not a comment.**
  `frontend/src/test/tenant-console-boundary.test.tsx` renders 13 tenant
  surfaces against a real `customer` session and fails on two counts: any
  platform word in the rendered text (platform, deployment, installation,
  system admin, model registry, deep ai, impersonat*, cross-customer, outbox,
  dead letter, scanner node, fleet, emergency stop) and any platform read in
  the request log (`/operations/runtime`, `/scanner-operations`, `/deep-ai`,
  `/connectors`, `/models`, `/features`, `/audit/checkpoint-status`). Payloads
  are empty-but-valid so headers, rails, guides and locked copy all paint;
  anything unstubbed answers 501 so error copy is policed too. It found three
  real copy leaks and the checkpoint race on its first run.
- **Gates**: `pnpm --dir frontend check-all` green (264 tests, 33 files);
  `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
-- -D warnings` and `cargo test --workspace` green.

## Landed in the tenth pass (the tenant console stopped echoing the platform)

The ninth pass made the console say the right things. Browsed again as
`ob2-customer-admin` on `.4`, it still showed the platform in three places the
console does not write itself: rows the server authored, a role chip that
humanises whatever key the audit row carries, and a detail route that hard-coded
"you are not looking at your own record".

- **Provider actors are bucketed, not named.** `AuditLog` rendered
  `event.actor_roles.map(roleLevelLabel)`, so a `system_admin` row appeared in a
  tenant's evidence queue as "System Administrator" and the detail dialog printed
  the bare key. `actorRoleLabels(roleKeys, tenant)` in
  `frontend/src/lib/labels.ts` folds the builtin platform keys into one "Provider"
  chip for a customer session and leaves every other key humanised: an audit row
  carries role keys, not levels, so a custom platform role can only be named, not
  classified, without reading a role directory the tenant console does not ask
  for. The scope cell now shows `—` instead of "Platform" when a row has no
  customer.
- **A refusal is written in the refuser's language.** `require_family_tier` and
  the override-scope gate recorded "This policy needs system-level access to
  change", which the tenant reads back in their own audit log. `family_tier_reason`
  and `override_scope_reason` in `crates/mail-core/src/policy_admin.rs` keep that
  wording for a support or system caller and write "This policy is changed by your
  provider." / "These overrides are changed by your provider." for a customer. The
  public body stays the generic `Permission is required` and the authorization
  outcome is untouched, so this is an audit-copy change, not a contract change. A
  `None` tier is not a customer and keeps the ladder wording.
- **The ledger is append-only, so old rows keep old words.** Verified live: a
  refusal written after the deploy reads "This policy is changed by your
  provider." while the 1:41pm rows from before it still read "…system-level access
  to change". There is no honest fix. Rewriting a recorded reason would falsify
  the audit trail, so the historic text is reported, not patched around.
- **Provider families are information, not dead ends.** 17 of the 24 families a
  tenant can list are support or system level, and every one of them was a link
  that 403'd on open and wrote a Denied row into that tenant's own log. For a
  customer session a family marked _Needs your provider_ renders as a plain name;
  the tenant's seven families stay links.
- **`/customers/$customerId` stopped assuming the viewer is platform.** The route
  hard-coded `ownRecord = false`, so a tenant opening their own record got "The
  platform sets it" for region, "The platform assigns it" for the sequence, and a
  Customers list link to a directory they cannot open. `CustomerDetail` now
  resolves the session and derives `ownRecord` from `isTenantTier(session) &&
session.customerId === customerId`, which restores the own-record framing and
  drops both hints for the tenant and keeps them for a platform viewer.
- **The guard widened to the data path.** `PLATFORM_LANGUAGE` now also fails on
  `system-level`, `support-level`, a `support_agent`/`support_viewer` key and the
  platform's own names for entering a customer. Bare `impersonat` was removed:
  the `impersonation` policy family is inbound sender impersonation, a tenant's
  own protection, so the word alone is not a leak. Four anti-vacuous assertions
  were added, so the guard fails if the payload stops reaching the render: the
  role directory must show the provider-level actor renamed rather than echoed,
  the audit log must bucket a provider actor while keeping the tenant's own role
  label, and the policy queue must link one tenant family and refuse to link two
  provider ones.
- **Live re-audit**: 22 tenant routes on `.4` as a fresh `customer` session.
  `PLATFORM_READS` is empty everywhere, including the `/admin/permissions` read
  the roles page used to make. Zero rendered mentions of models, Deep AI or
  connectors anywhere in the sweep. The five platform routes (`/deep-ai`,
  `/connectors-remediation`, `/models`, `/operations`, `/scanner-operations`) fall
  back to Overview. `/audit-log` was the only route with term hits, and all eight
  were the pre-deploy rows above.
- **Gates**: `pnpm --dir frontend check-all` green (272 tests, 33 files);
  `cargo test -p nullapart-mail-core policy_admin` green (25 passed) with
  `tier_refusal_reasons_are_written_in_the_callers_own_words` covering all three
  caller classes; `cargo fmt -p nullapart-mail-core -- --check` leaves
  `policy_admin.rs` untouched. `cargo test --workspace` recorded separately.

## Landed in the eleventh pass (what the server hands, and what the guard can see)

The tenth pass rewrote copy the console authors itself. Browsed again as
`ob2-customer-admin` on `.4`, what was left was not the console's wording. It
was values the API put on the wire, one class of value the guard was blind to,
and a screen that read as an operator's readout because it named the component
that produced it. The pass settled on a division the rest of the tenant console
now follows: **an identity is removed by the server projection, a vocabulary is
replaced by the naming layer, and a handle the customer must be able to quote
stays on the wire and is never merely printed.**

- **Placement decides the words; permission still decides the access.** An
  operator who entered a customer through customer entry is answered as that
  customer. `634990d` and `9cefad7` moved that to one predicate per read instead
  of three drifting copies in the projections, and nothing about authorization
  changed.
- **Internal evidence is rebuilt, not filtered.** The customer trace projection
  used to strip scanner prose by a fixed word list, so any engine that named
  something the list forgot passed through verbatim. It now composes the sentence
  from severity and category and the customer query no longer selects the stored
  description column at all (`9cefad7`). A model, an engine or a threshold scheme
  cannot reach a customer response by accident.
- **A readout with no credential answers nothing about itself.** The trace health
  route is the one surface a load balancer calls without one, and it reported the
  node id and build version to anyone who could reach the port. It reports
  liveness only (`9cefad7`).
- **The installation's own seal is not a tenant record.** The audit checkpoint
  carried the root hash, signer key id and archive location behind `audit:view`,
  which the tenant role holds. Scope says which rows a read may see, so placement
  is now carried alongside it and the checkpoint readout requires a
  platform-placed actor (`9cefad7`).
- **Bookkeeping identifiers are withheld, not restyled.** The mail-server queue
  ids, the content dedup hash, the node reference, the answering `deployment_id`
  on domain security, outbound and notification settings, the alert-delivery
  queue reference, and the surrogate placement key, region and sequence on a
  customer record are absent from the customer answer rather than blanked in the
  UI (`634990d`, `3b2095b`, `afb60d2`, `6439080`). What a customer quotes back
  stays: the transaction id, the message id and the SMTP codes a sender saw.
- **Machine codes read as outcomes.** Every reason code the policy engine can
  emit maps to outcome words, and an operator-typed code falls back to words from
  its shape instead of echoing the key (`1daf24c`). The same vocabulary now covers
  the held-mail checks: a tenant's case detail lists the capability the server
  names and whether it answered, while whether that check was mandatory, how long
  its node took and the word for the component itself stay on the operator's side
  (`6b99056`). The rule builder reads "Security check findings" for a tenant and
  "Scanner findings" for a platform seat.
- **A stored key gets a name before it reaches the screen.** The policy list and
  the role directory stopped printing the row identifier under the human name
  (`8ed30dd`); a tenant's history rows name the family, the sender and the action
  instead of keying them (`98d615f`); the audit detail dialog names the 13
  platform-only detail keys it no longer shows and renders the rest in the console's
  own words (`2945a21`). `detail_fields` is untouched, so credential redaction
  still happens where it was designed. One vocabulary collision found while
  reading the writers: `source_key` is only ever written by a DMARC report-source
  row, so it now reads "Report source", not "Sending range".
- **A revision says who published it.** `published_by` stores the actor's row key.
  `57c9abd` adds `published_by_name` alongside it (the additive shape `docs/27`
  prescribes) and resolves it per seat: a customer reads their own administrator's
  display name, and anyone outside their organisation reads "Your provider".
- **The field is additive, so the render must survive skew.** Live on `.4` the
  queue printed `#5 · by undefined`: the rebuilt frontend had run ahead of a
  mailcore image that does not publish the new field. `f1fdb6c` types
  `published_by_name` as optional, drops the clause instead of printing a missing
  value, and gives the guard a `undefined`/`NaN` tripwire. The lesson is a rule,
  not an apology: a UI that reads a new field must not be the reason the field's
  absence becomes a word on a customer screen.
- **The guard's blind spot is closed.** The snake_case tripwire from the tenth
  pass cannot see a primary key, because a UUID has no underscore. `d3fefac` adds
  an opaque-shape term for UUIDs and long hex, and with it the exemption that
  makes it honest: `tenantResourceReference` lets an opaque value through when the
  resource type names the customer's own mail (`transaction`, `quarantine`,
  `quarantine_case`, `message`), and checks a composite key segment by segment.
  The boundary test derives the same exemption from its own trace fixture rather
  than weakening the pattern, so a real row key still fails. The first run of the
  new term reported the trace page's transaction id, which is the customer's
  handle, and that is what settled the rule with evidence from both sides: the
  trace search accepts a transaction id and the quarantine route opens on a
  message id.
- **The guard reports all of it, and now reads a case.** `a4dbf08` fails with
  every match of a term rather than the first, so a page with three machine keys
  reads as three findings. `6b99056` adds `/quarantine/$tenant_message_id` as a
  tenant surface, a `scanner` term, and an anti-vacuous test that the case detail
  paints its checks and their outcomes. `17c3bed` then removed the guard's own
  blind spot: the audit fixtures were keyed `event-tenant`, an opaque term can
  never fire on a word, so the one page that legitimately prints an id — the
  detail dialog, where an operator quotes the event they are disputing — was
  untested. The fixtures now carry real UUIDs, and the event id is a third named
  customer handle shared by the row and its detail payload.
- **Engine identity has its own tripwire, and the guard must prove it works.**
  The suite had `model registry` and `deep ai` but nothing for the word _model_,
  a weights file, a parameter count or a classifier, so a payload that named the
  engine would have passed on a wording accident rather than on a rule. Four
  terms now cover the class the whole sweep exists for. They join with
  `TERM_SAMPLES`: one leak string per term, and a test that fails if a term has
  no sample, if a sample names a removed term, or if a pattern no longer matches
  the string it is supposed to catch. Verified by breaking one on purpose. All
  11 tenant surfaces in the boundary suite stay clean under the widened set,
  which is the evidence that the projection, not the copy, is what keeps engine
  names off them. The live sweep below predates these four terms, so re-run it
  against the next frontend build rather than reading it as cover for them.
- **Live re-audit**: 11 tenant routes on `.4` as a fresh `customer` session,
  scanned with the guard's own terms. Ten are clean. The only hit is
  `Transaction d43552d2-…` on an audit row whose resource type is `transaction`,
  which is the allowed handle, and `/policies` showed the `undefined` publisher
  above before `f1fdb6c`. Re-run after the mailcore rebuild, `/policies` reads
  `#5 · by ob1`: on this deployment the seed account that published the revision
  carries a `customer_id`, so the resolution treats it as the customer's own
  administrator and prints its account name. That is the same decision already
  made about `actor_login` below, not a leak fixed by the projection.
- **Gates**: `pnpm check-all` green (296 tests, 34 files) with the new publisher,
  check-outcome, boundary and term-validity cases.

**Not changed, and why.** `connectors_remediation` keeps its family name and the
outbound "Source kind" option list keeps its words: both are surfaces a tenant
selects on, not machinery reporting itself. `actor_login` still shows for a
provider actor, because a tenant is entitled to know that someone outside their
organisation touched their record, and only the ladder is renamed. A tenant's CSV
export keeps raw action, resource and role keys, because that file is evidence the
customer quotes to us. The scanner's own health page is unchanged; it is a
platform read.

**Coverage the guard has that live data does not.** The `.4` quarantine queue was
empty during the sweep, so the held-message detail is verified by the boundary
test and its fixture, not by a real case. The same holds for `outbound_transaction_id`:
this deployment has no `notification_deliveries` rows, so no alert has carried the
reference a customer would quote. Say so rather than implying a live pass.

## Landed in the twelfth pass (the wire, not only the render)

The eleventh pass finished by teaching the guard to read a DOM. That left three
things unstated: a read the console never renders is still a read a customer
session can make, an answer that carries `null` has not withheld anything, and a
guard that only compares words cannot see a page that fell over. This pass worked
on the wire.

- **A `null` in a withheld slot still advertises the slot.** The eleventh pass
  wrote that the bookkeeping identifiers "are absent from the customer answer
  rather than blanked in the UI". That was the intent, not the JSON: five reads
  serialized the word `null` into exactly the field they were meant to withhold,
  so a customer answer said _there is a correlation id, a node reference, a dedup
  hash, a queue reference, a placement number; we are just not telling you_.
  `e294afb` puts `skip_serializing_if` on `trace_id`, `deployment_id` and
  `content_hash` in the trace detail, on the answering `deployment_id` in domain
  security, outbound intelligence and notification settings, on a delivery row's
  `outbound_transaction_id`, and on the `internal_key`, `region_code` and
  `sequence_no` of a customer record. The Rust placement test now asserts the
  three keys are _not in the serialized object_ for a customer answer and _are_
  in it for a platform answer, which is the only claim worth keeping: an absent
  key cannot be re-serialised back into existence by a later refactor of the
  projection.
- **A withheld key changes what the console can test for.** `CustomerDetail` used
  `internal_key !== null` as its marker that placement had been withheld. Against
  an absent key that predicate is true, and the page would have printed `Internal
key:` with nothing after it. It now asks for a number, and the tenant fixture
  in the boundary suite omits the keys rather than setting them to `null`, so the
  guard renders the real customer answer. A new "crashed render" term
  (`Something went wrong`, `Cannot read propert…`) is what proved the fixture
  mattered: the stub matched `/admin/customers/CZA-1` before
  `/admin/customers/CZA-1/source-ip-groups`, so the tenant's own organisation
  surface had been rendering an error boundary inside a green sweep. The stub is
  ordered, the term stays, and the tripwire was verified by removing the stub
  again and watching the new test fail.
- **Three reads a customer session can make that no tenant page renders.** The
  DOM guard is blind to them by construction, so these were swept by calling them
  directly. `4bf3ceb` answers `GET /admin/permissions` with the permissions a
  caller is actually allowed to hand out, and `GET /admin/roles` with the levels
  at or under that caller's own ceiling: a `customer_admin` session was reading
  "Read the ML model registry and model telemetry." and a directory that named a
  System Administrator, and neither read is used by the tenant console. Both
  tests keep an anti-vacuous platform branch that requires the full catalog and
  every builtin role to answer a platform seat.
- **The feature switchboard is projected, not refused.** `GET /features` is
  readable by `customer_admin`, which also holds `policies:manage`, so a refusal
  would have deleted a capability the architecture already grants: a tenant's own
  Tenant-scope override. `9b5d43d` moves the read through one pure
  `project_features` and, for a customer reader, drops the scope ladder, the
  security floors, the kill-switch flags, the winning-scope label and the
  description, hides features no Customer scope can reach, returns only that
  customer's override rows, and replaces the whole question with a `governed_by`
  outcome word: `you` or `provider`. `b2c0cc1` records what that means at the two
  call sites that read those narrowed lists, and the guard's role-directory
  fixture deliberately keeps answering every level, because a console that only
  renders what the server narrowed cannot tell whether the narrowing regressed.

**Gates**: `cargo test -p nullapart-mail-core --lib` 636 passed (1 ignored),
`cargo fmt` and `cargo clippy --all-targets -- -D warnings` clean. `pnpm
check-all` green (297 tests, 34 files) with the placement-absence, crashed-render
and organisation-record cases.

**Live wire sweep on `.4`.** _(recorded below once this build is deployed.)_

## Landed in the thirteenth pass (the tenant got a switch panel, and a name it owns)

Twelve passes removed words from the customer console. This pass gave it back
something to do, and moved the last naming decision to the place it can actually
be enforced.

- **A customer-facing name is catalog data, not a browser dictionary.** The
  internal name of a switch describes the machinery behind it, and a customer who
  reads that name can quote it in a ticket, screenshot it, or reason about what
  the deployment runs. A dictionary in `labels.ts` only cleans the render.
  `044_customer_catalog_labels.sql` adds `customer_facing_label` to both
  `feature_definitions` and `policy_families` (plus a customer-facing
  description), backfills the values the tenant console is allowed to show, and
  then raises an exception if any tenant-reachable row still carries machinery
  vocabulary, so the migration itself refuses to install a leak. The projection
  picks the column: a platform reader gets the stored name, a tenant reader gets
  the catalog wording, and the frontend dictionary stays only as the fallback for
  an answer that predates the column. Both paths must emit the same words, which
  the Rust label test and the boundary guard each check from their own side.
- **The feature panel was refusing a capability the architecture grants.** The
  eleventh-pass work narrowed `GET /features`, and the console answered that
  narrowing by telling a tenant that nothing there was open to them. That was
  false twice over: `customer_admin` holds `policies:manage`, and the server
  already authorises a Tenant-scope override write. The page now renders the
  customer projection as a working panel. A tenant reads the settings their
  sending is configured for, changes them, and takes them back, with no scope
  picker offered anywhere: the only level they may write is fixed, so the editor
  states it as a fact ("Change it for: Your sending") rather than posing a choice
  the server would reject.
- **What the tenant panel does not show.** The raw `feature_id`, the "What it
  controls" description, the platform default, the security-floor and
  emergency-stop counts, and the scope ladder are all gone from both the render
  and the answer. The rail reports the one fact a customer projection can
  honestly publish, which is how many values in force are the provider's decision
  rather than the customer's, and each row says `set by you` or `set by your
provider` from `governed_by` instead of naming a tier. Retiring an override says
  "cleared at your setting" and resolves to "Use your provider's setting"; a
  read-only customer is told their roles can read but not change, with no
  instruction to find a system administrator.
- **The guard had to change shape for this.** `/features` was in
  `PLATFORM_READS`, asserting a tenant session never asks for it. That assertion
  was protecting a page that should not have existed; it now belongs to the
  payload sweep, so the suite carries a customer feature fixture and a
  non-vacuous test that the customer's own rows actually render while their
  snake_case keys do not.

**Gates**: `cargo test -p nullapart-mail-core --lib` 638 passed (1 ignored),
`cargo fmt --check` clean. `pnpm check-all` green (302 tests, 34 files).

## Landed in the fourteenth pass (the directory stopped naming rungs above the reader)

Twelve passes named one leak and left it standing: the administrator directory.
This pass closes it in the projection, where a word can be removed by a server
rather than reworded by a browser.

- **One ceiling, reused.** `crates/mail-core/src/admin_rbac.rs` now resolves
  `VisibleRoles` for the caller and applies it to both reads
  (`GET /api/v1/admin/users`, `GET /api/v1/admin/users/{id}`) and both mutations
  (grant, revoke). Its ceiling is the same `grantor_rank` the write paths already
  enforce, so the answer a customer gets cannot be more generous than the change
  that customer is allowed to make. A role key whose level is above the reader,
  or whose level the role directory cannot resolve at all, is left off.
- **Withheld is a fact, not a blank.** Omitting a key silently would render an
  account that holds a platform role as an account that holds nothing, which is
  both wrong and the kind of wrong that gets acted on. The answer therefore
  carries `roles_outside_reach` (an absent key when nothing was withheld, not
  `null`) and the console renders it as a gap: `A role you cannot manage` to a
  tenant, `A role above your level` to a support-tier reader. Neither names the
  role, its key, or how many were left off.
- **The mutation answer uses the same projection.** A grant response echoes the
  roles held after the change, so an unprojected write would hand back the exact
  key the list read had just withheld. Both success arms now go through
  `role_mutation_answer`.
- **Platform answers are unchanged, and said so.** The projection is skipped
  entirely at or above `SYSTEM_RANK`: no extra store read, no new key, nothing
  withheld. A test asserts a platform session still gets the plain role list, so
  this pass cannot quietly narrow the console it is not for. `create_user` is
  deliberately not projected because its gate already refuses an above-ceiling
  grant, so there is nothing there for the answer to name.
- **What the dialog now refuses to imply.** The Manage-roles editor states that
  the withheld grant stays as it is while the tenant changes the rest, and the
  "an administrator with no roles" warning suppresses itself when the account
  does hold something outside the reader's reach.

**Flagged, not fixed.** `admin_roles` is scoped by deployment, not by customer.
A tenant's role-directory read therefore lists custom customer-level roles owned
by other customers, and the grant path will bestow one. The rank ceiling applied
this pass is the same ceiling that gap hides under, so closing it means scoping
the role store, not rewording a console; it belongs to the placement work, and is
recorded here rather than absorbed into a wording pass.

**Gates**: `cargo test -p nullapart-mail-core --lib` 640 passed (1 ignored),
`cargo fmt --all` and `cargo clippy -p nullapart-mail-core --all-targets -- -D
warnings` clean. `pnpm check-all` green (305 tests, 34 files).

## Landed in the fifteenth pass (the audit ledger stopped naming the actor's ladder)

The same fact reaches a customer console by three paths, and only one of them was
a screen.

- **Reads and the export share one rule.** `crates/mail-core/src/admin_audit.rs`
  now splits an actor's roles against the reader's own ladder in
  `list_item`/`detail`, and `render_csv` uses the same split. The CSV path
  matters: `audit:export` is a `customer_admin` permission, so a tenant could
  download a file the console had been careful not to show them. A withheld role
  travels there as the words `A role outside your view`, because a spreadsheet has
  no flag column to carry it.
- **What stays visible, and why.** The actor's login is not withheld. A customer
  is entitled to know that a named hand touched their record; what the platform
  used to leak is the rung that hand stood on. `impersonated_subject` stays for
  the same reason: it is the customer's own account, not a platform identity.
- **The ladder is resolved without a new dependency.** `is_customer_ladder_role`
  reads the builtin table, and a key the reader holds themselves counts as their
  own ladder even when no builtin can resolve it, so a tenant's custom role is
  still named to that tenant. The audit router does not gain a role-store handle,
  which keeps the placement rule inside the two modules that already own it.
- **The console says the gap, and keeps its guard.** `actorRoleLabels` takes the
  flag as a third input, so a tenant row reads `Customer admin, A role outside
your view`. The old bucket that renamed a leaked `system_admin` to `Provider`
  is still in place: the boundary fixture keeps answering with platform keys on
  purpose, so a projection regression cannot turn into a rendered platform name.

**Gates**: `cargo test -p nullapart-mail-core --lib` 641 passed (1 ignored),
`cargo fmt --all` and `cargo clippy -p nullapart-mail-core --all-targets -- -D
warnings` clean. `pnpm check-all` green (306 tests, 34 files).

**Still open, stated rather than implied.** The live wire sweep on `.4` has not
re-run against this build, and migration `044` has not been applied to the
long-lived Postgres volume there. A route-by-route read of what a `customer_admin`
session can still pull named four more answers that publish platform machinery:
`GET /outbound-intelligence` carries the stored rule algorithm
(`rspamd_fuzzy`, `nullapart_v1`) and a content-derived fingerprint that the page
uses as a row heading; `GET /quarantine/{id}` carries each check's capability key,
status and duration; `GET /mail-trace/transaction/{id}` keeps the
`postfix_queue_id` and `scanner_type` field names on the wire even though it
empties their values; and `GET /notifications/settings` delivery rows carry
internal failure prose. Each is a projection fix, not a wording fix.

## Landed in the sixteenth pass (the field name is the leak)

The four routes the fifteenth pass named are still open, but two of them turned
out to be worse than "publishes a machine value". The value was never the whole
problem: the _key_ was.

- **An empty value under a platform's name still names the platform.**
  `crates/mail-core/src/trace.rs` used to answer a customer trace with
  `postfix_queue_ids: []` and `postfix_queue_id: null`. Both keys are now omitted
  (`skip_serializing_if` on the `Option` and on the `Vec`), because the word
  `postfix` in the response is a fact about the running platform whether or not a
  value rides next to it. `frontend/src/api/trace.ts` marks both optional and
  `MessageDetail.tsx:177` tests for a string rather than for non-null, so the
  queue column disappears instead of rendering dashes. Committed as `97a2a7c`.
- **The outbound console stopped handing the customer the platform's content
  hash.** `load_campaigns` now takes the caller's placement and withholds
  `fingerprint` and `algorithm`; `load_security_events` withholds
  `campaign_fingerprint` alongside the runbook it already hid. What a customer
  keeps is the volume, the disposition and the dates, which is everything the
  console can act on. `postgres_outbound_intelligence.rs` proves both sides: the
  customer answer has the keys _absent_, the `system_admin` answer still carries
  `fp-<customer>` and `nullapart_v1`, and the withheld row keeps its
  `reason_code`.
- **A tenant row gets a name it owns.** `OutboundIntelligence.tsx` renders the
  section as _Similar-message groups_ with a _Group_ column reading "Similar
  messages · First seen 6 Jan 2026", keyed by position, and leaves the platform
  console its fingerprints and matcher versions. The branch is on `tenant`, not on
  whether the payload carried a hash: the guard's fixture still answers with
  `rspamd_fuzzy` on purpose, and a projection regression must not become a
  rendered engine name.
- **Two blind spots in the guard, found by making it look harder.** The sweep
  waited only for the session chip, so a page whose tables had not painted yet
  scanned green; `Surface.ready` now waits for one data-derived label, and the
  outbound fixture carries a real campaign row. And the opaque-key pattern anchored
  its bare-hash branch with `\b`, which cannot match welded `textContent`:
  `…takenLast seena3f19c0d…Campaign rule Rspamd…` slipped through both the hash
  and the engine name. The anchor is gone, `rspamd`/`milter`/`dovecot`/`amavis`
  joined the engine-name term, and the term samples now include a welded hash so a
  future anchor regression fails the completeness test. Both leaks reproduced in
  red before the page changed.

**Gates**: `cargo test -p nullapart-mail-core --lib` 641 passed (1 ignored),
`cargo fmt --all`, `cargo clippy -p nullapart-mail-core --all-targets -- -D
warnings` clean, `cargo test --test postgres_outbound_intelligence --no-run`
links. `pnpm check-all` green (307 tests, 34 files).

**What this does not prove.** The two new PostgreSQL assertions live in
`#[ignore]`d DB tests and compile-verify only here: the local tunnel to the test
database has been broken since the RBAC pass, so the projection was checked by
reading the serializer attributes and by the frontend guard, not by a live row.
The live wire sweep on `.4` and migration `044` are still outstanding (task 81).
`scanner_type` on the trace wire, the quarantine checks' capability keys and the
notification delivery failure prose are unchanged.

## Landed in the seventeenth pass (a customer gets a check, not a scanner)

Of the four answers the fifteenth pass named, this closes the trace route. The
value behind `scanner_type` was already humanised; the key was not.

- **One additive key, not a rename.** `crates/mail-core/src/trace.rs` now emits
  `check` for a customer placement and `scanner_type` for a platform one, each
  carrying the same projected source. A rename would have broken every existing
  consumer of the trace contract, and `docs/27-API-VERSIONING-FEATURE-FLAGS.md`
  asks for additive keys with conditional omission instead. `project_customer_safe`
  takes the caller's placement and returns whichever field belongs to it, so
  neither name ever appears in the other's answer.
- **Why the platform keeps its name for it.** `scanner_type` is a fact about the
  fleet that produced the evidence, which is what a platform operator triages
  with. A customer chooses evidence by what was looked at, so their answer says
  `check: "malware_analysis"` and nothing about a scanner. The two tests in
  `postgres_trace.rs` assert both shapes on the same stored row: the customer
  answer has `check` and no `scanner_type`, the `system_admin` answer has
  `scanner_type` and no `check`.
- **The console reads whichever name arrived.** `frontend/src/api/trace.ts` marks
  both optional, and `MessageDetail.tsx:123` resolves a finding's source through
  one helper that reads `check` then `scanner_type`, falling back to "Security
  analysis" for any key the naming layer does not know. A stored value that
  reaches the browser unprojected renders as a capability, not a machine token.
- **The guard had never rendered a finding at all.** Its trace fixture carried
  `findings: []`, so the whole naming-layer path for security evidence was
  untested for a tenant seat. It now has two rows: one with the customer key, and
  one answering as a platform would (`scanner_type: "inline_ml"`, on purpose, the
  way the other fixtures keep platform keys). The sweep waits for a
  data-derived label before scanning, so it cannot pass on a loading state.
  Verified by making it look harder: returning the raw source from `sourceLabel`
  turned the Message trace surface red with two `machine key` hits before the
  page was restored.
- **A heading I dropped last pass.** The `rsync --delete` incident section lost
  its title when the sixteenth pass was inserted above it. Restored here.

**Gates**: `cargo fmt --all`, `cargo test -p nullapart-mail-core --lib` 642
passed (1 ignored), `cargo clippy -p nullapart-mail-core --all-targets -- -D
warnings` clean, `cargo test --test postgres_trace --no-run` links.
`pnpm check-all` green (308 tests, 34 files).

**What this does not prove.** The `postgres_trace` assertions are `#[ignore]`d DB
tests and compile-verify only: the local tunnel to the test database has been
broken since the RBAC pass. The live wire sweep on `.4` and migration `044` are
still outstanding (task 81). One of the four answers remained: the internal
failure prose in `GET /notifications/settings` delivery rows. The quarantine
check internals are handled in the pass below.

## Landed in the eighteenth pass (a held message answers with a verdict, not a run report)

This closes the quarantine answer from the same list of four. The customer read
of a case carried three facts about the platform's scanning machinery: the
fabric's own status token (`clean`, `error`, `unknown`, `not_applicable`),
whether the delivery decision _required_ that check, and how many milliseconds
the scanner ran.

- **`capability` was already safe, and checking that changed the plan.** The
  stored row's `capability` is produced by `scanner_capability_label` at
  `crates/mail-core/src/quarantine.rs:868`, which is fed the raw scanner id and
  returns a human name before anything is persisted. So the leak was never the
  check's name; it was the run telemetry beside it. The fix projects those three
  keys away instead of renaming the one that was fine.
- **One additive key: `outcome`.** A customer decides whether to release a held
  message, so they need the verdict, and a withheld verdict is worse than a
  withheld duration. `crates/mail-core/src/quarantine_api.rs` now emits
  `outcome` for a customer placement and `status` / `required` / `duration_ms`
  for a platform one, each `#[serde(skip_serializing_if = "Option::is_none")]`
  so the other side's key is absent rather than null. Same shape as the
  sixteenth and seventeenth passes, and for the same contract reason: an
  existing endpoint gains a key, it does not lose one.
- **The status vocabulary projects onto one axis.** `customer_check_outcome`
  maps the six stored tokens onto `clear`, `threat_found`, `suspicious_found`,
  `not_applicable`, `no_answer`. Anything it does not recognise answers
  `no_answer`, never `clear`. That is AGENTS.md's "unknown/scanner/model failure
  never silently becomes CLEAN" applied to the wording a tenant reads, and the
  unit test walks all eight cases including an empty string.
- **The old label was wrong, not just platform-ish.** `checkOutcomeLabel` used
  to take the raw status and call everything that was not `healthy` / `complete`
  "Not completed" — so a real `threat` result rendered as "Not completed" to a
  tenant. The customer answer now carries an outcome key and
  `frontend/src/lib/status.ts` maps it to "No issue found", "Threat found",
  "Something suspicious", "No answer recorded", "Not applicable", with the same
  fail-closed default for a missing or unknown key.
- **The route, not only the projection.** A unit test on `from_detail` would not
  have caught the handler forgetting to ask who is reading. `quarantine_api.rs`
  now has a store double that answers `detail` with one recorded check, and one
  test that reads the same case twice through `quarantine_router`: as
  `customer_admin` (gets `outcome: "threat_found"`, `capability` and
  `completed_at`, and none of `status` / `required` / `duration_ms`) and as
  `system_admin` (gets `status: "threat"` and no `outcome`). Proven red by
  hard-coding `platform = true` in the handler: the customer half failed before
  it was restored.
- **The guard keeps a platform row on purpose.** The `Held message` fixture now
  has two checks: one answering the way a platform seat would, with `status`
  "healthy", `required` true and `duration_ms` 41 but no `outcome`, and one with
  `outcome: "suspicious_found"`. A tenant page that branches on payload presence
  rather than placement would print `healthy` here and be caught. Proven red by
  rendering the raw key next to the capability: the surface reported a
  `"machine key"` hit on `suspicious_found` before the page was restored.

**Gates**: `cargo fmt --all`, `cargo test -p nullapart-mail-core --lib` 646
passed (1 ignored), `cargo clippy -p nullapart-mail-core --all-targets -- -D
warnings` clean, `cargo test --test postgres_quarantine_detail --no-run` links.
`pnpm check-all` green (309 tests, 34 files).

**What this does not prove.** The route test answers from an in-memory store
double, so it covers the handler and the projection but not the SQL read that
turns a `scanner_results` row into a `QuarantineScannerResult`. That
read is unchanged here and its `postgres_quarantine_detail` test stays
`#[ignore]`d, compile-verify only, for the same broken local tunnel.
`scanner_results` exists only on the detail answer, so the list projection had
nothing to withhold. `/api/v1/scanner-operations` sits behind
`scanner:operations:view`, a permission no role in the catalog grants, and is
outside this slice. The remaining named leak is the internal failure prose in
`GET /notifications/settings` delivery rows.

## Deploy incident: never `rsync --delete` to `.4`

A previous sync used `rsync --delete` while deploying frontend changes. It was
wrong: the task was UI-only, the flag was unnecessary, and `ml/inline/checkpoints/multilabel-v1/{model,onnx}`
is remote-only data that the local tree does not contain. Those ONNX artifacts
were removed, so mailcore now logs `inline ml registry gate failed; runtime is
unavailable` and stays fail-closed until they are re-exported with
`ml/inline/export_onnx.py`. The deploy recipe is now rsync without `--delete`,
and any future destructive sync needs explicit approval first.

## Functional map for the remaining surfaces

Each entry lists the operations the page should expose and whether the
backend already serves them.

- **Customers / Customer detail**: already functional (create, lifecycle,
  domains, verify, source-IP groups). Next: surface notification groups and
  VIP records when backend support lands (gap G7, G8).
- **Operations**: already functional (scoped refresh). Next: per-node stale
  revision drill-down and dead-letter triage actions (gap G9).
- **Models**: already functional (register, approve, activate, rollback,
  shadow evaluations). Write history now names the person (gap G16 closed).
- **Policy families**: already functional (rule editor, publish, refresh).
  Next: policy simulation/dry-run (gap G10).
- **Feature overrides**: complete (set + clear override, both audited, both
  attributed by name).
- **Domain security**: one action today (source classification). Next:
  BIMI validation view, ruf sample inspection, domain observer history
  (gaps G5, G6, G11).
- **Outbound intelligence**: complete against the current API (upsert,
  deactivate/reactivate, edit). Next: hard revoke (gap G1), ledger claim
  visibility (gap G2).
- **Deep AI / Connectors & remediation**: complete against the current API
  (scoped grants, grant revocation with a retained reason, rollback with
  prefill, connector upsert with edit, remediation intent with purpose).
  Next: remediation outcome lifecycle (gap G3).
- **Scanner operations**: readout by design; fabric mutations are in-process.
  Next: drain/offline node drill-down evidence and links into message trace.
- **Audit log**: functional (filters, audited export, step-up). Next: saved
  filter views and impersonation-chain rendering (data exists).
- **Settings**: functional core (theme, session facts, sign out) plus the
  read-only Platform readout (installation, sign-in method, session policy).
  Next: "sign out other sessions" when the backend exposes session listing
  (gap G12).

## Backend gaps flagged (need endpoints before UI can act)

- **G1** Approved-sender revoke: `outbound_intelligence_api.rs` only upserts.
- **G2** Submission-ledger read route: the durable ledger has zero HTTP
  routes; operators cannot see stuck `in_progress` claims.
- **G3** Remediation outcome lifecycle routes (list attempts, record
  MANUAL_ACTION_REQUIRED resolution).
- **G4** Message-level retro-scan trigger (re-run scanner fabric on a
  delivered message).
- **G5** BIMI validation read model + endpoint.
- **G6** DMARC ruf failure-sample inspection (restricted RBAC, isolated
  rendering per `docs/08`).
- **G7** Notification routing configuration.
- **G8** VIP record management.
- **G9** Dead-letter inspect/retry/delete operations.
- **G10** Policy simulation/dry-run.
- **G11** Domain observer history (MX/SPF/DKIM/DMARC change log).
- **G12** Admin session listing/revocation.
- **G13** Role catalog endpoint (`GET /admin/roles`); the console currently
  carries the three documented platform roles plus directory-observed roles.
- **G14** Quarantine reject/hold-edit mutations (release is the only
  quarantine mutation today).

Closed in the fifth pass: **G15** Deep AI artifact-grant revocation (route +
console affordance; no migration needed) and **G16** actor display names on
write history. Both are described under "Landed in the fifth pass".

## Rules this redesign keeps

- Server-side authorization is the only boundary; UI gating is affordance
  only. Disabled actions explain themselves rather than impersonate security.
- Mutations send idempotency keys and surface `STEP_UP_REQUIRED` through the
  shared `StepUpPrompt` pattern.
- No message body/MIME is rendered outside the isolated `MessageContent`
  view; no action implies content access that the API does not grant.
- Every mutation is assumed audited server-side; toasts confirm outcomes but
  never carry evidence.
- A customer console leaks in three distinct ways, and each has one fixed
  remedy. An **identity** (which engine, node, version or row produced this) is
  removed by the server projection, not by hiding it in the UI. A **vocabulary**
  (a mechanism word the customer has no use for) is replaced in the naming
  layer, `src/lib/labels.ts`. A **handle** the customer must be able to quote —
  a transaction id, a held message id, an audit event id — stays on the wire and
  is printed only when it names their own mail or their own ledger row.
- Which vocabulary a page uses is decided by placement, not permission: an
  operator seated inside a customer entry is answered as that customer. The
  permission still decides whether they get the data at all.
- Every guard term carries a sample of the leak it catches, and a test fails if
  a term has no sample or its pattern no longer matches it. A tripwire that
  cannot fire is indistinguishable from a clean console.
- An additive response field needs a render fallback. A service that has not
  been rebuilt yet omits the field, and `undefined` reaching a customer screen
  is the incident; the guard trips on `undefined`/`NaN` so the class cannot
  return quietly.
- Coverage floors in `vitest.config.ts` hold: each converted page ships with
  updated tests, and CI (`pnpm check-all`) is the merge gate.

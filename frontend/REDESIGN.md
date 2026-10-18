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

- **Rail rebuilt.** The dark rail was the last surface still reading as an
  afterthought. It carried a boxed session card that duplicated the scope the
  command bar already states, a selected row that lost to hover, and a foot of
  three unrelated widgets. Navigation now starts directly under the wordmark;
  the selected row is fill + white semibold + a 2px inset `--color-rail-accent`
  bar; and the operator's identity, boundary label, display-mode control and
  sign out sit together as one account block. Below 980px that block stays
  visible instead of being hidden, which removes the previous dead end where a
  narrow screen offered no way to sign out.

Deferred, not fixed: the Overview control rail restates the metric strip below
it, and `--color-bg-glass` / `--color-bg-glass-strong` still exist as flat
aliases of the surface colours. Renaming them is a cross-file sweep that should
ride along with a component pass, not a styling commit.

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
- Coverage floors in `vitest.config.ts` hold: each converted page ships with
  updated tests, and CI (`pnpm check-all`) is the merge gate.

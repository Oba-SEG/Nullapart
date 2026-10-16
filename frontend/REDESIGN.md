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
outcomes. The visual system is unchanged: `tokens.css` (Acid Lime + Midnight),
restrained neumorphism, status scale, WCAG AA in both themes.

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

## Functional map for the remaining surfaces

Each entry lists the operations the page should expose and whether the
backend already serves them.

- **Customers / Customer detail**: already functional (create, lifecycle,
  domains, verify, source-IP groups). Next: surface notification groups and
  VIP records when backend support lands (gap G7, G8).
- **Operations**: already functional (scoped refresh). Next: per-node stale
  revision drill-down and dead-letter triage actions (gap G9).
- **Models**: already functional (register, approve, activate, rollback,
  shadow evaluations). Keep; tighten copy to task language.
- **Policy families**: already functional (rule editor, publish, refresh).
  Next: policy simulation/dry-run (gap G10).
- **Feature overrides**: complete (set + clear override, both audited).
- **Domain security**: one action today (source classification). Next:
  BIMI validation view, ruf sample inspection, domain observer history
  (gaps G5, G6, G11).
- **Outbound intelligence**: complete against the current API (upsert,
  deactivate/reactivate, edit). Next: hard revoke (gap G1), ledger claim
  visibility (gap G2).
- **Deep AI / Connectors & remediation**: complete against the current API
  (scoped grants, rollback with prefill, connector upsert with edit,
  remediation intent with purpose). Next: grant revocation endpoint (gap
  G15), remediation outcome lifecycle (gap G3).
- **Scanner operations**: readout by design; fabric mutations are in-process.
  Next: drain/offline node drill-down evidence and links into message trace.
- **Audit log**: functional (filters, audited export, step-up). Next: saved
  filter views and impersonation-chain rendering (data exists).
- **Settings**: functional core (theme, session facts, sign out). Next:
  "sign out other sessions" when the backend exposes session listing (gap G12).

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
- **G15** Deep AI artifact-grant revocation (grants expire but cannot be
  actively revoked before their TTL runs out).
- **G16** Actor display names on write history. Feature-override rows show
  "set by 32e35eba-a628-..." because the API returns the administrator id and
  no display name; the console cannot resolve a login without a new read route
  or an embedded name.

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

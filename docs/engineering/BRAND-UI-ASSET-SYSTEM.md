# Nullapart Brand, UI and Stationery System

**Status:** implementation record.

**Last verified:** 2026-10-19.

## Purpose

This document ties the implemented frontend visual language to the Phase 0
and Phase 3 requirements: a tokenised, accessible, flat administrative
console. It is not a replacement for security, RBAC, server-side
authorization or the phase plans.

## Visual direction

Nullapart uses a light-first, flat enterprise security-console register. The
dark navigation rail and login brief carry the approved light wordmark; the
working canvas uses cool neutrals, hairline boundaries and a restrained blue
action/focus accent. Brand lime remains a logo/status-art asset, not an action
or health signal. The reference artwork establishes the atmosphere; it does
not override the administrative UI requirements:

- cards use a clear one-pixel boundary and spacing, not raised or inset depth;
- focus, status and text retain explicit contrast independent of colour or
  elevation;
- tables remain compact and readable for operator workloads;
- status/severity colours are semantic tokens, not decorative status;
- the light theme preserves the same hierarchy without turning the application
  into a different product;
- reduced-motion preference disables nonessential transition duration.

The implementation lives in `frontend/src/styles/tokens.css`,
`frontend/src/styles/global.css`, and the existing component/page styles.
`DESIGN.md` is the visual implementation authority. The application shell
supplies a keyboard-visible skip link to `#main-content`.

## Asset inventory and provenance

`frontend/public/brand/asset-manifest.json` is the machine-readable inventory.
It maps every labelled item in `/Users/ob/Downloads/asset_contact_sheet.png`.
The production pack uses the separate supplied original exports under
`/Users/ob/Downloads/nullapart-acid-lime-assets`; it does **not** use crops or
Lanczos upscales of the flattened contact sheet.

| Reference group | Production files | Origin / dimensions | Current use |
| --- | --- | --- | --- |
| Primary vertical, horizontal and mark | `logos/primary-logo-dark@2x.png`, `logos/horizontal-logo-dark.png`, `logos/logo-mark@2x.png` | supplied originals; 2350×2272, 1770×521, 2048×2048 | Login, shell and compact context mark. |
| Wordmark/tagline and monochrome lock-ups | `logos/wordmark-light.png`, `logos/tagline-lime.png`, `logos/horizontal-clean-teal.png`, `logos/horizontal-threat-magenta.png` | supplied originals | Approved variants for email, status communications and dark/light composition. |
| Website hero and header | `web/website-hero-2560x900.png`, `web/website-header-1600x320.png` | supplied originals | Login hero; marketing/header usage only. |
| Corporate security network | `web/corporate-security-network-16x9.png` | direct generated artwork from the approved design board; 1672×941 | Public corporate landing only; decorative image, with no embedded product claims or controls. |
| Social cards | `social/x-card-1200x675.png`, `social/linkedin-card-1200x627.png`, `social/youtube-card-2560x1440.png` | supplied originals | Publishing assets; not loaded into the operator console. |
| App, favicon and profile assets | `app/*` including Android, Apple, maskable, favicon and round signature mark variants | supplied originals; 16–2048 px | Wired by `index.html` and `site.webmanifest` for browser/PWA and email-signature use. |
| Email signature and stationery artwork | `email/email-signature-horizontal-600.png`, `email/email-stationery-banner-{600x200,1200x400}.png` | supplied originals | Browser/email composition reference; the supplied 1200×400 banner is also bundled as the CID-safe mail-core attachment. |
| Motion frames | `animation/{logo,mark}-loop.{gif,webp}`, `frames/logo-motion-01.png` through `04.png` | supplied animation plus native-frame extraction; 1280×420 frames | Motion/export production; stills correspond to the four contact-sheet frames. |
| Globe and wave backgrounds | `generated/nullapart-{globe,wave}-command-bg@2x.png` | direct generated artwork; 3344×1882 and 3832×1642 | Decorative shell atmosphere only, never status information. |
| Security icon set | `icons/icon-{clean-shield,threat-shield,review-warning,processing-mail,settings}.svg` | code-native SVG; scalable | Semantic visual vocabulary, safe at zoom and themable by context. |
| CTA reference assets | `ui/{get-started-button,contact-sales-button}.svg` | code-native SVG; 360×112 | Marketing reference assets; not used to create deceptive admin actions. |
| Status set | `status/status-{clean,threat,review}-256.png`, `status/status-{processing,delivered}.svg` | supplied originals plus code-native SVG; 256 px/scalable | Live application status pills and sidebar session-boundary mark. |

The application uses high-density original image files where imagery is useful,
and uses SVG/CSS for scalable interactive controls. Decorative images carry an
empty `alt`; labels and state stay in semantic text so no security meaning is
lost when images, animation or colour are unavailable.

The shell now applies the horizontal lock-up, status mark and an authenticated
scope bar to every protected route. The login uses the supplied 2560×900 hero
behind an overlay, preserving foreground contrast and never making a visual
asset an authentication or authorization signal.

## Public corporate landing

**Implemented:** 2026-10-20.

`/` is a public corporate landing page, distinct from the authenticated
operator workspace at `/console`. It uses only generic, supportable product
statements and never loads session, customer, operational or model data. Its
calls to action lead to the existing `/login` flow; it does not imply a
public self-service control plane. The new security-network artwork is a
high-density generated asset informed by the approved design board, not a crop
of that board. Its source prompt explicitly excludes logos, text, UI and
status meaning, leaving all product language as accessible HTML.

## Operator workspace interaction model

**Implemented:** 2026-10-15.

The protected console is organized as an operator workspace rather than a
decorated dashboard. Each operational route uses a shared `WorkspaceHeader`
that states the control domain, the route purpose and the authorization
boundary. Its primary action slot contains only controls already backed by an
authorized server operation; it never creates an implied local-only control.

The `WorkflowGuide` beneath the route header puts the existing workflow in the
order an administrator should follow: assess evidence, make a bounded change,
then confirm the server-reported result. It is present across customers,
policies and feature overrides, runtime/scanner operations, domains, outbound
intelligence, connectors, quarantine, message tracing, audit, AI/model
governance, user directory and local console settings. Record-detail routes
retain their case/customer/policy facts and use the same workflow treatment
where an investigation or revision decision is required.

Routes with a live operational state also use `ControlRail`, a compact
priority surface whose operational and risk signals come from the query
response already authorized for that route. It may also label explicitly local
UI state, such as the browser theme or whether a search has been submitted;
local state is never presented as server health. It puts the relevant queue or
risk signal directly beside the permitted operation: customer lifecycle state,
policy release scope, feature floors, runtime outbox/dead letters, scanner
capacity, domain trust, outbound events, connector remediation, quarantine
eligibility, model/AI governance and the dashboard's navigation-only priority
queue. A rail never manufactures a health state from browser data, and
dashboard signals link to the workspace where the authorized action actually
exists.

This presentation layer does not change the authority model. Buttons still
render according to the existing permission checks; server authorization,
tenant ownership, step-up prompts, idempotency keys and audit records remain
the source of truth. The workflow language explicitly calls out sandboxed
message rendering, non-display of provider secrets, security floors and
exception-only quarantine release so visual convenience cannot be mistaken for
permission.

## Email stationery

`crates/mail-core/src/notification_stationery.rs` provides a branded HTML
renderer, matching plain-text alternative, and the supplied 1200×400 CID-ready
header artwork bundle. It deliberately contains no remote images, tracking pixels,
scripts, forms, caller-controlled markup or URLs. This works in image-blocking
mail clients and avoids privacy/tracking behaviour in a security-product
notification.

The renderer escapes every content value at the final HTML boundary. It is not
a mail sender. No current Nullapart workflow dispatches it, and this document
does not authorize one. A future sending workflow must document and implement
authorization, recipient scope, outbox/audit atomicity, idempotency, rate
limits, retry/dead-letter handling, tenant/deployment identity and user
notification preferences before use.

## Verification

- Frontend: `pnpm --dir frontend check-all` and `pnpm --dir frontend build`.
- Stationery: `cargo test -p nullapart-mail-core notification_stationery`.
- Visual review: inspect authenticated dashboard, operations and at least one
  dense table/form route at desktop and narrow viewport; verify dark/light,
  keyboard focus, skip link, empty/error/loading states and reduced motion.

The generated visual assets must be reviewed after any replacement rather than
being accepted solely because their files exist.

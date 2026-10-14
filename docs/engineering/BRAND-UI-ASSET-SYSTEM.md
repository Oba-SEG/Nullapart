# Nullapart Brand, UI and Stationery System

**Status:** implementation record.

**Last verified:** 2026-10-14.

## Purpose

This document ties the implemented frontend visual language to the Phase 0
and Phase 3 requirements: a tokenised, accessible, neumorphic administrative
console. It is not a replacement for security, RBAC, server-side
authorization or the phase plans.

## Visual direction

Nullapart uses a midnight command surface with acid-lime as the primary
operator signal and cyan as a successful/healthy supporting signal. The
reference artwork establishes the atmosphere; it does not override the
administrative UI requirements:

- cards use soft raised and inset depth, plus a visible border;
- focus, status and text retain explicit contrast independent of shadows;
- tables remain compact and readable for operator workloads;
- status/severity colours are semantic tokens, not decorative status;
- the light theme preserves the same hierarchy without turning the application
  into a different product;
- reduced-motion preference disables nonessential transition duration.

The implementation lives in `frontend/src/styles/tokens.css`,
`frontend/src/styles/global.css`, and the existing component/page styles. The
application shell supplies a keyboard-visible skip link to `#main-content`.

## Asset inventory

| Asset | Dimensions | Purpose | Use constraints |
| --- | ---: | --- | --- |
| `frontend/public/brand/horizontal-logo.png` | existing source | Application shell lock-up | Do not regenerate textual logo art with an image model. |
| `frontend/public/brand/logo-mark.png` | existing source | Compact product mark | Preserve its established brand geometry. |
| `frontend/public/brand/generated/nullapart-globe-command-bg.png` | 1672×941 | Wide admin header/ambient background | Decorative only; never conveys state. |
| `frontend/public/brand/generated/nullapart-globe-command-bg@2x.png` | 3344×1882 | High-density rendition | Current header/background source. |
| `frontend/public/brand/generated/nullapart-wave-command-bg.png` | 1916×821 | Panel/sidebar ambient background | Decorative only; never conveys state. |
| `frontend/public/brand/generated/nullapart-wave-command-bg@2x.png` | 3832×1642 | High-density rendition | Current panel/sidebar source. |

The two visual compositions were generated as artwork, then retained with
high-density renditions for the browser. CSS-built grids, focus rings, status
markers, controls and table structures are deliberately code-native rather
than raster assets so they respond to theme, zoom, content and assistive
technology.

## Email stationery

`crates/mail-core/src/notification_stationery.rs` provides a branded HTML
renderer and matching plain-text alternative. It deliberately contains no
remote images, tracking pixels, scripts, forms, caller-controlled markup or
URLs. This works in image-blocking mail clients and avoids privacy/tracking
behaviour in a security-product notification.

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

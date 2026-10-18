# DESIGN.md — Nullapart Console

Design source of truth for the Nullapart admin console. Register: product.

The visual direction was deliberately re-anchored on 2026-10-17 to the
**flat enterprise security-console register (Mimecast admin console /
Proofpoint Enterprise Privacy)**. This supersedes the depth language of the
earlier "ACID LIME + MIDNIGHT v1.0" board: the board remains the source for
brand _assets_ (logo crops, favicons, status icon chips) and for the `--lime`
signal hue, but no longer prescribes surface treatment. `docs/12-UI-DESIGN-SYSTEM.md`
and this file are the implementation authority; where the board picture and
this file disagree, this file wins.

## Visual Theme

Light-first operational console on a cool neutral canvas. Every surface is
flat: separation comes from 1px hairline rules and background steps, never
from raised shells, inset wells, glows or gradients. One restrained cool
accent (`--color-primary`) carries focus, links, primary actions and
selection; the status scale is fixed and never recolored by theme. Hierarchy
comes from typography, spacing and rules.

Themes:

- **Light (default)** — `#eef1f5` canvas, white panels, ink
  `#1b2733` text, accent `#1a6ba1`.
- **Dark (opt-in, persisted in `localStorage["nullapart-theme"]`)** — the
  same token names with AA-recalibrated values for long low-light sessions.

The navigation rail and the login brief panel stay on a dark ink ground in
both themes so the white wordmark artwork always reads on its intended
background.

## Color Palette

### Semantic roles (tokens in `frontend/src/styles/tokens.css`)

| Token                                      | Light value           | Role                                              |
| ------------------------------------------ | --------------------- | ------------------------------------------------- |
| `--color-bg-primary`                       | `#eef1f5`             | App canvas                                        |
| `--color-bg-secondary`                     | `#ffffff`             | Panels, cards, inputs                             |
| `--color-bg-tertiary`                      | `#f6f8fa`             | Table headers, sub-tone blocks                    |
| `--color-text-primary`                     | `#1b2733`             | Body and labels (≥4.5:1 on every surface)         |
| `--color-border` / `--color-border-strong` | `#d6dde5` / `#aab6c3` | Hairlines, control outlines                       |
| `--color-primary`                          | `#1a6ba1`             | Focus, links, primary action                      |
| `--color-selected-bg` / `-text`            | `#e3eef7` / `#145682` | Selection tint                                    |
| `--color-rail-*`                           | `#16202a` ground      | Navigation rail, login brief                      |
| `--lime`                                   | `#A8FF00`             | Brand signal constant only, never an action color |

Status and severity are fixed roles: `--color-success` `#1c7a4b`,
`--color-warning` `#8a5a00`, `--color-error` `#b0144a`, plus
`--color-severity-{critical,high,medium,low,info}`. Badges are a tinted
background, a 1px `color-mix` border and the tone-colored label; glow is not
a status affordance anywhere in the console.

### Status icons

| State                          | Chip                                     |
| ------------------------------ | ---------------------------------------- |
| Clean                          | lime `#A8FF00` circle, black check       |
| Threat                         | pink `#FF006E` circle, white `(!)`       |
| Review                         | amber `#FFB020` circle, black triangle-! |
| Processing / Delivered / Muted | hairline outline chips                   |

Rendered by `frontend/src/components/StatusPill.tsx`; the icon chips are
board-derived brand constants valid in both themes. Severity mapping:
critical/high → threat, medium → review, low/info → muted. Never color
alone: the label always ships with the icon.

## Typography

- Family: **Inter** (bundled via `@fontsource/inter`, CSP `font-src 'self'`),
  400/500/600/700. Mono: system stack for IDs, digests and timestamps.
  Display and body use the same family; hierarchy comes from size and weight.
- Scale: 11 / 12 / 13 / 14 / 15 / 17 / 20 / 24 / 30px. Page titles are 20px
  semibold with `-0.02em` tracking, not display type.
- Numerals in data surfaces use `font-variant-numeric: tabular-nums`.
- No all-caps body copy. Section labels are sentence case; uppercase survives
  only in short status badges.

## Components

- **Buttons**: 32px compact, radius 4px, 1px outline, hover/active change
  fill or border only. Primary = accent fill + white text; Danger =
  `--color-error` fill; Clean/allow = `--color-success` fill. Disabled is
  flat and hairline-outlined.
- **Panels/cards**: white fill, 1px `--color-border`, radius 6px, no shadow.
  Tables stay tables: one bordered frame, no per-cell treatment.
- **Inputs**: white fill, 1px `--color-border-strong`, radius 4px, focus =
  accent border + `--focus-ring`.
- **Links**: colour shift on hover, never an underline. Every link here is a
  discrete affordance (nav row, table action, labelled button), not a link
  inside running prose, so the underline read as a selection artefact.
- **Dialogs**: the only shadowed surface (`--shadow-lg`) over a dimmed
  backdrop.
- **Nav active state**: `--color-rail-active-bg` fill plus a white semibold
  label and an aria-current hook. Selection never relies on a border around the
  pill, an edge stripe, or a solid lime fill.
- **Toasts, hints, badges**: hairline-bordered, tint-filled, no glow.

## Layout

- **App shell: left sidebar**, 240px, dark ink rail: the horizontal logo
  artwork, grouped vertical nav, then one account block at the foot (operator
  identity and boundary label, the display-mode control and sign out). The rail
  carries no session card, because the command bar above the content already
  states scope and authority. Content column `min(1440px, 100%)`. Below 980px
  the rail becomes a top bar and the account block stays visible.
- **Login**: light page, a single bordered two-panel stage. The left brief
  panel is the dark ink ground with the wordmark and a plain sentence; the
  right panel is the form. No backdrop imagery, no rings, no glow.
- Dashboard: metric ledger → command grid → activity/health panels, all
  divided by hairlines rather than cards within cards.
- Spacing: 4px token scale; rhythm 8/16/24/32/48.

## Motion

- Transitions 120–240ms on colour and border only; `prefers-reduced-motion`
  → instant.
- No transform-based hover lift, no decorative loops; processing may use a
  slow spinner only.

## Assets (approved board pack, `frontend/public/brand/`)

- `horizontal-logo.png` — sidebar lockup (mark + wordmark + tagline)
- `primary-logo.png` — login lockup (vertical)
- `logo-mark.png` — icon-only mark
- `favicon_16x16.png` / `favicon_32x32.png` / `favicon_512x512.png` —
  real favicons from the pack (`index.html`)
- `status/*.png` — status icon chips listed above
- The globe hero artwork is retired from the UI (it is depth decoration, not
  an information surface). It remains in the pack; `scripts/verify-brand-assets.mjs`
  still checks it exists.
- No stock photography; email content renders via the isolated renderer.
- These PNGs are exact crops of the approved board (no vectors exist in the
  pack); redraw/replacements are not permitted.

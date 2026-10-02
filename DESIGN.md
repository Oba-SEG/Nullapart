# DESIGN.md — Nullapart Console

Design source of truth for the Nullapart admin console. Derived from the
**approved "ACID LIME + MIDNIGHT v1.0" brand board** (source of truth:
`approved-reference-board.png` in the reference pack; extracted assets in
`nullapart_assets/`). Register: product.

When documentation and the board disagree, the board wins.

## Visual Theme

Dark-first operational console on the Midnight canvas, using the
**restrained neumorphic / soft-interface language mandated by
`docs/12-UI-DESIGN-SYSTEM.md`**: surfaces are raised clay shells (deep
shade bottom-right + paper tint top-left), wells/inputs are recessed, and
interactive controls press into an inset state. Hairline borders remain on
every shell so boundaries never depend on shadow alone, hierarchy stays
stronger than decoration, and important actions are never signalled by
shadow alone. Acid lime is the only primary action color; pink/amber/cyan
carry the security status scale. On Midnight the tint/shade pair is
`rgba(250,250,250,0.07–0.09)` / `rgba(0,0,0,0.65–0.75)`; the light theme
uses classic paper neumorphism (white / `rgba(5,5,5,0.13–0.17)`). Lime
pills may add the soft `--shadow-glow-lime` outer glow (board glow
language).

Themes:

- **Dark (default)** — the board's own theme; used unless the operator
  picks light.
- **Light (toggle, persisted in `localStorage["nullapart-theme"]`)** — a
  console convenience not present on the board: same token names with
  AA-contrast recalibrated values. Lime fills keep dark text; lime-as-text
  darkens to a lime ink. The sidebar stays Midnight in both themes so the
  real logo artwork always reads on its intended background.

## Color Palette

### Core (board labels, exact)

| Token | Hex | Role (board label) |
| --- | --- | --- |
| `--lime` | `#A8FF00` | Primary — Signal, detect |
| `--midnight` | `#050505` | Background — Midnight |
| `--pink` | `#FF006E` | Accent — Threat, block |
| `--cyan` | `#00F5D4` | Accent — Clean, allow |
| `--panel` | `#000D0D` | Surface — Panels, UI |
| `--paper` | `#FAFAFA` | Text — Primary copy |

There is **no blue** in the board palette; selection and management-level
affordances use lime tints or neutral surfaces instead.

### Semantic status scale (board "UI ELEMENTS", sampled from board pixels)

| State | Icon chip | Label |
| --- | --- | --- |
| Clean | lime `#A8FF00` circle, black check | primary text |
| Threat | pink `#FF006E` circle, white `(!)` | pink |
| Review | amber `#FFB020` circle, black triangle-! | amber |
| Processing | transparent, gray outline circle + clock | tertiary |
| Delivered | transparent, gray outline square + mail | secondary |
| Muted | transparent, hairline outline circle + dash | secondary |

Rendered by `frontend/src/components/StatusPill.tsx` (icon chips are brand
constants valid in both themes). Severity mapping: critical/high → threat,
medium → review, low/info → muted. Never color alone: the label always
ships with the icon.

## Typography

- Family: **Inter** (bundled via `@fontsource/inter`, CSP `font-src 'self'`),
  Regular/Medium/Semibold/Bold/Extrabold. Mono: existing system stack.
- Wordmark and tagline are **not** typeset in the app: they come from the
  board's logo artwork (`brand/horizontal-logo.png`, `brand/primary-logo.png`).
- No all-caps body copy; uppercase reserved for short labels/badges.

## Components

- **Buttons**: full pill with neumorphic press states — raised
  (`--shadow-sm`) at rest, deeper (`--shadow-md`) on hover, recessed
  (`--shadow-inset`) on press, flat when disabled; primary lime also
  carries `--shadow-glow-lime`. Primary = lime fill + `#050505` text;
  Secondary = hairline outline; Danger = pink fill (near-black text — the
  board shows white-on-pink, but white on `#FF006E` is 3.8:1 and fails
  WCAG AA, so we keep the board hue with dark text at 5.3:1);
  Clean/allow = cyan fill + `#050505` text (board "Message Clean").
- **Panels/cards**: `--panel #000D0D` fill, hairline border, radius 12px,
  raised `--shadow-sm` (`card-elevated` uses `--shadow-md`). Page/state
  banners and the isolated message viewer get the same shell treatment.
  Tables stay tables: framing around the table/page, no per-cell clay
  (`docs/12:71`).
- **Status pills**: board status elements (icon chip + label), see above.
- **Tables**: tertiary header row, hairline separators, lime-tint selection.
- **Inputs**: elevated fill, hairline border, recessed `--shadow-inset`
  well; focus = inset + lime focus ring. Dialogs are neumorphic detail
  surfaces (`--shadow-lg` + dimmed backdrop).
- **Nav active state**: solid lime pill with dark text (board nav language).

## Layout

- **App shell: left sidebar** (operator console convention; the board's own
  nav example is the marketing top bar, not the console). Sidebar is fixed
  248px, always Midnight, holds the horizontal logo artwork, vertical nav
  with lucide icons and lime active pills, and theme/session/sign-out at
  the foot. Content column max ~1400px. Collapses to a horizontal nav bar
  under 900px.
- **Login**: full-bleed Midnight with the board's globe artwork as a low
  opacity backdrop, centered card carrying the primary vertical logo, one
  lime pill CTA.
- Dashboard: metric tiles → activity/health panels; health states use
  status pills.
- Spacing: 4px token scale; rhythm 8/16/24/32/48.

## Motion

- Transitions 150–300ms; `prefers-reduced-motion` → instant.
- No decorative loops; processing may use a slow spinner only.

## Assets (approved board pack, `frontend/public/brand/`)

- `horizontal-logo.png` — sidebar lockup (mark + wordmark + tagline)
- `primary-logo.png` — login lockup (vertical)
- `logo-mark.png` — icon-only mark
- `globe-background.png` — login backdrop (board hero artwork)
- `favicon_16x16.png` / `favicon_32x32.png` / `favicon_512x512.png` —
  real favicons from the pack (`index.html`)
- No stock photography; email content renders via the isolated renderer.
- These PNGs are exact crops of the approved board (no vectors exist in the
  pack); redraw/replacements are not permitted.

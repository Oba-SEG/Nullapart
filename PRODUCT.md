# Product

## Register

product

## Users

Security operators and system administrators who run the Nullapart secure email
gateway. They work in long operational sessions: triaging quarantined mail,
reviewing scanner findings, editing policy rules, watching queue and delivery
health. The console is a work surface, not a brochure; every screen answers
"what needs my attention right now" and gets out of the way.

## Product Purpose

Operate and govern the mail security gateway: inspect messages and quarantine
decisions, manage tenants/customers, author policy and feature overrides, audit
administrative actions, and monitor delivery health. Success is fast, confident
operational decisions with clear evidence and zero ambiguity about system state.

## Brand Personality

Precise, vigilant, electric. Security-grade seriousness with a high-energy
signal color; confident and technical, never playful or corporate-soft.

## Anti-references

- The console's former look: light neumorphic gray/blue enterprise UI
  (soft embossed cards, muted slate text), called out in CODE-STANDARDS as
  accessibility-breaking neumorphism.
- Generic light SaaS admin templates: white-on-white cards, pillowy shadows,
  indigo primary, decorative gradients.
- Marketing gloss inside the product: hero theatrics, gradient text,
  decorative glassmorphism on operational data.

## Design Principles

1. Signal has meaning: acid lime marks live/active/primary affordances; nothing
   is lime because it looks nice.
2. Status is readable at a glance: threat (pink), clean (cyan), review (amber)
   follow one semantic scale across every table, badge, and icon.
3. Dark-first, contrast-locked: Midnight canvas with ≥4.5:1 body contrast in
   both themes; the light theme is a peer theme, not an afterthought.
4. Density with hierarchy: tables and forms stay information-dense; scale and
   weight contrast (Inter Light→Extrabold) carry hierarchy, not decoration.
5. The brand shows up where identity matters (login, header, empty states),
   the workflow stays quiet everywhere else.

## Accessibility & Inclusion

- Target WCAG 2.2 AA: ≥4.5:1 body text, ≥3:1 large text and UI boundaries in
  both themes.
- Theme choice is user-controlled (dark default, persisted light toggle).
- `prefers-reduced-motion` respected for all transitions/animations.
- Status never relies on color alone: icons/labels accompany semantic colors.
- Restrained neumorphism per `docs/12-UI-DESIGN-SYSTEM.md`: raised shells and
  recessed wells use light/dark shadow pairs, but every shell keeps a hairline
  border, hierarchy never depends on shadow alone (CODE-STANDARDS bans only
  accessibility-breaking embossing), and both themes hold WCAG AA contrast.

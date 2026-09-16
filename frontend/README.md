# Nullapart Frontend

Administration console for System, Support and Customer Admin roles.

## Baseline architecture

See [Frontend Architecture and Package Baseline](../docs/23-FRONTEND-ARCHITECTURE.md).

Phase 0 baseline:

- React + TypeScript;
- Vite;
- pnpm;
- TanStack Router;
- TanStack Query;
- TanStack Table;
- React Hook Form;
- Zod;
- Radix Primitives;
- custom CSS custom-properties/CSS Modules for Nullapart neumorphism;
- Sentry-compatible browser SDK -> regional SegLumberjack;
- Vitest + Testing Library;
- Playwright.

Exact dependency versions are pinned in the lockfile when Phase 0 initializes the application.

## Security invariants

- no authentication/refresh tokens in Local Storage/Session Storage/IndexedDB;
- route guards are UX, not authorization;
- backend performs tenant/resource ownership checks;
- client validation is backed by server validation;
- one central API client handles CSRF, errors, timeouts and idempotency;
- no raw JSON UI;
- hostile email HTML never runs in the trusted application DOM;
- Restricted artifacts use an authenticated controlled download path;
- URLs never contain bearer/session/API secrets.

## Design

Carefully planned neumorphism with security-console density, accessibility and keyboard operation.

See:

- `docs/12-UI-DESIGN-SYSTEM.md`
- `docs/19-SECURE-MESSAGE-RENDERING.md`
- `docs/security/20-APPLICATION-SECURITY-CONTROLS.md`

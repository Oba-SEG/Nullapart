# Frontend Architecture and Package Baseline

**Status:** Phase 0 implementation baseline.

## Objective

Build a secure, accessible, maintainable administration console for System, Support and Customer Admin roles.

The frontend is a security console, not a marketing site and not a generic component-demo application.

## Architecture

Use a regional same-origin application model:

```text
Browser
  -> https://<deployment>.nullapart.com
  -> AWS ALB / WAF
       |-- /api/v1/* and /auth/* -> Control Backend / BFF
       '-- UI/static routes      -> Frontend service/static delivery
```

The browser should not manage long-lived OAuth/OIDC bearer credentials.

The Control Backend/BFF owns the OIDC authorization-code exchange/session where practical and issues secure server-managed session cookies.

## Baseline stack

The Phase 0 baseline is:

- React;
- TypeScript;
- Vite;
- TanStack Router;
- TanStack Query;
- TanStack Table;
- React Hook Form;
- Zod;
- Radix Primitives;
- CSS custom properties + CSS Modules for the Nullapart neumorphic design system;
- Lucide React or equivalent reviewed icon package;
- date-fns or equivalent focused date/time utilities;
- Sentry-compatible browser SDK configured to regional SegLumberjack;
- Vitest + Testing Library;
- Playwright for critical E2E/security UI flows.

Do not add a global state framework such as Redux by default. Use:

- TanStack Query for server state;
- Router state for navigation/search params;
- local React state/context for local UI state.

Introduce another state manager only when a demonstrated need exists.

## Current supported baseline at architecture review

As of September 2026, the ecosystem baseline selected for Phase 0 is compatible with:

- React 19 current major;
- Vite 8 supported major;
- TanStack Query v5;
- Zod v4;
- Vitest v5;
- Node.js 24 LTS for CI/build runtime.

Exact patch versions are selected at Phase 0 initialization and pinned in `pnpm-lock.yaml`; architecture docs should not be used as a substitute for the lockfile.

See [Package Compatibility and Upgrade Matrix](26-PACKAGE-COMPATIBILITY.md).

## Package manager

Use `pnpm`.

Commit:

- `package.json`;
- `pnpm-lock.yaml`;
- package-manager version metadata.

Do not use multiple frontend package managers in the same repo.

CI uses frozen lockfile installation.

## Dependency compatibility

Frontend dependencies are evaluated as a stack, not independently.

Requirements include:

- React/ReactDOM compatibility;
- Vite/Node compatibility;
- TypeScript support window;
- peer-dependency correctness;
- package-manager compatibility;
- test/build compatibility;
- browser support;
- license/security review.

Do not use `--force`/legacy peer dependency bypass as the normal solution to incompatibility.

## Dependency rules

A new frontend dependency requires justification for:

- capability;
- maintenance/security;
- license;
- bundle impact;
- accessibility impact;
- overlap with existing package.

Avoid dependency-heavy component suites that fight the custom neumorphic design system.

## Radix role

Radix provides accessible behavior primitives such as dialogs, dropdowns, tooltips, popovers, tabs, selects and related controls.

Nullapart owns:

- styling;
- design tokens;
- visual hierarchy;
- security/product semantics.

Do not ship default third-party visual themes as the product design.

## Routing

Use typed route definitions.

Route guards improve UX but are not authorization.

Every backend request remains independently authorized.

Sensitive resource IDs in routes do not grant access.

## URL rules

URLs may contain:

- non-sensitive navigation state;
- pagination/filter values;
- tenant/resource identifiers that are already safe to reveal to that role.

URLs must not contain:

- session IDs;
- access tokens;
- refresh tokens;
- API keys;
- passwords;
- OpenBao/AWS credentials;
- bearer credentials;
- HMAC/shared secrets;
- message body/content;
- sensitive audit evidence.

OIDC protocol callback parameters such as short-lived authorization `code`/`state` may appear only as required by the protocol. The backend must exchange them immediately and redirect to a clean URL so they are not retained in browser history/application logs longer than necessary.

Avoid direct browser S3 presigned query-string credentials for Restricted mail artifacts. Prefer an authenticated application download/stream endpoint.

## Authentication storage

Do not persist auth/refresh tokens in:

- Local Storage;
- Session Storage;
- IndexedDB.

Preferred session:

- Secure;
- HttpOnly;
- appropriate SameSite;
- short/session-limited lifetime;
- CSRF protected;
- revocable server-side/session-provider side.

Frontend code treats authentication state as session status, not as ownership of a bearer token.

## API client

Provide one typed API-client boundary responsible for:

- `/api/v1` contract access;
- credentials/cookie behavior;
- CSRF token;
- correlation ID handling;
- error normalization;
- retry rules;
- idempotency key support;
- cancellation/timeouts;
- compatible API/schema handling.

Do not let every component hand-roll `fetch`.

Automatic retries must never blindly repeat unsafe mutations.

See [API Versioning, Feature Flags and Feature Addition Governance](27-API-VERSIONING-FEATURE-FLAGS.md).

## Feature switches

The frontend may use feature flags to shape navigation/UX, but backend evaluation remains authoritative for security-sensitive capabilities.

Rules:

- do not treat hidden UI as authorization;
- design disabled/unavailable states;
- do not allow client parameters to self-enable a feature;
- temporary release flags have owner/removal target;
- System kill switches should produce a clear product state/error rather than a broken page.

## Validation

Use Zod/shared schema approach for frontend UX validation where appropriate.

Server validation remains authoritative.

Do not assume sharing a schema means sharing authorization/business logic; authorization remains backend-owned.

## Errors

Create a standard error UI model:

- stable error code;
- safe message;
- field errors where relevant;
- correlation ID;
- retryable/non-retryable;
- action guidance.

Never display:

- stack traces;
- SQL/provider internals;
- raw JSON exception objects;
- auth tokens;
- Restricted message data in unrelated error banners.

## TLS / certificate trust

Browser HTTPS uses normal modern Web PKI validation.

Do not add HPKP/Public-Key-Pins headers or hard-code browser certificate fingerprints.

Use:

- valid public certificates;
- HSTS;
- CAA;
- certificate renewal/monitoring;
- normal browser trust validation.

See `docs/security/25-CERTIFICATE-TRUST-PINNING.md`.

## Security headers/browser policy

Control Plane should use a restrictive baseline including:

- Content Security Policy;
- frame restrictions;
- Referrer Policy;
- permissions policy as appropriate;
- HSTS;
- MIME sniffing protection.

Message rendering uses the separate hostile-content architecture.

## Accessibility

Component wrappers around Radix/HTML primitives must preserve:

- keyboard support;
- focus;
- labels;
- ARIA semantics;
- contrast;
- reduced motion;
- screen-reader status.

Neumorphism never overrides accessibility.

## Brand, visual system and email stationery

**Last verified:** 2026-10-14.

The design system is an accessible **midnight neumorphic command console**:
soft raised/inset surfaces, explicit borders, visible focus, dense operational
tables and a restrained acid-lime/cyan signal palette. The aesthetic is not a
marketing dashboard and visual elevation never supplies meaning on its own.

The definitive implementation inventory and asset rules are maintained in
[`docs/engineering/BRAND-UI-ASSET-SYSTEM.md`](engineering/BRAND-UI-ASSET-SYSTEM.md).
It records which visual files are generated, their dimensions, allowed uses,
and the verified no-remote-image email-stationery policy.

Service email stationery is a pure rendering foundation only. It has no
dispatch path, recipient selection, link generation or feature flag. A future
phase that sends notification email must separately define its data classes,
recipient authorization, audit/outbox record, retry semantics, unsubscribe/
notification preference behaviour and transport identity before it calls the
renderer.

## Testing

### Unit/component

Use Vitest + Testing Library.

Test:

- permissions/visibility;
- feature-enabled/disabled states;
- validation;
- errors;
- loading/empty states;
- keyboard interactions;
- accessibility-critical behavior.

### E2E

Use Playwright for:

- login/session;
- deployment selection;
- RBAC;
- impersonation;
- wrong-tenant URLs;
- CSRF/session expiry;
- quarantine release;
- audit;
- hostile message rendering;
- token/local-storage checks;
- feature-switch behavior;
- API compatibility critical workflows;
- critical policy workflows.

## Bundle/security

- no production source maps publicly exposed unless intentionally secured;
- no secrets/env credentials bundled;
- environment-specific public configuration is non-secret;
- dependency/bundle analysis in CI where useful;
- avoid dynamic code execution/eval dependencies.

## Directory structure

Recommended:

```text
frontend/
  src/
    app/
    routes/
    features/
    components/
      primitives/
      design-system/
    api/
    auth/
    security/
    flags/
    styles/
    test/
```

Organize domain behavior by feature, not one global folder per technical type when that harms maintainability.

## AI-agent rules

AI agents must:

- use existing design-system components before inventing new patterns;
- keep API access through the central client;
- never store auth tokens in browser storage;
- never treat route guards or feature flags as authorization;
- implement server-error handling, loading and empty states;
- add role/wrong-tenant tests for protected UI;
- preserve the package compatibility matrix/lockfile;
- not introduce packages merely to save a few lines of code.

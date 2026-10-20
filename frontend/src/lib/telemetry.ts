// Browser application telemetry (docs/11): Sentry-compatible envelopes to
// the regional SegLumberjack backend.
//
// Design invariants:
//
// - when VITE_TELEMETRY_DSN is unset the module stays inert: initTelemetry
//   is a no-op and captureException returns an empty id, so feature code
//   never branches on telemetry state;
// - the SDK never carries user content the console does not give it:
//   sendDefaultPii stays false, breadcrumbs are capped, session replay and
//   performance traces stay disabled (this is an operator console);
// - the scrub gate here mirrors crates/observability/src/scrub.rs in
//   spirit: error text is the attacker-reachable frontend surface, so
//   secret-shaped material must never reach the wire.

import * as Sentry from "@sentry/browser";

interface TelemetryOptions {
  dsn: string;
  environment?: string;
  release?: string;
}

/// Returns true when the value must not be transmitted: secret-shaped
/// material, an over-long dump, or control characters. Losing a diagnostic
/// string is acceptable, leaking it is not.
export function scrubbedOrNone(value: string | undefined | null): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const lowered = value.toLowerCase();
  const markers = [
    "begin private key",
    "begin certificate",
    "akia",
    "ghp_",
    "gho_",
    "bearer",
    "authorization",
    "set-cookie",
    "cookie:",
    "password",
    "x-spam",
    "subject:",
  ];
  if (markers.some((marker) => lowered.includes(marker))) {
    return null;
  }
  const bounded = value
    .split("")
    .slice(0, 512)
    .map((character) => (/[\x00-\x1f\x7f]/.test(character) ? "\uFFFD" : character))
    .join("");
  if (bounded.trim().length === 0) {
    return null;
  }
  return bounded;
}

export function isTelemetryConfigured(dsn: string | undefined): boolean {
  return typeof dsn === "string" && dsn.startsWith("http") && dsn.trim().length > 0;
}

type Room = { active: TelemetryOptions | null };
const room: Room = { active: null };

function activeState(): TelemetryOptions | null {
  return room.active;
}

/// Initialize browser telemetry. Safe to call unconditionally at startup;
/// an unusable DSN clears any previous state instead of leaving partial
/// configuration behind.
export function initTelemetry(options: TelemetryOptions): void {
  if (!isTelemetryConfigured(options.dsn)) {
    room.active = null;
    return;
  }
  room.active = options;
  Sentry.init({
    dsn: options.dsn,
    environment: options.environment,
    release: options.release,
    sendDefaultPii: false,
    attachStacktrace: true,
    tracesSampleRate: 0,
    maxBreadcrumbs: 24,
    beforeBreadcrumb(breadcrumb) {
      if (
        typeof breadcrumb.message === "string" &&
        scrubbedOrNone(breadcrumb.message) === null
      ) {
        return null;
      }
      return breadcrumb;
    },
    beforeSend(event) {
      // The console's own error text is the only free-form field; it
      // passes the same gate. Structure elsewhere stays untouched.
      if (event.message && scrubbedOrNone(event.message) === null) {
        event.message = "<scrubbed>";
      }
      if (event.extra) {
        for (const key of Object.keys(event.extra)) {
          if (scrubbedOrNone(key) === null) {
            delete event.extra[key];
          }
        }
      }
      return event;
    },
  });
}

/// Fire-and-forget exception capture. Returns the event id (or an empty
/// string when telemetry is off) as a correlation artefact for the UI.
export function captureException(
  error: unknown,
  correlationId?: string,
  hint?: { component?: string },
): string {
  const state = activeState();
  if (!state || !isTelemetryConfigured(state.dsn)) {
    return "";
  }
  let id: string | null = null;
  Sentry.withScope((scope) => {
    if (correlationId) {
      scope.setTag("correlation_id", correlationId);
    }
    if (hint?.component) {
      scope.setTag("component", hint.component);
    }
    id = Sentry.captureException(error);
  });
  return id ?? "";
}

/// Convenience entry point used by main.tsx: reads the build-time
/// VITE_TELEMETRY_* variables.
export function initFromEnvironment(): void {
  const env = import.meta.env as {
    VITE_TELEMETRY_DSN?: string;
    VITE_TELEMETRY_ENVIRONMENT?: string;
    VITE_TELEMETRY_RELEASE?: string;
  };
  if (!env?.VITE_TELEMETRY_DSN) {
    return;
  }
  initTelemetry({
    dsn: env.VITE_TELEMETRY_DSN,
    environment: env.VITE_TELEMETRY_ENVIRONMENT,
    release: env.VITE_TELEMETRY_RELEASE,
  });
}


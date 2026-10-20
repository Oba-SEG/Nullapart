/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Sentry-compatible telemetry DSN; unset means telemetry stays off. */
  readonly VITE_TELEMETRY_DSN?: string;
  readonly VITE_TELEMETRY_ENVIRONMENT?: string;
  readonly VITE_TELEMETRY_RELEASE?: string;
}

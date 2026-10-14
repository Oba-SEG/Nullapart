/**
 * Nullapart API Client
 *
 * Centralized typed API boundary for /api/v1 contract access.
 * Session cookies are server-managed; bearer tokens are never stored in browser storage.
 */

import { getCsrfToken } from "../auth/csrf";
import { randomUuid } from "../lib/ids";

export interface ApiError {
  code: string;
  message: string;
  traceId?: string;
  apiVersion?: string;
  retryable: boolean;
}

interface ApiSuccessEnvelope<T> {
  data: T;
  api_version: string;
  trace_id: string;
}

interface ApiErrorEnvelope {
  code?: string;
  error?: string;
  message: string;
  trace_id?: string;
  api_version?: string;
}

export interface ApiClientConfig {
  baseUrl: string;
  timeoutMs?: number;
}

function generateCorrelationId(): string {
  return randomUuid();
}

/**
 * Whether this tab has ever held a server session. Lets the 401 handler
 * distinguish "session expired" from "never signed in" without touching
 * browser storage (the session cookie is HttpOnly).
 */
let sessionSeen = false;

export function markSessionSeen(): void {
  sessionSeen = true;
}

export function hasSeenSession(): boolean {
  return sessionSeen;
}

function redirectToLogin(): void {
  if (window.location.pathname.startsWith("/login")) return;
  const suffix = sessionSeen ? "&reason=expired" : "";
  const target = `/login?return_to=${encodeURIComponent(
    window.location.pathname + window.location.search,
  )}${suffix}`;
  window.location.replace(target);
}

export function createApiClient(config: ApiClientConfig) {
  const { baseUrl, timeoutMs = 30_000 } = config;

  async function request<T>(
    method: string,
    path: string,
    body?: unknown,
    options?: {
      signal?: AbortSignal;
      idempotencyKey?: string;
      redirect?: RequestRedirect;
    },
  ): Promise<T> {
    const correlationId = generateCorrelationId();
    const csrfToken = getCsrfToken();

    const headers: Record<string, string> = {
      Accept: "application/json",
      "X-Correlation-ID": correlationId,
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    if (options?.idempotencyKey) {
      headers["X-Idempotency-Key"] = options.idempotencyKey;
    }

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
    const externalSignal = options?.signal;
    const abortFromExternalSignal = () => controller.abort();
    if (externalSignal?.aborted) {
      controller.abort();
    } else {
      externalSignal?.addEventListener("abort", abortFromExternalSignal, { once: true });
    }

    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        credentials: "same-origin",
        signal: controller.signal,
        redirect: options?.redirect ?? "follow",
      });

      // `redirect: "manual"` hides the 3xx itself: a navigation the caller
      // must follow as a full-page load surfaces as an opaque redirect.
      if (response.type === "opaqueredirect") {
        throw {
          code: "AUTH_REDIRECT",
          message: "Authentication continues in the identity provider",
          traceId: correlationId,
          retryable: false,
        } satisfies ApiError;
      }

      if (response.status === 204) {
        return undefined as T;
      }

      const json: unknown = await response.json().catch(() => null);

      if (!response.ok) {
        const errorBody = (json ?? {}) as Partial<ApiErrorEnvelope>;
        const code = errorBody.code ?? errorBody.error ?? `HTTP_${response.status}`;
        if (
          response.status === 401 &&
          !path.startsWith("/auth/") &&
          (code === "UNAUTHENTICATED" || code === "unauthorized" || code === "HTTP_401")
        ) {
          redirectToLogin();
        }
        throw {
          code,
          message: errorBody.message ?? response.statusText,
          traceId: errorBody.trace_id ?? correlationId,
          apiVersion: errorBody.api_version,
          retryable: response.status === 429 || response.status >= 500,
        } satisfies ApiError;
      }

      const envelope = json as ApiSuccessEnvelope<T>;
      if (!envelope || typeof envelope !== "object" || !("data" in envelope)) {
        throw {
          code: "INVALID_API_ENVELOPE",
          message: "The server returned an invalid response envelope",
          traceId: correlationId,
          retryable: false,
        } satisfies ApiError;
      }

      return envelope.data;
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw {
          code: "TIMEOUT",
          message: "Request timed out",
          traceId: correlationId,
          retryable: true,
        } satisfies ApiError;
      }
      throw error;
    } finally {
      externalSignal?.removeEventListener("abort", abortFromExternalSignal);
      window.clearTimeout(timeoutId);
    }
  }

  /**
   * Fetches a non-JSON contract (currently CSV export) through the same
   * cookie/CSRF/correlation boundary as `request`, returning the raw body
   * as a Blob. Error responses still surface the typed `ApiError`, and a
   * 401 still triggers the session-expiry redirect — so no caller ever
   * needs a raw `fetch` for an authenticated download.
   */
  async function download(
    method: string,
    path: string,
    body?: unknown,
    options?: { signal?: AbortSignal },
  ): Promise<Blob> {
    const correlationId = generateCorrelationId();
    const csrfToken = getCsrfToken();

    const headers: Record<string, string> = {
      Accept: "text/csv, application/octet-stream",
      "X-Correlation-ID": correlationId,
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
    const externalSignal = options?.signal;
    const abortFromExternalSignal = () => controller.abort();
    if (externalSignal?.aborted) {
      controller.abort();
    } else {
      externalSignal?.addEventListener("abort", abortFromExternalSignal, { once: true });
    }

    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        credentials: "same-origin",
        signal: controller.signal,
      });

      if (!response.ok) {
        const json: unknown = await response.json().catch(() => null);
        const errorBody = (json ?? {}) as Partial<ApiErrorEnvelope>;
        const code = errorBody.code ?? errorBody.error ?? `HTTP_${response.status}`;
        if (
          response.status === 401 &&
          (code === "UNAUTHENTICATED" || code === "unauthorized" || code === "HTTP_401")
        ) {
          redirectToLogin();
        }
        throw {
          code,
          message: errorBody.message ?? response.statusText,
          traceId: errorBody.trace_id ?? correlationId,
          apiVersion: errorBody.api_version,
          retryable: response.status === 429 || response.status >= 500,
        } satisfies ApiError;
      }

      return await response.blob();
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw {
          code: "TIMEOUT",
          message: "Request timed out",
          traceId: correlationId,
          retryable: true,
        } satisfies ApiError;
      }
      throw error;
    } finally {
      externalSignal?.removeEventListener("abort", abortFromExternalSignal);
      window.clearTimeout(timeoutId);
    }
  }

  return {
    get<T>(path: string, signal?: AbortSignal) {
      return request<T>("GET", path, undefined, { signal });
    },
    post<T>(
      path: string,
      body?: unknown,
      options?: {
        signal?: AbortSignal;
        idempotencyKey?: string;
        redirect?: RequestRedirect;
      },
    ) {
      return request<T>("POST", path, body, options);
    },
    put<T>(
      path: string,
      body?: unknown,
      options?: { signal?: AbortSignal; idempotencyKey?: string },
    ) {
      return request<T>("PUT", path, body, options);
    },
    patch<T>(
      path: string,
      body?: unknown,
      options?: { signal?: AbortSignal; idempotencyKey?: string },
    ) {
      return request<T>("PATCH", path, body, options);
    },
    delete<T>(path: string, options?: { signal?: AbortSignal; idempotencyKey?: string }) {
      return request<T>("DELETE", path, undefined, options);
    },
    download(method: string, path: string, body?: unknown, options?: { signal?: AbortSignal }) {
      return download(method, path, body, options);
    },
  };
}

export const api = createApiClient({
  baseUrl: "/api/v1",
});

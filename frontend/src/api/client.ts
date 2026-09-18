/**
 * Nullapart API Client
 *
 * Centralized typed API boundary for /api/v1 contract access.
 * Session cookies are server-managed; bearer tokens are never stored in browser storage.
 */

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
  error: string;
  message: string;
  trace_id?: string;
  api_version?: string;
}

export interface ApiClientConfig {
  baseUrl: string;
  timeoutMs?: number;
}

function generateCorrelationId(): string {
  return crypto.randomUUID();
}

function getCsrfToken(): string | null {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta?.getAttribute("content") ?? null;
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
    const signal = options?.signal
      ? AbortSignal.any([options.signal, controller.signal])
      : controller.signal;

    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        credentials: "same-origin",
        signal,
      });

      if (response.status === 204) {
        return undefined as T;
      }

      const json: unknown = await response.json().catch(() => null);

      if (!response.ok) {
        const errorBody = (json ?? {}) as Partial<ApiErrorEnvelope>;
        throw {
          code: errorBody.error ?? `HTTP_${response.status}`,
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
      options?: { signal?: AbortSignal; idempotencyKey?: string },
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
    patch<T>(path: string, body?: unknown, options?: { signal?: AbortSignal }) {
      return request<T>("PATCH", path, body, { signal: options?.signal });
    },
    delete<T>(path: string, options?: { signal?: AbortSignal }) {
      return request<T>("DELETE", path, undefined, { signal: options?.signal });
    },
  };
}

export const api = createApiClient({
  baseUrl: "/api/v1",
});

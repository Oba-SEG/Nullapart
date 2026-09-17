/**
 * Nullapart API Client
 *
 * Centralized typed API boundary for /api/v1 contract access.
 * Handles credentials/cookies, CSRF, correlation IDs, error normalization,
 * retry rules, idempotency key support, cancellation/timeouts.
 *
 * Follows: docs/23-FRONTEND-ARCHITECTURE.md
 */

// API error model
export interface ApiError {
  code: string;
  message: string;
  field?: string;
  correlationId?: string;
  retryable: boolean;
}

// Standard API response envelope
export interface ApiResponse<T> {
  data: T;
  meta?: {
    page?: number;
    pageSize?: number;
    total?: number;
    correlationId?: string;
  };
}

// API client configuration
export interface ApiClientConfig {
  baseUrl: string;
  timeoutMs?: number;
}

// Generate a correlation ID for request tracing
function generateCorrelationId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

// CSRF token management (read from meta tag or cookie)
function getCsrfToken(): string | null {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta?.getAttribute("content") ?? null;
}

// Create a typed API client
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
      "Content-Type": "application/json",
      "X-Correlation-ID": correlationId,
    };

    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }

    if (options?.idempotencyKey) {
      headers["X-Idempotency-Key"] = options.idempotencyKey;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    // Merge caller's signal with our timeout
    const signal = options?.signal
      ? AbortSignal.any([options.signal, controller.signal])
      : controller.signal;

    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        credentials: "same-origin", // cookies only, never localStorage tokens
        signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw {
          code: errorBody.code || `HTTP_${response.status}`,
          message: errorBody.message || response.statusText,
          field: errorBody.field,
          correlationId,
          retryable: response.status === 429 || response.status >= 500,
        } as ApiError;
      }

      // Handle 204 No Content
      if (response.status === 204) {
        return undefined as T;
      }

      return response.json();
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof DOMException && error.name === "AbortError") {
        throw {
          code: "TIMEOUT",
          message: "Request timed out",
          correlationId,
          retryable: true,
        } as ApiError;
      }

      throw error;
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

// Singleton API client instance
export const api = createApiClient({
  baseUrl: "/api/v1",
});

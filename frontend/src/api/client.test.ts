import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clearCsrfToken, setCsrfToken } from "../auth/csrf";
import { createApiClient } from "./client";

function jsonResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "Response",
    json: async () => body,
  };
}

describe("api client CSRF header", () => {
  beforeEach(() => {
    clearCsrfToken();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("attaches the in-memory CSRF token to mutating requests", async () => {
    setCsrfToken("session-csrf");
    const fetchMock = vi.fn(async () => jsonResponse(200, { data: { ok: true } }));
    vi.stubGlobal("fetch", fetchMock);
    const client = createApiClient({ baseUrl: "/api/v1" });

    await client.post("/auth/logout");

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/auth/logout");
    const headers = init.headers as Record<string, string>;
    expect(headers["X-CSRF-Token"]).toBe("session-csrf");
    expect(init.credentials).toBe("same-origin");
  });

  it("omits the CSRF header when no session token is held", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { data: { ok: true } }));
    vi.stubGlobal("fetch", fetchMock);
    const client = createApiClient({ baseUrl: "/api/v1" });

    await client.get("/auth/session");

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("surfaces server error envelopes as typed API errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(403, { code: "FORBIDDEN", message: "Permission is required" }),
      ),
    );
    const client = createApiClient({ baseUrl: "/api/v1" });

    await expect(client.post("/admin/users")).rejects.toMatchObject({
      code: "FORBIDDEN",
      message: "Permission is required",
      retryable: false,
    });
  });

  it("keeps step-up failures distinguishable from other rejections", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(401, { code: "STEP_UP_REQUIRED", message: "Re-authentication required" }),
      ),
    );
    const client = createApiClient({ baseUrl: "/api/v1" });

    await expect(client.post("/quarantine/x/release")).rejects.toMatchObject({
      code: "STEP_UP_REQUIRED",
      retryable: false,
    });
  });

  it("asks for a manual redirect when the caller expects a navigation", async () => {
    const fetchMock = vi.fn(async () => ({
      type: "opaqueredirect",
      status: 0,
      ok: false,
      json: async () => null,
    }));
    vi.stubGlobal("fetch", fetchMock);
    const client = createApiClient({ baseUrl: "/api/v1" });

    await expect(
      client.post("/auth/login", undefined, { redirect: "manual" }),
    ).rejects.toMatchObject({ code: "AUTH_REDIRECT" });

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.redirect).toBe("manual");
  });
});

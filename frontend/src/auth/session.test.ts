import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clearCsrfToken, getCsrfToken, setCsrfToken } from "./csrf";
import {
  beginLogin,
  beginStepUp,
  canImpersonate,
  endImpersonation,
  exchangeLogin,
  isStepUpRequired,
  loadSession,
  logout,
  startImpersonation,
  type Session,
} from "./session";

function jsonResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 401 ? "Unauthorized" : "Response",
    json: async () => body,
  };
}

function redirectResponse() {
  return { type: "opaqueredirect", status: 0, json: async () => null };
}

function stubLocation() {
  const assign = vi.fn();
  Object.defineProperty(window, "location", {
    value: { assign, origin: "http://localhost", search: "", pathname: "/quarantine" },
    writable: true,
    configurable: true,
  });
  return assign;
}

function sessionEnvelope(csrfToken?: string) {
  return {
    data: {
      authenticated: true,
      userId: "user-1",
      email: "admin@example.test",
      roles: ["customer_admin"],
      permissions: ["audit:view", "admin:users:manage"],
      customerId: "customer-a",
      expiresAt: "2099-01-01T00:00:00Z",
      stepUpActive: true,
      ...(csrfToken ? { csrfToken } : {}),
    },
  };
}

describe("browser session boundary", () => {
  beforeEach(() => {
    clearCsrfToken();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("loadSession retains the session CSRF token in memory", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(200, sessionEnvelope("csrf-from-session"))),
    );

    const session = await loadSession();

    expect(session?.userId).toBe("user-1");
    expect(getCsrfToken()).toBe("csrf-from-session");
  });

  it("loadSession returns null and drops the CSRF token when unauthenticated", async () => {
    setCsrfToken("stale-token");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(401, { code: "UNAUTHENTICATED", message: "no session" })),
    );

    const session = await loadSession();

    expect(session).toBeNull();
    expect(getCsrfToken()).toBeNull();
  });

  it("exchangeLogin POSTs the boundary identity and keeps a sanitized target", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, sessionEnvelope("csrf-login")));
    vi.stubGlobal("fetch", fetchMock);

    const target = await exchangeLogin("//evil.example");

    expect(target).toBe("/");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/auth/login");
    expect(init.method).toBe("POST");
    expect(getCsrfToken()).toBe("csrf-login");
  });

  it("exchangeLogin preserves a same-origin return path", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(200, sessionEnvelope("csrf-login"))),
    );

    await expect(exchangeLogin("/audit-log")).resolves.toBe("/audit-log");
  });

  it("beginLogin navigates straight to the target once the session exists", async () => {
    const assign = stubLocation();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(200, sessionEnvelope("csrf-login"))),
    );

    await beginLogin("/audit-log");

    expect(assign).toHaveBeenCalledWith("/audit-log");
    expect(getCsrfToken()).toBe("csrf-login");
  });

  it("beginLogin falls back to a full-page login entry when the POST is a redirect", async () => {
    const assign = stubLocation();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => redirectResponse()),
    );

    await beginLogin("https://evil.example");

    expect(assign).toHaveBeenCalledWith("/api/v1/auth/login?return_to=%2F");
  });

  it("beginStepUp starts re-authentication and returns to the current page", async () => {
    const assign = stubLocation();

    beginStepUp();

    expect(assign).toHaveBeenCalledWith("/api/v1/auth/reauth?return_to=%2Fquarantine");
  });

  it("isStepUpRequired recognizes only the step-up error code", () => {
    expect(isStepUpRequired({ code: "STEP_UP_REQUIRED", message: "re-auth" })).toBe(true);
    expect(isStepUpRequired({ code: "FORBIDDEN", message: "denied" })).toBe(false);
    expect(isStepUpRequired(new Error("nope"))).toBe(false);
  });

  it("logout clears the CSRF token even when the request fails", async () => {
    const assign = stubLocation();
    setCsrfToken("csrf-logout");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(503, { code: "UNAVAILABLE", message: "down" })),
    );

    await expect(logout()).rejects.toBeTruthy();

    expect(getCsrfToken()).toBeNull();
    expect(assign).toHaveBeenCalledWith("/login");
  });

  it("logout continues with RP-initiated IdP logout when the IdP publishes one", async () => {
    const assign = stubLocation();
    setCsrfToken("csrf-logout");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(200, {
          data: { authenticated: false, idpLogoutUrl: "http://idp.example/logout" },
        }),
      ),
    );

    await logout();

    expect(assign).toHaveBeenCalledWith("http://idp.example/logout");
  });

  it("logout ignores a non-HTTP IdP logout destination", async () => {
    const assign = stubLocation();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(200, { data: { authenticated: false, idpLogoutUrl: "javascript:alert(1)" } }),
      ),
    );

    await logout();

    expect(assign).toHaveBeenCalledWith("/login");
  });

  it("startImpersonation POSTs the entered customer and the mandatory reason", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        data: {
          id: "impersonation-1",
          customerId: "customer-a",
          customerDisplayName: "Acme Corporation",
          reason: "investigating a report",
          startedAt: "2026-09-29T00:00:00Z",
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await startImpersonation("customer-a", "investigating a report");

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/impersonations");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({
      customerId: "customer-a",
      reason: "investigating a report",
    });
  });

  it("endImpersonation POSTs the idempotent end route", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { data: { ended: true } }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(endImpersonation()).resolves.toEqual({ ended: true });

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/impersonations/end");
    expect(init.method).toBe("POST");
  });

  it("canImpersonate derives from permission claims, not role names", () => {
    const base: Session = {
      authenticated: true,
      userId: "user-1",
      email: "admin@example.test",
      roles: ["system_admin"],
      customerId: "customer-a",
      expiresAt: "2099-01-01T00:00:00Z",
    };

    expect(canImpersonate(null)).toBe(false);
    expect(canImpersonate({ ...base, permissions: ["admin:impersonate"] })).toBe(true);
    expect(canImpersonate({ ...base, permissions: ["audit:view"] })).toBe(false);
    expect(canImpersonate({ ...base })).toBe(false);
  });
});

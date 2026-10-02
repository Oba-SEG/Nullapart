import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { Customers } from "../pages/Customers";
import { verifySecureSession } from "./content";

const apiSources = import.meta.glob("../api/*.ts", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const customerRow = {
  id: "customer-1",
  display_name: "Acme Corporation",
  internal_key: 42,
  lifecycle: "active",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
  domain_count: 1,
};

const adminSession = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  permissions: ["admin:customers:view", "admin:customers:manage"],
  customerId: null,
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
};

function ok(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    statusText: "OK",
    json: async () => body,
  };
}

function stubFetch(options: { session: unknown; customers?: unknown[] }) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: options.session });
    }
    if (url.includes("/admin/customers")) {
      return ok({ data: { customers: options.customers ?? [] } });
    }
    throw new Error(`unexpected fetch ${method} ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderAt(entry: string) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/customers",
      component: Customers,
    }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [entry] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

function storageKeys(): string[] {
  const keys: string[] = [];
  for (const storage of [localStorage, sessionStorage]) {
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key !== null) {
        keys.push(key);
      }
    }
  }
  return keys;
}

describe("verifySecureSession", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("returns true when browser storage holds no token-ish keys", () => {
    localStorage.clear();
    sessionStorage.clear();
    expect(verifySecureSession()).toBe(true);
  });

  it("returns false when an access token key is planted in localStorage", () => {
    localStorage.setItem("access_token", "secret-value");
    expect(verifySecureSession()).toBe(false);
  });

  it("returns false when a refresh token key is planted in sessionStorage", () => {
    sessionStorage.setItem("refresh_token", "secret-value");
    expect(verifySecureSession()).toBe(false);
  });

  it("returns false for jwt and auth key shapes", () => {
    localStorage.setItem("session.jwt", "secret-value");
    expect(verifySecureSession()).toBe(false);
    localStorage.clear();
    sessionStorage.setItem("authToken", "secret-value");
    expect(verifySecureSession()).toBe(false);
  });
});

describe("Customers page session model", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("performs authenticated API calls without writing any browser storage", async () => {
    const fetchMock = stubFetch({ session: adminSession, customers: [customerRow] });
    const { container } = renderAt("/customers");

    await screen.findByRole("link", { name: "Acme Corporation" });

    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/auth/session"))).toBe(
      true,
    );
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          String(input).includes("/admin/customers") && (init?.method ?? "GET") === "GET",
      ),
    ).toBe(true);

    expect(container.textContent).toContain("Acme Corporation");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(
      storageKeys().filter((key) => /token|session|bearer|jwt|refresh|auth/i.test(key)),
    ).toEqual([]);
    expect(verifySecureSession()).toBe(true);
  });
});

describe("API client sources never touch browser storage", () => {
  it("omits localStorage, sessionStorage and indexedDB identifiers from frontend/src/api", () => {
    const files = Object.keys(apiSources).sort();
    expect(files.some((file) => file.endsWith("/client.ts"))).toBe(true);
    expect(files.length).toBeGreaterThan(0);

    const needles = ["localStorage", "sessionStorage", "indexedDB"];
    for (const [file, source] of Object.entries(apiSources)) {
      for (const needle of needles) {
        expect(source, `${file} must not contain the identifier ${needle}`).not.toContain(needle);
      }
    }
  });
});

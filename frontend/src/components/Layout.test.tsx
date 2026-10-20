import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { Layout } from "./Layout";
import type { Session } from "../auth/session";

const NAV_PATHS = [
  "/console",
  "/operations",
  "/scanner-operations",
  "/domain-security",
  "/outbound-intelligence",
  "/messages",
  "/quarantine",
  "/customers",
  "/deep-ai",
  "/connectors-remediation",
  "/audit-log",
  "/policies",
  "/models",
  "/admin-users",
  "/roles",
  "/settings",
];

const systemSession: Session = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  tier: "system",
  permissions: [
    "operations:view",
    "scanner:operations:view",
    "domain-security:view",
    "outbound-intelligence:view",
    "trace:view",
    "quarantine:view",
    "admin:customers:view",
    "deep-ai:view",
    "connectors:view",
    "audit:view",
    "policies:view",
    "models:view",
    "admin:users:manage",
    "admin:impersonate",
  ],
  customerId: null,
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
};

const tenantSession: Session = {
  ...systemSession,
  userId: "actor-9",
  email: "tenant-admin@example.test",
  roles: ["customer_admin"],
  tier: "customer",
  customerId: "customer-acme",
  permissions: [
    "domain-security:view",
    "trace:view",
    "quarantine:view",
    "admin:customers:view",
    "audit:view",
    "policies:view",
    "admin:users:manage",
  ],
};

function stubSession(session: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => ({ data: session }),
    })),
  );
}

function renderLayout() {
  const rootRoute = createRootRoute({ component: () => <Layout /> });
  const child = createRoute({
    getParentRoute: () => rootRoute,
    path: "/console",
    component: () => null,
  });
  const withChildren = NAV_PATHS.filter((path) => path !== "/console").map((path) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => null }),
  );
  const router = createRouter({
    routeTree: rootRoute.addChildren([child, ...withChildren]),
    history: createMemoryHistory({ initialEntries: ["/console"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

function renderPublicLayout() {
  const rootRoute = createRootRoute({ component: () => <Layout /> });
  const child = createRoute({
    getParentRoute: () => rootRoute,
    path: "/",
    component: () => <p>Public landing content</p>,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([child]),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

beforeAll(() => {
  // The shell keeps the active row in view; jsdom does not implement it.
  Element.prototype.scrollIntoView = () => {};
});

beforeEach(() => {
  // The shell watches the nav for overflow; jsdom implements neither.
  class Observer {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  vi.stubGlobal("ResizeObserver", Observer);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Layout", () => {
  it("does not start an authenticated-session request for the public landing", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    renderPublicLayout();

    expect(await screen.findByText("Public landing content")).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("labels the shell from the tier the server published", async () => {
    stubSession(tenantSession);
    renderLayout();

    expect(await screen.findByText("Nullapart Customer console")).toBeTruthy();
    expect(screen.getByText("Customer administrator")).toBeTruthy();
    expect(screen.getByText("Customer control")).toBeTruthy();
    expect(screen.getByText("Your customer · customer-acme")).toBeTruthy();
  });

  it("keeps platform operations out of the tenant sidebar", async () => {
    stubSession(tenantSession);
    renderLayout();

    // Wait for the tenant shell to actually resolve before asserting absence.
    expect(await screen.findByText("Your organisation")).toBeTruthy();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(screen.getAllByText("Overview").length).toBeGreaterThan(0);
    expect(screen.getByText("Your mail")).toBeTruthy();
    expect(screen.getByText("Your customer")).toBeTruthy();
    expect(screen.getByText("Your administrators")).toBeTruthy();
    expect(screen.getByText("Your roles")).toBeTruthy();
    expect(screen.getByText("Your settings")).toBeTruthy();

    expect(screen.queryByText("Runtime status")).toBeNull();
    expect(screen.queryByText("Scanner nodes")).toBeNull();
    expect(screen.queryByText("Models")).toBeNull();
    expect(screen.queryByText("Deep AI")).toBeNull();
    expect(screen.queryByText("Connectors")).toBeNull();
    expect(screen.queryByText("Customers")).toBeNull();
    expect(screen.queryByText("Administration")).toBeNull();
    expect(nav.textContent).not.toContain("Platform settings");
  });

  it("leaves the system console unchanged", async () => {
    stubSession(systemSession);
    renderLayout();

    expect(await screen.findByText("Nullapart System console")).toBeTruthy();
    expect(screen.getByText("System overview")).toBeTruthy();
    expect(screen.getByText("Runtime status")).toBeTruthy();
    expect(screen.getByText("Scanner nodes")).toBeTruthy();
    expect(screen.getByText("Models")).toBeTruthy();
    expect(screen.getByText("Deep AI")).toBeTruthy();
    expect(screen.getByText("Connectors")).toBeTruthy();
    expect(screen.getByText("Customers")).toBeTruthy();
    expect(screen.getByText("Administration")).toBeTruthy();
    expect(screen.getByText("Admin users")).toBeTruthy();
    expect(screen.getByText("Platform settings")).toBeTruthy();

    expect(screen.queryByText("Your organisation")).toBeNull();
    expect(screen.queryByText("Your administrators")).toBeNull();
  });

  it("does not claim system control for a session with no published tier", async () => {
    stubSession({ ...systemSession, tier: undefined });
    renderLayout();

    expect(await screen.findByText("Server-managed session")).toBeTruthy();
    expect(screen.getByText("Nullapart Security Desk")).toBeTruthy();
    expect(screen.queryByText("System overview")).toBeNull();
    expect(screen.queryByText("Administration")).toBeNull();
  });
});

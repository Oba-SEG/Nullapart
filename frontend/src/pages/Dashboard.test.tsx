import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Dashboard } from "./Dashboard";
import type { Session } from "../auth/session";

const systemSession: Session = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  tier: "system",
  permissions: [
    "audit:view",
    "quarantine:view",
    "operations:view",
    "scanner:operations:view",
    "domain-security:view",
    "policies:view",
  ],
  customerId: null,
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
};

// Exactly the server-published shape for a Customer Administrator: their own
// tenant surfaces, and no platform runtime, scanner or model read.
const tenantSession: Session = {
  ...systemSession,
  userId: "actor-9",
  email: "tenant-admin@example.test",
  roles: ["customer_admin"],
  tier: "customer",
  customerId: "customer-acme",
  permissions: [
    "audit:view",
    "quarantine:view",
    "domain-security:view",
    "domain-security:manage",
    "policies:view",
    "policies:manage",
    "admin:customers:view",
  ],
};

const healthyRuntime = {
  deployment_id: "CZA-1",
  config: { db_revision: 12 },
  outbox: { unpublished_count: 0, oldest_unpublished_age_seconds: null },
  dead_letters: { count: 0 },
  scanner: { total: 4, active: 4, draining: 0, offline: 0 },
};

const degradedRuntime = {
  deployment_id: "CZA-1",
  config: { db_revision: 12 },
  outbox: { unpublished_count: 5, oldest_unpublished_age_seconds: 420 },
  dead_letters: { count: 3 },
  scanner: { total: 4, active: 3, draining: 0, offline: 1 },
};

const cleanDomainSecurity = {
  deployment_id: "CZA-1",
  summary: {
    domains_total: 2,
    verified_domains: 2,
    messages_30d: 1240,
    open_notifications: 0,
  },
};

const findingsDomainSecurity = {
  deployment_id: "CZA-1",
  summary: {
    domains_total: 3,
    verified_domains: 2,
    messages_30d: 88,
    open_notifications: 2,
  },
};

function ok(body: unknown) {
  return { ok: true, status: 200, statusText: "OK", json: async () => body };
}

function stubFetch(options: {
  session?: typeof systemSession;
  runtime: unknown;
  quarantine: unknown[];
  nodeStatus: string;
  domainSecurity: unknown;
}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/auth/session")) return ok({ data: options.session ?? systemSession });
    if (url.includes("/operations/runtime")) return ok({ data: options.runtime });
    if (url.includes("/quarantine")) return ok({ data: options.quarantine });
    if (url.includes("/audit/events")) return ok({ data: { events: [] } });
    if (url.includes("/domain-security")) return ok({ data: options.domainSecurity });
    if (url.includes("/scanner-operations")) {
      return ok({ data: { node: { node_id: "scanner-1", status: options.nodeStatus } } });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderDashboard() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const paths = [
    "/",
    "/quarantine",
    "/operations",
    "/scanner-operations",
    "/domain-security",
    "/customers",
    "/policies",
    "/audit-log",
  ];
  const routeTree = rootRoute.addChildren(
    paths.map((path) =>
      createRoute({
        getParentRoute: () => rootRoute,
        path,
        component: path === "/" ? Dashboard : () => null,
      }),
    ),
  );
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Dashboard", () => {
  it("surfaces an ordered attention queue when queues are backed up", async () => {
    stubFetch({
      runtime: degradedRuntime,
      quarantine: [{ tenant_message_id: "tm-1" }],
      nodeStatus: "draining",
      domainSecurity: findingsDomainSecurity,
    });
    renderDashboard();

    expect(await screen.findByRole("region", { name: "Needs attention" })).toBeTruthy();
    expect(screen.getByText("3 dead letters need review")).toBeTruthy();
    expect(screen.getByText("Publication queue is overdue")).toBeTruthy();
    expect(screen.getByText("1 held message waiting for a decision")).toBeTruthy();
    expect(screen.getByText("2 domain security findings open")).toBeTruthy();
    expect(screen.getByText("1 domain still unverified")).toBeTruthy();
    expect(screen.getByText("Scanner node is draining")).toBeTruthy();
  });

  it("reports a clear queue when nothing needs operator attention", async () => {
    stubFetch({
      runtime: healthyRuntime,
      quarantine: [],
      nodeStatus: "healthy",
      domainSecurity: cleanDomainSecurity,
    });
    renderDashboard();

    expect(await screen.findByText(/Nothing requires operator attention/)).toBeTruthy();
    expect(screen.getByText("Quarantined now")).toBeTruthy();
    expect(screen.getByText("Open quarantine")).toBeTruthy();
    expect(screen.getByText("Scanner nodes active")).toBeTruthy();
  });

  it("shows a tenant only the signals their own tenant publishes", async () => {
    const fetchMock = stubFetch({
      session: tenantSession,
      runtime: degradedRuntime,
      quarantine: [{ tenant_message_id: "tm-7" }],
      nodeStatus: "offline",
      domainSecurity: findingsDomainSecurity,
    });
    renderDashboard();

    expect(await screen.findByText("1 held message waiting for a decision")).toBeTruthy();
    expect(screen.getByText("Security overview")).toBeTruthy();
    expect(screen.getByText("Your customer")).toBeTruthy();
    expect(screen.getByText("Open domain findings")).toBeTruthy();
    expect(screen.getByText("Open your organisation")).toBeTruthy();
    expect(screen.getByText("Manage your mail controls")).toBeTruthy();

    // Platform runtime health is not a tenant signal: the reads are never made,
    // so the dashboard cannot show "Unavailable" for data the tenant may not see.
    expect(screen.queryByText("Pending publication")).toBeNull();
    expect(screen.queryByText("Dead letters")).toBeNull();
    expect(screen.queryByText("Scanner nodes active")).toBeNull();
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((call) => String(call[0]));
      expect(urls.some((url) => url.includes("/operations/runtime"))).toBe(false);
      expect(urls.some((url) => url.includes("/scanner-operations"))).toBe(false);
    });
  });
});

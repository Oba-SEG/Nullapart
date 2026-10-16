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
import { describe, expect, it, vi } from "vitest";

import { Dashboard } from "./Dashboard";

const session = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  permissions: ["audit:view", "quarantine:view", "operations:view"],
  customerId: null,
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
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

function ok(body: unknown) {
  return { ok: true, status: 200, statusText: "OK", json: async () => body };
}

function stubFetch(options: { runtime: unknown; quarantine: unknown[]; nodeStatus: string }) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/auth/session")) return ok({ data: session });
    if (url.includes("/operations/runtime")) return ok({ data: options.runtime });
    if (url.includes("/quarantine")) return ok({ data: options.quarantine });
    if (url.includes("/audit/events")) return ok({ data: { events: [] } });
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

describe("Dashboard", () => {
  it("surfaces an ordered attention queue when queues are backed up", async () => {
    stubFetch({
      runtime: degradedRuntime,
      quarantine: [{ tenant_message_id: "tm-1" }],
      nodeStatus: "draining",
    });
    renderDashboard();

    expect(await screen.findByRole("region", { name: "Needs attention" })).toBeTruthy();
    expect(screen.getByText("3 dead letters need review")).toBeTruthy();
    expect(screen.getByText("Publication queue is overdue")).toBeTruthy();
    expect(screen.getByText("1 held message waiting for a decision")).toBeTruthy();
    expect(screen.getByText("Scanner node is draining")).toBeTruthy();
  });

  it("reports a clear queue when nothing needs operator attention", async () => {
    stubFetch({ runtime: healthyRuntime, quarantine: [], nodeStatus: "healthy" });
    renderDashboard();

    expect(await screen.findByText(/Nothing requires operator attention/)).toBeTruthy();
    expect(screen.getByText("Quarantined now")).toBeTruthy();
    expect(screen.getByText("Open quarantine")).toBeTruthy();
  });
});

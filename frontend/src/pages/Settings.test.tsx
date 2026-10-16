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
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { Settings } from "./Settings";

const runtime = {
  deployment_id: "local-test",
  config: { db_revision: 191 },
  outbox: { unpublished_count: 0, oldest_unpublished_age_seconds: null },
  dead_letters: { count: 0 },
  scanner: { total: 0, active: 0, draining: 0, offline: 0 },
};

function stubFetch(permissions: string[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/auth/session")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              authenticated: true,
              userId: "actor-1",
              email: "ob1",
              roles: ["system_admin"],
              permissions,
              customerId: null,
              stepUpActive: false,
              expiresAt: "2026-10-17T18:00:00Z",
            },
          }),
        };
      }
      if (url.includes("/operations/runtime")) {
        return { ok: true, status: 200, json: async () => ({ data: runtime }) };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    }),
  );
}

function renderSettings() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({ getParentRoute: () => rootRoute, path: "/settings", component: Settings }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/settings"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("Settings", () => {
  beforeAll(() => {
    vi.stubGlobal("matchMedia", (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));
  });

  beforeEach(() => {
    window.localStorage.clear();
  });

  it("states session facts in words rather than stored keys", async () => {
    stubFetch(["operations:view", "audit:view"]);
    renderSettings();

    // The theme rail shows the label the picker uses, and the runtime signal
    // says what the role can do; neither repeats a wire token back at the
    // operator.
    expect(await screen.findByText("Allowed")).toBeTruthy();
    expect((await screen.findAllByText("Midnight")).length).toBeGreaterThan(0);
    expect(screen.queryByText(/^dark$/)).toBeNull();
    expect(screen.queryByText(/^permitted$/)).toBeNull();
    expect(screen.getByText("System admin")).toBeTruthy();
    expect(screen.getByText("Not verified")).toBeTruthy();
  });

  it("withholds the deployment card when the role cannot see runtime", async () => {
    stubFetch(["audit:view"]);
    renderSettings();

    expect(await screen.findByText("Not available")).toBeTruthy();
    expect(screen.queryByText("Config version")).toBeNull();
  });
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { Settings } from "./Settings";

const runtime = {
  deployment_id: "local-test",
  config: { db_revision: 191 },
  outbox: { unpublished_count: 0, oldest_unpublished_age_seconds: null },
  dead_letters: { count: 0 },
  scanner: { total: 0, active: 0, draining: 0, offline: 0 },
};

const platformFacts = {
  deploymentId: "AFRICA-1",
  deploymentName: "Johannesburg mail serving",
  deploymentRegion: "af-south-1",
  deploymentLifecycle: "active",
  deploymentCreatedAt: "2026-02-25T06:13:20+00:00",
  deploymentRecordAvailable: true,
  identityProvider: "proxy-header",
  identityIssuer: null,
  idleTtlSecs: 3600,
  absoluteTtlSecs: 28800,
  stepUpTtlSecs: 600,
};

/** The server decides who sees platform facts, so the stub mirrors that. */
function stubFetch(permissions: string[], platform: unknown = undefined) {
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
              ...(platform === undefined ? {} : { platform }),
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
    expect((await screen.findAllByText("Light")).length).toBeGreaterThan(0);
    expect(screen.queryByText(/^dark$/)).toBeNull();
    expect(screen.queryByText(/^permitted$/)).toBeNull();
    expect(screen.getByText("System admin")).toBeTruthy();
    expect(screen.getByText("Not verified")).toBeTruthy();
  });

  it("withholds the runtime card when the role cannot see it", async () => {
    stubFetch(["audit:view"]);
    renderSettings();

    // The card is not rendered as an unavailable readout: a session that cannot
    // open the operations service is never told the readout exists.
    await screen.findByText("Signed in as");
    expect(screen.queryByRole("region", { name: "Runtime" })).toBeNull();
    expect(screen.queryByText("Runtime")).toBeNull();
    expect(screen.queryByText("Config version")).toBeNull();
    expect(screen.queryByText(/live runtime detail/)).toBeNull();
  });

  it("reads the platform back in words for a system session", async () => {
    stubFetch(["operations:view"], platformFacts);
    renderSettings();

    const card = await screen.findByRole("region", { name: "Platform" });
    expect(within(card).getByText("Johannesburg mail serving")).toBeTruthy();
    expect(within(card).getByText("In service")).toBeTruthy();
    expect(within(card).getByText("This installation's sign-in boundary")).toBeTruthy();
    // Seconds are what the server enforces; nobody reads a policy as 28800.
    expect(within(card).getByText(/1 hour without activity/)).toBeTruthy();
    expect(within(card).getByText(/8 hours from sign-in/)).toBeTruthy();
    expect(within(card).getByText("10 minutes")).toBeTruthy();
    expect(within(card).queryByText("28800")).toBeNull();
    expect(within(card).queryByText("3600")).toBeNull();
    // The reference is evidence, so it stays on the page beside the name.
    expect(within(card).getByText("AFRICA-1")).toBeTruthy();
    // Each hint term carries its explanation for a screen reader, not only a
    // pointer user.
    expect(within(card).getByText(/How long this sign-in lasts/)).toBeTruthy();
    expect(within(card).getByText(/How this installation proves who you are/)).toBeTruthy();
  });

  it("shows no platform readout to a session the server did not publish it for", async () => {
    stubFetch(["operations:view"], null);
    renderSettings();

    await screen.findByText("Signed in as");
    expect(screen.queryByRole("region", { name: "Platform" })).toBeNull();
    expect(screen.queryByText("Platform facts")).toBeNull();
    expect(screen.queryByText(/what the running platform reports/)).toBeNull();
    // The runtime readout is a separate gate and this session still holds it.
    expect(screen.getByRole("region", { name: "Runtime" })).toBeTruthy();
  });

  it("says the deployment record is unreadable rather than inventing a name", async () => {
    stubFetch(["operations:view"], {
      ...platformFacts,
      deploymentName: null,
      deploymentLifecycle: null,
      deploymentCreatedAt: null,
      deploymentRecordAvailable: false,
    });
    renderSettings();

    const card = await screen.findByRole("region", { name: "Platform" });
    expect(within(card).getByText(/could not be read/)).toBeTruthy();
    expect(within(card).queryByText("Not named in the record")).toBeNull();
    expect(within(card).queryByText("Provisioned")).toBeNull();
    expect(within(card).getByText("AFRICA-1")).toBeTruthy();
  });
});

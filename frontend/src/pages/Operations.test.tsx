import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { Operations } from "./Operations";

function buildSession(roles: string[], permissions: string[]) {
  return {
    authenticated: true,
    userId: "actor-1",
    email: "admin@example.test",
    roles,
    permissions,
    customerId: null,
    expiresAt: "2099-01-01T00:00:00Z",
    csrfToken: "csrf-token",
    impersonation: null,
  };
}

const managerSession = buildSession(["system_admin"], ["operations:view", "operations:manage"]);
const viewerSession = buildSession(["support"], ["operations:view"]);

const baseSnapshot = {
  deployment_id: "dep-1",
  config: {
    db_revision: 12,
    scopes: [
      {
        scope: "system",
        scope_id: "system",
        revision_number: 4,
        published_by: "ops@example.test",
        published_at: "2026-01-05T10:00:00Z",
      },
      {
        scope: "tenant",
        scope_id: "customer-with-a-very-long-identifier",
        revision_number: 7,
        published_by: "admin@example.test",
        published_at: "2026-01-06T10:00:00Z",
      },
    ],
  },
  nodes: [
    {
      id: "mx-1",
      node_type: "mx",
      role: "mta",
      status: "healthy",
      hostname: "mx-1.example.test",
      version: "1.4.0",
      config_revision: 12,
      last_health_check: "2026-01-06T09:59:00Z",
      stale: true,
    },
    {
      id: "scan-1",
      node_type: "scanner",
      role: "scanner",
      status: "draining",
      hostname: null,
      version: "1.4.0",
      config_revision: 11,
      last_health_check: null,
      stale: false,
    },
    {
      id: "core-1",
      node_type: "core",
      role: "mail-core",
      status: "starting",
      hostname: "core-1.example.test",
      version: "1.4.0",
      config_revision: null,
      last_health_check: "2026-01-06T09:58:00Z",
      stale: null,
    },
  ],
  outbox: { unpublished_count: 3, oldest_unpublished_age_seconds: 300 },
  dead_letters: { count: 1 },
  scanner: { total: 4, active: 2, draining: 1, offline: 1 },
  smtp: {
    commissioning: "not_configured",
    detail: "No commissioned SMTP identity is recorded for this deployment.",
  },
};

function ok(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    statusText: "OK",
    json: async () => body,
  };
}

function fail(status: number, body: unknown) {
  return {
    ok: false,
    status,
    statusText: "Error",
    json: async () => body,
  };
}

interface StubOptions {
  session: unknown;
  snapshot?: unknown;
  snapshotError?: { status: number; code: string; message: string };
  refreshResult?: unknown;
  refreshError?: { status: number; code: string; message: string };
}

function stubFetch(options: StubOptions) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: options.session });
    }
    if (method === "POST" && url.endsWith("/operations/refresh")) {
      if (options.refreshError) {
        return fail(options.refreshError.status, {
          code: options.refreshError.code,
          message: options.refreshError.message,
        });
      }
      return ok({ data: options.refreshResult }, 201);
    }
    if (options.snapshotError && url.includes("/operations/runtime")) {
      return fail(options.snapshotError.status, {
        code: options.snapshotError.code,
        message: options.snapshotError.message,
      });
    }
    if (url.includes("/operations/runtime")) {
      return ok({ data: options.snapshot ?? baseSnapshot });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderAt(entry: string) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({ getParentRoute: () => rootRoute, path: "/operations", component: Operations }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [entry] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

function rowFor(text: string): HTMLElement {
  const cell = screen.getByText(text);
  const row = cell.closest("tr");
  if (!row) throw new Error(`no table row found for ${text}`);
  return row;
}

async function openNodeRefresh(user: ReturnType<typeof userEvent.setup>, nodeId: string) {
  await user.click(await screen.findByRole("button", { name: "Refresh" }));
  await user.selectOptions(await screen.findByLabelText("Target"), "node");
  await user.type(screen.getByLabelText("Node id"), nodeId);
}

describe("Operations", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("renders the snapshot summary values", async () => {
    stubFetch({ session: managerSession, snapshot: baseSnapshot });
    renderAt("/operations");

    await screen.findByRole("heading", { name: "Runtime operations" });
    const summary = await screen.findByRole("region", { name: "Runtime summary" });
    expect(within(summary).getByText("DB config revision")).toBeTruthy();
    expect(within(summary).getByText("12")).toBeTruthy();
    expect(within(summary).getByText("3 unpublished · oldest 5m")).toBeTruthy();
    expect(within(summary).getByText("Dead letters")).toBeTruthy();
    expect(within(summary).getByText("1")).toBeTruthy();
    expect(within(summary).getByText("Scanner nodes")).toBeTruthy();
    expect(within(summary).getByText("2/4")).toBeTruthy();
  });

  it("renders stale badges for nodes and unknown freshness as muted", async () => {
    stubFetch({ session: managerSession, snapshot: baseSnapshot });
    renderAt("/operations");

    await screen.findByRole("region", { name: "Nodes" });
    expect(within(rowFor("mx-1")).getByText("stale config")).toBeTruthy();
    expect(within(rowFor("scan-1")).getByText("current")).toBeTruthy();
    expect(within(rowFor("core-1")).getByText("unknown")).toBeTruthy();
    expect(within(rowFor("scan-1")).getByText("never")).toBeTruthy();
  });

  it("renders an honest empty state when no nodes are registered", async () => {
    stubFetch({ session: managerSession, snapshot: { ...baseSnapshot, nodes: [] } });
    renderAt("/operations");

    const nodes = await screen.findByRole("region", { name: "Nodes" });
    expect(within(nodes).queryByRole("table")).toBeNull();
    expect(within(nodes).getByText(/No nodes are registered/)).toBeTruthy();
    expect(screen.queryByText("mx-1")).toBeNull();
  });

  it("hides the refresh action without operations:manage", async () => {
    stubFetch({ session: viewerSession, snapshot: baseSnapshot });
    renderAt("/operations");

    await screen.findByRole("heading", { name: "Runtime operations" });
    expect(screen.queryByRole("button", { name: "Refresh" })).toBeNull();
    expect(screen.getByRole("button", { name: "Reload" })).toBeTruthy();
  });

  it("posts a node refresh with an idempotency key and reloads the snapshot", async () => {
    const fetchMock = stubFetch({
      session: managerSession,
      snapshot: baseSnapshot,
      refreshResult: {
        requested_at: "2026-01-06T10:00:00Z",
        target: "node",
        scope_id: "mx-1",
      },
    });
    const user = userEvent.setup();
    renderAt("/operations");
    await screen.findByRole("heading", { name: "Runtime operations" });
    const initialReads = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes("/operations/runtime"),
    ).length;

    await openNodeRefresh(user, "mx-1");
    await user.click(screen.getByRole("button", { name: "Confirm refresh" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith("/operations/refresh") && init?.method === "POST",
      );
      expect(call).toBeTruthy();
      const headers = new Headers(call?.[1]?.headers);
      expect(headers.get("X-Idempotency-Key")).toBeTruthy();
      const body = JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>;
      expect(body).toEqual({ target: "node", node_id: "mx-1" });
    });

    expect(await screen.findByText(/Refresh requested for mx-1/)).toBeTruthy();
    await waitFor(() => {
      const reads = fetchMock.mock.calls.filter(([input]) =>
        String(input).includes("/operations/runtime"),
      ).length;
      expect(reads).toBeGreaterThan(initialReads);
    });
  });

  it("rejects an invalid node id inline without posting", async () => {
    const fetchMock = stubFetch({ session: managerSession, snapshot: baseSnapshot });
    const user = userEvent.setup();
    renderAt("/operations");
    await screen.findByRole("heading", { name: "Runtime operations" });

    await openNodeRefresh(user, "not a node");
    await user.click(screen.getByRole("button", { name: "Confirm refresh" }));

    const error = await screen.findByRole("alert");
    expect(error).toHaveTextContent(/letters, digits, dot, underscore or hyphen/);
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
    expect(screen.getByRole("button", { name: "Confirm refresh" })).toBeTruthy();
  });

  it("surfaces an unknown node as Node was not found", async () => {
    stubFetch({
      session: managerSession,
      snapshot: baseSnapshot,
      refreshError: { status: 404, code: "NOT_FOUND", message: "Node does not exist" },
    });
    const user = userEvent.setup();
    renderAt("/operations");
    await screen.findByRole("heading", { name: "Runtime operations" });

    await openNodeRefresh(user, "ghost-1");
    await user.click(screen.getByRole("button", { name: "Confirm refresh" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Node was not found");
  });

  it("offers step-up re-authentication when the refresh requires it", async () => {
    stubFetch({
      session: managerSession,
      snapshot: baseSnapshot,
      refreshError: {
        status: 403,
        code: "STEP_UP_REQUIRED",
        message: "Step-up authentication is required",
      },
    });
    const user = userEvent.setup();
    renderAt("/operations");
    await screen.findByRole("heading", { name: "Runtime operations" });

    await openNodeRefresh(user, "mx-1");
    await user.click(screen.getByRole("button", { name: "Confirm refresh" }));

    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
    expect(screen.getByText("Re-authentication is required for this action.")).toBeTruthy();
  });
});

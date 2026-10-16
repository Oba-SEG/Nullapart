import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { AuditLog } from "./AuditLog";

const auditEvent = {
  id: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
  created_at: "2026-09-29T10:00:00Z",
  actor_login: "admin@example.test",
  actor_roles: ["customer_admin"],
  impersonated_subject: null,
  impersonated_customer: null,
  customer_id: "customer-a",
  action: "quarantine.release",
  resource_type: "quarantine_case",
  resource_id: "case-1",
  result: "success",
  reason: "false positive",
  source_ip: null,
  trace_id: "trace-1",
};

function stubFetch() {
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
              email: "admin@example.test",
              roles: ["customer_admin"],
              permissions: ["audit:view", "audit:export"],
              customerId: "customer-a",
              expiresAt: "2026-09-29T18:00:00Z",
            },
          }),
        };
      }
      if (url.includes("/audit/checkpoint-status")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              state: "not_configured",
              last_checkpoint_at: null,
              covers_events_through: null,
              checkpoint_sequence: null,
              event_count: null,
              root_hash: null,
              signer_key_id: null,
              archive_uri: null,
            },
          }),
        };
      }
      if (url.includes("/audit/events/")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              ...auditEvent,
              session_id: "session-1",
              details: [
                { key: "release_reason", value: "false positive" },
                { key: "session_token", value: "[redacted]" },
              ],
            },
          }),
        };
      }
      if (url.includes("/audit/events")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: { events: [auditEvent], next_cursor: null } }),
        };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    }),
  );
}

function renderInRouter() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/audit-log",
      component: AuditLog,
    }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/audit-log"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("AuditLog", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("renders scoped audit rows and offers a permission-gated CSV export", async () => {
    stubFetch();
    renderInRouter();

    // The row reads as an action in words; the wire name is evidence and stays
    // in the detail drawer rather than repeating under every row.
    expect(await screen.findByText("Quarantine release")).toBeTruthy();
    expect(screen.queryByText("quarantine.release")).toBeNull();
    expect(screen.getByText("admin@example.test")).toBeTruthy();
    expect(screen.getByText("Customer admin")).toBeTruthy();
    expect(screen.getByText("false positive")).toBeTruthy();
    const exportButton = screen.getByRole("button", { name: /export csv/i });
    await waitFor(() => expect(exportButton).toBeEnabled());
    expect(screen.getAllByText("Not configured").length).toBeGreaterThan(0);
    // Each filter says what it narrows, so the row is usable without a
    // placeholder that disappears the moment anything is typed.
    expect(screen.getByLabelText("Actor login")).toBeTruthy();
    expect(screen.getByLabelText("Action")).toBeTruthy();
    expect(screen.getByLabelText("Result")).toBeTruthy();
  });

  it("opens a redacted key/value detail drawer instead of raw JSON", async () => {
    stubFetch();
    renderInRouter();

    fireEvent.click(await screen.findByRole("button", { name: /2026/ }));

    expect(await screen.findByText("release_reason")).toBeTruthy();
    expect(screen.getByText("session_token")).toBeTruthy();
    expect(screen.getByText("[redacted]")).toBeTruthy();
    expect(screen.getByText("quarantine.release")).toBeTruthy();
  });
});

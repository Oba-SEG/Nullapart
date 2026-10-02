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

import { Quarantine } from "./Quarantine";

function renderInRouter() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/quarantine",
      component: Quarantine,
    }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/quarantine/$tenant_message_id",
      component: () => null,
    }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/quarantine"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("Quarantine", () => {
  it("renders safe finding summaries from the typed API projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: [
            {
              tenant_message_id: "tenant-message-1",
              transaction_id: "transaction-1",
              sender: "sender@example.test",
              recipient_count: 1,
              reason_code: "QUARANTINE_MALWARE",
              quarantined_at: "2026-01-01T00:00:00Z",
              release_allowed: false,
              findings: [
                {
                  id: "finding-1",
                  category: "malware",
                  severity: "high",
                  description: "Static malware rule matched",
                  created_at: "2026-01-01T00:00:00Z",
                },
              ],
            },
          ],
        }),
      }),
    );
    renderInRouter();

    expect(await screen.findByText("sender@example.test")).toBeTruthy();
    expect(screen.getByText("high")).toBeTruthy();
    expect(screen.getByText("Category: malware")).toBeTruthy();
    expect(screen.getByText("Finding: Static malware rule matched")).toBeTruthy();
    expect(screen.getByText(/never rendered here/i)).toBeTruthy();
    expect(screen.getByRole("link", { name: /tenant-message-1/ })).toHaveProperty(
      "href",
      expect.stringContaining("/quarantine/tenant-message-1"),
    );
  });
});

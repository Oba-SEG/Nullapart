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
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("renders safe finding summaries from the typed API", async () => {
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
    expect(screen.getByText("High", { selector: ".status-pill" })).toBeTruthy();
    expect(screen.getByText("Category: Malware")).toBeTruthy();
    expect(screen.getByText("Finding: Static malware rule matched")).toBeTruthy();
    expect(screen.getByText(/never shown here/i)).toBeTruthy();
    expect(screen.getByRole("link", { name: /tenant-message-1/ })).toHaveProperty(
      "href",
      expect.stringContaining("/quarantine/tenant-message-1"),
    );
  });

  it("releases selected eligible cases in one audited batch", async () => {
    const quarantineCase = (id: string, releaseAllowed: boolean) => ({
      tenant_message_id: id,
      transaction_id: `transaction-${id}`,
      sender: `sender@${id}.test`,
      recipient_count: 1,
      reason_code: "QUARANTINE_POLICY",
      quarantined_at: "2026-01-01T00:00:00Z",
      released_at: null,
      release_allowed: releaseAllowed,
      findings: [],
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "GET" && url.includes("/quarantine")) {
        return {
          ok: true,
          status: 200,
          statusText: "OK",
          json: async () => ({
            data: [quarantineCase("batch-1", true), quarantineCase("batch-2", true)],
          }),
        };
      }
      if (method === "POST" && url.includes("/release")) {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({ data: {} }) };
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    renderInRouter();

    fireEvent.click(
      await screen.findByRole("checkbox", { name: "Select all ready-to-release messages" }),
    );
    expect(screen.getByText("2 messages ready to release")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Release selected" }));
    fireEvent.change(screen.getByPlaceholderText("Why are you releasing these messages?"), {
      target: { value: "Verified benign attachments with the customer" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Release 2 selected messages" }));

    await waitFor(() => {
      const releaseCalls = fetchMock.mock.calls.filter(
        ([input, init]) =>
          String(input).includes("/release") &&
          String(init?.method ?? "GET").toUpperCase() === "POST",
      );
      expect(releaseCalls).toHaveLength(2);
      const releasedIds = releaseCalls.map(([input]) => String(input));
      expect(releasedIds.some((url) => url.includes("batch-1"))).toBe(true);
      expect(releasedIds.some((url) => url.includes("batch-2"))).toBe(true);
    });
  });
});

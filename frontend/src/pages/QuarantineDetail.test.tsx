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

import { QuarantineDetail } from "./QuarantineDetail";

function renderDetail() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/quarantine/$tenant_message_id",
      component: QuarantineDetail,
    }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/quarantine/tenant-message-1"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("QuarantineDetail", () => {
  it("renders retention, audit and capability labels without engine exposure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            tenant_message_id: "tenant-message-1",
            transaction_id: "transaction-1",
            sender: "sender@example.test",
            recipient_count: 2,
            reason_code: "QUARANTINE_MALWARE",
            quarantined_at: "2026-01-01T00:00:00Z",
            released_at: null,
            release_allowed: false,
            released_by: null,
            release_reason: null,
            retention: {
              retention_class: "standard",
              artifact_created_at: "2026-01-01T00:00:00Z",
              quarantined_at: "2026-01-01T00:00:00Z",
              released_at: null,
            },
            scanner_results: [
              {
                capability: "Attachment content analysis",
                status: "complete",
                required: true,
                duration_ms: 42,
                completed_at: "2026-01-01T00:00:01Z",
              },
            ],
            findings: [
              {
                id: "finding-1",
                category: "malware",
                severity: "high",
                description: "Static malware rule matched",
                created_at: "2026-01-01T00:00:00Z",
              },
            ],
            audit: [
              {
                action: "quarantine_hold",
                actor_login: "security-admin@example.test",
                result: "success",
                created_at: "2026-01-01T00:00:02Z",
              },
            ],
          },
        }),
      }),
    );
    renderDetail();

    expect(await screen.findByText("Attachment content analysis")).toBeTruthy();
    expect(screen.getByText(/security-admin@example\.test/)).toBeTruthy();
    expect(screen.getByText("standard")).toBeTruthy();
    expect(screen.getByText("High: Malware")).toBeTruthy();
    expect(screen.getByText(/Engine names, versions, endpoints/i)).toBeTruthy();
    const body = document.body.textContent ?? "";
    expect(body).not.toContain("attachment-analysis");
    expect(body).not.toContain("clamav");
    expect(body).not.toContain("raw_mime");
  });

  it("shows an explicit unavailable state when the case cannot be loaded", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({
          error: "not_found",
          message: "Quarantine case not found",
        }),
      }),
    );
    renderDetail();

    expect(await screen.findByRole("alert")).toHaveTextContent(/not found|unavailable/i);
  });
});

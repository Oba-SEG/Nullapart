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

const tenantSession = {
  authenticated: true,
  userId: "actor-2",
  email: "tenant-admin@example.test",
  roles: ["customer_admin"],
  permissions: ["quarantine:view", "quarantine:release"],
  customerId: "CZA-1",
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
  tier: "customer",
};

/**
 * Serves one detail answer to a tenant seat. The rows carry the platform's run
 * telemetry as well, which a real customer answer would not: if the console ever
 * renders that instead of the outcome, this fixture shows it.
 */
function stubTenantDetail(scannerResults: unknown[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const body = String(input).includes("/auth/session")
        ? { data: tenantSession }
        : {
            data: {
              tenant_message_id: "tenant-message-1",
              transaction_id: "transaction-1",
              sender: "newsletter@partner.example",
              recipient_count: 2,
              reason_code: "QUARANTINE_MALWARE",
              quarantined_at: "2026-01-01T00:00:00Z",
              released_at: null,
              release_allowed: true,
              findings: [],
              audit: [],
              scanner_results: scannerResults,
            },
          };
      return { ok: true, status: 200, json: async () => body };
    }),
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

  /**
   * A tenant's check table reads as what the platform concluded about their own
   * message. The run report behind a check (its status token, whether the fabric
   * required it, how long it took) is not on a customer answer, so an answer that
   * still carries it must not reach the page either.
   */
  it("names each check outcome for a tenant and hides the run report", async () => {
    stubTenantDetail([
      {
        capability: "Malware analysis",
        outcome: "clear",
        status: "clean",
        required: true,
        duration_ms: 41,
        completed_at: "2026-01-01T00:00:01Z",
      },
      {
        capability: "URL reputation",
        outcome: "threat_found",
        completed_at: "2026-01-01T00:00:02Z",
      },
      {
        capability: "Document safety",
        outcome: "no_answer",
        completed_at: "2026-01-01T00:00:03Z",
      },
    ]);
    renderDetail();

    expect(await screen.findByText("No issue found")).toBeTruthy();
    expect(screen.getByText("Threat found")).toBeTruthy();
    expect(screen.getByText("No answer recorded")).toBeTruthy();

    expect(screen.queryByText("Requirement")).toBeNull();
    expect(screen.queryByText("Duration")).toBeNull();
    expect(screen.queryByText("41 ms")).toBeNull();
    const body = document.body.textContent ?? "";
    for (const withheld of ["clean", "threat_found", "no_answer"]) {
      expect(body, `tenant check table carried ${withheld}`).not.toContain(withheld);
    }
  });
});

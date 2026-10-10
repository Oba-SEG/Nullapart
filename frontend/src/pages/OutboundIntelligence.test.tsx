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
import { describe, expect, it, vi } from "vitest";

import { OutboundIntelligence } from "./OutboundIntelligence";

const managerSession = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  permissions: ["outbound-intelligence:view", "outbound-intelligence:manage"],
  customerId: "CZA-1",
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
};

const baseSnapshot = {
  deployment_id: "LOCAL-TEST",
  generated_at: "2026-01-06T10:00:00Z",
  summary: {
    messages_1h: 42,
    recipients_1h: 120,
    unique_recipients_1h: 80,
    active_senders_1h: 2,
    campaigns_observed: 1,
    approved_bulk_senders: 1,
    open_security_events: 1,
    critical_security_events: 1,
  },
  approved_senders: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      sender_address: "bulk@example.test",
      sending_domain: "example.test",
      source_kind: "smtp_mta",
      source_id: "mx-1",
      source_ip: "192.0.2.10",
      max_messages_per_minute: 20,
      max_messages_per_hour: 500,
      max_recipients_per_message: 100,
      max_unique_recipients_per_hour: 5000,
      active: true,
      reason: "Approved launch campaign",
      approved_by: "admin@example.test",
      updated_at: "2026-01-06T09:00:00Z",
      expires_at: null,
    },
  ],
  sender_behaviour: [
    {
      sender_address: "bulk@example.test",
      sending_domain: "example.test",
      source_kind: "smtp_mta",
      source_id: "mx-1",
      source_ip: "192.0.2.10",
      messages_1h: 42,
      recipients_1h: 120,
      unique_recipients_1h: 80,
      new_recipients_1h: 20,
      bounce_failures_1h: 1,
      malware_observations_1h: 0,
      auth_source_changes_1h: 0,
      unusual_time_observations_1h: 0,
      latest_seen_at: "2026-01-06T09:59:00Z",
    },
  ],
  campaigns: [
    {
      fingerprint: "campaign-abc",
      algorithm: "nullapart_v1",
      message_count: 40,
      recipient_count: 120,
      disposition: "warned",
      first_seen_at: "2026-01-06T09:00:00Z",
      last_seen_at: "2026-01-06T09:59:00Z",
    },
  ],
  security_events: [
    {
      id: "22222222-2222-2222-2222-222222222222",
      event_type: "unauthorized_bulk",
      severity: "critical",
      outcome: "hold",
      reason_code: "OUTBOUND_UNAUTHORIZED_BULK",
      sender_address: "bulk@example.test",
      source_id: "mx-1",
      campaign_fingerprint: "campaign-abc",
      status: "open",
      message_count: 3,
      first_seen_at: "2026-01-06T09:50:00Z",
      last_seen_at: "2026-01-06T09:59:00Z",
      cooldown_until: "2026-01-06T10:29:00Z",
    },
  ],
  policy_history: [
    {
      id: "33333333-3333-3333-3333-333333333333",
      action: "outbound_bulk_sender_upserted",
      actor_login: "admin@example.test",
      resource_id: "bulk@example.test:smtp_mta:mx-1",
      result: "success",
      created_at: "2026-01-06T09:00:00Z",
    },
  ],
};

function ok(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    statusText: "OK",
    json: async () => body,
  };
}

function stubFetch() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: managerSession });
    }
    if (method === "POST" && url.endsWith("/outbound-intelligence/approved-senders")) {
      return ok({
        data: {
          sender_address: "bulk@example.test",
          active: true,
        },
      });
    }
    if (url.includes("/outbound-intelligence")) {
      return ok({ data: baseSnapshot });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderAt(entry: string) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/outbound-intelligence",
      component: OutboundIntelligence,
    }),
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

describe("OutboundIntelligence", () => {
  it("renders outbound summaries, events, campaigns and approval controls", async () => {
    stubFetch();
    renderAt("/outbound-intelligence");

    await screen.findByRole("heading", { name: "Outbound intelligence" });
    const summary = screen.getByRole("region", { name: "Outbound summary" });
    expect(within(summary).getByText("Messages")).toBeTruthy();
    expect(within(summary).getByText("42")).toBeTruthy();
    expect(screen.getByText("unauthorized bulk")).toBeTruthy();
    expect(screen.getAllByText("bulk@example.test").length).toBeGreaterThan(0);
    expect(screen.getByText("campaign-abc")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Save approval" })).toBeTruthy();
  });

  it("posts approved sender changes with an idempotency key", async () => {
    const fetchMock = stubFetch();
    const user = userEvent.setup();
    renderAt("/outbound-intelligence");
    await screen.findByRole("heading", { name: "Outbound intelligence" });

    await user.type(screen.getByLabelText("Sender address"), "bulk@example.test");
    await user.type(screen.getByLabelText("Sending domain"), "example.test");
    await user.type(screen.getByLabelText("Source ID"), "mx-1");
    await user.type(screen.getByLabelText("Reason"), "Approved launch campaign");
    await user.click(screen.getByRole("button", { name: "Save approval" }));

    await waitFor(() => {
      const approvalCall = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/outbound-intelligence/approved-senders") &&
          init?.method === "POST",
      );
      expect(approvalCall).toBeTruthy();
      expect(
        (approvalCall?.[1]?.headers as Record<string, string>)["X-Idempotency-Key"],
      ).toBeTruthy();
    });
  });
});

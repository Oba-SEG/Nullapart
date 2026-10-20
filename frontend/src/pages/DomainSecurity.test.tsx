import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DomainSecurity } from "./DomainSecurity";

function buildSession(permissions: string[]) {
  return {
    authenticated: true,
    userId: "actor-1",
    email: "ops@acme.test",
    roles: ["customer_admin"],
    permissions,
    customerId: "customer-acme",
    tier: "customer",
    expiresAt: "2099-01-01T00:00:00Z",
    csrfToken: "csrf-token",
    impersonation: null,
  };
}

const manageSession = buildSession(["domain-security:view", "domain-security:manage"]);
const viewSession = buildSession(["domain-security:view"]);

const finding = {
  id: "notice-1",
  domain_id: "domain-1",
  notification_type: "spf_missing",
  severity: "warning",
  title: "SPF is not publishing",
  detail: "acme.test has no SPF record, so receivers cannot validate a passing send.",
  status: "open",
  created_at: "2026-01-05T09:00:00Z",
};

const acknowledged = {
  id: "notice-2",
  domain_id: "domain-1",
  notification_type: "dmarc_missing",
  severity: "critical",
  title: "No DMARC policy",
  detail: "acme.test publishes no DMARC record.",
  acknowledged_by: "ops@acme.test",
  acknowledged_at: "2026-01-04T09:00:00Z",
};

function securityBody(overrides: Record<string, unknown> = {}) {
  return {
    deployment_id: "deployment-1",
    generated_at: "2026-01-06T10:00:00Z",
    summary: {
      domains_total: 1,
      verified_domains: 1,
      messages_30d: 40,
      dmarc_aligned_messages_30d: 12,
      unknown_sources: 0,
      report_authorization_broken: 0,
      bimi_not_ready: 0,
      open_notifications: 1,
    },
    domains: [],
    notifications: [finding],
    recent_acknowledgments: [acknowledged],
    ...overrides,
  };
}

function notificationSettingsBody() {
  return {
    deployment_id: "deployment-1",
    generated_at: "2026-01-06T10:00:00Z",
    settings: null,
    effective: {
      enabled: false,
      severity_floor: "warning",
      recipient_count: 0,
      digest_window_minutes: 60,
      deliverable: false,
    },
    verified_domains: ["acme.test"],
    deliveries: [],
    capabilities: { update_settings: { allowed: false, blocker: "permission" } },
  };
}

function ok(body: unknown) {
  return { ok: true, status: 200, statusText: "OK", json: async () => body };
}

function fail(status: number, body: unknown) {
  return { ok: false, status, statusText: "Error", json: async () => body };
}

interface StubOptions {
  session: unknown;
  body?: unknown;
  acknowledgeError?: { status: number; code: string; message: string };
  /** The server's `changed` verdict: false when the finding was already closed. */
  changed?: boolean;
}

function stub(opts: StubOptions) {
  const calls: Array<{ method: string; url: string; headers: Record<string, string> }> = [];
  const fetchMock = vi.fn(
    async (
      input: unknown,
      init?: { method?: string; body?: string; headers?: Record<string, string> },
    ) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push({ method, url, headers: init?.headers ?? {} });
      if (url.includes("/auth/session")) return ok({ data: opts.session });
      if (url.includes("/acknowledge")) {
        if (opts.acknowledgeError) {
          return fail(opts.acknowledgeError.status, {
            code: opts.acknowledgeError.code,
            message: opts.acknowledgeError.message,
          });
        }
        return ok({
          data: {
            notification_id: finding.id,
            notification_type: finding.notification_type,
            severity: finding.severity,
            title: finding.title,
            status: "acknowledged",
            acknowledged_by: "ops@acme.test",
            acknowledged_at: "2026-01-06T10:30:00Z",
            changed: opts.changed ?? true,
          },
        });
      }
      if (url.includes("/notifications/settings")) return ok({ data: notificationSettingsBody() });
      if (url.includes("/domain-security")) return ok({ data: opts.body ?? securityBody() });
      throw new Error(`unexpected fetch ${method} ${url}`);
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

function renderPage() {
  const rootRoute = createRootRoute({ component: () => <DomainSecurity /> });
  const route = createRoute({ getParentRoute: () => rootRoute, path: "/domain-security" });
  const router = createRouter({
    routeTree: rootRoute.addChildren([route]),
    history: createMemoryHistory({ initialEntries: ["/domain-security"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

async function openPage(session: unknown, options: StubOptions = { session }) {
  const calls = stub(options);
  renderPage();
  const alerts = await screen.findByRole("region", { name: "Findings" });
  return { calls, alerts };
}

afterEach(() => vi.unstubAllGlobals());

describe("DomainSecurity findings", () => {
  it("acknowledges a finding with an idempotency key and records the operator", async () => {
    const { calls, alerts } = await openPage(manageSession);
    await userEvent.click(within(alerts).getByRole("button", { name: "Acknowledge" }));

    expect(
      await screen.findByText(/“SPF is not publishing” acknowledged by ops@acme\.test/),
    ).toBeInTheDocument();
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toContain("/domain-security/notifications/notice-1/acknowledge");
    expect(post?.headers["X-Idempotency-Key"]).toMatch(/[0-9a-f-]{36}/i);
  });

  it("says so when the finding was already closed", async () => {
    const { alerts } = await openPage(manageSession, {
      session: manageSession,
      changed: false,
    });
    await userEvent.click(within(alerts).getByRole("button", { name: "Acknowledge" }));

    expect(await screen.findByText(/was already acknowledged/)).toBeInTheDocument();
  });

  it("surfaces a stale step-up window instead of a bare failure", async () => {
    const { alerts } = await openPage(manageSession, {
      session: manageSession,
      acknowledgeError: {
        status: 401,
        code: "STEP_UP_REQUIRED",
        message: "A fresh sign-in is required.",
      },
    });
    await userEvent.click(within(alerts).getByRole("button", { name: "Acknowledge" }));

    expect(await screen.findByText(/Re-authentication is required/)).toBeInTheDocument();
  });

  it("shows who closed an earlier finding", async () => {
    const { alerts } = await openPage(manageSession);
    const history = within(alerts).getByRole("region", { name: "Recently acknowledged findings" });

    expect(within(history).getByText("No DMARC policy")).toBeInTheDocument();
    expect(within(history).getByText(/ops@acme\.test/)).toBeInTheDocument();
  });

  it("withholds the action and names the permission it needs", async () => {
    const { calls, alerts } = await openPage(viewSession);

    expect(within(alerts).queryByRole("button", { name: "Acknowledge" })).not.toBeInTheDocument();
    expect(within(alerts).getByText("SPF is not publishing")).toBeInTheDocument();
    expect(calls.filter((call) => call.method === "POST")).toEqual([]);
  });

  it("distinguishes a cleared queue from a page with nothing to report", async () => {
    const { alerts } = await openPage(manageSession, {
      session: manageSession,
      body: securityBody({
        notifications: [],
        summary: { ...securityBody().summary, open_notifications: 0 },
      }),
    });

    expect(within(alerts).getByText("No open findings.")).toBeInTheDocument();
    expect(within(alerts).queryByRole("button", { name: "Acknowledge" })).not.toBeInTheDocument();
  });

  it("shows no findings section when nothing has ever been raised", async () => {
    stub({
      session: manageSession,
      body: securityBody({
        notifications: [],
        recent_acknowledgments: [],
        summary: { ...securityBody().summary, open_notifications: 0 },
      }),
    });
    renderPage();
    await screen.findByText("Domain security");

    expect(screen.queryByRole("region", { name: "Findings" })).not.toBeInTheDocument();
  });

  /**
   * The customer read keeps the counts it publishes and leaves the rest out, so an
   * absent numerator is a real answer rather than a broken one. A percentage
   * worked out from a value that never arrived reads "NaN%", and the tenant who
   * sees it cannot tell whether their mail aligned or the page simply gave up.
   */
  it("shows a dash for the alignment share when the count never arrived", async () => {
    const summary = { ...securityBody().summary } as Record<string, unknown>;
    delete summary.dmarc_aligned_messages_30d;
    stub({ session: viewSession, body: securityBody({ summary }) });
    renderPage();
    await screen.findByText("Domain security");

    const card = await screen.findByText("DMARC alignment");
    expect(card.parentElement).toHaveTextContent("—");
    expect(document.body.textContent).not.toMatch(/NaN/);
  });
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { NotificationSettings } from "./NotificationSettings";

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

const manageSession = buildSession([
  "domain-security:view",
  "notifications:view",
  "notifications:manage",
]);
const viewSession = buildSession(["domain-security:view", "notifications:view"]);
const noViewSession = buildSession(["domain-security:view"]);

const storedSettings = {
  enabled: true,
  severity_floor: "warning",
  recipient_emails: ["postmaster@acme.test"],
  digest_window_minutes: 60,
  updated_by: "ops@acme.test",
  updated_at: "2026-01-05T10:00:00Z",
};

function responseFor(overrides: Record<string, unknown> = {}) {
  return {
    deployment_id: "deployment-1",
    generated_at: "2026-01-06T10:00:00Z",
    settings: storedSettings,
    effective: {
      enabled: true,
      severity_floor: "warning",
      recipient_count: 1,
      digest_window_minutes: 60,
      deliverable: true,
    },
    verified_domains: ["acme.test"],
    deliveries: [],
    capabilities: { update_settings: { allowed: true, blocker: null } },
    ...overrides,
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
  loadError?: { status: number; code: string; message: string };
  saveError?: { status: number; code: string; message: string };
}

/** Records every write so the tests can assert the actual PUT body and header. */
function stub(opts: StubOptions) {
  const calls: Array<{
    method: string;
    url: string;
    body: unknown;
    headers: Record<string, string>;
  }> = [];
  const fetchMock = vi.fn(
    async (
      input: unknown,
      init?: { method?: string; body?: string; headers?: Record<string, string> },
    ) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push({
        method,
        url,
        body: init?.body === undefined ? null : JSON.parse(init.body),
        headers: init?.headers ?? {},
      });
      if (url.includes("/auth/session")) return ok({ data: opts.session });
      if (method === "PUT") {
        if (opts.saveError) {
          return fail(opts.saveError.status, {
            code: opts.saveError.code,
            message: opts.saveError.message,
          });
        }
        const sent = JSON.parse(init?.body ?? "{}") as typeof storedSettings;
        return ok({ data: { ...storedSettings, ...sent } });
      }
      if (opts.loadError) {
        return fail(opts.loadError.status, {
          code: opts.loadError.code,
          message: opts.loadError.message,
        });
      }
      return ok({ data: opts.body ?? responseFor() });
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

function renderCard() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <NotificationSettings titlesById={{ "notice-1": "SPF is not publishing" }} />
    </QueryClientProvider>,
  );
}

/**
 * The card renders a permission lock before the session has resolved, so a
 * test that expects the loaded form waits for the effective-settings sentence
 * rather than the heading both states share.
 */
async function openCard(session: unknown, options: StubOptions = { session }) {
  const calls = stub(options);
  renderCard();
  await screen.findByText(/^Currently:/);
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("NotificationSettings access states", () => {
  it("states the missing permission and never reads settings the actor cannot see", async () => {
    const calls = stub({ session: noViewSession });
    renderCard();
    const card = await screen.findByRole("region", { name: "Alert mail" });

    expect(within(card).getByText(/capability to view delivery alerts/)).toBeInTheDocument();
    expect(calls.filter((call) => call.url.includes("/notifications/settings"))).toEqual([]);
  });

  it("falls back to platform defaults when nobody has saved settings yet", async () => {
    await openCard(manageSession, {
      session: manageSession,
      body: responseFor({
        settings: null,
        effective: {
          enabled: false,
          severity_floor: "warning",
          recipient_count: 0,
          digest_window_minutes: 60,
          deliverable: false,
        },
      }),
    });

    expect(screen.getByText(/Nobody has saved settings for this customer yet/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save settings" })).toBeDisabled();
    expect(screen.getByLabelText("Recipients")).toHaveValue("");
  });

  it("says why saving is withheld when the server blocks the capability", async () => {
    await openCard(manageSession, {
      session: manageSession,
      body: responseFor({
        capabilities: { update_settings: { allowed: false, blocker: "permission" } },
      }),
    });

    expect(
      screen.getByText(
        /Saving notification settings needs the capability to change delivery alerts/,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Save settings/ })).not.toBeInTheDocument();
    expect(screen.getByRole("checkbox")).toBeDisabled();
  });

  it("reports a failed read instead of showing a form the actor is entitled to", async () => {
    const calls = stub({
      session: manageSession,
      loadError: {
        status: 503,
        code: "UNAVAILABLE",
        message: "Notification delivery is unavailable.",
      },
    });
    renderCard();
    await screen.findByRole("alert");

    expect(screen.getByRole("alert")).toHaveTextContent("Notification delivery is unavailable.");
    expect(
      calls.filter((call) => call.url.includes("/notifications/settings")).length,
    ).toBeGreaterThan(0);
  });
});

describe("NotificationSettings writes", () => {
  it("keeps Save inert until the draft differs from what is stored", async () => {
    await openCard(manageSession);
    const save = screen.getByRole("button", { name: "Save settings" });

    expect(save).toBeDisabled();
    await userEvent.click(save);
    expect(save).toBeDisabled();
  });

  it("sends the whole settings object with an idempotency key", async () => {
    const calls = await openCard(manageSession);
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.selectOptions(screen.getByLabelText("Severity floor"), "critical");
    const recipients = screen.getByLabelText("Recipients") as HTMLTextAreaElement;
    await userEvent.clear(recipients);
    await userEvent.type(recipients, "postmaster@acme.test, abuse@acme.test");

    await userEvent.click(screen.getByRole("button", { name: "Save settings" }));
    await screen.findByText(/Saved:/);

    const put = calls.find((call) => call.method === "PUT");
    expect(put?.url).toContain("/notifications/settings");
    expect(put?.body).toEqual({
      enabled: false,
      severity_floor: "critical",
      recipient_emails: ["postmaster@acme.test", "abuse@acme.test"],
      digest_window_minutes: 60,
    });
    expect(put?.headers["X-Idempotency-Key"]).toMatch(/[0-9a-f-]{36}/i);
  });

  it("refuses an address outside the verified domains before the server has to", async () => {
    await openCard(manageSession);
    const recipients = screen.getByLabelText("Recipients") as HTMLTextAreaElement;
    await userEvent.clear(recipients);
    await userEvent.type(recipients, "help@other.test");

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /outside the domains your customer has verified/,
    );
    expect(screen.getByRole("button", { name: "Save settings" })).toBeDisabled();
  });

  it("falls back to its own permission check when no capability is published", async () => {
    const calls = await openCard(viewSession, {
      session: viewSession,
      body: responseFor({ capabilities: undefined }),
    });

    expect(
      screen.getByText(
        /Saving notification settings needs the capability to change delivery alerts/,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save settings" })).not.toBeInTheDocument();
    expect(screen.getByRole("checkbox")).toBeDisabled();
    expect(calls.filter((call) => call.method === "PUT")).toEqual([]);
  });

  it("prompts for a fresh sign-in when the step-up window is stale", async () => {
    await openCard(manageSession, {
      session: manageSession,
      saveError: {
        status: 401,
        code: "STEP_UP_REQUIRED",
        message: "A fresh sign-in is required.",
      },
    });
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: "Save settings" }));

    expect(await screen.findByText(/Re-authentication is required/)).toBeInTheDocument();
  });
});

describe("NotificationSettings delivery ledger", () => {
  it("names each notice, its outcome and the mail queue reference", async () => {
    await openCard(manageSession, {
      session: manageSession,
      body: responseFor({
        deliveries: [
          {
            notification_id: "notice-1",
            status: "sent",
            recipient_count: 2,
            attempts: 1,
            reason: null,
            outbound_transaction_id: "4A2F1C9",
            created_at: "2026-01-06T09:00:00Z",
            updated_at: "2026-01-06T09:01:00Z",
          },
          {
            notification_id: "notice-2",
            status: "dead_lettered",
            recipient_count: 0,
            attempts: 3,
            reason: "The outbound relay refused the connection.",
            outbound_transaction_id: null,
            created_at: "2026-01-05T09:00:00Z",
            updated_at: "2026-01-05T09:20:00Z",
          },
        ],
      }),
    });

    const history = screen.getByRole("region", { name: "Delivery history" });
    expect(within(history).getByText("SPF is not publishing")).toBeInTheDocument();
    expect(within(history).getByText("Mail queue reference 4A2F1C9")).toBeInTheDocument();
    expect(within(history).getByText("Notice notice-2")).toBeInTheDocument();
    expect(within(history).getByText("Not delivered")).toBeInTheDocument();
    expect(
      within(history).getByText("The outbound relay refused the connection."),
    ).toBeInTheDocument();
  });

  it("says nothing has been queued rather than implying a quiet inbox", async () => {
    await openCard(manageSession);
    const history = screen.getByRole("region", { name: "Delivery history" });
    expect(within(history).getByText(/No notice has been queued/)).toBeInTheDocument();
  });
});

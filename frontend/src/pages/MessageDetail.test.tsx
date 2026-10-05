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
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { MessageDetail } from "./MessageDetail";

const traceTransaction = {
  transaction_id: "tx-2002",
  trace_id: "trace-9f2",
  direction: "inbound",
  deployment_id: "dep-eu-1",
  envelope_sender: "sender@example.test",
  message_id: "<m-2002@example.test>",
  content_hash: "sha256:9a3f",
  received_at: "2026-09-30T12:00:00Z",
  recipients: [
    { address: "alice@example.test", orcpt: "rfc822;alice@example.test", notify: "failure" },
  ],
  auth: {
    spf_result: "pass",
    dkim_result: { outcome: "pass", details: ["rsa-sha256"] },
    dmarc_result: "pass",
    arc_result: null,
  },
  postfix_queue_ids: ["3Fh2k1Q", "9Zx8p0A"],
  instances: [
    {
      tenant_message_id: "tenant-message-7",
      disposition: "quarantine",
      remediation_type: "release",
      created_at: "2026-09-30T12:00:04Z",
      updated_at: "2026-09-30T12:05:00Z",
    },
  ],
  delivery_attempts: [
    {
      attempt_number: 1,
      status: "deferred",
      smtp_code: "451",
      enhanced_code: "4.7.1",
      smtp_message: "Try again later",
      scheduled_at: "2026-09-30T12:01:00Z",
      completed_at: "2026-09-30T12:01:03Z",
      next_retry_at: "2026-09-30T12:06:00Z",
      postfix_queue_id: "3Fh2k1Q",
    },
  ],
  findings: [
    {
      id: "finding-1",
      severity: "high",
      category: "phishing",
      description: "Lookalike sender domain",
      scanner_type: "link_analysis",
      false_positive: true,
      created_at: "2026-09-30T12:00:03Z",
    },
  ],
  flow_stages: [
    { stage: "quarantined", at: "2026-09-30T12:00:05Z" },
    { stage: "received", at: "2026-09-30T12:00:00Z" },
    { stage: "spam_checked", at: "2026-09-30T12:00:02Z" },
  ],
};

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

const contentSession = buildSession(["system_admin"], ["trace:view", "trace:content"]);
const supportSession = buildSession(["support"], ["trace:view"]);

function ok(body: unknown, status = 200) {
  return { ok: true, status, statusText: "OK", json: async () => body };
}

function fail(status: number, body: unknown) {
  return { ok: false, status, statusText: "Error", json: async () => body };
}

interface StubOptions {
  session: unknown;
  detail?: unknown;
  detailError?: { status: number; code: string; message: string };
  content?: unknown;
  contentError?: { status: number; code: string; message: string };
}

function stubFetch(options: StubOptions) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/auth/session")) {
      return ok({ data: options.session });
    }
    if (url.includes("/mail-trace/transaction/tx-2002/content")) {
      if (options.contentError) {
        return fail(options.contentError.status, {
          code: options.contentError.code,
          message: options.contentError.message,
        });
      }
      return ok({ data: options.content });
    }
    if (url.includes("/mail-trace/transaction/")) {
      if (options.detailError) {
        return fail(options.detailError.status, {
          code: options.detailError.code,
          message: options.detailError.message,
        });
      }
      return ok({ data: options.detail });
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
      path: "/messages",
      component: () => <div>Messages list route</div>,
    }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/messages/$messageId",
      component: MessageDetail,
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

describe("MessageDetail", () => {
  it("renders the transaction fields, tables and the ordered flow timeline", async () => {
    stubFetch({ session: contentSession, detail: traceTransaction });
    renderAt("/messages/tx-2002");

    expect(await screen.findByText("tx-2002")).toBeTruthy();
    expect(screen.getByText("inbound")).toBeTruthy();
    expect(screen.getByText("sender@example.test")).toBeTruthy();
    expect(screen.getByText("<m-2002@example.test>")).toBeTruthy();
    expect(screen.getByText("sha256:9a3f")).toBeTruthy();
    expect(
      screen.getAllByText(new Date("2026-09-30T12:00:00Z").toLocaleString()).length,
    ).toBeGreaterThan(0);

    expect(screen.getByText("alice@example.test")).toBeTruthy();
    expect(screen.getByText("rfc822;alice@example.test")).toBeTruthy();
    expect(screen.getByText("failure")).toBeTruthy();

    expect(screen.getAllByText("pass").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('{"outcome":"pass","details":["rsa-sha256"]}')).toBeTruthy();
    expect(screen.getByText("9Zx8p0A")).toBeTruthy();
    expect(screen.getAllByText("3Fh2k1Q").length).toBeGreaterThanOrEqual(2);

    expect(screen.getByText("tenant-message-7")).toBeTruthy();
    expect(screen.getByText("quarantine")).toBeTruthy();
    expect(screen.getByText("release")).toBeTruthy();

    expect(screen.getByText("deferred")).toBeTruthy();
    expect(screen.getByText("451")).toBeTruthy();
    expect(screen.getByText("4.7.1")).toBeTruthy();
    expect(screen.getByText("Try again later")).toBeTruthy();

    expect(screen.getByText("high")).toBeTruthy();
    expect(screen.getByText("phishing")).toBeTruthy();
    expect(screen.getByText("Lookalike sender domain")).toBeTruthy();
    expect(screen.getByText(/Link analysis/)).toBeTruthy();
    expect(screen.queryByText(/Scanner urlanalysis/)).toBeNull();
    expect(screen.getByText("False positive")).toBeTruthy();

    const timeline = screen.getByRole("region", { name: "Flow timeline" });
    const timelineText = timeline.textContent ?? "";
    expect(timelineText.indexOf("Received")).toBeLessThan(timelineText.indexOf("Spam checked"));
    expect(timelineText.indexOf("Spam checked")).toBeLessThan(timelineText.indexOf("Quarantined"));
    expect(timelineText).toContain(new Date("2026-09-30T12:00:05Z").toLocaleString());

    expect(await screen.findByRole("button", { name: "View message content" })).toBeTruthy();
  });

  it("shows a Message not found state when the transaction is not visible", async () => {
    stubFetch({
      session: supportSession,
      detailError: { status: 404, code: "NOT_FOUND", message: "Transaction not visible" },
    });
    renderAt("/messages/tx-missing");

    expect(await screen.findByText("Message not found")).toBeTruthy();
    expect(screen.queryByText("Loading message trace…")).toBeNull();
  });

  it("hides the message content button for a support session without trace:content", async () => {
    stubFetch({ session: supportSession, detail: traceTransaction });
    renderAt("/messages/tx-2002");

    await screen.findByText("tx-2002");
    expect(screen.queryByRole("button", { name: "View message content" })).toBeNull();
  });

  it("renders the permission message when the content endpoint answers 403", async () => {
    stubFetch({
      session: contentSession,
      detail: traceTransaction,
      contentError: { status: 403, code: "FORBIDDEN", message: "trace:content is required" },
    });
    const user = userEvent.setup();
    renderAt("/messages/tx-2002");

    await user.click(await screen.findByRole("button", { name: "View message content" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("You do not have permission to view message content.");
  });

  it("renders the message content panel for a session with trace:content", async () => {
    stubFetch({
      session: contentSession,
      detail: traceTransaction,
      content: {
        transaction_id: "tx-2002",
        subject: "Quarterly report",
        from: "sender@example.test",
        to: ["alice@example.test"],
        date: "2026-09-30T12:00:00Z",
        headers: [{ name: "Subject", value: "Quarterly report" }],
        plain_text: "See the attached report.",
        html: null,
        truncated: false,
        attachments: [],
      },
    });
    const user = userEvent.setup();
    renderAt("/messages/tx-2002");

    await user.click(await screen.findByRole("button", { name: "View message content" }));

    const panel = await screen.findByRole("region", { name: "Message content" });
    expect(within(panel).getByText("Quarterly report")).toBeTruthy();
    expect(within(panel).getByText("See the attached report.")).toBeTruthy();
    await user.click(within(panel).getByRole("tab", { name: "HTML" }));
    expect(within(panel).getByText("No HTML part.")).toBeTruthy();
  });
});

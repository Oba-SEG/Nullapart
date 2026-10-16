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

import { Messages } from "./Messages";

const searchResult = {
  transaction_id: "tx-1001",
  direction: "inbound",
  envelope_sender: "sender@example.test",
  message_id: "<msg-1001@example.test>",
  received_at: "2026-09-30T10:00:00Z",
  recipients: ["alice@example.test", "bob@example.test"],
  instances: [{ tenant_message_id: "tenant-message-1", disposition: "quarantine" }],
};

function stubFetch(results: unknown) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "POST" && url.includes("/mail-trace/search")) {
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        json: async () => ({ data: results }),
      };
    }
    throw new Error(`unexpected fetch ${method} ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderInRouter() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/messages",
      component: Messages,
    }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/messages/$messageId",
      component: () => <div>Message detail route</div>,
    }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/quarantine/$tenant_message_id",
      component: () => null,
    }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/messages"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

async function runSearch(user: ReturnType<typeof userEvent.setup>, query: string) {
  await user.type(screen.getByLabelText("Search messages"), query);
  await user.click(screen.getByRole("button", { name: "Search" }));
}

describe("Messages", () => {
  it("shows an empty state before any search is run", async () => {
    const fetchMock = stubFetch({ results: [], total_count: 0, has_more: false });
    renderInRouter();

    expect(await screen.findByRole("status")).toHaveTextContent(/No search has been run yet/i);
    expect(screen.queryByRole("table")).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("blocks a query shorter than three characters with an inline message", async () => {
    const fetchMock = stubFetch({ results: [], total_count: 0, has_more: false });
    const user = userEvent.setup();
    renderInRouter();
    await screen.findByRole("status");

    await runSearch(user, "ab");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Enter at least 3 characters to search.");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fetches results from the mail trace search endpoint and renders them", async () => {
    const fetchMock = stubFetch({
      results: [searchResult],
      total_count: 4,
      has_more: true,
    });
    const user = userEvent.setup();
    renderInRouter();
    await screen.findByRole("status");

    await runSearch(user, "sender@example.test");

    const link = await screen.findByRole("link", { name: "tx-1001" });
    expect(link).toHaveProperty("href", expect.stringContaining("/messages/tx-1001"));

    const row = link.closest("tr");
    if (!row) throw new Error("expected a results table row");
    expect(within(row).getByText("sender@example.test")).toBeTruthy();
    expect(within(row).getByText("<msg-1001@example.test>")).toBeTruthy();
    expect(within(row).getByText("2")).toBeTruthy();
    expect(within(row).getByText("Held for review")).toBeTruthy();
    expect(screen.getByText(/Showing 1 of 4 matches/)).toBeTruthy();

    const call = fetchMock.mock.calls.find(
      ([input, init]) => String(input).includes("/mail-trace/search") && init?.method === "POST",
    );
    expect(call).toBeTruthy();
    const body = JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>;
    expect(body.q).toBe("sender@example.test");
  });

  it("navigates to the transaction detail when a result row is opened", async () => {
    stubFetch({ results: [searchResult], total_count: 1, has_more: false });
    const user = userEvent.setup();
    renderInRouter();
    await screen.findByRole("status");

    await runSearch(user, "sender@example.test");

    await user.click(await screen.findByRole("link", { name: "tx-1001" }));

    expect(await screen.findByText("Message detail route")).toBeTruthy();
  });

  it("surfaces a server search failure without fabricating rows", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      json: async () => ({ code: "VALIDATION", message: "Query is too short" }),
    }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderInRouter();
    await screen.findByRole("status");

    await runSearch(user, "sender@example.test");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Query is too short");
    expect(screen.queryByRole("table")).toBeNull();
  });
});

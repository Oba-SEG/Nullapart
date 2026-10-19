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
import { beforeAll, describe, expect, it, vi } from "vitest";

import { FeatureOverrides } from "./FeatureOverrides";

function sessionFor(
  roles: string[],
  permissions = ["policies:manage"],
  tier: string | null = null,
) {
  return {
    authenticated: true,
    userId: "actor-1",
    email: "admin@example.test",
    roles,
    permissions,
    customerId: "CZA-1",
    tier,
    expiresAt: "2099-01-01T00:00:00Z",
    csrfToken: "csrf-token",
    impersonation: null,
  };
}

const bulkGuard = {
  feature_id: "outbound_bulk_guard",
  display_name: "Outbound bulk sender guardrails",
  description: "Limits how fast one sender may release mail to many recipients.",
  default_value: "enabled",
  mandatory: false,
  kill_switch: false,
  allowed_scopes: ["system", "deployment", "tenant"],
  effective_value: "typed:rate_limit=10",
  winning_scope: "tenant",
  overrides: [
    {
      id: "override-tenant",
      scope: "tenant",
      scope_id: "CZA-1",
      value: "typed:rate_limit=10",
      // The stored reference is an administrator identity id, exactly as the
      // write path records it. The row has to read the resolved name instead.
      owner: "6f1f6b3e-7d0a-4d5c-9d43-0a1b2c3d4e5f",
      owner_display_name: "Lerato Mokoena",
      reason: "Campaign weekend lift",
      revision: 3,
      created_at: "2026-01-05T09:00:00Z",
      expires_at: "2026-02-01T00:00:00Z",
    },
    {
      id: "override-system",
      scope: "system",
      scope_id: "*",
      value: "enabled",
      owner: "2a8b1c4d-0e5f-4a6b-8c9d-0e1f2a3b4c5d",
      owner_display_name: "Platform rota",
      reason: "Initial platform posture",
      revision: 1,
      created_at: "2026-01-04T09:00:00Z",
      expires_at: null,
    },
  ],
};

/** A security floor an operator can read but never switch off. */
const spfEnforcement = {
  feature_id: "spf_enforcement",
  display_name: "SPF rejection",
  description: "Rejects mail from senders whose SPF check fails.",
  default_value: "enabled",
  mandatory: true,
  kill_switch: true,
  allowed_scopes: ["system"],
  effective_value: "enabled",
  winning_scope: "system",
  overrides: [],
};

function featuresBody(allowedOverrideScopes: string[]) {
  return {
    data: {
      features: [bulkGuard, spfEnforcement],
      allowed_override_scopes: allowedOverrideScopes,
    },
  };
}

function ok(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    statusText: "OK",
    json: async () => body,
  };
}

function clearedResult() {
  return {
    data: {
      id: "override-tenant",
      scope: "tenant",
      scope_id: "CZA-1",
      value: "inherit",
      owner: "6f1f6b3e-7d0a-4d5c-9d43-0a1b2c3d4e5f",
      owner_display_name: "Lerato Mokoena",
      reason: "Campaign finished; lift no longer required",
      revision: 4,
      created_at: "2026-01-06T10:00:00Z",
      expires_at: null,
      effective_value: "enabled",
      winning_scope: "system",
    },
  };
}

function savedResult(value: string) {
  return {
    data: {
      id: "override-tenant",
      scope: "tenant",
      scope_id: "CZA-1",
      value,
      owner: "6f1f6b3e-7d0a-4d5c-9d43-0a1b2c3d4e5f",
      owner_display_name: "Lerato Mokoena",
      reason: "Weekend campaign sends faster",
      revision: 5,
      created_at: "2026-01-07T10:00:00Z",
      expires_at: null,
      effective_value: value,
      winning_scope: "tenant",
    },
  };
}

function stubFetch(
  session: ReturnType<typeof sessionFor>,
  allowedOverrideScopes = ["tenant"],
  // Stands in for the server echoing the stored value back after a write.
  respondToPut: (body: Record<string, unknown>) => unknown = () => clearedResult(),
) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: session });
    }
    if (method === "PUT" && url.endsWith("/features/outbound_bulk_guard/overrides")) {
      return ok(respondToPut(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>));
    }
    if (url.includes("/features")) {
      return ok(featuresBody(allowedOverrideScopes));
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
      path: "/features-overrides",
      component: FeatureOverrides,
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

describe("FeatureOverrides", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("leads with the catalog label and keeps the raw id as evidence", async () => {
    stubFetch(sessionFor(["system_admin"]));
    renderAt("/features-overrides");

    expect(await screen.findByText("Outbound bulk sender guardrails")).toBeTruthy();
    // The identifier is still on the row because audit records name it.
    expect(screen.getByText("outbound_bulk_guard")).toBeTruthy();
    expect(screen.getByText("This customer · CZA-1")).toBeTruthy();
    // The typed value shows once as the value in force and once on the
    // override that produced it.
    expect(screen.getAllByText("rate_limit=10")).toHaveLength(2);
    expect(screen.getByText(/set by Lerato Mokoena/i)).toBeTruthy();
    // A bare identity id is not a decision anyone can read, so the row shows the
    // resolved name instead of the stored reference.
    expect(screen.queryByText(/6f1f6b3e-7d0a-4d5c-9d43/i)).toBeNull();
    expect(screen.getByText(/set by Platform rota/i)).toBeTruthy();
  });

  it("names enum values in operator words instead of wire values", async () => {
    stubFetch(sessionFor(["system_admin"]));
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    expect(screen.getByText("Security floor")).toBeTruthy();
    expect(screen.getByText("Emergency stop")).toBeTruthy();
    expect(screen.queryByText(/^\s*mandatory\s*$/i)).toBeNull();
    expect(screen.queryByText(/^\s*kill switch\s*$/i)).toBeNull();
    expect(screen.queryByText(/^wins at /i)).toBeNull();
  });

  it("shows the server-published writable scopes as the only edit actions", async () => {
    stubFetch(sessionFor(["support"]), ["deployment", "tenant"]);
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    const rows = screen.getAllByRole("row");
    const guardRow = rows.find((row) => within(row).queryByText("outbound_bulk_guard"));
    const spfRow = rows.find((row) => within(row).queryByText("spf_enforcement"));
    expect(within(guardRow as HTMLElement).getByRole("button", { name: "Change" })).toBeTruthy();
    // SPF only allows platform-wide changes, which this session was not given.
    expect(within(spfRow as HTMLElement).getByText("Locked at your level")).toBeTruthy();
  });

  it("states why a locked row is locked instead of failing silently", async () => {
    stubFetch(sessionFor(["support"]), ["tenant"]);
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    const lock = screen.getByText("Locked at your level");
    const described = lock.getAttribute("aria-describedby");
    expect(described).toBeTruthy();
    const description = document.getElementById(described as string);
    expect(description?.textContent).toMatch(/only changed at platform-wide/i);
  });

  it("filters to the rows this session can actually change", async () => {
    stubFetch(sessionFor(["system_admin"]), ["system", "deployment", "tenant"]);
    const user = userEvent.setup();
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    await user.click(screen.getByRole("button", { name: "Show only what you can change" }));
    expect(screen.getByRole("button", { name: "Showing what you can change" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Change" })).toHaveLength(2);
  });

  it("clears an override with an explicit inherit write and an audited reason", async () => {
    const fetchMock = stubFetch(sessionFor(["system_admin"]));
    const user = userEvent.setup();
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    await user.click(screen.getByRole("button", { name: "Clear this override" }));

    const dialog = screen.getByRole("dialog", { name: /clear outbound bulk/i });
    await user.type(
      within(dialog).getByLabelText("Why this is being retired"),
      "Campaign finished; lift no longer required",
    );
    await user.click(within(dialog).getByRole("button", { name: "Clear override" }));

    await waitFor(() => {
      const putCall = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/features/outbound_bulk_guard/overrides") &&
          init?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(JSON.parse(String(putCall?.[1]?.body))).toEqual({
        scope: "tenant",
        value: "inherit",
        reason: "Campaign finished; lift no longer required",
        expires_at: null,
      });
      expect((putCall?.[1]?.headers as Record<string, string>)["X-Idempotency-Key"]).toBeTruthy();
    });
    expect(await screen.findByText(/cleared at this customer/i)).toBeTruthy();
  });

  it("rejects a clear without a reason before any request is sent", async () => {
    const fetchMock = stubFetch(sessionFor(["system_admin"]));
    const user = userEvent.setup();
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    await user.click(screen.getByRole("button", { name: "Clear this override" }));
    const dialog = screen.getByRole("dialog", { name: /clear outbound bulk/i });
    await user.click(within(dialog).getByRole("button", { name: "Clear override" }));

    expect(within(dialog).getByRole("alert").textContent).toMatch(/at least 10 characters/i);
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          String(input).endsWith("/features/outbound_bulk_guard/overrides") &&
          init?.method === "PUT",
      ),
    ).toBe(false);
  });

  it("offers no clear action on an override set above this session", async () => {
    stubFetch(sessionFor(["support"]), ["tenant"]);
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    // The customer override is theirs to clear; the platform-wide one is not.
    expect(screen.getAllByRole("button", { name: "Clear this override" })).toHaveLength(1);
    expect(screen.getByText("Set by a higher level")).toBeTruthy();
  });

  it("gives a role without policy management no write action at all", async () => {
    stubFetch(sessionFor(["support"], []), ["tenant"]);
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    expect(screen.queryByRole("button", { name: "Change" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Clear this override" })).toBeNull();
    // Every row says so, and the page says why once above the table.
    expect(screen.getAllByText("Read-only")).toHaveLength(2);
    expect(screen.getByText(/your role cannot manage policy settings/i)).toBeTruthy();
  });

  it("keeps the deployment rollout catalog out of a customer console", async () => {
    const fetchMock = stubFetch(sessionFor(["customer_admin"], ["policies:view"], "customer"));
    renderAt("/features-overrides");

    expect(await screen.findByText(/nothing here is open to your customer/i)).toBeTruthy();
    // The platform surfaces are not merely hidden behind a spinner.
    expect(screen.queryByText("Outbound bulk sender guardrails")).toBeNull();
    expect(screen.queryByText("Emergency stops")).toBeNull();
    expect(screen.queryByText(/deployment/i)).toBeNull();
    // Nothing is fetched, because a read the tenant console will not show is
    // still a platform read made with the tenant's session.
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/features"))).toBe(false);
  });

  it("writes a typed value at the level the session was given", async () => {
    const fetchMock = stubFetch(
      sessionFor(["system_admin"]),
      ["system", "deployment", "tenant"],
      (body) => savedResult(String(body.value)),
    );
    const user = userEvent.setup();
    renderAt("/features-overrides");
    await screen.findByText("Outbound bulk sender guardrails");

    const guardRow = screen
      .getAllByRole("row")
      .find((row) => within(row).queryByText("outbound_bulk_guard"));
    await user.click(within(guardRow as HTMLElement).getByRole("button", { name: "Change" }));

    const valueSelect = await screen.findByLabelText("New value");
    // The value in force is prefilled rather than typed blind.
    expect(screen.getByLabelText("Value to use")).toHaveValue("rate_limit=10");

    await user.selectOptions(valueSelect, "inherit");
    expect(screen.queryByLabelText("Value to use")).toBeNull();
    await user.selectOptions(valueSelect, "typed");
    const typed = screen.getByLabelText("Value to use");
    await user.clear(typed);
    await user.type(typed, "rate_limit=25");
    await user.type(screen.getByLabelText("Why this change"), "Weekend campaign sends faster");
    await user.click(screen.getByRole("button", { name: "Save change" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/features/outbound_bulk_guard/overrides") &&
          init?.method === "PUT",
      );
      expect(call).toBeTruthy();
      expect(new Headers(call?.[1]?.headers).get("X-Idempotency-Key")).toBeTruthy();
      // Tenant scope travels without a client-supplied customer id; the
      // authenticated session supplies it.
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({
        scope: "tenant",
        value: "typed:rate_limit=25",
        reason: "Weekend campaign sends faster",
        expires_at: null,
      });
    });
    expect(
      await screen.findByText(
        /Outbound bulk sender guardrails is now rate_limit=25, set by this customer/,
      ),
    ).toBeTruthy();
  });
});

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

import { CustomerDetail } from "./CustomerDetail";
import { Customers } from "./Customers";

const customerRow = {
  id: "customer-1",
  display_name: "Acme Corporation",
  internal_key: 42,
  lifecycle: "active",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
  domain_count: 1,
};

const otherCustomer = {
  id: "customer-2",
  display_name: "Globex Inc.",
  internal_key: 43,
  lifecycle: "grace",
  created_at: "2026-02-01T00:00:00Z",
  updated_at: "2026-02-02T00:00:00Z",
  domain_count: 0,
};

const domain = {
  id: "domain-1",
  domain: "mail.acme.test",
  domain_type: "internal",
  verification_status: "pending",
  verification_method: "dns_txt",
  verification_attempts: 1,
  verification_expires_at: null,
  verified_at: null,
  created_at: "2026-01-01T00:00:00Z",
};

const sourceIpGroup = {
  id: "group-1",
  name: "Office network",
  cidrs: ["203.0.113.0/24"],
  created_at: "2026-01-01T00:00:00Z",
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

const adminSession = buildSession(
  ["system_admin"],
  ["admin:customers:view", "admin:customers:manage", "admin:domains:manage"],
);

const entrySession = buildSession(
  ["system_admin"],
  ["admin:customers:view", "admin:customers:manage", "admin:domains:manage", "admin:impersonate"],
);

const customerAdminSession = buildSession(
  ["customer_admin"],
  ["admin:customers:view", "admin:customers:manage", "admin:domains:manage"],
);

const readOnlySession = buildSession(["customer_admin"], ["admin:customers:view"]);

function ok(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    statusText: "OK",
    json: async () => body,
  };
}

function fail(status: number, body: unknown) {
  return {
    ok: false,
    status,
    statusText: "Error",
    json: async () => body,
  };
}

interface StubOptions {
  session: unknown;
  customers?: unknown[];
  listError?: { status: number; code: string; message: string };
  detail?: unknown;
  groups?: unknown[];
  created?: unknown;
  verified?: unknown;
}

function stubFetch(options: StubOptions) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: options.session });
    }
    if (method === "POST" && url.endsWith("/verify")) {
      return ok({ data: options.verified });
    }
    if (method === "POST" && url.endsWith("/admin/customers")) {
      return ok({ data: options.created }, 201);
    }
    if (method === "POST" && url.includes("/admin/impersonations")) {
      return ok({
        data: {
          id: "impersonation-1",
          customerId: "customer-1",
          customerDisplayName: "Acme Corporation",
          reason: "investigating a report",
          startedAt: "2026-09-29T00:00:00Z",
        },
      });
    }
    if (url.includes("/source-ip-groups")) {
      return ok({ data: { groups: options.groups ?? [] } });
    }
    if (url.includes("/admin/customers/customer-1")) {
      return ok({ data: options.detail });
    }
    if (options.listError && url.includes("/admin/customers")) {
      return fail(options.listError.status, {
        code: options.listError.code,
        message: options.listError.message,
      });
    }
    if (url.includes("/admin/customers")) {
      return ok({ data: { customers: options.customers ?? [] } });
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
      path: "/customers",
      component: Customers,
    }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/customers/$customerId",
      component: CustomerDetail,
    }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [entry] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

const hostileDisplayName = `<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>`;
const hostileDomain = `<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>.evil.test`;

type HostileWindow = Window & { __pwned?: number };

function expectLiteralAndNotExecuted(container: HTMLElement, raw: string) {
  expect(container.textContent).toContain(raw);
  expect(container.querySelector('img[src="x"]')).toBeNull();
  expect(container.querySelector("script")).toBeNull();
  expect((window as HostileWindow).__pwned).toBeUndefined();
}

describe("Customers", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("lists customers from the API with lifecycle and domain details", async () => {
    stubFetch({ session: adminSession, customers: [customerRow, otherCustomer] });
    renderAt("/customers");

    const link = await screen.findByRole("link", { name: "Acme Corporation" });
    expect(link).toHaveProperty("href", expect.stringContaining("/customers/customer-1"));
    expect(screen.getByText("customer-1")).toBeTruthy();
    expect(screen.getByText("active")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Globex Inc." })).toBeTruthy();
    expect(screen.getByText("grace")).toBeTruthy();
    expect(screen.getByText("0")).toBeTruthy();
  });

  it("renders a hostile customer display name as literal text without executing it", async () => {
    stubFetch({
      session: adminSession,
      customers: [
        {
          ...customerRow,
          display_name: hostileDisplayName,
        },
      ],
    });
    const { container } = renderAt("/customers");

    const link = await screen.findByRole("link", { name: hostileDisplayName });
    expect(link.textContent).toBe(hostileDisplayName);
    expect(screen.getByText(hostileDisplayName)).toBeTruthy();
    expectLiteralAndNotExecuted(container, hostileDisplayName);
  });

  it("hides the new customer action without admin:customers:manage", async () => {
    stubFetch({ session: readOnlySession, customers: [customerRow] });
    renderAt("/customers");

    await screen.findByRole("link", { name: "Acme Corporation" });
    expect(screen.queryByRole("button", { name: "New customer" })).toBeNull();
  });

  it("creates a customer with an idempotency key and refreshes the list", async () => {
    const fetchMock = stubFetch({
      session: adminSession,
      customers: [customerRow],
      created: { ...customerRow, id: "customer-3", display_name: "New Co" },
    });
    const user = userEvent.setup();
    renderAt("/customers");

    await user.click(await screen.findByRole("button", { name: "New customer" }));
    await user.type(screen.getByLabelText("Display name"), "New Co");
    await user.click(screen.getByRole("button", { name: "Create customer" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith("/admin/customers") && init?.method === "POST",
      );
      expect(call).toBeTruthy();
      const init = call?.[1];
      expect(init?.method).toBe("POST");
      const headers = new Headers(init?.headers);
      expect(headers.get("X-Idempotency-Key")).toBeTruthy();
      expect(JSON.parse(String(init?.body))).toEqual({ display_name: "New Co" });
    });

    await waitFor(() => {
      const listCalls = fetchMock.mock.calls.filter(
        ([input, init]) =>
          String(input).includes("/admin/customers") && (init?.method ?? "GET") === "GET",
      );
      expect(listCalls.length).toBeGreaterThanOrEqual(2);
    });
    await waitFor(() => {
      const dialog = document.querySelector("dialog");
      expect(dialog).not.toBeNull();
      expect(dialog?.open).toBe(false);
    });
  });

  it("shows the safe server message when the list is denied", async () => {
    stubFetch({
      session: adminSession,
      listError: {
        status: 403,
        code: "FORBIDDEN",
        message: "You do not have permission to list customers.",
      },
    });
    renderAt("/customers");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("You do not have permission to list customers.");
  });

  it("offers Enter only for active customers when the actor holds admin:impersonate", async () => {
    stubFetch({ session: entrySession, customers: [customerRow, otherCustomer] });
    renderAt("/customers");

    await screen.findByRole("link", { name: "Acme Corporation" });
    expect(screen.getAllByRole("button", { name: "Enter" })).toHaveLength(1);
  });

  it("hides Enter without admin:impersonate", async () => {
    stubFetch({ session: adminSession, customers: [customerRow] });
    renderAt("/customers");

    await screen.findByRole("link", { name: "Acme Corporation" });
    expect(screen.queryByRole("button", { name: "Enter" })).toBeNull();
  });

  it("requires a reason before entering a customer and posts the customerId", async () => {
    const fetchMock = stubFetch({ session: entrySession, customers: [customerRow] });
    const user = userEvent.setup();
    renderAt("/customers");

    await user.click(await screen.findByRole("button", { name: "Enter" }));
    expect(await screen.findByRole("heading", { name: "Enter Acme Corporation" })).toBeTruthy();
    const enter = screen.getByRole("button", { name: "Enter customer" });
    expect(enter).toBeDisabled();

    const reason = screen.getByLabelText("Reason");
    await user.type(reason, "short");
    expect(enter).toBeDisabled();

    await user.clear(reason);
    await user.type(reason, "investigating a report");
    await waitFor(() => expect(enter).toBeEnabled());
    await user.click(enter);

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([input]) =>
        String(input).includes("/admin/impersonations"),
      );
      expect(call).toBeTruthy();
      const [, init] = call as unknown as [RequestInfo | URL, RequestInit];
      expect(init.method).toBe("POST");
      expect(JSON.parse(String(init.body))).toEqual({
        customerId: "customer-1",
        reason: "investigating a report",
      });
    });
  });
});

describe("CustomerDetail", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("omits the send_only domain type for a customer admin session", async () => {
    stubFetch({
      session: customerAdminSession,
      detail: { ...customerRow, domains: [domain], source_ip_groups: [sourceIpGroup] },
      groups: [sourceIpGroup],
    });
    renderAt("/customers/customer-1");

    await screen.findByRole("heading", { name: "Acme Corporation" });
    const typeSelect = screen.getByLabelText("Domain type");
    expect(within(typeSelect).getByRole("option", { name: "Internal" })).toBeTruthy();
    expect(within(typeSelect).queryByRole("option", { name: "Send only" })).toBeNull();
    expect(screen.queryByLabelText("New lifecycle")).toBeNull();
  });

  it("limits lifecycle transitions to the allowed set for the current lifecycle", async () => {
    stubFetch({
      session: adminSession,
      detail: { ...customerRow, domains: [domain], source_ip_groups: [] },
      groups: [],
    });
    renderAt("/customers/customer-1");

    const lifecycleSelect = await screen.findByLabelText("New lifecycle");
    expect(within(lifecycleSelect).getByRole("option", { name: "grace" })).toBeTruthy();
    expect(within(lifecycleSelect).getByRole("option", { name: "suspended" })).toBeTruthy();
    expect(within(lifecycleSelect).getByRole("option", { name: "terminated" })).toBeTruthy();
    expect(within(lifecycleSelect).queryByRole("option", { name: "active" })).toBeNull();
    expect(screen.getByRole("button", { name: "Apply lifecycle change" })).toBeDisabled();
  });

  it("calls the verify endpoint for a domain that is not verified", async () => {
    const fetchMock = stubFetch({
      session: adminSession,
      detail: { ...customerRow, domains: [domain], source_ip_groups: [] },
      groups: [],
      verified: {
        ...domain,
        verification_status: "verified",
        verified_at: "2026-01-03T00:00:00Z",
      },
    });
    const user = userEvent.setup();
    renderAt("/customers/customer-1");

    await user.click(await screen.findByRole("button", { name: "Verify" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).includes("/domains/domain-1/verify") && init?.method === "POST",
      );
      expect(call).toBeTruthy();
    });
    expect(
      await screen.findByText(/Verification result for mail\.acme\.test: verified/),
    ).toBeTruthy();
  });

  it("renders hostile customer and domain names as literal text without executing them", async () => {
    stubFetch({
      session: adminSession,
      detail: {
        ...customerRow,
        display_name: hostileDisplayName,
        domains: [{ ...domain, domain: hostileDomain }],
        source_ip_groups: [],
      },
      groups: [],
    });
    const { container } = renderAt("/customers/customer-1");

    const heading = await screen.findByRole("heading", { name: hostileDisplayName });
    expect(heading.textContent).toBe(hostileDisplayName);
    expect(screen.getByText(hostileDomain)).toBeTruthy();
    expectLiteralAndNotExecuted(container, hostileDisplayName);
    expectLiteralAndNotExecuted(container, hostileDomain);
  });
});

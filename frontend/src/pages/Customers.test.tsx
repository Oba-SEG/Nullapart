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
  region_code: "ZA",
  sequence_no: 1042,
  lifecycle: "active",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
  domain_count: 1,
};

const otherCustomer = {
  id: "customer-2",
  display_name: "Globex Inc.",
  internal_key: 43,
  region_code: "NG",
  sequence_no: 1043,
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

/**
 * A customer-tier session: the server publishes the tier, and the console places
 * this route as the operator's own organisation instead of the directory.
 * `buildSession` carries no tier, so the directory tests keep their shape.
 */
function tenantSession(permissions: string[]) {
  return {
    ...buildSession(["customer_admin"], permissions),
    tier: "customer",
    customerId: "customer-1",
  };
}

/** What a customer_admin actually gets: the tenant writes are role-blocked. */
const tenantBlocked: StubOptions["blocked"] = [
  "create_customer",
  "change_lifecycle",
  "add_send_only_domain",
];

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
  /** Overrides the published capabilities for one specific gate. */
  blocked?: Array<"create_customer" | "change_lifecycle" | "add_send_only_domain">;
  blocker?: "permission" | "lifecycle" | "deployment" | "role";
}

const allowedCapability = { allowed: true, blocker: null };

/**
 * The stub answers with the same shape the server publishes: the customer list
 * and detail payloads carry the write verdict, so these tests exercise what the
 * console does with it rather than re-deriving roles in the page.
 */
function capabilitiesFor(
  blocked: StubOptions["blocked"] = [],
  blocker: StubOptions["blocker"] = "role",
) {
  const blockedCapability = { allowed: false, blocker };
  return {
    create_customer: blocked?.includes("create_customer") ? blockedCapability : allowedCapability,
    change_lifecycle: blocked?.includes("change_lifecycle") ? blockedCapability : allowedCapability,
    add_send_only_domain: blocked?.includes("add_send_only_domain")
      ? blockedCapability
      : allowedCapability,
  };
}

function stubFetch(options: StubOptions) {
  const capabilities = capabilitiesFor(options.blocked, options.blocker);
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
      return ok({ data: { ...(options.detail as object), capabilities } });
    }
    if (options.listError && url.includes("/admin/customers")) {
      return fail(options.listError.status, {
        code: options.listError.code,
        message: options.listError.message,
      });
    }
    if (url.includes("/admin/customers")) {
      return ok({ data: { customers: options.customers ?? [], capabilities } });
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
    expect(screen.getByText("ZA")).toBeTruthy();
    expect(screen.getByText("NG")).toBeTruthy();
    // "Active" is also a summary label, so the count is what matters: the row
    // renders the human state, never the wire value.
    expect(screen.getAllByText("Active").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole("link", { name: "Globex Inc." })).toBeTruthy();
    expect(screen.getByText("In grace period")).toBeTruthy();
    expect(screen.getByText("0")).toBeTruthy();
    // The wire state never renders on its own.
    expect(screen.queryByText(/^grace$/)).toBeNull();
    expect(screen.queryByText(/^active$/)).toBeNull();
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

  it("hides the new customer action and names the missing permission", async () => {
    stubFetch({
      session: readOnlySession,
      customers: [customerRow],
      blocked: ["create_customer"],
      blocker: "permission",
    });
    renderAt("/customers");

    await screen.findByRole("link", { name: "Acme Corporation" });
    expect(screen.queryByRole("button", { name: "New customer" })).toBeNull();
    expect(
      await screen.findByText(
        /needs the customer management permission, which your roles do not grant/,
      ),
    ).toBeTruthy();
  });

  it("states the role requirement when the server blocks creation at role level", async () => {
    // The mismatch this closes: the session holds admin:customers:manage, so a
    // client-side permission check offered "New customer" while the API refused
    // it. The list now publishes the gate that refused.
    stubFetch({
      session: customerAdminSession,
      customers: [customerRow],
      blocked: ["create_customer"],
      blocker: "role",
    });
    renderAt("/customers");

    await screen.findByRole("link", { name: "Acme Corporation" });
    expect(screen.queryByRole("button", { name: "New customer" })).toBeNull();
    expect(
      await screen.findByText(
        /Creating a customer is reserved for provider-level roles, and yours include neither/,
      ),
    ).toBeTruthy();
  });

  it("offers the new customer action when the server publishes it as allowed", async () => {
    stubFetch({ session: adminSession, customers: [customerRow] });
    renderAt("/customers");

    expect(await screen.findByRole("button", { name: "New customer" })).toBeTruthy();
    expect(document.querySelector(".customers-lock")).toBeNull();
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
  it("renders the organisation surface for a customer session without reading the directory", async () => {
    const fetchMock = stubFetch({
      session: tenantSession(["admin:customers:view", "admin:domains:manage"]),
      detail: { ...customerRow, domains: [domain], source_ip_groups: [sourceIpGroup] },
      groups: [sourceIpGroup],
      blocked: tenantBlocked,
      blocker: "role",
    });
    renderAt("/customers");

    // The record is the operator's own, so the customer name is a section
    // heading: the page already has exactly one h1.
    expect(await screen.findByRole("heading", { name: "Acme Corporation", level: 2 })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Your organisation", level: 1 })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "New customer" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Customers" })).toBeNull();

    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(([input]) =>
          String(input).endsWith("/admin/customers/customer-1"),
        ),
      ).toBe(true);
    });
    // Another customer's name is never fetched into a tenant session.
    const directoryCalls = fetchMock.mock.calls.filter(
      ([input, init]) =>
        String(input).endsWith("/admin/customers") && (init?.method ?? "GET") === "GET",
    );
    expect(directoryCalls).toHaveLength(0);

    expect(screen.getByText("Domains your customer has proved it controls.")).toBeTruthy();

    // Platform-only controls state the gate that withheld them.
    expect(
      await screen.findByText(
        /Changing your customer's lifecycle is reserved for provider-level roles/,
      ),
    ).toBeTruthy();
    expect(screen.queryByLabelText("New lifecycle")).toBeNull();

    // The send-only refusal comes from the published role blocker, and the
    // option itself is absent so the form cannot offer a refused write.
    const typeSelect = screen.getByLabelText("Domain type");
    expect(within(typeSelect).getByRole("option", { name: "Internal" })).toBeTruthy();
    expect(within(typeSelect).queryByRole("option", { name: "Send only" })).toBeNull();
    expect(
      screen.getByText(/Adding a send-only domain is reserved for provider-level roles/),
    ).toBeTruthy();

    // Source IP groups are readable at view permission, writable only at manage.
    expect(await screen.findByText("Office network")).toBeTruthy();
    expect(screen.getByText("203.0.113.0/24")).toBeTruthy();
    expect(
      screen.getByText(
        /Changing your source IP groups needs the admin:customers:manage permission/,
      ),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Add group" })).toBeNull();
  });

  it("keeps the source IP group forms open for a customer session that holds the manage permission", async () => {
    stubFetch({
      session: tenantSession([
        "admin:customers:view",
        "admin:customers:manage",
        "admin:domains:manage",
      ]),
      detail: { ...customerRow, domains: [], source_ip_groups: [] },
      groups: [],
      blocked: tenantBlocked,
      blocker: "role",
    });
    renderAt("/customers");

    expect(await screen.findByRole("button", { name: "Add group" })).toBeTruthy();
    expect(screen.queryByText(/Changing your source IP groups/)).toBeNull();
    expect(
      await screen.findByText(/Adding a send-only domain is reserved for provider-level roles/),
    ).toBeTruthy();
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

  it("omits the send_only domain type and states why, from the published capability", async () => {
    stubFetch({
      session: customerAdminSession,
      detail: { ...customerRow, domains: [domain], source_ip_groups: [sourceIpGroup] },
      groups: [sourceIpGroup],
      blocked: ["change_lifecycle", "add_send_only_domain"],
      blocker: "role",
    });
    renderAt("/customers/customer-1");

    await screen.findByRole("heading", { name: "Acme Corporation" });
    const typeSelect = screen.getByLabelText("Domain type");
    expect(within(typeSelect).getByRole("option", { name: "Internal" })).toBeTruthy();
    expect(within(typeSelect).queryByRole("option", { name: "Send only" })).toBeNull();
    expect(screen.queryByLabelText("New lifecycle")).toBeNull();
    expect(
      screen.getByText(/Adding a send-only domain is reserved for provider-level roles/),
    ).toBeTruthy();
    expect(
      screen.getByText(/Changing this lifecycle is reserved for provider-level roles/),
    ).toBeTruthy();
  });

  it("frames the route as the tenant's own organisation when it names their customer", async () => {
    stubFetch({
      session: tenantSession([
        "admin:customers:view",
        "admin:customers:manage",
        "admin:domains:manage",
      ]),
      detail: { ...customerRow, domains: [domain], source_ip_groups: [sourceIpGroup] },
      groups: [sourceIpGroup],
    });
    renderAt("/customers/customer-1");

    await screen.findByRole("heading", { name: "Acme Corporation" });
    // The same facts, addressed to the owner: the platform framing is a directory
    // affordance, and a tenant reading their own record is not in a directory.
    expect(screen.getByText(/Your provider sets it/)).toBeTruthy();
    expect(screen.getByText(/Your provider assigns it/)).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/the platform (sets|assigns) it/i);
    expect(screen.queryByRole("link", { name: "Customers" })).toBeNull();
  });

  it("keeps the directory framing on the route for a session with no customer scope", async () => {
    stubFetch({
      session: customerAdminSession,
      detail: { ...customerRow, domains: [domain], source_ip_groups: [sourceIpGroup] },
      groups: [sourceIpGroup],
    });
    renderAt("/customers/customer-1");

    await screen.findByRole("heading", { name: "Acme Corporation" });
    expect(screen.getByText(/The platform sets it/)).toBeTruthy();
  });

  it("limits lifecycle transitions to the allowed set for the current lifecycle", async () => {
    stubFetch({
      session: adminSession,
      detail: { ...customerRow, domains: [domain], source_ip_groups: [] },
      groups: [],
    });
    renderAt("/customers/customer-1");

    const lifecycleSelect = await screen.findByLabelText("New lifecycle");
    expect(within(lifecycleSelect).getByRole("option", { name: "In grace period" })).toBeTruthy();
    expect(within(lifecycleSelect).getByRole("option", { name: "Suspended" })).toBeTruthy();
    expect(within(lifecycleSelect).getByRole("option", { name: "Terminated" })).toBeTruthy();
    expect(within(lifecycleSelect).queryByRole("option", { name: "Active" })).toBeNull();
    expect(screen.getByRole("button", { name: "Apply lifecycle change" })).toBeDisabled();
    expect(screen.getByText("Region")).toBeTruthy();
    expect(screen.getByText("ZA")).toBeTruthy();
    expect(screen.getByText("Sequence")).toBeTruthy();
    expect(screen.getByText("1042")).toBeTruthy();
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
    expect(await screen.findByText(/Verification for mail\.acme\.test: Verified/)).toBeTruthy();
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

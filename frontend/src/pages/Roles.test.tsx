import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { Roles } from "./Roles";

const session = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  permissions: ["admin:users:manage", "audit:view"],
  customerId: null,
  expiresAt: "2099-01-01T00:00:00Z",
  stepUpActive: true,
  csrfToken: "csrf-token",
  impersonation: null,
};

const catalog = [
  {
    key: "quarantine:view",
    displayName: "View quarantine",
    description: "Read quarantine items for triage.",
    group: "Quarantine",
  },
  {
    key: "audit:view",
    displayName: "View audit log",
    description: "Read the immutable audit trail.",
    group: "Governance",
  },
];

const roles = [
  {
    roleKey: "system_admin",
    displayName: "System admin",
    description: "Regional platform administration.",
    roleLevel: "system",
    builtin: true,
    permissions: ["quarantine:view", "audit:view"],
    userCount: 2,
  },
  {
    roleKey: "triage_agent",
    displayName: "Triage agent",
    description: null,
    roleLevel: "support",
    builtin: false,
    permissions: ["quarantine:view"],
    userCount: 1,
  },
];

function ok(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    statusText: status === 201 ? "Created" : "OK",
    json: async () => body,
  };
}

interface StubOptions {
  permissions?: string[];
  deleteError?: { status: number; code: string; message: string };
  session?: Record<string, unknown>;
}

function stubFetch(options: StubOptions = {}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "GET" && url.includes("/auth/session")) {
      return ok({
        data: {
          ...session,
          permissions: options.permissions ?? session.permissions,
          ...options.session,
        },
      });
    }
    if (method === "GET" && url.includes("/admin/roles")) {
      return ok({ data: roles });
    }
    if (method === "GET" && url.includes("/admin/permissions")) {
      return ok({ data: catalog });
    }
    if (method === "POST" && url.endsWith("/admin/roles")) {
      return ok({ data: roles[1] }, 201);
    }
    if (method === "DELETE" && url.includes("/admin/roles/")) {
      const failure = options.deleteError;
      if (failure) {
        return {
          ok: false,
          status: failure.status,
          statusText: "Conflict",
          json: async () => ({ code: failure.code, message: failure.message }),
        };
      }
      return ok({ data: { deleted: true } });
    }
    throw new Error(`unexpected fetch ${method} ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <Roles />
    </QueryClientProvider>,
  );
}

describe("Roles", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("renders builtin and custom rows with levels, keys and expandable permissions", async () => {
    stubFetch();
    renderPage();

    expect(await screen.findByText("System admin")).toBeTruthy();
    expect(screen.getByText("Triage agent")).toBeTruthy();
    expect(screen.getByText("triage_agent")).toBeTruthy();
    expect(screen.getByText("Built-in")).toBeTruthy();
    const customRow = screen.getByText("triage_agent").closest("tr")!;
    expect(within(customRow).getByText("Custom")).toBeTruthy();
    expect(screen.getByText("Managed by platform")).toBeTruthy();

    fireEvent.click(screen.getByText("1 permission"));
    const row = screen.getByText("triage_agent").closest("tr")!;
    expect(within(row).getByText("quarantine:view")).toBeTruthy();
  });

  it("hides every management affordance without admin:users:manage", async () => {
    stubFetch({ permissions: [] });
    renderPage();

    expect(await screen.findByText("Triage agent")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "New role" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
  });

  it("shows Edit and Delete only on custom rows", async () => {
    stubFetch();
    renderPage();

    expect(await screen.findByRole("button", { name: "Edit" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Delete" })).toHaveLength(1);
  });

  it("creates a custom role with the contract payload and an idempotency key", async () => {
    const fetchMock = stubFetch();
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "New role" }));
    fireEvent.change(await screen.findByLabelText("Role key"), {
      target: { value: "message_reader" },
    });
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Message reader" },
    });
    fireEvent.change(screen.getByLabelText("Role level"), { target: { value: "support" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /View quarantine/ }));

    expect(screen.getByRole("button", { name: "Create role" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/admin/roles") &&
          String(init?.method ?? "GET").toUpperCase() === "POST",
      );
      expect(call).toBeTruthy();
      const [, init] = call!;
      const headers = new Headers(init?.headers);
      expect(headers.get("X-Idempotency-Key")).toBeTruthy();
      expect(JSON.parse(String(init?.body))).toEqual({
        roleKey: "message_reader",
        displayName: "Message reader",
        roleLevel: "support",
        permissions: ["quarantine:view"],
      });
    });
  });

  it("rejects an invalid role key client-side before any POST is sent", async () => {
    const fetchMock = stubFetch();
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "New role" }));
    fireEvent.change(await screen.findByLabelText("Role key"), { target: { value: "Bad Key!" } });
    fireEvent.change(screen.getByLabelText("Display name"), { target: { value: "Broken" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /View quarantine/ }));

    fireEvent.click(screen.getByRole("button", { name: "Create role" }));

    expect(
      await screen.findByText(/3-64 characters/i, { selector: "[role='alert']" }),
    ).toBeTruthy();
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          String(input).endsWith("/admin/roles") &&
          String(init?.method ?? "GET").toUpperCase() === "POST",
      ),
    ).toBe(false);
  });

  it("states the reserved identity instead of offering a refused role write", async () => {
    stubFetch({
      session: { capabilities: { defineRoles: { allowed: false, blocker: "role" } } },
    });
    renderPage();

    expect(await screen.findByText("Triage agent")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "New role" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(screen.getByText(/Creating or editing a role needs a provider-level role/)).toBeTruthy();
  });

  it("renders the tenant role list as read-only with its own framing", async () => {
    stubFetch({
      permissions: ["admin:users:manage"],
      session: {
        tier: "customer",
        roles: ["customer_admin"],
        customerId: "customer-1",
        capabilities: { defineRoles: { allowed: false, blocker: "role" } },
      },
    });
    renderPage();

    expect(await screen.findByRole("heading", { name: "Your roles" })).toBeTruthy();
    expect(screen.queryByRole("columnheader", { name: "Actions" })).toBeNull();
    expect(screen.queryByRole("button", { name: "New role" })).toBeNull();
    expect(screen.queryByText("Managed by platform")).toBeNull();
    expect(
      screen.getByText(/A role can let you manage your administrators and still not/),
    ).toBeTruthy();
    expect(screen.getByText("Custom roles written by your provider.")).toBeTruthy();
  });

  it("follows the published verdict even for a system session", async () => {
    stubFetch({
      session: { capabilities: { defineRoles: { allowed: false, blocker: "permission" } } },
    });
    renderPage();

    expect(await screen.findByText("Triage agent")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "New role" })).toBeNull();
    expect(
      screen.getByText(
        "Creating or editing a role needs the capability to manage your administrators",
        {
          exact: false,
        },
      ),
    ).toBeTruthy();
  });

  it("surfaces the in-use guidance when the server rejects a delete with ROLE_IN_USE", async () => {
    stubFetch({
      deleteError: {
        status: 409,
        code: "ROLE_IN_USE",
        message: "role is still assigned",
      },
    });
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    expect(await screen.findByRole("heading", { name: "Delete Triage agent" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Delete role" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Role is assigned to users; remove assignments first.");
  });
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { AdminUsers } from "./AdminUsers";

const session = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  permissions: ["admin:users:manage", "audit:view"],
  customerId: "customer-a",
  expiresAt: "2099-01-01T00:00:00Z",
  stepUpActive: true,
  csrfToken: "csrf-token",
  impersonation: null,
};

const users = [
  {
    id: "actor-1",
    login: "admin@example.test",
    displayName: "Admin",
    customerId: null,
    lifecycle: "active",
    roles: ["system_admin"],
  },
  {
    id: "subject-1",
    login: "ca@example.test",
    displayName: "Customer Admin",
    customerId: "customer-a",
    lifecycle: "active",
    roles: ["customer_admin"],
  },
  {
    id: "subject-2",
    login: "resting@example.test",
    displayName: "Resting",
    customerId: "customer-a",
    lifecycle: "suspended",
    roles: ["customer_admin"],
  },
];

const serverRoles = [
  {
    roleKey: "system_admin",
    displayName: "System admin",
    description: "Regional platform administration, full policy visibility.",
    roleLevel: "system",
    builtin: true,
    permissions: ["admin:users:manage", "audit:view"],
    userCount: 1,
  },
  {
    roleKey: "support",
    displayName: "Support",
    description: "Customer administration without message body access.",
    roleLevel: "support",
    builtin: true,
    permissions: ["audit:view"],
    userCount: 0,
  },
  {
    roleKey: "customer_admin",
    displayName: "Customer admin",
    description: "Tenant-scoped administration for a single customer.",
    roleLevel: "customer",
    builtin: true,
    permissions: [],
    userCount: 2,
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

function stubFetch(permissions: string[] = session.permissions) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "GET" && url.includes("/auth/session")) {
      return ok({ data: { ...session, permissions } });
    }
    if (method === "GET" && url.includes("/admin/roles")) {
      return ok({ data: serverRoles });
    }
    if (method === "GET" && url.includes("/admin/users")) {
      return ok({ data: users });
    }
    if (method === "POST" && url.endsWith("/admin/users")) {
      return ok({ data: users[0] }, 201);
    }
    if (method === "POST" && url.includes("/roles")) {
      return ok({ data: { changed: true, roles: ["customer_admin"] } });
    }
    if (method === "DELETE" && url.includes("/roles")) {
      return ok({ data: { changed: true, roles: [] } });
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
      <AdminUsers />
    </QueryClientProvider>,
  );
}

describe("AdminUsers", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("lists administrators without any customer-entry affordance", async () => {
    stubFetch();
    renderPage();

    expect(await screen.findByText("ca@example.test")).toBeTruthy();
    expect(screen.getByText("resting@example.test")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Act as" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Enter" })).toBeNull();
  });

  it("hides role mutation controls without the management permission", async () => {
    stubFetch([]);
    renderPage();

    expect(await screen.findByText("ca@example.test")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "New administrator" })).toBeNull();
    expect(screen.queryAllByRole("button", { name: "Manage roles" })).toHaveLength(0);
  });

  it("creates an administrator with initial roles", async () => {
    const fetchMock = stubFetch();
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "New administrator" }));

    fireEvent.change(await screen.findByLabelText("Login"), {
      target: { value: "new.operator@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "New Operator" },
    });
    fireEvent.click(screen.getByRole("checkbox", { name: /^Customer admin/ }));

    fireEvent.click(screen.getByRole("button", { name: "Create administrator" }));

    await waitFor(() => {
      const createCall = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/admin/users") &&
          String(init?.method ?? "GET").toUpperCase() === "POST",
      );
      expect(createCall).toBeTruthy();
    });
    const [, createInit] = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith("/admin/users") &&
        String(init?.method ?? "GET").toUpperCase() === "POST",
    )!;
    const body = JSON.parse(String(createInit?.body));
    expect(body.login).toBe("new.operator@example.test");
    expect(body.displayName).toBe("New Operator");
    expect(body.roles).toEqual(["customer_admin"]);
  });

  it("grants and revokes roles from the directory", async () => {
    const fetchMock = stubFetch();
    renderPage();

    const manageButtons = await screen.findAllByRole("button", { name: "Manage roles" });
    fireEvent.click(manageButtons[0]!);

    fireEvent.click(await screen.findByRole("checkbox", { name: /Support/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /System admin/ }));

    expect(screen.getByText("Pending changes")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Save role changes" }));

    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            String(input).includes("/admin/users/actor-1/roles") &&
            String(init?.method ?? "GET").toUpperCase() === "POST",
        ),
      ).toBe(true);
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            String(input).includes("/admin/users/actor-1/roles/system_admin") &&
            String(init?.method ?? "GET").toUpperCase() === "DELETE",
        ),
      ).toBe(true);
    });
  });
});

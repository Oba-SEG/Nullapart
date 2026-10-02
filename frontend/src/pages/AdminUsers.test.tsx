import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

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

function ok(body: unknown) {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => body,
  };
}

function stubFetch() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/auth/session")) {
      return ok({ data: session });
    }
    if (url.includes("/admin/users")) {
      return ok({ data: users });
    }
    throw new Error(`unexpected fetch ${url}`);
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
  it("lists administrators without any customer-entry affordance", async () => {
    stubFetch();
    renderPage();

    expect(await screen.findByText("ca@example.test")).toBeTruthy();
    expect(screen.getByText("resting@example.test")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Act as" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Enter" })).toBeNull();
  });
});

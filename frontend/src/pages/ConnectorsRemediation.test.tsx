import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ConnectorsRemediation } from "./ConnectorsRemediation";

const managerSession = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  permissions: ["connectors:view", "connectors:manage"],
  customerId: "CZA-1",
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
};

const baseSnapshot = {
  deployment_id: "LOCAL-TEST",
  generated_at: "2026-01-08T10:00:00Z",
  summary: {
    active_connectors: 1,
    degraded_connectors: 0,
    directory_sync_enabled: 1,
    mailbox_search_enabled: 1,
    retro_remediation_enabled: 1,
    pending_remediations: 1,
    manual_action_required: 0,
    failed_operations: 0,
  },
  connectors: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      provider: "microsoft_365",
      display_name: "Microsoft 365 ZA",
      external_tenant_id_hash: "tenant_hash_123456",
      status: "active",
      auth_state: "healthy",
      token_expires_at: null,
      last_directory_sync_at: "2026-01-08T09:00:00Z",
      last_directory_sync_status: "succeeded",
      last_mailbox_search_at: null,
      last_remediation_at: null,
      updated_at: "2026-01-08T09:00:00Z",
      capabilities: [
        {
          capability: "directory_sync",
          enabled: true,
          granted_scopes: ["User.Read.All"],
          reason: "Directory validation",
          updated_at: "2026-01-08T09:00:00Z",
        },
        {
          capability: "mailbox_search",
          enabled: true,
          granted_scopes: ["Mail.Read"],
          reason: "Mailbox search",
          updated_at: "2026-01-08T09:00:00Z",
        },
      ],
    },
  ],
  directory_sync_runs: [
    {
      id: "22222222-2222-2222-2222-222222222222",
      connector_id: "11111111-1111-1111-1111-111111111111",
      provider: "microsoft_365",
      display_name: "Microsoft 365 ZA",
      state: "succeeded",
      started_at: "2026-01-08T09:00:00Z",
      completed_at: "2026-01-08T09:01:00Z",
      users_seen: 10,
      groups_seen: 2,
      aliases_seen: 4,
      vip_candidates: 1,
      error_code: null,
      error_summary: null,
    },
  ],
  mailbox_searches: [],
  remediation_actions: [
    {
      id: "33333333-3333-3333-3333-333333333333",
      connector_id: "11111111-1111-1111-1111-111111111111",
      provider: "microsoft_365",
      action_type: "move_to_quarantine",
      state: "pending",
      provider_outcome_code: null,
      error_summary: null,
      reason: "Post delivery threat remediation",
      created_at: "2026-01-08T09:10:00Z",
      updated_at: "2026-01-08T09:10:00Z",
    },
  ],
  audit_history: [],
};

type MutationPath = "/connectors-remediation/connectors" | "/connectors-remediation/remediations";

function mockFetch(snapshot = baseSnapshot, options: { stepUpPath?: MutationPath } = {}) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.endsWith("/auth/session")) {
      return Response.json({ data: managerSession });
    }
    if (method === "POST" && options.stepUpPath && url.endsWith(options.stepUpPath)) {
      expect(init?.headers).toEqual(
        expect.objectContaining({
          "X-Idempotency-Key": expect.any(String),
          "X-CSRF-Token": "csrf-token",
        }),
      );
      return Response.json(
        { code: "STEP_UP_REQUIRED", message: "Step-up authentication is required" },
        { status: 403 },
      );
    }
    if (method === "POST" && url.endsWith("/connectors-remediation/connectors")) {
      expect(init?.headers).toEqual(
        expect.objectContaining({
          "X-Idempotency-Key": expect.any(String),
          "X-CSRF-Token": "csrf-token",
        }),
      );
      return Response.json({ data: { id: "connector-id", changed: true } });
    }
    if (method === "POST" && url.endsWith("/connectors-remediation/remediations")) {
      expect(init?.headers).toEqual(
        expect.objectContaining({
          "X-Idempotency-Key": expect.any(String),
          "X-CSRF-Token": "csrf-token",
        }),
      );
      return Response.json({ data: { remediation_id: "rid", mailbox_search_id: "sid" } });
    }
    if (url.includes("/connectors-remediation")) {
      return Response.json({ data: snapshot });
    }
    return Response.json({ data: {} });
  });
}

function renderAt(path = "/connectors-remediation") {
  const rootRoute = createRootRoute({ component: Outlet });
  const route = createRoute({
    getParentRoute: () => rootRoute,
    path: "/connectors-remediation",
    component: ConnectorsRemediation,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([route]),
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("ConnectorsRemediation", () => {
  it("renders connector capabilities without provider tokens", async () => {
    vi.stubGlobal("fetch", mockFetch());
    renderAt();
    expect(await screen.findByText("Connectors & remediation")).toBeTruthy();
    expect(screen.getAllByText("Microsoft 365 ZA").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Directory sync").length).toBeGreaterThan(0);
    expect(screen.getByText(/credentials: Credentials valid/)).toBeTruthy();
    expect(screen.getByText("Recorded, not yet run")).toBeTruthy();
    expect(screen.getByText(/Succeeded · users/)).toBeTruthy();
    expect(screen.getAllByText("Move to quarantine").length).toBeGreaterThan(1);
    expect(screen.queryByText("pending")).toBeNull();
    expect(screen.queryByText(/refresh token/i)).toBeNull();
  });

  it("posts connector updates with idempotency and csrf", async () => {
    const fetchMock = mockFetch();
    vi.stubGlobal("fetch", fetchMock);
    renderAt();
    await screen.findByText("Save connector");
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Display name"), "Google Workspace ZA");
    await user.type(screen.getByLabelText("External account ID"), "tenant_hash_abcdef");
    await user.type(screen.getByLabelText("Credential reference hash"), "credential_hash_abcdef");
    await user.clear(screen.getByLabelText("Directory scopes"));
    await user.type(screen.getByLabelText("Directory scopes"), "User.Read.All");
    await user.type(
      screen.getAllByLabelText("Reason")[0],
      "Directory sync for address validation.",
    );
    await user.click(screen.getByText("Save connector"));
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            String(input).endsWith("/connectors-remediation/connectors") && init?.method === "POST",
        ),
      ).toBe(true);
    });
  });

  it("posts remediation intent with idempotency and csrf", async () => {
    const fetchMock = mockFetch();
    vi.stubGlobal("fetch", fetchMock);
    renderAt();
    await screen.findByText("Record remediation intent");
    const user = userEvent.setup();
    await user.selectOptions(
      screen.getByLabelText("Connector"),
      "11111111-1111-1111-1111-111111111111",
    );
    await user.type(screen.getByLabelText("Message ID"), "44444444-4444-4444-4444-444444444444");
    await user.type(screen.getByLabelText("Mailbox address hash"), "mailbox_hash_abcdef");
    await user.type(screen.getByLabelText("Provider message hash"), "provider_hash_abcdef");
    await user.type(screen.getAllByLabelText("Reason")[1], "Post delivery threat remediation.");
    await user.click(screen.getByText("Record remediation intent"));
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            String(input).endsWith("/connectors-remediation/remediations") &&
            init?.method === "POST",
        ),
      ).toBe(true);
    });
  });

  it("prefills the connector form for editing and rewrites the record", async () => {
    const fetchMock = mockFetch();
    vi.stubGlobal("fetch", fetchMock);
    renderAt();
    await screen.findByText("Save connector");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Edit capability" }));

    expect(screen.getByRole("heading", { name: "Update connector capability" })).toBeTruthy();
    expect(screen.getByLabelText("Display name")).toHaveValue("Microsoft 365 ZA");
    expect(screen.getByLabelText("Directory scopes")).toHaveValue("User.Read.All");
    expect(screen.getByLabelText("Mailbox search scopes")).toHaveValue("Mail.Read");

    await user.type(screen.getByLabelText("Credential reference hash"), "credential_hash_abcdef");
    await user.type(
      screen.getAllByLabelText("Reason")[0],
      "Rotated credential reference and confirmed scopes.",
    );
    await user.click(screen.getByRole("button", { name: "Update connector" }));

    await waitFor(() => {
      const editCall = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/connectors-remediation/connectors") && init?.method === "POST",
      );
      expect(editCall).toBeTruthy();
      const body = JSON.parse(String(editCall?.[1]?.body));
      expect(body.display_name).toBe("Microsoft 365 ZA");
      expect(body.external_tenant_id_hash).toBe("tenant_hash_123456");
      expect(body.capabilities[0].granted_scopes).toEqual(["User.Read.All"]);
      expect(body.capabilities[1].granted_scopes).toEqual(["Mail.Read"]);
      expect(body.capabilities[2].enabled).toBe(false);
    });
  });

  it("records the remediation purpose with the request", async () => {
    const fetchMock = mockFetch();
    vi.stubGlobal("fetch", fetchMock);
    renderAt();
    await screen.findByText("Record remediation intent");
    const user = userEvent.setup();
    await user.selectOptions(
      screen.getByLabelText("Connector"),
      "11111111-1111-1111-1111-111111111111",
    );
    await user.type(screen.getByLabelText("Message ID"), "44444444-4444-4444-4444-444444444444");
    await user.type(screen.getByLabelText("Mailbox address hash"), "mailbox_hash_abcdef");
    await user.selectOptions(screen.getByLabelText("Purpose"), "customer_reported_phishing");
    await user.type(screen.getAllByLabelText("Reason")[1], "Customer reported the message.");
    await user.click(screen.getByText("Record remediation intent"));
    await waitFor(() => {
      const remediationCall = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/connectors-remediation/remediations") && init?.method === "POST",
      );
      expect(remediationCall).toBeTruthy();
      expect(JSON.parse(String(remediationCall?.[1]?.body)).purpose).toBe(
        "customer_reported_phishing",
      );
    });
  });

  it("surfaces the step-up re-auth prompt when connector save is rejected", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch(baseSnapshot, { stepUpPath: "/connectors-remediation/connectors" }),
    );
    renderAt();
    await screen.findByText("Save connector");
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Display name"), "Google Workspace ZA");
    await user.type(screen.getByLabelText("External account ID"), "tenant_hash_abcdef");
    await user.type(screen.getByLabelText("Credential reference hash"), "credential_hash_abcdef");
    await user.type(
      screen.getAllByLabelText("Reason")[0],
      "Directory sync for address validation.",
    );
    await user.click(screen.getByText("Save connector"));
    expect(await screen.findByText("Re-authentication is required for this action.")).toBeTruthy();
    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
  });

  it("surfaces the step-up re-auth prompt when a remediation request is rejected", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch(baseSnapshot, { stepUpPath: "/connectors-remediation/remediations" }),
    );
    renderAt();
    await screen.findByText("Record remediation intent");
    const user = userEvent.setup();
    await user.selectOptions(
      screen.getByLabelText("Connector"),
      "11111111-1111-1111-1111-111111111111",
    );
    await user.type(screen.getByLabelText("Message ID"), "44444444-4444-4444-4444-444444444444");
    await user.type(screen.getByLabelText("Mailbox address hash"), "mailbox_hash_abcdef");
    await user.type(screen.getAllByLabelText("Reason")[1], "Post delivery threat remediation.");
    await user.click(screen.getByText("Record remediation intent"));
    expect(await screen.findByText("Re-authentication is required for this action.")).toBeTruthy();
    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
  });
});

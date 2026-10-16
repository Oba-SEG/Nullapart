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

import { Operations } from "./Operations";

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

const managerSession = buildSession(["system_admin"], ["operations:view", "operations:manage"]);
const viewerSession = buildSession(["support"], ["operations:view"]);

const baseSnapshot = {
  deployment_id: "dep-1",
  config: {
    db_revision: 12,
    scopes: [
      {
        scope: "system",
        scope_id: "system",
        revision_number: 4,
        published_by: "ops@example.test",
        published_at: "2026-01-05T10:00:00Z",
      },
      {
        scope: "tenant",
        scope_id: "customer-with-a-very-long-identifier",
        revision_number: 7,
        published_by: "admin@example.test",
        published_at: "2026-01-06T10:00:00Z",
      },
    ],
  },
  nodes: [
    {
      id: "mx-1",
      node_type: "mail",
      role: "mx",
      status: "active",
      hostname: "mx-1.example.test",
      version: "1.4.0",
      config_revision: 12,
      last_health_check: "2026-01-06T09:59:00Z",
      stale: true,
    },
    {
      id: "scan-1",
      node_type: "scanner",
      role: "scanner",
      status: "draining",
      hostname: null,
      version: "1.4.0",
      config_revision: 11,
      last_health_check: null,
      stale: false,
    },
    {
      id: "core-1",
      node_type: "control",
      role: "control",
      status: "offline",
      hostname: "core-1.example.test",
      version: "1.4.0",
      config_revision: null,
      last_health_check: "2026-01-06T09:58:00Z",
      stale: null,
    },
  ],
  outbox: { unpublished_count: 3, oldest_unpublished_age_seconds: 300 },
  dead_letters: { count: 1 },
  scanner: { total: 4, active: 2, draining: 1, offline: 1 },
  smtp: {
    commissioning: "not_configured",
    detail: "No commissioned SMTP identity is recorded for this deployment.",
  },
};

const baseHardening = {
  deployment_id: "dep-1",
  generated_at: "2026-01-06T10:00:00Z",
  summary: {
    tier3_capabilities: 2,
    capabilities_tested: 0,
    alert_rules: 3,
    enabled_alert_rules: 0,
    automation_categories: 1,
    automation_categories_ready: 0,
    readiness_ready: 1,
    readiness_partial: 2,
    readiness_not_ready: 1,
    readiness_blocked: 0,
  },
  tier3_capabilities: [
    {
      capability_id: "inbound_smtp_acceptance",
      display_name: "Inbound SMTP acceptance",
      owner: "mail-operations",
      sli: "Eligible SMTP sessions receive a correct response.",
      slo_target: "99.95% monthly design target",
      error_budget: "0.05% monthly",
      measurement_source: "Postfix and Mail Core telemetry",
      rto_minutes: 30,
      rpo_minutes: 5,
      dependency_map: "MX node, queue, Mail Core, PostgreSQL",
      redundancy_design: "Multiple commissioned MX nodes before production.",
      degraded_mode: "Temporary defer before unsafe overload.",
      capacity_threshold: "Queue depth and oldest age.",
      runbook: "docs/runbooks/PHASE9-OPERATIONS-HARDENING.md",
      readiness_state: "defined",
      last_exercise_at: null,
      updated_at: "2026-01-06T10:00:00Z",
    },
    {
      capability_id: "audit_persistence",
      display_name: "Audit persistence",
      owner: "security-operations",
      sli: "High-risk mutations commit durable audit records or fail closed.",
      slo_target: "100% by design",
      error_budget: "0 accepted unaudited mutations",
      measurement_source: "Audit events and checkpoint metadata",
      rto_minutes: 30,
      rpo_minutes: 1,
      dependency_map: "PostgreSQL audit_events and checkpoint path",
      redundancy_design: "Durable database and archive before production.",
      degraded_mode: "Mutation fails closed if audit cannot persist.",
      capacity_threshold: "Audit insert failures and checkpoint staleness.",
      runbook: "docs/runbooks/PHASE9-OPERATIONS-HARDENING.md",
      readiness_state: "instrumented",
      last_exercise_at: null,
      updated_at: "2026-01-06T10:00:00Z",
    },
  ],
  alert_rules: [
    {
      alert_key: "inbound_smtp_acceptance:fast-burn",
      capability_id: "inbound_smtp_acceptance",
      severity: "page",
      burn_rate: "14.40",
      long_window_minutes: 60,
      short_window_minutes: 5,
      threshold_description: "Page when both 1h and 5m windows burn at 14.4x.",
      owner: "mail-operations",
      runbook: "docs/runbooks/PHASE9-OPERATIONS-HARDENING.md",
      suppression: "Approved maintenance only.",
      escalation: "Primary on-call, then platform lead.",
      enabled: false,
      last_tested_at: null,
    },
  ],
  automation_categories: [
    {
      category_id: "critical_threat_incident",
      display_name: "Critical threat incident",
      destination: "clickup",
      severity: "page",
      owner: "security-operations",
      minimized_metadata: "deployment, customer scope, threat class and bounded evidence ids",
      deduplication_key: "deployment:customer:threat_class:rolling_1h",
      aggregation_window_minutes: 60,
      delivery_mode: "outbox_sqs_worker",
      blocks_mail_delivery: false,
      runbook: "docs/runbooks/PHASE9-OPERATIONS-HARDENING.md",
      readiness_state: "defined",
      updated_at: "2026-01-06T10:00:00Z",
    },
  ],
  readiness_checks: [
    {
      check_id: "tier3_slo_alerts",
      category: "reliability",
      title: "Tier-3 SLO/error-budget/burn-rate alerting active",
      status: "partial",
      owner: "platform-operations",
      evidence_ref: "docs/compliance/08-TIER3-SLO-EVIDENCE.md",
      runbook: "docs/runbooks/PHASE9-OPERATIONS-HARDENING.md",
      last_verified_at: null,
      notes: "Rules are defined but not enabled until monitoring is live.",
    },
    {
      check_id: "zero_day_exercise",
      category: "zero_day",
      title: "Zero-day parser/dependency exercise completed",
      status: "not_ready",
      owner: "security-operations",
      evidence_ref: "docs/compliance/15-ZERO-DAY-TABLETOP-TEMPLATE.md",
      runbook: "docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md",
      last_verified_at: null,
      notes: "Exercise evidence is required before production readiness.",
    },
  ],
};

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
  snapshot?: unknown;
  hardening?: unknown;
  snapshotError?: { status: number; code: string; message: string };
  hardeningError?: { status: number; code: string; message: string };
  refreshResult?: unknown;
  refreshError?: { status: number; code: string; message: string };
}

function stubFetch(options: StubOptions) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: options.session });
    }
    if (method === "POST" && url.endsWith("/operations/refresh")) {
      if (options.refreshError) {
        return fail(options.refreshError.status, {
          code: options.refreshError.code,
          message: options.refreshError.message,
        });
      }
      return ok({ data: options.refreshResult }, 201);
    }
    if (options.snapshotError && url.includes("/operations/runtime")) {
      return fail(options.snapshotError.status, {
        code: options.snapshotError.code,
        message: options.snapshotError.message,
      });
    }
    if (options.hardeningError && url.includes("/operations/hardening")) {
      return fail(options.hardeningError.status, {
        code: options.hardeningError.code,
        message: options.hardeningError.message,
      });
    }
    if (url.includes("/operations/runtime")) {
      return ok({ data: options.snapshot ?? baseSnapshot });
    }
    if (url.includes("/operations/hardening")) {
      return ok({ data: options.hardening ?? baseHardening });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderAt(entry: string) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({ getParentRoute: () => rootRoute, path: "/operations", component: Operations }),
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

function rowFor(text: string): HTMLElement {
  const cell = screen.getByText(text);
  const row = cell.closest("tr");
  if (!row) throw new Error(`no table row found for ${text}`);
  return row;
}

async function openNodeRefresh(user: ReturnType<typeof userEvent.setup>, nodeId: string) {
  await user.click(await screen.findByRole("button", { name: "Refresh" }));
  await user.selectOptions(await screen.findByLabelText("Target"), "node");
  await user.type(screen.getByLabelText("Node id"), nodeId);
}

describe("Operations", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("renders the snapshot summary values", async () => {
    stubFetch({ session: managerSession, snapshot: baseSnapshot });
    renderAt("/operations");

    await screen.findByRole("heading", { name: "Runtime operations" });
    const summary = await screen.findByRole("region", { name: "Runtime summary" });
    expect(within(summary).getByText("DB config revision")).toBeTruthy();
    expect(within(summary).getByText("12")).toBeTruthy();
    expect(within(summary).getByText("3 unpublished · oldest 5m")).toBeTruthy();
    expect(within(summary).getByText("Dead letters")).toBeTruthy();
    expect(within(summary).getByText("1")).toBeTruthy();
    expect(within(summary).getByText("Scanner nodes")).toBeTruthy();
    expect(within(summary).getByText("2/4")).toBeTruthy();
  });

  it("renders Phase 9 hardening evidence without claiming production readiness", async () => {
    stubFetch({ session: managerSession, snapshot: baseSnapshot, hardening: baseHardening });
    renderAt("/operations");

    const summary = await screen.findByRole("region", { name: "Phase 9 hardening summary" });
    expect(within(summary).getByText("Tier-3 capabilities")).toBeTruthy();
    expect(within(summary).getByText("2")).toBeTruthy();
    expect(within(summary).getByText("Enabled burn alerts")).toBeTruthy();
    expect(within(summary).getByText("0/3")).toBeTruthy();
    expect(within(summary).getByText("Automation ready")).toBeTruthy();
    expect(within(summary).getByText("0/1")).toBeTruthy();
    expect(within(summary).getByText("Readiness ready")).toBeTruthy();
    expect(within(summary).getByText("Not ready")).toBeTruthy();
    expect(summary).toHaveTextContent("Readiness ready1");
    expect(summary).toHaveTextContent("Not ready1");

    const tier3 = await screen.findByRole("region", { name: "Tier-3 SLO capabilities" });
    expect(within(tier3).getByText("Inbound SMTP acceptance")).toBeTruthy();
    expect(within(tier3).getByText("99.95% monthly design target")).toBeTruthy();
    expect(within(tier3).getByText("Rules defined")).toBeTruthy();

    const alerts = await screen.findByRole("region", { name: "Burn-rate alert rules" });
    expect(within(alerts).getByText("inbound_smtp_acceptance:fast-burn")).toBeTruthy();
    expect(within(alerts).getByText("14.40x")).toBeTruthy();
    expect(within(alerts).getByText("Not ready")).toBeTruthy();
    expect(within(alerts).getByText("Pages on-call")).toBeTruthy();

    const automation = await screen.findByRole("region", {
      name: "Durable automation categories",
    });
    expect(within(automation).getByText("Critical threat incident")).toBeTruthy();
    expect(within(automation).getByText("ClickUp")).toBeTruthy();
    expect(
      within(automation).getByText("deployment:customer:threat_class:rolling_1h"),
    ).toBeTruthy();

    const readiness = await screen.findByRole("region", {
      name: "Production-readiness evidence",
    });
    expect(
      within(readiness).getByText("Zero-day parser/dependency exercise completed"),
    ).toBeTruthy();
    expect(within(readiness).getByText("Not ready")).toBeTruthy();
  });

  it("labels each readiness status and keeps its evidence linkable", async () => {
    stubFetch({ session: managerSession, snapshot: baseSnapshot, hardening: baseHardening });
    renderAt("/operations");

    const readiness = await screen.findByRole("region", {
      name: "Production-readiness evidence",
    });

    const partialRow = rowFor("Tier-3 SLO/error-budget/burn-rate alerting active");
    expect(within(partialRow).getByText("Partly working")).toBeTruthy();
    expect(within(partialRow).getByText("docs/compliance/08-TIER3-SLO-EVIDENCE.md")).toBeTruthy();

    const notReadyRow = rowFor("Zero-day parser/dependency exercise completed");
    expect(within(notReadyRow).getByText("Not ready")).toBeTruthy();
    expect(
      within(notReadyRow).getByText("docs/compliance/15-ZERO-DAY-TABLETOP-TEMPLATE.md"),
    ).toBeTruthy();

    // The page must never upgrade a partial/not-ready row to a ready badge.
    expect(within(partialRow).queryByText("Ready")).toBeNull();
    expect(within(notReadyRow).queryByText("Ready")).toBeNull();
    expect(readiness).not.toHaveTextContent("production ready");
  });

  it("renders stale badges for nodes and unknown freshness as muted", async () => {
    stubFetch({ session: managerSession, snapshot: baseSnapshot });
    renderAt("/operations");

    await screen.findByRole("region", { name: "Nodes" });
    expect(within(rowFor("mx-1")).getByText("Stale config")).toBeTruthy();
    expect(within(rowFor("scan-1")).getByText("Current")).toBeTruthy();
    expect(within(rowFor("core-1")).getByText("Unknown")).toBeTruthy();
    expect(within(rowFor("scan-1")).getByText("Never checked")).toBeTruthy();
  });

  it("describes each node in operator terms, not its stored tokens", async () => {
    stubFetch({ session: managerSession, snapshot: baseSnapshot });
    renderAt("/operations");

    await screen.findByRole("region", { name: "Nodes" });
    expect(within(rowFor("mx-1")).getByText("Mail node")).toBeTruthy();
    expect(within(rowFor("mx-1")).getByText("Receives inbound mail")).toBeTruthy();
    expect(within(rowFor("scan-1")).getByText("Draining: no new work")).toBeTruthy();
    expect(within(rowFor("core-1")).getByText("Serves the console and APIs")).toBeTruthy();
    expect(within(rowFor("core-1")).queryByText("control")).toBeNull();
  });

  it("renders an honest empty state when no nodes are registered", async () => {
    stubFetch({ session: managerSession, snapshot: { ...baseSnapshot, nodes: [] } });
    renderAt("/operations");

    const nodes = await screen.findByRole("region", { name: "Nodes" });
    expect(within(nodes).queryByRole("table")).toBeNull();
    expect(within(nodes).getByText(/No nodes are registered/)).toBeTruthy();
    expect(screen.queryByText("mx-1")).toBeNull();
  });

  it("hides the refresh action without operations:manage", async () => {
    stubFetch({ session: viewerSession, snapshot: baseSnapshot });
    renderAt("/operations");

    await screen.findByRole("heading", { name: "Runtime operations" });
    expect(screen.queryByRole("button", { name: "Refresh" })).toBeNull();
    expect(screen.getByRole("button", { name: "Reload" })).toBeTruthy();
  });

  it("posts a node refresh with an idempotency key and reloads the snapshot", async () => {
    const fetchMock = stubFetch({
      session: managerSession,
      snapshot: baseSnapshot,
      refreshResult: {
        requested_at: "2026-01-06T10:00:00Z",
        target: "node",
        scope_id: "mx-1",
      },
    });
    const user = userEvent.setup();
    renderAt("/operations");
    await screen.findByRole("heading", { name: "Runtime operations" });
    const initialReads = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes("/operations/runtime"),
    ).length;

    await openNodeRefresh(user, "mx-1");
    await user.click(screen.getByRole("button", { name: "Confirm refresh" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith("/operations/refresh") && init?.method === "POST",
      );
      expect(call).toBeTruthy();
      const headers = new Headers(call?.[1]?.headers);
      expect(headers.get("X-Idempotency-Key")).toBeTruthy();
      const body = JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>;
      expect(body).toEqual({ target: "node", node_id: "mx-1" });
    });

    expect(await screen.findByText(/Refresh requested for mx-1/)).toBeTruthy();
    await waitFor(() => {
      const reads = fetchMock.mock.calls.filter(([input]) =>
        String(input).includes("/operations/runtime"),
      ).length;
      expect(reads).toBeGreaterThan(initialReads);
    });
  });

  it("rejects an invalid node id inline without posting", async () => {
    const fetchMock = stubFetch({ session: managerSession, snapshot: baseSnapshot });
    const user = userEvent.setup();
    renderAt("/operations");
    await screen.findByRole("heading", { name: "Runtime operations" });

    await openNodeRefresh(user, "not a node");
    await user.click(screen.getByRole("button", { name: "Confirm refresh" }));

    const error = await screen.findByRole("alert");
    expect(error).toHaveTextContent(/letters, digits, dot, underscore or hyphen/);
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
    expect(screen.getByRole("button", { name: "Confirm refresh" })).toBeTruthy();
  });

  it("surfaces an unknown node as Node was not found", async () => {
    stubFetch({
      session: managerSession,
      snapshot: baseSnapshot,
      refreshError: { status: 404, code: "NOT_FOUND", message: "Node does not exist" },
    });
    const user = userEvent.setup();
    renderAt("/operations");
    await screen.findByRole("heading", { name: "Runtime operations" });

    await openNodeRefresh(user, "ghost-1");
    await user.click(screen.getByRole("button", { name: "Confirm refresh" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Node was not found");
  });

  it("offers step-up re-authentication when the refresh requires it", async () => {
    stubFetch({
      session: managerSession,
      snapshot: baseSnapshot,
      refreshError: {
        status: 403,
        code: "STEP_UP_REQUIRED",
        message: "Step-up authentication is required",
      },
    });
    const user = userEvent.setup();
    renderAt("/operations");
    await screen.findByRole("heading", { name: "Runtime operations" });

    await openNodeRefresh(user, "mx-1");
    await user.click(screen.getByRole("button", { name: "Confirm refresh" }));

    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
    expect(screen.getByText("Re-authentication is required for this action.")).toBeTruthy();
  });
});

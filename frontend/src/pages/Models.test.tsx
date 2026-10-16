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

import { metricFieldError, Models } from "./Models";

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

const managerSession = buildSession(["system_admin"], ["models:view", "models:manage"]);
const viewerSession = buildSession(["support"], ["models:view"]);

const baseModel = {
  id: "model-row-1",
  model_id: "multilabel-v1",
  model_version: "1",
  input_schema_version: 1,
  training_dataset_version: "multilabel-v1",
  code_commit: "18015b5",
  metrics: {
    macro_f1: 0.9862,
    macro_roc_auc: 1,
    ham_false_positive_rate: 0.0042,
    latency_p95_ms: 41.01,
  },
  artifact_uri: "ml/inline/checkpoints/multilabel-v1/onnx/model_int8.onnx",
  artifact_sha256: "a".repeat(64),
  deployment_regions: ["local"],
  approved_by: null,
  approved_at: null,
  approval_note: null,
  activated_by: null,
  activated_at: null,
  deactivated_by: null,
  deactivated_at: null,
  deactivation_reason: null,
  rollback_model_id: null,
  rollback_model_version: null,
  registered_by: "actor-1",
  registered_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-10-01T00:00:00Z",
};

const pendingModel = { ...baseModel, approval_state: "pending" as const };

const activeModel = {
  ...baseModel,
  id: "model-row-0",
  model_version: "0",
  approval_state: "approved" as const,
  approved_by: "actor-1",
  approved_at: "2026-10-01T01:00:00Z",
  activated_at: "2026-10-01T02:00:00Z",
  activated_by: "actor-1",
  rollback_model_id: null,
  rollback_model_version: null,
};

const approvedCandidateWithTarget = {
  ...baseModel,
  approval_state: "approved" as const,
  approved_by: "actor-1",
  approved_at: "2026-10-01T01:00:00Z",
};

const activeModelWithRollbackTarget = {
  ...activeModel,
  rollback_model_id: "multilabel-v1",
  rollback_model_version: "1",
};

function ok(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    statusText: "OK",
    json: async () => body,
  };
}

interface StubOptions {
  session: unknown;
  models: unknown[];
}

function stubFetch(options: StubOptions) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: options.session });
    }
    if (url.includes("/shadow-evaluations")) {
      return ok({ data: { evaluations: [] } });
    }
    if (method === "POST" && url.endsWith("/approve")) {
      return ok({ data: { ...pendingModel, approval_state: "approved" } });
    }
    if (method === "POST" && url.endsWith("/activate")) {
      return ok({ data: activeModel });
    }
    if (method === "POST" && url.endsWith("/rollback")) {
      return ok({ data: activeModel });
    }
    if (method === "POST" && url.endsWith("/reject")) {
      return ok({ data: { ...pendingModel, approval_state: "rejected" } });
    }
    if (method === "POST" && url.endsWith("/admin/models")) {
      return ok({ data: pendingModel }, 201);
    }
    if (method === "GET" && url.endsWith("/admin/models")) {
      return ok({ data: { models: options.models } });
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
      path: "/models",
      component: Models,
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

type FetchCall = [input: RequestInfo | URL, init?: RequestInit];
function idempotencyKeyOf(call: FetchCall): string | undefined {
  return (call[1]?.headers as Record<string, string> | undefined)?.["X-Idempotency-Key"];
}

beforeAll(() => {
  // Dialog uses <dialog>.showModal; jsdom needs the method stubbed.
  if (!HTMLDialogElement.prototype.showModal) {
    Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
      configurable: true,
      value() {
        this.open = true;
      },
    });
  }
  if (!HTMLDialogElement.prototype.close) {
    Object.defineProperty(HTMLDialogElement.prototype, "close", {
      configurable: true,
      value() {
        this.open = false;
      },
    });
  }
});

describe("Models", () => {
  it("lists registered models and reports the active runtime", async () => {
    const fetchMock = stubFetch({ session: managerSession, models: [activeModel, pendingModel] });
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    const chip = (await screen.findByText("Active runtime")).parentElement;
    expect(chip?.textContent).toContain("multilabel-v1/0");
    expect(
      screen.getAllByRole("heading", { level: 2, name: /multilabel-v1/ }).length,
    ).toBeGreaterThan(0);
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/admin/models"))).toBe(
      true,
    );
  });

  it("explains why the controls are absent without the manage permission", async () => {
    stubFetch({ session: viewerSession, models: [pendingModel] });
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    expect(await screen.findByText("Awaiting approval")).toBeTruthy();
    expect((await screen.findAllByText("Not active")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Model administration" })).toBeNull();
    expect(screen.getByText(/Those actions need the model management permission/i)).toBeTruthy();
  });

  it("explains a switched-off action instead of leaving it silent", async () => {
    stubFetch({ session: managerSession, models: [activeModel] });
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    const approve = await screen.findByRole("button", { name: "Approve" });
    expect(approve).toBeDisabled();

    // A disabled control cannot take focus, so the hint wrapper borrows the tab
    // stop and the reason stays reachable by keyboard.
    const hint = approve.closest("span.hint") as HTMLElement;
    expect(hint).toHaveAttribute("tabindex", "0");

    hint.focus();
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).toHaveTextContent(/already approved/i);
  });

  it("does not approve until the confirmation dialog is confirmed", async () => {
    const fetchMock = stubFetch({ session: managerSession, models: [pendingModel] });
    const user = userEvent.setup();
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    await user.click(await screen.findByRole("button", { name: "Approve" }));

    expect(
      fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/approve")),
    ).toHaveLength(0);

    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Confirm approval" }));

    await waitFor(() => {
      const approveCalls = fetchMock.mock.calls.filter(
        ([input, init]) => String(input).endsWith("/approve") && init?.method === "POST",
      );
      expect(approveCalls).toHaveLength(1);
      expect(idempotencyKeyOf(approveCalls[0])).toBeTruthy();
    });
  });

  it("does not activate until the confirmation dialog is confirmed", async () => {
    const fetchMock = stubFetch({ session: managerSession, models: [approvedCandidateWithTarget] });
    const user = userEvent.setup();
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    await user.click(await screen.findByRole("button", { name: /activate/i }));

    expect(
      fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/activate")),
    ).toHaveLength(0);

    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Confirm activation" }));

    await waitFor(() => {
      const activateCalls = fetchMock.mock.calls.filter(
        ([input, init]) => String(input).endsWith("/activate") && init?.method === "POST",
      );
      expect(activateCalls).toHaveLength(1);
      expect(idempotencyKeyOf(activateCalls[0])).toBeTruthy();
    });
  });

  it("does not roll back until the confirmation dialog is confirmed", async () => {
    const fetchMock = stubFetch({
      session: managerSession,
      models: [activeModelWithRollbackTarget, approvedCandidateWithTarget],
    });
    const user = userEvent.setup();
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    // The superseded model also renders a rollback button (disabled): only the
    // active model's recorded target is actionable.
    const rollbackButtons = await screen.findAllByRole("button", { name: /roll back to this/i });
    const enabledRollback = rollbackButtons.filter(
      (button) => (button as HTMLButtonElement).disabled === false,
    );
    expect(enabledRollback).toHaveLength(1);
    await user.click(enabledRollback[0]);

    expect(
      fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/rollback")),
    ).toHaveLength(0);

    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Confirm rollback" }));

    await waitFor(() => {
      const rollbackCalls = fetchMock.mock.calls.filter(
        ([input, init]) => String(input).endsWith("/rollback") && init?.method === "POST",
      );
      expect(rollbackCalls).toHaveLength(1);
      expect(idempotencyKeyOf(rollbackCalls[0])).toBeTruthy();
    });
  });

  it("cancels a pending action without calling the API", async () => {
    const fetchMock = stubFetch({ session: managerSession, models: [pendingModel] });
    const user = userEvent.setup();
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    await user.click(await screen.findByRole("button", { name: "Approve" }));

    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));

    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(
      fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/approve")),
    ).toHaveLength(0);
  });

  it("flags non-finite metric input instead of submitting it", async () => {
    // jsdom's number input sanitizes overflow values like "1e400" to "", so
    // the UI blocks the submit as a required field; the finite-value guard
    // itself is asserted directly against the validator that renders the
    // field-level error (in a real browser "1e400" survives the input filter
    // and reaches this guard as Infinity).
    expect(metricFieldError("1e400", "Macro F1")).toBe("Macro F1 must be a finite number.");
    expect(metricFieldError("abc", "Macro F1")).toBe("Macro F1 must be a finite number.");
    expect(metricFieldError("  ", "Macro F1")).toBe("Macro F1 is required.");
    expect(metricFieldError("0.9862", "Macro F1")).toBeUndefined();

    const fetchMock = stubFetch({ session: managerSession, models: [] });
    const user = userEvent.setup();
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    await user.type(await screen.findByLabelText("Model ID"), "multilabel-v2");
    await user.type(screen.getByLabelText("Version"), "1");
    await user.type(screen.getByLabelText("Dataset version"), "multilabel-v2");
    await user.type(screen.getByLabelText("Code commit"), "18015b5");
    await user.type(screen.getByLabelText("Artifact URI"), "ml/inline/checkpoints/model.onnx");
    await user.type(screen.getByLabelText("Artifact SHA-256"), "b".repeat(64));
    await user.type(screen.getByLabelText("Macro F1"), "1e400");

    await user.click(screen.getByRole("button", { name: "Register model" }));

    expect(await screen.findByText(/Macro F1 is required/i)).toBeTruthy();
    expect(
      fetchMock.mock.calls.filter(
        ([input, init]) => String(input).endsWith("/admin/models") && init?.method === "POST",
      ),
    ).toHaveLength(0);
  });

  it("rejects registration when a required metric field is left empty", async () => {
    const fetchMock = stubFetch({ session: managerSession, models: [] });
    const user = userEvent.setup();
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    await user.type(await screen.findByLabelText("Model ID"), "multilabel-v2");
    await user.type(screen.getByLabelText("Version"), "1");
    await user.type(screen.getByLabelText("Dataset version"), "multilabel-v2");
    await user.type(screen.getByLabelText("Code commit"), "18015b5");
    await user.type(screen.getByLabelText("Artifact URI"), "ml/inline/checkpoints/model.onnx");
    await user.type(screen.getByLabelText("Artifact SHA-256"), "b".repeat(64));
    await user.type(screen.getByLabelText("Macro F1"), "0.9862");

    await user.click(screen.getByRole("button", { name: "Register model" }));

    expect(await screen.findByText(/ROC-AUC is required/i)).toBeTruthy();
    expect(
      fetchMock.mock.calls.filter(
        ([input, init]) => String(input).endsWith("/admin/models") && init?.method === "POST",
      ),
    ).toHaveLength(0);
  });

  it("submits structured numeric metrics with an idempotency key", async () => {
    const fetchMock = stubFetch({ session: managerSession, models: [] });
    const user = userEvent.setup();
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    await user.type(await screen.findByLabelText("Model ID"), "multilabel-v2");
    await user.type(screen.getByLabelText("Version"), "1");
    await user.type(screen.getByLabelText("Dataset version"), "multilabel-v2");
    await user.type(screen.getByLabelText("Code commit"), "18015b5");
    await user.type(screen.getByLabelText("Artifact URI"), "ml/inline/checkpoints/model.onnx");
    await user.type(screen.getByLabelText("Artifact SHA-256"), "b".repeat(64));
    await user.type(screen.getByLabelText("Macro F1"), "0.9862");
    await user.type(screen.getByLabelText("ROC-AUC"), "1.0");
    await user.type(screen.getByLabelText("Clean-mail false positive rate"), "0.0042");
    await user.type(screen.getByLabelText("95th percentile latency (ms)"), "41.01");

    await user.click(screen.getByRole("button", { name: "Register model" }));

    await waitFor(() => {
      const registerCall = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith("/admin/models") && init?.method === "POST",
      );
      expect(registerCall).toBeTruthy();
      expect(idempotencyKeyOf(registerCall!)).toBeTruthy();
      const body = JSON.parse(String(registerCall?.[1]?.body)) as {
        metrics: Record<string, unknown>;
      };
      expect(body.metrics).toEqual({
        macro_f1: 0.9862,
        macro_roc_auc: 1,
        ham_false_positive_rate: 0.0042,
        latency_p95_ms: 41.01,
      });
    });
  });

  it("records shadow evidence from structured fields with an idempotency key", async () => {
    const fetchMock = stubFetch({ session: managerSession, models: [pendingModel] });
    const user = userEvent.setup();
    renderAt("/models");

    await screen.findByRole("heading", { name: "Inline ML control plane" });
    await user.type(await screen.findByLabelText("Evaluation set"), "shadow-eval-2026-10-04");
    await user.type(screen.getByLabelText("Macro F1 change"), "0.021");
    await user.selectOptions(screen.getByLabelText("Comparison decision"), "promote_candidate");

    await user.click(screen.getByRole("button", { name: "Record shadow evidence" }));

    await waitFor(() => {
      const shadowCall = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith("/shadow-evaluations") && init?.method === "POST",
      );
      expect(shadowCall).toBeTruthy();
      expect(idempotencyKeyOf(shadowCall!)).toBeTruthy();
      const body = JSON.parse(String(shadowCall?.[1]?.body)) as {
        metrics: Record<string, unknown>;
        comparison: Record<string, unknown>;
      };
      expect(body.metrics).toEqual({ macro_f1_delta: 0.021 });
      expect(body.comparison).toEqual({ decision: "promote_candidate" });
    });
  });
});

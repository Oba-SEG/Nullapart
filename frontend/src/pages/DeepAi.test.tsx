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
import { describe, expect, it, vi } from "vitest";

import { DeepAi } from "./DeepAi";

const managerSession = {
  authenticated: true,
  userId: "actor-1",
  email: "admin@example.test",
  roles: ["system_admin"],
  permissions: ["deep-ai:view", "deep-ai:manage"],
  customerId: "CZA-1",
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
};

const snapshot = {
  deployment_id: "LOCAL-TEST",
  generated_at: "2026-10-12T10:00:00Z",
  summary: {
    released_skills: 7,
    approved_model_releases: 1,
    approved_regional_benchmarks: 1,
    active_artifact_grants: 1,
    valid_results_24h: 1,
    invalid_or_error_results_24h: 0,
    approved_training_datasets: 1,
  },
  skills: [
    {
      skill_id: "security.message.deep_analysis",
      skill_version: "v1",
      owner: "security-platform",
      purpose: "Analyze eligible messages with scoped Deep AI evidence.",
      allowed_data_classes: ["quarantined", "reported_phishing"],
      allowed_tools: ["artifact.retrieve", "scanner.findings"],
      max_input_tokens: 32768,
      max_output_tokens: 2048,
      max_artifacts: 8,
      timeout_ms: 120000,
      concurrency_limit: 4,
      model_requirement: "openai-compatible",
      prompt_template_version: "prompt-v1",
      input_schema_version: "input-v1",
      output_schema_version: "output-v1",
      evaluation_suite_version: "eval-v1",
      release_state: "released",
      rollback_skill_version: null,
      updated_at: "2026-10-12T10:00:00Z",
    },
  ],
  model_releases: [
    {
      region: "za",
      model_release: "local-qwen3.5-9b-phase7",
      backend: "ollama",
      serving_contract: "openai_compatible",
      quantization: "q4_local_dev",
      context_window: 32768,
      approval_state: "approved",
      rollback_to_model_release: null,
      updated_at: "2026-10-12T10:00:00Z",
    },
  ],
  regional_benchmarks: [
    {
      region: "za",
      model_release: "local-qwen3.5-9b-phase7",
      accelerator_family: "local-dev",
      quantization: "q4",
      vram_gb: 8,
      gpu_count: 0,
      topology: "single node",
      model_load_seconds: 0,
      tokens_per_second: 1,
      concurrent_requests: 1,
      context_target_tokens: 32768,
      multimodal_supported: false,
      availability_notes: "local benchmark only",
      failover_notes: "mail path independent",
      cost_per_case_estimate: 0,
      approved: true,
      approval_note: "approved for local Phase 7 verification",
      measured_at: "2026-10-12T10:00:00Z",
    },
  ],
  artifact_grants: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      tenant_message_id: null,
      artifact_id: "22222222-2222-2222-2222-222222222222",
      resource_type: "reported_phishing",
      purpose: "security_analysis",
      skill_id: "security.message.deep_analysis",
      skill_version: "v1",
      artifact_type: "message_rfc822",
      expires_at: "2026-10-12T11:00:00Z",
      created_by: "admin@example.test",
      created_at: "2026-10-12T10:00:00Z",
      revoked_at: null,
    },
  ],
  analysis_results: [
    {
      id: "33333333-3333-3333-3333-333333333333",
      skill_id: "security.message.deep_analysis",
      skill_version: "v1",
      model_release: "local-qwen3.5-9b-phase7",
      artifact_grant_id: "11111111-1111-1111-1111-111111111111",
      classification: "malicious",
      attack_type: "phishing",
      severity: "high",
      confidence: 0.91,
      impersonated_entity: null,
      evidence_references: ["grant:11111111-1111-1111-1111-111111111111"],
      recommended_action: "quarantine",
      analyst_summary: "Deep AI found trusted evidence for a credential lure.",
      processing_duration_ms: 1200,
      validation_state: "valid",
      error_code: null,
      created_at: "2026-10-12T10:01:00Z",
    },
  ],
  training_datasets: [
    {
      dataset_version: "phase7-governance-v1",
      region: "za",
      allowed_data_classes: ["reported_phishing"],
      provenance: "Governance record only.",
      labeling_process: "Analyst labels with protected splits.",
      approval_state: "approved",
      deletion_withdrawal_process: "Withdrawn customer data is removed from future datasets.",
      evaluation_split_protected: true,
      created_at: "2026-10-12T10:00:00Z",
    },
  ],
};

function ok(body: unknown) {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => body,
  };
}

function stubFetch() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: managerSession });
    }
    if (method === "POST" && url.endsWith("/deep-ai/artifact-grants")) {
      return ok({ data: { id: "grant-new", expires_at: "2026-10-12T11:00:00Z" } });
    }
    if (url.includes("/deep-ai")) {
      return ok({ data: snapshot });
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
      path: "/deep-ai",
      component: DeepAi,
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

describe("DeepAi", () => {
  it("renders actionable regional Deep AI controls", async () => {
    stubFetch();
    renderAt("/deep-ai");

    await screen.findByRole("heading", { name: "Regional Deep AI" });
    const summary = screen.getByRole("region", { name: "Deep AI summary" });
    expect(within(summary).getByText("Released skills")).toBeTruthy();
    expect(screen.getByText("security.message.deep_analysis")).toBeTruthy();
    expect(screen.getByText("approved for local Phase 7 verification")).toBeTruthy();
    expect(screen.getByText("Deep AI found trusted evidence for a credential lure.")).toBeTruthy();
    expect(screen.getByText("phase7-governance-v1")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Create scoped grant" })).toBeTruthy();
  });

  it("creates scoped artifact grants with an idempotency key", async () => {
    const fetchMock = stubFetch();
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.type(screen.getByLabelText("Artifact ID"), "22222222-2222-2222-2222-222222222222");
    await user.click(screen.getByRole("button", { name: "Create scoped grant" }));

    await waitFor(() => {
      const grantCall = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/deep-ai/artifact-grants") && init?.method === "POST",
      );
      expect(grantCall).toBeTruthy();
      expect((grantCall?.[1]?.headers as Record<string, string>)["X-Idempotency-Key"]).toBeTruthy();
    });
  });
});

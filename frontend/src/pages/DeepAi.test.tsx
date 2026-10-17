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

const viewerSession = {
  ...managerSession,
  roles: ["support_agent"],
  permissions: ["deep-ai:view"],
};

/**
 * A finding may only cite a grant that is still open, so the fixture grant
 * expires relative to now rather than on a fixed historical date.
 */
const openUntil = new Date(Date.now() + 25 * 60_000).toISOString();

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
      expires_at: openUntil,
      created_by: "admin@example.test",
      created_at: "2026-10-12T10:00:00Z",
      revoked_at: null as string | null,
      revoked_by: null as string | null,
      revoke_reason: null as string | null,
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
      recorded_by: "model_runtime",
      created_at: "2026-10-12T10:01:00Z",
    },
    {
      id: "44444444-4444-4444-4444-444444444444",
      skill_id: "security.message.deep_analysis",
      skill_version: "v1",
      model_release: "local-qwen3.5-9b-phase7",
      artifact_grant_id: "11111111-1111-1111-1111-111111111111",
      classification: "suspicious",
      attack_type: "bec",
      severity: "medium",
      confidence: 0.6,
      impersonated_entity: "Finance director",
      evidence_references: ["grant:11111111-1111-1111-1111-111111111111"],
      recommended_action: "escalate",
      analyst_summary: "Analyst read the payment request as an invoice diversion attempt.",
      processing_duration_ms: 0,
      validation_state: "valid",
      error_code: null,
      recorded_by: "administrator",
      created_at: "2026-10-12T10:02:00Z",
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

function stepUpDenied() {
  return {
    ok: false,
    status: 403,
    statusText: "Forbidden",
    json: async () => ({
      code: "STEP_UP_REQUIRED",
      message: "Step-up authentication is required",
    }),
  };
}

function stubFetch(
  overrides: Partial<typeof snapshot> = {},
  session: typeof managerSession = managerSession,
) {
  const data = { ...snapshot, ...overrides };
  /**
   * A revocation is durable, so a read after it must show the closed grant. The
   * console refetches on success, and this is what lets a test assert the card
   * actually changes instead of only that the request was sent.
   */
  let revocation: { at: string; by: string; reason: string } | null = null;
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: session });
    }
    if (method === "POST" && url.endsWith("/deep-ai/artifact-grants")) {
      return ok({ data: { id: "grant-new", expires_at: openUntil } });
    }
    if (method === "POST" && url.endsWith("/revoke")) {
      const body = JSON.parse(String(init?.body)) as { reason: string };
      revocation = {
        at: "2026-10-12T10:30:00Z",
        by: "admin@example.test",
        reason: body.reason,
      };
      return ok({
        data: {
          id: "11111111-1111-1111-1111-111111111111",
          artifact_id: "22222222-2222-2222-2222-222222222222",
          revoked_at: revocation.at,
          revoked_by: revocation.by,
          reason: revocation.reason,
          changed: true,
        },
      });
    }
    if (method === "POST" && url.endsWith("/deep-ai/rollback")) {
      return ok({ data: { changed: true } });
    }
    if (method === "POST" && url.endsWith("/deep-ai/analysis-results")) {
      return ok({ data: { id: "result-new", recorded_by: "administrator" } });
    }
    if (url.includes("/deep-ai")) {
      const closed = revocation;
      if (!closed) {
        return ok({ data });
      }
      return ok({
        data: {
          ...data,
          artifact_grants: data.artifact_grants.map((grant) => ({
            ...grant,
            revoked_at: closed.at,
            revoked_by: closed.by,
            revoke_reason: closed.reason,
          })),
        },
      });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function stubFetchStepUpDenied(
  deniedPath:
    | "/deep-ai/artifact-grants"
    | "/deep-ai/rollback"
    | "/deep-ai/analysis-results"
    | "/deep-ai/artifact-grants/11111111-1111-1111-1111-111111111111/revoke",
) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: managerSession });
    }
    if (method === "POST" && url.endsWith(deniedPath)) {
      return stepUpDenied();
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
    expect(screen.getByRole("button", { name: "Record rollback" })).toBeTruthy();
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

  it("posts release rollback requests with an idempotency key", async () => {
    const fetchMock = stubFetch();
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.type(screen.getByLabelText("Skill ID"), "security.message.deep_analysis");
    await user.type(screen.getByLabelText("Current skill version"), "v2");
    await user.type(screen.getByLabelText("Rollback skill version"), "v1");
    await user.type(screen.getByLabelText("Rollback reason"), "Failed evaluation gate");
    await user.click(screen.getByRole("button", { name: "Record rollback" }));

    await waitFor(() => {
      const rollbackCall = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith("/deep-ai/rollback") && init?.method === "POST",
      );
      expect(rollbackCall).toBeTruthy();
      expect(
        (rollbackCall?.[1]?.headers as Record<string, string>)["X-Idempotency-Key"],
      ).toBeTruthy();
    });
  });

  it("prefills rollback targets from the registry instead of free-text entry", async () => {
    const fetchMock = stubFetch();
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.click(screen.getByRole("button", { name: "Roll back" }));
    expect(screen.getByLabelText("Skill ID")).toHaveValue("security.message.deep_analysis");
    expect(screen.getByLabelText("Current skill version")).toHaveValue("v1");

    await user.click(screen.getByRole("button", { name: "Roll back release" }));
    expect(screen.getByLabelText("Model release")).toHaveValue("local-qwen3.5-9b-phase7");

    await user.click(screen.getByRole("button", { name: "Roll back" }));
    await user.type(screen.getByLabelText("Rollback skill version"), "v0");
    await user.type(screen.getByLabelText("Rollback reason"), "Failed evaluation gate");
    await user.click(screen.getByRole("button", { name: "Record rollback" }));

    await waitFor(() => {
      const rollbackCall = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith("/deep-ai/rollback") && init?.method === "POST",
      );
      expect(rollbackCall).toBeTruthy();
      const body = JSON.parse(String(rollbackCall?.[1]?.body));
      expect(body.skill_id).toBe("security.message.deep_analysis");
      expect(body.current_skill_version).toBe("v1");
      expect(body.rollback_skill_version).toBe("v0");
    });
  });

  it("offers step-up re-authentication when grant creation requires step-up", async () => {
    stubFetchStepUpDenied("/deep-ai/artifact-grants");
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.type(screen.getByLabelText("Artifact ID"), "22222222-2222-2222-2222-222222222222");
    await user.click(screen.getByRole("button", { name: "Create scoped grant" }));

    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
    expect(screen.getByText("Re-authentication is required for this action.")).toBeTruthy();
  });

  it("offers step-up re-authentication when rollback requires step-up", async () => {
    stubFetchStepUpDenied("/deep-ai/rollback");
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.type(screen.getByLabelText("Skill ID"), "security.message.deep_analysis");
    await user.type(screen.getByLabelText("Current skill version"), "v2");
    await user.type(screen.getByLabelText("Rollback skill version"), "v1");
    await user.type(screen.getByLabelText("Rollback reason"), "Failed evaluation gate");
    await user.click(screen.getByRole("button", { name: "Record rollback" }));

    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
    expect(screen.getByText("Re-authentication is required for this action.")).toBeTruthy();
  });

  it("records a finding against the grant it was read under", async () => {
    const fetchMock = stubFetch();
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.click(screen.getByRole("button", { name: "Record a finding" }));
    await user.selectOptions(
      screen.getByLabelText("Release that ran the analysis"),
      "local-qwen3.5-9b-phase7",
    );
    await user.selectOptions(screen.getByLabelText("Verdict"), "malicious");
    await user.type(screen.getByLabelText("Confidence (0 to 1)"), "0.8");
    await user.type(
      screen.getByLabelText("What was seen"),
      "Sender domain registered four days ago\nReply-to differs from the sending address",
    );
    await user.type(
      screen.getByLabelText("Summary for a reviewer"),
      "Credential lure sent from a lookalike domain to finance staff.",
    );
    await user.click(screen.getByRole("button", { name: "Record finding" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/deep-ai/analysis-results") && init?.method === "POST",
      );
      expect(call).toBeTruthy();
      const body = JSON.parse(String(call?.[1]?.body));
      expect(body.artifact_grant_id).toBe("11111111-1111-1111-1111-111111111111");
      // Skill identity is copied from the cited grant, never typed.
      expect(body.skill_id).toBe("security.message.deep_analysis");
      expect(body.skill_version).toBe("v1");
      expect(body.model_release).toBe("local-qwen3.5-9b-phase7");
      expect(body.classification).toBe("malicious");
      expect(body.confidence).toBeCloseTo(0.8);
      expect(body.observations).toHaveLength(2);
      expect(body.evidence_references).toContain("grant:11111111-1111-1111-1111-111111111111");
      expect((call?.[1]?.headers as Record<string, string>)["X-Idempotency-Key"]).toBeTruthy();
    });
  });

  it("names who recorded each finding so model output and admin input stay distinct", async () => {
    stubFetch();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    expect(screen.getByText("Produced by the analysis runtime")).toBeTruthy();
    expect(screen.getByText("Entered by an administrator")).toBeTruthy();
  });

  it("refuses an incomplete finding and says which field is short", async () => {
    const fetchMock = stubFetch();
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.click(screen.getByRole("button", { name: "Record finding" }));

    expect(
      await screen.findByText("Choose the open grant this finding was made under."),
    ).toBeTruthy();
    expect(screen.getByText("Choose the approved release that ran this analysis.")).toBeTruthy();
    expect(screen.getByText("Record at least one observation this finding rests on.")).toBeTruthy();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("explains why nothing can be recorded while no grant is open", async () => {
    stubFetch({ artifact_grants: [] });
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    expect(
      await screen.findByText(
        "A finding has to cite an open artifact grant, and none is open for this customer. Create a scoped grant first.",
      ),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: "Record finding" })).toBeDisabled();
  });

  it("offers step-up re-authentication when recording a finding requires step-up", async () => {
    stubFetchStepUpDenied("/deep-ai/analysis-results");
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.click(screen.getByRole("button", { name: "Record a finding" }));
    await user.selectOptions(
      screen.getByLabelText("Release that ran the analysis"),
      "local-qwen3.5-9b-phase7",
    );
    await user.type(screen.getByLabelText("Confidence (0 to 1)"), "0.7");
    await user.type(screen.getByLabelText("What was seen"), "Invoice total changed mid-thread");
    await user.type(
      screen.getByLabelText("Summary for a reviewer"),
      "Payment details swapped inside an existing invoicing thread.",
    );
    await user.click(screen.getByRole("button", { name: "Record finding" }));

    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
  });

  it("explains why nothing can be recorded while no release is approved", async () => {
    stubFetch({ model_releases: [] });
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    expect(
      await screen.findByText(
        "A finding cites an approved model release, and this deployment has none. Approve one on the model list first.",
      ),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: "Record finding" })).toBeDisabled();
  });

  it("offers no finding action on a grant that is already closed", async () => {
    stubFetch({
      artifact_grants: [{ ...snapshot.artifact_grants[0], revoked_at: "2026-10-12T10:30:00Z" }],
    });
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    expect(screen.queryByRole("button", { name: "Record a finding" })).toBeNull();
  });

  it("revokes an open grant with a reason and shows the closed record afterwards", async () => {
    const fetchMock = stubFetch();
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.click(screen.getByRole("button", { name: "Revoke grant" }));
    const reason = screen.getByLabelText("Reason this access ends");
    await user.type(reason, "Review done");
    await user.click(screen.getByRole("button", { name: "Revoke this grant" }));

    expect(
      await screen.findByText(
        "Write at least 12 characters so a reader knows why this access ended.",
      ),
    ).toBeTruthy();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);

    await user.clear(reason);
    await user.type(reason, "Analyst finished review; no further access is needed.");
    await user.click(screen.getByRole("button", { name: "Revoke this grant" }));

    await waitFor(() => {
      const revokeCall = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith("/revoke") && init?.method === "POST",
      );
      expect(revokeCall).toBeTruthy();
      expect(
        (revokeCall?.[1]?.headers as Record<string, string>)["X-Idempotency-Key"],
      ).toBeTruthy();
      expect(JSON.parse(String(revokeCall?.[1]?.body)).reason).toBe(
        "Analyst finished review; no further access is needed.",
      );
    });

    // The refetched card says who ended the access and why, and offers no way to
    // revoke the same grant a second time.
    expect(
      await screen.findByText(
        "Revoked by admin@example.test: Analyst finished review; no further access is needed.",
      ),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Revoke grant" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Record a finding" })).toBeNull();
  });

  it("offers step-up re-authentication when a revocation requires step-up", async () => {
    stubFetchStepUpDenied("/deep-ai/artifact-grants/11111111-1111-1111-1111-111111111111/revoke");
    const user = userEvent.setup();
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    await user.click(screen.getByRole("button", { name: "Revoke grant" }));
    await user.type(
      screen.getByLabelText("Reason this access ends"),
      "The artifact was mislabeled and never needed analysis.",
    );
    await user.click(screen.getByRole("button", { name: "Revoke this grant" }));

    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
    // The reason stays typed so a re-authenticated operator does not retype it.
    expect(screen.getByLabelText("Reason this access ends")).toHaveValue(
      "The artifact was mislabeled and never needed analysis.",
    );
  });

  it("keeps the revocation reason on a revoked grant for readers without the permission", async () => {
    stubFetch(
      {
        artifact_grants: [
          {
            ...snapshot.artifact_grants[0],
            revoked_at: "2026-10-12T10:30:00Z",
            revoked_by: "dana@example.test",
            revoke_reason: "Case closed after the sender was confirmed legitimate.",
          },
        ],
      },
      viewerSession,
    );
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    expect(
      await screen.findByText(
        "Revoked by dana@example.test: Case closed after the sender was confirmed legitimate.",
      ),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Revoke grant" })).toBeNull();
  });

  it("shows the finding form as read-only without the management permission", async () => {
    stubFetch({}, viewerSession);
    renderAt("/deep-ai");
    await screen.findByRole("heading", { name: "Regional Deep AI" });

    expect(
      await screen.findByText(
        "You can read findings, but recording one needs the Deep AI management permission.",
      ),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Record a finding" })).toBeNull();
  });
});

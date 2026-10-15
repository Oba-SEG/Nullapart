import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, BrainCircuit, DatabaseZap, KeyRound, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";

import { api, type ApiError } from "../api/client";
import { hasPermission, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { StatusPill } from "../components/StatusPill";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
import type { StatusTone } from "../lib/status";
import "./DeepAi.css";

interface DeepAiSummary {
  released_skills: number;
  approved_model_releases: number;
  approved_regional_benchmarks: number;
  active_artifact_grants: number;
  valid_results_24h: number;
  invalid_or_error_results_24h: number;
  approved_training_datasets: number;
}

interface DeepAiSkill {
  skill_id: string;
  skill_version: string;
  owner: string;
  purpose: string;
  allowed_data_classes: string[];
  allowed_tools: string[];
  max_input_tokens: number;
  max_output_tokens: number;
  max_artifacts: number;
  timeout_ms: number;
  concurrency_limit: number;
  model_requirement: string;
  prompt_template_version: string;
  input_schema_version: string;
  output_schema_version: string;
  evaluation_suite_version: string;
  release_state: string;
  rollback_skill_version: string | null;
  updated_at: string;
}

interface DeepAiModelRelease {
  region: string;
  model_release: string;
  backend: string;
  serving_contract: string;
  quantization: string;
  context_window: number;
  approval_state: string;
  rollback_to_model_release: string | null;
  updated_at: string;
}

interface DeepAiBenchmark {
  region: string;
  model_release: string;
  accelerator_family: string;
  quantization: string;
  vram_gb: number;
  gpu_count: number;
  topology: string;
  model_load_seconds: number;
  tokens_per_second: number;
  concurrent_requests: number;
  context_target_tokens: number;
  multimodal_supported: boolean;
  availability_notes: string;
  failover_notes: string;
  cost_per_case_estimate: number;
  approved: boolean;
  approval_note: string;
  measured_at: string;
}

interface DeepAiGrant {
  id: string;
  tenant_message_id: string | null;
  artifact_id: string;
  resource_type: string;
  purpose: string;
  skill_id: string;
  skill_version: string;
  artifact_type: string;
  expires_at: string;
  created_by: string;
  created_at: string;
  revoked_at: string | null;
}

interface DeepAiResult {
  id: string;
  skill_id: string;
  skill_version: string;
  model_release: string;
  artifact_grant_id: string;
  classification: string;
  attack_type: string;
  severity: string;
  confidence: number;
  impersonated_entity: string | null;
  evidence_references: string[];
  recommended_action: string;
  analyst_summary: string;
  processing_duration_ms: number;
  validation_state: string;
  error_code: string | null;
  created_at: string;
}

interface DeepAiDataset {
  dataset_version: string;
  region: string;
  allowed_data_classes: string[];
  provenance: string;
  labeling_process: string;
  approval_state: string;
  deletion_withdrawal_process: string;
  evaluation_split_protected: boolean;
  created_at: string;
}

interface DeepAiResponse {
  deployment_id: string;
  generated_at: string;
  summary: DeepAiSummary;
  skills: DeepAiSkill[];
  model_releases: DeepAiModelRelease[];
  regional_benchmarks: DeepAiBenchmark[];
  artifact_grants: DeepAiGrant[];
  analysis_results: DeepAiResult[];
  training_datasets: DeepAiDataset[];
}

interface GrantDraft {
  artifact_id: string;
  tenant_message_id: string;
  resource_type: string;
  purpose: string;
  skill: string;
  artifact_type: string;
  ttl_minutes: string;
}

interface RollbackDraft {
  skill_id: string;
  current_skill_version: string;
  rollback_skill_version: string;
  model_release: string;
  rollback_to_model_release: string;
  reason: string;
}

const defaultGrantDraft: GrantDraft = {
  artifact_id: "",
  tenant_message_id: "",
  resource_type: "reported_phishing",
  purpose: "security_analysis",
  skill: "",
  artifact_type: "message_rfc822",
  ttl_minutes: "30",
};

const defaultRollbackDraft: RollbackDraft = {
  skill_id: "",
  current_skill_version: "",
  rollback_skill_version: "",
  model_release: "",
  rollback_to_model_release: "",
  reason: "",
};

const resourceOptions = [
  { value: "reported_phishing", label: "Reported phishing" },
  { value: "quarantine_case", label: "Quarantine case" },
  { value: "blocked_message", label: "Blocked message" },
  { value: "confirmed_threat", label: "Confirmed threat" },
  { value: "false_positive_review", label: "False positive review" },
  { value: "false_negative_review", label: "False negative review" },
  { value: "held_for_deep_analysis", label: "Held for deep analysis" },
];

const purposeOptions = [
  { value: "security_analysis", label: "Security analysis" },
  { value: "bec_analysis", label: "BEC analysis" },
  { value: "impersonation_analysis", label: "Impersonation analysis" },
  { value: "case_summary", label: "Case summary" },
  { value: "campaign_correlation", label: "Campaign correlation" },
  { value: "false_positive_review", label: "False positive review" },
  { value: "false_negative_review", label: "False negative review" },
];

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "Deep AI is temporarily unavailable.";
}

function formatDate(value: string | null): string {
  if (!value) return "none";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unknown";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    date,
  );
}

function stateTone(value: string): StatusTone {
  if (["released", "approved", "valid", "clean"].includes(value)) return "clean";
  if (
    ["disabled", "rejected", "error", "schema_invalid", "hallucinated_evidence"].includes(value)
  ) {
    return "threat";
  }
  return "review";
}

function severityTone(value: string): StatusTone {
  if (["critical", "high", "malicious"].includes(value)) return "threat";
  if (["medium", "suspicious", "unknown"].includes(value)) return "review";
  return "clean";
}

function shortId(value: string, length = 10): string {
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

function skillKey(skill: DeepAiSkill): string {
  return `${skill.skill_id}/${skill.skill_version}`;
}

export function DeepAi() {
  const queryClient = useQueryClient();
  const [grantDraft, setGrantDraft] = useState<GrantDraft>(defaultGrantDraft);
  const [rollbackDraft, setRollbackDraft] = useState<RollbackDraft>(defaultRollbackDraft);
  const [formError, setFormError] = useState<string | null>(null);
  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const deepAi = useQuery({
    queryKey: ["deep-ai"],
    queryFn: ({ signal }) => api.get<DeepAiResponse>("/deep-ai", signal),
    refetchInterval: 60_000,
  });
  const canManage = hasPermission(session.data ?? null, "deep-ai:manage");

  const skillOptions = useMemo(
    () =>
      (deepAi.data?.skills ?? [])
        .filter((skill) => skill.release_state === "released")
        .map((skill) => ({ value: skillKey(skill), label: skillKey(skill) })),
    [deepAi.data?.skills],
  );

  const createGrant = useMutation({
    mutationFn: (draft: GrantDraft) => {
      const [skill_id, skill_version] = draft.skill.split("/");
      return api.post<{ id: string; expires_at: string }>(
        "/deep-ai/artifact-grants",
        {
          artifact_id: draft.artifact_id.trim(),
          tenant_message_id: draft.tenant_message_id.trim() || undefined,
          resource_type: draft.resource_type,
          purpose: draft.purpose,
          skill_id,
          skill_version,
          artifact_type: draft.artifact_type,
          ttl_minutes: Number.parseInt(draft.ttl_minutes, 10),
        },
        { idempotencyKey: randomUuid() },
      );
    },
    onSuccess: async () => {
      setGrantDraft({ ...defaultGrantDraft, skill: skillOptions[0]?.value ?? "" });
      setFormError(null);
      await queryClient.invalidateQueries({ queryKey: ["deep-ai"] });
    },
  });
  const rollbackRelease = useMutation({
    mutationFn: (draft: RollbackDraft) =>
      api.post<{ changed: boolean }>(
        "/deep-ai/rollback",
        {
          skill_id: draft.skill_id.trim() || undefined,
          current_skill_version: draft.current_skill_version.trim() || undefined,
          rollback_skill_version: draft.rollback_skill_version.trim() || undefined,
          model_release: draft.model_release.trim() || undefined,
          rollback_to_model_release: draft.rollback_to_model_release.trim() || undefined,
          reason: draft.reason.trim(),
        },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async () => {
      setRollbackDraft(defaultRollbackDraft);
      setFormError(null);
      await queryClient.invalidateQueries({ queryKey: ["deep-ai"] });
    },
  });

  if (deepAi.isPending) {
    return (
      <div className="deep-ai-state" role="status">
        Loading regional Deep AI controls…
      </div>
    );
  }
  if (deepAi.isError) {
    return (
      <div className="deep-ai-state error" role="alert">
        {errorMessage(deepAi.error)}
      </div>
    );
  }

  const data = deepAi.data;
  const activeSkill = grantDraft.skill || skillOptions[0]?.value || "";
  const latestBenchmark = data.regional_benchmarks[0] ?? null;
  const grantError = createGrant.isError ? errorMessage(createGrant.error) : null;
  const rollbackError = rollbackRelease.isError ? errorMessage(rollbackRelease.error) : null;

  return (
    <div className="deep-ai-page">
      <WorkspaceHeader
        eyebrow="Model governance"
        title="Regional Deep AI"
        description={`Versioned skills, scoped artifact grants, validated findings and training governance for ${data.deployment_id}.`}
        scope="Regional AI controls"
        actions={
          <StatusPill
            tone={data.summary.approved_regional_benchmarks > 0 ? "clean" : "review"}
            label={
              data.summary.approved_regional_benchmarks > 0
                ? "regional benchmark recorded"
                : "benchmark required"
            }
          />
        }
      />

      <ControlRail
        title="Regional AI governance state"
        summary="Use only server-reported model, grant and benchmark state when deciding whether a regional skill can be trusted for its approved scope."
        signals={[
          {
            label: "Approved benchmarks",
            value: data.summary.approved_regional_benchmarks,
            detail: "Regional benchmark records accepted for this deployment.",
            tone: data.summary.approved_regional_benchmarks > 0 ? "healthy" : "attention",
          },
          {
            label: "Artifact grants",
            value: data.summary.active_artifact_grants,
            detail: "Active customer-scoped artifact grants.",
          },
          {
            label: "Skills",
            value: data.skills.length,
            detail: "Versioned skill definitions available to this deployment.",
          },
        ]}
      />

      <WorkflowGuide
        title="Constrain regional AI handling"
        description="Regional model configuration and customer grants are explicit controls; they do not give a model ambient access to messages, providers or infrastructure."
        steps={[
          {
            label: "Review deployment",
            detail: "Confirm the target regional AI deployment and its permitted capability set.",
          },
          {
            label: "Grant narrowly",
            detail: "Apply customer grants only to the required scope with an auditable reason.",
          },
          {
            label: "Verify status",
            detail: "Refresh the server-reported deployment state after configuration changes.",
          },
        ]}
      />

      <section className="deep-ai-summary" aria-label="Deep AI summary">
        <div className="deep-ai-summary-card">
          <BrainCircuit aria-hidden="true" />
          <span>Released skills</span>
          <strong>{data.summary.released_skills}</strong>
        </div>
        <div className="deep-ai-summary-card">
          <ShieldCheck aria-hidden="true" />
          <span>Approved releases</span>
          <strong>{data.summary.approved_model_releases}</strong>
        </div>
        <div className="deep-ai-summary-card">
          <KeyRound aria-hidden="true" />
          <span>Active grants</span>
          <strong>{data.summary.active_artifact_grants}</strong>
        </div>
        <div className="deep-ai-summary-card">
          <AlertTriangle aria-hidden="true" />
          <span>Invalid results 24h</span>
          <strong>{data.summary.invalid_or_error_results_24h}</strong>
        </div>
        <div className="deep-ai-summary-card">
          <DatabaseZap aria-hidden="true" />
          <span>Training datasets</span>
          <strong>{data.summary.approved_training_datasets}</strong>
        </div>
      </section>

      <section className="deep-ai-grid">
        <article className="deep-ai-panel">
          <h2>Skill registry</h2>
          <div className="deep-ai-table-wrap">
            <table className="deep-ai-table">
              <thead>
                <tr>
                  <th>Skill</th>
                  <th>State</th>
                  <th>Budgets</th>
                  <th>Tools</th>
                </tr>
              </thead>
              <tbody>
                {data.skills.map((skill) => (
                  <tr key={skillKey(skill)}>
                    <td>
                      <strong>{skill.skill_id}</strong>
                      <small>
                        {skill.skill_version} · {skill.evaluation_suite_version}
                      </small>
                    </td>
                    <td>
                      <StatusPill
                        tone={stateTone(skill.release_state)}
                        label={skill.release_state}
                      />
                    </td>
                    <td>
                      {skill.max_input_tokens.toLocaleString()} in /{" "}
                      {skill.max_output_tokens.toLocaleString()} out
                      <small>
                        {skill.max_artifacts} artifacts · {skill.timeout_ms / 1000}s
                      </small>
                    </td>
                    <td>{skill.allowed_tools.join(", ") || "none"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <article className="deep-ai-panel">
          <h2>Regional serving and capacity</h2>
          <div className="deep-ai-release-list">
            {data.model_releases.map((release) => (
              <div className="deep-ai-release" key={`${release.region}-${release.model_release}`}>
                <div>
                  <strong>{release.region}</strong>
                  <span>{release.model_release}</span>
                  <small>
                    {release.backend} · {release.serving_contract}
                  </small>
                </div>
                <StatusPill
                  tone={stateTone(release.approval_state)}
                  label={release.approval_state}
                />
              </div>
            ))}
          </div>
          {latestBenchmark ? (
            <div className="deep-ai-benchmark">
              <strong>{latestBenchmark.region} benchmark</strong>
              <p>{latestBenchmark.approval_note}</p>
              <dl>
                <div>
                  <dt>Accelerator</dt>
                  <dd>{latestBenchmark.accelerator_family}</dd>
                </div>
                <div>
                  <dt>Tokens/sec</dt>
                  <dd>{latestBenchmark.tokens_per_second}</dd>
                </div>
                <div>
                  <dt>Context</dt>
                  <dd>{latestBenchmark.context_target_tokens.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>Failover</dt>
                  <dd>{latestBenchmark.failover_notes}</dd>
                </div>
              </dl>
            </div>
          ) : (
            <p className="deep-ai-muted">No benchmark recorded for this deployment.</p>
          )}
        </article>
      </section>

      <section className="deep-ai-grid">
        <article className="deep-ai-panel">
          <h2>Scoped artifact access</h2>
          <p>
            Grant short-lived access only to eligible security artifacts. The model never receives
            broad S3, database, shell or browser authority.
          </p>
          {canManage ? (
            <form
              className="deep-ai-form"
              onSubmit={(event) => {
                event.preventDefault();
                const nextDraft = { ...grantDraft, skill: activeSkill };
                if (!nextDraft.artifact_id.trim() || !nextDraft.skill) {
                  setFormError("Artifact ID and released skill are required.");
                  return;
                }
                setFormError(null);
                createGrant.mutate(nextDraft);
              }}
            >
              <Input
                label="Artifact ID"
                value={grantDraft.artifact_id}
                onChange={(event) =>
                  setGrantDraft({ ...grantDraft, artifact_id: event.target.value })
                }
                placeholder="UUID from quarantine/report/case"
              />
              <Input
                label="Tenant message ID"
                value={grantDraft.tenant_message_id}
                onChange={(event) =>
                  setGrantDraft({ ...grantDraft, tenant_message_id: event.target.value })
                }
                placeholder="optional unless quarantine case"
              />
              <Select
                label="Skill"
                value={activeSkill}
                onChange={(event) => setGrantDraft({ ...grantDraft, skill: event.target.value })}
                options={skillOptions}
              />
              <Select
                label="Resource type"
                value={grantDraft.resource_type}
                onChange={(event) =>
                  setGrantDraft({ ...grantDraft, resource_type: event.target.value })
                }
                options={resourceOptions}
              />
              <Select
                label="Purpose"
                value={grantDraft.purpose}
                onChange={(event) => setGrantDraft({ ...grantDraft, purpose: event.target.value })}
                options={purposeOptions}
              />
              <Input
                label="TTL minutes"
                type="number"
                min="5"
                max="1440"
                value={grantDraft.ttl_minutes}
                onChange={(event) =>
                  setGrantDraft({ ...grantDraft, ttl_minutes: event.target.value })
                }
              />
              {formError || grantError ? (
                <p className="deep-ai-error">{formError ?? grantError}</p>
              ) : null}
              {createGrant.isError ? <StepUpPrompt error={createGrant.error} /> : null}
              <Button type="submit" disabled={createGrant.isPending}>
                {createGrant.isPending ? "Creating grant…" : "Create scoped grant"}
              </Button>
            </form>
          ) : (
            <p className="deep-ai-muted">
              You can view grants, but cannot create new Deep AI access.
            </p>
          )}
          <div className="deep-ai-grants">
            {data.artifact_grants.map((grant) => (
              <div className="deep-ai-grant" key={grant.id}>
                <div>
                  <strong>{grant.resource_type.replaceAll("_", " ")}</strong>
                  <span>
                    {shortId(grant.artifact_id)} · {grant.skill_id}
                  </span>
                </div>
                <small>expires {formatDate(grant.expires_at)}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="deep-ai-panel">
          <h2>Validated findings</h2>
          <div className="deep-ai-results">
            {data.analysis_results.length === 0 ? (
              <p className="deep-ai-muted">No Deep AI findings recorded yet.</p>
            ) : null}
            {data.analysis_results.map((result) => (
              <div className="deep-ai-result" key={result.id}>
                <div className="deep-ai-result-head">
                  <StatusPill tone={severityTone(result.severity)} label={result.severity} />
                  <StatusPill
                    tone={stateTone(result.validation_state)}
                    label={result.validation_state}
                  />
                </div>
                <strong>
                  {result.classification} · {result.attack_type}
                </strong>
                <p>{result.analyst_summary}</p>
                <small>
                  {result.skill_id}/{result.skill_version} · confidence{" "}
                  {Math.round(result.confidence * 100)}% · {formatDate(result.created_at)}
                </small>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="deep-ai-panel">
        <h2>Release rollback</h2>
        <p className="deep-ai-muted">
          Roll back a released skill and/or approved model release. This is audited and requires an
          idempotency key; it does not execute mail or remediation actions.
        </p>
        {canManage ? (
          <form
            className="deep-ai-form"
            onSubmit={(event) => {
              event.preventDefault();
              const hasSkill =
                rollbackDraft.skill_id.trim() &&
                rollbackDraft.current_skill_version.trim() &&
                rollbackDraft.rollback_skill_version.trim();
              const hasModel =
                rollbackDraft.model_release.trim() &&
                rollbackDraft.rollback_to_model_release.trim();
              if ((!hasSkill && !hasModel) || rollbackDraft.reason.trim().length < 12) {
                setFormError("Provide a skill or model rollback target and a substantive reason.");
                return;
              }
              setFormError(null);
              rollbackRelease.mutate(rollbackDraft);
            }}
          >
            <Input
              label="Skill ID"
              value={rollbackDraft.skill_id}
              onChange={(event) =>
                setRollbackDraft({ ...rollbackDraft, skill_id: event.target.value })
              }
              placeholder="security.message.deep_analysis"
            />
            <Input
              label="Current skill version"
              value={rollbackDraft.current_skill_version}
              onChange={(event) =>
                setRollbackDraft({ ...rollbackDraft, current_skill_version: event.target.value })
              }
              placeholder="v2"
            />
            <Input
              label="Rollback skill version"
              value={rollbackDraft.rollback_skill_version}
              onChange={(event) =>
                setRollbackDraft({ ...rollbackDraft, rollback_skill_version: event.target.value })
              }
              placeholder="v1"
            />
            <Input
              label="Model release"
              value={rollbackDraft.model_release}
              onChange={(event) =>
                setRollbackDraft({ ...rollbackDraft, model_release: event.target.value })
              }
              placeholder="qwen-phase7-v2"
            />
            <Input
              label="Rollback model release"
              value={rollbackDraft.rollback_to_model_release}
              onChange={(event) =>
                setRollbackDraft({
                  ...rollbackDraft,
                  rollback_to_model_release: event.target.value,
                })
              }
              placeholder="qwen-phase7-v1"
            />
            <Input
              label="Rollback reason"
              value={rollbackDraft.reason}
              onChange={(event) =>
                setRollbackDraft({ ...rollbackDraft, reason: event.target.value })
              }
              placeholder="Failed evaluation gate; restoring prior release"
            />
            {formError || rollbackError ? (
              <p className="deep-ai-error">{formError ?? rollbackError}</p>
            ) : null}
            {rollbackRelease.isError ? <StepUpPrompt error={rollbackRelease.error} /> : null}
            <Button type="submit" variant="danger" disabled={rollbackRelease.isPending}>
              {rollbackRelease.isPending ? "Rolling back…" : "Record rollback"}
            </Button>
          </form>
        ) : (
          <p className="deep-ai-muted">
            You can view release state, but cannot roll back releases.
          </p>
        )}
      </section>

      <section className="deep-ai-panel">
        <h2>Training governance</h2>
        <div className="deep-ai-datasets">
          {data.training_datasets.map((dataset) => (
            <div className="deep-ai-dataset" key={dataset.dataset_version}>
              <div>
                <strong>{dataset.dataset_version}</strong>
                <span>
                  {dataset.region} · {dataset.allowed_data_classes.join(", ")}
                </span>
              </div>
              <StatusPill tone={stateTone(dataset.approval_state)} label={dataset.approval_state} />
              <p>{dataset.provenance}</p>
              <small>{dataset.deletion_withdrawal_process}</small>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export default DeepAi;

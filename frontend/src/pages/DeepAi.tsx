import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  BrainCircuit,
  ClipboardList,
  DatabaseZap,
  KeyRound,
  ShieldCheck,
  ShieldOff,
  Undo2,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";

import { api, type ApiError } from "../api/client";
import { hasPermission, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { StatusPill } from "../components/StatusPill";
import { ControlRail } from "../components/ControlRail";
import { Hint } from "../components/primitives/Hint";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
import {
  analysisVerdictLabel,
  approvalStateLabel,
  attackTypeLabel,
  deepAiStateLabel,
  findingCategoryLabel,
  grantResourceLabel,
  HINTS,
  recommendedActionLabel,
  resultOriginLabel,
  tokenLabel,
} from "../lib/labels";
import { severityLabel } from "../lib/status";
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
  /** Set by the revoke route from the authenticated session, never by a client. */
  revoked_by: string | null;
  revoke_reason: string | null;
}

/**
 * Returned by `POST /api/v1/deep-ai/artifact-grants/:grant_id/revoke`.
 * `changed` is false when the grant was already revoked, so a repeated request
 * reports the existing record instead of pretending to have ended access again.
 */
interface RevokeGrantResponse {
  id: string;
  artifact_id: string;
  revoked_at: string;
  revoked_by: string;
  reason: string;
  changed: boolean;
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
  /** `model_runtime` or `administrator`, decided by the server; null on rows
   * written before origin tracking existed. */
  recorded_by: string | null;
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

interface ResultDraft {
  grantId: string;
  modelRelease: string;
  classification: string;
  attackType: string;
  severity: string;
  confidence: string;
  recommendedAction: string;
  impersonatedEntity: string;
  observations: string;
  analystSummary: string;
  processingDurationMs: string;
}

const defaultResultDraft: ResultDraft = {
  grantId: "",
  modelRelease: "",
  classification: "suspicious",
  attackType: "unknown",
  severity: "medium",
  confidence: "",
  recommendedAction: "escalate",
  impersonatedEntity: "",
  observations: "",
  analystSummary: "",
  processingDurationMs: "",
};

/**
 * The finding vocabularies below mirror the server's checked lists in
 * `validate_result_request`. The server stays authoritative; these exist so the
 * form offers only values it will accept.
 */
const CLASSIFICATIONS = ["clean", "suspicious", "malicious", "unknown", "error"] as const;
const ATTACK_TYPES = [
  "none",
  "phishing",
  "bec",
  "impersonation",
  "malware",
  "spam",
  "scam",
  "unknown",
] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical", "unknown"] as const;
const RECOMMENDED_ACTIONS = [
  "deliver",
  "hold",
  "quarantine",
  "block",
  "escalate",
  "release",
  "unknown",
] as const;

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

/**
 * A grant can be cited by a new finding only while it is open. Revoked or
 * expired grants stay listed as history, but the server refuses a result that
 * references one.
 */
function grantIsLive(grant: DeepAiGrant): boolean {
  return grant.revoked_at === null && new Date(grant.expires_at).getTime() > Date.now();
}

/**
 * Mirrors `validate_revocation_reason` on the server. A revocation reason is
 * stored on the grant and in the audit record, so it has to read as a sentence
 * someone later can act on. The server stays authoritative; this only reports
 * the failure before the request goes out.
 */
const REVOCATION_REASON_MIN = 12;
const REVOCATION_REASON_MAX = 500;

/** Named apart from the component's `revocationReasonError` state, which would
 * otherwise shadow this helper inside the render body. */
function revocationReasonProblem(reason: string): string | null {
  const trimmed = reason.trim();
  if (trimmed.length < REVOCATION_REASON_MIN) {
    return `Write at least ${REVOCATION_REASON_MIN} characters so a reader knows why this access ended.`;
  }
  if (trimmed.length > REVOCATION_REASON_MAX) {
    return `Keep the reason under ${REVOCATION_REASON_MAX} characters.`;
  }
  return null;
}

type ResultField =
  | "grantId"
  | "modelRelease"
  | "observations"
  | "analystSummary"
  | "confidence"
  | "processingDurationMs";

/**
 * Mirrors the bounds the server applies in `validate_result_request` so an
 * operator is told which field is short before the request goes out. The server
 * stays authoritative; nothing here relaxes it.
 */
function resultFieldErrors(draft: ResultDraft): Partial<Record<ResultField, string>> {
  const errors: Partial<Record<ResultField, string>> = {};
  if (draft.grantId === "") {
    errors.grantId = "Choose the open grant this finding was made under.";
  }
  if (draft.modelRelease === "") {
    errors.modelRelease = "Choose the approved release that ran this analysis.";
  }
  const summary = draft.analystSummary.trim();
  if (summary.length < 12) {
    errors.analystSummary = "Write at least 12 characters so a reader can act on this finding.";
  } else if (summary.length > 4000) {
    errors.analystSummary = "Keep the summary under 4000 characters.";
  }
  const confidence = Number(draft.confidence);
  if (draft.confidence.trim() === "" || !Number.isFinite(confidence)) {
    errors.confidence = "Confidence is required, from 0 to 1.";
  } else if (confidence < 0 || confidence > 1) {
    errors.confidence = "Confidence must be between 0 and 1.";
  }
  if (draft.observations.trim() === "") {
    errors.observations = "Record at least one observation this finding rests on.";
  }
  const duration = Number(draft.processingDurationMs);
  if (
    draft.processingDurationMs.trim() !== "" &&
    (!Number.isFinite(duration) || duration < 0 || !Number.isInteger(duration))
  ) {
    errors.processingDurationMs = "Duration is whole milliseconds, 0 or more.";
  }
  return errors;
}

export function DeepAi() {
  const queryClient = useQueryClient();
  const [grantDraft, setGrantDraft] = useState<GrantDraft>(defaultGrantDraft);
  const [rollbackDraft, setRollbackDraft] = useState<RollbackDraft>(defaultRollbackDraft);
  const [grantFormError, setGrantFormError] = useState<string | null>(null);
  const [rollbackFormError, setRollbackFormError] = useState<string | null>(null);
  const [resultDraft, setResultDraft] = useState<ResultDraft>(defaultResultDraft);
  const [resultErrors, setResultErrors] = useState<Partial<Record<ResultField, string>>>({});
  const [resultFormError, setResultFormError] = useState<string | null>(null);
  /** Only one grant can be mid-revocation at a time, so the reason form belongs
   * to a single card rather than appearing beside every open grant. */
  const [revokingGrantId, setRevokingGrantId] = useState<string | null>(null);
  const [revocationReason, setRevocationReason] = useState("");
  const [revocationReasonError, setRevocationReasonError] = useState<string | null>(null);
  const rollbackPanelRef = useRef<HTMLElement>(null);
  const resultPanelRef = useRef<HTMLElement>(null);
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

  /** Grants a new finding can cite: still open, not revoked, not expired. */
  const liveGrants = useMemo(
    () => (deepAi.data?.artifact_grants ?? []).filter(grantIsLive),
    [deepAi.data?.artifact_grants],
  );
  const grantOptions = useMemo(
    () =>
      liveGrants.map((grant) => ({
        value: grant.id,
        label: `${grantResourceLabel(grant.resource_type)} · ${shortId(grant.artifact_id)} · ${grant.skill_id}/${grant.skill_version}`,
      })),
    [liveGrants],
  );
  const releaseOptions = useMemo(
    () =>
      (deepAi.data?.model_releases ?? [])
        .filter((release) => release.approval_state === "approved")
        .map((release) => ({
          value: release.model_release,
          label: `${release.model_release} · ${release.region}`,
        })),
    [deepAi.data?.model_releases],
  );
  const classificationOptions = useMemo(
    () => CLASSIFICATIONS.map((value) => ({ value, label: analysisVerdictLabel(value) })),
    [],
  );
  const attackTypeOptions = useMemo(
    () => ATTACK_TYPES.map((value) => ({ value, label: attackTypeLabel(value) })),
    [],
  );
  const severityOptions = useMemo(
    () => SEVERITIES.map((value) => ({ value, label: severityLabel(value) })),
    [],
  );
  const recommendedActionOptions = useMemo(
    () => RECOMMENDED_ACTIONS.map((value) => ({ value, label: recommendedActionLabel(value) })),
    [],
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
      setGrantFormError(null);
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
      setRollbackFormError(null);
      await queryClient.invalidateQueries({ queryKey: ["deep-ai"] });
    },
  });
  const recordResult = useMutation({
    mutationFn: (draft: ResultDraft) => {
      const grant = (deepAi.data?.artifact_grants ?? []).find(
        (candidate) => candidate.id === draft.grantId,
      );
      if (!grant) throw new Error("Choose an open artifact grant for this finding.");
      return api.post<{ id: string; recorded_by: string }>(
        "/deep-ai/analysis-results",
        {
          artifact_grant_id: grant.id,
          // Skill identity is copied from the grant the finding cites, never
          // typed: the server refuses a result whose skill does not match the
          // grant it references.
          skill_id: grant.skill_id,
          skill_version: grant.skill_version,
          model_release: draft.modelRelease,
          classification: draft.classification,
          attack_type: draft.attackType,
          severity: draft.severity,
          confidence: Number(draft.confidence),
          impersonated_entity: draft.impersonatedEntity.trim() || null,
          evidence_references: [`grant:${grant.id}`, `artifact:${grant.artifact_id}`],
          observations: draft.observations
            .split("\n")
            .map((line) => line.trim())
            .filter((line) => line !== ""),
          recommended_action: draft.recommendedAction,
          analyst_summary: draft.analystSummary.trim(),
          processing_duration_ms:
            draft.processingDurationMs.trim() === ""
              ? 0
              : Math.trunc(Number(draft.processingDurationMs)),
        },
        { idempotencyKey: randomUuid() },
      );
    },
    onSuccess: async () => {
      setResultDraft({ ...defaultResultDraft, grantId: resultDraft.grantId });
      setResultErrors({});
      setResultFormError(null);
      await queryClient.invalidateQueries({ queryKey: ["deep-ai"] });
    },
  });

  const revokeGrant = useMutation({
    mutationFn: ({ grantId, reason }: { grantId: string; reason: string }) =>
      api.post<RevokeGrantResponse>(
        `/deep-ai/artifact-grants/${grantId}/revoke`,
        { reason },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async () => {
      setRevokingGrantId(null);
      setRevocationReason("");
      setRevocationReasonError(null);
      await queryClient.invalidateQueries({ queryKey: ["deep-ai"] });
    },
  });

  function beginSkillRollback(skill: DeepAiSkill) {
    setRollbackDraft({
      skill_id: skill.skill_id,
      current_skill_version: skill.skill_version,
      rollback_skill_version: skill.rollback_skill_version ?? "",
      model_release: "",
      rollback_to_model_release: "",
      reason: "",
    });
    setRollbackFormError(null);
    rollbackRelease.reset();
    rollbackPanelRef.current?.scrollIntoView?.({ block: "start" });
  }

  function beginModelRollback(release: DeepAiModelRelease) {
    setRollbackDraft({
      skill_id: "",
      current_skill_version: "",
      rollback_skill_version: "",
      model_release: release.model_release,
      rollback_to_model_release: release.rollback_to_model_release ?? "",
      reason: "",
    });
    setRollbackFormError(null);
    rollbackRelease.reset();
    rollbackPanelRef.current?.scrollIntoView?.({ block: "start" });
  }

  /** Opens the finding form pre-cited to the grant this card belongs to. */
  function beginResultFromGrant(grant: DeepAiGrant) {
    setResultDraft({ ...defaultResultDraft, grantId: grant.id });
    setResultErrors({});
    setResultFormError(null);
    recordResult.reset();
    resultPanelRef.current?.scrollIntoView?.({ block: "start" });
  }

  /**
   * Opens the reason form inside this grant's card. A revocation ends access for
   * good, so the reason is collected before anything is sent rather than asked
   * for after the fact.
   */
  function beginGrantRevocation(grant: DeepAiGrant) {
    setRevokingGrantId(grant.id);
    setRevocationReason("");
    setRevocationReasonError(null);
    revokeGrant.reset();
  }

  function cancelGrantRevocation() {
    setRevokingGrantId(null);
    setRevocationReason("");
    setRevocationReasonError(null);
    revokeGrant.reset();
  }

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
  const grantError = createGrant.isError ? errorMessage(createGrant.error) : null;
  const rollbackError = rollbackRelease.isError ? errorMessage(rollbackRelease.error) : null;
  const latestBenchmark = data.regional_benchmarks[0] ?? null;
  const citedGrant = liveGrants.find((grant) => grant.id === resultDraft.grantId) ?? null;
  const resultError = recordResult.isError ? errorMessage(recordResult.error) : null;
  const revocationError = revokeGrant.isError ? errorMessage(revokeGrant.error) : null;
  /**
   * Why the form cannot be submitted yet, in the words an operator acts on.
   * Empty when every input the server needs is available.
   */
  const resultLock =
    grantOptions.length === 0
      ? "A finding has to cite an open artifact grant, and none is open for this customer. Create a scoped grant first."
      : releaseOptions.length === 0
        ? "A finding cites an approved model release, and this deployment has none. Approve one on the model list first."
        : "";

  return (
    <div className="deep-ai-page">
      <WorkspaceHeader
        eyebrow="Model governance"
        title="Regional Deep AI"
        description="Versioned skills, scoped artifact grants, validated findings and training governance for this deployment."
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
                  {canManage ? <th>Actions</th> : null}
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
                        label={deepAiStateLabel(skill.release_state)}
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
                    {canManage ? (
                      <td>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          onClick={() => beginSkillRollback(skill)}
                        >
                          <Undo2 size={13} aria-hidden="true" />
                          Roll back
                        </button>
                      </td>
                    ) : null}
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
                <div className="deep-ai-release-side">
                  <StatusPill
                    tone={stateTone(release.approval_state)}
                    label={approvalStateLabel(release.approval_state)}
                  />
                  {canManage ? (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => beginModelRollback(release)}
                    >
                      <Undo2 size={13} aria-hidden="true" />
                      Roll back release
                    </button>
                  ) : null}
                </div>
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
            broad S3, database, shell or browser authority. Access that should not wait for its
            expiry can be revoked here, with the reason kept on the record.
          </p>
          {canManage ? (
            <form
              className="deep-ai-form"
              onSubmit={(event) => {
                event.preventDefault();
                const nextDraft = { ...grantDraft, skill: activeSkill };
                if (!nextDraft.artifact_id.trim() || !nextDraft.skill) {
                  setGrantFormError("Artifact ID and released skill are required.");
                  return;
                }
                setGrantFormError(null);
                createGrant.mutate(nextDraft);
              }}
            >
              <Input
                label="Artifact ID"
                value={grantDraft.artifact_id}
                onChange={(event) =>
                  setGrantDraft({ ...grantDraft, artifact_id: event.target.value })
                }
                placeholder="Copy it from the message or case page"
              />
              <Input
                label="Message it came from (optional)"
                value={grantDraft.tenant_message_id}
                onChange={(event) =>
                  setGrantDraft({ ...grantDraft, tenant_message_id: event.target.value })
                }
                placeholder="Only needed for a quarantine case"
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
              {grantFormError || grantError ? (
                <p className="deep-ai-error">{grantFormError ?? grantError}</p>
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
                  <strong>{grantResourceLabel(grant.resource_type)}</strong>
                  <span>
                    {shortId(grant.artifact_id)} · {grant.skill_id}
                  </span>
                  {grant.revoked_at ? (
                    <small className="deep-ai-revoked-by">
                      Revoked by {grant.revoked_by ?? "a record before this console"}
                      {grant.revoke_reason ? `: ${grant.revoke_reason}` : ""}
                    </small>
                  ) : null}
                </div>
                <div className="deep-ai-grant-side">
                  {grant.revoked_at ? (
                    <StatusPill tone="threat" label={`revoked ${formatDate(grant.revoked_at)}`} />
                  ) : (
                    <small>expires {formatDate(grant.expires_at)}</small>
                  )}
                  {canManage && grantIsLive(grant) ? (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => beginResultFromGrant(grant)}
                    >
                      <ClipboardList size={13} aria-hidden="true" />
                      Record a finding
                    </button>
                  ) : null}
                  {/* An expired grant can still be closed out: the record should
                      say the access ended and why, not trail off silently. */}
                  {canManage && grant.revoked_at === null && revokingGrantId !== grant.id ? (
                    <Hint label={HINTS.grantRevocation}>
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => beginGrantRevocation(grant)}
                      >
                        <ShieldOff size={13} aria-hidden="true" />
                        Revoke grant
                      </button>
                    </Hint>
                  ) : null}
                </div>
                {revokingGrantId === grant.id ? (
                  <form
                    className="deep-ai-grant-revoke"
                    onSubmit={(event) => {
                      event.preventDefault();
                      const reasonError = revocationReasonProblem(revocationReason);
                      if (reasonError) {
                        setRevocationReasonError(reasonError);
                        return;
                      }
                      setRevocationReasonError(null);
                      revokeGrant.mutate({
                        grantId: grant.id,
                        reason: revocationReason.trim(),
                      });
                    }}
                  >
                    <Input
                      label="Reason this access ends"
                      autoFocus
                      value={revocationReason}
                      onChange={(event) => {
                        setRevocationReason(event.target.value);
                        if (revocationReasonError) setRevocationReasonError(null);
                      }}
                      placeholder="Review is complete; no further analysis needed on this artifact."
                      hint="Saved with the grant and in the audit record. 12 to 500 characters."
                      error={revocationReasonError ?? undefined}
                      disabled={revokeGrant.isPending}
                    />
                    {revocationError ? (
                      <p className="deep-ai-error" role="alert">
                        {revocationError}
                      </p>
                    ) : null}
                    {revokeGrant.isError ? <StepUpPrompt error={revokeGrant.error} /> : null}
                    <div className="deep-ai-grant-revoke-actions">
                      <Button
                        type="submit"
                        variant="danger"
                        loading={revokeGrant.isPending}
                        disabled={revokeGrant.isPending}
                      >
                        {revokeGrant.isPending ? "Revoking grant…" : "Revoke this grant"}
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        onClick={cancelGrantRevocation}
                        disabled={revokeGrant.isPending}
                      >
                        Cancel revocation
                      </Button>
                    </div>
                  </form>
                ) : null}
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
                  <StatusPill
                    tone={severityTone(result.severity)}
                    label={severityLabel(result.severity)}
                  />
                  <StatusPill
                    tone={stateTone(result.validation_state)}
                    label={deepAiStateLabel(result.validation_state)}
                  />
                </div>
                <strong>
                  {analysisVerdictLabel(result.classification)} ·{" "}
                  {findingCategoryLabel(result.attack_type)}
                </strong>
                <p>{result.analyst_summary}</p>
                <small>
                  {result.skill_id}/{result.skill_version} · confidence{" "}
                  {Math.round(result.confidence * 100)}% · {formatDate(result.created_at)}
                </small>
                <div className="deep-ai-result-foot">
                  <Hint label={HINTS.resultOrigin}>
                    <span className="deep-ai-origin">{resultOriginLabel(result.recorded_by)}</span>
                  </Hint>
                  <span>Recommends: {recommendedActionLabel(result.recommended_action)}</span>
                </div>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="deep-ai-panel" ref={resultPanelRef}>
        <h2>Record a finding</h2>
        <p className="deep-ai-subtitle">
          Write down what an analysis concluded so it can be reviewed, cited and measured against
          later mail. A finding made here is labelled as entered by an administrator, never as model
          output.
        </p>
        {canManage ? (
          <form
            className="deep-ai-form"
            onSubmit={(event) => {
              event.preventDefault();
              const nextErrors = resultFieldErrors(resultDraft);
              setResultErrors(nextErrors);
              if (Object.keys(nextErrors).length > 0) {
                setResultFormError("Fix the highlighted fields before recording this finding.");
                return;
              }
              setResultFormError(null);
              recordResult.mutate(resultDraft);
            }}
          >
            <Select
              label="Open grant this finding cites"
              value={resultDraft.grantId}
              onChange={(event) => setResultDraft({ ...resultDraft, grantId: event.target.value })}
              options={grantOptions}
              placeholder={grantOptions.length === 0 ? "No open grant" : "Choose a grant"}
              error={resultErrors.grantId}
              hint={HINTS.citedEvidence}
            />
            <Select
              label="Release that ran the analysis"
              value={resultDraft.modelRelease}
              onChange={(event) =>
                setResultDraft({ ...resultDraft, modelRelease: event.target.value })
              }
              options={releaseOptions}
              placeholder={releaseOptions.length === 0 ? "No approved release" : "Choose a release"}
              error={resultErrors.modelRelease}
              hint={HINTS.modelReleaseChoice}
            />
            <Select
              label="Verdict"
              value={resultDraft.classification}
              onChange={(event) =>
                setResultDraft({ ...resultDraft, classification: event.target.value })
              }
              options={classificationOptions}
            />
            <Select
              label="Attack type"
              value={resultDraft.attackType}
              onChange={(event) =>
                setResultDraft({ ...resultDraft, attackType: event.target.value })
              }
              options={attackTypeOptions}
            />
            <Select
              label="Severity"
              value={resultDraft.severity}
              onChange={(event) => setResultDraft({ ...resultDraft, severity: event.target.value })}
              options={severityOptions}
            />
            <Select
              label="Recommended action"
              value={resultDraft.recommendedAction}
              onChange={(event) =>
                setResultDraft({ ...resultDraft, recommendedAction: event.target.value })
              }
              options={recommendedActionOptions}
            />
            <Input
              label="Confidence (0 to 1)"
              type="number"
              min="0"
              max="1"
              step="0.05"
              value={resultDraft.confidence}
              onChange={(event) =>
                setResultDraft({ ...resultDraft, confidence: event.target.value })
              }
              error={resultErrors.confidence}
              placeholder="0.85"
            />
            <Input
              label="How long the analysis took (milliseconds)"
              type="number"
              min="0"
              step="1"
              value={resultDraft.processingDurationMs}
              onChange={(event) =>
                setResultDraft({ ...resultDraft, processingDurationMs: event.target.value })
              }
              error={resultErrors.processingDurationMs}
              placeholder="optional"
            />
            <div className="deep-ai-field">
              <label htmlFor="deep-ai-observations" className="deep-ai-field-label">
                What was seen
              </label>
              <textarea
                id="deep-ai-observations"
                className="deep-ai-textarea"
                rows={3}
                value={resultDraft.observations}
                onChange={(event) =>
                  setResultDraft({ ...resultDraft, observations: event.target.value })
                }
                placeholder={
                  "One observation per line, for example: sender domain registered 4 days ago"
                }
                aria-describedby={
                  resultErrors.observations ? "deep-ai-observations-error" : undefined
                }
              />
              {resultErrors.observations ? (
                <p id="deep-ai-observations-error" className="deep-ai-field-error" role="alert">
                  {resultErrors.observations}
                </p>
              ) : null}
            </div>
            <div className="deep-ai-field">
              <label htmlFor="deep-ai-summary" className="deep-ai-field-label">
                Summary for a reviewer
              </label>
              <textarea
                id="deep-ai-summary"
                className="deep-ai-textarea"
                rows={3}
                maxLength={4000}
                value={resultDraft.analystSummary}
                onChange={(event) =>
                  setResultDraft({ ...resultDraft, analystSummary: event.target.value })
                }
                placeholder="What this finding means for the message and what you recommend doing about it."
                aria-describedby={resultErrors.analystSummary ? "deep-ai-summary-error" : undefined}
              />
              {resultErrors.analystSummary ? (
                <p id="deep-ai-summary-error" className="deep-ai-field-error" role="alert">
                  {resultErrors.analystSummary}
                </p>
              ) : (
                <p className="input-hint">
                  Between 12 and 4000 characters. This is the text a reviewer reads first.
                </p>
              )}
            </div>
            <Input
              label="Accounted for as (optional)"
              value={resultDraft.impersonatedEntity}
              onChange={(event) =>
                setResultDraft({ ...resultDraft, impersonatedEntity: event.target.value })
              }
              placeholder="person or brand the message posed as"
            />
            {citedGrant ? (
              <p className="deep-ai-evidence">
                Cites <code>grant:{shortId(citedGrant.id)}</code> and{" "}
                <code>artifact:{shortId(citedGrant.artifact_id)}</code> · skill{" "}
                {citedGrant.skill_id}/{citedGrant.skill_version}
              </p>
            ) : null}
            {resultLock !== "" ? <p className="deep-ai-note">{resultLock}</p> : null}
            {resultFormError || resultError ? (
              <p className="deep-ai-error">{resultFormError ?? resultError}</p>
            ) : null}
            {recordResult.isError ? <StepUpPrompt error={recordResult.error} /> : null}
            <Button type="submit" disabled={recordResult.isPending || resultLock !== ""}>
              {recordResult.isPending ? "Recording finding…" : "Record finding"}
            </Button>
          </form>
        ) : (
          <p className="deep-ai-muted">
            You can read findings, but recording one needs the Deep AI management permission.
          </p>
        )}
      </section>

      <section className="deep-ai-panel" ref={rollbackPanelRef}>
        <h2>Release rollback</h2>
        <p className="deep-ai-muted">
          Roll back a released skill, an approved model release, or both. Pressing the button once
          is enough: repeating it does not roll back twice. This changes which version answers
          future analyses, it does not act on any message.
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
                setRollbackFormError(
                  "Provide a skill or model rollback target and a substantive reason.",
                );
                return;
              }
              setRollbackFormError(null);
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
            {rollbackFormError || rollbackError ? (
              <p className="deep-ai-error">{rollbackFormError ?? rollbackError}</p>
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
                  {dataset.region} · data in it:{" "}
                  {dataset.allowed_data_classes.map(tokenLabel).join(", ")}
                </span>
              </div>
              <StatusPill
                tone={stateTone(dataset.approval_state)}
                label={approvalStateLabel(dataset.approval_state)}
              />
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

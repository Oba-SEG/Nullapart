import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api, type ApiError } from "../api/client";
import {
  CONDITION_SCOPES,
  DISPOSITIONS,
  FINDING_CATEGORIES,
  FINDING_SEVERITIES,
  NOTIFY_TARGETS,
  SCANNER_TYPES,
  AUTH_RESULTS,
  cloneRulesForEditing,
  draftErrors,
  draftFromRule,
  isDraftValid,
  newRuleDraft,
  resequenceRules,
  ruleFromDraft,
  sortByEvaluationOrder,
  tierAllows,
  type AuthResult,
  type ClassBandEntry,
  type ConditionFieldProfile,
  type ConditionScope,
  type Disposition,
  type FindingCategory,
  type FindingSeverity,
  type NotifyTarget,
  type PolicyDetail,
  type PolicyPublishBody,
  type PolicyRevision,
  type PublishResult,
  type RefreshResult,
  type Rule,
  type RuleDraft,
  type RuleProfile,
  type ScannerType,
  type TriState,
} from "../api/policies";
import { hasPermission, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { ControlRail } from "../components/ControlRail";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
import { humanizeToken } from "../lib/text";
import {
  AUTH_RESULT_LABELS,
  CONDITION_FIELD_LABELS,
  CONDITION_SCOPE_LABELS,
  ENFORCEMENT_MODE_LABELS,
  FINDING_CATEGORY_LABELS,
  FINDING_SEVERITY_LABELS,
  HINTS,
  MANAGEMENT_LEVEL_LABELS,
  NOTIFY_TARGET_LABELS,
  OVERRIDE_SCOPE_LABELS,
  POLICY_DISPOSITION_LABELS,
  SCANNER_LABELS,
  TENANT_LEVEL_LABELS,
  familyDisplayName,
  reasonCodeLabel,
  summarizeRuleCondition,
  tenantLevelBucket,
} from "../lib/labels";
import "./PolicyFamilyDetail.css";

const TRI_OPTIONS = [
  { value: "", label: "Not set" },
  { value: "true", label: "Yes" },
  { value: "false", label: "No" },
];

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : "";
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    const message = String((error as ApiError).message);
    if (errorCode(error) === "RATE_LIMITED") {
      return `${message} Please wait a moment before retrying.`;
    }
    return message;
  }
  return "Policy data is temporarily unavailable.";
}

// A rejected publish stays actionable: the safe server message plus a hint for
// the two failures the structured editor can actually correct.
function publishErrorMessage(error: unknown): string {
  const code = errorCode(error);
  const message = errorMessage(error);
  if (code === "INVALID_REQUEST" || code === "IDEMPOTENCY_REQUIRED" || code === "HTTP_400") {
    return `${message} Review the rule fields and try again.`;
  }
  if (code === "FORBIDDEN" || code === "HTTP_403") {
    return `${message} Your account is not allowed to publish this policy family.`;
  }
  return message;
}

function revisionRulesLabel(revision: PolicyRevision): string {
  if (typeof revision.rules_count === "number") return String(revision.rules_count);
  if (revision.rules !== null) return String(revision.rules.length);
  return "—";
}

function ruleCarriesMlThresholds(rule: Rule): boolean {
  const metadata = rule.action.metadata;
  return (
    typeof metadata === "object" &&
    metadata !== null &&
    Object.prototype.hasOwnProperty.call(metadata, "thresholds")
  );
}

function publishWouldClearMlThresholds(familyKey: string, rules: Rule[] | null): boolean {
  return (
    familyKey === "ml_threat_classification" &&
    rules !== null &&
    !rules.some(ruleCarriesMlThresholds)
  );
}

function toggleInList<T>(values: T[], value: T): T[] {
  return values.includes(value) ? values.filter((entry) => entry !== value) : [...values, value];
}

interface TriSelectProps {
  label: string;
  value: TriState;
  onChange: (value: TriState) => void;
}

function TriSelect({ label, value, onChange }: TriSelectProps) {
  return (
    <Select
      label={label}
      value={value === null ? "" : String(value)}
      options={TRI_OPTIONS}
      onChange={(event) => {
        const next = event.target.value;
        onChange(next === "" ? null : next === "true");
      }}
    />
  );
}

interface CheckGroupProps<T extends string> {
  legend: string;
  values: T[];
  options: T[];
  /** Operator-facing wording per option; falls back to the wire value. */
  labels?: Record<T, string>;
  onToggle: (value: T) => void;
}

function CheckGroup<T extends string>({
  legend,
  values,
  options,
  labels,
  onToggle,
}: CheckGroupProps<T>) {
  return (
    <fieldset className="policy-detail-checkset">
      <legend>{legend}</legend>
      <div className="policy-detail-checks">
        {options.map((option) => (
          <label key={option} className="policy-detail-check">
            <input
              type="checkbox"
              checked={values.includes(option)}
              onChange={() => onToggle(option)}
            />
            {labels?.[option] ?? option}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/** Joins labels so a group of condition names reads as one sentence. */
function joinLabels(labels: string[]): string {
  if (labels.length <= 1) return labels[0] ?? "";
  return `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
}

interface ConditionNoticeProps {
  conditions: ConditionFieldProfile[];
}

/**
 * Which condition groups the delivery path never evaluates, in the words the
 * server publishes. A family whose predicates are read shows nothing here, so
 * the warning cannot survive the change that makes conditions real.
 */
function ConditionNotice({ conditions }: ConditionNoticeProps) {
  const byNote = new Map<string, string[]>();
  for (const entry of conditions) {
    if (entry.honoured) continue;
    const labels = byNote.get(entry.note) ?? [];
    labels.push(CONDITION_FIELD_LABELS[entry.field]);
    byNote.set(entry.note, labels);
  }
  if (byNote.size === 0) return null;
  return (
    <div className="policy-detail-stored-only">
      {[...byNote.entries()].map(([note, labels]) => (
        <p key={note}>
          <strong>{joinLabels(labels)}</strong> {labels.length === 1 ? "is" : "are"} recorded on the
          rule but never evaluated. {note}
        </p>
      ))}
    </div>
  );
}

/** Class keys the profile declares, in taxonomy order, minus the ones already banded. */
function remainingClasses(classes: string[], draft: RuleDraft): string[] {
  return classes.filter((classKey) => draft.classBands[classKey] === undefined);
}

/** Keys of a stored payload this family has no form for, so a notice can name them. */
function storedMetadataKeys(metadata: Record<string, unknown> | undefined): string[] {
  return metadata === undefined ? [] : Object.keys(metadata);
}

function classLabel(classKey: string): string {
  const known = FINDING_CATEGORY_LABELS[classKey as FindingCategory];
  return known ?? humanizeToken(classKey);
}

/** Each band point, in the words an operator sets an operating point with. */
const BAND_PART_LABELS: Record<keyof ClassBandEntry, string> = {
  low: "Becomes a finding at",
  medium: "Medium band above",
  high: "High band above",
};

interface MetadataFieldsProps {
  profile: RuleProfile;
  draft: RuleDraft;
  errors: Record<string, string | undefined>;
  showErrors: boolean;
  onDraftChange: (next: RuleDraft) => void;
}

/**
 * The threshold form for one family, built from the keys its runtime reader
 * actually consumes. `exact_keys` families publish all declared keys or none,
 * so a partial set is refused here rather than at publish time.
 */
function MetadataFields({
  profile,
  draft,
  errors,
  showErrors,
  onDraftChange,
}: MetadataFieldsProps) {
  const metadata = profile.metadata;
  if (!metadata.read || metadata.fields.length === 0) return null;

  const bandField = metadata.fields.find((field) => field.kind === "class_bands");
  const scalarFields = metadata.fields.filter((field) => field.kind !== "class_bands");
  const setScalar = (key: string, value: string) =>
    onDraftChange({ ...draft, metadataValues: { ...draft.metadataValues, [key]: value } });
  const setBand = (classKey: string, part: keyof ClassBandEntry, value: string) => {
    const current = draft.classBands[classKey] ?? { low: "", medium: "", high: "" };
    onDraftChange({
      ...draft,
      classBands: { ...draft.classBands, [classKey]: { ...current, [part]: value } },
    });
  };
  const addBand = (classKey: string) => {
    if (classKey.length === 0 || draft.classBands[classKey] !== undefined) return;
    onDraftChange({
      ...draft,
      classBands: { ...draft.classBands, [classKey]: { low: "", medium: "", high: "" } },
    });
  };
  const removeBand = (classKey: string) => {
    const next = { ...draft.classBands };
    delete next[classKey];
    onDraftChange({ ...draft, classBands: next });
  };
  const bandedClasses = (bandField?.classes ?? []).filter(
    (key) => draft.classBands[key] !== undefined,
  );

  return (
    <fieldset className="policy-detail-fieldset">
      <legend>{bandField !== undefined ? bandField.label : "Limits this rule sets"}</legend>
      <p className="policy-detail-hint">{metadata.merge}</p>
      {bandField !== undefined ? <p className="policy-detail-hint">{bandField.hint}</p> : null}

      {scalarFields.map((field) => {
        const value = draft.metadataValues[field.key] ?? "";
        const error = showErrors || value.trim().length > 0 ? errors[field.key] : undefined;
        return (
          <Input
            key={field.key}
            label={field.label}
            type="number"
            min={field.min ?? undefined}
            max={field.max ?? undefined}
            step="any"
            value={value}
            placeholder={field.default === null ? undefined : String(field.default)}
            onChange={(event) => setScalar(field.key, event.target.value)}
            error={error}
            hint={
              field.default === null
                ? field.hint
                : `${field.hint} Left empty, the built-in ${field.default} stays in force.`
            }
          />
        );
      })}

      {bandField !== undefined ? (
        <>
          {bandedClasses.map((classKey) => {
            const entry = draft.classBands[classKey] ?? { low: "", medium: "", high: "" };
            const rowError =
              showErrors || entry.low.length + entry.medium.length + entry.high.length > 0
                ? errors[`${bandField.key}:${classKey}`]
                : undefined;
            return (
              <div className="policy-detail-band" key={classKey}>
                <div className="policy-detail-band-head">
                  <span className="policy-detail-band-class">{classLabel(classKey)}</span>
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    onClick={() => removeBand(classKey)}
                  >
                    Remove class
                  </Button>
                </div>
                <div className="policy-detail-band-inputs">
                  {(["low", "medium", "high"] as const).map((part) => (
                    <Input
                      key={part}
                      label={BAND_PART_LABELS[part]}
                      type="number"
                      min={bandField.min ?? undefined}
                      max={bandField.max ?? undefined}
                      step="any"
                      value={entry[part]}
                      onChange={(event) => setBand(classKey, part, event.target.value)}
                    />
                  ))}
                </div>
                {rowError ? (
                  <p className="policy-detail-error" role="alert">
                    {rowError}
                  </p>
                ) : null}
              </div>
            );
          })}
          {remainingClasses(bandField.classes ?? [], draft).length > 0 ? (
            <Select
              label="Add a class band"
              value=""
              options={[
                { value: "", label: "Choose a class" },
                ...remainingClasses(bandField.classes ?? [], draft).map((classKey) => ({
                  value: classKey,
                  label: classLabel(classKey),
                })),
              ]}
              onChange={(event) => addBand(event.target.value)}
              hint="Only the classes you add are published. A class with no band produces no finding."
            />
          ) : (
            <p className="policy-detail-hint">Every class already has a band row.</p>
          )}
        </>
      ) : null}
    </fieldset>
  );
}

export function PolicyFamilyDetail() {
  const { familyKey = "" } = useParams({ from: "/policies/$familyKey" });
  const queryClient = useQueryClient();

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const detail = useQuery({
    queryKey: ["policy-family", familyKey],
    queryFn: ({ signal }) =>
      api.get<PolicyDetail>(`/policies/${encodeURIComponent(familyKey)}`, signal),
    enabled: familyKey.length > 0,
  });

  const current = session.data ?? null;
  const canManage = hasPermission(current, "policies:manage");
  const family = detail.data?.family ?? null;
  // The tier comes from the server with the family, never re-derived from role
  // names here, so a custom role reaches the same conclusion in UI and API.
  const callerTier = detail.data?.caller_tier ?? null;
  const tenantTier = callerTier === "customer";
  // Every threshold field, predicate note and enforcement sentence below comes
  // from this server-published profile, so the form cannot offer a field the
  // delivery path would ignore.
  const profile = detail.data?.profile ?? null;
  const mayPublish =
    canManage && family !== null && tierAllows(callerTier, family.management_level);

  const activeRevisionNumber = family?.active_revision?.revision_number ?? null;
  const revisions = detail.data?.revisions ?? [];

  const activeRules = useMemo(() => {
    const data = detail.data;
    if (!data) return null;
    const activeNumber = data.family.active_revision?.revision_number ?? null;
    const active =
      data.revisions.find((revision) => revision.revision_number === activeNumber) ??
      data.revisions.find((revision) => revision.rules !== null) ??
      null;
    return active?.rules ?? [];
  }, [detail.data]);

  const [rules, setRules] = useState<Rule[] | null>(null);
  const [syncedRevision, setSyncedRevision] = useState<number | null | undefined>(undefined);
  const [editing, setEditing] = useState<RuleDraft | null>(null);
  const [showErrors, setShowErrors] = useState(false);
  const [publishOpen, setPublishOpen] = useState(false);
  const [publishNotice, setPublishNotice] = useState<string | null>(null);
  const [refreshNotice, setRefreshNotice] = useState<string | null>(null);

  useEffect(() => {
    if (activeRules === null || syncedRevision === activeRevisionNumber) return;
    setRules(cloneRulesForEditing(activeRules));
    setSyncedRevision(activeRevisionNumber);
  }, [activeRules, activeRevisionNumber, syncedRevision]);

  const publish = useMutation({
    mutationFn: (body: PolicyPublishBody) =>
      api.post<PublishResult>(`/policies/${encodeURIComponent(familyKey)}/revisions`, body, {
        idempotencyKey: randomUuid(),
      }),
    onSuccess: async (created) => {
      setPublishOpen(false);
      setPublishNotice(
        `Published revision #${created.revision_number} with ${created.rules_count} rule${
          created.rules_count === 1 ? "" : "s"
        }.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["policy-family", familyKey] });
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
  });

  const refresh = useMutation({
    mutationFn: () =>
      api.post<RefreshResult>(`/policies/${encodeURIComponent(familyKey)}/refresh`, undefined, {
        idempotencyKey: randomUuid(),
      }),
    onSuccess: (result) =>
      setRefreshNotice(
        `Reload requested at ${new Date(result.refresh_requested_at).toLocaleString()}. ` +
          "Delivery servers pick up the published revision on their next reload.",
      ),
  });

  function openEditor(rule?: Rule) {
    setEditing(rule ? draftFromRule(rule, profile ?? undefined) : newRuleDraft());
    setShowErrors(false);
  }

  function closeEditor() {
    setEditing(null);
    setShowErrors(false);
  }

  function saveRule() {
    if (!editing) return;
    if (!isDraftValid(editing, profile ?? undefined)) {
      setShowErrors(true);
      return;
    }
    const rule = ruleFromDraft(editing, profile ?? undefined);
    setRules((previous) => {
      const list = previous ?? [];
      const exists = list.some((entry) => entry.id === rule.id);
      const next = exists
        ? list.map((entry) => (entry.id === rule.id ? rule : entry))
        : [...list, rule];
      return sortByEvaluationOrder(next);
    });
    closeEditor();
  }

  function removeRule(ruleId: string) {
    setRules((previous) =>
      resequenceRules((previous ?? []).filter((entry) => entry.id !== ruleId)),
    );
  }

  function moveRule(index: number, direction: -1 | 1) {
    setRules((previous) => {
      const list = previous ?? [];
      const target = index + direction;
      if (index < 0 || target < 0 || target >= list.length) return list;
      const next = [...list];
      const [moved] = next.splice(index, 1);
      next.splice(target, 0, moved);
      return resequenceRules(next);
    });
  }

  function confirmPublish() {
    const ordered = resequenceRules(rules ?? []);
    setRules(ordered);
    publish.mutate({ rules: ordered });
  }

  const errors = editing ? draftErrors(editing, profile ?? undefined) : {};
  const thresholdClearWarning = publishWouldClearMlThresholds(familyKey, rules);
  const nameError =
    showErrors || (editing !== null && editing.name.length > 0) ? errors.name : undefined;
  const priorityError =
    showErrors || (editing !== null && !Number.isFinite(editing.priority))
      ? errors.priority
      : undefined;
  const reasonCodeError =
    showErrors || (editing !== null && editing.reasonCode.length > 0)
      ? errors.reasonCode
      : undefined;
  const scopeName =
    family?.management_level === "system"
      ? OVERRIDE_SCOPE_LABELS.system
      : OVERRIDE_SCOPE_LABELS.tenant;
  // Whether the rules table column is a matcher or only stored data, decided by
  // the reader the server names rather than by the column's traditional label.
  const evaluatesConditions = profile?.conditions.some((entry) => entry.honoured) ?? true;

  // The tier in these sentences comes from the server, so the reason an
  // operator reads is the same reason the API applied.
  const lockReason = family
    ? tenantTier
      ? canManage
        ? "This family is changed by your provider, not by your organisation. Ask them if it needs new rules."
        : "You can read this family, but your role cannot publish policy changes. Ask your provider if it needs new rules."
      : canManage
        ? callerTier === null
          ? `This family changes at ${MANAGEMENT_LEVEL_LABELS[family.management_level]} level. Your roles do not carry a policy level, so nothing here can be published.`
          : `This family changes at ${MANAGEMENT_LEVEL_LABELS[family.management_level]} level. Your roles reach ${MANAGEMENT_LEVEL_LABELS[callerTier]} level, so publishing is not available here.`
        : "You can read this family, but your role cannot publish policy changes. Ask a system administrator if it needs new rules."
    : "";

  return (
    <div className="policy-detail-page">
      <Link to="/policies" className="policy-detail-back">
        <ArrowLeft size={16} aria-hidden="true" />
        Policies
      </Link>

      <header className="policy-detail-header">
        {detail.isPending ? (
          <p className="policy-detail-hint" role="status">
            Loading policy family…
          </p>
        ) : null}
        {detail.isError ? (
          <>
            <p className="policy-detail-error" role="alert">
              {errorMessage(detail.error)}
            </p>
            <StepUpPrompt error={detail.error} />
          </>
        ) : null}
        {family ? (
          <>
            <div className="policy-detail-heading">
              <h1 className="policy-detail-title">
                {familyDisplayName(family.family_key, family.display_name, tenantTier)}
              </h1>
              <span
                className={`policy-detail-badge policy-detail-level-${family.management_level}`}
              >
                {tenantTier
                  ? TENANT_LEVEL_LABELS[tenantLevelBucket(family.management_level)]
                  : MANAGEMENT_LEVEL_LABELS[family.management_level]}
              </span>
              {family.security_floor ? (
                <Hint label={HINTS.securityFloor}>
                  <span className="policy-detail-badge policy-detail-floor">Security floor</span>
                </Hint>
              ) : null}
            </div>
            <p className="policy-detail-hint">{family.description}</p>
            {tenantTier ? null : (
              <p className="policy-detail-key">
                <Hint label={HINTS.internalIdentifier}>
                  <code>{family.family_key}</code>
                </Hint>
              </p>
            )}
          </>
        ) : null}
      </header>

      {family ? (
        <ControlRail
          title="Revision release state"
          summary="Policy work is always versioned. The active revision and your access level decide what you can do next."
          signals={[
            {
              label: tenantTier ? "Your access" : "Your level",
              value: tenantTier
                ? "Your organisation"
                : callerTier === null
                  ? "None"
                  : MANAGEMENT_LEVEL_LABELS[callerTier],
              detail: tenantTier
                ? "You publish the families marked Yours to change. Your provider publishes the ones marked Needs your provider."
                : callerTier === null
                  ? "Your roles do not include a policy level, so nothing here can be published."
                  : `You can publish families that need the ${MANAGEMENT_LEVEL_LABELS[callerTier]} level or lower.`,
              tone: callerTier === null ? "attention" : "neutral",
            },
            {
              label: "Revisions",
              value: revisions.length,
              detail: "Revisions published for this policy family.",
            },
            {
              label: "In effect",
              value: family.active_revision?.revision_number ?? "none",
              detail: "The revision mail is being filtered with right now.",
              tone: family.active_revision ? "healthy" : "attention",
            },
            {
              label: "Security floor",
              value: family.security_floor ? "enforced" : "none",
              detail: "A published revision in this family cannot switch the floor off.",
              tone: family.security_floor ? "attention" : "neutral",
            },
          ]}
        />
      ) : null}

      {family ? (
        <WorkflowGuide
          title="Change policy through a revision"
          description="Editing the rule table changes a draft only. Nothing reaches live mail until a revision is published, and there is no other way in."
          steps={[
            {
              label: "Review",
              detail: "Check what is in effect now and which level this family needs to change it.",
            },
            {
              label: "Draft",
              detail: "Build the rule set you want below. Edits stay on this page until published.",
            },
            {
              label: "Publish",
              detail:
                "Publish the revision. It takes effect immediately and is recorded against your account.",
            },
          ]}
        />
      ) : null}

      <section className="card policy-detail-panel" aria-labelledby="revisions-heading">
        <h2 id="revisions-heading">Revision history</h2>
        {detail.isSuccess && revisions.length === 0 ? (
          <p className="policy-detail-hint">No revisions have been published for this family.</p>
        ) : null}
        {revisions.length > 0 ? (
          <div className="policy-detail-table-wrap">
            <table className="policy-detail-table">
              <caption className="sr-only">Published revisions for this policy family</caption>
              <thead>
                <tr>
                  <th scope="col">Revision</th>
                  <th scope="col">Applies to</th>
                  <th scope="col">Published by</th>
                  <th scope="col">Published</th>
                  <th scope="col">Status</th>
                  <th scope="col">Rules</th>
                </tr>
              </thead>
              <tbody>
                {revisions.map((revision) => (
                  <tr key={revision.revision_number}>
                    <td>#{revision.revision_number}</td>
                    <td>{OVERRIDE_SCOPE_LABELS[revision.scope_level]}</td>
                    <td>{revision.published_by}</td>
                    <td>{new Date(revision.published_at).toLocaleString()}</td>
                    <td>
                      {revision.revision_number === activeRevisionNumber ? (
                        <span className="policy-detail-status policy-detail-status-active">
                          in effect
                        </span>
                      ) : (
                        <span className="policy-detail-status">replaced</span>
                      )}
                    </td>
                    <td>{revisionRulesLabel(revision)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      <section className="card policy-detail-panel" aria-labelledby="rules-heading">
        <div className="policy-detail-panel-head">
          <h2 id="rules-heading">Rules</h2>
          {mayPublish ? (
            <div className="policy-detail-actions">
              <Button
                type="button"
                variant="primary"
                disabled={rules === null}
                onClick={() => openEditor()}
              >
                Add rule
              </Button>
              <Button
                type="button"
                disabled={rules === null}
                onClick={() => {
                  setPublishNotice(null);
                  publish.reset();
                  setPublishOpen(true);
                }}
              >
                Publish revision
              </Button>
              <Button
                type="button"
                loading={refresh.isPending}
                disabled={refresh.isPending}
                onClick={() => {
                  setRefreshNotice(null);
                  refresh.mutate();
                }}
              >
                Reload delivery servers
              </Button>
            </div>
          ) : null}
        </div>

        {!mayPublish && family ? (
          <p className="policy-detail-lock" role="status">
            {lockReason}
          </p>
        ) : null}

        {profile ? (
          <div className="policy-detail-enforcement">
            <span className={`policy-detail-badge policy-detail-mode-${profile.enforcement.mode}`}>
              {ENFORCEMENT_MODE_LABELS[profile.enforcement.mode]}
            </span>
            <p className="policy-detail-hint">{profile.enforcement.summary}</p>
            {profile.metadata.read ? (
              <p className="policy-detail-hint">{profile.metadata.merge}</p>
            ) : null}
          </div>
        ) : null}

        {publishNotice ? (
          <p className="policy-detail-notice" role="status">
            {publishNotice}
          </p>
        ) : null}
        {refreshNotice ? (
          <p className="policy-detail-notice" role="status">
            {refreshNotice}
          </p>
        ) : null}
        {refresh.isError ? (
          <p className="policy-detail-error" role="alert">
            {publishErrorMessage(refresh.error)}
          </p>
        ) : null}

        {rules === null && detail.isPending ? (
          <p className="policy-detail-hint" role="status">
            Loading rules…
          </p>
        ) : null}
        {rules !== null && rules.length === 0 ? (
          <p className="policy-detail-hint">
            {activeRevisionNumber === null
              ? "Nothing is published for this family yet, so no rule is stopping mail. Add rules to build the first revision."
              : "The revision in effect has no rules, so this family decides nothing right now."}
          </p>
        ) : null}

        {rules !== null && rules.length > 0 ? (
          <div className="policy-detail-table-wrap">
            <table className="policy-detail-table">
              <caption className="sr-only">
                {mayPublish
                  ? "Rules in your current draft, not yet published"
                  : "Rules in the revision currently in effect"}
              </caption>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Order</th>
                  <th scope="col">Status</th>
                  <th scope="col">{evaluatesConditions ? "Matches when" : "Conditions, stored"}</th>
                  <th scope="col">Does</th>
                  <th scope="col">Reason code</th>
                  {mayPublish ? <th scope="col">Actions</th> : null}
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, index) => (
                  <tr key={rule.id}>
                    <td>{rule.name}</td>
                    <td>{rule.priority}</td>
                    <td>{rule.enabled ? "On" : "Off"}</td>
                    <td className="policy-detail-condition">
                      {summarizeRuleCondition(rule.condition)}
                    </td>
                    <td>
                      <span
                        className={`policy-detail-badge policy-detail-disposition-${rule.action.disposition}`}
                      >
                        {POLICY_DISPOSITION_LABELS[rule.action.disposition]}
                      </span>
                    </td>
                    <td className="policy-detail-code">
                      {reasonCodeLabel(rule.action.reason_code)}
                    </td>
                    {mayPublish ? (
                      <td>
                        <div className="policy-detail-row-actions">
                          <Button type="button" size="sm" onClick={() => openEditor(rule)}>
                            Edit
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            variant="danger"
                            onClick={() => removeRule(rule.id)}
                          >
                            Remove
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            aria-label={`Move ${rule.name} earlier`}
                            disabled={index === 0}
                            onClick={() => moveRule(index, -1)}
                          >
                            Up
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            aria-label={`Move ${rule.name} later`}
                            disabled={index === rules.length - 1}
                            onClick={() => moveRule(index, 1)}
                          >
                            Down
                          </Button>
                        </div>
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      <Dialog
        open={editing !== null}
        onClose={closeEditor}
        title={editing && rules?.some((rule) => rule.id === editing.id) ? "Edit rule" : "Add rule"}
      >
        {editing ? (
          <form
            className="policy-detail-form"
            onSubmit={(event) => {
              event.preventDefault();
              saveRule();
            }}
          >
            <fieldset className="policy-detail-fieldset">
              <legend>Basics</legend>
              <Input
                label="Rule name"
                value={editing.name}
                onChange={(event) => setEditing({ ...editing, name: event.target.value })}
                maxLength={128}
                error={nameError}
              />
              <Input
                label="Order"
                type="number"
                min={-1000}
                max={1000}
                value={Number.isFinite(editing.priority) ? editing.priority : ""}
                onChange={(event) =>
                  setEditing({ ...editing, priority: event.target.valueAsNumber })
                }
                error={priorityError}
                hint="Higher order is checked first. The first rule that matches decides what happens."
              />
              <label className="policy-detail-check">
                <input
                  type="checkbox"
                  checked={editing.enabled}
                  onChange={(event) => setEditing({ ...editing, enabled: event.target.checked })}
                />
                Rule is active
              </label>
              <Select
                label="Rule applies to"
                value={editing.scope}
                options={CONDITION_SCOPES.map((value) => ({
                  value,
                  label: CONDITION_SCOPE_LABELS[value],
                }))}
                onChange={(event) =>
                  setEditing({ ...editing, scope: event.target.value as ConditionScope })
                }
              />
            </fieldset>

            {profile ? <ConditionNotice conditions={profile.conditions} /> : null}

            <fieldset className="policy-detail-fieldset">
              <legend>Sender</legend>
              <Input
                label="Sender domains"
                value={editing.senderDomains}
                onChange={(event) => setEditing({ ...editing, senderDomains: event.target.value })}
                placeholder="example.test, partner.test"
                hint="Comma separated; leave empty to leave the sender domain unrestricted."
              />
              <Input
                label="Sender addresses"
                value={editing.senderAddresses}
                onChange={(event) =>
                  setEditing({ ...editing, senderAddresses: event.target.value })
                }
                placeholder="alerts@example.test"
                hint="Comma separated; leave empty to leave the sender address unrestricted."
              />
              <TriSelect
                label="Internal sender"
                value={editing.senderInternal}
                onChange={(value) => setEditing({ ...editing, senderInternal: value })}
              />
              <TriSelect
                label="Authenticated sender"
                value={editing.senderAuthenticated}
                onChange={(value) => setEditing({ ...editing, senderAuthenticated: value })}
              />
            </fieldset>

            <fieldset className="policy-detail-fieldset">
              <legend>Recipient</legend>
              <Input
                label="Recipient domains"
                value={editing.recipientDomains}
                onChange={(event) =>
                  setEditing({ ...editing, recipientDomains: event.target.value })
                }
                placeholder="example.test"
                hint="Comma separated; leave empty to leave the recipient domain unrestricted."
              />
              <Input
                label="Recipient addresses"
                value={editing.recipientAddresses}
                onChange={(event) =>
                  setEditing({ ...editing, recipientAddresses: event.target.value })
                }
                placeholder="ceo@example.test"
                hint="Comma separated; leave empty to leave the recipient address unrestricted."
              />
              <TriSelect
                label="Internal recipient"
                value={editing.recipientInternal}
                onChange={(value) => setEditing({ ...editing, recipientInternal: value })}
              />
            </fieldset>

            <fieldset className="policy-detail-fieldset">
              <legend>Authentication</legend>
              <CheckGroup<AuthResult>
                legend="SPF result is"
                values={editing.authSpf}
                options={AUTH_RESULTS}
                labels={AUTH_RESULT_LABELS}
                onToggle={(value) =>
                  setEditing({ ...editing, authSpf: toggleInList(editing.authSpf, value) })
                }
              />
              <CheckGroup<AuthResult>
                legend="DKIM result is"
                values={editing.authDkim}
                options={AUTH_RESULTS}
                labels={AUTH_RESULT_LABELS}
                onToggle={(value) =>
                  setEditing({ ...editing, authDkim: toggleInList(editing.authDkim, value) })
                }
              />
              <CheckGroup<AuthResult>
                legend="DMARC result is"
                values={editing.authDmarc}
                options={AUTH_RESULTS}
                labels={AUTH_RESULT_LABELS}
                onToggle={(value) =>
                  setEditing({ ...editing, authDmarc: toggleInList(editing.authDmarc, value) })
                }
              />
            </fieldset>

            <fieldset className="policy-detail-fieldset">
              <legend>Content</legend>
              <TriSelect
                label="Has attachment"
                value={editing.hasAttachment}
                onChange={(value) => setEditing({ ...editing, hasAttachment: value })}
              />
              <Input
                label="Attachment types"
                value={editing.attachmentTypes}
                onChange={(event) =>
                  setEditing({ ...editing, attachmentTypes: event.target.value })
                }
                placeholder="pdf, exe"
                hint="Comma separated file extensions; leave empty to leave attachment types unrestricted."
              />
              <Input
                label="Size greater than (bytes)"
                type="number"
                min={0}
                value={editing.sizeGt}
                onChange={(event) => setEditing({ ...editing, sizeGt: event.target.value })}
                hint="Leave empty to leave message size unrestricted."
              />
              <TriSelect
                label="Contains a link"
                value={editing.hasUrl}
                onChange={(value) => setEditing({ ...editing, hasUrl: value })}
              />
            </fieldset>

            <fieldset className="policy-detail-fieldset">
              <legend>Scanner findings</legend>
              <CheckGroup<ScannerType>
                legend="From scanner"
                values={editing.scanners}
                options={SCANNER_TYPES}
                labels={SCANNER_LABELS}
                onToggle={(value) =>
                  setEditing({ ...editing, scanners: toggleInList(editing.scanners, value) })
                }
              />
              <CheckGroup<FindingSeverity>
                legend="At severity"
                values={editing.severities}
                options={FINDING_SEVERITIES}
                labels={FINDING_SEVERITY_LABELS}
                onToggle={(value) =>
                  setEditing({ ...editing, severities: toggleInList(editing.severities, value) })
                }
              />
              <CheckGroup<FindingCategory>
                legend="Of category"
                values={editing.categories}
                options={FINDING_CATEGORIES}
                labels={FINDING_CATEGORY_LABELS}
                onToggle={(value) =>
                  setEditing({ ...editing, categories: toggleInList(editing.categories, value) })
                }
              />
              <TriSelect
                label="Already marked a false positive"
                value={editing.falsePositive}
                onChange={(value) => setEditing({ ...editing, falsePositive: value })}
              />
            </fieldset>

            <fieldset className="policy-detail-fieldset">
              <legend>Action</legend>
              <Select
                label="Then the message is"
                value={editing.disposition}
                options={DISPOSITIONS.map((value) => ({
                  value,
                  label: POLICY_DISPOSITION_LABELS[value],
                }))}
                onChange={(event) =>
                  setEditing({ ...editing, disposition: event.target.value as Disposition })
                }
              />
              <Input
                label="Reason code"
                value={editing.reasonCode}
                onChange={(event) => setEditing({ ...editing, reasonCode: event.target.value })}
                placeholder="QUARANTINE_PHISHING"
                maxLength={64}
                error={reasonCodeError}
                hint="Appears in the mail log and the hold reason an admin sees. Uppercase letters, digits and underscores, up to 64 characters."
              />
              <CheckGroup<NotifyTarget>
                legend="Notify"
                values={editing.notify}
                options={NOTIFY_TARGETS}
                labels={NOTIFY_TARGET_LABELS}
                onToggle={(value) =>
                  setEditing({ ...editing, notify: toggleInList(editing.notify, value) })
                }
              />
            </fieldset>

            {profile ? (
              <MetadataFields
                profile={profile}
                draft={editing}
                errors={errors}
                showErrors={showErrors}
                onDraftChange={setEditing}
              />
            ) : null}

            {!profile?.metadata.read && storedMetadataKeys(editing.actionMetadata).length > 0 ? (
              <p className="policy-detail-hint">
                This rule already carries{" "}
                <code>{storedMetadataKeys(editing.actionMetadata).join(", ")}</code> in its action
                data. Nothing in this family reads it, and saving keeps it unchanged.
              </p>
            ) : null}

            <div className="policy-detail-form-actions">
              <Button type="button" variant="ghost" onClick={closeEditor}>
                Cancel
              </Button>
              <Button type="submit" variant="primary">
                Save rule
              </Button>
            </div>
          </form>
        ) : null}
      </Dialog>

      <Dialog open={publishOpen} onClose={() => setPublishOpen(false)} title="Publish revision">
        <div className="policy-detail-form">
          <p>
            Publish <strong>{rules?.length ?? 0}</strong> rules for{" "}
            <strong>{family?.display_name}</strong> at <strong>{scopeName}</strong> level?
          </p>
          <p className="policy-detail-hint">
            This becomes the live rule set as soon as you confirm, replacing the revision in effect.
            The publish is recorded with your account and the revision number, so it can be reviewed
            and rolled back by publishing an earlier rule set again.
          </p>
          {thresholdClearWarning ? (
            <p className="policy-detail-warning" role="alert">
              No rule in this draft carries machine-learning score thresholds. Publishing clears the
              thresholds now in force, so the inline analysis stage will report evidence without
              scoring messages until you publish a rule set that includes them.
            </p>
          ) : null}
          {publish.isError ? (
            <>
              <p className="policy-detail-error" role="alert">
                {publishErrorMessage(publish.error)}
              </p>
              <StepUpPrompt error={publish.error} />
            </>
          ) : null}
          <div className="policy-detail-form-actions">
            <Button
              type="button"
              variant="ghost"
              disabled={publish.isPending}
              onClick={() => {
                setPublishOpen(false);
                publish.reset();
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="primary"
              loading={publish.isPending}
              onClick={confirmPublish}
            >
              Confirm publish
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}

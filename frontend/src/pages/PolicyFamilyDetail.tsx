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
  managementTierAllows,
  newRuleDraft,
  resequenceRules,
  ruleFromDraft,
  sortByEvaluationOrder,
  summarizeCondition,
  type AuthResult,
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
  type ScannerType,
  type TriState,
} from "../api/policies";
import { hasPermission, loadSession } from "../auth/session";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
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
  onToggle: (value: T) => void;
}

function CheckGroup<T extends string>({ legend, values, options, onToggle }: CheckGroupProps<T>) {
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
            {option}
          </label>
        ))}
      </div>
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
  const roles = current?.roles ?? [];
  const canManage = hasPermission(current, "policies:manage");
  const family = detail.data?.family ?? null;
  const mayPublish =
    canManage && family !== null && managementTierAllows(family.management_level, roles);

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
        `Published revision #${created.revision_number} with ${created.rules_count} rules.`,
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
        `Policy refresh requested at ${new Date(result.refresh_requested_at).toLocaleString()}.`,
      ),
  });

  function openEditor(rule?: Rule) {
    setEditing(rule ? draftFromRule(rule) : newRuleDraft());
    setShowErrors(false);
  }

  function closeEditor() {
    setEditing(null);
    setShowErrors(false);
  }

  function saveRule() {
    if (!editing) return;
    if (!isDraftValid(editing)) {
      setShowErrors(true);
      return;
    }
    const rule = ruleFromDraft(editing);
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

  const errors = editing ? draftErrors(editing) : {};
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
  const scopeLevel = family?.management_level === "system" ? "system" : "tenant";

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
              <h1 className="policy-detail-title">{family.family_key}</h1>
              <span
                className={`policy-detail-badge policy-detail-level-${family.management_level}`}
              >
                {family.management_level}
              </span>
              {family.security_floor ? (
                <span className="policy-detail-badge policy-detail-floor">security floor</span>
              ) : null}
            </div>
            <p className="policy-detail-hint">{family.description}</p>
          </>
        ) : null}
      </header>

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
                  <th scope="col">Scope</th>
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
                    <td>{revision.scope_level}</td>
                    <td>{revision.published_by}</td>
                    <td>{new Date(revision.published_at).toLocaleString()}</td>
                    <td>
                      {revision.revision_number === activeRevisionNumber ? (
                        <span className="policy-detail-status policy-detail-status-active">
                          active
                        </span>
                      ) : (
                        <span className="policy-detail-status">superseded</span>
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
          <div className="policy-detail-actions">
            <Button
              type="button"
              variant="primary"
              disabled={rules === null}
              onClick={() => openEditor()}
            >
              Add rule
            </Button>
            {mayPublish ? (
              <>
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
                  Request refresh
                </Button>
              </>
            ) : null}
          </div>
        </div>

        {!mayPublish && family ? (
          <p className="policy-detail-hint">
            Publishing needs the policies:manage permission and the {family.management_level}{" "}
            management tier.
          </p>
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
              ? "This family has no published revision yet. Add rules to build the first revision; publishing is audited and versioned, and the server enforces the management tier for this family."
              : "The active revision contains no rules."}
          </p>
        ) : null}

        {rules !== null && rules.length > 0 ? (
          <div className="policy-detail-table-wrap">
            <table className="policy-detail-table">
              <caption className="sr-only">Rules in the current draft</caption>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Priority</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">Condition</th>
                  <th scope="col">Disposition</th>
                  <th scope="col">Reason code</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, index) => (
                  <tr key={rule.id}>
                    <td>{rule.name}</td>
                    <td>{rule.priority}</td>
                    <td>{rule.enabled ? "enabled" : "disabled"}</td>
                    <td className="policy-detail-condition">
                      {summarizeCondition(rule.condition)}
                    </td>
                    <td>
                      <span
                        className={`policy-detail-badge policy-detail-disposition-${rule.action.disposition}`}
                      >
                        {rule.action.disposition}
                      </span>
                    </td>
                    <td className="policy-detail-code">{rule.action.reason_code}</td>
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
                          aria-label={`Move ${rule.name} up`}
                          disabled={index === 0}
                          onClick={() => moveRule(index, -1)}
                        >
                          Up
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          aria-label={`Move ${rule.name} down`}
                          disabled={index === rules.length - 1}
                          onClick={() => moveRule(index, 1)}
                        >
                          Down
                        </Button>
                      </div>
                    </td>
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
                label="Priority"
                type="number"
                min={-1000}
                max={1000}
                value={Number.isFinite(editing.priority) ? editing.priority : ""}
                onChange={(event) =>
                  setEditing({ ...editing, priority: event.target.valueAsNumber })
                }
                error={priorityError}
                hint="Higher priorities are evaluated first."
              />
              <label className="policy-detail-check">
                <input
                  type="checkbox"
                  checked={editing.enabled}
                  onChange={(event) => setEditing({ ...editing, enabled: event.target.checked })}
                />
                Enabled
              </label>
              <Select
                label="Condition scope"
                value={editing.scope}
                options={CONDITION_SCOPES.map((value) => ({ value, label: value }))}
                onChange={(event) =>
                  setEditing({ ...editing, scope: event.target.value as ConditionScope })
                }
              />
            </fieldset>

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
                legend="SPF"
                values={editing.authSpf}
                options={AUTH_RESULTS}
                onToggle={(value) =>
                  setEditing({ ...editing, authSpf: toggleInList(editing.authSpf, value) })
                }
              />
              <CheckGroup<AuthResult>
                legend="DKIM"
                values={editing.authDkim}
                options={AUTH_RESULTS}
                onToggle={(value) =>
                  setEditing({ ...editing, authDkim: toggleInList(editing.authDkim, value) })
                }
              />
              <CheckGroup<AuthResult>
                legend="DMARC"
                values={editing.authDmarc}
                options={AUTH_RESULTS}
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
                label="Has URL"
                value={editing.hasUrl}
                onChange={(value) => setEditing({ ...editing, hasUrl: value })}
              />
            </fieldset>

            <fieldset className="policy-detail-fieldset">
              <legend>Finding</legend>
              <CheckGroup<ScannerType>
                legend="Scanner"
                values={editing.scanners}
                options={SCANNER_TYPES}
                onToggle={(value) =>
                  setEditing({ ...editing, scanners: toggleInList(editing.scanners, value) })
                }
              />
              <CheckGroup<FindingSeverity>
                legend="Severity"
                values={editing.severities}
                options={FINDING_SEVERITIES}
                onToggle={(value) =>
                  setEditing({ ...editing, severities: toggleInList(editing.severities, value) })
                }
              />
              <CheckGroup<FindingCategory>
                legend="Category"
                values={editing.categories}
                options={FINDING_CATEGORIES}
                onToggle={(value) =>
                  setEditing({ ...editing, categories: toggleInList(editing.categories, value) })
                }
              />
              <TriSelect
                label="False positive"
                value={editing.falsePositive}
                onChange={(value) => setEditing({ ...editing, falsePositive: value })}
              />
            </fieldset>

            <fieldset className="policy-detail-fieldset">
              <legend>Action</legend>
              <Select
                label="Disposition"
                value={editing.disposition}
                options={DISPOSITIONS.map((value) => ({ value, label: value }))}
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
                hint="Uppercase letters, digits and underscores, up to 64 characters."
              />
              <CheckGroup<NotifyTarget>
                legend="Notify"
                values={editing.notify}
                options={NOTIFY_TARGETS}
                onToggle={(value) =>
                  setEditing({ ...editing, notify: toggleInList(editing.notify, value) })
                }
              />
            </fieldset>

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
            <strong>{family?.family_key}</strong> at <strong>{scopeLevel}</strong> scope?
          </p>
          <p className="policy-detail-hint">
            Publishing is audited and versioned. The new revision becomes active immediately and
            supersedes the previous revision for this family.
          </p>
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

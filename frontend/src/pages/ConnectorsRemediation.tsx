import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cable, CheckCircle2, Pencil, Search, ShieldCheck, TriangleAlert } from "lucide-react";
import { useRef, useState } from "react";

import { api, type ApiError } from "../api/client";
import { hasPermission, loadSession } from "../auth/session";
import { Button } from "../components/primitives/Button";
import { Hint } from "../components/primitives/Hint";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { ControlRail } from "../components/ControlRail";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { randomUuid } from "../lib/ids";
import {
  authStateLabel,
  connectorCapabilityLabel,
  connectorStatusLabel,
  executionStateLabel,
  HINTS,
  remediationActionLabel,
  searchPurposeLabel,
} from "../lib/labels";
import "./ConnectorsRemediation.css";

type Provider = "microsoft_365" | "google_workspace" | "imap_pop";
type Capability = "directory_sync" | "mailbox_search" | "retro_remediation";
type ConnectorStatus = "setup_required" | "active" | "degraded" | "disabled" | "revoked";
type AuthState =
  "not_configured" | "healthy" | "expiring" | "expired" | "revoked" | "provider_error";
type RemediationAction = "move_to_quarantine" | "move_to_junk" | "delete" | "manual_review";
type SearchPurpose =
  | "post_delivery_threat"
  | "customer_reported_phishing"
  | "false_negative_review"
  | "manual_security_case";

interface ConnectorsSummary {
  active_connectors: number;
  degraded_connectors: number;
  directory_sync_enabled: number;
  mailbox_search_enabled: number;
  retro_remediation_enabled: number;
  pending_remediations: number;
  manual_action_required: number;
  failed_operations: number;
}

interface CapabilityView {
  capability: Capability;
  enabled: boolean;
  granted_scopes: string[];
  reason: string;
  updated_at: string;
}

interface ConnectorView {
  id: string;
  provider: Provider;
  display_name: string;
  external_tenant_id_hash: string;
  status: ConnectorStatus;
  auth_state: AuthState;
  token_expires_at: string | null;
  last_directory_sync_at: string | null;
  last_directory_sync_status: string | null;
  last_mailbox_search_at: string | null;
  last_remediation_at: string | null;
  updated_at: string;
  capabilities: CapabilityView[];
}

interface DirectorySyncRun {
  id: string;
  connector_id: string;
  provider: Provider;
  display_name: string;
  state: string;
  started_at: string;
  completed_at: string | null;
  users_seen: number;
  groups_seen: number;
  aliases_seen: number;
  vip_candidates: number;
  error_code: string | null;
  error_summary: string | null;
}

interface MailboxSearchView {
  id: string;
  connector_id: string;
  provider: Provider;
  purpose: SearchPurpose;
  state: string;
  match_confirmation: string;
  mailbox_address_hash: string;
  provider_message_id_hash: string | null;
  created_at: string;
  error_code: string | null;
  error_summary: string | null;
}

interface RemediationActionView {
  id: string;
  connector_id: string;
  provider: Provider;
  action_type: RemediationAction;
  state: string;
  provider_outcome_code: string | null;
  error_summary: string | null;
  reason: string;
  created_at: string;
  updated_at: string;
}

interface ConnectorsResponse {
  deployment_id: string;
  generated_at: string;
  summary: ConnectorsSummary;
  connectors: ConnectorView[];
  directory_sync_runs: DirectorySyncRun[];
  mailbox_searches: MailboxSearchView[];
  remediation_actions: RemediationActionView[];
  audit_history: Array<{
    id: string;
    action: string;
    actor_login: string;
    resource_id: string | null;
    result: string;
    created_at: string;
  }>;
}

interface ConnectorDraft {
  provider: Provider;
  display_name: string;
  external_tenant_id_hash: string;
  credential_reference_hash: string;
  status: ConnectorStatus;
  auth_state: AuthState;
  directory_scope: string;
  mailbox_scope: string;
  remediation_scope: string;
  reason: string;
}

interface RemediationDraft {
  connector_id: string;
  tenant_message_id: string;
  mailbox_address_hash: string;
  provider_message_id_hash: string;
  purpose: SearchPurpose;
  action_type: RemediationAction;
  reason: string;
}

const defaultConnectorDraft: ConnectorDraft = {
  provider: "microsoft_365",
  display_name: "",
  external_tenant_id_hash: "",
  credential_reference_hash: "",
  status: "active",
  auth_state: "healthy",
  directory_scope: "User.Read.All",
  mailbox_scope: "",
  remediation_scope: "",
  reason: "",
};

const defaultRemediationDraft: RemediationDraft = {
  connector_id: "",
  tenant_message_id: "",
  mailbox_address_hash: "",
  provider_message_id_hash: "",
  purpose: "post_delivery_threat",
  action_type: "move_to_quarantine",
  reason: "",
};

const providerLabel: Record<Provider, string> = {
  microsoft_365: "Microsoft 365",
  google_workspace: "Google Workspace",
  imap_pop: "IMAP/POP",
};

/**
 * The two unions a remediation request is built from. The <option> value stays
 * the wire token the API expects; the words come from the shared catalog so the
 * form and the history list never describe the same action differently.
 */
const SEARCH_PURPOSES: SearchPurpose[] = [
  "post_delivery_threat",
  "customer_reported_phishing",
  "false_negative_review",
  "manual_security_case",
];

const REMEDIATION_ACTIONS: RemediationAction[] = [
  "move_to_quarantine",
  "move_to_junk",
  "delete",
  "manual_review",
];

function errorMessage(error: unknown): string {
  const apiError = error as Partial<ApiError>;
  return apiError.message ?? "Request failed";
}

function splitScopes(value: string): string[] {
  return value
    .split(",")
    .map((scope) => scope.trim())
    .filter(Boolean);
}

function capabilityTone(capability: CapabilityView): string {
  return capability.enabled ? "enabled" : "disabled";
}

export function ConnectorsRemediation() {
  const queryClient = useQueryClient();
  const [connectorDraft, setConnectorDraft] = useState<ConnectorDraft>(defaultConnectorDraft);
  const [remediationDraft, setRemediationDraft] =
    useState<RemediationDraft>(defaultRemediationDraft);
  const [connectorFormError, setConnectorFormError] = useState<string | null>(null);
  const [remediationFormError, setRemediationFormError] = useState<string | null>(null);
  const [editingConnectorId, setEditingConnectorId] = useState<string | null>(null);
  const connectorFormRef = useRef<HTMLFormElement>(null);

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const connectors = useQuery({
    queryKey: ["connectors-remediation"],
    queryFn: ({ signal }) => api.get<ConnectorsResponse>("/connectors-remediation", signal),
  });
  const canManage = hasPermission(session.data ?? null, "connectors:manage");

  const upsertConnector = useMutation({
    mutationFn: (draft: ConnectorDraft) =>
      api.post(
        "/connectors-remediation/connectors",
        {
          provider: draft.provider,
          display_name: draft.display_name.trim(),
          external_tenant_id_hash: draft.external_tenant_id_hash.trim(),
          credential_reference_hash: draft.credential_reference_hash.trim(),
          status: draft.status,
          auth_state: draft.auth_state,
          capabilities: [
            {
              capability: "directory_sync",
              enabled: splitScopes(draft.directory_scope).length > 0,
              granted_scopes: splitScopes(draft.directory_scope),
              reason: draft.reason.trim(),
            },
            {
              capability: "mailbox_search",
              enabled: splitScopes(draft.mailbox_scope).length > 0,
              granted_scopes: splitScopes(draft.mailbox_scope),
              reason: draft.mailbox_scope.trim()
                ? draft.reason.trim()
                : "Mailbox search is not granted for this connector.",
            },
            {
              capability: "retro_remediation",
              enabled: splitScopes(draft.remediation_scope).length > 0,
              granted_scopes: splitScopes(draft.remediation_scope),
              reason: draft.remediation_scope.trim()
                ? draft.reason.trim()
                : "Retro remediation is not granted for this connector.",
            },
          ],
        },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async () => {
      setConnectorFormError(null);
      setConnectorDraft(defaultConnectorDraft);
      await queryClient.invalidateQueries({ queryKey: ["connectors-remediation"] });
    },
  });

  const requestRemediation = useMutation({
    mutationFn: (draft: RemediationDraft) =>
      api.post(
        "/connectors-remediation/remediations",
        {
          connector_id: draft.connector_id,
          tenant_message_id: draft.tenant_message_id.trim(),
          mailbox_address_hash: draft.mailbox_address_hash.trim(),
          provider_message_id_hash: draft.provider_message_id_hash.trim() || undefined,
          purpose: draft.purpose,
          action_type: draft.action_type,
          reason: draft.reason.trim(),
        },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: async () => {
      setRemediationFormError(null);
      setRemediationDraft(defaultRemediationDraft);
      await queryClient.invalidateQueries({ queryKey: ["connectors-remediation"] });
    },
  });

  function beginEditConnector(connector: ConnectorView) {
    const capabilityScopes = (capability: Capability) =>
      connector.capabilities.find((entry) => entry.capability === capability)?.granted_scopes ?? [];
    setConnectorDraft({
      provider: connector.provider,
      display_name: connector.display_name,
      external_tenant_id_hash: connector.external_tenant_id_hash,
      // The stored credential reference is never rendered back; saving an edit
      // requires re-entering it to confirm the rotation.
      credential_reference_hash: "",
      status: connector.status,
      auth_state: connector.auth_state,
      directory_scope: capabilityScopes("directory_sync").join(", "),
      mailbox_scope: capabilityScopes("mailbox_search").join(", "),
      remediation_scope: capabilityScopes("retro_remediation").join(", "),
      reason: "",
    });
    setEditingConnectorId(connector.id);
    setConnectorFormError(null);
    upsertConnector.reset();
    connectorFormRef.current?.scrollIntoView?.({ block: "start" });
  }

  function cancelEditConnector() {
    setConnectorDraft(defaultConnectorDraft);
    setEditingConnectorId(null);
    setConnectorFormError(null);
    upsertConnector.reset();
  }

  if (connectors.isLoading) {
    return (
      <div className="connectors-state" role="status">
        Loading connector controls…
      </div>
    );
  }
  if (connectors.isError || !connectors.data) {
    return (
      <div className="connectors-state error" role="alert">
        {errorMessage(connectors.error)}
      </div>
    );
  }

  const data = connectors.data;
  const upsertError = upsertConnector.isError ? errorMessage(upsertConnector.error) : null;
  const remediationError = requestRemediation.isError
    ? errorMessage(requestRemediation.error)
    : null;
  const editingConnector = editingConnectorId
    ? (data.connectors.find((connector) => connector.id === editingConnectorId) ?? null)
    : null;

  return (
    <div className="connectors-page">
      <WorkspaceHeader
        eyebrow="Provider controls"
        title="Connectors & remediation"
        description="Set up the Microsoft 365 and Google Workspace connections for a customer: directory status, mailbox search and the remediation actions you record here. Provider sign-in secrets are never shown on this page."
        scope="Customer connector controls"
      />

      <ControlRail
        title="Connector action queue"
        summary="Start with connector availability, then use only the capabilities that are enabled for the selected customer."
        signals={[
          {
            label: "Active",
            value: data.summary.active_connectors,
            detail: "Connected integrations available right now.",
            tone: data.summary.active_connectors > 0 ? "healthy" : "attention",
          },
          {
            label: "Directory sync",
            value: data.summary.directory_sync_enabled,
            detail: "Connectors that sync directories right now.",
          },
          {
            label: "Pending remediation",
            value: data.summary.pending_remediations,
            detail: "Remediation actions waiting for a result.",
            tone: data.summary.pending_remediations > 0 ? "attention" : "healthy",
          },
        ]}
      />

      <WorkflowGuide
        title="Remediate through the connected provider"
        description="Capabilities and mailbox actions apply to one customer. This page records the result but never shows provider sign-in secrets."
        steps={[
          {
            label: "Validate",
            detail: "Confirm the connection and directory state for the selected customer.",
          },
          {
            label: "Locate",
            detail:
              "Find the delivered message and mailbox for this case. Searches are logged with their result.",
          },
          {
            label: "Remediate",
            detail: "Run the action your role allows and note the result it returns.",
          },
        ]}
      />

      <section className="connectors-summary" aria-label="Connector summary">
        <div>
          <Cable aria-hidden="true" />
          <span>Active</span>
          <strong>{data.summary.active_connectors}</strong>
        </div>
        <div>
          <ShieldCheck aria-hidden="true" />
          <span>Directory</span>
          <strong>{data.summary.directory_sync_enabled}</strong>
        </div>
        <div>
          <Search aria-hidden="true" />
          <span>Mailbox search</span>
          <strong>{data.summary.mailbox_search_enabled}</strong>
        </div>
        <div>
          <CheckCircle2 aria-hidden="true" />
          <span>Remediation</span>
          <strong>{data.summary.retro_remediation_enabled}</strong>
        </div>
        <div>
          <TriangleAlert aria-hidden="true" />
          <span>Needs action</span>
          <strong>{data.summary.manual_action_required + data.summary.failed_operations}</strong>
        </div>
      </section>

      <section className="connectors-grid">
        <article className="connectors-panel">
          <h2>Connector capabilities</h2>
          <div className="connectors-list">
            {data.connectors.length === 0 ? (
              <p className="connectors-muted">No connector records yet.</p>
            ) : (
              data.connectors.map((connector) => (
                <div className="connector-card" key={connector.id}>
                  <div>
                    <strong>{connector.display_name}</strong>
                    <span>
                      {providerLabel[connector.provider]} · {connectorStatusLabel(connector.status)}{" "}
                      · credentials: {authStateLabel(connector.auth_state)}
                    </span>
                  </div>
                  <div className="capability-list">
                    {connector.capabilities.map((capability) => (
                      <span
                        className={capabilityTone(capability)}
                        key={capability.capability}
                        title={`${capability.reason} · scopes: ${
                          capability.granted_scopes.join(", ") || "none"
                        }`}
                      >
                        {connectorCapabilityLabel(capability.capability)}
                      </span>
                    ))}
                  </div>
                  <small>
                    External account ID {connector.external_tenant_id_hash} · updated{" "}
                    {new Date(connector.updated_at).toLocaleString()}
                  </small>
                  {canManage ? (
                    <button
                      type="button"
                      className="btn btn-ghost connector-edit"
                      onClick={() => beginEditConnector(connector)}
                    >
                      <Pencil size={13} aria-hidden="true" />
                      Edit capability
                    </button>
                  ) : null}
                </div>
              ))
            )}
          </div>
        </article>

        <article className="connectors-panel">
          <h2>Directory sync status</h2>
          <div className="connectors-list">
            {data.directory_sync_runs.length === 0 ? (
              <p className="connectors-muted">No directory sync run recorded.</p>
            ) : (
              data.directory_sync_runs.map((run) => (
                <div className="connector-card" key={run.id}>
                  <strong>{run.display_name}</strong>
                  <span>
                    {executionStateLabel(run.state)} · users {run.users_seen} · groups{" "}
                    {run.groups_seen} · aliases {run.aliases_seen}
                  </span>
                  {run.error_summary ? <small>{run.error_summary}</small> : null}
                </div>
              ))
            )}
          </div>
        </article>
      </section>

      {canManage ? (
        <section className="connectors-grid">
          <form
            className="connectors-panel connectors-form"
            ref={connectorFormRef}
            onSubmit={(event) => {
              event.preventDefault();
              if (
                connectorDraft.display_name.trim().length < 3 ||
                connectorDraft.external_tenant_id_hash.trim().length < 16 ||
                connectorDraft.credential_reference_hash.trim().length < 16 ||
                connectorDraft.reason.trim().length < 12
              ) {
                setConnectorFormError(
                  "Add a connector name, the account and credential references, and a reason in a full sentence.",
                );
                return;
              }
              upsertConnector.mutate(connectorDraft);
            }}
          >
            <h2>
              {editingConnector ? "Update connector capability" : "Register connector capability"}
            </h2>
            {editingConnector ? (
              <p className="connectors-editing-note">
                Editing {editingConnector.display_name}. Saving updates this connector; re-enter the
                credential reference to confirm it.
                <button type="button" className="btn btn-ghost" onClick={cancelEditConnector}>
                  Cancel edit
                </button>
              </p>
            ) : null}
            <label>
              Provider
              <select
                value={connectorDraft.provider}
                onChange={(event) =>
                  setConnectorDraft({ ...connectorDraft, provider: event.target.value as Provider })
                }
              >
                <option value="microsoft_365">Microsoft 365</option>
                <option value="google_workspace">Google Workspace</option>
                <option value="imap_pop">IMAP/POP disabled</option>
              </select>
            </label>
            <label>
              Display name
              <input
                value={connectorDraft.display_name}
                onChange={(event) =>
                  setConnectorDraft({ ...connectorDraft, display_name: event.target.value })
                }
              />
            </label>
            <label>
              External account ID
              <input
                value={connectorDraft.external_tenant_id_hash}
                onChange={(event) =>
                  setConnectorDraft({
                    ...connectorDraft,
                    external_tenant_id_hash: event.target.value,
                  })
                }
              />
            </label>
            <label>
              Credential reference hash
              <input
                value={connectorDraft.credential_reference_hash}
                onChange={(event) =>
                  setConnectorDraft({
                    ...connectorDraft,
                    credential_reference_hash: event.target.value,
                  })
                }
              />
            </label>
            <label>
              Directory scopes
              <input
                value={connectorDraft.directory_scope}
                onChange={(event) =>
                  setConnectorDraft({ ...connectorDraft, directory_scope: event.target.value })
                }
              />
            </label>
            <label>
              Mailbox search scopes
              <input
                value={connectorDraft.mailbox_scope}
                onChange={(event) =>
                  setConnectorDraft({ ...connectorDraft, mailbox_scope: event.target.value })
                }
              />
            </label>
            <label>
              Remediation scopes
              <input
                value={connectorDraft.remediation_scope}
                onChange={(event) =>
                  setConnectorDraft({ ...connectorDraft, remediation_scope: event.target.value })
                }
              />
            </label>
            <label>
              Reason
              <textarea
                value={connectorDraft.reason}
                onChange={(event) =>
                  setConnectorDraft({ ...connectorDraft, reason: event.target.value })
                }
              />
            </label>
            {connectorFormError || upsertError ? (
              <p className="connectors-error">{connectorFormError ?? upsertError}</p>
            ) : null}
            <StepUpPrompt error={upsertConnector.error} />
            <Button type="submit" variant="primary" loading={upsertConnector.isPending}>
              {editingConnector ? "Update connector" : "Save connector"}
            </Button>
          </form>

          <form
            className="connectors-panel connectors-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (
                !remediationDraft.connector_id ||
                remediationDraft.tenant_message_id.trim().length < 16 ||
                remediationDraft.mailbox_address_hash.trim().length < 16 ||
                remediationDraft.reason.trim().length < 12
              ) {
                setRemediationFormError(
                  "Choose a connector, then enter the message ID, mailbox reference and a reason in a full sentence.",
                );
                return;
              }
              requestRemediation.mutate(remediationDraft);
            }}
          >
            <h2>Request post-delivery remediation</h2>
            <label>
              Connector
              <select
                value={remediationDraft.connector_id}
                onChange={(event) =>
                  setRemediationDraft({ ...remediationDraft, connector_id: event.target.value })
                }
              >
                <option value="">Select connector</option>
                {data.connectors.map((connector) => (
                  <option value={connector.id} key={connector.id}>
                    {connector.display_name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Message ID
              <input
                value={remediationDraft.tenant_message_id}
                onChange={(event) =>
                  setRemediationDraft({
                    ...remediationDraft,
                    tenant_message_id: event.target.value,
                  })
                }
              />
            </label>
            <label>
              Mailbox address hash
              <input
                value={remediationDraft.mailbox_address_hash}
                onChange={(event) =>
                  setRemediationDraft({
                    ...remediationDraft,
                    mailbox_address_hash: event.target.value,
                  })
                }
              />
            </label>
            <label>
              Provider message hash
              <input
                value={remediationDraft.provider_message_id_hash}
                onChange={(event) =>
                  setRemediationDraft({
                    ...remediationDraft,
                    provider_message_id_hash: event.target.value,
                  })
                }
              />
            </label>
            <label>
              Purpose
              <select
                value={remediationDraft.purpose}
                onChange={(event) =>
                  setRemediationDraft({
                    ...remediationDraft,
                    purpose: event.target.value as SearchPurpose,
                  })
                }
              >
                {SEARCH_PURPOSES.map((purpose) => (
                  <option value={purpose} key={purpose}>
                    {searchPurposeLabel(purpose)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Action on the message
              <select
                value={remediationDraft.action_type}
                onChange={(event) =>
                  setRemediationDraft({
                    ...remediationDraft,
                    action_type: event.target.value as RemediationAction,
                  })
                }
              >
                {REMEDIATION_ACTIONS.map((action) => (
                  <option value={action} key={action}>
                    {remediationActionLabel(action)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Reason
              <textarea
                value={remediationDraft.reason}
                onChange={(event) =>
                  setRemediationDraft({ ...remediationDraft, reason: event.target.value })
                }
              />
            </label>
            {remediationFormError || remediationError ? (
              <p className="connectors-error">{remediationFormError ?? remediationError}</p>
            ) : null}
            <StepUpPrompt error={requestRemediation.error} />
            <Hint label="This acts on the customer's mailbox through the provider. Delete and move actions can remove mail the customer still needs.">
              <Button type="submit" variant="danger" loading={requestRemediation.isPending}>
                Record remediation intent
              </Button>
            </Hint>
          </form>
        </section>
      ) : null}

      <section className="connectors-grid">
        <article className="connectors-panel">
          <h2>Mailbox searches</h2>
          <div className="connectors-list">
            {data.mailbox_searches.length === 0 ? (
              <p className="connectors-muted">No mailbox searches recorded.</p>
            ) : (
              data.mailbox_searches.map((searchItem) => (
                <div className="connector-card" key={searchItem.id}>
                  <strong>{searchPurposeLabel(searchItem.purpose)}</strong>
                  <Hint label={HINTS.providerState}>
                    <span>
                      {executionStateLabel(searchItem.state)} · match check:{" "}
                      {executionStateLabel(searchItem.match_confirmation)}
                    </span>
                  </Hint>
                  <small>Mailbox {searchItem.mailbox_address_hash}</small>
                </div>
              ))
            )}
          </div>
        </article>
        <article className="connectors-panel">
          <h2>Remediation history</h2>
          <div className="connectors-list">
            {data.remediation_actions.length === 0 ? (
              <p className="connectors-muted">No remediation action recorded.</p>
            ) : (
              data.remediation_actions.map((action) => (
                <div className="connector-card" key={action.id}>
                  <strong>{remediationActionLabel(action.action_type)}</strong>
                  <Hint label={HINTS.providerState}>
                    <span>{executionStateLabel(action.state)}</span>
                  </Hint>
                  {action.provider_outcome_code ? (
                    <small>Provider outcome: {action.provider_outcome_code}</small>
                  ) : null}
                  {action.error_summary ? (
                    <small className="connectors-error">{action.error_summary}</small>
                  ) : null}
                  <small>{action.reason}</small>
                </div>
              ))
            )}
          </div>
        </article>
      </section>
    </div>
  );
}

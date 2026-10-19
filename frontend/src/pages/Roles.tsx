import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldPlus } from "lucide-react";
import { useId, useMemo, useState } from "react";

import { api, type ApiError } from "../api/client";
import { capabilityLock, type WriteCapability } from "../api/capabilities";
import {
  listPermissionCatalog,
  listRoles,
  type PermissionCatalogEntry,
  type RoleDefinition,
  type RoleLevel,
} from "../api/roles";
import { hasPermission, isTenantTier, loadSession, type Session } from "../auth/session";
import { ControlRail } from "../components/ControlRail";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
import { Input } from "../components/primitives/Input";
import { Select } from "../components/primitives/Select";
import { randomUuid } from "../lib/ids";
import { permissionCapabilityLabel, roleLevelLabel, TENANT_ROLE_LEVEL_LABEL } from "../lib/labels";
import { notify } from "../lib/notify";
import "./Roles.css";

const ROLE_LEVELS: RoleLevel[] = ["system", "support", "customer"];

/** Mirrors the server-side role-key rule; the server stays authoritative. */
const ROLE_KEY_PATTERN = /^[a-z][a-z0-9_]{2,63}$/;

/** The builtin role the role-definition routes reserve their writes to. */
const SYSTEM_ADMIN_ROLE = "system_admin";

/**
 * A role can hold the administrator-management capability and still be refused:
 * the routes behind these buttons keep definition changes to the platform's
 * built-in System Administrator. Stating the reservation is what makes the lock
 * actionable, and the reason needs no authorization table to read.
 */
const ROLE_DEFINITION_REFUSAL =
  "Creating or editing a role needs a provider-level role, and your session does not hold one. A role can let you manage your administrators and still not let you define roles.";

/**
 * The gate the server publishes on the session decides. A session that carries
 * no capabilities (a console talking to a server that predates the field) falls
 * back to the same two predicates the route runs, so the console neither offers
 * a write the API will refuse nor invents a refusal it does not apply.
 */
function defineRolesGate(session: Session | null): WriteCapability | undefined {
  if (session === null) return undefined;
  const published = session.capabilities?.defineRoles;
  if (published) return published;
  if (!hasPermission(session, "admin:users:manage")) {
    return { allowed: false, blocker: "permission" };
  }
  if (!session.roles.includes(SYSTEM_ADMIN_ROLE)) {
    return { allowed: false, blocker: "role" };
  }
  return { allowed: true, blocker: null };
}

function roleKeyError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0) return "Enter a role key.";
  if (!ROLE_KEY_PATTERN.test(trimmed)) {
    return "Role keys are 3-64 characters: a lowercase letter, then lowercase letters, digits or underscores.";
  }
  return undefined;
}

function displayNameError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    return "Enter a display name between 1 and 128 characters.";
  }
  return undefined;
}

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : "";
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    const code = errorCode(error);
    if (code === "ROLE_IN_USE") {
      return "Role is assigned to users; remove assignments first.";
    }
    if (code === "ROLE_BUILTIN") {
      return "Built-in roles come with Nullapart and cannot be changed here.";
    }
    const message = String((error as ApiError).message);
    if (code === "RATE_LIMITED") {
      return `${message} Please wait a moment before retrying.`;
    }
    return message;
  }
  return "Role data is temporarily unavailable.";
}

interface RoleDraft {
  mode: "create" | "edit";
  original: RoleDefinition | null;
}

/**
 * Role workspace listing platform built-ins and deployment-defined custom
 * roles, with creation, editing and deletion of custom roles. The server
 * enforces who may hold each capability: definition changes are reserved for the
 * built-in System Administrator identity, built-ins are immutable, and role
 * deletion is rejected while users still hold the role. A customer administrator
 * sees the same directory as "Your roles" with those changes stated as locked.
 */
export function Roles() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [dialog, setDialog] = useState<RoleDraft | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<RoleDefinition | null>(null);

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const roles = useQuery({
    queryKey: ["admin-roles"],
    queryFn: ({ signal }) => listRoles(signal),
  });
  const permissionCatalog = useQuery({
    queryKey: ["admin-permissions"],
    queryFn: ({ signal }) => listPermissionCatalog(signal),
    // Only the role-definition dialog reads the catalog, and a customer console
    // cannot define roles, so it never asks. The read would be safe anyway: the
    // server answers a caller who can only grant with the permissions they
    // already hold, not the platform's full vocabulary.
    enabled: session.isSuccess && !isTenantTier(session.data ?? null),
  });

  const current = session.data ?? null;
  const tenant = isTenantTier(current);
  const defineRoles = defineRolesGate(current);
  const canManage = defineRoles?.allowed === true;
  const defineRolesLock = capabilityLock(
    defineRoles,
    "Creating or editing a role",
    "admin:users:manage",
    ROLE_DEFINITION_REFUSAL,
  );
  // A customer administers the roles that exist inside their own customer. The
  // server already stops the directory at the levels this caller may grant, so
  // this filter is what keeps the list honest for a support-tier seat that can
  // see customer roles but must not present them as its whole ladder.
  const directory = useMemo(
    () => (roles.data ?? []).filter((role) => !tenant || role.roleLevel === "customer"),
    [roles.data, tenant],
  );
  const tenantPermissionCount = useMemo(
    () => new Set(directory.flatMap((role) => role.permissions)).size,
    [directory],
  );

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return directory;
    return directory.filter((role) =>
      [
        role.displayName,
        role.roleKey,
        role.roleLevel,
        ...role.permissions.map((permission) =>
          tenant ? permissionCapabilityLabel(permission) : permission,
        ),
      ]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [directory, search, tenant]);

  const rolesAvailable = roles.isSuccess;
  const rolesState = roles.isError ? "Unavailable" : "Loading";

  function refresh() {
    void queryClient.invalidateQueries({ queryKey: ["admin-roles"] });
  }

  return (
    <div className="roles-page">
      <WorkspaceHeader
        eyebrow="Access"
        title={tenant ? "Your roles" : "Roles"}
        description={
          canManage
            ? "Built-in roles come with Nullapart and cannot be changed here. Custom roles are ones you create for this installation from the permissions listed here."
            : tenant
              ? "The roles your administrators are assigned to, and the permissions each one grants. Role definitions themselves are written by your provider."
              : "Built-in roles come with Nullapart and cannot be changed here. Custom roles are ones the platform defines for this installation from the permissions listed here."
        }
        scope={canManage ? "Managing roles" : tenant ? "Viewing your roles" : "Viewing roles"}
      />

      <ControlRail
        title="Roles"
        summary={
          tenant
            ? "Give an administrator the smallest role that lets them do their job. Your provider writes the role definitions behind these."
            : "Give an administrator the smallest role that lets them do their job. A custom role can only use the permissions listed here."
        }
        signals={[
          {
            label: "Roles",
            value: rolesAvailable ? directory.length : rolesState,
            detail: rolesAvailable
              ? "Built-in and custom roles you can see."
              : "The role list is still loading.",
          },
          {
            label: "Custom",
            value: rolesAvailable ? directory.filter((role) => !role.builtin).length : rolesState,
            detail: rolesAvailable
              ? canManage
                ? "Custom roles you can edit or delete."
                : tenant
                  ? "Custom roles written by your provider."
                  : "Custom roles written by the platform."
              : "The custom role count is unavailable until the roles load.",
            tone:
              rolesAvailable && directory.some((role) => !role.builtin) ? "attention" : "neutral",
          },
          {
            label: "Permissions",
            value: tenant
              ? rolesAvailable
                ? tenantPermissionCount
                : rolesState
              : permissionCatalog.isSuccess
                ? permissionCatalog.data.length
                : permissionCatalog.isError
                  ? "Unavailable"
                  : "Loading",
            detail: tenant
              ? rolesAvailable
                ? "Distinct permissions your roles grant."
                : "The permission count is unavailable until the roles load."
              : permissionCatalog.isSuccess
                ? "Permissions you can add to a custom role."
                : "The permission list is still loading.",
          },
        ]}
      />

      <WorkflowGuide
        title={tenant ? "Keep each role narrow" : "Introduce a custom role deliberately"}
        description={
          tenant
            ? "A role decides what its holders can do next. Your provider writes the definitions; you assign roles to your administrators, and every grant and removal is recorded."
            : "A role decides what its holders can do later. Saving, editing and deleting a role is checked against your own role and recorded."
        }
        steps={
          tenant
            ? [
                {
                  label: "Compare",
                  detail:
                    "Open a role's permissions before assigning it. Check none of them already fits.",
                },
                {
                  label: "Assign",
                  detail: "Give the smallest role that lets the administrator do their job.",
                },
                {
                  label: "Review",
                  detail:
                    "Remove roles an administrator no longer needs, from the administrators page.",
                },
              ]
            : [
                {
                  label: "Compare",
                  detail:
                    "Check the built-in roles first. Add a custom role only when none of them fit.",
                },
                {
                  label: "Compose",
                  detail: "Select only the permissions the role needs.",
                },
                {
                  label: "Assign",
                  detail:
                    "Give the role to administrators from the directory. Remove those grants before deleting the role.",
                },
              ]
        }
      />

      {roles.isError ? (
        <div className="roles-state error" role="alert">
          {errorMessage(roles.error)}
          <StepUpPrompt error={roles.error} />
        </div>
      ) : null}
      {permissionCatalog.isError ? (
        <p className="roles-error" role="alert">
          {errorMessage(permissionCatalog.error)}
        </p>
      ) : null}

      <div className="roles-toolbar">
        <label className="roles-search">
          <span className="sr-only">Search roles</span>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder={
              tenant ? "Search your roles by name or capability" : "Search role key, name, level"
            }
          />
        </label>
        {canManage ? (
          <Button
            variant="primary"
            onClick={() => {
              setDialog({ mode: "create", original: null });
            }}
          >
            <ShieldPlus size={16} aria-hidden="true" />
            New role
          </Button>
        ) : defineRolesLock !== "" ? (
          <p className="roles-lock" role="status">
            {defineRolesLock}
          </p>
        ) : null}
      </div>

      <div className="card roles-card">
        <table className="roles-table">
          <caption className="sr-only">
            {tenant ? "Roles your customer uses" : "Roles defined in this deployment"}
          </caption>
          <thead>
            <tr>
              <th scope="col">Role</th>
              <th scope="col">Level</th>
              <th scope="col">Source</th>
              <th scope="col">Permissions</th>
              <th scope="col">Users</th>
              {canManage ? <th scope="col">Actions</th> : null}
            </tr>
          </thead>
          <tbody>
            {filtered.map((role) => (
              <tr key={role.roleKey}>
                <td>
                  <strong>{role.displayName}</strong>
                  {/* The role key is the row in the platform's role table. A
                      tenant grants roles by name and never quotes a key back,
                      so the customer projection shows the name alone. */}
                  {tenant ? null : <span className="roles-key">{role.roleKey}</span>}
                </td>
                <td>
                  <Hint
                    label={
                      tenant
                        ? "Every role listed here reaches one organisation: your own. Roles above that belong to your provider and are not listed."
                        : "The level sets the widest scope this role can reach. System reaches everything, support reaches customer and support work, and customer reaches one customer."
                    }
                  >
                    <span className={`roles-badge roles-badge-${role.roleLevel} hint-term`}>
                      {tenant ? TENANT_ROLE_LEVEL_LABEL : roleLevelLabel(role.roleLevel)}
                    </span>
                  </Hint>
                </td>
                <td>
                  <Hint
                    label={
                      tenant
                        ? "Built-in roles come with Nullapart and custom roles are written by your provider. Neither can be edited or deleted from here."
                        : "Built-in roles come with Nullapart and cannot be edited or deleted here. Custom roles are ones you created."
                    }
                  >
                    <span className="hint-term">{role.builtin ? "Built-in" : "Custom"}</span>
                  </Hint>
                </td>
                <td>
                  <details className="roles-permissions">
                    <summary>
                      {role.permissions.length} {tenant ? "capability" : "permission"}
                      {role.permissions.length === 1 ? "" : "s"}
                    </summary>
                    <div className="roles-permission-list">
                      {role.permissions.length === 0 ? (
                        <span className="roles-permission-empty">
                          {tenant ? "Nothing extra is allowed" : "No permissions"}
                        </span>
                      ) : (
                        role.permissions.map((permission) => (
                          <span key={permission} className="roles-permission-chip">
                            {tenant ? permissionCapabilityLabel(permission) : permission}
                          </span>
                        ))
                      )}
                    </div>
                  </details>
                </td>
                <td>{role.userCount}</td>
                {canManage ? (
                  <td>
                    {role.builtin ? (
                      <span className="roles-managed">Managed by platform</span>
                    ) : (
                      <div className="roles-actions">
                        <Button
                          size="sm"
                          onClick={() => {
                            setDialog({ mode: "edit", original: role });
                          }}
                        >
                          Edit
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          onClick={() => {
                            setDeleteTarget(role);
                          }}
                        >
                          Delete
                        </Button>
                      </div>
                    )}
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
        {roles.isLoading ? (
          <p className="roles-hint" role="status">
            Loading roles…
          </p>
        ) : null}
        {!roles.isLoading && roles.isSuccess && directory.length === 0 ? (
          <p className="roles-hint">
            {tenant
              ? "No roles are defined for your customer."
              : "No roles are defined in this deployment."}
          </p>
        ) : null}
        {!roles.isLoading && roles.isSuccess && directory.length > 0 && filtered.length === 0 ? (
          <p className="roles-hint">No roles match this search.</p>
        ) : null}
      </div>

      {dialog ? (
        <RoleDialog
          editing={dialog.original}
          catalog={permissionCatalog.data ?? []}
          catalogLoading={permissionCatalog.isLoading}
          onClose={() => {
            setDialog(null);
          }}
          onSaved={() => {
            setDialog(null);
            notify(
              dialog.mode === "create"
                ? "Role created."
                : "Role updated. Existing administrators keep their current permissions.",
            );
            refresh();
          }}
        />
      ) : null}

      {deleteTarget ? (
        <DeleteRoleDialog
          target={deleteTarget}
          onClose={() => {
            setDeleteTarget(null);
          }}
          onDeleted={() => {
            setDeleteTarget(null);
            notify(`Role "${deleteTarget.displayName}" deleted.`);
            refresh();
          }}
        />
      ) : null}
    </div>
  );
}

interface RoleDialogProps {
  editing: RoleDefinition | null;
  catalog: PermissionCatalogEntry[];
  catalogLoading: boolean;
  onClose: () => void;
  onSaved: () => void;
}

function RoleDialog({ editing, catalog, catalogLoading, onClose, onSaved }: RoleDialogProps) {
  const descriptionInputId = useId();
  const [roleKey, setRoleKey] = useState(editing?.roleKey ?? "");
  const [displayName, setDisplayName] = useState(editing?.displayName ?? "");
  const [description, setDescription] = useState(editing?.description ?? "");
  const [roleLevel, setRoleLevel] = useState<RoleLevel>(editing?.roleLevel ?? "customer");
  const [permissions, setPermissions] = useState<string[]>(editing?.permissions ?? []);
  const [permissionSearch, setPermissionSearch] = useState("");
  const [showErrors, setShowErrors] = useState(false);

  const keyProblem = editing ? undefined : roleKeyError(roleKey);
  const nameProblem = displayNameError(displayName);
  const noPermissions = permissions.length === 0;
  const canSubmit = keyProblem === undefined && nameProblem === undefined && !noPermissions;

  const save = useMutation({
    mutationFn: async () => {
      const shared = {
        displayName: displayName.trim(),
        permissions,
        ...(description.trim().length > 0 ? { description: description.trim() } : {}),
      };
      if (editing) {
        // The role key and level are immutable after creation; PATCH only
        // carries the mutable fields.
        return api.patch<RoleDefinition>(
          `/admin/roles/${encodeURIComponent(editing.roleKey)}`,
          shared,
          { idempotencyKey: randomUuid() },
        );
      }
      return api.post<RoleDefinition>(
        "/admin/roles",
        { roleKey: roleKey.trim(), roleLevel, ...shared },
        { idempotencyKey: randomUuid() },
      );
    },
    onSuccess: onSaved,
  });

  const grouped = useMemo(() => {
    const needle = permissionSearch.trim().toLowerCase();
    const visible = catalog.filter(
      (entry) =>
        !needle ||
        [entry.key, entry.displayName, entry.description, entry.group]
          .join(" ")
          .toLowerCase()
          .includes(needle),
    );
    const groups = new Map<string, PermissionCatalogEntry[]>();
    for (const entry of visible) {
      const bucket = groups.get(entry.group);
      if (bucket) bucket.push(entry);
      else groups.set(entry.group, [entry]);
    }
    return [...groups.entries()];
  }, [catalog, permissionSearch]);

  function close() {
    save.reset();
    onClose();
  }

  return (
    <Dialog open onClose={close} title={editing ? `Edit ${editing.displayName}` : "Create role"}>
      <form
        className="roles-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (!canSubmit) {
            setShowErrors(true);
            return;
          }
          save.mutate();
        }}
      >
        <p className="roles-form-hint">
          The role key cannot change after you create the role. Only the permissions listed here can
          be added. Built-in roles cannot be changed here.
        </p>
        <Input
          label="Role key"
          value={roleKey}
          onChange={(event) => setRoleKey(event.target.value)}
          placeholder="triage_agent"
          maxLength={64}
          disabled={editing !== null}
          className="roles-input-mono"
          error={showErrors || roleKey.trim().length > 0 ? keyProblem : undefined}
          hint={editing ? "Role keys cannot be changed after creation." : undefined}
        />
        <Input
          label="Display name"
          value={displayName}
          onChange={(event) => setDisplayName(event.target.value)}
          placeholder="Triage agent"
          maxLength={128}
          error={showErrors || displayName.trim().length > 0 ? nameProblem : undefined}
        />
        <div className="roles-field">
          <label htmlFor={descriptionInputId} className="roles-field-label">
            Description (optional)
          </label>
          <textarea
            id={descriptionInputId}
            className="roles-textarea"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            rows={2}
            maxLength={500}
            placeholder="What this role is for and who should hold it."
          />
        </div>
        <Hint label="The level sets the widest scope this role can reach. Only a system-level role can create roles.">
          <Select
            label="Role level"
            value={roleLevel}
            disabled={editing !== null}
            onChange={(event) => setRoleLevel(event.target.value as RoleLevel)}
            options={ROLE_LEVELS.map((level) => ({
              value: level,
              label: roleLevelLabel(level),
            }))}
          />
        </Hint>

        <fieldset className="roles-permission-picker">
          <legend>
            <Hint label="A custom role can only use permissions this installation publishes. A permission you do not hold cannot be added.">
              <span className="hint-term">Permissions</span>
            </Hint>
          </legend>
          {catalogLoading ? (
            <p className="roles-form-hint" role="status">
              Loading permissions…
            </p>
          ) : catalog.length === 0 ? (
            <p className="roles-form-hint">
              No permissions are available to add. A role needs at least one permission.
            </p>
          ) : (
            <>
              <label className="roles-permission-search">
                <span className="sr-only">Search permissions</span>
                <input
                  value={permissionSearch}
                  onChange={(event) => setPermissionSearch(event.target.value)}
                  placeholder="Search permission key, name, or group"
                />
              </label>
              {grouped.length === 0 ? (
                <p className="roles-form-hint">No permissions match this search.</p>
              ) : (
                grouped.map(([group, entries]) => (
                  <div key={group} className="roles-permission-group">
                    <p className="roles-permission-group-label">{group}</p>
                    {entries.map((entry) => (
                      <label key={entry.key} className="roles-permission-option">
                        <input
                          type="checkbox"
                          checked={permissions.includes(entry.key)}
                          onChange={(event) => {
                            setPermissions((current) =>
                              event.target.checked
                                ? [...current, entry.key]
                                : current.filter((key) => key !== entry.key),
                            );
                          }}
                        />
                        <span>
                          <strong>{entry.displayName}</strong>
                          <code>{entry.key}</code>
                          <span>{entry.description}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                ))
              )}
            </>
          )}
          {showErrors && noPermissions ? (
            <p className="roles-error" role="alert">
              Select at least one permission.
            </p>
          ) : null}
        </fieldset>

        {save.isError ? (
          <>
            <p className="roles-error" role="alert">
              {errorMessage(save.error)}
            </p>
            <StepUpPrompt error={save.error} />
          </>
        ) : null}
        <div className="roles-form-actions">
          <Button type="button" variant="ghost" onClick={close} disabled={save.isPending}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            loading={save.isPending}
            disabled={save.isPending}
          >
            {editing ? "Save role" : "Create role"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

interface DeleteRoleDialogProps {
  target: RoleDefinition;
  onClose: () => void;
  onDeleted: () => void;
}

function DeleteRoleDialog({ target, onClose, onDeleted }: DeleteRoleDialogProps) {
  const remove = useMutation({
    mutationFn: () =>
      api.delete<{ deleted: boolean }>(`/admin/roles/${encodeURIComponent(target.roleKey)}`, {
        idempotencyKey: randomUuid(),
      }),
    onSuccess: onDeleted,
  });

  return (
    <Dialog
      open
      onClose={remove.isPending ? () => undefined : onClose}
      title={`Delete ${target.displayName}`}
    >
      <div className="roles-form">
        <p className="roles-form-hint">
          Deleting <strong>{target.displayName}</strong> ({target.roleKey}) removes this role. You
          cannot delete a role while any administrator still holds it, so remove those grants first.
        </p>
        {remove.isError ? (
          <>
            <p className="roles-error" role="alert">
              {errorMessage(remove.error)}
            </p>
            <StepUpPrompt error={remove.error} />
          </>
        ) : null}
        <div className="roles-form-actions">
          <Button type="button" variant="ghost" onClick={onClose} disabled={remove.isPending}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="danger"
            loading={remove.isPending}
            onClick={() => remove.mutate()}
          >
            Delete role
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

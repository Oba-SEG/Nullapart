import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
import { useMemo, useState } from "react";

import { api, type ApiError } from "../api/client";
import { listRoles, rolePermissionsWithin, type RoleDefinition } from "../api/roles";
import { isTenantTier, loadSession, type Session } from "../auth/session";
import { ControlRail } from "../components/ControlRail";
import { StepUpPrompt } from "../components/StepUpPrompt";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import { Button } from "../components/primitives/Button";
import { Dialog } from "../components/primitives/Dialog";
import { Hint } from "../components/primitives/Hint";
import { Input } from "../components/primitives/Input";
import { randomUuid } from "../lib/ids";
import { lifecycleLabel, roleLevelLabel } from "../lib/labels";
import { notify } from "../lib/notify";
import { humanizeToken } from "../lib/text";
import "./AdminUsers.css";

interface AdminUser {
  id: string;
  login: string;
  displayName: string;
  customerId: string | null;
  lifecycle: string;
  roles: string[];
}

/**
 * Directory-facing projection of a server role definition
 * (`GET /admin/roles`). `grantable` and `revocable` are UI affordances only:
 * a role above the viewing session's own level cannot be assigned or removed
 * by them, a custom role whose permissions are not fully held cannot be
 * assigned, and the server re-checks every attempt.
 */
interface RoleView {
  key: string;
  label: string;
  level: string;
  description: string;
  builtin: boolean;
  grantable: boolean;
  grantReason: string | null;
  revocable: boolean;
  revokeReason: string | null;
}

/** Mirrors `rank_for_level` in `crates/mail-core/src/admin_rbac.rs`. */
const LEVEL_RANK: Record<string, number> = { system: 3, support: 2, customer: 1 };

function rankForLevel(level: string): number {
  return LEVEL_RANK[level] ?? 0;
}

/**
 * The caller's highest role level, as the server resolved it onto the session
 * tier. A session with no published tier keeps unrestricted role lists rather
 * than inventing refusals the API may not apply.
 */
function callerRank(session: Session | null): number {
  return typeof session?.tier === "string" ? rankForLevel(session.tier) : Number.POSITIVE_INFINITY;
}

const ABOVE_LEVEL_GRANT = "Only a session at this role's level can grant it.";
const ABOVE_LEVEL_REVOKE = "Only a session at this role's level can remove it.";
const PERMISSIONS_NOT_HELD = "Contains permissions you do not hold.";

function toRoleView(role: RoleDefinition, sessionPermissions: string[], rank: number): RoleView {
  const aboveOwnLevel = rankForLevel(role.roleLevel) > rank;
  const withinHeld = role.builtin || rolePermissionsWithin(role, sessionPermissions);
  return {
    key: role.roleKey,
    label: role.displayName,
    level: role.roleLevel,
    description: role.description ?? "Custom role.",
    builtin: role.builtin,
    grantable: !aboveOwnLevel && withinHeld,
    grantReason: aboveOwnLevel ? ABOVE_LEVEL_GRANT : withinHeld ? null : PERMISSIONS_NOT_HELD,
    revocable: !aboveOwnLevel,
    revokeReason: aboveOwnLevel ? ABOVE_LEVEL_REVOKE : null,
  };
}

/** Keys present in the directory but absent from the role service render without a documented description. */
function unknownRoleView(key: string): RoleView {
  return {
    key,
    label: humanizeToken(key),
    level: "custom",
    description:
      "This role is not in the role list. Its permissions are checked before any change is saved.",
    builtin: false,
    grantable: false,
    grantReason: "This role is not in the role list, so its permissions cannot be checked.",
    revocable: true,
    revokeReason: null,
  };
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "The request could not be completed.";
}

/**
 * Administrator directory with working lifecycle operations: create
 * administrators, grant and revoke roles. Listing requires
 * `admin:users:manage` or `admin:impersonate`; every mutation additionally
 * requires `admin:users:manage` and is re-authorized server-side. For a
 * customer-tier session the server scopes the directory to that customer and
 * requires new accounts to carry its own customer id, so the console states the
 * organisation instead of offering a customer field that can only be refused.
 */
export function AdminUsers() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [rolesTarget, setRolesTarget] = useState<AdminUser | null>(null);

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const users = useQuery({
    queryKey: ["admin-users"],
    queryFn: ({ signal }) => api.get<AdminUser[]>("/admin/users", signal),
  });
  const roleDirectory = useQuery({
    queryKey: ["admin-roles"],
    queryFn: ({ signal }) => listRoles(signal),
  });

  const current = session.data ?? null;
  const canManage = current?.permissions?.includes("admin:users:manage") ?? false;
  // A customer-tier actor administers one organisation; a support or system
  // session's own customerId is the deployment template, not a customer it
  // creates accounts for, so only the tenant shape locks the scope.
  const tenant = isTenantTier(current);
  const tenantCustomerId = tenant ? (current?.customerId ?? null) : null;
  const directory = useMemo(() => users.data ?? [], [users.data]);

  const sessionPermissions = useMemo(() => current?.permissions ?? [], [current]);
  const grantorRank = callerRank(current);
  const roleViews = useMemo(
    () =>
      (roleDirectory.data ?? []).map((role) => toRoleView(role, sessionPermissions, grantorRank)),
    [roleDirectory.data, sessionPermissions, grantorRank],
  );
  const rolesByKey = useMemo(() => new Map(roleViews.map((role) => [role.key, role])), [roleViews]);
  const viewFor = useMemo(
    () => (key: string) => rolesByKey.get(key) ?? unknownRoleView(key),
    [rolesByKey],
  );

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return directory;
    return directory.filter((user) =>
      [user.login, user.displayName, user.customerId ?? "", ...user.roles]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [directory, search]);

  const directoryAvailable = users.isSuccess;
  const directoryState = users.isError ? "Unavailable" : "Loading";

  return (
    <div className="admin-users-page">
      <WorkspaceHeader
        eyebrow="Identity administration"
        title={tenant ? "Your administrators" : "Admin users"}
        description={
          tenant
            ? "Create administrators for your organisation and manage their roles. Accounts created here belong to your organisation, and each grant or removal is checked against your own role and recorded."
            : "Create administrators and manage their roles. Each grant and removal is checked against your own role and recorded."
        }
        scope={canManage ? "Managing administrators" : "Viewing administrators"}
      />

      <ControlRail
        title={tenant ? "Your organisation" : "Directory scope"}
        summary="Give an administrator the smallest role that lets them do their job, and remove roles they no longer need."
        signals={[
          {
            label: "Administrators",
            value: directoryAvailable ? directory.length : directoryState,
            detail: directoryAvailable
              ? "Administrators you can see."
              : "The directory is still loading.",
          },
          {
            label: "Active",
            value: directoryAvailable
              ? directory.filter((user) => user.lifecycle === "active").length
              : directoryState,
            detail: directoryAvailable
              ? "Administrators who are active."
              : "The count is unavailable until the directory loads.",
            tone: directoryAvailable ? "healthy" : "neutral",
          },
          {
            label: "Role changes",
            value: canManage ? "Available" : "not granted",
            detail: canManage
              ? "Grants and removals are recorded with the change."
              : "Your current role cannot manage administrators.",
            tone: canManage ? "attention" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Change administrative access deliberately"
        description="A role change affects what an administrator can do next. Each change is recorded and cannot be deleted."
        steps={[
          {
            label: "Locate",
            detail: tenant
              ? "Find the administrator and check which roles they already hold."
              : "Find the administrator and check which customer they belong to.",
          },
          {
            label: "Review",
            detail: "Compare the account status and current roles before you change anything.",
          },
          {
            label: "Grant only what is needed",
            detail: "Grant only the roles needed. Remove roles that are no longer required.",
          },
        ]}
      />

      {users.isError ? (
        <p className="admin-users-error" role="alert">
          {errorMessage(users.error)}
        </p>
      ) : null}
      {roleDirectory.isError ? (
        <p className="admin-users-error" role="alert">
          The role list is unavailable, so the roles below may be incomplete. It refreshes once the
          role list responds.
        </p>
      ) : null}

      <div className="admin-users-toolbar">
        <label className="admin-users-search">
          <span className="sr-only">Search administrators</span>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder={
              tenant ? "Search login, name, or role" : "Search login, name, customer, or role"
            }
          />
        </label>
        {canManage ? (
          <Button
            variant="primary"
            onClick={() => {
              setCreateOpen(true);
            }}
          >
            <UserPlus size={16} aria-hidden="true" />
            New administrator
          </Button>
        ) : null}
      </div>

      <div className="card admin-users-card">
        <table className="admin-users-table">
          <thead>
            <tr>
              <th scope="col">Login</th>
              <th scope="col">Name</th>
              {tenant ? null : <th scope="col">Customer</th>}
              <th scope="col">Lifecycle</th>
              <th scope="col">Roles</th>
              {canManage ? <th scope="col">Actions</th> : null}
            </tr>
          </thead>
          <tbody>
            {filtered.map((user) => (
              <tr key={user.id}>
                <td>
                  <strong>{user.login}</strong>
                </td>
                <td>{user.displayName}</td>
                {tenant ? null : <td>{user.customerId ?? "Platform"}</td>}
                <td>{lifecycleLabel(user.lifecycle)}</td>
                <td>
                  <div className="admin-users-role-list">
                    {user.roles.length === 0 ? (
                      <span className="admin-users-role-empty">No roles</span>
                    ) : (
                      user.roles.map((roleKey) => (
                        <span
                          key={roleKey}
                          className="admin-users-role-chip"
                          title={viewFor(roleKey).description}
                        >
                          {viewFor(roleKey).label}
                        </span>
                      ))
                    )}
                  </div>
                </td>
                {canManage ? (
                  <td>
                    {user.id === current?.userId ? (
                      <p className="admin-users-lock" role="status">
                        You cannot change your own roles. Another administrator at your level has to
                        do it.
                      </p>
                    ) : (
                      <Button
                        size="sm"
                        onClick={() => {
                          setRolesTarget(user);
                        }}
                      >
                        Manage roles
                      </Button>
                    )}
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
        {users.isLoading ? <p className="admin-users-hint">Loading administrators…</p> : null}
        {!users.isLoading && filtered.length === 0 ? (
          <p className="admin-users-hint">
            {directory.length === 0
              ? "No administrators are provisioned yet."
              : "No administrators match this search."}
          </p>
        ) : null}
      </div>

      <CreateAdministratorDialog
        open={createOpen}
        roles={roleViews}
        rolesLoading={roleDirectory.isLoading}
        rolesError={roleDirectory.isError ? roleDirectory.error : null}
        tenant={tenant}
        tenantCustomerId={tenantCustomerId}
        onClose={() => {
          setCreateOpen(false);
        }}
        onCreated={() => {
          setCreateOpen(false);
          notify("Administrator created.");
          void queryClient.invalidateQueries({ queryKey: ["admin-users"] });
        }}
      />

      {rolesTarget ? (
        <ManageRolesDialog
          target={rolesTarget}
          roles={roleViews}
          rolesLoading={roleDirectory.isLoading}
          rolesError={roleDirectory.isError ? roleDirectory.error : null}
          tenant={tenant}
          onClose={() => {
            setRolesTarget(null);
          }}
          onSaved={() => {
            setRolesTarget(null);
            notify("Role changes saved.");
            void queryClient.invalidateQueries({ queryKey: ["admin-users"] });
          }}
        />
      ) : null}
    </div>
  );
}

/** Shared loading/error presentation for the server-driven role checkbox lists. */
function RolePickerState({ loading, error }: { loading: boolean; error: unknown }) {
  if (loading) {
    return (
      <p className="admin-users-form-hint" role="status">
        Reading the role directory…
      </p>
    );
  }
  if (error) {
    return (
      <p className="admin-users-error" role="alert">
        {errorMessage(error)} The role list is unavailable. Roles are checked again before any
        change is saved.
      </p>
    );
  }
  return null;
}

interface CreateDialogProps {
  open: boolean;
  roles: RoleView[];
  rolesLoading: boolean;
  rolesError: unknown;
  /** True for a customer-tier session, whose accounts are always its own. */
  tenant: boolean;
  /** The tenant session's own customer id, which the create route requires. */
  tenantCustomerId: string | null;
  onClose: () => void;
  onCreated: () => void;
}

function CreateAdministratorDialog({
  open,
  roles,
  rolesLoading,
  rolesError,
  tenant,
  tenantCustomerId,
  onClose,
  onCreated,
}: CreateDialogProps) {
  const [login, setLogin] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [customerId, setCustomerId] = useState("");
  const [selected, setSelected] = useState<string[]>([]);

  const scopedCustomerId = tenant ? (tenantCustomerId ?? "") : customerId.trim();
  const create = useMutation({
    mutationFn: async () =>
      api.post(
        "/admin/users",
        {
          login: login.trim(),
          displayName: displayName.trim(),
          customerId: scopedCustomerId === "" ? null : scopedCustomerId,
          roles: selected,
        },
        { idempotencyKey: randomUuid() },
      ),
    onSuccess: onCreated,
  });

  const loginValid = login.trim().includes("@");
  const canSubmit =
    loginValid &&
    displayName.trim().length > 0 &&
    selected.length > 0 &&
    (!tenant || scopedCustomerId.length > 0);

  function close() {
    setLogin("");
    setDisplayName("");
    setCustomerId("");
    setSelected([]);
    create.reset();
    onClose();
  }

  return (
    <Dialog open={open} onClose={close} title="Create administrator">
      <form
        className="admin-users-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (canSubmit) create.mutate();
        }}
      >
        <Input
          label="Login"
          value={login}
          onChange={(event) => setLogin(event.target.value)}
          placeholder="operator@example.test"
          error={login.trim().length > 0 && !loginValid ? "Enter an email address." : undefined}
        />
        <Input
          label="Display name"
          value={displayName}
          onChange={(event) => setDisplayName(event.target.value)}
          placeholder="Operator"
        />
        {tenant ? (
          <Input
            label="Customer account"
            value={scopedCustomerId.length > 0 ? "Your organisation" : ""}
            readOnly
            hint="Accounts you create here belong to your organisation."
            error={
              scopedCustomerId.length > 0
                ? undefined
                : "This session is not scoped to a customer, so an account cannot be created."
            }
          />
        ) : (
          <Input
            label="Customer account (optional)"
            value={customerId}
            onChange={(event) => setCustomerId(event.target.value)}
            placeholder="Leave blank for a platform account"
            hint="A customer administrator belongs to one customer only."
          />
        )}
        <fieldset className="admin-users-role-picker">
          <legend>
            <Hint label="You can only grant roles at or below your own level whose permissions you already hold. Roles you cannot grant appear dimmed.">
              <span className="hint-term">Roles</span>
            </Hint>
          </legend>
          <p className="admin-users-form-hint">
            You can only grant roles at or below your own level whose permissions you already hold.
            Each grant is recorded.
          </p>
          <RolePickerState loading={rolesLoading} error={rolesError} />
          {!rolesLoading && !rolesError
            ? roles.map((role) => (
                <label key={role.key} className="admin-users-role-option">
                  <input
                    type="checkbox"
                    checked={selected.includes(role.key)}
                    disabled={!role.grantable}
                    title={role.grantReason ?? undefined}
                    onChange={(event) => {
                      setSelected((current) =>
                        event.target.checked
                          ? [...current, role.key]
                          : current.filter((key) => key !== role.key),
                      );
                    }}
                  />
                  <span>
                    <strong>{role.label}</strong>
                    <em>{roleLevelLabel(role.level)}</em>
                    <span>{role.description}</span>
                  </span>
                </label>
              ))
            : null}
        </fieldset>
        {create.isError && (
          <>
            <p className="admin-users-error" role="alert">
              {errorMessage(create.error)}
            </p>
            <StepUpPrompt error={create.error} />
          </>
        )}
        <div className="admin-users-form-actions">
          <Button type="button" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={!canSubmit}>
            Create administrator
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

interface ManageRolesDialogProps {
  target: AdminUser;
  roles: RoleView[];
  rolesLoading: boolean;
  rolesError: unknown;
  tenant: boolean;
  onClose: () => void;
  onSaved: () => void;
}

function ManageRolesDialog({
  target,
  roles,
  rolesLoading,
  rolesError,
  tenant,
  onClose,
  onSaved,
}: ManageRolesDialogProps) {
  const [draft, setDraft] = useState<string[]>([...target.roles]);

  const availableRoles = useMemo(() => {
    const known = new Map(roles.map((role) => [role.key, role]));
    for (const key of draft) {
      if (!known.has(key)) known.set(key, unknownRoleView(key));
    }
    for (const key of target.roles) {
      if (!known.has(key)) known.set(key, unknownRoleView(key));
    }
    return [...known.values()];
  }, [roles, target.roles, draft]);

  const grants = draft.filter((key) => !target.roles.includes(key));
  const revokes = target.roles.filter((key) => !draft.includes(key));
  const unchanged = grants.length === 0 && revokes.length === 0;

  const save = useMutation({
    mutationFn: async () => {
      for (const roleKey of grants) {
        await api.post(
          `/admin/users/${encodeURIComponent(target.id)}/roles`,
          { roleKey },
          { idempotencyKey: randomUuid() },
        );
      }
      for (const roleKey of revokes) {
        await api.delete(
          `/admin/users/${encodeURIComponent(target.id)}/roles/${encodeURIComponent(roleKey)}`,
          { idempotencyKey: randomUuid() },
        );
      }
    },
    onSuccess: onSaved,
  });

  function close() {
    save.reset();
    onClose();
  }

  return (
    <Dialog open onClose={close} title="Manage roles">
      <form
        className="admin-users-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (!unchanged) save.mutate();
        }}
      >
        <p className="admin-users-form-summary">
          <strong>{target.displayName}</strong> ({target.login})
          {target.customerId
            ? tenant
              ? " in your organisation"
              : ` in customer ${target.customerId}`
            : " on the platform"}
        </p>
        <fieldset className="admin-users-role-picker">
          <legend>
            <Hint label="These are the roles the administrator holds now. Untick to remove a role, tick to add one.">
              <span className="hint-term">Current roles</span>
            </Hint>
          </legend>
          <RolePickerState loading={rolesLoading} error={rolesError} />
          {!rolesLoading && !rolesError
            ? availableRoles.map((role) => {
                const checked = draft.includes(role.key);
                // A role already held stays togglable so revokes remain possible
                // unless its level is above the viewer's own; the server still
                // authorizes both directions.
                const blocked = checked ? !role.revocable : !role.grantable;
                const reason = checked ? role.revokeReason : role.grantReason;
                return (
                  <label key={role.key} className="admin-users-role-option">
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={blocked}
                      title={reason ?? undefined}
                      onChange={(event) => {
                        setDraft((current) =>
                          event.target.checked
                            ? [...current, role.key]
                            : current.filter((key) => key !== role.key),
                        );
                      }}
                    />
                    <span>
                      <strong>{role.label}</strong>
                      <em>{roleLevelLabel(role.level)}</em>
                      <span>{role.description}</span>
                    </span>
                  </label>
                );
              })
            : null}
        </fieldset>
        {draft.length === 0 ? (
          <p className="admin-users-form-hint" role="note">
            An administrator with no roles cannot do anything. Consider suspending the account
            instead of removing every role.
          </p>
        ) : null}
        {!unchanged ? (
          <div className="admin-users-pending">
            <span className="admin-users-pending-title">Pending changes</span>
            <ul>
              {grants.map((roleKey) => (
                <li key={`grant-${roleKey}`}>
                  Add{" "}
                  <strong>
                    {availableRoles.find((role) => role.key === roleKey)?.label ?? roleKey}
                  </strong>
                </li>
              ))}
              {revokes.map((roleKey) => (
                <li key={`revoke-${roleKey}`}>
                  Remove{" "}
                  <strong>
                    {availableRoles.find((role) => role.key === roleKey)?.label ?? roleKey}
                  </strong>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {save.isError && (
          <>
            <p className="admin-users-error" role="alert">
              {errorMessage(save.error)} Parts of this change that already saved are kept.
            </p>
            <StepUpPrompt error={save.error} />
          </>
        )}
        <div className="admin-users-form-actions">
          <Button type="button" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={unchanged}>
            Save role changes
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

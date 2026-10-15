import { useQuery } from "@tanstack/react-query";
import { api, type ApiError } from "../api/client";
import { loadSession } from "../auth/session";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import "./AdminUsers.css";

interface AdminUser {
  id: string;
  login: string;
  displayName: string;
  customerId: string | null;
  lifecycle: string;
  roles: string[];
}

function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as ApiError).message);
  }
  return "The request could not be completed.";
}

/**
 * Admin user directory. Listing is available to `admin:users:manage`;
 * customer entry lives on the Customers page because entry targets a
 * customer tenant, not a subject user.
 */
export function AdminUsers() {
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

  const current = session.data ?? null;
  const canManage = current?.permissions?.includes("admin:users:manage") ?? false;
  const directoryAvailable = users.isSuccess;
  const directoryState = users.isError ? "Unavailable" : "Loading";

  return (
    <div className="admin-users-page">
      <WorkspaceHeader
        eyebrow="Identity administration"
        title="Admin users"
        description="Review the administrators recognized by this deployment and their current lifecycle. Role grants and revocations remain server-authorized and audited."
        scope={canManage ? "Administrator directory" : "Read-only directory"}
      />

      <ControlRail
        title="Directory scope"
        summary="This console route is intentionally read-only. User-role mutation is not implemented as a browser action in this deployment."
        signals={[
          {
            label: "Administrators",
            value: directoryAvailable ? (users.data ?? []).length : directoryState,
            detail: directoryAvailable
              ? "Directory subjects returned in the permitted scope."
              : "The directory has not produced an authoritative result yet.",
          },
          {
            label: "Active",
            value: directoryAvailable
              ? (users.data ?? []).filter((user) => user.lifecycle === "active").length
              : directoryState,
            detail: directoryAvailable
              ? "Subjects with an active lifecycle."
              : "Lifecycle status is unavailable until the directory query succeeds.",
            tone: directoryAvailable ? "healthy" : "neutral",
          },
          {
            label: "Mutation path",
            value: canManage ? "API-only" : "not granted",
            detail: canManage
              ? "The management API remains separately authorized and audited; no grant control is implied here."
              : "Your current role has no user-management permission.",
          },
        ]}
      />

      <WorkflowGuide
        title="Review identity scope before access changes"
        description="This directory is evidence for administrative access. User-role mutation is intentionally API-only in this deployment."
        steps={[
          {
            label: "Locate",
            detail: "Find the administrator and verify their tenant association.",
          },
          { label: "Review", detail: "Compare lifecycle and currently effective roles." },
          {
            label: "Escalate",
            detail: "Role mutation is API-only and remains separately authorized and audited.",
          },
        ]}
      />

      {users.isError ? (
        <p className="admin-users-error" role="alert">
          {errorMessage(users.error)}
        </p>
      ) : null}

      <div className="card admin-users-card">
        <table className="admin-users-table">
          <thead>
            <tr>
              <th scope="col">Login</th>
              <th scope="col">Name</th>
              <th scope="col">Customer</th>
              <th scope="col">Lifecycle</th>
              <th scope="col">Roles</th>
            </tr>
          </thead>
          <tbody>
            {(users.data ?? []).map((user) => (
              <tr key={user.id}>
                <td>{user.login}</td>
                <td>{user.displayName}</td>
                <td>{user.customerId ?? "—"}</td>
                <td>{user.lifecycle}</td>
                <td>{user.roles.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {users.isLoading ? <p className="admin-users-hint">Loading administrators…</p> : null}
        {!users.isLoading && (users.data ?? []).length === 0 ? (
          <p className="admin-users-hint">No administrators are provisioned yet.</p>
        ) : null}
      </div>

      {canManage ? (
        <p className="admin-users-hint">Role mutation is intentionally API-only.</p>
      ) : null}
    </div>
  );
}

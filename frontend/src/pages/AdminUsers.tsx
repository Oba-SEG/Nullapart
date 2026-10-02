import { useQuery } from "@tanstack/react-query";
import { api, type ApiError } from "../api/client";
import { loadSession } from "../auth/session";
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

  return (
    <div className="admin-users-page">
      <div>
        <h1>Admin users</h1>
        <p className="admin-users-subtitle">Directory of administrators for this deployment.</p>
      </div>

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
        <p className="admin-users-hint">
          Role changes happen through the management API; every grant and revocation is audited.
        </p>
      ) : null}
    </div>
  );
}

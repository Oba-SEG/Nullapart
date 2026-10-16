/**
 * Shared contract types for the deployment role catalogue.
 *
 * `GET /admin/roles` and `GET /admin/permissions` back both the Roles
 * workspace and the role pickers in the administrator directory. The server
 * remains the authorization boundary; these types only describe what it
 * publishes.
 */

import { api } from "./client";

export type RoleLevel = "system" | "support" | "customer";

export interface RoleDefinition {
  roleKey: string;
  displayName: string;
  description: string | null;
  roleLevel: RoleLevel;
  builtin: boolean;
  permissions: string[];
  userCount: number;
}

export interface PermissionCatalogEntry {
  key: string;
  displayName: string;
  description: string;
  group: string;
}

export function listRoles(signal?: AbortSignal): Promise<RoleDefinition[]> {
  return api.get<RoleDefinition[]>("/admin/roles", signal);
}

export function listPermissionCatalog(signal?: AbortSignal): Promise<PermissionCatalogEntry[]> {
  return api.get<PermissionCatalogEntry[]>("/admin/permissions", signal);
}

/**
 * True when every permission of a custom role is already held by the acting
 * session. UI affordance only: a non-system grantor can still attempt the
 * grant; the server rejects it authoritatively.
 */
export function rolePermissionsWithin(role: RoleDefinition, sessionPermissions: string[]) {
  return role.permissions.every((permission) => sessionPermissions.includes(permission));
}

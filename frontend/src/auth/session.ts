/**
 * Nullapart Auth module
 *
 * Session-based authentication state. Tokens are NEVER stored in
 * browser Local Storage, Session Storage, or IndexedDB.
 * The backend BFF owns the OIDC authorization-code exchange/session
 * and issues secure server-managed session cookies.
 *
 * Follows: docs/23-FRONTEND-ARCHITECTURE.md
 */

export interface Session {
  authenticated: boolean;
  userId: string;
  email: string;
  roles: string[];
  customerId: string | null;
  expiresAt: string;
}

// Check if the user has a specific role
export function hasRole(session: Session | null, role: string): boolean {
  return session?.roles.includes(role) ?? false;
}

// Check if the user is a system admin
export function isSystemAdmin(session: Session | null): boolean {
  return hasRole(session, "system_admin");
}

// Check if the user can impersonate
export function canImpersonate(session: Session | null): boolean {
  return hasRole(session, "system_admin") || hasRole(session, "support");
}

// Check if the session is expired
export function isSessionExpired(session: Session): boolean {
  return new Date(session.expiresAt) < new Date();
}

// Get the effective customer ID (respects impersonation)
export function getEffectiveCustomerId(session: Session): string | null {
  return session.customerId;
}

// Route guard: checks if the current session can access a route
export function canAccessRoute(session: Session | null, requiredRoles: string[]): boolean {
  if (!session || isSessionExpired(session)) return false;
  return requiredRoles.some((role) => session.roles.includes(role));
}

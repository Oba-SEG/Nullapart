/**
 * Nullapart browser session boundary.
 *
 * OIDC authorization-code exchange, token custody and refresh happen in the BFF.
 * The browser receives only a Secure/HttpOnly server-managed session cookie.
 */

import { api } from "../api/client";

export interface Session {
  authenticated: boolean;
  userId: string;
  email: string;
  roles: string[];
  customerId: string | null;
  expiresAt: string;
}

export async function loadSession(signal?: AbortSignal): Promise<Session | null> {
  try {
    return await api.get<Session>("/auth/session", signal);
  } catch (error) {
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? String((error as { code: unknown }).code)
        : "";
    if (code === "unauthorized" || code === "HTTP_401") {
      return null;
    }
    throw error;
  }
}

export function beginLogin(returnTo = "/"): void {
  const target = new URL("/api/v1/auth/login", window.location.origin);
  const safeReturnTo =
    returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";
  target.searchParams.set("return_to", safeReturnTo);
  window.location.assign(target.toString());
}

export async function logout(): Promise<void> {
  await api.post<void>("/auth/logout", undefined, {
    idempotencyKey: crypto.randomUUID(),
  });
  window.location.assign("/login");
}

export function hasRole(session: Session | null, role: string): boolean {
  return session?.roles.includes(role) ?? false;
}

export function isSystemAdmin(session: Session | null): boolean {
  return hasRole(session, "system_admin");
}

export function canImpersonate(session: Session | null): boolean {
  return hasRole(session, "system_admin") || hasRole(session, "support");
}

export function isSessionExpired(session: Session): boolean {
  return new Date(session.expiresAt).getTime() <= Date.now();
}

export function getEffectiveCustomerId(session: Session): string | null {
  return session.customerId;
}

export function canAccessRoute(session: Session | null, requiredRoles: string[]): boolean {
  if (!session || !session.authenticated || isSessionExpired(session)) return false;
  return requiredRoles.length === 0 || requiredRoles.some((role) => session.roles.includes(role));
}

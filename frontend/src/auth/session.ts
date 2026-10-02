/**
 * Nullapart browser session boundary.
 *
 * OIDC authorization-code exchange, token custody and refresh happen in the BFF.
 * The browser receives only a Secure/HttpOnly server-managed session cookie;
 * the CSRF token for mutating requests is held in memory (auth/csrf).
 */

import { api, markSessionSeen } from "../api/client";
import { clearCsrfToken, setCsrfToken } from "./csrf";
import { randomUuid } from "../lib/ids";

export interface ImpersonationInfo {
  id: string;
  customerId: string;
  customerDisplayName: string;
  reason: string;
  startedAt: string;
}

export interface Session {
  authenticated: boolean;
  userId: string;
  email: string;
  roles: string[];
  /** Server-derived claims for UI affordances; every API re-authorizes. */
  permissions?: string[];
  customerId: string | null;
  expiresAt: string;
  stepUpActive?: boolean;
  csrfToken?: string;
  /** Active customer-entry overlay; the actor's roles/permissions are unchanged. */
  impersonation?: ImpersonationInfo | null;
}

export function hasPermission(session: Session | null, permission: string): boolean {
  return session?.permissions?.includes(permission) ?? false;
}

function sessionFromResponse(data: Session): Session {
  markSessionSeen();
  setCsrfToken(data.csrfToken ?? null);
  return data;
}

export async function loadSession(signal?: AbortSignal): Promise<Session | null> {
  try {
    return sessionFromResponse(await api.get<Session>("/auth/session", signal));
  } catch (error) {
    const code = errorCode(error);
    if (
      code === "UNAUTHENTICATED" ||
      code === "unauthorized" ||
      code === "HTTP_401" ||
      code === "HTTP_403"
    ) {
      clearCsrfToken();
      return null;
    }
    throw error;
  }
}

function safeReturnTo(returnTo: string): string {
  const hasControlChar = Array.from(returnTo).some((char) => {
    const code = char.charCodeAt(0);
    return code < 0x20 || code === 0x7f;
  });
  return returnTo.startsWith("/") &&
    !returnTo.startsWith("//") &&
    !returnTo.includes("\\") &&
    !hasControlChar
    ? returnTo
    : "/";
}

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : "";
}

/**
 * Same-origin navigation entry point for a full-page login. The BFF answers
 * with either a session cookie (proxy-header mode) or a redirect to the IdP;
 * the browser follows it as a real navigation so the IdP can set its own
 * cookies the way it would for any other authorization-code client.
 */
function loginEntryUrl(target: string): string {
  return `/api/v1/auth/login?return_to=${encodeURIComponent(target)}`;
}

/**
 * Exchanges the reverse-proxy boundary identity for a server-side session and
 * returns the sanitized post-login destination. The CSRF token from the
 * response is retained in memory for mutating requests.
 *
 * In OIDC mode the POST carries no identity, so the server answers with a
 * redirect (surfaced as `AUTH_REDIRECT`) and the caller performs the
 * full-page navigation to the login entry point instead.
 */
export async function exchangeLogin(returnTo = "/"): Promise<string> {
  const target = safeReturnTo(returnTo);
  sessionFromResponse(await api.post<Session>("/auth/login", undefined, { redirect: "manual" }));
  return target;
}

export async function beginLogin(returnTo = "/"): Promise<void> {
  const target = safeReturnTo(returnTo);
  try {
    await exchangeLogin(target);
  } catch (error) {
    if (errorCode(error) === "AUTH_REDIRECT") {
      // OIDC mode: the POST was side-effect free, so start the flow with a
      // real top-level navigation (flow cookie, authorize redirect, IdP UI).
      window.location.assign(loginEntryUrl(target));
      return;
    }
    throw error;
  }
  window.location.assign(target);
}

export interface LogoutResult {
  authenticated: boolean;
  /** RP-initiated IdP logout endpoint, when the IdP publishes one. */
  idpLogoutUrl?: string | null;
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Revokes the local session first (server-side) and then, when the IdP
 * exposes an end-session endpoint, continues with RP-initiated logout so the
 * identity-provider session dies too. The destination is validated before the
 * browser follows it; anything unexpected falls back to the login page.
 */
export async function logout(): Promise<void> {
  let destination = "/login";
  try {
    const result = await api.post<LogoutResult>("/auth/logout", undefined, {
      idempotencyKey: randomUuid(),
    });
    const idpLogoutUrl = result?.idpLogoutUrl;
    if (typeof idpLogoutUrl === "string" && isHttpUrl(idpLogoutUrl)) {
      destination = idpLogoutUrl;
    }
  } finally {
    clearCsrfToken();
    window.location.assign(destination);
  }
}

/**
 * Starts a step-up re-authentication round trip for the current session and
 * returns to `returnTo` (defaults to the current page) once it completes.
 * Used when an API answers `STEP_UP_REQUIRED`.
 */
export function beginStepUp(returnTo?: string): void {
  const current =
    typeof window !== "undefined" ? `${window.location.pathname}${window.location.search}` : "/";
  const target = safeReturnTo(returnTo ?? current);
  window.location.assign(`/api/v1/auth/reauth?return_to=${encodeURIComponent(target)}`);
}

/** True when a rejected API call means the session must re-authenticate. */
export function isStepUpRequired(error: unknown): boolean {
  return errorCode(error) === "STEP_UP_REQUIRED";
}

export function hasRole(session: Session | null, role: string): boolean {
  return session?.roles.includes(role) ?? false;
}

export function isSystemAdmin(session: Session | null): boolean {
  return hasRole(session, "system_admin");
}

export function canImpersonate(session: Session | null): boolean {
  return hasPermission(session, "admin:impersonate");
}

/**
 * Enters a customer: the session's customer scope switches to the target
 * while the actor's own roles, permissions, and identity stay untouched.
 * The reason is mandatory server-side (10-500 characters); step-up and the
 * dedicated entry rate limit are enforced by the API.
 */
export async function startImpersonation(customerId: string, reason: string): Promise<void> {
  await api.post<ImpersonationInfo>("/admin/impersonations", { customerId, reason });
}

/**
 * Exits the entered customer. Idempotent: ending when nothing is active
 * resolves without a change.
 */
export async function endImpersonation(): Promise<{ ended: boolean }> {
  return api.post<{ ended: boolean }>("/admin/impersonations/end");
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

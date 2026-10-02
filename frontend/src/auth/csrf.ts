/**
 * Nullapart CSRF token custody.
 *
 * The token is minted with the server-side session (POST /auth/login), held
 * only in this in-memory module, and attached to mutating API requests. It is
 * never persisted to browser storage and is cleared when the session ends.
 */

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

export function clearCsrfToken(): void {
  csrfToken = null;
}

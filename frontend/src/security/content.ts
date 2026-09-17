/**
 * Nullapart Security utilities for hostile content rendering
 *
 * Untrusted email content never executes in the trusted UI origin.
 * Message rendering uses the separate hostile-content architecture.
 *
 * Follows: docs/23-FRONTEND-ARCHITECTURE.md
 */

// Sanitize a string for safe display in the trusted UI
export function sanitizeDisplay(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// Check if a URL is safe to link to (no javascript: or data: schemes)
export function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ["http:", "https:", "mailto:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

// Check if the current session is stored securely (no localStorage tokens)
export function verifySecureSession(): boolean {
  // Check that auth tokens are not in localStorage/sessionStorage/IndexedDB
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && /token|auth|session|jwt|refresh/i.test(key)) {
      return false;
    }
  }
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (key && /token|auth|session|jwt|refresh/i.test(key)) {
      return false;
    }
  }
  return true;
}

// Content Security Policy nonce for inline scripts (if needed)
export function getCspNonce(): string | null {
  const meta = document.querySelector('meta[name="csp-nonce"]');
  return meta?.getAttribute("content") ?? null;
}

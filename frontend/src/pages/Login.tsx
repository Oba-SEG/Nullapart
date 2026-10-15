import { ShieldCheck } from "lucide-react";
import { useState } from "react";
import { beginLogin } from "../auth/session";
import "./Login.css";

export function Login() {
  const search = new URLSearchParams(window.location.search);
  const returnTo = search.get("return_to") ?? "/";
  const sessionExpired = search.get("reason") === "expired";
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleLogin() {
    setBusy(true);
    setError(null);
    try {
      await beginLogin(returnTo);
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : "Sign-in could not be completed. Try again.",
      );
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <img
            src="/brand/logos/primary-logo-dark@2x.png"
            alt="Nullapart — Cleaner mail. A safer world."
            className="login-logo-img"
          />
          <p className="login-subtitle">Secure administration access</p>
        </div>

        {sessionExpired ? (
          <p className="login-notice" role="status">
            Your session expired. Sign in again to continue where you left off.
          </p>
        ) : null}

        <button
          type="button"
          className="btn btn-primary login-btn"
          onClick={() => void handleLogin()}
          disabled={busy}
        >
          <ShieldCheck size={18} aria-hidden="true" />
          {busy ? "Signing in…" : "Continue with secure sign-in"}
        </button>

        {error ? (
          <p className="form-error login-error" role="alert">
            {error}
          </p>
        ) : null}

        <div className="login-footer">
          <p className="footer-text">
            Authentication and MFA are handled by the Nullapart identity service. Your browser may
            first ask for the local console credentials.
          </p>
        </div>
      </div>
    </div>
  );
}

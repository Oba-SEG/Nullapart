import { ArrowRight, KeyRound, LockKeyhole, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { beginLocalLogin, beginLogin } from "../auth/session";
import "./Login.css";

export function Login() {
  const search = new URLSearchParams(window.location.search);
  const returnTo = search.get("return_to") ?? "/";
  const sessionExpired = search.get("reason") === "expired";
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  async function handleLocalLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!username || !password) {
      setError("Enter both local console credentials to continue.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await beginLocalLogin(username, password, returnTo);
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : "The local console credentials were not accepted.",
      );
      setPassword("");
      setBusy(false);
    }
  }

  function handleIdentityProviderLogin() {
    setBusy(true);
    setError(null);
    beginLogin(returnTo);
  }

  return (
    <div className="login-page">
      <div className="login-stage">
        <section className="login-brief" aria-labelledby="login-brief-title">
          <img
            src="/brand/logos/horizontal-logo-dark.png"
            alt="Nullapart — Cleaner mail. A safer world."
            className="login-wordmark"
          />
          <p className="login-kicker">Control plane · restricted access</p>
          <h1 id="login-brief-title">Operate the mail-security boundary.</h1>
          <p>
            Review the platform estate, enter a customer only with an audited reason, and make
            changes through server-authorized controls.
          </p>
          <dl className="login-assurances">
            <div>
              <dt>
                <ShieldCheck size={16} aria-hidden="true" /> Session custody
              </dt>
              <dd>Authenticated sessions are HttpOnly and server-managed.</dd>
            </div>
            <div>
              <dt>
                <LockKeyhole size={16} aria-hidden="true" /> Protected actions
              </dt>
              <dd>High-risk operations require the appropriate authority and step-up.</dd>
            </div>
          </dl>
        </section>

        <section className="login-card" aria-labelledby="login-form-title">
          <div className="login-header">
            <span className="login-eyebrow">Operator sign-in</span>
            <h2 id="login-form-title">Local control console</h2>
            <p className="login-subtitle">
              Use the local development credentials configured for this private console.
            </p>
          </div>

          {sessionExpired ? (
            <p className="login-notice" role="status">
              Your session expired. Sign in again to continue where you left off.
            </p>
          ) : null}

          <form className="login-form" onSubmit={(event) => void handleLocalLogin(event)}>
            <label className="form-group" htmlFor="local-console-user">
              <span className="form-label">Local console user</span>
              <span className="input-wrapper">
                <KeyRound className="input-icon" size={17} aria-hidden="true" />
                <input
                  id="local-console-user"
                  className="form-input with-icon"
                  name="username"
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  disabled={busy}
                />
              </span>
            </label>
            <label className="form-group" htmlFor="local-console-password">
              <span className="form-label">Local console password</span>
              <span className="input-wrapper">
                <LockKeyhole className="input-icon" size={17} aria-hidden="true" />
                <input
                  id="local-console-password"
                  className="form-input with-icon"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={busy}
                />
              </span>
            </label>
            <button type="submit" className="btn btn-primary login-btn" disabled={busy}>
              <ShieldCheck size={18} aria-hidden="true" />
              {busy ? "Establishing session…" : "Enter local control plane"}
            </button>
          </form>

          {error ? (
            <p className="form-error login-error" role="alert">
              {error}
            </p>
          ) : null}

          <div className="login-footer">
            <p className="footer-text">Signing in through an external identity provider instead?</p>
            <button
              type="button"
              className="login-idp-link"
              onClick={handleIdentityProviderLogin}
              disabled={busy}
            >
              Continue with configured identity provider <ArrowRight size={15} aria-hidden="true" />
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}

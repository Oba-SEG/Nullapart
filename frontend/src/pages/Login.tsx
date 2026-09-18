import { ShieldCheck } from "lucide-react";
import { beginLogin } from "../auth/session";
import "./Login.css";

export function Login() {
  const returnTo = new URLSearchParams(window.location.search).get("return_to") ?? "/";

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <div className="login-logo" aria-label="Nullapart">
            <span className="logo-text">NULLAPART</span>
          </div>
          <p className="login-subtitle">Secure administration access</p>
        </div>

        <button
          type="button"
          className="btn btn-primary login-btn"
          onClick={() => beginLogin(returnTo)}
        >
          <ShieldCheck size={18} aria-hidden="true" />
          Continue with secure sign-in
        </button>

        <div className="login-footer">
          <p className="footer-text">
            Authentication and MFA are handled by the Nullapart identity service.
          </p>
        </div>
      </div>
    </div>
  );
}

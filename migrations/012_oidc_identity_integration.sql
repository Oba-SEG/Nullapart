-- 012_oidc_identity_integration.sql
--
-- OIDC identity integration (docs/03-IDENTITY-RBAC-IMPERSONATION.md,
-- docs/phases/PHASE-3-LOCAL-IMPLEMENTATION-PLAN.md increment 4): ZITADEL is
-- the login/assertion source only. The BFF keeps opaque cookie sessions,
-- server-side authorization, RLS and audit semantics unchanged.
--
-- Trust notes:
--   * auth_subject is a mapping key, never authorization (see 010): the
--     unique-per-deployment index makes one IdP subject bind to at most one
--     local admin user, and a local user to at most one subject, so a
--     replayed/mis-issued assertion cannot fan out or retarget an identity.
--   * oidc_login_flows stores the CSRF `state` binding (hashed), `nonce` and
--     PKCE code verifier for an in-flight authorization-code exchange. It
--     holds no tokens and no assertion claims; rows are claimed exactly once
--     (application issues a DELETE ... RETURNING), expire in minutes and are
--     deployment-scoped by row-level security like the other admin_* tables.
--   * A reauth (step-up) flow is bound to its session row and disappears
--     when that session does (ON DELETE CASCADE).

CREATE UNIQUE INDEX admin_users_deployment_auth_subject_unique
    ON admin_users (deployment_id, auth_subject)
    WHERE auth_subject IS NOT NULL;

CREATE TABLE oidc_login_flows (
    state_hash BYTEA PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    nonce TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    flow_kind TEXT NOT NULL CHECK (flow_kind IN ('login', 'reauth')),
    session_id UUID REFERENCES admin_sessions(id) ON DELETE CASCADE,
    -- Same-origin absolute path to return to after completion; the check
    -- mirrors the application-level `safe_return_to` validation so a
    -- stored destination can never become an open redirect or carry
    -- header bytes into the callback response.
    return_to TEXT NOT NULL DEFAULT '/'
        CHECK (return_to ~ '^/[ -~]*$' AND return_to NOT LIKE '//%'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK ((flow_kind = 'reauth') = (session_id IS NOT NULL))
);

CREATE INDEX idx_oidc_login_flows_deployment
    ON oidc_login_flows (deployment_id, expires_at);

ALTER TABLE oidc_login_flows ENABLE ROW LEVEL SECURITY;

CREATE POLICY oidc_login_flows_deployment_isolation ON oidc_login_flows
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

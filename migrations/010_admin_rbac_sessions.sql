-- 010_admin_rbac_sessions.sql
--
-- Server-side administrative identity foundation for the Control Plane
-- (docs/03-IDENTITY-RBAC-IMPERSONATION.md, docs/phases/PHASE-3-CONTROL-PLANE.md).
--
-- This is the IdP-agnostic half of sessions/RBAC: Nullapart owns admin users,
-- role membership, effective permissions and server-side sessions here. The
-- external identity provider (when the owner records that decision) supplies
-- authentication only; it does not replace these tables.
--
-- Trust notes:
--   * admin_sessions stores only a SHA-256 hash of the opaque session cookie;
--     the plaintext token exists solely in the HttpOnly browser cookie.
--   * Row-level security binds every read/write to app.current_deployment_id
--     so a pooled connection that forgets the deployment filter reads zero
--     rows (fail closed), mirroring migration 009. Deployment isolation is
--     still applied in every application query as the primary control.
--   * Role grants/revokes and logins write audit_events rows in the same
--     transaction (application-enforced; audit_events RLS comes from 001/002/009).

CREATE TABLE admin_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    login TEXT NOT NULL,
    display_name TEXT NOT NULL,
    -- NULL marks a platform identity (System/Support); a value binds the
    -- user to one customer's Customer Admin scope.
    customer_id TEXT REFERENCES customers(id),
    lifecycle TEXT NOT NULL DEFAULT 'active'
        CHECK (lifecycle IN ('active', 'suspended')),
    -- Future identity-provider subject (mapping only, never authorization).
    auth_subject TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, login)
);

CREATE TABLE admin_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    role_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role_level TEXT NOT NULL CHECK (role_level IN ('system', 'support', 'customer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, role_key)
);

CREATE TABLE admin_role_permissions (
    role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE admin_user_roles (
    user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
    granted_by TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE admin_sessions (
    id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    source_ip TEXT,
    authenticated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    step_up_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT
);

CREATE INDEX idx_admin_users_deployment ON admin_users (deployment_id, lifecycle);
CREATE INDEX idx_admin_user_roles_role ON admin_user_roles (role_id);
CREATE INDEX idx_admin_sessions_user ON admin_sessions (user_id, revoked_at);
CREATE INDEX idx_admin_sessions_deployment ON admin_sessions (deployment_id);

ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY;

-- Missing deployment setting => current_setting(..., true) is NULL => the
-- predicate is NULL => zero rows (fail closed), never an error mid-query.
CREATE POLICY admin_users_deployment_isolation ON admin_users
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

CREATE POLICY admin_roles_deployment_isolation ON admin_roles
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

CREATE POLICY admin_role_permissions_deployment_isolation ON admin_role_permissions
    USING (
        EXISTS (
            SELECT 1 FROM admin_roles AS role
            WHERE role.id = admin_role_permissions.role_id
              AND role.deployment_id = current_setting('app.current_deployment_id', true)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM admin_roles AS role
            WHERE role.id = admin_role_permissions.role_id
              AND role.deployment_id = current_setting('app.current_deployment_id', true)
        )
    );

CREATE POLICY admin_user_roles_deployment_isolation ON admin_user_roles
    USING (
        EXISTS (
            SELECT 1 FROM admin_users AS admin_user
            WHERE admin_user.id = admin_user_roles.user_id
              AND admin_user.deployment_id = current_setting('app.current_deployment_id', true)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM admin_users AS admin_user
            WHERE admin_user.id = admin_user_roles.user_id
              AND admin_user.deployment_id = current_setting('app.current_deployment_id', true)
        )
    );

CREATE POLICY admin_sessions_deployment_isolation ON admin_sessions
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

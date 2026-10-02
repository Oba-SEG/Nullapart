-- 011_admin_impersonation.sql
--
-- Audited Customer Admin impersonation (docs/03-IDENTITY-RBAC-IMPERSONATION.md,
-- docs/phases/PHASE-3-CONTROL-PLANE.md): a Support/System actor may act as a
-- Customer Admin for a bounded, reasoned, explicitly ended interval.
--
-- Trust notes:
--   * One active impersonation per admin session (partial unique index), so a
--     session can never carry two competing acting-as contexts.
--   * Reason is mandatory at the database level as defense in depth; the
--     application enforces the same rule plus permission/step-up/rate limits.
--   * Rows are deployment-bound by row-level security like the other admin_*
--     tables (fail closed without app.current_deployment_id); application
--     queries also filter deployment_id as the primary control.
--   * Start/end write audit_events rows in the same transaction
--     (application-enforced), carrying both the real actor and the
--     impersonated subject/customer.

CREATE TABLE admin_impersonations (
    id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    session_id UUID NOT NULL REFERENCES admin_sessions(id) ON DELETE CASCADE,
    actor_user_id UUID NOT NULL REFERENCES admin_users(id),
    actor_login TEXT NOT NULL,
    subject_user_id UUID NOT NULL REFERENCES admin_users(id),
    subject_login TEXT NOT NULL,
    subject_customer_id TEXT NOT NULL REFERENCES customers(id),
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 10 AND 500),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    ended_reason TEXT
);

CREATE UNIQUE INDEX admin_impersonations_one_active_per_session
    ON admin_impersonations (session_id)
    WHERE ended_at IS NULL;
CREATE INDEX idx_admin_impersonations_deployment
    ON admin_impersonations (deployment_id, started_at);

ALTER TABLE admin_impersonations ENABLE ROW LEVEL SECURITY;

CREATE POLICY admin_impersonations_deployment_isolation ON admin_impersonations
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

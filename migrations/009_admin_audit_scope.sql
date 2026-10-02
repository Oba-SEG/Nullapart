-- 009_admin_audit_scope.sql
--
-- Administrative audit read scopes for the Phase 3 Admin Audit API
-- (docs/17-ADMIN-AUDIT-LOGGING.md, docs/29-TENANT-FEATURE-ROUTING.md).
--
-- The original policy only expressed one legitimate read:
--     customer_id = current_setting('app.current_customer_id')
-- Phase 3 needs three server-authorized scopes:
--
--   tenant   (default) rows of the current customer only;
--   platform          System Admin regional read of every row;
--   own               Support "own activity" read keyed on the actor.
--
-- Write authority stays narrow in every scope:
--   tenant scope may insert rows for its own customer;
--   platform/own scope may insert only platform rows (customer_id IS NULL),
--   so a read scope can never fabricate history for another tenant.
--
-- Scope is selected by the application after server-side authorization. As
-- with app.current_customer_id, PostgreSQL cannot authenticate a session that
-- sets these settings, so RLS remains defense in depth against a forgotten or
-- missing scope rather than a hostile session holding the application role;
-- application authorization is the primary control. Deployment isolation
-- stays in the application query (regional boundary), unchanged here.
--
-- The missing_ok form of current_setting makes an unscoped session match zero
-- rows (fail closed) instead of raising in the middle of a query.

DROP POLICY IF EXISTS audit_events_isolation ON audit_events;

CREATE POLICY audit_events_isolation ON audit_events
    USING (
        customer_id = current_setting('app.current_customer_id', true)
        OR current_setting('app.audit_scope', true) = 'platform'
        OR (
            current_setting('app.audit_scope', true) = 'own'
            AND actor_id = current_setting('app.current_actor_id', true)
        )
    )
    WITH CHECK (
        customer_id = current_setting('app.current_customer_id', true)
        OR (
            customer_id IS NULL
            AND current_setting('app.audit_scope', true) IN ('platform', 'own')
        )
    );

-- Admin Audit search reads are deployment-bounded and time-ordered first.
CREATE INDEX IF NOT EXISTS idx_audit_events_deployment_created
    ON audit_events (deployment_id, created_at DESC);

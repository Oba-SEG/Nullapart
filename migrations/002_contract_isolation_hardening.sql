-- Nullapart Database Migration 002
-- Contract alignment, tenant isolation hardening, delivery persistence.
--
-- This migration intentionally does not create application/platform roles because
-- role ownership and BYPASSRLS grants are deployment-specific. Normal request roles
-- must not own these tables and must not have BYPASSRLS.

ALTER TABLE smtp_transactions
    ADD COLUMN IF NOT EXISTS connection_id TEXT,
    ADD COLUMN IF NOT EXISTS trace_id TEXT,
    ADD COLUMN IF NOT EXISTS postfix_queue_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

CREATE INDEX IF NOT EXISTS idx_transactions_trace ON smtp_transactions(trace_id);

CREATE TABLE IF NOT EXISTS smtp_transaction_recipients (
    id BIGSERIAL PRIMARY KEY,
    transaction_id UUID NOT NULL REFERENCES smtp_transactions(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    orcpt TEXT,
    notify TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_transaction_recipients_tx
    ON smtp_transaction_recipients(transaction_id);

CREATE TABLE IF NOT EXISTS tenant_message_recipients (
    id BIGSERIAL PRIMARY KEY,
    tenant_message_id UUID NOT NULL REFERENCES tenant_message_instances(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    orcpt TEXT,
    notify TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tenant_message_recipients_message
    ON tenant_message_recipients(tenant_message_id);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    id UUID PRIMARY KEY,
    tenant_message_id UUID NOT NULL REFERENCES tenant_message_instances(id) ON DELETE CASCADE,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    scheduled_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'in_progress', 'success', 'transient_failure', 'permanent_failure', 'bounced')
    ),
    smtp_code INTEGER,
    enhanced_code TEXT,
    smtp_message TEXT,
    next_retry_at TIMESTAMPTZ,
    postfix_queue_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_message_id, attempt_number)
);

CREATE INDEX IF NOT EXISTS idx_delivery_attempts_message
    ON delivery_attempts(tenant_message_id);
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_retry
    ON delivery_attempts(next_retry_at)
    WHERE status = 'transient_failure' AND next_retry_at IS NOT NULL;

-- One domain may resolve to one customer in a regional deployment database.
-- This removes ambiguous recipient -> tenant ownership.
CREATE UNIQUE INDEX IF NOT EXISTS uq_domains_domain_global
    ON domains (lower(domain));

-- Replace permissive tenant policies. Rows with customer_id IS NULL are platform
-- scope and are NOT visible to ordinary tenant request roles.
DROP POLICY IF EXISTS tenant_messages_isolation ON tenant_message_instances;
DROP POLICY IF EXISTS audit_events_isolation ON audit_events;
DROP POLICY IF EXISTS artifacts_isolation ON artifacts;
DROP POLICY IF EXISTS domains_isolation ON domains;

ALTER TABLE tenant_message_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_message_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_messages_isolation ON tenant_message_instances
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_isolation ON audit_events
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY artifacts_isolation ON artifacts
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

ALTER TABLE domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE domains FORCE ROW LEVEL SECURITY;
CREATE POLICY domains_isolation ON domains
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

ALTER TABLE policy_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_revisions_isolation ON policy_revisions
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

ALTER TABLE config_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY config_revisions_tenant_isolation ON config_revisions
    USING (
        scope = 'tenant'
        AND scope_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        scope = 'tenant'
        AND scope_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE feature_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE feature_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY feature_overrides_tenant_isolation ON feature_overrides
    USING (
        scope = 'tenant'
        AND scope_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        scope = 'tenant'
        AND scope_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_events_tenant_isolation ON outbox_events
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

ALTER TABLE tenant_message_recipients ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_message_recipients FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_message_recipients_isolation ON tenant_message_recipients
    USING (
        EXISTS (
            SELECT 1
            FROM tenant_message_instances tmi
            WHERE tmi.id = tenant_message_recipients.tenant_message_id
              AND tmi.customer_id = current_setting('app.current_customer_id', true)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM tenant_message_instances tmi
            WHERE tmi.id = tenant_message_recipients.tenant_message_id
              AND tmi.customer_id = current_setting('app.current_customer_id', true)
        )
    );

ALTER TABLE delivery_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_attempts_isolation ON delivery_attempts
    USING (
        EXISTS (
            SELECT 1
            FROM tenant_message_instances tmi
            WHERE tmi.id = delivery_attempts.tenant_message_id
              AND tmi.customer_id = current_setting('app.current_customer_id', true)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM tenant_message_instances tmi
            WHERE tmi.id = delivery_attempts.tenant_message_id
              AND tmi.customer_id = current_setting('app.current_customer_id', true)
        )
    );

-- Prevent ordinary application code from rewriting or deleting audit evidence.
-- INSERT remains possible subject to RLS; platform maintenance uses a separate
-- explicitly privileged role and audited maintenance procedure.
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

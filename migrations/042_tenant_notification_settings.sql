-- 042_tenant_notification_settings.sql
--
-- Customer-admin notification controls and the delivery ledger for
-- docs/14-NOTIFICATIONS-REMEDIATION.md.
--
-- Before this file, `domain_security_notifications` rows were produced by the
-- domain observer and rendered in the console, but nothing delivered them:
-- there was no per-tenant setting, no worker and no record of what was sent.
-- These tables give the tenant a control surface and give the platform an
-- audit trail that is the source of truth for delivery.
--
-- Recipients are validated in the API against the tenant's own verified
-- domains, so Nullapart cannot be used to mail another tenant or an arbitrary
-- third party. The row-level policies below are defense in depth for the same
-- rule, not its enforcement.
--
-- The notifications permissions are not seeded here: `admin_role_permissions`
-- rows for builtin roles are reconciled from the compiled-in catalog on every
-- login, so a migration insert would be a second copy able to drift from it.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_notification_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    enabled BOOLEAN NOT NULL DEFAULT true,
    severity_floor TEXT NOT NULL DEFAULT 'warning'
        CHECK (severity_floor IN ('info', 'warning', 'critical')),
    recipient_emails TEXT[] NOT NULL DEFAULT '{}',
    -- Repeats of the same (notification_type, domain) inside this window are
    -- coalesced into one mail. Zero means every open finding is delivered.
    digest_window_minutes INTEGER NOT NULL DEFAULT 60
        CHECK (digest_window_minutes BETWEEN 0 AND 1440),
    updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 160),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT tenant_notification_settings_recipient_cap
        CHECK (cardinality(recipient_emails) <= 10),
    CONSTRAINT tenant_notification_settings_one_per_tenant
        UNIQUE (deployment_id, customer_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_notification_settings_deployment
    ON tenant_notification_settings (deployment_id, enabled);

CREATE TABLE IF NOT EXISTS notification_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    notification_id UUID NOT NULL
        REFERENCES domain_security_notifications(id) ON DELETE CASCADE,
    -- One delivery attempt record per produced notification, so a replayed
    -- claim can never send a second customer alert.
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) <= 200),
    status TEXT NOT NULL CHECK (status IN ('queued', 'sent', 'suppressed', 'dead_lettered')),
    recipient_count INTEGER NOT NULL DEFAULT 0 CHECK (recipient_count >= 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    reason TEXT CHECK (reason IS NULL OR length(reason) <= 512),
    -- sha256 of the exact MIME bytes the delivery worker composed for this
    -- notification. A retry that would mail different bytes (the tenant changed
    -- its recipients, or the finding text moved) cannot be deduplicated by the
    -- outbound submission ledger, so the worker dead-letters it instead of
    -- risking a duplicate or a mismatched alert.
    content_sha256 TEXT NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    -- Set only on a 'sent' row: the outbound_submission_ledger transaction this
    -- delivery maps to, so a mailed notice can be traced to its Postfix queue id.
    outbound_transaction_id TEXT CHECK (outbound_transaction_id IS NULL OR length(outbound_transaction_id) <= 160),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT notification_deliveries_idempotency_unique UNIQUE (idempotency_key),
    CONSTRAINT notification_deliveries_sent_has_reference
        CHECK (status <> 'sent' OR outbound_transaction_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_customer
    ON notification_deliveries (customer_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_digest_window
    ON notification_deliveries (deployment_id, customer_id, created_at DESC);

ALTER TABLE tenant_notification_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_notification_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_notification_settings_customer_isolation
    ON tenant_notification_settings
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_deliveries_customer_isolation
    ON notification_deliveries
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON tenant_notification_settings TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON notification_deliveries TO nullapart_mailcore;
    END IF;
END
$$;

-- Postflight: the shape this arc depends on must actually exist.
DO $$
BEGIN
    IF (SELECT count(*) FROM information_schema.tables
        WHERE table_name IN ('tenant_notification_settings', 'notification_deliveries')) <> 2 THEN
        RAISE EXCEPTION 'notification control tables were not created';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'tenant_notification_settings'
          AND policyname = 'tenant_notification_settings_customer_isolation'
    ) THEN
        RAISE EXCEPTION 'tenant_notification_settings must be row-level-security protected';
    END IF;
END
$$;

COMMIT;

-- 031_connectors_remediation.sql
-- Phase 8: explicitly scoped connector capabilities, directory-sync posture,
-- mailbox-search records and post-delivery remediation intent/outcome state.
--
-- Provider OAuth access/refresh tokens are deliberately not stored here. The
-- connector record keeps only a regional encrypted-secret reference hash and
-- safe capability/status metadata for Control Plane display and audit.

BEGIN;

CREATE TABLE connector_integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    provider TEXT NOT NULL CHECK (provider IN ('microsoft_365', 'google_workspace', 'imap_pop')),
    display_name TEXT NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 3 AND 160),
    external_tenant_id_hash TEXT NOT NULL CHECK (char_length(btrim(external_tenant_id_hash)) BETWEEN 16 AND 128),
    credential_reference_hash TEXT NOT NULL CHECK (char_length(btrim(credential_reference_hash)) BETWEEN 16 AND 128),
    status TEXT NOT NULL CHECK (status IN ('setup_required', 'active', 'degraded', 'disabled', 'revoked')),
    auth_state TEXT NOT NULL CHECK (auth_state IN ('not_configured', 'healthy', 'expiring', 'expired', 'revoked', 'provider_error')),
    token_expires_at TIMESTAMPTZ,
    last_directory_sync_at TIMESTAMPTZ,
    last_directory_sync_status TEXT CHECK (last_directory_sync_status IS NULL OR last_directory_sync_status IN ('pending', 'succeeded', 'failed', 'manual_action_required')),
    last_mailbox_search_at TIMESTAMPTZ,
    last_remediation_at TIMESTAMPTZ,
    created_by TEXT NOT NULL CHECK (btrim(created_by) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    revoke_reason TEXT,
    UNIQUE (deployment_id, customer_id, provider, external_tenant_id_hash),
    CHECK (
        (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revoke_reason IS NOT NULL)
        OR (status <> 'revoked' AND revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason IS NULL)
    )
);

CREATE INDEX idx_connector_integrations_customer
    ON connector_integrations (customer_id, status, updated_at DESC);

CREATE TABLE connector_capability_grants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id UUID NOT NULL REFERENCES connector_integrations(id) ON DELETE CASCADE,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    capability TEXT NOT NULL CHECK (capability IN ('directory_sync', 'mailbox_search', 'retro_remediation')),
    enabled BOOLEAN NOT NULL DEFAULT false,
    granted_scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    approved_by TEXT NOT NULL CHECK (btrim(approved_by) <> ''),
    reason TEXT NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 12 AND 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (connector_id, capability),
    CHECK (
        enabled = false
        OR array_length(granted_scopes, 1) >= 1
    )
);

CREATE INDEX idx_connector_capability_grants_customer
    ON connector_capability_grants (customer_id, capability, enabled);

CREATE TABLE connector_directory_sync_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id UUID NOT NULL REFERENCES connector_integrations(id) ON DELETE CASCADE,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    state TEXT NOT NULL CHECK (state IN ('pending', 'succeeded', 'failed', 'manual_action_required')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    users_seen INTEGER NOT NULL DEFAULT 0 CHECK (users_seen >= 0),
    groups_seen INTEGER NOT NULL DEFAULT 0 CHECK (groups_seen >= 0),
    aliases_seen INTEGER NOT NULL DEFAULT 0 CHECK (aliases_seen >= 0),
    vip_candidates INTEGER NOT NULL DEFAULT 0 CHECK (vip_candidates >= 0),
    error_code TEXT CHECK (error_code IS NULL OR char_length(error_code) <= 80),
    error_summary TEXT CHECK (error_summary IS NULL OR char_length(error_summary) <= 512),
    CHECK (
        (state IN ('succeeded', 'failed', 'manual_action_required') AND completed_at IS NOT NULL)
        OR (state = 'pending' AND completed_at IS NULL)
    )
);

CREATE INDEX idx_connector_directory_sync_runs_customer
    ON connector_directory_sync_runs (customer_id, started_at DESC);

CREATE TABLE connector_mailbox_searches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id UUID NOT NULL REFERENCES connector_integrations(id) ON DELETE CASCADE,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    tenant_message_id UUID REFERENCES tenant_message_instances(id),
    mailbox_address_hash TEXT NOT NULL CHECK (char_length(btrim(mailbox_address_hash)) BETWEEN 16 AND 128),
    provider_message_id_hash TEXT CHECK (provider_message_id_hash IS NULL OR char_length(provider_message_id_hash) BETWEEN 16 AND 128),
    purpose TEXT NOT NULL CHECK (purpose IN ('post_delivery_threat', 'customer_reported_phishing', 'false_negative_review', 'manual_security_case')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'succeeded', 'failed', 'manual_action_required')),
    match_confirmation TEXT NOT NULL CHECK (match_confirmation IN ('not_checked', 'matched', 'ambiguous', 'not_found')),
    error_code TEXT CHECK (error_code IS NULL OR char_length(error_code) <= 80),
    error_summary TEXT CHECK (error_summary IS NULL OR char_length(error_summary) <= 512),
    created_by TEXT NOT NULL CHECK (btrim(created_by) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_connector_mailbox_searches_customer
    ON connector_mailbox_searches (customer_id, created_at DESC);

CREATE TABLE connector_remediation_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id UUID NOT NULL REFERENCES connector_integrations(id) ON DELETE CASCADE,
    mailbox_search_id UUID REFERENCES connector_mailbox_searches(id),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    tenant_message_id UUID REFERENCES tenant_message_instances(id),
    action_type TEXT NOT NULL CHECK (action_type IN ('move_to_quarantine', 'move_to_junk', 'delete', 'manual_review')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'succeeded', 'failed', 'manual_action_required')),
    provider_outcome_code TEXT CHECK (provider_outcome_code IS NULL OR char_length(provider_outcome_code) <= 80),
    error_summary TEXT CHECK (error_summary IS NULL OR char_length(error_summary) <= 512),
    idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 8 AND 128),
    requested_by TEXT NOT NULL CHECK (btrim(requested_by) <> ''),
    reason TEXT NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 12 AND 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, customer_id, idempotency_key)
);

CREATE INDEX idx_connector_remediation_actions_customer
    ON connector_remediation_actions (customer_id, state, created_at DESC);

ALTER TABLE connector_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_integrations FORCE ROW LEVEL SECURITY;
CREATE POLICY connector_integrations_customer_isolation ON connector_integrations
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE connector_capability_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_capability_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY connector_capability_grants_customer_isolation ON connector_capability_grants
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE connector_directory_sync_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_directory_sync_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY connector_directory_sync_runs_customer_isolation ON connector_directory_sync_runs
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE connector_mailbox_searches ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_mailbox_searches FORCE ROW LEVEL SECURITY;
CREATE POLICY connector_mailbox_searches_customer_isolation ON connector_mailbox_searches
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE connector_remediation_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_remediation_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY connector_remediation_actions_customer_isolation ON connector_remediation_actions
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, permission.permission
FROM admin_roles AS role
CROSS JOIN (VALUES
    ('connectors:view'),
    ('connectors:manage')
) AS permission(permission)
WHERE role.role_key IN ('system_admin', 'support')
ON CONFLICT DO NOTHING;

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, 'connectors:view'
FROM admin_roles AS role
WHERE role.role_key = 'customer_admin'
ON CONFLICT DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON connector_integrations TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON connector_capability_grants TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON connector_directory_sync_runs TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON connector_mailbox_searches TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON connector_remediation_actions TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

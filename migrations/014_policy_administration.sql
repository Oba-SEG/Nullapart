-- Nullapart Database Migration 014
-- Phase 3 increment 6: policy family administration and feature overrides.
--
-- `policy_revisions` gains the family/scope columns the administration API
-- writes. Legacy rows keep `family_id IS NULL` and remain visible only to the
-- customer that owns them; the new API always selects a family, so those rows
-- are never returned by it.
--
-- The legacy `UNIQUE (customer_id, revision_number)` key cannot survive:
-- revision numbers are now allocated per family and scope, so two families
-- published by one customer would collide on the next publish. The partial
-- unique index replaces it with the invariant the publisher maintains — one
-- active revision per family and scope identity.
--
-- `feature_overrides` and `config_revisions` move from the tenant-only policy
-- of migration 002 to the three-level model of docs/29-TENANT-FEATURE-ROUTING.md:
-- system rows require a deployment scope, deployment rows are keyed to it and
-- tenant rows to the customer. A session that only established a customer
-- scope still cannot mint a system or deployment row, so a forgotten scope
-- fails closed rather than widening access.

BEGIN;

CREATE TABLE policy_families (
    family_key TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    management_level TEXT NOT NULL
        CHECK (management_level IN ('customer', 'support', 'system')),
    security_floor BOOLEAN NOT NULL DEFAULT false
);

INSERT INTO policy_families (family_key, description, management_level, security_floor) VALUES
    ('attachments', 'Attachment handling and file-type restrictions', 'customer', false),
    ('authentication', 'Sender authentication requirements for SPF, DKIM and DMARC', 'system', true),
    ('bulk_sending', 'Bulk and marketing sending limits', 'support', false),
    ('connection_security', 'Inbound and outbound connection security requirements', 'system', true),
    ('connectors_remediation', 'Connector and remediation integration behaviour', 'customer', false),
    ('content_security', 'Content filtering and unsafe content handling', 'system', true),
    ('dmarc_bimi', 'DMARC and BIMI alignment and reporting', 'system', true),
    ('geolocation', 'Sender and recipient geography rules', 'support', false),
    ('greylisting', 'Greylisting timing and retest behaviour', 'support', false),
    ('impersonation', 'Impersonation and look-alike sender protection', 'system', true),
    ('inbound_routing', 'Inbound recipient routing decisions', 'customer', false),
    ('malware', 'Malware scanning and disposition', 'system', true),
    ('ml_threat_classification', 'Machine-learning threat classification evidence', 'support', false),
    ('notifications', 'Administrative and recipient notification behaviour', 'support', false),
    ('outbound_abuse', 'Outbound abuse detection and sender suspension', 'support', false),
    ('outbound_routing', 'Outbound delivery routing decisions', 'customer', false),
    ('quarantine', 'Quarantine placement, retention and release', 'support', false),
    ('recipient_controls', 'Per-recipient policy controls', 'support', false),
    ('retention', 'Message and evidence retention windows', 'support', false),
    ('sender_reputation', 'Sender reputation and trust scoring', 'support', false),
    ('spam_filtering', 'Spam classification thresholds and disposition', 'support', false),
    ('transport_security', 'TLS transport security requirements', 'system', true),
    ('url_security', 'URL reputation and link protection', 'system', true),
    ('vip_protection', 'VIP sender and recipient protection', 'support', false);

ALTER TABLE policy_revisions
    ADD COLUMN deployment_id TEXT REFERENCES deployments(id),
    ADD COLUMN family_id TEXT REFERENCES policy_families(family_key),
    ADD COLUMN scope_level TEXT CHECK (scope_level IN ('system', 'tenant')),
    ALTER COLUMN revision_number DROP DEFAULT;

ALTER TABLE policy_revisions
    DROP CONSTRAINT IF EXISTS policy_revisions_customer_id_revision_number_key;

-- One active revision per family and scope identity: system rows are keyed by
-- their deployment, tenant rows by their customer. Legacy rows carry a NULL
-- family key and are excluded from conflicts by the default NULLS DISTINCT.
CREATE UNIQUE INDEX idx_policy_revisions_family_scope
    ON policy_revisions (family_id, scope_level, COALESCE(customer_id, deployment_id))
    WHERE deactivated_at IS NULL;

DROP POLICY IF EXISTS policy_revisions_isolation ON policy_revisions;

CREATE POLICY policy_revisions_isolation ON policy_revisions
    USING (
        (scope_level = 'system'
            AND deployment_id = current_setting('app.current_deployment_id', true))
        OR (scope_level = 'tenant'
            AND customer_id = current_setting('app.current_customer_id', true))
        OR (scope_level IS NULL
            AND customer_id = current_setting('app.current_customer_id', true))
    )
    WITH CHECK (
        (scope_level = 'system'
            AND deployment_id = current_setting('app.current_deployment_id', true))
        OR (scope_level = 'tenant'
            AND customer_id = current_setting('app.current_customer_id', true))
    );

DROP POLICY IF EXISTS feature_overrides_tenant_isolation ON feature_overrides;
DROP POLICY IF EXISTS feature_overrides_isolation ON feature_overrides;

CREATE POLICY feature_overrides_isolation ON feature_overrides
    USING (
        (scope = 'system'
            AND scope_id = 'system'
            AND COALESCE(current_setting('app.current_deployment_id', true), '') <> '')
        OR (scope = 'deployment'
            AND scope_id = current_setting('app.current_deployment_id', true))
        OR (scope = 'tenant'
            AND scope_id = current_setting('app.current_customer_id', true))
    )
    WITH CHECK (
        (scope = 'system'
            AND scope_id = 'system'
            AND COALESCE(current_setting('app.current_deployment_id', true), '') <> '')
        OR (scope = 'deployment'
            AND scope_id = current_setting('app.current_deployment_id', true))
        OR (scope = 'tenant'
            AND scope_id = current_setting('app.current_customer_id', true))
    );

DROP POLICY IF EXISTS config_revisions_tenant_isolation ON config_revisions;
DROP POLICY IF EXISTS config_revisions_isolation ON config_revisions;

CREATE POLICY config_revisions_isolation ON config_revisions
    USING (
        (scope = 'system'
            AND scope_id = 'system'
            AND COALESCE(current_setting('app.current_deployment_id', true), '') <> '')
        OR (scope = 'deployment'
            AND scope_id = current_setting('app.current_deployment_id', true))
        OR (scope = 'tenant'
            AND scope_id = current_setting('app.current_customer_id', true))
    )
    WITH CHECK (
        (scope = 'system'
            AND scope_id = 'system'
            AND COALESCE(current_setting('app.current_deployment_id', true), '') <> '')
        OR (scope = 'deployment'
            AND scope_id = current_setting('app.current_deployment_id', true))
        OR (scope = 'tenant'
            AND scope_id = current_setting('app.current_customer_id', true))
    );

-- Initial feature catalog (docs/26-API-VERSIONING-FEATURE-SWITCHES.md and
-- docs/27-API-VERSIONING-FEATURE-FLAGS.md name these classes: mandatory
-- security floors that a switch may never disable, operational kill switches
-- for risky scanners/connectors, and tenant capability/release switches).
-- `ON CONFLICT DO NOTHING` keeps an already-seeded deployment stable.
INSERT INTO feature_definitions
    (feature_id, description, default_value, mandatory, kill_switch, allowed_scopes)
VALUES
    ('tenant_authorization',
     'Server-authoritative tenant authorization boundary',
     'enabled', true, false, ARRAY['system']),
    ('admin_audit',
     'Administrative and security action audit recording',
     'enabled', true, false, ARRAY['system']),
    ('required_encryption',
     'Required encryption in transit and at rest',
     'enabled', true, false, ARRAY['system']),
    ('data_residency_enforcement',
     'Core data-residency routing restrictions',
     'enabled', true, false, ARRAY['system']),
    ('deep_ai_analysis',
     'Deep AI content analysis scanner',
     'enabled', false, true, ARRAY['system', 'deployment', 'tenant']),
    ('inline_ml_classification',
     'Inline ML threat classification scanner',
     'enabled', false, true, ARRAY['system', 'deployment', 'tenant']),
    ('outbound_remediation_connector',
     'Outbound remediation connector execution',
     'disabled', false, true, ARRAY['system', 'deployment']),
    ('remote_resource_preview',
     'Preview rendering of remote message resources',
     'disabled', false, false, ARRAY['system', 'deployment', 'tenant']),
    ('quarantine_digest_notifications',
     'Daily quarantine digest notifications',
     'enabled', false, false, ARRAY['system', 'deployment', 'tenant'])
ON CONFLICT (feature_id) DO NOTHING;

-- The restricted runtime role is granted by the local provisioning script,
-- which only runs when the volume is initialised. Granting the two tables this
-- increment creates or writes here keeps an already-provisioned deployment
-- able to run it; the guard keeps a fresh volume (role not created yet) from
-- failing init. `feature_overrides`/`config_revisions` write grants stay with
-- the provisioning script so this migration changes nothing else.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT ON policy_families, feature_definitions TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON policy_revisions TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

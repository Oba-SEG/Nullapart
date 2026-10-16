-- 039_catalog_display_names.sql
--
-- Human labels for the policy and feature catalogs
-- (docs/engineering/UX-TERMINOLOGY.md, rule 1).
--
-- Both catalogs publish only a machine key and a sentence today, so the console
-- renders `admin_audit`, `deep_ai_analysis` and `dmarc_bimi` as primary labels.
-- The labels belong on the server that owns the catalog, not in a frontend map
-- that drifts the moment a row is seeded: a UI-side dictionary would be a
-- second source of truth for what a control is called.
--
-- `display_name` is NOT NULL on purpose. A catalog row without a human label is
-- a build failure at seed time, not a silent fallback to the raw key in the UI.
-- The raw key stays in every response as secondary metadata, because it is what
-- appears in audit events and support evidence.
--
-- Idempotent (guarded ADD COLUMN, NULL-guarded UPDATE) so it can be re-applied
-- to an already-migrated database. Migrations only run at initdb locally, so a
-- long-lived volume needs this file applied manually.

BEGIN;

ALTER TABLE policy_families
    ADD COLUMN IF NOT EXISTS display_name TEXT;

UPDATE policy_families
SET display_name = CASE family_key
    WHEN 'attachments' THEN 'Attachment handling'
    WHEN 'authentication' THEN 'Sender authentication'
    WHEN 'bulk_sending' THEN 'Bulk sending limits'
    WHEN 'connection_security' THEN 'Connection security'
    WHEN 'connectors_remediation' THEN 'Connector remediation'
    WHEN 'content_security' THEN 'Content filtering'
    WHEN 'dmarc_bimi' THEN 'DMARC and BIMI'
    WHEN 'geolocation' THEN 'Geolocation rules'
    WHEN 'greylisting' THEN 'Greylisting'
    WHEN 'impersonation' THEN 'Impersonation protection'
    WHEN 'inbound_routing' THEN 'Inbound routing'
    WHEN 'malware' THEN 'Malware scanning'
    WHEN 'ml_threat_classification' THEN 'ML threat classification'
    WHEN 'notifications' THEN 'Notifications'
    WHEN 'outbound_abuse' THEN 'Outbound abuse detection'
    WHEN 'outbound_routing' THEN 'Outbound routing'
    WHEN 'quarantine' THEN 'Quarantine handling'
    WHEN 'recipient_controls' THEN 'Recipient controls'
    WHEN 'retention' THEN 'Retention windows'
    WHEN 'sender_reputation' THEN 'Sender reputation'
    WHEN 'spam_filtering' THEN 'Spam filtering'
    WHEN 'transport_security' THEN 'TLS transport security'
    WHEN 'url_security' THEN 'URL protection'
    WHEN 'vip_protection' THEN 'VIP protection'
    ELSE display_name
END
WHERE display_name IS NULL;

-- Fail loudly rather than let a family reach the console without a label.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM policy_families WHERE display_name IS NULL
    ) THEN
        RAISE EXCEPTION 'policy_families rows exist without a display_name';
    END IF;
END
$$;

ALTER TABLE policy_families
    ALTER COLUMN display_name SET NOT NULL;

ALTER TABLE feature_definitions
    ADD COLUMN IF NOT EXISTS display_name TEXT;

UPDATE feature_definitions
SET display_name = CASE feature_id
    WHEN 'tenant_authorization' THEN 'Customer authorization boundary'
    WHEN 'admin_audit' THEN 'Administrator action auditing'
    WHEN 'required_encryption' THEN 'Required encryption'
    WHEN 'data_residency_enforcement' THEN 'Data residency enforcement'
    WHEN 'deep_ai_analysis' THEN 'Deep AI message analysis'
    WHEN 'dmarc_failure_reports' THEN 'DMARC failure reports'
    WHEN 'inline_ml_classification' THEN 'Inline ML classification'
    WHEN 'outbound_remediation_connector' THEN 'Outbound remediation connector'
    WHEN 'remote_resource_preview' THEN 'Remote resource preview'
    WHEN 'quarantine_digest_notifications' THEN 'Daily quarantine digest'
    ELSE display_name
END
WHERE display_name IS NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM feature_definitions WHERE display_name IS NULL
    ) THEN
        RAISE EXCEPTION 'feature_definitions rows exist without a display_name';
    END IF;
END
$$;

ALTER TABLE feature_definitions
    ALTER COLUMN display_name SET NOT NULL;

COMMIT;

-- 026_dmarc_failure_report_controls.sql
-- Phase 5: failure-report privacy controls.
--
-- DMARC failure reports can carry headers/body samples. This migration creates
-- an explicit feature switch and a metadata-only quarantine ledger for any
-- failure report detected at the aggregate-report ingress boundary. The ledger
-- stores no report body, raw MIME, headers, XML or rendered content.

BEGIN;

INSERT INTO feature_definitions (
    feature_id,
    description,
    default_value,
    mandatory,
    kill_switch,
    allowed_scopes
) VALUES (
    'dmarc_failure_reports',
    'Opt-in DMARC failure-report handling; failure reports may contain restricted message/header content',
    'disabled',
    false,
    true,
    ARRAY['system', 'deployment', 'tenant']
) ON CONFLICT (feature_id) DO NOTHING;

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, 'domain-security:failure-report:view'
FROM admin_roles AS role
WHERE role.role_key = 'system_admin'
ON CONFLICT DO NOTHING;

CREATE TABLE dmarc_failure_report_quarantine (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    source_artifact_id UUID NOT NULL REFERENCES artifacts(id),
    artifact_hash TEXT NOT NULL CHECK (length(artifact_hash) <= 128),
    compressed_size_bytes BIGINT NOT NULL CHECK (compressed_size_bytes >= 0),
    reason_code TEXT NOT NULL CHECK (
        reason_code IN (
            'FAILURE_REPORT_FEATURE_DISABLED',
            'FAILURE_REPORT_HANDLER_UNAVAILABLE'
        )
    ),
    detail TEXT NOT NULL CHECK (length(detail) <= 512),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, source_artifact_id, reason_code)
);

CREATE INDEX idx_dmarc_failure_report_quarantine_customer
    ON dmarc_failure_report_quarantine (customer_id, detected_at DESC);

ALTER TABLE dmarc_failure_report_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE dmarc_failure_report_quarantine FORCE ROW LEVEL SECURITY;
CREATE POLICY dmarc_failure_report_quarantine_customer_isolation
    ON dmarc_failure_report_quarantine
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
        GRANT SELECT, INSERT ON dmarc_failure_report_quarantine TO nullapart_mailcore;
    END IF;
END $$;

COMMIT;

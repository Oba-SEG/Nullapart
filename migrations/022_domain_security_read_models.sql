-- 022_domain_security_read_models.sql
-- Phase 5 increment 2: actionable domain-security read models.
--
-- These tables hold normalized observer/reporting/BIMI/source-classification
-- state. They intentionally store DNS/report metadata and validation status
-- only; no raw XML, failure-report content, SVG bytes, or message samples are
-- stored here.

BEGIN;

CREATE TABLE domain_security_observations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID NOT NULL REFERENCES domains(id),
    check_type TEXT NOT NULL CHECK (
        check_type IN ('mx', 'spf', 'dkim', 'dmarc', 'report_authorization', 'bimi', 'mta_sts', 'tls_rpt')
    ),
    status TEXT NOT NULL CHECK (status IN ('pass', 'warning', 'fail', 'unknown')),
    observed_value TEXT,
    detail TEXT NOT NULL CHECK (length(detail) <= 512),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_domain_security_observations_latest
    ON domain_security_observations (domain_id, check_type, observed_at DESC);
CREATE INDEX idx_domain_security_observations_customer
    ON domain_security_observations (customer_id, observed_at DESC);

CREATE TABLE dmarc_report_authorizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID NOT NULL REFERENCES domains(id),
    report_host TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    expected_value TEXT NOT NULL DEFAULT 'v=DMARC1',
    actual_value TEXT,
    status TEXT NOT NULL CHECK (status IN ('valid', 'missing', 'invalid', 'unknown')),
    checked_at TIMESTAMPTZ,
    detail TEXT NOT NULL CHECK (length(detail) <= 512),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT dmarc_report_authorizations_unique_host UNIQUE (deployment_id, domain_id, report_host)
);

CREATE INDEX idx_dmarc_report_authorizations_customer
    ON dmarc_report_authorizations (customer_id, status, updated_at DESC);

CREATE TABLE bimi_domain_status (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID NOT NULL REFERENCES domains(id),
    selector TEXT NOT NULL DEFAULT 'default',
    record_value TEXT,
    logo_url TEXT,
    status TEXT NOT NULL CHECK (status IN ('ready', 'not_ready', 'invalid', 'unknown')),
    svg_status TEXT NOT NULL CHECK (svg_status IN ('valid', 'invalid', 'not_checked', 'unknown')),
    dmarc_enforcement_status TEXT NOT NULL CHECK (
        dmarc_enforcement_status IN ('enforced', 'not_enforced', 'unknown')
    ),
    certificate_status TEXT NOT NULL CHECK (
        certificate_status IN ('valid', 'missing', 'invalid', 'not_required', 'unknown')
    ),
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    checked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT bimi_domain_status_unique_selector UNIQUE (deployment_id, domain_id, selector)
);

CREATE INDEX idx_bimi_domain_status_customer
    ON bimi_domain_status (customer_id, status, updated_at DESC);

CREATE TABLE domain_source_classifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID NOT NULL REFERENCES domains(id),
    source_key TEXT NOT NULL,
    source_ip INET,
    source_domain TEXT,
    classification TEXT NOT NULL CHECK (
        classification IN ('authorized', 'expected_incomplete', 'unknown', 'suspicious', 'malicious', 'third_party')
    ),
    notes TEXT CHECK (notes IS NULL OR length(notes) <= 512),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT domain_source_classifications_unique_source UNIQUE (deployment_id, domain_id, source_key)
);

CREATE INDEX idx_domain_source_classifications_customer
    ON domain_source_classifications (customer_id, classification, updated_at DESC);

CREATE TABLE domain_security_notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID REFERENCES domains(id),
    notification_type TEXT NOT NULL CHECK (
        notification_type IN (
            'dmarc_failure_spike',
            'new_unknown_source',
            'known_source_alignment_loss',
            'dmarc_record_invalid',
            'report_authorization_broken',
            'dkim_selector_failure',
            'bimi_invalid',
            'mta_sts_degraded',
            'tls_rpt_degraded'
        )
    ),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    title TEXT NOT NULL CHECK (length(title) <= 160),
    detail TEXT NOT NULL CHECK (length(detail) <= 512),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_domain_security_notifications_customer
    ON domain_security_notifications (customer_id, status, severity, created_at DESC);

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, permission.permission
FROM admin_roles AS role
CROSS JOIN (VALUES
    ('domain-security:view'),
    ('domain-security:manage')
) AS permission(permission)
WHERE role.role_key IN ('system_admin', 'support')
ON CONFLICT DO NOTHING;

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, 'domain-security:view'
FROM admin_roles AS role
WHERE role.role_key = 'customer_admin'
ON CONFLICT DO NOTHING;

ALTER TABLE domain_security_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_security_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY domain_security_observations_customer_isolation ON domain_security_observations
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE dmarc_report_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE dmarc_report_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY dmarc_report_authorizations_customer_isolation ON dmarc_report_authorizations
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE bimi_domain_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE bimi_domain_status FORCE ROW LEVEL SECURITY;
CREATE POLICY bimi_domain_status_customer_isolation ON bimi_domain_status
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE domain_source_classifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_source_classifications FORCE ROW LEVEL SECURITY;
CREATE POLICY domain_source_classifications_customer_isolation ON domain_source_classifications
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE domain_security_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_security_notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY domain_security_notifications_customer_isolation ON domain_security_notifications
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
        GRANT SELECT, INSERT, UPDATE ON domain_security_observations TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON dmarc_report_authorizations TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON bimi_domain_status TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON domain_source_classifications TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON domain_security_notifications TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

-- 021_dmarc_aggregate_reports.sql
-- Phase 5 increment 1: regional DMARC aggregate report ingestion foundation.
--
-- This migration stores normalized aggregate-report metadata and rows only.
-- Raw XML/report bytes remain artifact-store content; malformed input is
-- represented by bounded quarantine metadata plus optional artifact/hash
-- references. Failure-report (ruf) content is intentionally out of scope.

BEGIN;

CREATE TABLE dmarc_aggregate_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID NOT NULL REFERENCES domains(id),
    policy_domain TEXT NOT NULL,
    reporter_org_name TEXT NOT NULL,
    report_id TEXT NOT NULL,
    date_range_begin TIMESTAMPTZ NOT NULL,
    date_range_end TIMESTAMPTZ NOT NULL,
    policy_adkim TEXT CHECK (policy_adkim IS NULL OR policy_adkim IN ('r', 's')),
    policy_aspf TEXT CHECK (policy_aspf IS NULL OR policy_aspf IN ('r', 's')),
    policy_p TEXT NOT NULL CHECK (policy_p IN ('none', 'quarantine', 'reject')),
    parser_version TEXT NOT NULL,
    duplicate_key TEXT NOT NULL CHECK (duplicate_key ~ '^[0-9a-f]{64}$'),
    source_artifact_id UUID REFERENCES artifacts(id),
    source_artifact_hash TEXT CHECK (source_artifact_hash IS NULL OR source_artifact_hash ~ '^[0-9a-f]{64}$'),
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT dmarc_aggregate_reports_unique_duplicate UNIQUE (deployment_id, duplicate_key)
);

CREATE INDEX idx_dmarc_aggregate_reports_customer_time
    ON dmarc_aggregate_reports (customer_id, date_range_begin DESC);
CREATE INDEX idx_dmarc_aggregate_reports_domain_time
    ON dmarc_aggregate_reports (domain_id, date_range_begin DESC);
CREATE INDEX idx_dmarc_aggregate_reports_deployment_time
    ON dmarc_aggregate_reports (deployment_id, date_range_begin DESC);

CREATE TABLE dmarc_aggregate_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID NOT NULL REFERENCES domains(id),
    report_id UUID NOT NULL REFERENCES dmarc_aggregate_reports(id) ON DELETE CASCADE,
    source_ip INET NOT NULL,
    message_count BIGINT NOT NULL CHECK (message_count > 0),
    header_from_domain TEXT NOT NULL,
    envelope_from_domain TEXT,
    disposition TEXT NOT NULL CHECK (disposition IN ('none', 'quarantine', 'reject')),
    dkim_aligned_result TEXT CHECK (dkim_aligned_result IS NULL OR dkim_aligned_result IN ('pass', 'fail')),
    spf_aligned_result TEXT CHECK (spf_aligned_result IS NULL OR spf_aligned_result IN ('pass', 'fail')),
    dkim_auth_results JSONB NOT NULL DEFAULT '[]'::jsonb,
    spf_auth_results JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_dmarc_aggregate_records_report
    ON dmarc_aggregate_records (report_id);
CREATE INDEX idx_dmarc_aggregate_records_customer_source
    ON dmarc_aggregate_records (customer_id, source_ip);
CREATE INDEX idx_dmarc_aggregate_records_domain_result
    ON dmarc_aggregate_records (domain_id, disposition, dkim_aligned_result, spf_aligned_result);

CREATE TABLE dmarc_report_quarantine (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    source_artifact_id UUID REFERENCES artifacts(id),
    source_artifact_hash TEXT CHECK (source_artifact_hash IS NULL OR source_artifact_hash ~ '^[0-9a-f]{64}$'),
    compressed_size_bytes BIGINT NOT NULL CHECK (compressed_size_bytes >= 0),
    error_code TEXT NOT NULL,
    error_detail TEXT NOT NULL CHECK (length(error_detail) <= 512),
    reporter_org_name TEXT,
    report_id TEXT,
    policy_domain TEXT,
    duplicate_key TEXT CHECK (duplicate_key IS NULL OR duplicate_key ~ '^[0-9a-f]{64}$'),
    parser_version TEXT NOT NULL,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_dmarc_report_quarantine_deployment_time
    ON dmarc_report_quarantine (deployment_id, quarantined_at DESC);
CREATE INDEX idx_dmarc_report_quarantine_domain
    ON dmarc_report_quarantine (deployment_id, lower(policy_domain));

CREATE OR REPLACE FUNCTION public.resolve_verified_report_domain(
    requested_policy_domain TEXT,
    requested_deployment_id TEXT
)
RETURNS TABLE(customer_id TEXT, domain_id UUID, domain TEXT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT c.id, d.id, lower(d.domain)
    FROM public.domains AS d
    JOIN public.customers AS c ON c.id = d.customer_id
    WHERE lower(d.domain) = lower(requested_policy_domain)
      AND d.verification_status = 'verified'
      AND c.deployment_id = requested_deployment_id
      AND c.lifecycle = 'active'
$$;

REVOKE ALL ON FUNCTION public.resolve_verified_report_domain(TEXT, TEXT) FROM PUBLIC;

ALTER TABLE dmarc_aggregate_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE dmarc_aggregate_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY dmarc_aggregate_reports_customer_isolation ON dmarc_aggregate_reports
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE dmarc_aggregate_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE dmarc_aggregate_records FORCE ROW LEVEL SECURITY;
CREATE POLICY dmarc_aggregate_records_customer_isolation ON dmarc_aggregate_records
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE dmarc_report_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE dmarc_report_quarantine FORCE ROW LEVEL SECURITY;
CREATE POLICY dmarc_report_quarantine_deployment_isolation ON dmarc_report_quarantine
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT ON dmarc_aggregate_reports TO nullapart_mailcore;
        GRANT SELECT, INSERT ON dmarc_aggregate_records TO nullapart_mailcore;
        GRANT SELECT, INSERT ON dmarc_report_quarantine TO nullapart_mailcore;
        GRANT EXECUTE ON FUNCTION public.resolve_verified_report_domain(TEXT, TEXT)
            TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

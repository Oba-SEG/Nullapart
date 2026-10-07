-- 023_dmarc_report_ingress_jobs.sql
-- Phase 5 increment 3: durable regional DMARC aggregate-report ingress jobs.
--
-- Raw report bytes remain in ArtifactStore. This queue records only the
-- artifact pointer, terminal worker state and bounded error metadata.

CREATE TABLE dmarc_report_ingress_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    source_customer_id TEXT NOT NULL REFERENCES customers(id),
    source_artifact_id UUID NOT NULL REFERENCES artifacts(id),
    idempotency_key TEXT NOT NULL CHECK (btrim(idempotency_key) <> '' AND length(idempotency_key) <= 256),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'processing', 'failed', 'succeeded', 'duplicate', 'quarantined', 'dead_lettered')
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    locked_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    report_row_id UUID REFERENCES dmarc_aggregate_reports(id),
    records_inserted BIGINT NOT NULL DEFAULT 0 CHECK (records_inserted >= 0),
    last_error_code TEXT,
    last_error_detail TEXT CHECK (last_error_detail IS NULL OR length(last_error_detail) <= 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, idempotency_key)
);

CREATE INDEX idx_dmarc_report_ingress_jobs_ready
    ON dmarc_report_ingress_jobs (deployment_id, created_at, id)
    WHERE status IN ('pending', 'failed');

CREATE INDEX idx_dmarc_report_ingress_jobs_artifact
    ON dmarc_report_ingress_jobs (deployment_id, source_artifact_id);

ALTER TABLE dmarc_report_ingress_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE dmarc_report_ingress_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY dmarc_report_ingress_jobs_deployment_isolation ON dmarc_report_ingress_jobs
    USING (deployment_id = current_setting('app.current_deployment_id'))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id'));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON dmarc_report_ingress_jobs TO nullapart_mailcore;
    END IF;
END $$;

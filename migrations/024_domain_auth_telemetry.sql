-- 024_domain_auth_telemetry.sql
-- Phase 5 increment 4: live authentication telemetry projection.
--
-- This table stores normalized, content-free SPF/DKIM/DMARC observations
-- derived from already-authenticated Mail Core handoff metadata. It does not
-- store message bodies, raw headers, Authentication-Results text, raw DNS
-- payloads, or failure-report content.

CREATE TABLE domain_auth_telemetry (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID NOT NULL REFERENCES domains(id),
    transaction_id UUID NOT NULL REFERENCES smtp_transactions(id) ON DELETE CASCADE,
    tenant_message_id UUID NOT NULL REFERENCES tenant_message_instances(id) ON DELETE CASCADE,
    source_ip INET NOT NULL,
    source_domain TEXT,
    envelope_from_domain TEXT,
    header_from_domain TEXT NOT NULL,
    spf_result TEXT CHECK (spf_result IS NULL OR length(spf_result) <= 64),
    dkim_result TEXT CHECK (dkim_result IS NULL OR length(dkim_result) <= 64),
    dmarc_result TEXT CHECK (dmarc_result IS NULL OR length(dmarc_result) <= 64),
    disposition TEXT NOT NULL CHECK (disposition IN ('allow', 'quarantine', 'reject', 'hold', 'defer')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT domain_auth_telemetry_unique_message_domain
        UNIQUE (deployment_id, tenant_message_id, domain_id)
);

CREATE INDEX idx_domain_auth_telemetry_domain_time
    ON domain_auth_telemetry (deployment_id, customer_id, domain_id, observed_at DESC);
CREATE INDEX idx_domain_auth_telemetry_source
    ON domain_auth_telemetry (customer_id, source_ip, observed_at DESC);

ALTER TABLE domain_auth_telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_auth_telemetry FORCE ROW LEVEL SECURITY;
CREATE POLICY domain_auth_telemetry_customer_isolation ON domain_auth_telemetry
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
        GRANT SELECT, INSERT, UPDATE ON domain_auth_telemetry TO nullapart_mailcore;
    END IF;
END $$;

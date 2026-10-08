-- 025_domain_source_classification_history.sql
-- Phase 5 increment 5: durable source-classification change history.
--
-- The current classification row is operational state. This history table is
-- append-only evidence for source-attribution decisions; it stores normalized
-- metadata only, never message content, raw headers, DNS payloads or samples.

CREATE TABLE domain_source_classification_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain_id UUID NOT NULL REFERENCES domains(id),
    source_key TEXT NOT NULL,
    previous_classification TEXT CHECK (
        previous_classification IS NULL OR previous_classification IN ('authorized', 'expected_incomplete', 'unknown', 'suspicious', 'malicious', 'third_party')
    ),
    new_classification TEXT NOT NULL CHECK (
        new_classification IN ('authorized', 'expected_incomplete', 'unknown', 'suspicious', 'malicious', 'third_party')
    ),
    previous_source_ip INET,
    new_source_ip INET,
    previous_source_domain TEXT,
    new_source_domain TEXT,
    previous_notes TEXT CHECK (previous_notes IS NULL OR length(previous_notes) <= 512),
    new_notes TEXT CHECK (new_notes IS NULL OR length(new_notes) <= 512),
    changed_by TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_domain_source_classification_history_source
    ON domain_source_classification_history (deployment_id, customer_id, domain_id, source_key, changed_at DESC);

ALTER TABLE domain_source_classification_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_source_classification_history FORCE ROW LEVEL SECURITY;
CREATE POLICY domain_source_classification_history_customer_isolation ON domain_source_classification_history
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

CREATE OR REPLACE FUNCTION prevent_domain_source_classification_history_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'domain_source_classification_history is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER domain_source_classification_history_no_update
BEFORE UPDATE OR DELETE ON domain_source_classification_history
FOR EACH ROW EXECUTE FUNCTION prevent_domain_source_classification_history_mutation();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT ON domain_source_classification_history TO nullapart_mailcore;
    END IF;
END $$;

-- Phase 2 normalized scanner evidence. Raw MIME stays in ArtifactStore.
CREATE TABLE scanner_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_message_id UUID NOT NULL REFERENCES tenant_message_instances(id),
    transaction_id UUID NOT NULL REFERENCES smtp_transactions(id),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    scanner_id TEXT NOT NULL,
    scanner_type TEXT NOT NULL,
    status TEXT NOT NULL,
    required BOOLEAN NOT NULL,
    duration_ms BIGINT,
    completed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX scanner_results_case_lookup
    ON scanner_results(customer_id, tenant_message_id, completed_at DESC);

CREATE TABLE security_findings (
    id UUID PRIMARY KEY,
    tenant_message_id UUID NOT NULL REFERENCES tenant_message_instances(id),
    transaction_id UUID NOT NULL REFERENCES smtp_transactions(id),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    scanner_type TEXT NOT NULL,
    scanner_status TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    details JSONB,
    false_positive BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX security_findings_case_lookup
    ON security_findings(customer_id, tenant_message_id, created_at DESC);

ALTER TABLE scanner_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE scanner_results FORCE ROW LEVEL SECURITY;
ALTER TABLE security_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_findings FORCE ROW LEVEL SECURITY;

CREATE POLICY scanner_results_tenant_isolation ON scanner_results
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));
CREATE POLICY security_findings_tenant_isolation ON security_findings
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

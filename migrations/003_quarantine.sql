-- Phase 2 quarantine state. Raw MIME remains in ArtifactStore; this schema
-- stores only scoped references and safe operational metadata.
CREATE TABLE quarantine_cases (
    tenant_message_id UUID PRIMARY KEY REFERENCES tenant_message_instances(id),
    transaction_id UUID NOT NULL REFERENCES smtp_transactions(id),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    reason_code TEXT NOT NULL,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at TIMESTAMPTZ,
    released_by UUID,
    release_reason TEXT,
    release_idempotency_key TEXT,
    CHECK ((released_at IS NULL) = (released_by IS NULL)),
    CHECK ((released_at IS NULL) = (release_reason IS NULL))
);

CREATE UNIQUE INDEX quarantine_release_idempotency_per_customer
    ON quarantine_cases(customer_id, release_idempotency_key)
    WHERE release_idempotency_key IS NOT NULL;

CREATE INDEX quarantine_cases_active_by_customer
    ON quarantine_cases(customer_id, quarantined_at DESC)
    WHERE released_at IS NULL;

ALTER TABLE quarantine_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE quarantine_cases FORCE ROW LEVEL SECURITY;

CREATE POLICY quarantine_cases_tenant_isolation ON quarantine_cases
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

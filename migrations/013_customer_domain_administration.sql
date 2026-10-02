-- Nullapart Database Migration 013
-- Phase 3 increment 5: customer/domain administration.
-- Lifecycle gains grace/terminated, domains gain type plus DNS verification
-- state, and source IP groups are added with tenant row-level security.

BEGIN;

UPDATE customers SET lifecycle = 'terminated' WHERE lifecycle = 'deprovisioned';

ALTER TABLE customers DROP CONSTRAINT IF EXISTS customers_lifecycle_check;
ALTER TABLE customers ADD CONSTRAINT customers_lifecycle_check
    CHECK (lifecycle IN ('active', 'grace', 'suspended', 'terminated'));

ALTER TABLE domains
    ADD COLUMN domain_type TEXT NOT NULL DEFAULT 'internal'
        CHECK (domain_type IN ('internal', 'send_only')),
    ADD COLUMN verification_token TEXT,
    ADD COLUMN verification_expires_at TIMESTAMPTZ,
    ADD COLUMN verification_attempts INTEGER NOT NULL DEFAULT 0;

CREATE TABLE source_ip_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    name TEXT NOT NULL,
    cidrs TEXT[] NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT source_ip_groups_customer_name_unique UNIQUE (customer_id, name)
);

CREATE INDEX idx_source_ip_groups_customer ON source_ip_groups (customer_id);

ALTER TABLE source_ip_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_ip_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY source_ip_groups_isolation ON source_ip_groups
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

-- The restricted runtime role is granted explicitly by the local provisioning
-- script, which only runs when the volume is initialised. Granting here as
-- well keeps already-provisioned deployments able to run this increment; the
-- guard keeps a fresh volume (role not created yet) from failing init.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON customers TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON domains TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON idempotency_keys TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE, DELETE ON source_ip_groups TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

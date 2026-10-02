-- Idempotent local-only tenant fixture for the real Postfix Phase 2 proof.
-- This file is mounted only by compose.local.yml; it is not a production seed.
INSERT INTO deployments (id, region, display_name)
VALUES ('LOCAL-TEST', 'local', 'Nullapart local development')
ON CONFLICT (id) DO NOTHING;

INSERT INTO customers (id, deployment_id, display_name)
VALUES ('local-customer', 'LOCAL-TEST', 'Local Phase 2 customer')
ON CONFLICT (id) DO NOTHING;

INSERT INTO domains (customer_id, domain, verification_status, verification_method, verified_at)
VALUES ('local-customer', 'phase2.test', 'verified', 'local-fixture', now())
ON CONFLICT (customer_id, domain) DO UPDATE
SET verification_status = 'verified', verified_at = EXCLUDED.verified_at;

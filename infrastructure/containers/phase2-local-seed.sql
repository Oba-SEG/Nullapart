-- Idempotent local-only tenant fixture for the real Postfix Phase 2 proof.
-- This file is mounted only by compose.local.yml; it is not a production seed.
-- Identity follows docs/02-REGIONS-TENANCY-NAMING.md: the local deployment is
-- the ZA region and the customer carries the operational `CZA-{sequence}`
-- identity with its structured region/sequence fields.
INSERT INTO deployments (id, region, display_name)
VALUES ('LOCAL-TEST', 'ZA', 'Nullapart local development')
ON CONFLICT (id) DO NOTHING;

INSERT INTO customers (id, deployment_id, display_name, region_code, sequence_no)
VALUES ('CZA-1', 'LOCAL-TEST', 'Local Phase 2 customer', 'ZA', 1)
ON CONFLICT (id) DO NOTHING;

INSERT INTO domains (customer_id, domain, verification_status, verification_method, verified_at)
VALUES ('CZA-1', 'phase2.test', 'verified', 'local-fixture', now())
ON CONFLICT (customer_id, domain) DO UPDATE
SET verification_status = 'verified', verified_at = EXCLUDED.verified_at;

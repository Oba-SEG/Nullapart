-- 027_domain_auth_telemetry_details.sql
-- Phase 5 completion: structured live authentication telemetry detail.
--
-- Migration 024 intentionally stored only coarse SPF/DKIM/DMARC result labels.
-- Phase 5's exit criteria also require source-alignment detail, DKIM selector
-- evidence and ARC status. These columns remain content-free normalized
-- metadata: no raw Authentication-Results header text, raw MIME, message body
-- or DNS payload is stored.

BEGIN;

ALTER TABLE domain_auth_telemetry
    ADD COLUMN IF NOT EXISTS spf_aligned_result TEXT
        CHECK (spf_aligned_result IS NULL OR length(spf_aligned_result) <= 64),
    ADD COLUMN IF NOT EXISTS dkim_aligned_result TEXT
        CHECK (dkim_aligned_result IS NULL OR length(dkim_aligned_result) <= 64),
    ADD COLUMN IF NOT EXISTS dkim_domain TEXT
        CHECK (dkim_domain IS NULL OR length(dkim_domain) <= 253),
    ADD COLUMN IF NOT EXISTS dkim_selector TEXT
        CHECK (dkim_selector IS NULL OR length(dkim_selector) <= 128),
    ADD COLUMN IF NOT EXISTS arc_result TEXT
        CHECK (arc_result IS NULL OR length(arc_result) <= 64);

COMMIT;

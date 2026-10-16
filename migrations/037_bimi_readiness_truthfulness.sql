-- 037_bimi_readiness_truthfulness.sql
--
-- A prior DNS observer labelled safe-shaped BIMI URLs as `ready` even though
-- it never fetched the SVG or certificate. Correct persisted metadata so the
-- API/UI cannot imply cryptographic BIMI validation that did not occur.

BEGIN;

UPDATE bimi_domain_status
SET status = 'not_ready',
    errors = CASE
        WHEN errors @> '["BIMI SVG profile has not been fetched and validated by an approved isolated validator."]'::jsonb
         AND errors @> '["BIMI VMC/CMC material has not been fetched and cryptographically validated."]'::jsonb
        THEN errors
        ELSE errors
            || '["BIMI SVG profile has not been fetched and validated by an approved isolated validator.","BIMI VMC/CMC material has not been fetched and cryptographically validated."]'::jsonb
    END,
    updated_at = now()
WHERE status = 'ready'
  AND svg_status = 'not_checked'
  AND certificate_status = 'unknown';

COMMIT;

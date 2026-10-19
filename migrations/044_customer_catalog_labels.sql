-- 044_customer_catalog_labels.sql
--
-- The wording a customer seat reads for a catalog row.
--
-- Migration 039 put one human label on each catalog row, which is the right
-- thing for the platform's own console and the wrong thing for a tenant's: a
-- customer is not told that a deep-AI scanner, an inline ML classifier or a
-- machine-learning model decides what happens to their mail. They are told what
-- the check does. The rename therefore belongs on the row the catalog owns, not
-- only in a frontend dictionary, because a name that reaches the network answer
-- is readable in the browser's own inspector even when the console never prints
-- it. `docs/engineering/UX-TERMINOLOGY.md` rule 1 is the same rule either way.
--
-- The new columns are nullable and the projection falls back to the shared
-- text. Most catalog rows already read as their outcome ("Malware scanning",
-- "Quarantine handling") and renaming them would be churn; only a row whose
-- name or prose describes the technique needs customer wording. An operator who
-- adds a catalog row without it therefore gets the shared text, never a blank or
-- a raw key.
--
-- `feature_id` and `family_key` stay in every response: they are what the write
-- path is addressed by and what audit records name. They are handles, not
-- labels, and the customer console does not print them.
--
-- Idempotent (guarded ADD COLUMN, NULL-guarded UPDATE) because migrations only
-- run at initdb locally, so a long-lived volume needs this file applied
-- manually.

BEGIN;

ALTER TABLE feature_definitions
    ADD COLUMN IF NOT EXISTS customer_facing_label TEXT;

UPDATE feature_definitions
SET customer_facing_label = CASE feature_id
    WHEN 'deep_ai_analysis' THEN 'Message content review'
    WHEN 'inline_ml_classification' THEN 'Threat checks on arrival'
    ELSE customer_facing_label
END
WHERE feature_id IN ('deep_ai_analysis', 'inline_ml_classification')
  AND customer_facing_label IS NULL;

ALTER TABLE policy_families
    ADD COLUMN IF NOT EXISTS customer_facing_label TEXT,
    ADD COLUMN IF NOT EXISTS customer_facing_description TEXT;

UPDATE policy_families
SET customer_facing_label = CASE family_key
    WHEN 'ml_threat_classification' THEN 'Automatic threat review'
    ELSE customer_facing_label
END
WHERE family_key = 'ml_threat_classification'
  AND customer_facing_label IS NULL;

UPDATE policy_families
SET customer_facing_description = CASE family_key
    WHEN 'connectors_remediation'
        THEN 'How connected mailboxes are checked and repaired'
    WHEN 'ml_threat_classification' THEN 'Automatic threat review evidence'
    ELSE customer_facing_description
END
WHERE family_key IN ('connectors_remediation', 'ml_threat_classification')
  AND customer_facing_description IS NULL;

-- Tripwire, not the rename list: every technique-naming row is renamed above by
-- hand, and this catches the next one seeded without a decision. A feature only
-- reaches a customer when its ladder allows a Customer scope, so its check is
-- scoped to those rows; the policy family list is published to every seat, so
-- its check covers all of them. `\y` is the word boundary in Postgres regex, so
-- `ml_threat_classification` cannot slip past on an inner match.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM feature_definitions
        WHERE allowed_scopes && ARRAY['tenant']
          AND coalesce(customer_facing_label, display_name) ~*
              '(deep ai|machine learning|machine-learning|\yml\y|model|classifier|inference|neural)'
    ) THEN
        RAISE EXCEPTION 'a tenant-reachable feature is still named for its machinery';
    END IF;
    IF EXISTS (
        SELECT 1 FROM policy_families
        WHERE coalesce(customer_facing_label, display_name) ~*
                  '(deep ai|machine learning|machine-learning|\yml\y|classifier|inference|neural)'
           OR coalesce(customer_facing_description, description) ~*
                  '(machine learning|machine-learning|\yml\y|classifier|inference|neural)'
    ) THEN
        RAISE EXCEPTION 'a policy family is still worded for its machinery';
    END IF;
END
$$;

COMMIT;

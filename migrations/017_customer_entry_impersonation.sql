-- 017_customer_entry_impersonation.sql
--
-- Customer entry redesign (docs/03-IDENTITY-RBAC-IMPERSONATION.md):
-- impersonation no longer "acts as" a subject user with intersected
-- permissions. Support/System actors enter a customer tenant; their own
-- roles, permissions, and identity are unchanged.
--
-- The subject identity columns therefore become optional: customer-entry
-- rows record NULL subject_user_id/subject_login and identify the entered
-- tenant solely through subject_customer_id. Legacy subject-based rows keep
-- their existing values for audit continuity.
--
-- Trust notes:
--   * Application start/insert writes NULL subject columns (defense in depth
--     matches the NOT NULL drop here).
--   * reason/start/end checks from 011 are unchanged; the one-active-row-per-
--     session partial unique index is unchanged.

ALTER TABLE admin_impersonations
    ALTER COLUMN subject_user_id DROP NOT NULL,
    ALTER COLUMN subject_login DROP NOT NULL;

-- 038_custom_admin_roles.sql
--
-- Custom administrative role definitions (docs/03-IDENTITY-RBAC-IMPERSONATION.md).
--
-- `admin_roles` rows were previously always builtin seeds from the static
-- BUILTIN_ROLES catalog. This migration marks those rows explicitly and lets
-- the Control Plane store reviewed custom roles (builtin = false) in the same
-- table, so `admin_role_permissions` and session resolution already work
-- unchanged for any deployment-seeded role.
--
-- The statements are idempotent (guarded ADD COLUMN, unconditional-value
-- UPDATE) so the file can be re-applied to an existing database: local
-- migrations only run at Postgres initdb, and operators may need to apply
-- this file manually to an already-initialized volume.
--
-- Row-level security, deployment isolation and the builtin-key collision
-- rules stay exactly as migration 010 established them; `builtin` is
-- metadata that the API uses to refuse editing or deleting a builtin role.

BEGIN;

ALTER TABLE admin_roles
    ADD COLUMN IF NOT EXISTS builtin BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE admin_roles
    ADD COLUMN IF NOT EXISTS description TEXT;

UPDATE admin_roles
SET builtin = true
WHERE role_key IN ('system_admin', 'support', 'customer_admin');

-- Role definition editing needs row-level privileges the builtin-only model
-- never required: the runtime role locks a role with SELECT ... FOR UPDATE
-- (which needs UPDATE), rewrites its display name/description (UPDATE) and
-- deletes a custom role (DELETE). Migration 010 granted no DML to the runtime
-- role at all, and the local provisioning script granted only SELECT/INSERT,
-- so the grants live here too; the guard keeps a fresh volume (role not
-- created yet) from failing init. Deployment isolation is unchanged: the
-- policies from 010 are FOR ALL, so they already cover UPDATE and DELETE.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON admin_roles TO nullapart_mailcore;
        GRANT SELECT, INSERT, DELETE ON admin_role_permissions TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

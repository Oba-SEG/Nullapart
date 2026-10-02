-- 016_audit_checkpoints.sql
--
-- Phase 3 administrative audit checkpoint metadata.
--
-- The full immutable archive/WORM path is an operations-hardening concern,
-- but Phase 3 needs a functional Control Plane status surface that can report
-- whether independent tamper-evidence checkpoints exist for the deployment.
-- Rows are append-only metadata about signed/hash checkpoint batches; ordinary
-- runtime roles can read them for the Admin Audit UI but cannot create,
-- update or delete checkpoint records.

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    checkpoint_sequence BIGINT NOT NULL CHECK (checkpoint_sequence > 0),
    covers_events_through TIMESTAMPTZ NOT NULL,
    event_count BIGINT NOT NULL CHECK (event_count >= 0),
    root_hash TEXT NOT NULL CHECK (root_hash ~ '^sha256:[0-9a-f]{64}$'),
    signer_key_id TEXT NOT NULL CHECK (length(signer_key_id) BETWEEN 3 AND 200),
    signature TEXT NOT NULL CHECK (length(signature) BETWEEN 16 AND 4096),
    archive_uri TEXT CHECK (archive_uri IS NULL OR length(archive_uri) <= 2048),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, checkpoint_sequence)
);

CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_deployment_created
    ON audit_checkpoints (deployment_id, created_at DESC);

ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_checkpoints_deployment_read ON audit_checkpoints;
CREATE POLICY audit_checkpoints_deployment_read ON audit_checkpoints
    FOR SELECT
    USING (deployment_id = current_setting('app.current_deployment_id', true));

-- No INSERT/UPDATE/DELETE policy is intentionally defined here. Checkpoint
-- writers use a separate least-privilege identity in later hardening work.
-- The guard keeps fresh-volume init working before the local runtime role is
-- created; the provisioning script is still the canonical grant source.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT ON audit_checkpoints TO nullapart_mailcore;
    END IF;
END
$$;

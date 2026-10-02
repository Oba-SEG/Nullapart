-- 019_inline_ml_models.sql
-- Phase 4 increment 4: inline ML model registry
-- (docs/phases/PHASE-4-INLINE-ML.md, "Model registry"; plan decision 6).
--
-- One audited, system-scoped table records every registered model artifact
-- with its provenance (training dataset version, code commit, metrics,
-- artifact digest), its approval state, and its rollout state:
--
-- - registration is evidence only: a registered model changes nothing until
--   it is approved and activated;
-- - approval and activation are separate transitions; activation requires
--   the approved state (enforced below and in the admin API);
-- - exactly one model per deployment is active at a time (partial unique
--   index), and every activation records the model it replaced
--   (rollback_model_id/version), so rollback is an audited re-activation
--   rather than a schema or data migration;
-- - deployment-region tracking, rollout time (activated_at) and the
--   rollback target are columns per the phase document's tracking list.
--
-- The deployment isolation policy makes the table system-scoped: a session
-- that never establishes the deployment scope observes zero rows (fail
-- closed), and the table owner is covered too (FORCE).

BEGIN;

CREATE TABLE inline_ml_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    model_id TEXT NOT NULL,
    model_version TEXT NOT NULL,
    input_schema_version INTEGER NOT NULL CHECK (input_schema_version > 0),
    training_dataset_version TEXT NOT NULL
        CHECK (btrim(training_dataset_version) <> ''),
    code_commit TEXT NOT NULL CHECK (code_commit ~ '^[0-9a-f]{7,40}$'),
    metrics JSONB NOT NULL CHECK (jsonb_typeof(metrics) = 'object'),
    artifact_uri TEXT NOT NULL CHECK (btrim(artifact_uri) <> ''),
    artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    deployment_regions TEXT[] NOT NULL DEFAULT ARRAY['local']
        CHECK (array_length(deployment_regions, 1) >= 1),
    approval_state TEXT NOT NULL
        CHECK (approval_state IN ('pending', 'approved', 'rejected')),
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    approval_note TEXT,
    activated_at TIMESTAMPTZ,
    activated_by TEXT,
    deactivated_at TIMESTAMPTZ,
    deactivated_by TEXT,
    deactivation_reason TEXT,
    rollback_model_id TEXT,
    rollback_model_version TEXT,
    registered_by TEXT NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT inline_ml_models_unique_version
        UNIQUE (deployment_id, model_id, model_version),
    -- Approved rows always carry their approver; pending and rejected rows
    -- never do, and a rejection always carries its reason.
    CONSTRAINT inline_ml_models_approval_fields CHECK (
        (approval_state = 'approved'
            AND approved_by IS NOT NULL AND approved_at IS NOT NULL)
        OR (approval_state = 'pending'
            AND approved_by IS NULL AND approved_at IS NULL)
        OR (approval_state = 'rejected'
            AND approved_by IS NULL AND approved_at IS NULL
            AND approval_note IS NOT NULL)
    ),
    CONSTRAINT inline_ml_models_activation_fields CHECK (
        (activated_at IS NULL AND activated_by IS NULL)
        OR (activated_at IS NOT NULL AND activated_by IS NOT NULL)
    ),
    -- A model can only have been activated while approved; approval is a
    -- one-way transition, so this invariant cannot be violated later.
    CONSTRAINT inline_ml_models_activation_requires_approval
        CHECK (activated_at IS NULL OR approval_state = 'approved'),
    CONSTRAINT inline_ml_models_deactivation_fields CHECK (
        (deactivated_at IS NULL
            AND deactivated_by IS NULL AND deactivation_reason IS NULL)
        OR (deactivated_at IS NOT NULL
            AND deactivated_by IS NOT NULL AND deactivation_reason IS NOT NULL)
    ),
    CONSTRAINT inline_ml_models_deactivation_reason CHECK (
        deactivation_reason IS NULL
        OR deactivation_reason IN ('superseded', 'rollback')
    ),
    CONSTRAINT inline_ml_models_rollback_fields CHECK (
        (rollback_model_id IS NULL AND rollback_model_version IS NULL)
        OR (rollback_model_id IS NOT NULL AND rollback_model_version IS NOT NULL)
    )
);

-- One active model per deployment: activation deactivates the previous
-- row first, and this index makes a concurrent double-activation fail at
-- the database instead of racing past the API lock.
CREATE UNIQUE INDEX inline_ml_models_one_active_per_deployment
    ON inline_ml_models (deployment_id)
    WHERE activated_at IS NOT NULL AND deactivated_at IS NULL;

CREATE INDEX idx_inline_ml_models_deployment
    ON inline_ml_models (deployment_id, model_id, model_version);

ALTER TABLE inline_ml_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE inline_ml_models FORCE ROW LEVEL SECURITY;

-- Missing deployment setting => current_setting(..., true) is NULL =>
-- the predicate is NULL => zero rows and zero writable rows (fail closed).
CREATE POLICY inline_ml_models_deployment_isolation ON inline_ml_models
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

-- The restricted runtime role is granted by the local provisioning script,
-- which only runs when the volume is initialised. Granting the table this
-- migration creates keeps an already-provisioned deployment able to run it;
-- the guard keeps a fresh volume (role not created yet) from failing init.
-- The provisioning script remains the canonical grant source.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON inline_ml_models TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

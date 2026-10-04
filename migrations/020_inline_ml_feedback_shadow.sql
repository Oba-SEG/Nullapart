-- 020_inline_ml_feedback_shadow.sql
-- Phase 4 increments 6-7: candidate feedback records and shadow
-- evaluation/version-comparison evidence.
--
-- Feedback candidates are deliberately not training data. They are scoped,
-- auditable curation inputs only; no table/function here promotes a candidate
-- into a dataset or live model.

BEGIN;

CREATE TABLE ml_feedback_candidates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    tenant_message_id UUID REFERENCES tenant_message_instances(id) ON DELETE SET NULL,
    transaction_id UUID REFERENCES smtp_transactions(id) ON DELETE SET NULL,
    source TEXT NOT NULL CHECK (source IN (
        'quarantine_release',
        'user_report',
        'admin_adjudication'
    )),
    proposed_label TEXT NOT NULL CHECK (
        proposed_label IN (
            'malware',
            'phishing',
            'spam',
            'spoofing',
            'business_email_compromise',
            'credential_harvest',
            'malicious_url',
            'malicious_attachment',
            'suspicious_content',
            'policy_violation',
            'auth_failure',
            'reputation',
            'unknown',
            'false_positive'
        )
    ),
    curator_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (curator_state IN ('pending', 'accepted', 'rejected')),
    actor_login TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (btrim(reason) <> '' AND length(reason) <= 500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    curated_by TEXT,
    curated_at TIMESTAMPTZ,
    curation_note TEXT,
    CONSTRAINT ml_feedback_candidates_curation_fields CHECK (
        (curator_state = 'pending'
            AND curated_by IS NULL
            AND curated_at IS NULL
            AND curation_note IS NULL)
        OR (curator_state IN ('accepted', 'rejected')
            AND curated_by IS NOT NULL
            AND curated_at IS NOT NULL
            AND curation_note IS NOT NULL
            AND btrim(curation_note) <> '')
    )
);

CREATE INDEX idx_ml_feedback_candidates_scope
    ON ml_feedback_candidates(deployment_id, customer_id, created_at DESC);

CREATE INDEX idx_ml_feedback_candidates_pending
    ON ml_feedback_candidates(deployment_id, created_at DESC)
    WHERE curator_state = 'pending';

CREATE UNIQUE INDEX idx_ml_feedback_candidates_unique_tenant_source
    ON ml_feedback_candidates(deployment_id, tenant_message_id, source)
    WHERE tenant_message_id IS NOT NULL;

ALTER TABLE ml_feedback_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE ml_feedback_candidates FORCE ROW LEVEL SECURITY;

CREATE POLICY ml_feedback_candidates_scope ON ml_feedback_candidates
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

CREATE TABLE inline_ml_shadow_evaluations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    candidate_model_id TEXT NOT NULL,
    candidate_model_version TEXT NOT NULL,
    active_model_id TEXT,
    active_model_version TEXT,
    input_schema_version INTEGER NOT NULL CHECK (input_schema_version > 0),
    evaluation_set_id TEXT NOT NULL CHECK (btrim(evaluation_set_id) <> ''),
    metrics JSONB NOT NULL CHECK (jsonb_typeof(metrics) = 'object'),
    comparison JSONB NOT NULL CHECK (jsonb_typeof(comparison) = 'object'),
    result TEXT NOT NULL CHECK (result IN (
        'candidate_better',
        'candidate_worse',
        'inconclusive',
        'rollback_rehearsed'
    )),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_inline_ml_shadow_evaluations_model
    ON inline_ml_shadow_evaluations(
        deployment_id,
        candidate_model_id,
        candidate_model_version,
        created_at DESC
    );

ALTER TABLE inline_ml_shadow_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE inline_ml_shadow_evaluations FORCE ROW LEVEL SECURITY;

CREATE POLICY inline_ml_shadow_evaluations_deployment ON inline_ml_shadow_evaluations
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON ml_feedback_candidates TO nullapart_mailcore;
        GRANT SELECT, INSERT ON inline_ml_shadow_evaluations TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

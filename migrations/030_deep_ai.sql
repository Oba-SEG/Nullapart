-- 030_deep_ai.sql
-- Phase 7: regional Deep AI registry, scoped artifact grants, structured
-- analysis outputs, regional capacity evidence and training-governance records.
--
-- These tables deliberately do not store prompts, raw message bodies, raw MIME
-- or attachment contents. Deep-AI artifact access is grant based and
-- tenant/deployment scoped; ordinary mail delivery is not coupled to these
-- records.

BEGIN;

CREATE TABLE deep_ai_skills (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    skill_id TEXT NOT NULL CHECK (skill_id ~ '^security\.[a-z0-9_]+(\.[a-z0-9_]+)*$'),
    skill_version TEXT NOT NULL CHECK (skill_version ~ '^v[0-9]+$'),
    owner TEXT NOT NULL CHECK (btrim(owner) <> ''),
    purpose TEXT NOT NULL CHECK (char_length(btrim(purpose)) BETWEEN 12 AND 500),
    allowed_data_classes TEXT[] NOT NULL CHECK (array_length(allowed_data_classes, 1) >= 1),
    allowed_tools TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    max_input_tokens INTEGER NOT NULL CHECK (max_input_tokens BETWEEN 256 AND 262144),
    max_output_tokens INTEGER NOT NULL CHECK (max_output_tokens BETWEEN 64 AND 16384),
    max_artifacts INTEGER NOT NULL CHECK (max_artifacts BETWEEN 0 AND 50),
    timeout_ms INTEGER NOT NULL CHECK (timeout_ms BETWEEN 1000 AND 600000),
    concurrency_limit INTEGER NOT NULL CHECK (concurrency_limit BETWEEN 1 AND 128),
    model_requirement TEXT NOT NULL CHECK (btrim(model_requirement) <> ''),
    prompt_template_version TEXT NOT NULL CHECK (btrim(prompt_template_version) <> ''),
    input_schema_version TEXT NOT NULL CHECK (btrim(input_schema_version) <> ''),
    output_schema_version TEXT NOT NULL CHECK (btrim(output_schema_version) <> ''),
    evaluation_suite_version TEXT NOT NULL CHECK (btrim(evaluation_suite_version) <> ''),
    release_state TEXT NOT NULL
        CHECK (release_state IN ('draft', 'approved', 'released', 'rolled_back', 'disabled')),
    rollback_skill_version TEXT,
    created_by TEXT NOT NULL CHECK (btrim(created_by) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, skill_id, skill_version),
    CHECK (
        (release_state = 'rolled_back' AND rollback_skill_version IS NOT NULL)
        OR (release_state <> 'rolled_back')
    )
);

CREATE INDEX idx_deep_ai_skills_deployment
    ON deep_ai_skills (deployment_id, skill_id, skill_version);

CREATE TABLE deep_ai_model_releases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    region TEXT NOT NULL CHECK (btrim(region) <> ''),
    model_release TEXT NOT NULL CHECK (btrim(model_release) <> ''),
    backend TEXT NOT NULL CHECK (backend IN ('vllm', 'ollama', 'openai_compatible', 'mock')),
    serving_base_url TEXT NOT NULL CHECK (btrim(serving_base_url) <> ''),
    serving_contract TEXT NOT NULL DEFAULT 'openai_compatible'
        CHECK (serving_contract = 'openai_compatible'),
    quantization TEXT NOT NULL CHECK (btrim(quantization) <> ''),
    context_window INTEGER NOT NULL CHECK (context_window BETWEEN 1024 AND 262144),
    approval_state TEXT NOT NULL CHECK (approval_state IN ('pending', 'approved', 'rejected')),
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    rollback_to_model_release TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, region, model_release),
    CHECK (
        (approval_state = 'approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL)
        OR (approval_state <> 'approved' AND approved_by IS NULL AND approved_at IS NULL)
    )
);

CREATE TABLE deep_ai_regional_benchmarks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    region TEXT NOT NULL CHECK (btrim(region) <> ''),
    model_release TEXT NOT NULL CHECK (btrim(model_release) <> ''),
    accelerator_family TEXT NOT NULL CHECK (btrim(accelerator_family) <> ''),
    quantization TEXT NOT NULL CHECK (btrim(quantization) <> ''),
    vram_gb NUMERIC(8,2) NOT NULL CHECK (vram_gb > 0),
    gpu_count INTEGER NOT NULL CHECK (gpu_count >= 0),
    topology TEXT NOT NULL CHECK (btrim(topology) <> ''),
    model_load_seconds NUMERIC(10,2) NOT NULL CHECK (model_load_seconds >= 0),
    tokens_per_second NUMERIC(10,2) NOT NULL CHECK (tokens_per_second >= 0),
    concurrent_requests INTEGER NOT NULL CHECK (concurrent_requests >= 1),
    context_target_tokens INTEGER NOT NULL CHECK (context_target_tokens >= 1024),
    multimodal_supported BOOLEAN NOT NULL,
    availability_notes TEXT NOT NULL CHECK (btrim(availability_notes) <> ''),
    failover_notes TEXT NOT NULL CHECK (btrim(failover_notes) <> ''),
    cost_per_case_estimate NUMERIC(12,6) NOT NULL CHECK (cost_per_case_estimate >= 0),
    approved BOOLEAN NOT NULL DEFAULT false,
    approval_note TEXT NOT NULL CHECK (char_length(btrim(approval_note)) BETWEEN 12 AND 1000),
    measured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL CHECK (btrim(created_by) <> '')
);

CREATE INDEX idx_deep_ai_regional_benchmarks_deployment
    ON deep_ai_regional_benchmarks (deployment_id, region, model_release, measured_at DESC);

CREATE TABLE deep_ai_training_datasets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    dataset_version TEXT NOT NULL CHECK (btrim(dataset_version) <> ''),
    region TEXT NOT NULL CHECK (btrim(region) <> ''),
    allowed_data_classes TEXT[] NOT NULL CHECK (array_length(allowed_data_classes, 1) >= 1),
    provenance TEXT NOT NULL CHECK (char_length(btrim(provenance)) BETWEEN 12 AND 1000),
    labeling_process TEXT NOT NULL CHECK (char_length(btrim(labeling_process)) BETWEEN 12 AND 1000),
    approval_state TEXT NOT NULL CHECK (approval_state IN ('draft', 'approved', 'rejected', 'withdrawn')),
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    deletion_withdrawal_process TEXT NOT NULL
        CHECK (char_length(btrim(deletion_withdrawal_process)) BETWEEN 12 AND 1000),
    evaluation_split_protected BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, dataset_version),
    CHECK (
        (approval_state = 'approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL)
        OR (approval_state <> 'approved' AND approved_by IS NULL AND approved_at IS NULL)
    )
);

CREATE TABLE deep_ai_artifact_access_grants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    tenant_message_id UUID REFERENCES tenant_message_instances(id),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    resource_type TEXT NOT NULL CHECK (resource_type IN (
        'quarantine_case',
        'blocked_message',
        'reported_phishing',
        'confirmed_threat',
        'false_positive_review',
        'false_negative_review',
        'held_for_deep_analysis'
    )),
    purpose TEXT NOT NULL CHECK (purpose IN (
        'security_analysis',
        'bec_analysis',
        'impersonation_analysis',
        'case_summary',
        'campaign_correlation',
        'false_positive_review',
        'false_negative_review'
    )),
    skill_id TEXT NOT NULL,
    skill_version TEXT NOT NULL,
    artifact_type TEXT NOT NULL CHECK (artifact_type IN ('message_rfc822', 'headers', 'text_extract', 'attachment_extract', 'scanner_metadata')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL CHECK (btrim(created_by) <> ''),
    trace_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    revoke_reason TEXT,
    CHECK (expires_at > created_at),
    CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revoke_reason IS NOT NULL)
    ),
    FOREIGN KEY (deployment_id, skill_id, skill_version)
        REFERENCES deep_ai_skills(deployment_id, skill_id, skill_version)
);

CREATE INDEX idx_deep_ai_grants_customer
    ON deep_ai_artifact_access_grants (customer_id, created_at DESC);
CREATE INDEX idx_deep_ai_grants_artifact
    ON deep_ai_artifact_access_grants (artifact_id, expires_at);

CREATE TABLE deep_ai_analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    skill_id TEXT NOT NULL,
    skill_version TEXT NOT NULL,
    model_release TEXT NOT NULL CHECK (btrim(model_release) <> ''),
    artifact_grant_id UUID NOT NULL REFERENCES deep_ai_artifact_access_grants(id),
    classification TEXT NOT NULL CHECK (classification IN ('clean', 'suspicious', 'malicious', 'unknown', 'error')),
    attack_type TEXT NOT NULL CHECK (attack_type IN ('none', 'phishing', 'bec', 'impersonation', 'malware', 'spam', 'scam', 'unknown')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')),
    confidence NUMERIC(5,4) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    impersonated_entity TEXT,
    evidence_references JSONB NOT NULL CHECK (jsonb_typeof(evidence_references) = 'array'),
    observations JSONB NOT NULL CHECK (jsonb_typeof(observations) = 'array'),
    recommended_action TEXT NOT NULL CHECK (recommended_action IN ('deliver', 'hold', 'quarantine', 'block', 'escalate', 'release', 'unknown')),
    analyst_summary TEXT NOT NULL CHECK (char_length(btrim(analyst_summary)) BETWEEN 12 AND 4000),
    processing_duration_ms BIGINT NOT NULL CHECK (processing_duration_ms >= 0),
    validation_state TEXT NOT NULL CHECK (validation_state IN ('valid', 'schema_invalid', 'hallucinated_evidence', 'tool_denied', 'model_unavailable')),
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (deployment_id, skill_id, skill_version)
        REFERENCES deep_ai_skills(deployment_id, skill_id, skill_version),
    CHECK (
        (validation_state = 'valid' AND error_code IS NULL)
        OR (validation_state <> 'valid')
    )
);

CREATE INDEX idx_deep_ai_results_customer
    ON deep_ai_analysis_results (customer_id, created_at DESC);
CREATE INDEX idx_deep_ai_results_grant
    ON deep_ai_analysis_results (artifact_grant_id);

ALTER TABLE deep_ai_skills ENABLE ROW LEVEL SECURITY;
ALTER TABLE deep_ai_skills FORCE ROW LEVEL SECURITY;
CREATE POLICY deep_ai_skills_deployment_isolation ON deep_ai_skills
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

ALTER TABLE deep_ai_model_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE deep_ai_model_releases FORCE ROW LEVEL SECURITY;
CREATE POLICY deep_ai_model_releases_deployment_isolation ON deep_ai_model_releases
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

ALTER TABLE deep_ai_regional_benchmarks ENABLE ROW LEVEL SECURITY;
ALTER TABLE deep_ai_regional_benchmarks FORCE ROW LEVEL SECURITY;
CREATE POLICY deep_ai_benchmarks_deployment_isolation ON deep_ai_regional_benchmarks
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

ALTER TABLE deep_ai_training_datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE deep_ai_training_datasets FORCE ROW LEVEL SECURITY;
CREATE POLICY deep_ai_training_datasets_deployment_isolation ON deep_ai_training_datasets
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

ALTER TABLE deep_ai_artifact_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE deep_ai_artifact_access_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY deep_ai_artifact_grants_customer_isolation ON deep_ai_artifact_access_grants
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE deep_ai_analysis_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE deep_ai_analysis_results FORCE ROW LEVEL SECURITY;
CREATE POLICY deep_ai_results_customer_isolation ON deep_ai_analysis_results
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

INSERT INTO deep_ai_skills (
    deployment_id,
    skill_id,
    skill_version,
    owner,
    purpose,
    allowed_data_classes,
    allowed_tools,
    max_input_tokens,
    max_output_tokens,
    max_artifacts,
    timeout_ms,
    concurrency_limit,
    model_requirement,
    prompt_template_version,
    input_schema_version,
    output_schema_version,
    evaluation_suite_version,
    release_state,
    created_by
)
SELECT deployment.id, skill.skill_id, 'v1', 'security-platform',
       skill.purpose,
       ARRAY['quarantined','blocked','reported_phishing','confirmed_threat','false_positive_negative_review','held_for_deep_analysis'],
       skill.allowed_tools,
       32768, 2048, 8, 120000, 4,
       'OpenAI-compatible regional Deep AI backend',
       'prompt-v1', 'input-v1', 'output-v1', 'eval-v1',
       'released', 'migration-030'
FROM deployments AS deployment
CROSS JOIN (VALUES
    ('security.message.deep_analysis', 'Analyze an eligible security message and return structured Deep AI findings.', ARRAY['artifact.retrieve','scanner.findings','auth.findings']::TEXT[]),
    ('security.bec_analysis', 'Assess business-email-compromise indicators using authorized evidence only.', ARRAY['artifact.retrieve','scanner.findings','customer.vip_context']::TEXT[]),
    ('security.impersonation_analysis', 'Assess executive, brand, domain and person impersonation evidence.', ARRAY['artifact.retrieve','auth.findings','customer.vip_context']::TEXT[]),
    ('security.case_summary', 'Summarize already-authorized case evidence for analyst review.', ARRAY['scanner.findings','case.history']::TEXT[]),
    ('security.campaign_correlation', 'Correlate authorized security evidence into campaign-level relationships.', ARRAY['case.history','threat_intel.query']::TEXT[]),
    ('security.false_positive_review', 'Assist authorized analysts reviewing a possible false positive release.', ARRAY['artifact.retrieve','scanner.findings','case.history']::TEXT[]),
    ('security.false_negative_review', 'Assist authorized analysts reviewing a confirmed missed threat.', ARRAY['artifact.retrieve','scanner.findings','case.history']::TEXT[])
) AS skill(skill_id, purpose, allowed_tools)
ON CONFLICT DO NOTHING;

INSERT INTO deep_ai_model_releases (
    deployment_id,
    region,
    model_release,
    backend,
    serving_base_url,
    quantization,
    context_window,
    approval_state,
    approved_by,
    approved_at
)
SELECT id,
       region,
       'local-qwen3.5-9b-phase7',
       'ollama',
       'http://127.0.0.1:11434/v1',
       'q4_local_dev',
       32768,
       'approved',
       'migration-030',
       now()
FROM deployments
ON CONFLICT DO NOTHING;

INSERT INTO deep_ai_regional_benchmarks (
    deployment_id,
    region,
    model_release,
    accelerator_family,
    quantization,
    vram_gb,
    gpu_count,
    topology,
    model_load_seconds,
    tokens_per_second,
    concurrent_requests,
    context_target_tokens,
    multimodal_supported,
    availability_notes,
    failover_notes,
    cost_per_case_estimate,
    approved,
    approval_note,
    created_by
)
SELECT id,
       region,
       'local-qwen3.5-9b-phase7',
       'local-dev-cpu-or-apple-gpu',
       'q4_local_dev',
       8,
       0,
       'local development single-node benchmark placeholder',
       0,
       1,
       1,
       32768,
       false,
       'Local development target approved for Phase 7 wiring only; production ZA benchmark remains separate.',
       'Normal mail path is independent and continues when Deep AI is unavailable.',
       0,
       true,
       'Approved only for local/dev Phase 7 verification; not production capacity approval.',
       'migration-030'
FROM deployments
ON CONFLICT DO NOTHING;

INSERT INTO deep_ai_training_datasets (
    deployment_id,
    dataset_version,
    region,
    allowed_data_classes,
    provenance,
    labeling_process,
    approval_state,
    approved_by,
    approved_at,
    deletion_withdrawal_process,
    evaluation_split_protected
)
SELECT id,
       'phase7-governance-v1',
       region,
       ARRAY['quarantined','blocked','reported_phishing','confirmed_threat','false_positive_negative_review','outbound_abuse'],
       'Governance record only; operational access does not automatically grant training permission.',
       'Analyst-curated labels with train, validation and test split separation before model release.',
       'approved',
       'migration-030',
       now(),
       'Withdrawn customer data must be removed from future datasets and adapter releases by dataset version.',
       true
FROM deployments
ON CONFLICT DO NOTHING;

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, permission.permission
FROM admin_roles AS role
CROSS JOIN (VALUES
    ('deep-ai:view'),
    ('deep-ai:manage')
) AS permission(permission)
WHERE role.role_key IN ('system_admin', 'support')
ON CONFLICT DO NOTHING;

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, 'deep-ai:view'
FROM admin_roles AS role
WHERE role.role_key = 'customer_admin'
ON CONFLICT DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON deep_ai_skills TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON deep_ai_model_releases TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON deep_ai_regional_benchmarks TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON deep_ai_training_datasets TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON deep_ai_artifact_access_grants TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON deep_ai_analysis_results TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

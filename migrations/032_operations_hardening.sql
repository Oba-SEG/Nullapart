-- 032_operations_hardening.sql
--
-- Phase 9 local/dev operations-hardening foundation: Tier-3 capability
-- records, burn-rate alert definitions and production-readiness evidence
-- register. These records are deployment-scoped operational evidence, not a
-- customer data surface and not a certification claim.

BEGIN;

CREATE TABLE operations_tier3_capabilities (
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    capability_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    owner TEXT NOT NULL,
    sli TEXT NOT NULL,
    slo_target TEXT NOT NULL,
    error_budget TEXT NOT NULL,
    measurement_source TEXT NOT NULL,
    rto_minutes INTEGER NOT NULL CHECK (rto_minutes >= 0),
    rpo_minutes INTEGER NOT NULL CHECK (rpo_minutes >= 0),
    dependency_map TEXT NOT NULL,
    redundancy_design TEXT NOT NULL,
    degraded_mode TEXT NOT NULL,
    capacity_threshold TEXT NOT NULL,
    runbook TEXT NOT NULL,
    readiness_state TEXT NOT NULL CHECK (readiness_state IN ('defined', 'instrumented', 'alerting_active', 'tested', 'not_ready')),
    last_exercise_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, capability_id)
);

CREATE INDEX idx_operations_tier3_capabilities_deployment
    ON operations_tier3_capabilities (deployment_id, readiness_state, capability_id);

CREATE TABLE operations_alert_rules (
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    alert_key TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('ticket', 'page')),
    burn_rate NUMERIC(6, 2) NOT NULL CHECK (burn_rate > 0),
    long_window_minutes INTEGER NOT NULL CHECK (long_window_minutes > 0),
    short_window_minutes INTEGER NOT NULL CHECK (short_window_minutes > 0),
    threshold_description TEXT NOT NULL,
    owner TEXT NOT NULL,
    runbook TEXT NOT NULL,
    suppression TEXT NOT NULL,
    escalation TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT false,
    last_tested_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, alert_key),
    FOREIGN KEY (deployment_id, capability_id)
        REFERENCES operations_tier3_capabilities(deployment_id, capability_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_operations_alert_rules_deployment
    ON operations_alert_rules (deployment_id, enabled, severity, capability_id);

CREATE TABLE operations_readiness_checks (
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    check_id TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ready', 'partial', 'not_ready', 'blocked')),
    owner TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    runbook TEXT,
    last_verified_at TIMESTAMPTZ,
    notes TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, check_id)
);

CREATE INDEX idx_operations_readiness_checks_deployment
    ON operations_readiness_checks (deployment_id, status, category);

INSERT INTO operations_tier3_capabilities (
    deployment_id, capability_id, display_name, owner, sli, slo_target,
    error_budget, measurement_source, rto_minutes, rpo_minutes, dependency_map,
    redundancy_design, degraded_mode, capacity_threshold, runbook, readiness_state
)
SELECT deployments.id,
       seed.capability_id,
       seed.display_name,
       seed.owner,
       seed.sli,
       seed.slo_target,
       seed.error_budget,
       seed.measurement_source,
       seed.rto_minutes,
       seed.rpo_minutes,
       seed.dependency_map,
       seed.redundancy_design,
       seed.degraded_mode,
       seed.capacity_threshold,
       seed.runbook,
       seed.readiness_state
FROM deployments
CROSS JOIN (
    VALUES
    ('inbound_smtp_acceptance', 'Inbound SMTP acceptance', 'mail-operations',
     'Eligible SMTP sessions receive a correct accept/defer/reject response.',
     '99.95% monthly design target', '0.05% monthly',
     'Postfix transaction telemetry and Mail Core handoff results',
     30, 5,
     'MX node, Postfix queue, Mail Core handoff, PostgreSQL, policy/config runtime',
     'Multiple commissioned MX nodes before production; local/dev records design only.',
     'Temporary defer before unsafe spool or scanner overload.',
     'Queue depth and oldest age before disk/spool exhaustion.',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'defined'),
    ('accepted_message_durability', 'Accepted-message durability', 'mail-operations',
     'Messages accepted with 250 are durably retained or explicitly recoverable.',
     '99.9999% monthly design target', '0.0001% monthly',
     'SMTP transaction, artifact and tenant-message persistence records',
     15, 1,
     'PostgreSQL, artifact store, transactional outbox, backup/restore path',
     'Managed PostgreSQL and durable artifact store before production.',
     'Fail closed before 250 when durable responsibility cannot be established.',
     'Database/artifact write latency and failure budget.',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'defined'),
    ('mail_processing', 'Mail processing', 'mail-operations',
     'Accepted tenant instances reach a valid terminal or queued state within policy latency target.',
     '99.9% monthly design target', '0.1% monthly',
     'Tenant message state, scanner outcomes and outbox/retry telemetry',
     60, 5,
     'Mail Core, scanner fabric, policy runtime, PostgreSQL, SQS/outbox',
     'Redundant Mail Core workers and durable queues before production.',
     'Hold/defer when required security processing is unavailable.',
     'Scanner backlog, queue age and required-result success rate.',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'defined'),
    ('required_scanner_path', 'Required scanner path', 'security-operations',
     'Required scans produce valid results or explicit policy-safe handling.',
     '99.9% monthly design target', '0.1% monthly',
     'Scanner operation status, UNKNOWN/ERROR counts and required-coverage decisions',
     60, 5,
     'Scanner fabric, required adapters, artifact store, OCR/native dependencies',
     'Per-scanner bounded concurrency and redundant workers before production.',
     'Hold/quarantine instead of treating unknown scanner failures as clean.',
     'UNKNOWN/ERROR rate, scanner backlog and health deadline budget.',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'defined'),
    ('control_backend', 'Control backend', 'platform-operations',
     'Eligible administrative/security requests complete successfully without unsafe data exposure.',
     '99.9% monthly design target', '0.1% monthly',
     'Control Plane API status, latency and safe-error telemetry',
     60, 15,
     'Mail Core control routes, PostgreSQL, identity, audit, frontend proxy',
     'Redundant application tasks behind ALB before production.',
     'Read-only degraded mode where safe; high-risk mutations fail closed.',
     'API p95/p99 latency, error rate and DB pool saturation.',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'defined'),
    ('administrative_authentication', 'Administrative authentication', 'identity-operations',
     'Eligible login/session operations succeed and preserve server-side authorization.',
     '99.9% monthly design target', '0.1% monthly',
     'Admin session/OIDC/proxy identity telemetry and audit records',
     60, 15,
     'Identity provider, admin sessions, PostgreSQL, browser proxy',
     'Provider HA and break-glass process before production.',
     'Existing sessions continue until expiry; high-risk actions require step-up.',
     'Login failure rate, session resolution failure and IdP health.',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'defined'),
    ('audit_persistence', 'Audit persistence for required mutations', 'security-operations',
     'High-risk mutations commit durable audit records or fail closed.',
     '100% by design', '0 accepted unaudited high-risk mutations',
     'Audit event persistence and checkpoint metadata',
     30, 1,
     'PostgreSQL audit_events, checkpoint/archive path, transactional mutations',
     'Durable database, checkpoint archive and recovery path before production.',
     'Mutation fails closed if audit cannot persist.',
     'Audit insert failures, checkpoint staleness and archive lag.',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'instrumented'),
    ('transactional_outbox', 'Transactional outbox and required async workflows', 'platform-operations',
     'Required outbox/SQS workflows drain within age/backlog budget without duplicate side effects.',
     '99.9% monthly design target', '0.1% monthly',
     'Outbox unpublished count, oldest age and DLQ/dead-letter records',
     120, 15,
     'PostgreSQL outbox, SQS, idempotent workers, notification/remediation consumers',
     'Durable queue plus idempotent horizontally scalable workers before production.',
     'Non-critical n8n/ClickUp workflows degrade without blocking mail delivery.',
     'Oldest unpublished age, DLQ count and idempotency conflict rate.',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'instrumented')
) AS seed(
    capability_id, display_name, owner, sli, slo_target, error_budget,
    measurement_source, rto_minutes, rpo_minutes, dependency_map,
    redundancy_design, degraded_mode, capacity_threshold, runbook, readiness_state
)
ON CONFLICT (deployment_id, capability_id) DO NOTHING;

INSERT INTO operations_alert_rules (
    deployment_id, alert_key, capability_id, severity, burn_rate,
    long_window_minutes, short_window_minutes, threshold_description, owner,
    runbook, suppression, escalation, enabled
)
SELECT deployment_id,
       capability_id || ':fast-burn',
       capability_id,
       'page',
       14.40,
       60,
       5,
       'Page when both 1h and 5m windows burn error budget at 14.4x.',
       owner,
       runbook,
       'Suppress only during an approved maintenance window with owner acknowledgement.',
       'Primary on-call, then security/platform lead.',
       false
FROM operations_tier3_capabilities
ON CONFLICT (deployment_id, alert_key) DO NOTHING;

INSERT INTO operations_alert_rules (
    deployment_id, alert_key, capability_id, severity, burn_rate,
    long_window_minutes, short_window_minutes, threshold_description, owner,
    runbook, suppression, escalation, enabled
)
SELECT deployment_id,
       capability_id || ':sustained-burn',
       capability_id,
       'page',
       6.00,
       360,
       30,
       'Page when both 6h and 30m windows burn error budget at 6x.',
       owner,
       runbook,
       'Suppress only during an approved maintenance window with owner acknowledgement.',
       'Primary on-call, then security/platform lead.',
       false
FROM operations_tier3_capabilities
ON CONFLICT (deployment_id, alert_key) DO NOTHING;

INSERT INTO operations_alert_rules (
    deployment_id, alert_key, capability_id, severity, burn_rate,
    long_window_minutes, short_window_minutes, threshold_description, owner,
    runbook, suppression, escalation, enabled
)
SELECT deployment_id,
       capability_id || ':slow-burn-ticket',
       capability_id,
       'ticket',
       1.00,
       4320,
       360,
       'Create maintenance ticket for long-duration budget exhaustion around 1x burn.',
       owner,
       runbook,
       'Deduplicate by deployment, capability and rolling multi-day window.',
       'Capability owner backlog, escalated in weekly reliability review.',
       false
FROM operations_tier3_capabilities
ON CONFLICT (deployment_id, alert_key) DO NOTHING;

INSERT INTO operations_readiness_checks (
    deployment_id, check_id, category, title, status, owner, evidence_ref,
    runbook, notes
)
SELECT deployments.id,
       seed.check_id,
       seed.category,
       seed.title,
       seed.status,
       seed.owner,
       seed.evidence_ref,
       seed.runbook,
       seed.notes
FROM deployments
CROSS JOIN (
    VALUES
    ('phase_minus_1_current', 'security_program', 'Phase -1 security program accepted/current',
     'ready', 'security-operations', 'docs/compliance/18-PHASE--1-ACCEPTANCE.md',
     'docs/security/README.md',
     'Local evidence document exists; production sign-off remains deployment-specific.'),
    ('branch_protection_ready', 'source_ci', 'Protected source workflow and no direct main pushes',
     'partial', 'platform-operations', 'docs/security/19-VERSION-CONTROL-CICD.md',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'Policy is documented; live repository protection evidence must be attached before production.'),
    ('ci_security_gates', 'source_ci', 'Required CI/security gates active',
     'partial', 'platform-operations', 'docs/28-GITHUB-ACTIONS-ARCHITECTURE.md',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'Local gates pass; production CI evidence and scans must be attached.'),
    ('tier3_slo_alerts', 'reliability', 'Tier-3 SLO/error-budget/burn-rate alerting active',
     'partial', 'platform-operations', 'docs/compliance/08-TIER3-SLO-EVIDENCE.md',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'Rules are defined here but not marked enabled/tested until monitoring is live.'),
    ('audit_checkpoint', 'audit_monitoring', 'Admin Audit immutable checkpoint evidence',
     'partial', 'security-operations', 'migrations/016_audit_checkpoints.sql',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'Checkpoint metadata exists; production archive/WORM evidence remains required.'),
    ('zero_day_exercise', 'zero_day', 'Zero-day parser/dependency exercise completed',
     'not_ready', 'security-operations', 'docs/compliance/15-ZERO-DAY-TABLETOP-TEMPLATE.md',
     'docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md',
     'Exercise evidence is required before production readiness.'),
    ('restore_exercise', 'backup_dr', 'Restore/DR exercises completed',
     'not_ready', 'platform-operations', 'docs/compliance/06-PRODUCTION-READINESS-EVIDENCE.md',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'PostgreSQL, artifact, identity, audit and mail-queue restore exercises are not recorded.'),
    ('network_firewall_validation', 'network', 'Firewall/port registry verified against deployed reality',
     'partial', 'platform-operations', 'docs/24-CONTAINER-LOADBALANCING-NETWORK.md',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'Local/dev remote verifier checks service reachability; production SG/ALB/WAF evidence required.'),
    ('support_diagnostics_content_boundary', 'support_operations', 'Support diagnostics avoid message-content overreach',
     'ready', 'security-operations', 'SECURITY.md',
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md',
     'Existing Control Plane projections expose operational metadata and preserve content boundaries.')
) AS seed(check_id, category, title, status, owner, evidence_ref, runbook, notes)
ON CONFLICT (deployment_id, check_id) DO NOTHING;

ALTER TABLE operations_tier3_capabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE operations_tier3_capabilities FORCE ROW LEVEL SECURITY;
CREATE POLICY operations_tier3_capabilities_deployment_isolation
    ON operations_tier3_capabilities
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

ALTER TABLE operations_alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE operations_alert_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY operations_alert_rules_deployment_isolation
    ON operations_alert_rules
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

ALTER TABLE operations_readiness_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE operations_readiness_checks FORCE ROW LEVEL SECURITY;
CREATE POLICY operations_readiness_checks_deployment_isolation
    ON operations_readiness_checks
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON operations_tier3_capabilities TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON operations_alert_rules TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON operations_readiness_checks TO nullapart_mailcore;
    END IF;
END $$;

COMMIT;

-- 033_operations_automation_categories.sql
--
-- Phase 9 durable automation category register. This records the
-- n8n/ClickUp/customer-notification/reporting event classes that may be driven
-- from the durable outbox path. Rows are metadata-only and deliberately
-- deployment-scoped so automation can be audited without exposing message body
-- content or making mail delivery depend on workflow tools.

BEGIN;

CREATE TABLE operations_automation_categories (
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    category_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    destination TEXT NOT NULL CHECK (destination IN ('clickup', 'n8n', 'customer_notification', 'reporting')),
    severity TEXT NOT NULL CHECK (severity IN ('ticket', 'page', 'notify')),
    owner TEXT NOT NULL,
    minimized_metadata TEXT NOT NULL,
    deduplication_key TEXT NOT NULL,
    aggregation_window_minutes INTEGER NOT NULL CHECK (aggregation_window_minutes > 0),
    delivery_mode TEXT NOT NULL CHECK (delivery_mode IN ('outbox_sqs_worker', 'manual_review')),
    blocks_mail_delivery BOOLEAN NOT NULL DEFAULT false,
    runbook TEXT NOT NULL,
    readiness_state TEXT NOT NULL CHECK (readiness_state IN ('defined', 'wired', 'tested', 'ready', 'not_ready')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, category_id)
);

CREATE INDEX idx_operations_automation_categories_deployment
    ON operations_automation_categories (deployment_id, destination, readiness_state, category_id);

INSERT INTO operations_automation_categories (
    deployment_id, category_id, display_name, destination, severity, owner,
    minimized_metadata, deduplication_key, aggregation_window_minutes,
    delivery_mode, blocks_mail_delivery, runbook, readiness_state
)
SELECT deployments.id,
       seed.category_id,
       seed.display_name,
       seed.destination,
       seed.severity,
       seed.owner,
       seed.minimized_metadata,
       seed.deduplication_key,
       seed.aggregation_window_minutes,
       seed.delivery_mode,
       seed.blocks_mail_delivery,
       seed.runbook,
       seed.readiness_state
FROM deployments
CROSS JOIN (
    VALUES
    ('critical_threat_incident', 'Critical threat incident', 'clickup', 'page',
     'security-operations',
     'deployment, customer scope, threat class, policy disposition, bounded evidence ids, timestamps',
     'deployment:customer:threat_class:rolling_1h', 60,
     'outbox_sqs_worker', false,
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md', 'defined'),
    ('customer_outage', 'Customer outage', 'clickup', 'page',
     'platform-operations',
     'deployment, customer scope, affected capability, SLO window, runbook, safe diagnostic links',
     'deployment:customer:capability:rolling_30m', 30,
     'outbox_sqs_worker', false,
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md', 'defined'),
    ('outbound_outbreak', 'Outbound outbreak', 'clickup', 'page',
     'security-operations',
     'deployment, customer scope, source classification, aggregate recipient/domain counts, policy action',
     'deployment:customer:source_classification:rolling_1h', 60,
     'outbox_sqs_worker', false,
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md', 'defined'),
    ('remediation_failure', 'Remediation failure', 'n8n', 'ticket',
     'platform-operations',
     'deployment, connector kind, hashed mailbox/source ids, remediation intent, failure class',
     'deployment:connector_kind:failure_class:rolling_6h', 360,
     'outbox_sqs_worker', false,
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md', 'defined'),
    ('dmarc_degradation', 'DMARC degradation', 'reporting', 'ticket',
     'mail-operations',
     'deployment, customer scope, domain, aggregate result trend, policy alignment class',
     'deployment:customer:domain:dmarc_class:rolling_24h', 1440,
     'outbox_sqs_worker', false,
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md', 'defined'),
    ('scanner_system_failure', 'Scanner/system failure', 'clickup', 'page',
     'security-operations',
     'deployment, scanner capability, UNKNOWN/ERROR class, backlog bucket, runbook',
     'deployment:scanner_capability:failure_class:rolling_30m', 30,
     'outbox_sqs_worker', false,
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md', 'defined'),
    ('security_configuration_incident', 'Security-configuration incident', 'clickup', 'page',
     'security-operations',
     'deployment, config family, scope, revision, safe diff summary, audit event ids',
     'deployment:config_family:scope:rolling_1h', 60,
     'outbox_sqs_worker', false,
     'docs/runbooks/PHASE9-OPERATIONS-HARDENING.md', 'defined')
) AS seed(
    category_id, display_name, destination, severity, owner, minimized_metadata,
    deduplication_key, aggregation_window_minutes, delivery_mode,
    blocks_mail_delivery, runbook, readiness_state
)
ON CONFLICT (deployment_id, category_id) DO NOTHING;

ALTER TABLE operations_automation_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE operations_automation_categories FORCE ROW LEVEL SECURITY;
CREATE POLICY operations_automation_categories_deployment_isolation
    ON operations_automation_categories
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON operations_automation_categories TO nullapart_mailcore;
    END IF;
END $$;

COMMIT;

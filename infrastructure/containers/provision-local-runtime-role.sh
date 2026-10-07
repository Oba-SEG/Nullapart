#!/bin/sh
set -eu

: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${NULLAPART_MAILCORE_DB_PASSWORD:?NULLAPART_MAILCORE_DB_PASSWORD is required}"

psql --quiet --set ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set runtime_password="$NULLAPART_MAILCORE_DB_PASSWORD" <<'SQL'
SELECT format(
    'CREATE ROLE nullapart_mailcore LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'runtime_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore')
\gexec

ALTER ROLE nullapart_mailcore
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
SELECT format('ALTER ROLE nullapart_mailcore PASSWORD %L', :'runtime_password')
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO nullapart_mailcore', current_database())
\gexec
GRANT USAGE ON SCHEMA public TO nullapart_mailcore;

GRANT SELECT ON deployments TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON customers, domains TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON idempotency_keys TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE, DELETE ON source_ip_groups TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON smtp_transactions TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON handoff_idempotency TO nullapart_mailcore;
GRANT SELECT, INSERT ON
    smtp_transaction_recipients,
    tenant_message_recipients,
    artifacts,
    scanner_results,
    security_findings,
    quarantine_reinjection_envelopes,
    reinjection_deliveries,
    reinjection_dead_letters,
    audit_events
TO nullapart_mailcore;
GRANT SELECT ON audit_checkpoints, delivery_attempts, nodes TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON tenant_message_instances, quarantine_cases, outbox_events
TO nullapart_mailcore;

GRANT SELECT ON policy_families, feature_definitions TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON policy_revisions, config_revisions, feature_overrides
TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON inline_ml_models TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON ml_feedback_candidates TO nullapart_mailcore;
GRANT SELECT, INSERT ON inline_ml_shadow_evaluations TO nullapart_mailcore;
GRANT SELECT, INSERT ON dmarc_aggregate_reports TO nullapart_mailcore;
GRANT SELECT, INSERT ON dmarc_aggregate_records TO nullapart_mailcore;
GRANT SELECT, INSERT ON dmarc_report_quarantine TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON dmarc_report_ingress_jobs TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON domain_security_observations TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON dmarc_report_authorizations TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON bimi_domain_status TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON domain_source_classifications TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON domain_security_notifications TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON admin_users, admin_sessions TO nullapart_mailcore;
GRANT SELECT, INSERT, UPDATE ON admin_impersonations TO nullapart_mailcore;
GRANT SELECT, INSERT ON admin_roles TO nullapart_mailcore;
GRANT SELECT, INSERT, DELETE ON admin_role_permissions, admin_user_roles TO nullapart_mailcore;
GRANT SELECT, INSERT, DELETE ON oidc_login_flows TO nullapart_mailcore;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nullapart_mailcore;
GRANT EXECUTE ON FUNCTION public.resolve_verified_recipient_domains(TEXT[], TEXT)
    TO nullapart_mailcore;
GRANT EXECUTE ON FUNCTION public.resolve_verified_report_domain(TEXT, TEXT)
    TO nullapart_mailcore;
GRANT EXECUTE ON FUNCTION public.claim_quarantine_reinjection_event(TEXT, UUID[])
    TO nullapart_mailcore;
SQL

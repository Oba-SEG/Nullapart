-- Nullapart Database Migrations
-- Phase 0: Core schema foundation
-- PostgreSQL with RLS patterns

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- Customer / Deployment Identity
-- ============================================================

CREATE TABLE deployments (
    id TEXT PRIMARY KEY,
    region TEXT NOT NULL,
    display_name TEXT NOT NULL,
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'suspended', 'decommissioned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE customers (
    id TEXT PRIMARY KEY,
    internal_key BIGSERIAL UNIQUE NOT NULL,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    display_name TEXT NOT NULL,
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'suspended', 'deprovisioned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_customers_deployment ON customers(deployment_id);

-- ============================================================
-- Domains
-- ============================================================

CREATE TABLE domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    domain TEXT NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending', 'verified', 'failed')),
    verification_method TEXT,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(customer_id, domain)
);

CREATE INDEX idx_domains_customer ON domains(customer_id);
CREATE INDEX idx_domains_domain ON domains(domain);

-- ============================================================
-- SMTP Transaction / Tenant Message Metadata
-- ============================================================

CREATE TABLE smtp_transactions (
    id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    envelope_sender TEXT NOT NULL,
    message_id TEXT,
    content_hash TEXT NOT NULL,
    mime_artifact_id TEXT NOT NULL,
    spf_result JSONB,
    dkim_result JSONB,
    dmarc_result JSONB,
    arc_result JSONB,
    received_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_transactions_deployment ON smtp_transactions(deployment_id);
CREATE INDEX idx_transactions_received ON smtp_transactions(received_at);

CREATE TABLE tenant_message_instances (
    id UUID PRIMARY KEY,
    transaction_id UUID NOT NULL REFERENCES smtp_transactions(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    policy_revision_id UUID,
    disposition TEXT NOT NULL DEFAULT 'hold' CHECK (disposition IN ('allow', 'quarantine', 'reject', 'hold', 'defer')),
    remediation_type TEXT DEFAULT 'none',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tenant_messages_transaction ON tenant_message_instances(transaction_id);
CREATE INDEX idx_tenant_messages_customer ON tenant_message_instances(customer_id);

-- ============================================================
-- Policy / Config Revisions
-- ============================================================

CREATE TABLE policy_revisions (
    id UUID PRIMARY KEY,
    customer_id TEXT REFERENCES customers(id),
    revision_number BIGSERIAL NOT NULL,
    rules JSONB NOT NULL DEFAULT '[]',
    published_by TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,
    UNIQUE(customer_id, revision_number)
);

CREATE TABLE config_revisions (
    id UUID PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('system', 'deployment', 'tenant')),
    scope_id TEXT NOT NULL,
    revision_number BIGSERIAL NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    published_by TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(scope, scope_id, revision_number)
);

-- ============================================================
-- Feature Definition / Override Metadata
-- ============================================================

CREATE TABLE feature_definitions (
    feature_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    default_value TEXT NOT NULL DEFAULT 'disabled',
    mandatory BOOLEAN NOT NULL DEFAULT false,
    kill_switch BOOLEAN NOT NULL DEFAULT false,
    allowed_scopes TEXT[] NOT NULL DEFAULT ARRAY['system', 'deployment', 'tenant'],
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE feature_overrides (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    feature_id TEXT NOT NULL REFERENCES feature_definitions(feature_id),
    scope TEXT NOT NULL CHECK (scope IN ('system', 'deployment', 'tenant')),
    scope_id TEXT NOT NULL,
    value TEXT NOT NULL,
    owner TEXT NOT NULL,
    reason TEXT NOT NULL,
    revision BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    UNIQUE(feature_id, scope, scope_id, revision)
);

CREATE INDEX idx_feature_overrides_lookup ON feature_overrides(feature_id, scope, scope_id);

-- ============================================================
-- Admin Audit
-- ============================================================

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT REFERENCES customers(id),
    actor_id TEXT NOT NULL,
    actor_login TEXT NOT NULL,
    actor_roles TEXT[] NOT NULL,
    impersonated_subject TEXT,
    impersonated_customer TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    result TEXT NOT NULL CHECK (result IN ('success', 'denied', 'failed')),
    source_ip TEXT,
    session_id TEXT,
    trace_id TEXT NOT NULL,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_events_customer ON audit_events(customer_id);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id);
CREATE INDEX idx_audit_events_created ON audit_events(created_at);
CREATE INDEX idx_audit_events_action ON audit_events(action);

-- ============================================================
-- Outbox (transactional event publishing)
-- ============================================================

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type TEXT NOT NULL,
    event_version INTEGER NOT NULL DEFAULT 1,
    payload JSONB NOT NULL,
    idempotency_key TEXT,
    customer_id TEXT,
    deployment_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    UNIQUE(idempotency_key)
);

CREATE INDEX idx_outbox_unpublished ON outbox_events(created_at) WHERE published_at IS NULL;

-- ============================================================
-- Artifact Metadata
-- ============================================================

CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT REFERENCES customers(id),
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    content_hash TEXT NOT NULL,
    storage_backend TEXT NOT NULL DEFAULT 's3',
    storage_path TEXT NOT NULL,
    retention_class TEXT NOT NULL DEFAULT 'standard',
    encryption_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_artifacts_customer ON artifacts(customer_id);
CREATE INDEX idx_artifacts_hash ON artifacts(content_hash);

-- ============================================================
-- Idempotency Records
-- ============================================================

CREATE TABLE idempotency_keys (
    key TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);

-- ============================================================
-- Node / Runtime Identity
-- ============================================================

CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    node_type TEXT NOT NULL CHECK (node_type IN ('mail', 'control', 'scanner', 'worker')),
    role TEXT NOT NULL,
    private_ip INET,
    public_ip INET,
    hostname TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'draining', 'offline')),
    version TEXT NOT NULL,
    config_revision BIGINT,
    last_health_check TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_nodes_deployment ON nodes(deployment_id);

-- ============================================================
-- RLS Policies
-- ============================================================

-- Enable RLS on tenant-scoped tables
ALTER TABLE tenant_message_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE domains ENABLE ROW LEVEL SECURITY;

-- Normal request role: tenant-scoped access
CREATE POLICY tenant_messages_isolation ON tenant_message_instances
    USING (customer_id = current_setting('app.current_customer_id')::TEXT);

CREATE POLICY audit_events_isolation ON audit_events
    USING (customer_id IS NULL OR customer_id = current_setting('app.current_customer_id')::TEXT);

CREATE POLICY artifacts_isolation ON artifacts
    USING (customer_id IS NULL OR customer_id = current_setting('app.current_customer_id')::TEXT);

CREATE POLICY domains_isolation ON domains
    USING (customer_id = current_setting('app.current_customer_id')::TEXT);

-- Platform/maintenance role bypasses RLS (for migrations, support operations)
-- This role is used ONLY for explicit cross-tenant platform operations
-- and is never used by normal request paths.
-- GRANT ALL ON ALL TABLES IN SCHEMA public TO nullapart_platform;

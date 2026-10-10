-- 028_outbound_intelligence.sql
-- Phase 6 foundation: outbound intelligence read/control models.
--
-- These tables intentionally store normalized sender/source/campaign metrics
-- and event metadata only. They do not store raw MIME, message bodies, full
-- recipient lists or full subject/content samples merely to calculate
-- outbound-abuse similarity.

BEGIN;

CREATE TABLE approved_bulk_senders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    sender_address TEXT NOT NULL CHECK (length(sender_address) <= 320),
    sending_domain TEXT NOT NULL CHECK (length(sending_domain) <= 253),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('smtp_mta', 'internal_api', 'webhook', 'connector')),
    source_id TEXT NOT NULL CHECK (length(source_id) <= 160),
    source_ip INET,
    max_messages_per_minute INTEGER NOT NULL CHECK (max_messages_per_minute > 0),
    max_messages_per_hour INTEGER NOT NULL CHECK (max_messages_per_hour > 0),
    max_recipients_per_message INTEGER NOT NULL CHECK (max_recipients_per_message > 0),
    max_unique_recipients_per_hour INTEGER NOT NULL CHECK (max_unique_recipients_per_hour > 0),
    allowed_region TEXT CHECK (allowed_region IS NULL OR length(allowed_region) <= 64),
    active BOOLEAN NOT NULL DEFAULT true,
    approved_by TEXT NOT NULL CHECK (length(approved_by) <= 160),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 8 AND 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    CONSTRAINT approved_bulk_senders_sender_lower CHECK (sender_address = lower(sender_address)),
    CONSTRAINT approved_bulk_senders_domain_lower CHECK (sending_domain = lower(sending_domain)),
    CONSTRAINT approved_bulk_senders_expiry CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT approved_bulk_senders_sender_source_unique
        UNIQUE (deployment_id, customer_id, sender_address, source_kind, source_id)
);

CREATE INDEX idx_approved_bulk_senders_customer
    ON approved_bulk_senders (customer_id, active, updated_at DESC);
CREATE INDEX idx_approved_bulk_senders_lookup
    ON approved_bulk_senders (deployment_id, customer_id, sender_address, source_kind, source_id)
    WHERE active;

CREATE TABLE outbound_behavior_rollups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('smtp_mta', 'internal_api', 'webhook', 'connector')),
    source_id TEXT NOT NULL CHECK (length(source_id) <= 160),
    source_ip INET,
    sender_address TEXT NOT NULL CHECK (length(sender_address) <= 320),
    sending_domain TEXT NOT NULL CHECK (length(sending_domain) <= 253),
    campaign_fingerprint TEXT CHECK (campaign_fingerprint IS NULL OR length(campaign_fingerprint) <= 160),
    recipient_domain TEXT CHECK (recipient_domain IS NULL OR length(recipient_domain) <= 253),
    window_start TIMESTAMPTZ NOT NULL,
    window_seconds INTEGER NOT NULL CHECK (window_seconds IN (60, 3600, 86400)),
    message_count INTEGER NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    recipient_count INTEGER NOT NULL DEFAULT 0 CHECK (recipient_count >= 0),
    unique_recipient_count INTEGER NOT NULL DEFAULT 0 CHECK (unique_recipient_count >= 0),
    new_recipient_count INTEGER NOT NULL DEFAULT 0 CHECK (new_recipient_count >= 0),
    bounce_count INTEGER NOT NULL DEFAULT 0 CHECK (bounce_count >= 0),
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    malware_count INTEGER NOT NULL DEFAULT 0 CHECK (malware_count >= 0),
    auth_source_change_count INTEGER NOT NULL DEFAULT 0 CHECK (auth_source_change_count >= 0),
    unusual_time_count INTEGER NOT NULL DEFAULT 0 CHECK (unusual_time_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT outbound_behavior_rollups_sender_lower CHECK (sender_address = lower(sender_address)),
    CONSTRAINT outbound_behavior_rollups_domain_lower CHECK (sending_domain = lower(sending_domain))
);

CREATE UNIQUE INDEX idx_outbound_behavior_rollups_unique_window
    ON outbound_behavior_rollups (
        deployment_id,
        customer_id,
        source_kind,
        source_id,
        sender_address,
        COALESCE(campaign_fingerprint, ''),
        COALESCE(recipient_domain, ''),
        window_start,
        window_seconds
    );

CREATE INDEX idx_outbound_behavior_rollups_customer_window
    ON outbound_behavior_rollups (customer_id, window_start DESC, window_seconds);
CREATE INDEX idx_outbound_behavior_rollups_sender
    ON outbound_behavior_rollups (deployment_id, customer_id, sender_address, window_start DESC);
CREATE INDEX idx_outbound_behavior_rollups_campaign
    ON outbound_behavior_rollups (deployment_id, customer_id, campaign_fingerprint, window_start DESC)
    WHERE campaign_fingerprint IS NOT NULL;

CREATE TABLE outbound_campaign_fingerprints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) <= 160),
    algorithm TEXT NOT NULL CHECK (algorithm IN ('rspamd_fuzzy', 'nullapart_v1')),
    sample_subject_hash TEXT CHECK (sample_subject_hash IS NULL OR length(sample_subject_hash) <= 128),
    url_set_hash TEXT CHECK (url_set_hash IS NULL OR length(url_set_hash) <= 128),
    attachment_set_hash TEXT CHECK (attachment_set_hash IS NULL OR length(attachment_set_hash) <= 128),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    message_count INTEGER NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    recipient_count INTEGER NOT NULL DEFAULT 0 CHECK (recipient_count >= 0),
    disposition TEXT NOT NULL DEFAULT 'observed'
        CHECK (disposition IN ('observed', 'allowed', 'warned', 'throttled', 'held', 'blocked')),
    CONSTRAINT outbound_campaign_fingerprints_seen_order CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT outbound_campaign_fingerprints_unique
        UNIQUE (deployment_id, customer_id, fingerprint, algorithm)
);

CREATE INDEX idx_outbound_campaign_fingerprints_customer
    ON outbound_campaign_fingerprints (customer_id, disposition, last_seen_at DESC);

CREATE TABLE outbound_security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    event_key TEXT NOT NULL CHECK (length(event_key) <= 220),
    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'unauthorized_bulk',
            'compromised_sender',
            'source_spoofing',
            'malware_from_bulk_sender',
            'campaign_outbreak',
            'delivery_failure_spike'
        )
    ),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    outcome TEXT NOT NULL CHECK (
        outcome IN ('allow', 'warn', 'throttle', 'defer', 'hold', 'block_sender', 'suspend_outbound')
    ),
    reason_code TEXT NOT NULL CHECK (length(reason_code) <= 80),
    sender_address TEXT CHECK (sender_address IS NULL OR length(sender_address) <= 320),
    source_id TEXT CHECK (source_id IS NULL OR length(source_id) <= 160),
    campaign_fingerprint TEXT CHECK (campaign_fingerprint IS NULL OR length(campaign_fingerprint) <= 160),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    message_count INTEGER NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    cooldown_until TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    trace_id TEXT CHECK (trace_id IS NULL OR length(trace_id) <= 96),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT outbound_security_events_seen_order CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT outbound_security_events_dedupe UNIQUE (deployment_id, customer_id, event_key)
);

CREATE INDEX idx_outbound_security_events_customer
    ON outbound_security_events (customer_id, status, severity, last_seen_at DESC);
CREATE INDEX idx_outbound_security_events_campaign
    ON outbound_security_events (deployment_id, customer_id, campaign_fingerprint, last_seen_at DESC)
    WHERE campaign_fingerprint IS NOT NULL;

ALTER TABLE approved_bulk_senders ENABLE ROW LEVEL SECURITY;
ALTER TABLE approved_bulk_senders FORCE ROW LEVEL SECURITY;
CREATE POLICY approved_bulk_senders_customer_isolation ON approved_bulk_senders
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE outbound_behavior_rollups ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbound_behavior_rollups FORCE ROW LEVEL SECURITY;
CREATE POLICY outbound_behavior_rollups_customer_isolation ON outbound_behavior_rollups
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE outbound_campaign_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbound_campaign_fingerprints FORCE ROW LEVEL SECURITY;
CREATE POLICY outbound_campaign_fingerprints_customer_isolation ON outbound_campaign_fingerprints
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

ALTER TABLE outbound_security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbound_security_events FORCE ROW LEVEL SECURITY;
CREATE POLICY outbound_security_events_customer_isolation ON outbound_security_events
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON approved_bulk_senders TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON outbound_behavior_rollups TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON outbound_campaign_fingerprints TO nullapart_mailcore;
        GRANT SELECT, INSERT, UPDATE ON outbound_security_events TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

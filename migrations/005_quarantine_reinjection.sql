-- Durable, tenant-scoped envelope details required by the trusted release
-- worker. Raw MIME remains in ArtifactStore and is never stored here.
CREATE TABLE quarantine_reinjection_envelopes (
    tenant_message_id UUID PRIMARY KEY REFERENCES quarantine_cases(tenant_message_id) ON DELETE RESTRICT,
    transaction_id UUID NOT NULL REFERENCES smtp_transactions(id),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    envelope_sender TEXT NOT NULL,
    recipients JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (jsonb_typeof(recipients) = 'array'),
    CHECK (jsonb_array_length(recipients) > 0)
);

CREATE INDEX quarantine_reinjection_envelopes_customer_idx
    ON quarantine_reinjection_envelopes(customer_id, tenant_message_id);

ALTER TABLE quarantine_reinjection_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE quarantine_reinjection_envelopes FORCE ROW LEVEL SECURITY;

CREATE POLICY quarantine_reinjection_envelopes_tenant_isolation
    ON quarantine_reinjection_envelopes
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

-- Delivery history is append-only. It proves every reinjection attempt and
-- separates an SMTP transport retry from the authorization/release action.
CREATE TABLE reinjection_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    outbox_event_id UUID NOT NULL REFERENCES outbox_events(id),
    tenant_message_id UUID NOT NULL REFERENCES tenant_message_instances(id),
    transaction_id UUID NOT NULL REFERENCES smtp_transactions(id),
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    delivery_attempt_id UUID NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    postfix_queue_id TEXT,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((outcome = 'succeeded') = (postfix_queue_id IS NOT NULL)),
    CHECK ((outcome = 'failed') = (error_code IS NOT NULL))
);

CREATE UNIQUE INDEX reinjection_deliveries_one_success_per_event
    ON reinjection_deliveries(outbox_event_id)
    WHERE outcome = 'succeeded';

CREATE INDEX reinjection_deliveries_tenant_idx
    ON reinjection_deliveries(customer_id, tenant_message_id, created_at DESC);

ALTER TABLE reinjection_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE reinjection_deliveries FORCE ROW LEVEL SECURITY;

CREATE POLICY reinjection_deliveries_tenant_isolation ON reinjection_deliveries
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

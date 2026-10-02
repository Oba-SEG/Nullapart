-- Terminal release-reinjection failures remain unpublished in the outbox and
-- are recorded here so they cannot starve later events or disappear from
-- operations evidence.
CREATE TABLE reinjection_dead_letters (
    outbox_event_id UUID PRIMARY KEY REFERENCES outbox_events(id) ON DELETE RESTRICT,
    tenant_message_id UUID NOT NULL REFERENCES tenant_message_instances(id) ON DELETE RESTRICT,
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    failure_code TEXT NOT NULL CHECK (failure_code IN (
        'ARTIFACT_UNAVAILABLE',
        'LOOP_HEADER_PRESENT',
        'SMTP_UNAVAILABLE'
    )),
    exhausted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX reinjection_dead_letters_tenant_idx
    ON reinjection_dead_letters(customer_id, exhausted_at DESC);

ALTER TABLE reinjection_dead_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE reinjection_dead_letters FORCE ROW LEVEL SECURITY;

CREATE POLICY reinjection_dead_letters_tenant_isolation ON reinjection_dead_letters
    USING (customer_id = current_setting('app.current_customer_id', true))
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));


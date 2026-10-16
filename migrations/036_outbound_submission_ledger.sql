-- 036_outbound_submission_ledger.sql
--
-- Durable private-outbound SMTP submission identity. A row is claimed before
-- Mail Core sends to the isolated Postfix :10027 listener. If the TCP/SMTP
-- result is ambiguous, the row deliberately remains in_progress so a retry
-- cannot create a duplicate customer email after a lost final SMTP response.

BEGIN;

-- `customers.id` is globally unique today, but the composite key makes the
-- deployment/customer binding explicit and prevents a privileged writer from
-- associating a real customer with the wrong deployment in this new table.
ALTER TABLE customers
    ADD CONSTRAINT customers_id_deployment_unique UNIQUE (id, deployment_id);

CREATE TABLE outbound_submission_ledger (
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    customer_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL CHECK (
        idempotency_key ~ '^[0-9a-f]{64}$'
    ),
    submission_state TEXT NOT NULL CHECK (
        submission_state IN ('in_progress', 'submitted')
    ),
    transaction_id TEXT NOT NULL,
    postfix_queue_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_at TIMESTAMPTZ,
    PRIMARY KEY (deployment_id, customer_id, idempotency_key),
    FOREIGN KEY (customer_id, deployment_id)
        REFERENCES customers (id, deployment_id),
    CHECK (
        (submission_state = 'in_progress'
            AND postfix_queue_id IS NULL
            AND submitted_at IS NULL)
        OR
        (submission_state = 'submitted'
            AND transaction_id IS NOT NULL
            AND postfix_queue_id IS NOT NULL
            AND submitted_at IS NOT NULL)
    )
);

CREATE INDEX idx_outbound_submission_ledger_in_progress
    ON outbound_submission_ledger (created_at)
    WHERE submission_state = 'in_progress';

ALTER TABLE outbound_submission_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbound_submission_ledger FORCE ROW LEVEL SECURITY;

CREATE POLICY outbound_submission_ledger_tenant_isolation
    ON outbound_submission_ledger
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
        GRANT SELECT, INSERT, UPDATE ON outbound_submission_ledger TO nullapart_mailcore;
    END IF;
END
$$;

COMMIT;

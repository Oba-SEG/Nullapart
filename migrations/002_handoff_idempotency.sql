-- Durable Postfix-to-Mail-Core retry boundary.
-- Queue IDs are deployment-scoped; a changed content hash is a conflict, not a retry.
CREATE TABLE handoff_idempotency (
    deployment_id TEXT NOT NULL REFERENCES deployments(id),
    postfix_queue_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    transaction_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, postfix_queue_id)
);

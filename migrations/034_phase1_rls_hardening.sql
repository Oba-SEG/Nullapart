-- 034_phase1_rls_hardening.sql
--
-- Defense-in-depth row-level security for the remaining Phase 1 mail-foundation
-- tables that have no scope policy yet: customers, smtp_transactions,
-- smtp_transaction_recipients, handoff_idempotency and idempotency_keys
-- (docs/02, docs/04, docs/phases/PHASE-1-MAIL-FOUNDATION.md).
--
-- As with migrations 002/009/010/022 this is defense in depth, not a
-- replacement for application authorization: the missing_ok form of
-- current_setting makes an unscoped session match zero rows (fail closed)
-- instead of raising mid-query, and the application remains responsible for
-- setting app.current_deployment_id / app.current_customer_id inside every
-- scoped transaction. Deployment isolation is still present in each
-- application query as the primary control.
--
-- FORCE ROW LEVEL SECURITY is applied to match the established table policy.
-- The owner therefore needs the deployment GUC set to touch these tables once
-- this migration is live; later migrations or maintenance scripts that must
-- operate on these tables as the owner should follow the migration 018
-- NO FORCE / FORCE pattern (or run under a superuser, as the local harness
-- and phase2-local-seed do).

-- ============================================================
-- customers
-- ============================================================
-- Deployment-keyed read/write. The OR branch on app.current_customer_id
-- exists for the quarantine-reinjection worker, which sets only the customer
-- GUC before resolving the owning customer of an event
-- (quarantine_reinjection.rs invalid-event path). Inserts still require the
-- deployment GUC, so a customer-scoped session can never fabricate a
-- customer row.

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS customers_deployment_isolation ON customers;
CREATE POLICY customers_deployment_isolation ON customers
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        OR id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
    );

-- ============================================================
-- smtp_transactions
-- ============================================================
-- Deployment-keyed, mirroring the tenant_message_instances policy shape from
-- migration 002. The durable handoff transaction and the trace/workload
-- readers must set app.current_deployment_id in their transaction.

ALTER TABLE smtp_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE smtp_transactions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS smtp_transactions_deployment_isolation ON smtp_transactions;
CREATE POLICY smtp_transactions_deployment_isolation ON smtp_transactions
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

-- ============================================================
-- smtp_transaction_recipients
-- ============================================================
-- No scope column of its own: visibility follows the owning transaction's
-- deployment, mirroring the tenant_message_recipients / delivery_attempts
-- EXISTS pattern from migration 002.

ALTER TABLE smtp_transaction_recipients ENABLE ROW LEVEL SECURITY;
ALTER TABLE smtp_transaction_recipients FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS smtp_transaction_recipients_deployment_isolation
    ON smtp_transaction_recipients;
CREATE POLICY smtp_transaction_recipients_deployment_isolation
    ON smtp_transaction_recipients
    USING (
        EXISTS (
            SELECT 1
            FROM smtp_transactions AS tx
            WHERE tx.id = smtp_transaction_recipients.transaction_id
              AND tx.deployment_id = current_setting('app.current_deployment_id', true)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM smtp_transactions AS tx
            WHERE tx.id = smtp_transaction_recipients.transaction_id
              AND tx.deployment_id = current_setting('app.current_deployment_id', true)
        )
    );

-- ============================================================
-- handoff_idempotency
-- ============================================================
-- Deployment-keyed like its primary key (deployment_id, postfix_queue_id).
-- The durable handoff path reads/inserts this table before it sets any other
-- scope, so it must set app.current_deployment_id first.

ALTER TABLE handoff_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE handoff_idempotency FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS handoff_idempotency_deployment_isolation ON handoff_idempotency;
CREATE POLICY handoff_idempotency_deployment_isolation ON handoff_idempotency
    USING (deployment_id = current_setting('app.current_deployment_id', true))
    WITH CHECK (deployment_id = current_setting('app.current_deployment_id', true));

-- ============================================================
-- idempotency_keys
-- ============================================================
-- Tenant-scoped like the other FORCE-row-level-secured tables. Every claim
-- path sets both scope settings before claiming (domain_security,
-- outbound_intelligence_api, deep_ai, policy_admin, model_registry,
-- operations_api, admin_customers, connectors_remediation), and the claim
-- INSERT records the session's deployment and customer so a key claimed
-- inside one tenant can never be read, replayed or completed from another.
-- The composite primary key (deployment_id, customer_id, key) lets two
-- tenants pick the same client-generated key without colliding; a
-- same-tenant operation mismatch still surfaces through the stored
-- operation comparison in the claim path. An unscoped session matches zero
-- rows and cannot insert (fail closed).

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;

ALTER TABLE idempotency_keys
    ADD COLUMN IF NOT EXISTS deployment_id TEXT NOT NULL DEFAULT '';
ALTER TABLE idempotency_keys
    ADD COLUMN IF NOT EXISTS customer_id TEXT NOT NULL DEFAULT '';
ALTER TABLE idempotency_keys DROP CONSTRAINT IF EXISTS idempotency_keys_pkey;
ALTER TABLE idempotency_keys
    ADD PRIMARY KEY (deployment_id, customer_id, key);

DROP POLICY IF EXISTS idempotency_keys_scope_gate ON idempotency_keys;
DROP POLICY IF EXISTS idempotency_keys_tenant_isolation ON idempotency_keys;
CREATE POLICY idempotency_keys_tenant_isolation ON idempotency_keys
    USING (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    )
    WITH CHECK (
        deployment_id = current_setting('app.current_deployment_id', true)
        AND customer_id = current_setting('app.current_customer_id', true)
    );

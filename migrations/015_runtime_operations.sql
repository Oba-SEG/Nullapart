-- Nullapart Database Migration 015
-- Phase 3 increment 7: runtime operations visibility.
--
-- The runtime operations projection reports deployment-wide publication lag
-- and terminal reinjection failures, so its reads must span every row of the
-- deployment rather than only the caller's own customer. The `outbox_events`
-- and `reinjection_dead_letters` policies therefore accept a deployment match
-- as well as the original tenant match.
--
-- `WITH CHECK` is unchanged on both tables: minting stays tenant-bound, so a
-- tenant session still cannot attribute a row to a customer it does not own,
-- nor insert a platform-scoped (customer-less) event. The deployment scope is
-- a read widening only, and the GUC comparison fails closed when the setting
-- is absent (`NULL = NULL` is not true).
--
-- A session that established only a customer scope therefore sees exactly
-- what it saw before, while the operations API — which always sets both
-- settings — can observe the whole deployment.

BEGIN;

DROP POLICY outbox_events_tenant_isolation ON outbox_events;

-- Renamed because the policy is no longer tenant-only.
CREATE POLICY outbox_events_isolation ON outbox_events
    USING (
        customer_id = current_setting('app.current_customer_id', true)
        OR deployment_id = current_setting('app.current_deployment_id', true)
    )
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

DROP POLICY reinjection_dead_letters_tenant_isolation ON reinjection_dead_letters;

CREATE POLICY reinjection_dead_letters_isolation ON reinjection_dead_letters
    USING (
        customer_id = current_setting('app.current_customer_id', true)
        OR deployment_id = current_setting('app.current_deployment_id', true)
    )
    WITH CHECK (customer_id = current_setting('app.current_customer_id', true));

COMMIT;

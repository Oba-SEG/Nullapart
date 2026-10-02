-- Narrow privileged entry points needed before a tenant-scoped transaction
-- can be established. Deployment provisioning grants EXECUTE only to the
-- Mail Core runtime role; PUBLIC must never invoke these functions.

CREATE OR REPLACE FUNCTION public.resolve_verified_recipient_domains(
    requested_domains TEXT[],
    requested_deployment_id TEXT
)
RETURNS TABLE(domain TEXT, customer_id TEXT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT lower(d.domain), d.customer_id
    FROM public.domains AS d
    JOIN public.customers AS c ON c.id = d.customer_id
    WHERE lower(d.domain) = ANY(requested_domains)
      AND d.verification_status = 'verified'
      AND c.deployment_id = requested_deployment_id
      AND c.lifecycle = 'active'
$$;

REVOKE ALL ON FUNCTION public.resolve_verified_recipient_domains(TEXT[], TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.claim_quarantine_reinjection_event(
    requested_event_type TEXT,
    skipped_event_ids UUID[]
)
RETURNS TABLE(
    id UUID,
    customer_id TEXT,
    deployment_id TEXT,
    trace_id TEXT,
    payload JSONB
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT event.id,
           event.customer_id,
           event.deployment_id,
           event.trace_id,
           event.payload
    FROM public.outbox_events AS event
    WHERE event.event_type = requested_event_type
      AND event.published_at IS NULL
      AND event.customer_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1
          FROM public.reinjection_dead_letters AS dead
          WHERE dead.outbox_event_id = event.id
      )
      AND NOT (event.id = ANY(skipped_event_ids))
    ORDER BY event.created_at
    FOR UPDATE OF event SKIP LOCKED
    LIMIT 1
$$;

REVOKE ALL ON FUNCTION public.claim_quarantine_reinjection_event(TEXT, UUID[]) FROM PUBLIC;

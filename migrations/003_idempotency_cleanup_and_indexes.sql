-- Migration 003: Idempotency key cleanup and observability indexes
-- Adds:
--   - Expired idempotency key cleanup function + scheduled job
--   - Performance indexes for common query patterns
--   - Audit event retention index

BEGIN;

-- ============================================================================
-- Idempotency key automatic cleanup
-- ============================================================================

-- Function to delete expired idempotency keys
CREATE OR REPLACE FUNCTION public.cleanup_expired_idempotency_keys()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM public.idempotency_keys
    WHERE expires_at < now() - INTERVAL '1 hour';

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;

-- Schedule cleanup every hour via pg_cron (if available)
-- Falls back to no-op if pg_cron is not installed
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.schedule(
            'nullapart-idempotency-cleanup',
            '0 * * * *',  -- every hour
            $$SELECT public.cleanup_expired_idempotency_keys()$$
        );
    END IF;
EXCEPTION WHEN OTHERS THEN
    -- pg_cron not available; cleanup will be handled externally
    RAISE NOTICE 'pg_cron not available, skipping idempotency cleanup schedule';
END;
$$;

-- ============================================================================
-- Performance indexes for common query patterns
-- ============================================================================

-- Index for handoff lookups by queue ID (trace API)
CREATE INDEX IF NOT EXISTS idx_transactions_postfix_queue_id
    ON public.transactions (postfix_queue_id)
    WHERE deleted_at IS NULL;

-- Index for partition lookups by envelope sender domain
CREATE INDEX IF NOT EXISTS idx_transactions_sender_domain
    ON public.transactions (sender_domain)
    WHERE deleted_at IS NULL;

-- Index for tenant-scoped feature override lookups
CREATE INDEX IF NOT EXISTS idx_feature_overrides_scope
    ON public.feature_overrides (scope, scope_id, feature_id)
    WHERE expires_at IS NULL OR expires_at > now();

-- Index for audit event queries by resource
CREATE INDEX IF NOT EXISTS idx_audit_events_resource
    ON public.audit_events (resource_type, resource_id)
    WHERE deleted_at IS NULL;

-- Index for expired handoff cleanup
CREATE INDEX IF NOT EXISTS idx_transactions_expired
    ON public.transactions (expires_at)
    WHERE expires_at IS NOT NULL AND deleted_at IS NULL;

COMMIT;

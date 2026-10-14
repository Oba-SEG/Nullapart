-- 035_phase9_readiness_evidence_correction.sql
--
-- Corrects a migration 032 seed row that overstated readiness. The
-- production-readiness evidence register deliberately preserves `partial` and
-- `not_ready` states where real production evidence is still missing
-- (docs/phases/PHASE-9-LOCAL-IMPLEMENTATION-PLAN.md), and the
-- support-diagnostics content boundary is a code-enforced, locally tested
-- property rather than a production-verified one. SECURITY.md documents the
-- boundary and the Control Plane projections preserve it; deployed
-- production evidence must be attached before this row can claim `ready`.
--
-- The UPDATE runs per deployment inside the same FORCE-row-level-secured
-- table (migration 032), so the deployment tenant GUC is asserted for each
-- row instead of relying on a superuser migration connection.

DO $$
DECLARE
    deployment_row RECORD;
BEGIN
    FOR deployment_row IN SELECT id FROM deployments LOOP
        PERFORM set_config('app.current_deployment_id', deployment_row.id, false);
        UPDATE operations_readiness_checks
        SET status = 'partial',
            notes = 'Content boundary is enforced in code (Support lacks trace:content) and covered by tests; production-deployment verification evidence is still required before ready.',
            updated_at = now()
        WHERE deployment_id = deployment_row.id
          AND check_id = 'support_diagnostics_content_boundary'
          AND status = 'ready';
    END LOOP;
END;
$$;

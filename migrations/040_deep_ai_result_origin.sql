-- 040_deep_ai_result_origin.sql
--
-- Records who produced a Deep AI analysis result
-- (docs/engineering/UX-TERMINOLOGY.md rule 4, AGENTS.md "model output is
-- evidence, not authority").
--
-- `POST /api/v1/deep-ai/analysis-results` is called by an authenticated console
-- session. Before this column, a row inserted through it was indistinguishable
-- from output the analysis runtime produced: an administrator typing a verdict
-- created a `validation_state = 'valid'` row attributed to a model release, and
-- nothing downstream could tell the two apart. `validation_state` describes
-- whether the structured output contract was satisfied, not who asserted it, so
-- it cannot carry that meaning.
--
-- The value is derived by the server from the authenticated caller, never read
-- from the request body. A client-supplied origin would be forgeable, which is
-- the exact defect this column removes.
--
-- NULL means "recorded before origin tracking existed". It is deliberately not
-- backfilled to either value: the existing rows on a long-lived database were
-- inserted by neither a verifiable runtime nor a labelled console form, and
-- guessing would invent provenance. The console renders NULL as such.
--
-- Idempotent (guarded ADD COLUMN) because local migrations only run at initdb;
-- a long-lived volume needs this file applied manually.

BEGIN;

ALTER TABLE deep_ai_analysis_results
    ADD COLUMN IF NOT EXISTS recorded_by TEXT
        CHECK (recorded_by IN ('model_runtime', 'administrator'));

COMMENT ON COLUMN deep_ai_analysis_results.recorded_by IS
    'Origin of the assertion: model_runtime = produced by the skill runtime, administrator = entered by a person in the console, NULL = recorded before origin tracking existed. Server-derived.';

COMMIT;

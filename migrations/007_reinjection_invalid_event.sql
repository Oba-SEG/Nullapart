-- A released message whose reinjection context can never be rebuilt (missing
-- quarantine case, envelope, or artifact metadata) is terminal, not
-- retryable. Migration 006 requires terminal failures to be recorded so they
-- cannot starve later events, which needs a failure code of its own.
ALTER TABLE reinjection_dead_letters
    DROP CONSTRAINT IF EXISTS reinjection_dead_letters_failure_code_check;
ALTER TABLE reinjection_dead_letters
    ADD CONSTRAINT reinjection_dead_letters_failure_code_check
    CHECK (failure_code IN (
        'ARTIFACT_UNAVAILABLE',
        'LOOP_HEADER_PRESENT',
        'SMTP_UNAVAILABLE',
        'INVALID_EVENT'
    ));

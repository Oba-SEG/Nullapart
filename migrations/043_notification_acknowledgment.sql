-- 043_notification_acknowledgment.sql
--
-- `domain_security_notifications.status` has carried 'acknowledged' in its CHECK
-- list since 022, but no route could ever set it: a tenant could see a finding
-- and had nowhere to record that somebody handled it. This adds the read-model
-- columns the acknowledge route writes.
--
-- Who acknowledged and when belongs on the notification itself, not only in
-- `audit_events`: the console shows it inline, and reconstructing it from audit
-- rows would make an operational read depend on log retention.

BEGIN;

ALTER TABLE domain_security_notifications
    ADD COLUMN IF NOT EXISTS acknowledged_by TEXT,
    ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'domain_security_notifications_acknowledgment_shape'
    ) THEN
        ALTER TABLE domain_security_notifications
            ADD CONSTRAINT domain_security_notifications_acknowledgment_shape CHECK (
                (status = 'open' AND acknowledged_by IS NULL AND acknowledged_at IS NULL)
                OR (acknowledged_by IS NOT NULL AND acknowledged_at IS NOT NULL)
            );
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nullapart_mailcore') THEN
        GRANT SELECT, INSERT, UPDATE ON domain_security_notifications TO nullapart_mailcore;
    END IF;
END
$$;

-- Postflight: the columns the acknowledge route writes must exist.
DO $$
BEGIN
    IF (SELECT count(*) FROM information_schema.columns
        WHERE table_name = 'domain_security_notifications'
          AND column_name IN ('acknowledged_by', 'acknowledged_at')) <> 2 THEN
        RAISE EXCEPTION 'notification acknowledgment columns were not created';
    END IF;
END
$$;

COMMIT;

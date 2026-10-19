-- 041_customer_policy_levels.sql
--
-- Three families move to customer management so a tenant administrator can
-- publish the controls that decide what happens to their own mail. The seed in
-- migration 014 gave `customer` to four families that nothing else had reached
-- yet and left the quarantine, spam and notification decisions with platform
-- roles, which is why the tenant console had almost nothing to operate.
--
-- `spam_filtering` keeps `security_floor = true`: a tenant publishes its own
-- thresholds inside the floor, and `mandatory_security_floors_cannot_be_
-- disabled` still refuses a revision that would turn the floor off.
--
-- Enforcement truth is unchanged by this migration. The rule profile published
-- by `policy_profile.rs` already states which families a runtime reader
-- consumes, and quarantine, spam filtering and notifications are not among
-- them, so the console says "stored, not enforced" for all three. Moving the
-- management level decides who may author a revision, not whether a delivery
-- stage reads it.

BEGIN;

UPDATE policy_families
SET management_level = 'customer'
WHERE family_key IN ('quarantine', 'spam_filtering', 'notifications');

-- The 014 seed gave spam filtering no floor because no tenant could reach it.
-- A customer-managed family that decides spam disposition must keep one, so the
-- invariant is set here rather than assumed from an already-edited catalog: a
-- tenant may lower its own thresholds, never the platform floor.
UPDATE policy_families
SET security_floor = true
WHERE family_key = 'spam_filtering';

-- Guard the invariant the console renders from: exactly seven customer families
-- after this point, and spam filtering still carries its floor.
DO $$
BEGIN
    IF (SELECT count(*) FROM policy_families WHERE management_level = 'customer') <> 7 THEN
        RAISE EXCEPTION 'expected 7 customer-managed policy families, found %',
            (SELECT count(*) FROM policy_families WHERE management_level = 'customer');
    END IF;
    IF NOT (SELECT security_floor FROM policy_families WHERE family_key = 'spam_filtering') THEN
        RAISE EXCEPTION 'spam_filtering must keep its security floor when it becomes customer-managed';
    END IF;
END
$$;

COMMIT;

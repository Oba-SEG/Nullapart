-- Nullapart Database Migration 018
-- Customer operational identity: docs/02-REGIONS-TENANCY-NAMING.md.
--
-- A customer's visible identity is the operational ID `"C" + region code +
-- "-" + regional sequence` (for example `CZA-1`), and the structured
-- region/deployment/sequence fields are stored beside it so authorization and
-- routing never parse identity strings. This migration:
--
--   1. adds the structured `region_code` / `sequence_no` columns
--      (`deployment_id` is already the structured deployment field);
--   2. canonicalizes the local fixture region `local` to `ZA`;
--   3. backfills the structured fields for every existing customer;
--   4. rewrites `customers.id` to the operational format and follows every
--      referencing column: foreign-key children (under disabled RI triggers),
--      the non-referencing customer columns (`outbox_events.customer_id`,
--      audit scope/impersonation/resource/detail fields), tenant-scoped
--      `feature_overrides` / `config_revisions` scope IDs, and idempotency
--      records whose operation keys or replay envelopes embed the old ID.
--
-- `region_code` / `sequence_no` stay nullable: direct database fixtures may
-- omit operational metadata, while customers created through the API always
-- populate both (see `admin_customers::next_customer_id`).
--
-- The whole file runs in one transaction so a failure restores both data and
-- trigger/RLS state. `audit_events` carries an append-only trigger, and FORCE
-- ROW LEVEL SECURITY covers several children plus `outbox_events`,
-- `feature_overrides`, and `config_revisions`; all of them are held open for
-- the rewrite and restored in one step before commit. Owner privileges are
-- required (the canonical migration runner is the table owner).

BEGIN;

ALTER TABLE customers ADD COLUMN region_code TEXT;
ALTER TABLE customers ADD COLUMN sequence_no BIGINT;

-- docs/02 reserves the canonical uppercase region codes (ZA/ZAB/ZAC/EU/UK/US);
-- the historical local fixture stored the placeholder `local`.
UPDATE deployments SET region = 'ZA' WHERE region = 'local';

UPDATE customers c
SET region_code = upper(d.region)
FROM deployments d
WHERE d.id = c.deployment_id
  AND c.region_code IS NULL;

-- Refuse to mint operational identities from anything that is not a
-- canonical region code: a bad region fails the migration instead of
-- producing an ID no parser will accept.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM customers
        WHERE region_code IS NOT NULL
          AND region_code !~ '^[A-Z]{2,3}$'
    ) THEN
        RAISE EXCEPTION 'customer region code outside the canonical docs/02 set: %',
            (SELECT string_agg(DISTINCT region_code, ', ') FROM customers
             WHERE region_code IS NOT NULL AND region_code !~ '^[A-Z]{2,3}$');
    END IF;
END $$;

-- The sequence is regional (docs/02: CZA-1, CZA-2, ...), ordered by creation
-- time so the oldest customer keeps the lowest number.
UPDATE customers c
SET sequence_no = s.rn
FROM (
    SELECT id,
           row_number() OVER (
               PARTITION BY region_code ORDER BY created_at, id
           ) AS rn
    FROM customers
    WHERE region_code IS NOT NULL
) AS s
WHERE c.id = s.id
  AND c.sequence_no IS NULL;

-- Old to new identity mapping; rows already in operational form are skipped.
CREATE TEMP TABLE customer_id_remap ON COMMIT DROP AS
SELECT c.id AS old_id,
       'C' || c.region_code || '-' || c.sequence_no AS new_id
FROM customers c
WHERE c.region_code IS NOT NULL
  AND c.sequence_no IS NOT NULL
  AND c.id <> 'C' || c.region_code || '-' || c.sequence_no;

-- Children that were forced under RLS get FORCE restored after the rewrite.
CREATE TEMP TABLE customer_id_fks (
    tbl regclass NOT NULL,
    col name NOT NULL,
    was_forced boolean NOT NULL,
    PRIMARY KEY (tbl, col)
) ON COMMIT DROP;

INSERT INTO customer_id_fks (tbl, col, was_forced)
SELECT c.conrelid, a.attname, cl.relforcerowsecurity
FROM pg_constraint c
JOIN pg_class cl ON cl.oid = c.conrelid
JOIN pg_attribute a
  ON a.attrelid = c.conrelid
 AND a.attnum = ANY (c.conkey)
WHERE c.contype = 'f'
  AND c.confrelid = 'customers'::regclass;

-- Forced tables rewritten below that carry no foreign key to customers, so
-- their FORCE state is captured outside `customer_id_fks`.
CREATE TEMP TABLE customer_id_forced_extra (
    tbl regclass PRIMARY KEY,
    was_forced boolean NOT NULL
) ON COMMIT DROP;

-- Disable RI triggers on both sides, lift FORCE RLS on every table rewritten
-- in this file, and keep `audit_events`'s append-only guard off for the whole
-- window so the owning migration role sees every row and the identity
-- maintenance is not rejected as an audit mutation.
DO $$
DECLARE
    child RECORD;
BEGIN
    FOR child IN SELECT DISTINCT tbl FROM customer_id_fks ORDER BY tbl LOOP
        EXECUTE format('ALTER TABLE %s DISABLE TRIGGER ALL', child.tbl);
        EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY', child.tbl);
    END LOOP;
    ALTER TABLE customers DISABLE TRIGGER ALL;
    INSERT INTO customer_id_forced_extra (tbl, was_forced)
    SELECT c.oid, c.relforcerowsecurity
    FROM pg_class c
    WHERE c.oid = ANY (ARRAY[
        'outbox_events'::regclass,
        'feature_overrides'::regclass,
        'config_revisions'::regclass
    ]);
    ALTER TABLE outbox_events NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE feature_overrides NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE config_revisions NO FORCE ROW LEVEL SECURITY;
END $$;

DO $$
DECLARE
    child RECORD;
BEGIN
    FOR child IN SELECT tbl, col FROM customer_id_fks ORDER BY tbl, col LOOP
        EXECUTE format(
            'UPDATE %1$s t SET %2$I = m.new_id
             FROM customer_id_remap m WHERE t.%2$I = m.old_id',
            child.tbl,
            child.col
        );
    END LOOP;
END $$;

UPDATE customers c
SET id = m.new_id
FROM customer_id_remap m
WHERE c.id = m.old_id;

-- The window opened above stays in force across every rewrite below
-- (including the append-only `audit_events` statements) and is restored in
-- one step immediately before COMMIT.
-- Outbox events reference customers without a foreign key.
UPDATE outbox_events o
SET customer_id = m.new_id
FROM customer_id_remap m
WHERE o.customer_id = m.old_id;

UPDATE outbox_events o
SET payload = replace(
        o.payload::text,
        '"' || m.old_id || '"',
        '"' || m.new_id || '"'
    )::jsonb
FROM customer_id_remap m
WHERE o.payload IS NOT NULL
  AND o.payload::text LIKE '%"' || m.old_id || '"%';

-- Audit: scope column, impersonated customer, customer-resource IDs, and any
-- detail payload that echoes a customer identity verbatim.
UPDATE audit_events a
SET customer_id = m.new_id
FROM customer_id_remap m
WHERE a.customer_id = m.old_id;

UPDATE audit_events a
SET impersonated_customer = m.new_id
FROM customer_id_remap m
WHERE a.impersonated_customer = m.old_id;

UPDATE audit_events a
SET resource_id = m.new_id
FROM customer_id_remap m
WHERE a.resource_type = 'customer'
  AND a.resource_id = m.old_id;

UPDATE audit_events a
SET details = replace(
        a.details::text,
        '"' || m.old_id || '"',
        '"' || m.new_id || '"'
    )::jsonb
FROM customer_id_remap m
WHERE a.details IS NOT NULL
  AND a.details::text LIKE '%"' || m.old_id || '"%';

-- Tenant-scoped overrides and revisions key on the customer identity.
UPDATE feature_overrides f
SET scope_id = m.new_id
FROM customer_id_remap m
WHERE f.scope = 'tenant'
  AND f.scope_id = m.old_id;

UPDATE config_revisions r
SET scope_id = m.new_id
FROM customer_id_remap m
WHERE r.scope = 'tenant'
  AND r.scope_id = m.old_id;

-- Idempotency records embed the identity in operation keys
-- (`admin:customer:update:{id}` suffix and `admin:domain:add:{id}` style
-- segments) and echo it inside the stored replay envelope.
UPDATE idempotency_keys i
SET operation = left(i.operation, length(i.operation) - length(m.old_id)) || m.new_id
FROM customer_id_remap m
WHERE i.operation LIKE '%:' || m.old_id;

UPDATE idempotency_keys i
SET operation = replace(
        i.operation,
        ':' || m.old_id || ':',
        ':' || m.new_id || ':'
    )
FROM customer_id_remap m
WHERE i.operation LIKE '%:' || m.old_id || ':%';

UPDATE idempotency_keys i
SET result = replace(
        i.result::text,
        '"' || m.old_id || '"',
        '"' || m.new_id || '"'
    )::jsonb
FROM customer_id_remap m
WHERE i.result IS NOT NULL
  AND i.result::text LIKE '%"' || m.old_id || '"%';

-- Restore every trigger and FORCE RLS flag captured when the window opened.
DO $$
DECLARE
    child RECORD;
BEGIN
    FOR child IN SELECT DISTINCT tbl FROM customer_id_fks ORDER BY tbl LOOP
        EXECUTE format('ALTER TABLE %s ENABLE TRIGGER ALL', child.tbl);
    END LOOP;
    ALTER TABLE customers ENABLE TRIGGER ALL;
    FOR child IN
        SELECT tbl, was_forced FROM customer_id_fks WHERE was_forced ORDER BY tbl
    LOOP
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', child.tbl);
    END LOOP;
    FOR child IN
        SELECT tbl, was_forced FROM customer_id_forced_extra
        WHERE was_forced ORDER BY tbl
    LOOP
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', child.tbl);
    END LOOP;
END $$;

COMMIT;

-- Data the upgrade test carries across a migration chain.
--
-- A fresh install applies every migration to an empty schema, which is the one
-- case that cannot go wrong. The defects that reach operators need rows to be
-- there: an `ADD COLUMN ... NOT NULL` with no default, a unique index created
-- over rows that already violate it, a backfill reading a column it is about
-- to create, a type change that succeeds on zero rows.
--
-- Ids are fixed literals rather than generated, because the assertion after
-- the upgrade reads specific rows back by id. A count alone would pass over a
-- table that was dropped and repopulated with the same number of fabricated
-- rows, which is precisely the migration a real deployment cannot survive.
--
-- Written against the owner role (`aisoc`), which is also what applies the
-- migration chain. Every row carries `is_synthetic = true` where the column
-- exists, so a fixture can never be mistaken for a tenant's real state.

BEGIN;

INSERT INTO tenants (id, name, slug)
VALUES ('00000000-0000-0000-0000-0000000000aa', 'Upgrade Fixture Tenant', 'upgrade-fixture')
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, tenant_id, email, username, hashed_password)
VALUES (
    '33333333-3333-3333-3333-333333333333',
    '00000000-0000-0000-0000-0000000000aa',
    'fixture@example.com',          -- RFC 2606, unregistrable
    'upgrade-fixture',
    -- Not a usable credential: a deliberately invalid bcrypt-shaped string,
    -- so nothing can sign in as this row even if a fixture escaped into a
    -- real database.
    '$2b$12$invalid.fixture.hash.not.a.real.credential.000000000000'
)
ON CONFLICT (id) DO NOTHING;

-- One alert per severity, so a migration that rewrites the severity ladder or
-- adds a constraint to it meets every value rather than one.
INSERT INTO alerts (id, tenant_id, title, description, severity, status, is_synthetic)
VALUES
    ('11111111-1111-1111-1111-111111111111', '00000000-0000-0000-0000-0000000000aa',
     'pre-upgrade alert (critical)', 'Seeded before the migration chain ran.', 'critical', 'new', true),
    ('11111111-1111-1111-1111-111111111112', '00000000-0000-0000-0000-0000000000aa',
     'pre-upgrade alert (high)', 'Seeded before the migration chain ran.', 'high', 'investigating', true),
    ('11111111-1111-1111-1111-111111111113', '00000000-0000-0000-0000-0000000000aa',
     'pre-upgrade alert (medium)', 'Seeded before the migration chain ran.', 'medium', 'new', true),
    ('11111111-1111-1111-1111-111111111114', '00000000-0000-0000-0000-0000000000aa',
     'pre-upgrade alert (low)', 'Seeded before the migration chain ran.', 'low', 'closed', true),
    ('11111111-1111-1111-1111-111111111115', '00000000-0000-0000-0000-0000000000aa',
     'pre-upgrade alert (info)', 'Seeded before the migration chain ran.', 'info', 'closed', true)
ON CONFLICT (id) DO NOTHING;

-- The case table is named differently on either side of 083, which renames
-- `cases` to `cases_pre_consolidation` and consolidates into `aisoc_cases`.
-- This fixture runs against *the previous release's* schema, so which name
-- exists depends on which release that is: a hard-coded `cases` worked while
-- the previous release was 15.x and breaks the moment it is 16.x, under
-- `ON_ERROR_STOP=1`, with `relation "cases" does not exist`.
--
-- Resolving the name at run time rather than pinning either one keeps the
-- fixture working across the rename in both directions, which matters because
-- this is the one test whose whole job is to meet an older schema.
DO $$
DECLARE
    target text := COALESCE(
        to_regclass('public.aisoc_cases')::text,
        to_regclass('public.cases')::text
    );
BEGIN
    IF target IS NULL THEN
        RAISE EXCEPTION 'neither `aisoc_cases` nor `cases` exists; the previous '
                        'release applied no case table at all, which is not a '
                        'shape this fixture can seed';
    END IF;

    EXECUTE format(
        'INSERT INTO %I (id, tenant_id, case_number, title, description) '
        'VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING',
        target
    )
    USING '22222222-2222-2222-2222-222222222222'::uuid,
          '00000000-0000-0000-0000-0000000000aa'::uuid,
          'CASE-UPGRADE-0001',
          'pre-upgrade case',
          'Seeded before the migration chain ran, so a case-table migration meets a populated table.';

    RAISE NOTICE 'upgrade fixture seeded one case into %', target;
END
$$;

COMMIT;

\echo 'upgrade fixture: seeded 1 tenant, 1 user, 5 alerts, 1 case'

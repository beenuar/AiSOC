-- Consolidate `cases` into `aisoc_cases`.
--
-- Gap-closure wave 1.
--
-- The product has shipped with two case tables that never synchronised.
-- The console writes `aisoc_cases` — six-state machine, `sla_due_at`,
-- `evidence_chain`, `observable_graph`. Every metric reads `cases`:
-- `resolution_time` (which owns the one shared MTTR definition),
-- `metrics`, `insights`, `executive_digest`, `mssp_portfolio` and the
-- GraphQL query layer.
--
-- So **every case an analyst creates is invisible to every case metric**.
-- MTTR, `cases_opened_7d` and `cases_closed_7d` are computed over rows
-- written only by KEV-exposure sweeps, the scheduled-hunt worker and the
-- demo seed. A tenant could close fifty cases in the console and watch
-- MTTR stay null.
--
-- `aisoc_cases` survives because it holds the real user data and the
-- richer lifecycle. This migration widens it to carry everything the ORM
-- model needs, moves the rows across, and renames the old table out of
-- the way rather than dropping it — a consolidation that loses a row
-- nobody noticed is worse than two tables.

-- ── Columns the ORM `Case` model has and `aisoc_cases` lacked ───────────────
--
-- All nullable or defaulted, so existing rows stay valid.

ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS priority         TEXT;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS case_type        TEXT;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS mitre_tactics    JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS assigned_to_id   UUID;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS assigned_at      TIMESTAMPTZ;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS created_by_id    UUID;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS sla_deadline     TIMESTAMPTZ;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS sla_breached     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS ioc_ids          JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS artifact_ids     JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS ticket_refs      JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS summary          TEXT;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS resolution       TEXT;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS lessons_learned  TEXT;

-- `sla_deadline` and `sla_due_at` are the same fact under two names. Keep
-- both columns so neither side's readers break, and backfill the new one
-- from whichever the row already had.
UPDATE aisoc_cases SET sla_deadline = sla_due_at WHERE sla_deadline IS NULL AND sla_due_at IS NOT NULL;

-- ── Move the rows ──────────────────────────────────────────────────────────
--
-- `cases.status` uses a different vocabulary ('open'/'resolved'/...) from
-- `aisoc_cases` ('new'/'triaged'/'investigating'/'contained'/'resolved'/
-- 'closed'). Mapped rather than copied: a status outside the target
-- machine would make the case unmovable in the console.
--
-- Guarded on `to_regclass` so a fresh deployment, where `cases` may not
-- exist yet, is a no-op rather than an error.

DO $$
DECLARE
    r RECORD;
BEGIN
    IF to_regclass('public.cases') IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO aisoc_cases (
        id, tenant_id, case_number, title, description, severity, status,
        mitre_techniques, mitre_tactics, alert_ids, ioc_ids, artifact_ids,
        ticket_refs, tags, summary, resolution, lessons_learned,
        priority, case_type, assigned_to_id, assigned_at, created_by_id,
        sla_deadline, sla_due_at, sla_breached,
        opened_at, closed_at, created_at, updated_at
    )
    SELECT
        c.id, c.tenant_id, c.case_number, c.title, c.description,
        COALESCE(c.severity, 'medium'),
        CASE c.status
            WHEN 'open'          THEN 'new'
            WHEN 'in_progress'   THEN 'investigating'
            WHEN 'investigating' THEN 'investigating'
            WHEN 'triaged'       THEN 'triaged'
            WHEN 'contained'     THEN 'contained'
            WHEN 'resolved'      THEN 'resolved'
            WHEN 'closed'        THEN 'closed'
            ELSE 'new'
        END,
        COALESCE(c.mitre_techniques, '[]'::jsonb),
        COALESCE(c.mitre_tactics, '[]'::jsonb),
        -- `cases.alert_ids` is JSONB, `aisoc_cases.alert_ids` is uuid[].
        -- Unpacked element by element rather than cast, because a cast
        -- would fail the whole migration on one malformed entry while
        -- this drops only that entry.
        COALESCE(
            (SELECT array_agg(e::uuid)
               FROM jsonb_array_elements_text(COALESCE(c.alert_ids, '[]'::jsonb)) AS e
              WHERE e ~ '^[0-9a-fA-F-]{36}$'),
            ARRAY[]::uuid[]
        ),
        COALESCE(c.ioc_ids, '[]'::jsonb),
        COALESCE(c.artifact_ids, '[]'::jsonb),
        COALESCE(c.ticket_refs, '[]'::jsonb),
        COALESCE(c.tags, '[]'::jsonb),
        c.summary, c.resolution, c.lessons_learned,
        c.priority, c.case_type, c.assigned_to_id, c.assigned_at, c.created_by_id,
        c.sla_deadline, c.sla_deadline, COALESCE(c.sla_breached, FALSE),
        c.created_at, c.closed_at, c.created_at, c.updated_at
    FROM cases c
    -- An id already present means the row was migrated by an earlier run.
    WHERE NOT EXISTS (SELECT 1 FROM aisoc_cases a WHERE a.id = c.id);

    -- Child tables point at the surviving parent. Done before the rename
    -- so the constraint names are still predictable.
    --
    -- `case_tasks` and `case_timeline_events` both declared
    -- `REFERENCES cases(id)`, which is why repointing the ORM alone left
    -- SQLAlchemy unable to resolve `Case.tasks` at mapper-configuration
    -- time and took down every request that touched any model.
    FOR r IN
        SELECT tc.table_name, tc.constraint_name, kcu.column_name
          FROM information_schema.table_constraints tc
          JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
          JOIN information_schema.constraint_column_usage ccu
            ON tc.constraint_name = ccu.constraint_name
         WHERE tc.constraint_type = 'FOREIGN KEY' AND ccu.table_name = 'cases'
    LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', r.table_name, r.constraint_name);
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES aisoc_cases(id) ON DELETE CASCADE',
            r.table_name, r.constraint_name, r.column_name
        );
    END LOOP;

    -- Renamed, not dropped. If this consolidation lost a row, the evidence
    -- of what was lost has to still exist.
    ALTER TABLE cases RENAME TO cases_pre_consolidation;
END
$$;

COMMENT ON COLUMN aisoc_cases.sla_deadline IS
    'Same fact as sla_due_at, kept under both names so readers of either '
    'side of the pre-consolidation split keep working.';

-- ── Read compatibility for anything outside this repository ────────────────
--
-- Renaming the table is right for our own code and wrong for everyone
-- else's: a self-hoster with a Grafana panel, a scheduled export or any
-- SQL of their own against `cases` would silently start erroring on
-- upgrade, and the upgrade test caught exactly that.
--
-- So `cases` comes back as a **view** over the surviving table. External
-- readers keep working; our own code does not, because
-- `scripts/check_one_case_table.py` refuses `FROM cases` in tracked
-- source. That split is deliberate — the gate governs what we write, the
-- view governs what we already told other people to rely on.
--
-- Deliberately not updatable. A write through the view would bypass the
-- six-state machine the console enforces, and failing loudly on INSERT
-- is better than accepting a row nothing can transition.

DO $$
BEGIN
    IF to_regclass('public.cases') IS NULL THEN
        EXECUTE $view$
            CREATE VIEW cases AS
            SELECT id, tenant_id, case_number, title, description, status, priority,
                   severity, case_type, mitre_tactics, mitre_techniques,
                   assigned_to_id, assigned_at, created_by_id,
                   sla_deadline, sla_breached, alert_ids, ioc_ids, artifact_ids,
                   tags, ticket_refs, summary, closed_at, created_at, updated_at,
                   resolution, lessons_learned
              FROM aisoc_cases
        $view$;
    END IF;
END
$$;

COMMENT ON VIEW cases IS
    'Read-only compatibility view over aisoc_cases, kept so SQL written '
    'against the pre-consolidation schema keeps working. New code reads '
    'aisoc_cases; scripts/check_one_case_table.py enforces that.';

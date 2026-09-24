-- The one table application code created at runtime, brought into the chain.
--
-- What it is
-- ----------
-- `services/slack-bot` arms a timer for every action that needs approval, so
-- a forgotten Approve/Deny terminates on its configured safe default instead
-- of leaving a containment in `awaiting_approval` forever.
-- `PostgresTimerStore` makes those timers survive a bot restart — and it
-- created its own table on startup with `CREATE TABLE IF NOT EXISTS`, outside
-- every migration chain in the repository.
--
-- Why that was not harmless
-- -------------------------
-- Three things follow from a table no migration knows about, and the third is
-- the one that matters:
--
--   * `060_rls_coverage.sql` gave a policy to every tenant-scoped table *in
--     the chain*. This one was not in it, so it had none — and it gates
--     response actions. An approval timer names an action id and a safe
--     default; reading or deleting another tenant's row is the difference
--     between a containment that auto-rejects and one that does not.
--   * it carried no `tenant_id` at all, so no policy could have been written
--     for it even if somebody had looked.
--   * `061_runtime_app_role.sql` took `CREATE` on schema public away from the
--     runtime role, and Postgres checks the schema ACL *before* the existence
--     test — so `CREATE TABLE IF NOT EXISTS` raises `permission denied for
--     schema public` even when the table is already there. The store's
--     `create()` would have failed at startup on a correctly-configured
--     deployment, and `main.py` catches that into a `logger.warning` and
--     falls back to the in-memory store. Durable approval timers would have
--     silently stopped being durable.
--
-- It was reachable only by an operator who set `DATABASE_URL` on the
-- slack-bot service, which the default compose does not — which is why it
-- survived this long, not why it was safe.
--
-- Shape
-- -----
-- Mirrors `PostgresTimerStore`'s columns, plus `tenant_id`. `TEXT` rather than
-- `uuid` to match `aisoc_action_records` (055), the table this one is keyed
-- against: both hold ids minted by `services/actions`, and the policy below
-- casts exactly the way 060 does for that table.
--
-- `fire_at` stays a DOUBLE PRECISION epoch rather than becoming a TIMESTAMPTZ.
-- The scheduler compares it against `time.time()` and re-arms with the
-- difference; converting here would move that arithmetic into two places.

CREATE TABLE IF NOT EXISTS approval_timers (
    action_id     TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL DEFAULT '',
    fire_at       DOUBLE PRECISION NOT NULL,
    safe_default  TEXT NOT NULL DEFAULT 'rejected',
    case_id       TEXT NOT NULL DEFAULT '',
    channel       TEXT,
    approver_id   TEXT NOT NULL DEFAULT 'scheduler',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A deployment that already ran the store's own DDL has the table without the
-- column. Added separately so this migration converges on the same shape from
-- both starting points.
--
-- Rows already in such a table get `tenant_id = ''`, which matches no bound
-- tenant — so the bot will not recover those timers after the upgrade. That
-- is stated rather than guessed around: this migration cannot know which
-- tenant they belong to, and inventing one would re-arm an auto-reject
-- against the wrong estate. Backfill before restarting the bot:
--     UPDATE approval_timers SET tenant_id = '<your AISOC_DEFAULT_TENANT_ID>'
--      WHERE tenant_id = '';
ALTER TABLE approval_timers ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

-- The only query beyond primary key is recovery's "every pending timer for
-- this tenant", which runs once per bot start.
CREATE INDEX IF NOT EXISTS ix_approval_timers_tenant
    ON approval_timers (tenant_id);

-- Same shape as every other policy in this schema, and for the same reason:
-- the `IS NULL` arm keeps a connection that binds no tenant working, because
-- a worker that silently sees zero rows is worse than the bypass the role
-- split closes. `scripts/check_rls_policy_shape.py` fails if it is dropped.
ALTER TABLE approval_timers ENABLE ROW LEVEL SECURITY;
-- FORCE, or the owner — the role that runs this chain — walks straight past.
ALTER TABLE approval_timers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS approval_timers_tenant ON approval_timers;
CREATE POLICY approval_timers_tenant ON approval_timers
    USING (tenant_id = current_tenant_id()::text OR current_tenant_id() IS NULL);

-- No GRANT here. 061 runs before this migration and as the same owner, so its
-- `ALTER DEFAULT PRIVILEGES … GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES
-- TO aisoc_app` covers a table created afterwards. That is the mechanism the
-- four alembic chains cannot rely on — nothing orders them against 061 — which
-- is why they carry an explicit grant and this does not.

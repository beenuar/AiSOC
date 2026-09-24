-- The role the services connect as, so that the row-level security policies
-- 060_rls_coverage.sql added are something other than decoration.
--
-- What 060 left undone
-- --------------------
-- 060 took RLS from 31 of 95 tenant-scoped tables to 92, and measured that
-- not one of those policies filtered anything in the default deployment:
-- docker-compose.yml and the CI service containers run every service as
-- POSTGRES_USER=aisoc, which the postgres image creates as a SUPERUSER, and a
-- superuser ignores policies *even under* FORCE ROW LEVEL SECURITY — FORCE
-- binds the table owner, not a superuser. Seeded one alert per tenant and
-- bound the session to tenant A: `aisoc` saw 2 rows, a NOSUPERUSER
-- NOBYPASSRLS role saw 1.
--
-- 060 deliberately stopped there, because switching the connection role needs
-- a password and a grant review that belong to a deployment rather than to a
-- schema change. This migration does the grant review. The password is still
-- the deployment's (see "No credential is set here").
--
-- The role model
-- --------------
--   owner / migration role   `aisoc` (POSTGRES_USER). Owns every table, runs
--                            DDL, applies this chain. Superuser in the
--                            bundled Postgres; needs only table ownership and
--                            CREATE on the schema in a managed one.
--   runtime role             `aisoc_app`. Every service's DATABASE_URL. DML
--                            only: it can read and write rows and it cannot
--                            reach around a policy.
--
-- Separating them is the whole mechanism. Migrations legitimately need DDL;
-- the services do not, and a role that can ALTER a table can also
-- `ALTER TABLE … NO FORCE ROW LEVEL SECURITY`, which is a bypass with extra
-- steps. So `aisoc_app` owns nothing, and the gate
-- `scripts/check_runtime_db_role.py` fails if it ever does.
--
-- The minimum grants, worked out by measurement rather than by copying a
-- template
-- ------------------------------------------------------------------------
--   USAGE   on schema public        — without it every object reference fails.
--                                     NOT CREATE: see the note on runtime DDL.
--   SELECT, INSERT, UPDATE, DELETE  on tables and views. No TRUNCATE (nothing
--                                     outside migrations and tests issues
--                                     one), no REFERENCES, no TRIGGER.
--   USAGE, SELECT on sequences      — this chain currently defines none, every
--                                     key being a uuid. Granted anyway so the
--                                     first `BIGSERIAL` somebody adds does not
--                                     fail at 3am; `USAGE` is what `nextval`
--                                     needs and `SELECT` what `currval` does.
--   EXECUTE on functions            — PUBLIC already holds this by default, so
--                                     it changes nothing on a stock database.
--                                     It is spelled out because a hardened
--                                     deployment that runs
--                                     `REVOKE ALL ON ALL FUNCTIONS FROM PUBLIC`
--                                     would otherwise break RLS itself:
--                                     `current_tenant_id()` is evaluated as the
--                                     querying role inside every policy.
--
-- 002_rls.sql granted `ALL` on all tables and sequences. That included
-- TRUNCATE, which lets a role delete every tenant's rows in one statement
-- without a policy ever seeing a WHERE clause. It is revoked below.
--
-- Two views were reading around the policies
-- ------------------------------------------
-- A view executes its underlying reads as the *view's owner* unless it is
-- declared `security_invoker`. Both views in this schema are owned by the
-- superuser that ran the chain, so `mssp_tenant_latest_metrics` and
-- `mssp_effective_tenant_rules` would have kept returning every tenant's rows
-- to `aisoc_app` after the role switch — a bypass that survives the fix that
-- is supposed to close it. Neither view has a caller in the tree today, which
-- is why nobody noticed. Both are switched to `security_invoker` here, and the
-- gate checks views as well as tables so the next one cannot repeat it.
--
-- Cross-tenant work still works, and that is deliberate
-- -----------------------------------------------------
-- Every policy in this schema is `tenant_id = current_tenant_id() OR
-- current_tenant_id() IS NULL` — fail-open on a session that never bound a
-- tenant. Ingest, fusion, the retention purge, the hunt scheduler's sweep and
-- tenant deletion all run on such a session and keep seeing every tenant.
-- That arm is load-bearing rather than incidental: without it those workers
-- would silently process nothing, which is a worse failure than the bypass
-- this migration closes. `scripts/check_rls_policy_shape.py` fails if a policy
-- is added without it.
--
-- One construct does *not* survive the switch: `SET LOCAL row_security = off`.
-- For a role that is neither superuser nor exempt, Postgres does not ignore
-- policies when row security is off — it raises `query would be affected by
-- row-level security policy for table "…"`. Three call sites used it to
-- enumerate tenants and now rely on the unbound-session arm instead, with an
-- explicit precondition check so a bound tenant on a cross-tenant sweep is
-- reported rather than acted on.
--
-- No credential is set here
-- -------------------------
-- A migration in a public repository must not carry a password, and this one
-- does not set or clear one: an operator who has already configured
-- `aisoc_app` keeps their credential. 002_rls.sql did create the role with the
-- literal `changeme`; the compose stack now overwrites that on first boot from
-- `AISOC_APP_DB_PASSWORD`, CI provisions its own, and
-- `scripts/check_runtime_db_role.py --dsn` proves a live deployment is not
-- still on it by trying to log in with it.

-- ─── 1. The runtime role exists and cannot reach around a policy ─────────────
-- Created NOLOGIN with no password when absent, so a half-configured
-- deployment fails at connect time instead of coming up on a credential that
-- is public knowledge. Attributes are re-asserted on every apply: this is the
-- security property, and re-applying must converge on it however the role got
-- into its current state.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        CREATE ROLE aisoc_app NOLOGIN;
        RAISE NOTICE 'created role aisoc_app (NOLOGIN). Set a password and LOGIN before pointing DATABASE_URL at it.';
    END IF;
END
$$;

ALTER ROLE aisoc_app
    WITH NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;

COMMENT ON ROLE aisoc_app IS
    'AiSOC runtime role: DML only, subject to row-level security. Migrations run as the table owner, not as this role.';

-- ─── 2. Minimum grants ───────────────────────────────────────────────────────
-- REVOKE first so re-applying this migration narrows a widened grant rather
-- than layering a second one on top of it. Written against ALL TABLES /
-- ALL SEQUENCES rather than a list, because a list is a naming convention with
-- extra steps and the next migration would not be on it.

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM aisoc_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM aisoc_app;
REVOKE ALL ON SCHEMA public FROM aisoc_app;

GRANT USAGE ON SCHEMA public TO aisoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aisoc_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aisoc_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO aisoc_app;

-- Objects a later migration creates. These are recorded against the role that
-- runs this statement, which is the role that runs the chain — the same role
-- that will create those objects. A deployment that changes its migration role
-- must re-run this migration as the new one, and the gate's live mode reports
-- the resulting gap as a missing grant rather than leaving it to be discovered
-- by a 500.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM aisoc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM aisoc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aisoc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO aisoc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO aisoc_app;

-- ─── 3. Close the two views that read as their owner ─────────────────────────
-- `security_invoker` is Postgres 15+. Every deployment surface in this repo
-- provisions 16 (compose `postgres:16-alpine`, CI `postgres:16`, the RDS and
-- Cloud SQL modules `16.x`), so this is a floor the tree already had rather
-- than one this migration introduces. Guarded by `to_regclass` so the
-- statement is skipped rather than fatal on a database that predates the two
-- MSSP views.

DO $$
BEGIN
    IF to_regclass('public.mssp_tenant_latest_metrics') IS NOT NULL THEN
        EXECUTE 'ALTER VIEW public.mssp_tenant_latest_metrics SET (security_invoker = true)';
    END IF;
    IF to_regclass('public.mssp_effective_tenant_rules') IS NOT NULL THEN
        EXECUTE 'ALTER VIEW public.mssp_effective_tenant_rules SET (security_invoker = true)';
    END IF;
END
$$;

-- ─── 4. Refuse to report success on a role that can still bypass ─────────────
-- The failure this migration exists to prevent is a policy that reads as
-- protection and filters nothing. Asserting the outcome here means a chain
-- that applied "successfully" cannot have left that state behind — including
-- on a managed Postgres where `aisoc_app` was pre-created by someone else with
-- attributes this migration would otherwise have quietly left alone.

DO $$
DECLARE
    bad  text;
    owns text;
BEGIN
    SELECT string_agg(flag, ', ') INTO bad FROM (
        SELECT 'SUPERUSER' AS flag FROM pg_roles WHERE rolname = 'aisoc_app' AND rolsuper
        UNION ALL
        SELECT 'BYPASSRLS' FROM pg_roles WHERE rolname = 'aisoc_app' AND rolbypassrls
    ) f;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'aisoc_app still holds % — every RLS policy in this database would be bypassed', bad;
    END IF;

    SELECT string_agg(c.relname, ', ') INTO owns
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'v', 'm', 'p')
       AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'aisoc_app');
    IF owns IS NOT NULL THEN
        RAISE EXCEPTION 'aisoc_app owns %, and an owner can ALTER TABLE … NO FORCE ROW LEVEL SECURITY', owns;
    END IF;
END
$$;

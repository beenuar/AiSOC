-- Migration 035: Bidirectional ITSM ticket linkage (Workstream 8)
--
-- ``case_external_refs`` records the mapping between an AiSOC case and an
-- external ticketing system (Jira, ServiceNow, Linear, etc.). One AiSOC
-- case may have multiple external refs — a single security incident can
-- legitimately fan out to a Jira issue (for the engineering owner), a
-- ServiceNow incident (for the SOC's audit trail), and an internal
-- workflow ticket (for the IR team).
--
-- The table replaces the loose ``ticket_refs`` JSONB column on
-- ``aisoc_cases``: that column is fine for the read path ("show me the
-- list of tickets attached to this case") but it doesn't scale once you
-- need:
--
--   * uniqueness (don't re-create the same Jira issue if the worker
--     retries after a transient 502 — the ``UNIQUE (connector_instance_id,
--     external_id)`` constraint below makes that impossible);
--   * inbound lookups ("a ServiceNow webhook just told us
--     ``incident:INC0010023`` was closed — which AiSOC case does that
--     map to?" — answered by a single index hit on
--     ``(connector_instance_id, external_id)``);
--   * audit ("who pushed this case to which system, and when?").
--
-- Columns:
--   id                      stable PK so timeline events can reference a ref
--   case_id                 the AiSOC case (FK + cascade for tenant deletion)
--   connector_instance_id   the per-tenant connector row that did the push;
--                           ties the ref to a specific Jira project / ServiceNow
--                           instance / etc., not just to the connector class.
--   vendor                  denormalised connector_id ("jira", "servicenow")
--                           so dashboards can group by vendor without joining.
--   external_id             vendor's stable handle (Jira issue key, ServiceNow
--                           sys_id, etc.). Together with connector_instance_id
--                           this uniquely identifies the external ticket.
--   external_url            best-effort link the operator can click. May be
--                           NULL on systems that don't expose a stable URL.
--   external_status         last known status on the external side. Used by
--                           the actions worker to short-circuit no-op
--                           ``push_status_change`` calls when the external
--                           system already reflects the desired state.
--   created_at / updated_at audit timestamps.
--   pushed_by               user/email that triggered the most recent write.
--   last_synced_at          last successful inbound or outbound sync;
--                           drives the "stale ticket" health check.

BEGIN;

CREATE TABLE IF NOT EXISTS case_external_refs (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id                  UUID NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    connector_instance_id    UUID NOT NULL,
    vendor                   VARCHAR(64) NOT NULL,
    external_id              VARCHAR(255) NOT NULL,
    external_url             TEXT,
    external_status          VARCHAR(64),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pushed_by                TEXT,
    last_synced_at           TIMESTAMPTZ,
    -- Same external ticket should never be linked twice from the same
    -- connector instance — the worker MUST treat retries as idempotent.
    CONSTRAINT case_external_refs_unique_pair
        UNIQUE (connector_instance_id, external_id)
);

-- Forward lookup: "show me every external ticket for case X" — used by
-- the timeline view and the close-out fan-out worker.
CREATE INDEX IF NOT EXISTS case_external_refs_case_idx
    ON case_external_refs (case_id);

-- Reverse lookup: "an inbound webhook just told us
-- ``connector_instance=...`` and ``external_id=INC0010023`` — find the
-- AiSOC case to update". The unique constraint above already creates
-- the index, so we don't need a separate one for this path.

-- Vendor-level dashboards: "how many cases did we sync to Jira this
-- week?". Cheap GIN-style query without scanning the whole table.
CREATE INDEX IF NOT EXISTS case_external_refs_vendor_idx
    ON case_external_refs (vendor);

-- Auto-bump ``updated_at`` on every row update so the actions worker
-- doesn't have to remember to set it. We reuse the project's existing
-- ``set_updated_at`` trigger function (from migration 001) when present;
-- fall back to defining it locally otherwise so this migration is
-- self-contained for fresh installs.
DO $do$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc WHERE proname = 'set_updated_at'
    ) THEN
        CREATE FUNCTION set_updated_at() RETURNS TRIGGER AS $fn$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $fn$ LANGUAGE plpgsql;
    END IF;
END
$do$;

DROP TRIGGER IF EXISTS case_external_refs_set_updated_at ON case_external_refs;
CREATE TRIGGER case_external_refs_set_updated_at
    BEFORE UPDATE ON case_external_refs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  case_external_refs              IS 'WS8: AiSOC case ↔ external ticket mapping (Jira/ServiceNow/etc.).';
COMMENT ON COLUMN case_external_refs.connector_instance_id IS 'Row in connectors table that owns the push; ties ref to a specific Jira project / ServiceNow instance.';
COMMENT ON COLUMN case_external_refs.external_id  IS 'Vendor handle (Jira issue key, ServiceNow sys_id, etc.). Unique per connector instance.';
COMMENT ON COLUMN case_external_refs.external_status IS 'Last known status on the external side; used to short-circuit no-op status pushes.';

COMMIT;

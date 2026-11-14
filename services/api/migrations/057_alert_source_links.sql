-- Alert <-> source-finding reconciliation, so the loop can close both ways.
--
-- Ingest already knows the vendor's own identifier for a finding: the
-- normalizer maps `external_id` onto OCSF `finding.uid` for every connector
-- that emits a canonical envelope. Nothing downstream kept it. By the time a
-- row reached `alerts` the Splunk notable's rule UID, the Elastic signal id
-- and the QRadar offense id had all been discarded, so there was no way to
-- answer "which finding produced this alert" — and therefore no way to write
-- a verdict back to it.
--
-- Two additions, deliberately separate:
--
--   `alerts.external_id` is the denormalised join key. One per alert, on the
--   row itself, because it is read on every alert fetch and a join for a
--   single string would be the wrong shape.
--
--   `alert_source_links` is the reconciliation record: which connector
--   instance produced the finding, what was last written back to it, when,
--   and whether that write actually executed or was a dry run. It is a
--   separate table because one alert can legitimately be linked to findings
--   in more than one system (a Splunk notable and the ServiceNow ticket the
--   SOC raised from it), and because the writeback audit trail grows per
--   attempt while the alert row does not.
--
-- `executed` is the column that keeps this honest. A dry run writes a row
-- exactly like a live call does — same disposition, same plan, same
-- timestamp — and the only thing distinguishing them is this boolean. It has
-- no default: a writer that forgets to say which it was gets an error rather
-- than a row that reads as executed.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS external_id TEXT;

COMMENT ON COLUMN alerts.external_id IS
    'The source system''s own identifier for the finding that produced this alert (Splunk notable rule UID, Elastic signal id, Sentinel incident name, QRadar offense id). NULL when the alert did not originate from a vendor finding.';

-- Writeback resolves an alert by (tenant, external id), and dedup of repeat
-- deliveries reads the same pair. Partial because most alerts have no vendor
-- finding behind them and indexing their NULLs would be dead weight.
CREATE INDEX IF NOT EXISTS idx_alerts_external_id
    ON alerts (tenant_id, external_id)
    WHERE external_id IS NOT NULL;


CREATE TABLE IF NOT EXISTS alert_source_links (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id                UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,

    -- Which system the finding lives in, and which configured instance of it.
    -- `vendor` is the live-actions vendor id ('splunk', 'elastic', 'sentinel',
    -- 'qradar', 'defender'), not the connector type, because that is what the
    -- dispatcher routes on.
    vendor                  TEXT NOT NULL,
    connector_instance_id   UUID,

    -- The vendor's identifier for the finding. The join key.
    external_id             TEXT NOT NULL,
    external_url            TEXT,

    -- Last writeback attempt.
    last_disposition        TEXT,
    last_writeback_action   TEXT,
    last_writeback_status   TEXT,
    last_writeback_at       TIMESTAMPTZ,
    last_writeback_detail   TEXT,

    -- FALSE means nothing reached the vendor: a dry run, a refusal, or a
    -- simulation for want of credentials. No default on purpose.
    executed                BOOLEAN NOT NULL,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One link per (alert, vendor, finding). A repeat writeback for the same
    -- verdict updates in place rather than growing an unbounded log — the
    -- durable history of who decided what lives in the investigation ledger,
    -- and duplicating it here would give two sources of truth that drift.
    CONSTRAINT uq_alert_source_link UNIQUE (alert_id, vendor, external_id)
);

COMMENT ON TABLE alert_source_links IS
    'Reconciles an AiSOC alert with the vendor finding that produced it, and records what was last written back to that finding.';
COMMENT ON COLUMN alert_source_links.executed IS
    'TRUE only when a vendor call actually ran. FALSE for dry runs, refusals and credential-less simulations, so an unexecuted writeback can never be read as an executed one.';

CREATE INDEX IF NOT EXISTS idx_alert_source_links_alert
    ON alert_source_links (alert_id);

-- The writeback path's own lookup: "given this tenant and this vendor finding,
-- which alert is it". Also what a connector poll uses to dedup a re-delivered
-- finding.
CREATE INDEX IF NOT EXISTS idx_alert_source_links_lookup
    ON alert_source_links (tenant_id, vendor, external_id);

-- Row-level security mirrors the rest of the schema. The API additionally
-- filters by tenant_id in every WHERE clause; RLS is defence in depth, not
-- the only control.
ALTER TABLE alert_source_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_source_links FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS alert_source_links_tenant ON alert_source_links;
CREATE POLICY alert_source_links_tenant ON alert_source_links
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

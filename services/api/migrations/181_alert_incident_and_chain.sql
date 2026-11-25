-- Make fusion's grouping durable on the alert row.
--
-- Fusion computes two groupings for every alert and persisted neither.
-- `Correlator.correlate` assigns an incident id, which lives in Redis under
-- `correlation_window_seconds` (3600s default) and is gone after that.
-- `AttackChainGrouper` assigns a kill-chain story — a chain id, a 1-based
-- position and the alert's stage — which rode along in
-- `FusedAlert.enrichments` into Kafka and the narrative prose, and into no
-- column at all.
--
-- The cost of that was paid downstream: `aisoc_attack_chains` re-derives
-- relationships from scratch with a depth-3 graph walk over the denormalised
-- `affected_*` arrays, because the grouping fusion had already computed was
-- not available to read back.
--
-- All four columns are nullable on purpose. An alert fusion did not place in
-- a story genuinely has no chain, and NULL says that; a position of 0 or 1
-- would read as a real placement in a story of one.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS incident_id    UUID,
    ADD COLUMN IF NOT EXISTS chain_id       VARCHAR(128),
    ADD COLUMN IF NOT EXISTS chain_position INTEGER,
    ADD COLUMN IF NOT EXISTS chain_stage    VARCHAR(64);

-- A position only means something inside a chain, and only from 1 up.
-- Written as a NOT VALID constraint so the migration does not scan the
-- existing table: every pre-existing row has NULL in both columns and
-- satisfies it trivially, while every new write is checked.
ALTER TABLE alerts
    DROP CONSTRAINT IF EXISTS alerts_chain_position_requires_chain;
ALTER TABLE alerts
    ADD CONSTRAINT alerts_chain_position_requires_chain
    CHECK (
        chain_position IS NULL
        OR (chain_id IS NOT NULL AND chain_position >= 1)
    ) NOT VALID;

-- The timeline reads "every alert of this incident, oldest first" and
-- "every alert of this story, in order". Both are tenant-scoped, so the
-- tenant leads each index.
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_incident_time
    ON alerts (tenant_id, incident_id, event_time)
    WHERE incident_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_chain_position
    ON alerts (tenant_id, chain_id, chain_position)
    WHERE chain_id IS NOT NULL;

COMMENT ON COLUMN alerts.incident_id IS
    'Fusion''s correlation grouping, durable. Alerts sharing this id were correlated into one incident by Correlator.correlate.';
COMMENT ON COLUMN alerts.chain_id IS
    'Attack-story grouping from AttackChainGrouper. NULL when this alert joined no story.';
COMMENT ON COLUMN alerts.chain_position IS
    '1-based position of this alert within its attack story. NULL without a chain_id.';
COMMENT ON COLUMN alerts.chain_stage IS
    'This alert''s kill-chain stage within its story (reconnaissance .. impact).';

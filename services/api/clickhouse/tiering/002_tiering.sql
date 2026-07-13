-- Phase D2 — hot/warm/cold tiering for the event lake.
--
-- OPT-IN. Apply AFTER mounting tiering/storage-policy.xml into
-- /etc/clickhouse-server/config.d/ (so the `tiered` storage policy exists) and
-- AFTER 001_init.sql has created aisoc.raw_events. Applying it without the
-- storage policy will error, which is why it is NOT in the init path.
--
-- What it does:
--   * Rebinds aisoc.raw_events onto the `tiered` storage policy.
--   * Extends the TTL into a tiered lifecycle: rows stay on the hot (NVMe)
--     volume for 30 days, MOVE to the cold (object/NAS) volume for days 30-90,
--     then DELETE at 90 days. The hot window keeps hunt/Explore latency low;
--     the cold window keeps 90-day retention cheap.
--
-- Cost model: docs/decisions/storage-cost-model.json + scripts/storage_cost_model.py.

ALTER TABLE aisoc.raw_events
    MODIFY SETTING storage_policy = 'tiered';

ALTER TABLE aisoc.raw_events
    MODIFY TTL
        toDateTime(event_time) + INTERVAL 30 DAY TO VOLUME 'cold',
        toDateTime(event_time) + INTERVAL 90 DAY DELETE;

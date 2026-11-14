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
--     volume for 30 days, MOVE to the cold (object/S3) volume for the rest of
--     the ceiling, then DELETE at the ceiling. The hot window keeps
--     hunt/Explore latency low; the cold window is what makes a long window
--     affordable.
--
--   * Tiering is a STORAGE decision and must not shorten retention. The
--     DELETE here was 90 days while the table's own ceiling was 90 as well;
--     with the ceiling at 400 (see 001_init.sql and `MAX_LAKE_DAYS`) an
--     operator who applied this file used to silently cut their tenants'
--     retention by 310 days as a side effect of moving data to cheaper disk.
--     The two numbers are held equal by scripts/check_retention_window.py.
--
-- Cost model: docs/decisions/storage-cost-model.json + scripts/storage_cost_model.py.

ALTER TABLE aisoc.raw_events
    MODIFY SETTING storage_policy = 'tiered';

ALTER TABLE aisoc.raw_events
    MODIFY TTL
        toDateTime(event_time) + INTERVAL 30 DAY TO VOLUME 'cold',
        toDateTime(event_time) + INTERVAL 400 DAY DELETE;

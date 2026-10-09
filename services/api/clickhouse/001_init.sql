-- AiSOC ClickHouse init: raw events + metrics
-- Runs at container start via /docker-entrypoint-initdb.d

CREATE DATABASE IF NOT EXISTS aisoc;

-- ──────────────────────────────────────────────────────────────────────────────
-- Raw OCSF events.
--
-- The TTL below is a CEILING, not a retention policy. It used to be 90 days,
-- which meant a tenant who chose 400 days in the console — and whose policy
-- row said 400 — lost every event at day 90, with nothing erroring and the
-- console still showing their setting. ClickHouse enforces a table TTL during
-- merges and knows nothing about per-tenant policy.
--
-- So the table keeps rows for as long as the longest window anyone may choose
-- (`MAX_LAKE_DAYS` in services/api/app/services/retention.py), and the
-- per-tenant window is enforced above it by app/workers/retention_purge.py.
-- The two numbers are held equal by scripts/check_retention_window.py.
--
-- What that means operationally, said plainly: on a deployment where the
-- purge worker is not armed (it is off and in dry-run by default) the lake
-- now grows for 400 days rather than 90. Arm the worker, or lower both
-- numbers together.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aisoc.raw_events (
    event_id        UUID DEFAULT generateUUIDv4(),
    tenant_id       UUID,
    event_time      DateTime64(3, 'UTC'),
    ingest_time     DateTime64(3, 'UTC') DEFAULT now64(),
    class_uid       UInt32,
    category_uid    UInt32,
    severity_id     UInt8,
    severity        String,
    activity_id     UInt32,
    source_ip       IPv6,
    dest_ip         IPv6,
    src_port        UInt16,
    dst_port        UInt16,
    protocol        String,
    src_hostname    String,
    dst_hostname    String,
    user_name       String,
    process_name    String,
    file_path       String,
    hash_sha256     String,
    connector_type  String,
    raw_payload     String CODEC(ZSTD(3)),
    ocsf_json       String CODEC(ZSTD(3)),
    mitre_techniques Array(String),
    mitre_tactics   Array(String),
    iocs            Array(String),
    -- The activity projection (depth plan 2.2). Ingest answers five
    -- questions on every event and the lake carries the answers as columns
    -- rather than only inside ocsf_json, so a hunt for "every action by a
    -- non-human actor from a new ASN" is not a full scan of a ZSTD blob.
    --
    -- Kept in lockstep with lake_migrations.py's 002_activity_projection,
    -- which is what an *existing* deployment applies: this file only runs in
    -- the container entrypoint on a fresh volume, so a column added here
    -- alone would land on new deployments and silently not on old ones.
    actor_kind      LowCardinality(String) DEFAULT '',
    actor_kind_source String DEFAULT '',
    actor_id        String DEFAULT '',
    actor_on_behalf_of String DEFAULT '',
    action          String DEFAULT '',
    resource_type   String DEFAULT '',
    resource_id     String DEFAULT '',
    resource_owner  String DEFAULT '',
    src_country_code LowCardinality(String) DEFAULT '',
    src_asn         UInt32 DEFAULT 0,
    src_as_org      String DEFAULT '',
    src_reputation  Float32 DEFAULT 0,
    -- Zero and "nobody answered" are different facts: without this flag a
    -- clean verdict and an unreachable enrichment service are the same row.
    src_reputation_known UInt8 DEFAULT 0,
    client_family   LowCardinality(String) DEFAULT '',
    client_version  String DEFAULT '',
    client_category LowCardinality(String) DEFAULT '',
    -- The raw user agent beside the parse: it is attacker-controlled, every
    -- parser is a lossy summary, and a tool renamed to "Mozilla/5.0" is
    -- itself the finding.
    client_raw      String DEFAULT '',
    outcome         LowCardinality(String) DEFAULT '',
    -- Data-skipping (bloom-filter) indexes so hunts over high-cardinality
    -- needles (file hash, user, host, IOCs) skip granules instead of scanning
    -- the whole ZSTD blob. GRANULARITY 4 = one index block per 4 * 8192 rows.
    INDEX idx_hash hash_sha256 TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_user user_name TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_src_host src_hostname TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_iocs iocs TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_techniques mitre_techniques TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_resource_id resource_id TYPE bloom_filter(0.01) GRANULARITY 4
)
-- ReplacingMergeTree collapses rows sharing the ORDER BY key, keeping the row
-- with the greatest ingest_time. Ingest now stamps a replay-stable event_id
-- (derived from tenant + connector + vendor id), so overlapping connector
-- polls / backfills / Kafka replays of the same event dedup on merge instead of
-- accumulating duplicate lake rows. Queries needing exact-once before a merge
-- can still use `FINAL` or `LIMIT 1 BY event_id`.
ENGINE = ReplacingMergeTree(ingest_time)
PARTITION BY (toYYYYMM(event_time), tenant_id)
ORDER BY (tenant_id, event_time, class_uid, event_id)
TTL toDateTime(event_time) + INTERVAL 400 DAY
SETTINGS index_granularity = 8192;

-- ──────────────────────────────────────────────────────────────────────────────
-- Alert metrics for dashboards
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aisoc.alert_metrics (
    ts              DateTime DEFAULT now(),
    tenant_id       UUID,
    severity        String,
    connector_type  String,
    mitre_tactic    String,
    count           UInt64,
    avg_score       Float32
) ENGINE = SummingMergeTree(count)
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, toStartOfHour(ts), severity, connector_type, mitre_tactic)
TTL ts + INTERVAL 365 DAY;

-- ──────────────────────────────────────────────────────────────────────────────
-- IOC lookup table (append-only enrichment cache)
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aisoc.ioc_enrichments (
    ioc_value       String,
    ioc_type        String,
    tenant_id       UUID,
    malicious       UInt8,
    confidence      Float32,
    sources         Array(String),
    tags            Array(String),
    country         String,
    asn             UInt32,
    enriched_at     DateTime64(3, 'UTC') DEFAULT now64()
) ENGINE = ReplacingMergeTree(enriched_at)
ORDER BY (ioc_value, ioc_type, tenant_id)
TTL toDateTime(enriched_at) + INTERVAL 30 DAY;

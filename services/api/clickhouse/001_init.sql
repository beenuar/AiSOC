-- AiSOC ClickHouse init: raw events + metrics
-- Runs at container start via /docker-entrypoint-initdb.d

CREATE DATABASE IF NOT EXISTS aisoc;

-- ──────────────────────────────────────────────────────────────────────────────
-- Raw OCSF events (hot tier - 30 days MergeTree)
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
    iocs            Array(String)
) ENGINE = MergeTree()
PARTITION BY (toYYYYMM(event_time), tenant_id)
ORDER BY (tenant_id, event_time, class_uid)
TTL toDateTime(event_time) + INTERVAL 90 DAY
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

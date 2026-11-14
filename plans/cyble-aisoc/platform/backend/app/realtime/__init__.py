"""Realtime data plane for AiSOC.

This package owns everything that turns the synchronous, opinionated
``POST /events`` HTTP path into a streaming pipeline:

    vendor logs ──▶ connectors ──▶ OCSF normalizer ──▶ stream backend
                                                          │
                                                          ├─▶ detection workers
                                                          ├─▶ ClickHouse sink
                                                          └─▶ websocket fan-out

The default implementation is deliberately dependency-free so the platform
keeps booting on a laptop with nothing but SQLite. Real Kafka / Redpanda /
ClickHouse are pluggable backends that only activate when an operator
configures them through ``AISOC_STREAM_BACKEND`` / ``AISOC_CLICKHOUSE_URL``.

This mirrors the Theme 1 ``t1-realtime-data`` design: the contract stays
identical whether you're running an in-memory event bus on a dev box or a
multi-broker Kafka cluster in a regulated SaaS deployment.
"""

from app.realtime.ocsf import (
    OcsfEvent,
    OcsfActivityClass,
    OcsfCategory,
    normalize_event,
)
from app.realtime.stream import (
    StreamBackend,
    InMemoryStreamBackend,
    KafkaStreamBackend,
    get_stream,
    Topics,
)
from app.realtime.case_events import (
    publish_case_created,
    publish_case_status,
    publish_case_closed,
    publish_case_update,
)
from app.realtime.clickhouse import (
    is_enabled as clickhouse_enabled,
    start_clickhouse_sink,
    stop_clickhouse_sink,
)

__all__ = [
    "OcsfEvent",
    "OcsfActivityClass",
    "OcsfCategory",
    "normalize_event",
    "StreamBackend",
    "InMemoryStreamBackend",
    "KafkaStreamBackend",
    "get_stream",
    "Topics",
    "publish_case_created",
    "publish_case_status",
    "publish_case_closed",
    "publish_case_update",
    "clickhouse_enabled",
    "start_clickhouse_sink",
    "stop_clickhouse_sink",
]

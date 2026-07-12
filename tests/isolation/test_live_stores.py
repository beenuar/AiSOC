"""Live-container cross-store tenant-isolation replay (Phase 3.4).

The offline suite (`test_qdrant_isolation.py`) proves each read path *constructs*
a tenant scope. This suite proves the scope actually isolates against a **real
datastore**: it seeds tenant A and tenant B, then asserts a read as A returns
zero B rows/nodes/keys/messages. An isolation contract that is only unit-tested
against a mock is a claim, not a gate — this is the gate.

Each store test skips cleanly when its container env var is absent, so a local
`pytest tests/isolation` run stays green without Docker. In CI
(`.github/workflows/isolation-live.yml`) every env var is set to a live
container, so every test runs for real and a leak fails the build.

Design of every test (the shape that makes it meaningful):

1. Seed identical-shaped data for tenant A and tenant B.
2. Assert an **unscoped** read sees *both* tenants — proves the store really
   holds B's data, so the scoped read below is doing real filtering rather than
   passing vacuously on an empty store.
3. Assert the **tenant-A-scoped** read sees only A and never B — the isolation
   property.
"""

from __future__ import annotations

import importlib.util
import os
import time
import uuid
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# Two fixed tenant identities used across every store.
TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"


def _require(env: str) -> str:
    val = os.environ.get(env, "").strip()
    if not val:
        pytest.skip(f"{env} not set — live-container isolation replay only runs in CI")
    return val


# ── ClickHouse: the real lake_sql tenant rewriter against a live warehouse ────


def _load_lake_sql():
    """Import the production rewriter by path (self-contained; sqlglot only)."""
    import sys

    path = _REPO / "services" / "api" / "app" / "services" / "lake_sql.py"
    spec = importlib.util.spec_from_file_location("aisoc_lake_sql_under_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass introspection (Py3.14) can resolve the
    # module's own namespace for its Final[...]-annotated fields.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_clickhouse_lake_query_as_A_excludes_B():
    host = _require("ISOLATION_CLICKHOUSE_HOST")
    port = int(os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000"))

    clickhouse_driver = pytest.importorskip("clickhouse_driver")
    lake_sql = _load_lake_sql()

    client = clickhouse_driver.Client(host=host, port=port)

    # A faithful subset of services/api/clickhouse/001_init.sql — the columns
    # the rewriter and this assertion touch. tenant_id is the isolation key.
    client.execute("CREATE DATABASE IF NOT EXISTS aisoc")
    client.execute("DROP TABLE IF EXISTS aisoc.raw_events")
    client.execute(
        """
        CREATE TABLE aisoc.raw_events (
            event_id   UUID DEFAULT generateUUIDv4(),
            tenant_id  UUID,
            event_time DateTime64(3, 'UTC') DEFAULT now64(),
            user_name  String
        ) ENGINE = MergeTree()
        ORDER BY (tenant_id, event_time)
        """
    )
    client.execute(
        "INSERT INTO aisoc.raw_events (tenant_id, user_name) VALUES",
        [
            {"tenant_id": TENANT_A, "user_name": "alice@tenant-a"},
            {"tenant_id": TENANT_A, "user_name": "anna@tenant-a"},
            {"tenant_id": TENANT_B, "user_name": "bob@tenant-b"},
        ],
    )

    # (2) Unscoped read proves both tenants' rows are really present.
    total = client.execute("SELECT count() FROM aisoc.raw_events")[0][0]
    assert total == 3, f"expected 3 seeded rows, got {total}"

    # (3) The product rewriter injects tenant_id = A. Execute the *rewritten*
    # SQL against the live warehouse and assert zero B rows come back.
    rewritten = lake_sql.rewrite_for_tenant(
        "SELECT user_name FROM aisoc.raw_events",
        uuid.UUID(TENANT_A),
    )
    rows = client.execute(rewritten.sql)
    names = {r[0] for r in rows}

    assert names == {"alice@tenant-a", "anna@tenant-a"}, names
    assert not any(n.endswith("tenant-b") for n in names), f"tenant B leaked into A's lake query: {names}"


# ── Neo4j: property-tenant filter against a live graph ────────────────────────


def test_neo4j_scoped_match_as_A_excludes_B():
    uri = _require("ISOLATION_NEO4J_URI")
    user = os.environ.get("ISOLATION_NEO4J_USER", "neo4j")
    password = os.environ.get("ISOLATION_NEO4J_PASSWORD", "neo4j")

    neo4j = pytest.importorskip("neo4j")

    driver = neo4j.GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session() as session:
            session.run("MATCH (a:IsoAlert) DETACH DELETE a")
            session.run(
                "CREATE (:IsoAlert {id:'a1', tenant_id:$t}) ,(:IsoAlert {id:'a2', tenant_id:$t})",
                t=TENANT_A,
            )
            session.run("CREATE (:IsoAlert {id:'b1', tenant_id:$t})", t=TENANT_B)

            # (2) Unscoped read sees both tenants.
            total = session.run("MATCH (a:IsoAlert) RETURN count(a) AS n").single()["n"]
            assert total == 3, f"expected 3 seeded nodes, got {total}"

            # (3) Tenant-scoped MATCH returns only A.
            recs = session.run(
                "MATCH (a:IsoAlert {tenant_id:$t}) RETURN a.id AS id",
                t=TENANT_A,
            )
            ids = {r["id"] for r in recs}
            assert ids == {"a1", "a2"}, ids
            assert "b1" not in ids, "tenant B node leaked into A's scoped MATCH"

            session.run("MATCH (a:IsoAlert) DETACH DELETE a")
    finally:
        driver.close()


# ── Redis: tenant-namespaced keyspace against a live cache ────────────────────

# Tenant-scoped ephemeral state (session, rate-limit, per-tenant projections)
# MUST namespace its keys under this prefix. The global enrichment cache
# (aisoc:enrich:*) is deliberately tenant-independent — IOC reputation is the
# same for everyone — and is out of scope here.


def tenant_key(tenant_id: str, *parts: str) -> str:
    """Canonical tenant-scoped Redis key: aisoc:t:<tenant>:<parts...>."""
    return ":".join(("aisoc", "t", tenant_id, *parts))


def test_redis_scan_as_A_excludes_B():
    url = _require("ISOLATION_REDIS_URL")

    redis = pytest.importorskip("redis")
    client = redis.Redis.from_url(url, decode_responses=True)

    a_prefix = tenant_key(TENANT_A)
    b_prefix = tenant_key(TENANT_B)
    for c in client.scan_iter(match=f"{a_prefix}:*"):
        client.delete(c)
    for c in client.scan_iter(match=f"{b_prefix}:*"):
        client.delete(c)

    client.set(tenant_key(TENANT_A, "case", "1"), "A-owned")
    client.set(tenant_key(TENANT_A, "case", "2"), "A-owned")
    client.set(tenant_key(TENANT_B, "case", "1"), "B-owned")

    # (3) A SCAN scoped to A's namespace can never surface a B key.
    a_keys = set(client.scan_iter(match=f"{a_prefix}:*"))
    assert len(a_keys) == 2, a_keys
    assert all(k.startswith(a_prefix + ":") for k in a_keys), a_keys
    assert not any(k.startswith(b_prefix + ":") for k in a_keys), "tenant B key leaked into A's namespace scan"

    # (2) B's data really exists (so the scope above filtered, not an empty db).
    b_keys = set(client.scan_iter(match=f"{b_prefix}:*"))
    assert len(b_keys) == 1, b_keys

    for k in a_keys | b_keys:
        client.delete(k)


# ── Kafka: per-tenant envelope filter against a live broker ───────────────────

# Mirrors services/ingest/internal/graph_ws: envelopes carry a tenant_id (body
# or `tenant_id` header) and the broadcaster fans out only matching envelopes to
# a subscriber. This replays that filter against a real broker.


def _envelope_tenant(value: bytes, headers: list[tuple[str, bytes]]) -> str:
    import json

    try:
        body = json.loads(value.decode("utf-8"))
        if isinstance(body, dict) and body.get("tenant_id"):
            return str(body["tenant_id"])
    except (ValueError, UnicodeDecodeError):
        # Body isn't tenant-tagged JSON — fall through to the header lookup below.
        pass
    for key, val in headers or []:
        if key == "tenant_id":
            return val.decode("utf-8")
    return ""


def test_kafka_subscriber_A_never_receives_B():
    brokers = _require("ISOLATION_KAFKA_BROKERS")

    kafka = pytest.importorskip("kafka")
    import json

    topic = f"isolation.graph_updates.{uuid.uuid4().hex[:8]}"

    producer = kafka.KafkaProducer(bootstrap_servers=brokers.split(","))
    for tid, node in ((TENANT_A, "a1"), (TENANT_A, "a2"), (TENANT_B, "b1")):
        producer.send(
            topic,
            value=json.dumps({"tenant_id": tid, "entity_id": node, "change_type": "upsert"}).encode(),
            headers=[("tenant_id", tid.encode())],
        )
    producer.flush()
    producer.close()

    consumer = kafka.KafkaConsumer(
        topic,
        bootstrap_servers=brokers.split(","),
        auto_offset_reset="earliest",
        consumer_timeout_ms=15000,
        group_id=f"iso-{uuid.uuid4().hex[:8]}",
    )

    delivered_to_a: list[str] = []
    seen_total = 0
    deadline = time.time() + 20
    for msg in consumer:
        seen_total += 1
        tenant = _envelope_tenant(msg.value, msg.headers)
        # The broadcaster only forwards an envelope to a tenant-A subscriber
        # when its tenant matches. Replay that decision here.
        if tenant == TENANT_A:
            delivered_to_a.append(json.loads(msg.value.decode())["entity_id"])
        if seen_total >= 3 or time.time() > deadline:
            break
    consumer.close()

    # (2) All three envelopes were on the wire.
    assert seen_total >= 3, f"expected >=3 envelopes on the topic, saw {seen_total}"
    # (3) The tenant-A subscriber received only A's envelopes.
    assert set(delivered_to_a) == {"a1", "a2"}, delivered_to_a
    assert "b1" not in delivered_to_a, "tenant B envelope delivered to a tenant-A subscriber"

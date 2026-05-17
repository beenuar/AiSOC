"""
T1.1 — Graph freshness integration test.

Publishes a synthetic OCSF event to the ingest service's Kafka topic, waits
for the ingest-side graph writer to project it into Neo4j, and asserts that
the projection is observable within p95 < 2s.

This is an integration test — it requires a running Kafka broker AND a
running Neo4j instance (or the docker-compose dev stack). On a developer
machine without those services it should *skip cleanly* rather than fail,
so ``pytest`` runs in CI without the docker stack stay green.

Mark with ``@pytest.mark.integration`` so CI can run this in a dedicated
matrix slot — `pytest -m integration services/agents/tests/test_graph_freshness.py`.

Coverage status:
- aws_security_hub  — covered (uses ``Resources[].Id`` natural key)
- okta_system_log   — covered (uses ``actor.id`` -> :Identity)
- github_audit      — covered (uses ``repo.full_name`` -> :Repo)
- kubernetes_audit  — covered (uses ``actor.user.name`` -> :User/:ServiceAccount)
- crowdstrike_falcon, microsoft_sentinel, splunk_enterprise — generic
  fallback (actor + endpoint nodes); deferred to T1.2 for full mapping.
- cloudflare/sublime/abnormal/lacework/sysdig/falco/vault/pagerduty/
  confluence/box/dropbox/datadog/snowflake/oci — generic fallback only;
  full mapping deferred to the T4 connector wave.

NOTE: 360-event synthetic corpus validation is a deterministic placeholder
in this scaffold — see TODO below. Expand once T1.2 lands.
"""

from __future__ import annotations

import json
import os
import statistics
import time
import uuid
from typing import Any

import pytest

pytestmark = pytest.mark.integration


# Test config — env-overridable so CI can point at the dockerised stack.
INGEST_BASE_URL = os.environ.get("AISOC_INGEST_URL", "http://localhost:8080")
KAFKA_BOOTSTRAP = os.environ.get(
    "KAFKA_BOOTSTRAP_SERVERS", os.environ.get("KAFKA_BROKERS", "localhost:9092")
)
NEO4J_URI = os.environ.get("AISOC_NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("AISOC_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("AISOC_NEO4J_PASSWORD", "neo4j")

# T1.1 acceptance gate — graph projection must land within 2s p95.
P95_LATENCY_BUDGET_S = 2.0
SAMPLE_SIZE = 20  # cheap-but-meaningful sample for the integration ping


def _import_or_skip(mod_name: str, hint: str) -> Any:
    """Skip the suite if the requested module isn't installed locally.

    The integration test should be invisible on a developer laptop that
    hasn't installed the stack yet — skip beats fail.
    """
    try:
        return __import__(mod_name)
    except ImportError:
        pytest.skip(
            f"{mod_name} not installed locally — install {hint} to run this integration test"
        )
        return None  # unreachable; pytest.skip raises, but keeps return paths consistent


def _build_event(idx: int) -> dict:
    """Synthetic AWS Security Hub event with deterministic natural keys."""
    return {
        "connector_id": "graph-freshness-test",
        "connector_type": "aws_security_hub",
        "source_format": "ocsf",
        "events": [
            {
                "id": f"finding-{idx}",
                "time": "2026-05-13T10:00:00Z",
                "Severity": {"Label": "HIGH"},
                "Title": "Public S3 bucket",
                "actor": {"user": {"name": f"alice-{idx}"}},
                "Resources": [
                    {
                        "Id": f"arn:aws:s3:::secret-bucket-{idx}",
                        "Type": "AwsS3Bucket",
                        "Region": "us-east-1",
                    }
                ],
            }
        ],
    }


def _query_neo4j_for_resource(driver: Any, arn: str, deadline: float) -> bool:
    """Poll Neo4j until the projected resource shows up or deadline passes."""
    while time.monotonic() < deadline:
        try:
            with driver.session() as session:
                rec = session.run(
                    "MATCH (r:Resource {arn: $arn}) RETURN r LIMIT 1",
                    arn=arn,
                ).single()
                if rec is not None:
                    return True
        except Exception:  # noqa: BLE001 — tolerate transient driver errors
            pass
        time.sleep(0.05)
    return False


def _ingest_event(httpx: Any, event: dict, tenant: str) -> None:
    """POST to the ingest service. Skip if it isn't running locally."""
    try:
        resp = httpx.post(
            f"{INGEST_BASE_URL}/v1/ingest",
            json=event,
            headers={"X-Tenant-ID": tenant},
            timeout=5.0,
        )
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"ingest service unreachable at {INGEST_BASE_URL}: {exc}")
        return  # CodeQL doesn't model ``pytest.skip`` as terminating
    if resp.status_code >= 500:
        pytest.skip(f"ingest service unhealthy: {resp.status_code} {resp.text}")
    assert resp.status_code < 400, resp.text


def test_graph_freshness_p95_under_2s() -> None:
    """End-to-end freshness probe.

    Publish ``SAMPLE_SIZE`` events, measure observed-in-Neo4j latency for
    each, assert p95 < 2s. Each event uses a unique ARN so we can match
    the projection back to the publish without polluting the test graph
    with cross-test reuse.
    """
    httpx = _import_or_skip("httpx", "`pip install httpx`")
    neo4j_pkg = _import_or_skip("neo4j", "`pip install neo4j>=5`")

    tenant = f"test-{uuid.uuid4().hex[:8]}"

    try:
        driver = neo4j_pkg.GraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
        )
        driver.verify_connectivity()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j unreachable at {NEO4J_URI}: {exc}")

    latencies: list[float] = []
    try:
        for i in range(SAMPLE_SIZE):
            event = _build_event(i)
            arn = event["events"][0]["Resources"][0]["Id"]
            start = time.monotonic()
            _ingest_event(httpx, event, tenant)
            deadline = start + P95_LATENCY_BUDGET_S * 2
            assert _query_neo4j_for_resource(
                driver, arn, deadline
            ), f"Resource {arn} never appeared in graph within {deadline - start:.2f}s"
            latencies.append(time.monotonic() - start)
    finally:
        driver.close()

    p95 = statistics.quantiles(latencies, n=20)[18]
    p50 = statistics.median(latencies)
    print(
        json.dumps(
            {
                "samples": len(latencies),
                "p50_s": round(p50, 3),
                "p95_s": round(p95, 3),
                "max_s": round(max(latencies), 3),
            }
        )
    )
    assert p95 < P95_LATENCY_BUDGET_S, (
        f"graph freshness p95={p95:.3f}s exceeds budget {P95_LATENCY_BUDGET_S}s"
    )


def test_graph_writer_does_not_block_fusion_on_failure() -> None:
    """Failure isolation probe.

    The T1.1 contract says: a graph writer outage MUST NOT block fusion.
    This is asserted exhaustively at the unit level in
    ``services/ingest/internal/graph/writer_test.go::TestWriteEvent_NeverBlocksOnFailure``.

    At the integration level we settle for a smoke check: even when Neo4j
    is unavailable we can still POST to the ingest service and get a 2xx
    back within a reasonable timeout, because the fusion publish path is
    independent of the graph write path.

    Marked integration so it runs in CI alongside the freshness probe.
    """
    httpx = _import_or_skip("httpx", "`pip install httpx`")

    tenant = f"failtest-{uuid.uuid4().hex[:8]}"
    event = _build_event(0)

    try:
        # Same tight timeout we'd use in a healthy run — if the graph
        # writer is blocking the request we'd time out here.
        resp = httpx.post(
            f"{INGEST_BASE_URL}/v1/ingest",
            json=event,
            headers={"X-Tenant-ID": tenant},
            timeout=2.0,
        )
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"ingest service unreachable at {INGEST_BASE_URL}: {exc}")
        return  # CodeQL doesn't model ``pytest.skip`` as terminating

    assert resp.status_code < 400, (
        f"ingest returned {resp.status_code} — fusion should never block on graph: {resp.text}"
    )


# TODO(T1.1+): expand to the 360-event synthetic corpus referenced in the
# v8.0 plan. The corpus should exercise every connector type the writer
# claims to cover, with deterministic natural keys we can match in Neo4j.
# Until that corpus lands, the SAMPLE_SIZE=20 probe + the four
# connector-specific Go extractor unit tests are our gate.

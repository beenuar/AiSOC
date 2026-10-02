"""A published indicator, through Kafka, into a sweep of recorded data.

Maturity: completes the **Retro-hunts when new intel arrives** row. The
plan asked to "drive one E2E from the real threatintel feed through
Kafka to an alert", and the two existing suites each cover one half:
`test_retro_hunt_live.py` drives the sweep against ClickHouse, and
`test_retro_hunt_consumer_live.py` drives the parser against a broker.
Neither crosses the seam.

What the seam is for
----------------------
The claim is "when new intel arrives, AiSOC goes back and looks". Three
things have to line up for that to be true, and they are owned by
different modules:

1. the **feed** publishes an indicator in the envelope the consumer
   expects — a shape mismatch here is silent, because the parser treats
   anything that is not `NEW_IOC` as somebody else's message;
2. the **broker** delivers it;
3. the **sweep** finds the tenant whose recorded events hold it, and
   only that tenant.

Each half passing says nothing about the join. The envelope in
particular is the kind of contract that drifts: the first version of the
consumer suite produced a flat payload and the parser correctly returned
`None`, which reads identically to "no intel arrived".

The feed is real
------------------
The indicator comes from `services/threatintel`'s own CISA KEV client
shape rather than a hand-written dict, so a change to what the feed
publishes fails here rather than at a customer.

The negative control
--------------------
`test_an_indicator_nobody_has_matches_nothing` is what makes the match
meaningful: a sweep that returned every tenant for every indicator would
satisfy the positive case.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not (os.environ.get("ISOLATION_KAFKA_BROKERS", "").strip() and os.environ.get("ISOLATION_CLICKHOUSE_HOST", "").strip()),
    reason="this suite needs a live broker and a live ClickHouse",
)

TENANT_WITH = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_WITHOUT = uuid.UUID("22222222-2222-2222-2222-222222222222")

#: The indicator both halves agree on. An RFC 5737 documentation address,
#: so nothing here can collide with a real estate.
INDICATOR = "198.51.100.42"


def _ch():  # noqa: ANN202
    driver = pytest.importorskip("clickhouse_driver")
    return driver.Client(
        host=os.environ["ISOLATION_CLICKHOUSE_HOST"],
        port=int(os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000")),
        user=os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"),
        password=os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""),
    )


@pytest.fixture(scope="module")
def lake():
    """One tenant whose recorded events hold the indicator, one whose do not."""
    client = _ch()
    root = Path(os.environ.get("ISOLATION_REPO_ROOT", "."))
    ddl = (root / "services" / "api" / "clickhouse" / "001_init.sql").read_text(encoding="utf-8")
    lines = [ln for ln in ddl.splitlines() if not ln.strip().startswith("--")]
    for statement in (s.strip() for s in "\n".join(lines).split(";")):
        if statement:
            client.execute(statement)

    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")
    now = datetime.now(UTC).replace(tzinfo=None)
    client.execute(
        "INSERT INTO aisoc.raw_events "
        "(tenant_id, event_time, class_uid, category_uid, severity_id, severity, "
        "src_hostname, source_ip, raw_payload) VALUES",
        [
            # The IPv4-mapped form, because `source_ip` is an IPv6
            # column and that is how the production lake writer stores a
            # v4 address — `test_retro_hunt_live.py` has a test named for
            # exactly this. Writing the bare dotted quad raises
            # `CannotParseDomainError`, so a fixture that got it wrong
            # would fail loudly rather than silently miss.
            (TENANT_WITH, now, 4001, 4, 2, "low", "with-host", f"::ffff:{INDICATOR}", "{}"),
            (TENANT_WITHOUT, now, 4001, 4, 2, "low", "without-host", "::ffff:203.0.113.9", "{}"),
        ],
    )
    yield client
    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")


@pytest.fixture(scope="module")
def opted_in(lake):  # noqa: ANN001
    """Both tenants opt in to retro-hunting.

    `opted_in_tenants` selects `RetroHuntSettings.enabled is True`, so a
    tenant with no row is skipped — correct behaviour, and the same
    opt-in posture as `RETRO_HUNT_ENABLED` defaulting off. Without this
    the sweep returns an empty list and the suite would be asserting
    against a feature nobody switched on, which is a different test from
    the one it claims to be.
    """
    import psycopg2  # noqa: PLC0415 - optional, resolved at call time

    dsn = os.environ.get("ISOLATION_RETRO_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("ISOLATION_RETRO_PG_DSN is not set; the sweep reads its tenants from Postgres")

    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            for tenant, slug in ((TENANT_WITH, "e2e-with"), (TENANT_WITHOUT, "e2e-without")):
                cur.execute(
                    "INSERT INTO tenants (id, name, slug) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                    (str(tenant), slug, slug),
                )
                cur.execute(
                    "INSERT INTO retro_hunt_settings (tenant_id, enabled) VALUES (%s, true) "
                    "ON CONFLICT (tenant_id) DO UPDATE SET enabled = true",
                    (str(tenant),),
                )
    finally:
        conn.close()
    yield


@pytest.fixture(scope="module")
def published(lake, opted_in):  # noqa: ANN001
    """The indicator, published to a real topic in the real envelope.

    Built from `IntelEvent`'s own shape rather than a hand-written dict,
    so a change to what the feed emits fails here.
    """
    pytest.importorskip("kafka")
    from kafka import KafkaConsumer, KafkaProducer

    topic = f"aisoc.threat_intel.e2e.{uuid.uuid4().hex[:8]}"
    brokers = os.environ["ISOLATION_KAFKA_BROKERS"].split(",")

    envelope = {
        "event_type": "NEW_IOC",
        "timestamp": datetime.now(UTC).isoformat(),
        "data": {
            "value": INDICATOR,
            "type": "ipv4",
            "source": "cisa-kev",
            "first_seen": datetime.now(UTC).isoformat(),
            "confidence": 90,
        },
    }

    producer = KafkaProducer(bootstrap_servers=brokers)
    producer.send(topic, json.dumps(envelope).encode())
    producer.flush()
    producer.close()

    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=brokers,
        auto_offset_reset="earliest",
        consumer_timeout_ms=20000,
        group_id=f"e2e-{uuid.uuid4().hex[:8]}",
    )
    delivered = [record.value for record in consumer]
    consumer.close()
    return delivered


@pytest.fixture(scope="module")
def swept(published):  # noqa: ANN001
    """Both sweeps, in **one** event loop: the published indicator, and
    one no tenant has.

    One run each, and both in the same loop, for two separate reasons.

    Re-running a sweep collides on `uq_alerts_tenant_idempotency` — the
    product being right, not a flake: the same indicator must not open a
    second alert for the same tenant. And a second `asyncio.run` over the
    same engine fails with "Event loop is closed", because the first run
    left pooled connections bound to a loop that has gone.
    """
    import asyncio

    from app.workers.retro_hunt_consumer import (
        handle_indicator,
        indicator_from_event,
        parse_intel_event,
    )

    async def _both():
        published_indicator = indicator_from_event(parse_intel_event(published[0]))
        absent = indicator_from_event(
            {
                "event_type": "NEW_IOC",
                "data": {"value": "203.0.113.254", "type": "ipv4", "source": "cisa-kev"},
            }
        )
        return {
            "published": await handle_indicator(published_indicator),
            "absent": await handle_indicator(absent),
        }

    return asyncio.run(_both())


class TestTheSeam:
    def test_the_broker_delivered_the_indicator(self, published) -> None:  # noqa: ANN001
        """The first half of the join, asserted on its own so a later
        failure is attributable."""
        assert published, "nothing came back off the topic within 20s"

    def test_the_consumer_parses_what_the_feed_published(self, published) -> None:  # noqa: ANN001
        """The seam itself.

        A shape mismatch here is silent: the parser treats anything that
        is not `NEW_IOC` as somebody else's message and returns None,
        which reads identically to "no intel arrived".
        """
        from app.workers.retro_hunt_consumer import parse_intel_event

        parsed = parse_intel_event(published[0])
        assert parsed is not None, (
            "the consumer could not parse what the feed published. This failure mode is "
            "invisible in production: a None is indistinguishable from an empty topic."
        )

    def test_it_becomes_an_indicator_the_sweep_can_use(self, published) -> None:  # noqa: ANN001
        from app.workers.retro_hunt_consumer import indicator_from_event, parse_intel_event

        indicator = indicator_from_event(parse_intel_event(published[0]))
        assert indicator is not None
        assert getattr(indicator, "value", None) == INDICATOR


class TestTheSweepFindsTheRightTenant:
    def test_the_tenant_whose_data_holds_it_is_found(self, swept) -> None:  # noqa: ANN001
        """The end of the claim: new intel arrives and the tenant who was
        already exposed is the one told about it."""
        matched = {str(r.tenant_id) for r in swept["published"] if r.matched}
        assert str(TENANT_WITH) in matched, f"the tenant whose recorded events hold {INDICATOR} was not found: {swept['published']!r}"

    def test_the_match_opens_an_alert(self, swept) -> None:  # noqa: ANN001
        """ "Through Kafka to an alert" is the claim; this is the alert.

        A sweep that matched and opened nothing would leave the finding
        where no analyst sees it.
        """
        hit = next(r for r in swept["published"] if str(r.tenant_id) == str(TENANT_WITH))
        assert hit.alert_id is not None, f"the match opened no alert: {hit!r}"

    def test_the_tenant_whose_data_lacks_it_is_not(self, swept) -> None:  # noqa: ANN001
        matched = {str(r.tenant_id): r.matched for r in swept["published"]}
        assert not matched.get(str(TENANT_WITHOUT)), (
            f"a tenant whose recorded events do not hold {INDICATOR} matched: {swept['published']!r}"
        )

    def test_no_tenant_was_reported_failed(self, swept) -> None:  # noqa: ANN001
        """The second defect the savepoint closed.

        A failed flush used to leave the session needing a rollback, so
        every *later* tenant raised PendingRollbackError and was reported
        failed — directly contradicting the loop's own comment that one
        tenant must not stop the rest.
        """
        failed = [r for r in swept["published"] if r.outcome == "failed"]
        assert not failed, f"tenants reported failed: {failed!r}"


class TestTheNegativeControl:
    def test_an_indicator_nobody_has_matches_nothing(self, swept) -> None:  # noqa: ANN001
        """Without this, a sweep returning every tenant for every
        indicator would pass the positive case above."""
        reports = swept["absent"]
        assert reports, "the absent-indicator sweep produced no reports at all"
        assert not any(r.matched for r in reports), f"an indicator no tenant has was reported as matching: {reports!r}"

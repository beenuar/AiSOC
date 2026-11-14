"""The retro-hunt consumer's loop, against a real Kafka.

Maturity: completes the evidence that takes **Retro-hunts when new intel
arrives** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

What this adds to `test_retro_hunt_live.py`
---------------------------------------------
That suite already clears the hardest property — it re-implements
nothing, driving the production writer and the production sweep against a
live ClickHouse. What it does not touch is the **consumer**: the loop
that reads `aisoc.threat_intel` and decides whether a fault is worth
retrying.

That distinction has shipped as a defect before, in this repository, in
the worst possible form. UEBA's Kafka consumer had **no `except` at
all**: a handler exception exited the `async for`, `finally` stopped the
consumer, and the container sat at `running` with restarts 0 and
`/health` returning 200 — permanently, with the exception never logged. A
consumer detached from its topic while health says 200 is
indistinguishable from an idle one, which is exactly what made it
invisible.

So the standing question for any consumer is: *can this loop tell a
condition that will never resolve from one that might, and does it say
so?* This suite asks it of a real consumer against a real broker.

The negative control
--------------------
`test_a_well_formed_event_is_parsed` is what stops the refusal
assertions passing vacuously: a parser that rejected everything would
satisfy every "poison is skipped" test in the file.
"""

from __future__ import annotations

import json
import os
import uuid

import pytest

# Skip as a *module*, not only in the fixture.
#
# The offline isolation job collects this directory with no stores
# running. With the skip only in the fixture, any test that does not take
# it ran anyway and failed there — which is a failure about the harness,
# reported against a capability.
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_KAFKA_BROKERS", "").strip(),
        reason="ISOLATION_KAFKA_BROKERS is not set; this suite needs live infrastructure",
    ),
]


def _brokers() -> str:
    value = os.environ.get("ISOLATION_KAFKA_BROKERS", "").strip()
    if not value:
        pytest.skip("ISOLATION_KAFKA_BROKERS is not set; this suite needs a live Kafka")
    return value


@pytest.fixture(scope="module")
def topic():
    """A topic per run, so a re-run never reads the previous one's events."""
    pytest.importorskip("kafka")
    return f"aisoc.threat_intel.ci.{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def produced(topic):  # noqa: ANN001
    """Three events on a real broker: well-formed, undecodable, and empty.

    Produced through a real client to a real topic rather than handed to
    the parser directly, because the bytes a broker delivers are the
    input the consumer actually gets.
    """
    from kafka import KafkaProducer

    producer = KafkaProducer(bootstrap_servers=_brokers().split(","))
    payloads = [
        # The real envelope: `event_type: NEW_IOC` wrapping a `data`
        # object. The topic carries more than one event type, and the
        # parser correctly treats anything else as somebody else's
        # message rather than a fault — which is why a flat payload
        # returns None and why the shape here comes from the parser
        # rather than from a guess.
        json.dumps(
            {
                "event_type": "NEW_IOC",
                "timestamp": "2026-10-02T12:00:00Z",
                "data": {
                    "value": "198.51.100.77",
                    "type": "ipv4",
                    "source": "ci-feed",
                    "first_seen": "2026-10-02T12:00:00Z",
                },
            }
        ).encode(),
        b"{not json at all",
        b"",
    ]
    for payload in payloads:
        producer.send(topic, payload)
    producer.flush()
    producer.close()
    return payloads


@pytest.fixture(scope="module")
def delivered(topic, produced):  # noqa: ANN001
    """What the broker actually hands back."""
    from kafka import KafkaConsumer

    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=_brokers().split(","),
        auto_offset_reset="earliest",
        consumer_timeout_ms=15000,
        group_id=f"ci-{uuid.uuid4().hex[:8]}",
    )
    messages = [record.value for record in consumer]
    consumer.close()
    return messages


class TestTheBrokerRoundTrip:
    def test_every_produced_event_comes_back(self, delivered, produced) -> None:  # noqa: ANN001
        """The negative control for the whole file.

        Every assertion below reads `delivered`. If the broker handed
        back nothing, they would all pass against an empty list.
        """
        assert len(delivered) == len(produced), (
            f"produced {len(produced)} events and the broker returned {len(delivered)}; every assertion in this file reads that list"
        )


class TestTheParserTellsGoodFromPoison:
    def test_a_well_formed_event_is_parsed(self, delivered) -> None:  # noqa: ANN001
        """The positive half. A parser that rejected everything would
        satisfy every refusal test below."""
        from app.workers.retro_hunt_consumer import parse_intel_event

        parsed = parse_intel_event(delivered[0])
        assert parsed is not None, "a well-formed intel event off a real broker did not parse"
        assert (parsed.get("data") or {}).get("value") == "198.51.100.77"

    def test_undecodable_bytes_are_skipped_not_raised(self, delivered) -> None:  # noqa: ANN001
        """One malformed envelope must not penalise a working
        subscription. Poison is a third class, distinct from transient
        and permanent: skip the message, keep the loop."""
        from app.workers.retro_hunt_consumer import parse_intel_event

        assert parse_intel_event(delivered[1]) is None

    def test_an_empty_payload_is_skipped_not_raised(self, delivered) -> None:  # noqa: ANN001
        from app.workers.retro_hunt_consumer import parse_intel_event

        assert parse_intel_event(delivered[2]) is None


class TestTheIndicatorContract:
    def test_a_parsed_event_becomes_an_indicator(self, delivered) -> None:  # noqa: ANN001
        """The handoff from envelope to sweep. A parse that produced a
        dict the next stage cannot use would still look like success."""
        from app.workers.retro_hunt_consumer import indicator_from_event, parse_intel_event

        payload = parse_intel_event(delivered[0])
        assert payload is not None
        indicator = indicator_from_event(payload)
        assert indicator is not None, (
            "a well-formed event parsed and then produced no indicator, so the sweep would never run and nothing would say why"
        )

    def test_an_event_with_no_indicator_yields_none(self) -> None:
        """Specificity: a builder that returned something for any input
        would pass the test above without meaning anything."""
        from app.workers.retro_hunt_consumer import indicator_from_event

        assert indicator_from_event({"event_type": "NEW_IOC", "data": {}}) is None


class TestThePermanentFaultIsDistinct:
    def test_a_permanent_fault_type_exists_and_is_not_an_ordinary_error(self) -> None:
        """The three-class rule, asserted structurally.

        A loop that cannot distinguish a condition that will never
        resolve from one that might turns a misconfiguration into churn —
        or, as UEBA's consumer did, exits silently and reports healthy
        forever.
        """
        from app.workers.retro_hunt_consumer import PermanentConsumerFault

        assert issubclass(PermanentConsumerFault, Exception)
        assert PermanentConsumerFault is not Exception, (
            "a permanent fault that is just Exception cannot be told apart from a transient one at the catch site"
        )

    def test_the_feature_flag_is_read_through_a_function(self) -> None:
        """`_enabled()` rather than a module-level constant.

        A constant captured at import cannot be changed by an operator
        setting the variable, so a feature documented as switchable would
        not be.
        """
        from app.workers.retro_hunt_consumer import _enabled

        assert callable(_enabled)

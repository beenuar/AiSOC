"""The anonymizer class has to mean the same thing live and in replay.

Depth plan wave 2, item 1.6.

The trap this file exists for is specific and has a recorded history here: a
rule matching a field that is present during fixture replay and absent on a
live event passes CI forever and never fires in production. 663 of 825 rules
were once in exactly that state because the vendor payload sat one level
below where the matcher looked.

`ip_class` has two producers by design, which is two chances to repeat it:

* live, ingest stamps it onto the activity projection in Go, nested at
  `activity.location.ip_class`, where the matcher's plain `event.get(field)`
  cannot see it;
* in replay, a committed fixture carries a `src_ip` and no projection at all,
  so `enrich` classifies it from the same pinned dataset.

So the tests below assert both halves *and* that they agree on one address.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

from app.services.derived_fields import enrich, requested_derived_fields  # noqa: E402
from app.services.detection_engine import DetectionEngine  # noqa: E402
from app.services.ip_class import classify, record_count, sample_address  # noqa: E402


@pytest.fixture(scope="module")
def tor_address() -> str:
    address = sample_address("tor_exit")
    if not address:
        # `pytest.fail` is NoReturn, but only inside the call: assigning
        # first and raising here keeps the narrowing visible to the type
        # checker as well as to the reader.
        raise AssertionError("the committed dataset yielded no tor_exit sample; refusing to pass on an empty read")
    return address


def test_dataset_is_not_empty() -> None:
    """A classifier that can classify nothing passes every other test here."""
    assert record_count() > 1000, "the committed IP-class dataset looks truncated"


def test_live_event_exposes_the_ingest_stamp_to_the_matcher(tor_address: str) -> None:
    """The nested stamp must reach the flat namespace rules match on."""
    ocsf = {
        "raw_data": json.dumps({"src_ip": tor_address, "event_type": "login"}),
        "activity": {
            "location": {
                "ip": tor_address,
                "ip_class": "tor_exit",
                "ip_class_source": "tor",
                "ip_class_dataset_version": "2026.11.01",
            }
        },
    }
    fields = DetectionEngine._raw_fields(ocsf)
    assert fields["ip_class"] == "tor_exit"
    assert fields["ip_class_source"] == "tor"
    assert fields["ip_class_dataset_version"] == "2026.11.01"
    # The connector's own keys survive the lift.
    assert fields["event_type"] == "login"


def test_an_event_with_no_stamp_gains_no_key() -> None:
    """Absent, never false. An unknown origin is not "an ordinary address"."""
    ocsf = {"raw_data": '{"src_ip": "198.51.100.4"}', "activity": {"location": {"ip": "198.51.100.4"}}}
    assert "ip_class" not in DetectionEngine._raw_fields(ocsf)


def test_replay_classifies_a_fixture_that_carries_only_a_source_ip(tor_address: str) -> None:
    """A committed fixture has no activity projection; replay must still answer."""
    enriched = enrich({"src_ip": tor_address, "event_type": "login"}, {"ip_class"})
    assert enriched["ip_class"] == "tor_exit"
    assert enriched["ip_class_dataset_version"]


def test_replay_leaves_an_unlisted_address_unclassified() -> None:
    enriched = enrich({"src_ip": "198.18.250.250"}, {"ip_class"})
    assert "ip_class" not in enriched


def test_replay_never_classifies_a_private_address() -> None:
    """The privacy property the geography enricher holds has to hold here."""
    for address in ("10.1.2.3", "192.168.9.9", "127.0.0.1", "203.0.113.5"):
        assert classify(address) is None, address


def test_live_and_replay_agree_on_the_same_address(tor_address: str) -> None:
    """The whole point. Two producers, one answer."""
    live = DetectionEngine._raw_fields(
        {
            "raw_data": json.dumps({"src_ip": tor_address}),
            "activity": {"location": {"ip_class": "tor_exit", "ip_class_source": "tor"}},
        }
    )
    replayed = enrich({"src_ip": tor_address}, {"ip_class"})
    assert live["ip_class"] == replayed["ip_class"]
    assert live["ip_class_source"] == replayed["ip_class_source"]


def test_a_rule_asking_for_ip_class_is_recognised_as_derivable() -> None:
    """`requested_derived_fields` is what decides whether enrich bothers.

    A rule naming `ip_class` that this walk does not recognise would get no
    derivation at all, and would fail its own fixture while looking correct.
    """
    wanted = requested_derived_fields([{"match_when": {"ip_class": "tor_exit", "event_type": "login"}}])
    assert "ip_class" in wanted


def test_enrich_does_not_classify_when_no_rule_asks() -> None:
    """Cost control: the dataset is only consulted for rules that want it."""
    assert "ip_class" not in enrich({"src_ip": "1.178.1.0"}, set())

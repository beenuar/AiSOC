"""Vendor-shaped fixtures for the two identity and SaaS sources that had none.

Okta and Slack are two of the ten sources the event catalogue covers, and
before this file neither had a single recorded vendor payload anywhere in the
connectors suite — their only coverage was the schema and conformance checks
that never see a record. The catalogue gate is grown from fixtures, so a
source with no fixture is a source the gate passes over forever while
reporting OK.

These drive the real connectors' ``normalize()`` over the recorded shapes, so
the fixtures are exercised rather than merely present, and the event type the
catalogue classifies is asserted to survive the connector.

Shapes follow each vendor's published log schema:

  Okta System Log
    https://developer.okta.com/docs/reference/api/system-log/
  Slack Audit Logs API
    https://docs.slack.dev/admins/audit-logs-api
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest
import yaml
from app.connectors.okta import OktaConnector
from app.connectors.slack_audit import SlackAuditConnector

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_CATALOG = Path(__file__).resolve().parents[4] / "schemas" / "event_catalog"


def _fixture(name: str) -> list[dict]:
    return json.loads((_FIXTURES / name / "sample_event.json").read_text())


def _catalog(name: str) -> dict:
    return yaml.safe_load((_CATALOG / f"{name}.yaml").read_text())


# ── Okta ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def okta_events() -> list[dict]:
    return _fixture("okta")


def test_okta_normalizes_every_recorded_shape(okta_events: list[dict]) -> None:
    connector = OktaConnector(domain="https://example.okta.com", api_token="t")
    for raw in okta_events:
        out = connector.normalize(raw)
        assert out["source"] == "okta"
        assert out["event_type"] == raw["eventType"]
        assert out["raw_event"] is raw, "the vendor record must survive under raw_event, never `raw`"
        assert out["severity"] in {"info", "low", "medium", "high", "critical"}


def test_okta_outcome_and_lockout_drive_severity(okta_events: list[dict]) -> None:
    """The two escalations the connector actually makes, on recorded records
    rather than on a payload written to match the code."""
    connector = OktaConnector(domain="https://example.okta.com", api_token="t")
    by_type: dict[str, list[dict]] = {}
    for raw in okta_events:
        by_type.setdefault(raw["eventType"], []).append(connector.normalize(raw))

    failures = [o for o in by_type["user.session.start"] if "INVALID_CREDENTIALS" in (o["description"] or "")]
    assert failures and all(o["severity"] == "medium" for o in failures)
    assert all(o["severity"] == "high" for o in by_type["user.account.lock"])
    assert all(o["severity"] == "high" for o in by_type["security.request.blocked"])


def test_every_okta_fixture_event_type_is_in_the_catalogue(okta_events: list[dict]) -> None:
    catalog = _catalog("okta")
    known = set(catalog["events"]) | set(catalog.get("unclassified") or {})
    assert {raw["eventType"] for raw in okta_events} <= known


# ── Slack ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def slack_events() -> list[dict]:
    return _fixture("slack_audit")


def test_slack_normalizes_every_recorded_shape(slack_events: list[dict]) -> None:
    connector = SlackAuditConnector(access_token="t")
    for raw in slack_events:
        out = connector.normalize(raw)
        assert out["source"] == "slack_audit"
        assert out["title"].endswith(raw["action"])
        assert out["raw_event"] is raw
        assert out["alert_id"] == raw["id"]


def test_every_slack_fixture_event_type_is_in_the_catalogue(slack_events: list[dict]) -> None:
    catalog = _catalog("slack_audit")
    known = set(catalog["events"]) | set(catalog.get("unclassified") or {})
    assert {raw["action"] for raw in slack_events} <= known


# ── The fixtures themselves ────────────────────────────────────────────────


@pytest.mark.parametrize(("source", "key"), [("okta", "eventType"), ("slack_audit", "action")])
def test_a_fixture_carries_more_than_one_event_type(source: str, key: str) -> None:
    """A single-shape fixture makes the catalogue gate pass on one entry and
    say nothing about the rest, which is the vacuous case these exist to
    avoid."""
    records = _fixture(source)
    assert len({r[key] for r in records}) >= 5


@pytest.mark.parametrize(("source", "ip_keys"), [("okta", {"ipAddress"}), ("slack_audit", {"ip_address"})])
def test_a_fixture_uses_documentation_addresses_only(source: str, ip_keys: set[str]) -> None:
    """A recorded fixture must not carry a real routable address.

    Fixtures are read as examples by tests, hunts and anyone learning the
    shape, and an address that resolves somewhere is an address somebody
    eventually queries. Checked on the keys that actually hold addresses
    rather than by scanning the blob — a first version of this test regexed
    the whole JSON and failed on the version in `Chrome/124.0.0.0`.
    """
    addresses: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ip_keys and isinstance(value, str):
                    addresses.append(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(_fixture(source))
    assert addresses, f"{source} fixture carries no address at {ip_keys}; the check would be vacuous"
    documentation = (ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
    allowed = list(documentation)
    routable = [a for a in addresses if not any(ipaddress.ip_address(a) in net for net in allowed)]
    assert not routable, f"{source} fixture carries non-documentation addresses: {routable}"

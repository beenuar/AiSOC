"""Wazuh occurrences must keep vendor event identity separate from rule identity."""

from __future__ import annotations

from copy import deepcopy

import pytest
from app.connectors.wazuh import WazuhConnector


def _hit(document_id: str | None, timestamp: str, *, agent_id: str = "002") -> dict:
    hit = {
        "_index": "wazuh-alerts-4.x-2026.11.17",
        "_source": {
            "@timestamp": timestamp,
            "agent": {"id": agent_id, "name": f"test-host-{agent_id}"},
            "rule": {
                "id": "110300",
                "level": 12,
                "description": "Repeated authentication failures",
            },
            "full_log": "HTTP 401",
        },
    }
    if document_id is not None:
        hit["_id"] = document_id
    return hit


@pytest.mark.parametrize("document_id", ["document-first", None])
def test_external_id_identifies_the_event_and_preserves_rule_id(document_id):
    connector = WazuhConnector("https://wazuh.test.local:9200", "reader", "test-password")
    hit = _hit(document_id, "2026-11-16T02:57:34.421Z")

    event = connector.normalize(hit)
    replay = connector.normalize(deepcopy(hit))

    # Ingest chooses external_id for its replay-stable event UUID. A rule id
    # here makes every future hit of the rule look like the same redelivery.
    assert event["external_id"] == event["alert_id"]
    assert event["external_id"] != event["rule_id"]
    assert event["external_id"] == replay["external_id"]
    assert event["rule_id"] == "110300"
    assert event["raw_event"] == hit["_source"]


@pytest.mark.parametrize(
    "first_document,repeat_document,repeat_timestamp,repeat_agent",
    [
        ("document-first", "document-next-day", "2026-11-17T03:11:51.099Z", "002"),
        ("document-first", "document-same-time", "2026-11-16T02:57:34.421Z", "002"),
        ("document-first", "document-other-host", "2026-11-16T02:57:34.421Z", "003"),
        (None, None, "2026-11-17T03:11:51.099Z", "002"),
        (None, None, "2026-11-16T02:57:34.421Z", "003"),
    ],
)
def test_distinct_occurrences_of_one_rule_have_distinct_external_ids(first_document, repeat_document, repeat_timestamp, repeat_agent):
    connector = WazuhConnector("https://wazuh.test.local:9200", "reader", "test-password")
    first = connector.normalize(_hit(first_document, "2026-11-16T02:57:34.421Z"))
    repeat = connector.normalize(_hit(repeat_document, repeat_timestamp, agent_id=repeat_agent))

    assert first["rule_id"] == repeat["rule_id"] == "110300"
    assert first["external_id"] != repeat["external_id"]


def test_vulnerability_inventory_preserves_document_identity():
    connector = WazuhConnector("https://wazuh.test.local:9200", "reader", "test-password")
    hit = _hit("vulnerability-document", "2026-11-17T03:11:51.099Z")
    hit["_source"]["data"] = {"vulnerability": {"cve": "CVE-2026-0001", "severity": "High"}}

    finding = connector.normalize_vulnerability(hit)

    assert finding is not None
    assert finding["external_id"] == "vulnerability-document"
    assert finding["hostname"] == "test-host-002"

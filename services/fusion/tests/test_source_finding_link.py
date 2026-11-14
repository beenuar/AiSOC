"""The join key has to survive the trip, or the return leg has nothing to aim at.

Ingest has always produced the vendor's own identifier for a finding — the
normalizer maps ``external_id`` onto OCSF ``finding.uid`` — and fusion threw
it away. By the time a row reached ``alerts`` the Splunk notable's rule UID,
the Elastic signal id and the QRadar offense id had all been discarded, so
"which finding produced this alert" had no answer and no verdict could be
written back.

Two claims here: the promoter carries the id onto the alert, and the sink
records the reconciliation row — but only for a vendor whose findings AiSOC
can actually write to. A link for a vendor with no writeback arm would read as
a two-way integration that is not one.
"""

from __future__ import annotations

import uuid

import pytest
from app.services.alert_sink import writeback_vendor
from app.services.promoter import promote_normalized_event


def _finding(external_uid: str | None = "NOTABLE-42", **overrides) -> dict:
    ocsf: dict = {
        "class_uid": 2001,
        "category_uid": 2,
        "severity_id": 4,
        "message": "Credential stuffing on svc-01",
        "metadata": {"product": {"vendor_name": "Splunk", "name": "Enterprise Security"}},
        "device": {"name": "svc-01"},
        "src_endpoint": {"ip": "198.51.100.7"},
    }
    if external_uid is not None:
        ocsf["finding"] = {"uid": external_uid, "desc": "120 failed logins in 4 minutes"}
    ocsf.update(overrides)
    return ocsf


def _message(ocsf: dict) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "connector_id": str(uuid.uuid4()),
        "connector_type": "splunk",
        "tenant_id": str(uuid.uuid4()),
        "ocsf_event": ocsf,
        "normalization_version": "1.1.0",
    }


def test_promoter_carries_the_vendor_finding_id_onto_the_alert() -> None:
    alert = promote_normalized_event(_message(_finding()))
    assert alert is not None
    assert alert.external_id == "NOTABLE-42"


def test_metadata_uid_is_the_fallback() -> None:
    """Some profiles carry the vendor id on metadata rather than finding."""
    ocsf = _finding(external_uid=None)
    ocsf["metadata"]["uid"] = "OFFENSE-9"
    alert = promote_normalized_event(_message(ocsf))
    assert alert is not None
    assert alert.external_id == "OFFENSE-9"


def test_no_vendor_id_is_none_not_an_empty_string() -> None:
    """NULL means 'no finding behind this alert'; '' would look like one."""
    alert = promote_normalized_event(_message(_finding(external_uid=None)))
    assert alert is not None
    assert alert.external_id is None


def test_an_oversized_identifier_is_bounded() -> None:
    alert = promote_normalized_event(_message(_finding(external_uid="x" * 4000)))
    assert alert is not None
    assert alert.external_id is not None
    assert len(alert.external_id) == 512


@pytest.mark.parametrize(
    ("connector_type", "expected"),
    [
        ("splunk", "splunk"),
        ("splunk_enterprise", "splunk"),
        ("Elastic", "elastic"),
        ("microsoft_sentinel", "sentinel"),
        ("ibm_qradar", "qradar"),
        ("microsoft_defender", "defender"),
    ],
)
def test_siem_connectors_resolve_to_a_writeback_vendor(connector_type: str, expected: str) -> None:
    assert writeback_vendor(connector_type) == expected


@pytest.mark.parametrize("connector_type", ["okta", "crowdstrike", "pagerduty", "aws_cloudtrail", "", None])
def test_sources_with_no_return_leg_resolve_to_nothing(connector_type: str | None) -> None:
    """Most sources are not a SIEM whose findings AiSOC can write to.

    Linking them anyway would put rows in the reconciliation table that read
    as a two-way integration and answer ``executor_not_found`` if anything
    ever dispatched against them.
    """
    assert writeback_vendor(connector_type) is None

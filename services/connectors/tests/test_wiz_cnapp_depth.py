"""Wiz reads more than issues, and what it reads does not become an alert.

Depth-2 item 8.1.

What was wrong
--------------
`wiz.py` pulled `issues` and nothing else, so the only thing AiSOC knew about
a cloud estate from a CNAPP was what the vendor had already correlated and
raised. The three other finding classes its API offers -- vulnerabilities,
configuration findings and runtime detections -- were never requested, and
`posture_findings`, the table that models exactly this, had no writer at all.

What this file asserts
----------------------
The connector against a mocked Wiz GraphQL endpoint. Several assertions are
on the **request** rather than on the parsed result, because a mock that
answers whatever it is asked cannot tell a correct query from a wrong one --
and two of the three defects worth catching here (the default type filter and
the FAIL filter) live in the request and are invisible in the response.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from app.connectors.wiz import WizConnector

pytestmark = pytest.mark.asyncio

_API = "https://api.test.app.wiz.io/graphql"
_AUTH = "https://auth.app.wiz.io/oauth/token"

_LADDER = {"info", "low", "medium", "high", "critical"}


def _connector(**toggles: object) -> WizConnector:
    return WizConnector(
        client_id="cid",
        client_secret="secret",
        api_endpoint_url=_API,
        **toggles,  # type: ignore[arg-type]
    )


def _auth_route() -> None:
    respx.post(_AUTH).mock(return_value=httpx.Response(200, json={"access_token": "tok"}))


def _requests() -> list[dict]:
    """Every GraphQL body the connector sent, decoded."""
    out = []
    for call in respx.calls:
        if str(call.request.url) == _API:
            out.append(json.loads(call.request.content))
    return out


# --- vendor-shaped payloads -------------------------------------------------
# Field names and nesting follow the queries two independently maintained
# shipped integrations drive against this API (Elastic's Wiz package and
# Cribl's collector templates), not a shape invented to match the parser.

_VULN_NODE = {
    "id": "vf-1",
    "name": "CVE-2026-11111",
    "CVEDescription": "A heap overflow in libwidget.",
    "CVSSSeverity": "HIGH",
    "vendorSeverity": "CRITICAL",
    "score": 9.1,
    "hasExploit": True,
    "hasCisaKevExploit": True,
    "status": "OPEN",
    "detailedName": "libwidget 1.2.3",
    "version": "1.2.3",
    "fixedVersion": "1.2.4",
    "lastDetectedAt": "2026-10-30T10:00:00Z",
    "vulnerableAsset": {
        "id": "wiz-asset-1",
        "type": "VIRTUAL_MACHINE",
        "name": "web-01.corp.example",
        "region": "us-east-1",
        "providerUniqueId": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
        "cloudPlatform": "AWS",
        "subscriptionExternalId": "123456789012",
        "operatingSystem": "Ubuntu 22.04",
        "ipAddresses": ["198.51.100.10"],
    },
}

_CONFIG_NODE = {
    "id": "cf-1",
    "analyzedAt": "2026-10-30T09:00:00Z",
    "updatedAt": "2026-10-30T09:30:00Z",
    "severity": "CRITICAL",
    "result": "FAIL",
    "remediation": "Enable Block Public Access.",
    "resource": {
        "id": "wiz-res-9",
        "providerId": "arn:aws:s3:::quarterly-reports",
        "name": "quarterly-reports",
        "nativeType": "bucket",
        "type": "BUCKET",
        "region": "us-east-1",
        "cloudPlatform": "AWS",
        "subscription": {"externalId": "123456789012", "cloudProvider": "AWS"},
    },
    "rule": {
        "id": "rule-uuid",
        "shortId": "CF-AWS-S3-01",
        "name": "S3 bucket is publicly readable",
        "description": "The bucket policy grants read to every principal.",
        "remediationInstructions": "Set BlockPublicAcls and BlockPublicPolicy.",
    },
    "evidence": {"currentValue": "PUBLIC", "expectedValue": "PRIVATE", "configurationPath": "policy.Statement[0]"},
}

_DETECTION_NODE = {
    "id": "det-1",
    "type": "MATCH_ONLY",
    "severity": "HIGH",
    "createdAt": "2026-10-30T11:00:00Z",
    "updatedAt": "2026-10-30T11:05:00Z",
    "description": "Credential access from an unfamiliar ASN.",
    "primaryResource": {
        "id": "wiz-res-3",
        "type": "VIRTUAL_MACHINE",
        "name": "web-01.corp.example",
        "externalId": "i-0abc",
        "region": "us-east-1",
    },
    "primaryActor": {"id": "a-1", "name": "svc-deploy", "type": "SERVICE_ACCOUNT", "externalId": "AIDA1"},
    "ruleMatch": {"rule": {"id": "tdr-7", "name": "Suspicious credential read"}},
}


def _page(root: str, nodes: list[dict], *, cursor: str | None = None) -> dict:
    return {
        "data": {
            root: {
                "nodes": nodes,
                "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
            }
        }
    }


# --- the issue path is unchanged --------------------------------------------


@respx.mock
async def test_issues_still_become_alerts_and_keep_the_raw_event_envelope() -> None:
    """The regression guard. Adding context reads must not disturb the one
    read that is supposed to produce alerts."""
    _auth_route()
    respx.post(_API).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "issues": {
                        "nodes": [
                            {
                                "id": "iss-1",
                                "severity": "CRITICAL",
                                "title": "Publicly exposed bucket with sensitive data",
                                "description": "d",
                                "createdAt": "2026-10-30T09:00:00Z",
                                "entitySnapshot": {"id": "r-1", "name": "quarterly-reports", "cloudPlatform": "AWS"},
                                "sourceRule": {"id": "sr-1", "name": "Public bucket"},
                            }
                        ]
                    }
                }
            },
        )
    )

    events = await _connector().fetch_alerts(300)

    assert len(events) == 1
    assert events[0]["source"] == "wiz"
    assert events[0]["severity"] == "critical"
    # The canonical envelope key. `raw` would fall through to the lenient
    # profile and be classified category 4, which never promotes.
    assert "raw_event" in events[0]
    assert "raw" not in events[0]


# --- off by default ---------------------------------------------------------


@respx.mock
async def test_every_context_read_is_off_until_the_tenant_turns_it_on() -> None:
    """Each read is a standing poll against someone else's API and needs a
    scope the customer's client may not hold."""
    _auth_route()
    route = respx.post(_API).mock(return_value=httpx.Response(200, json={"data": {}}))
    connector = _connector()

    assert await connector.fetch_vulnerability_findings() == []
    assert await connector.fetch_cloud_security_findings() == []

    assert not route.called, "a disabled read still called the vendor"


async def test_a_string_toggle_from_a_hand_written_row_is_honoured() -> None:
    """The wizard sends booleans; an instance row edited by hand sends
    strings. An unparseable value must mean off, never on."""
    assert _connector(collect_vulnerabilities="true")._collect_vulnerabilities is True
    assert _connector(collect_vulnerabilities="1")._collect_vulnerabilities is True
    assert _connector(collect_vulnerabilities="nonsense")._collect_vulnerabilities is False
    assert _connector()._collect_vulnerabilities is False


# --- vulnerabilities --------------------------------------------------------


@respx.mock
async def test_vulnerability_findings_are_shaped_for_the_inventory_writer() -> None:
    """`sync_findings` needs a CVE and a hostname and drops anything else, so
    the connector has to supply exactly those two, under those names."""
    _auth_route()
    respx.post(_API).mock(return_value=httpx.Response(200, json=_page("vulnerabilityFindings", [_VULN_NODE])))

    findings = await _connector(collect_vulnerabilities=True).fetch_vulnerability_findings()

    assert len(findings) == 1
    finding = findings[0]
    # `name` is the CVE and `detailedName` is the package. Confusing them puts
    # "libwidget 1.2.3" in the cve_id column, where the writer drops it as
    # un-matchable against KEV and counts it as skipped.
    assert finding["cve_id"] == "CVE-2026-11111"
    assert finding["title"] == "libwidget 1.2.3"
    assert finding["hostname"] == "web-01.corp.example"
    assert finding["ip_address"] == "198.51.100.10"
    assert finding["source"] == "wiz"
    assert finding["cvss_score"] == 9.1
    # vendorSeverity wins over CVSSSeverity: it is the tier the customer sees
    # in their own console.
    assert finding["severity"] == "critical"
    assert finding["severity"] in _LADDER


@respx.mock
async def test_a_vulnerability_with_no_asset_name_is_dropped_not_half_written() -> None:
    _auth_route()
    orphan = {**_VULN_NODE, "id": "vf-2", "vulnerableAsset": {"id": "x", "name": ""}}
    respx.post(_API).mock(return_value=httpx.Response(200, json=_page("vulnerabilityFindings", [orphan])))

    assert await _connector(collect_vulnerabilities=True).fetch_vulnerability_findings() == []


# --- configuration findings -------------------------------------------------


@respx.mock
async def test_configuration_findings_request_only_failures() -> None:
    """A passing check is a compliance datum, not a finding. Asserted on the
    request: a mock would happily return PASS rows and the parser would
    happily store them."""
    _auth_route()
    respx.post(_API).mock(return_value=httpx.Response(200, json=_page("configurationFindings", [_CONFIG_NODE])))

    await _connector(collect_configuration_findings=True).fetch_cloud_security_findings()

    sent = _requests()[-1]
    assert sent["variables"]["filterBy"]["result"] == ["FAIL"]
    assert "configurationFindings" in sent["query"]


@respx.mock
async def test_a_configuration_finding_carries_every_key_its_resource_answers_to() -> None:
    """An alert knows a resource by whichever identifier its own vendor
    emitted. Storing one of the CNAPP's three would mean a finding on a bucket
    never matches an alert that names it by ARN."""
    _auth_route()
    respx.post(_API).mock(return_value=httpx.Response(200, json=_page("configurationFindings", [_CONFIG_NODE])))

    findings = await _connector(collect_configuration_findings=True).fetch_cloud_security_findings()

    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_class"] == "misconfiguration"
    assert finding["external_id"] == "cf-1"
    assert finding["cloud_provider"] == "aws"
    assert finding["cloud_account"] == "123456789012"
    assert finding["severity"] == "critical"
    assert finding["rule_id"] == "CF-AWS-S3-01"
    assert finding["resource_id"] == "arn:aws:s3:::quarterly-reports"
    assert finding["resource_keys"] == [
        "arn:aws:s3:::quarterly-reports",
        "wiz-res-9",
        "quarterly-reports",
    ]
    assert finding["remediation_guide"] == "Set BlockPublicAcls and BlockPublicPolicy."
    assert finding["evidence"]["currentValue"] == "PUBLIC"


# --- runtime detections -----------------------------------------------------


@respx.mock
async def test_wiz_detections_request_both_types() -> None:
    """Wiz applies a default type filter of GENERATED_THREAT the moment any
    filterBy is sent, which silently drops MATCH_ONLY detections -- rule
    matches that did not raise a threat issue, and exactly the weak signals
    this read exists to supply.

    This is the negative-control-shaped assertion for the whole read: removing
    the explicit `type` filter leaves a query that still returns rows from any
    mock and still returns rows from a real tenant, just the wrong subset. No
    assertion on the response can see it.
    """
    _auth_route()
    respx.post(_API).mock(return_value=httpx.Response(200, json=_page("detections", [_DETECTION_NODE])))

    await _connector(collect_runtime_detections=True).fetch_cloud_security_findings()

    sent = _requests()[-1]
    assert sorted(sent["variables"]["filterBy"]["type"]["equals"]) == ["GENERATED_THREAT", "MATCH_ONLY"]


@respx.mock
async def test_a_runtime_detection_is_context_with_its_actor_and_resource() -> None:
    _auth_route()
    respx.post(_API).mock(return_value=httpx.Response(200, json=_page("detections", [_DETECTION_NODE])))

    findings = await _connector(collect_runtime_detections=True).fetch_cloud_security_findings()

    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_class"] == "runtime_detection"
    assert finding["severity"] == "high"
    assert finding["rule_title"] == "Suspicious credential read"
    assert "i-0abc" in finding["resource_keys"]
    assert "svc-deploy" in finding["resource_keys"]


# --- the failure modes that would read as a clean estate --------------------


@respx.mock
async def test_a_graphql_error_raises_rather_than_reading_as_no_findings() -> None:
    """A 200 carrying `errors` and a null `data` is how this API reports a
    missing scope. Returning an empty page for it turns "your API client
    cannot read configuration findings" into "your cloud estate is clean",
    which is the substitution this whole item exists to stop making."""
    _auth_route()
    respx.post(_API).mock(
        return_value=httpx.Response(
            200,
            json={"data": None, "errors": [{"message": "insufficient scope: read:cloud_configuration"}]},
        )
    )

    with pytest.raises(RuntimeError, match="insufficient scope"):
        await _connector(collect_configuration_findings=True).fetch_cloud_security_findings()


@respx.mock
async def test_paging_follows_the_cursor_to_the_end() -> None:
    _auth_route()
    second = {**_CONFIG_NODE, "id": "cf-2"}
    respx.post(_API).mock(
        side_effect=[
            httpx.Response(200, json=_page("configurationFindings", [_CONFIG_NODE], cursor="c1")),
            httpx.Response(200, json=_page("configurationFindings", [second])),
        ]
    )

    findings = await _connector(collect_configuration_findings=True).fetch_cloud_security_findings()

    assert [f["external_id"] for f in findings] == ["cf-1", "cf-2"]
    assert _requests()[1]["variables"]["after"] == "c1"


@respx.mock
async def test_paging_is_capped_so_one_poll_cannot_read_forever() -> None:
    """A CNAPP backlog is routinely tens of thousands of findings and the
    schedule is five minutes."""
    _auth_route()
    respx.post(_API).mock(return_value=httpx.Response(200, json=_page("configurationFindings", [_CONFIG_NODE], cursor="always-more")))

    findings = await _connector(collect_configuration_findings=True).fetch_cloud_security_findings()

    from app.connectors.wiz import _MAX_PAGES

    assert len(findings) == _MAX_PAGES
    assert len(_requests()) == _MAX_PAGES

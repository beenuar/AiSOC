"""Gap-closure Phase 4.2: the vendor reads an investigation could not make.

Every payload below is **synthetic**, shaped to the vendor's published
response schema, and no call in this file reaches a real vendor. That is
stated because a recorded-looking fixture that was in fact invented is the
kind of thing this repository publishes honestly or not at all.

Three properties are under test, and they are the three the plan turns on.

**A read failure is never an empty result.** Each executor has a test that
breaks its vendor and asserts the outcome is `FAILED` with an error that says
so, because an empty list reaching a model reads as evidence of absence and
gets reasoned on as if the host were clean. The distinction is asserted at
the executor boundary, which is where a caller sees it.

**Not-found and could-not-read are different answers.** A host that no longer
exists is `SUCCEEDED` with `found: False`; a vendor that 500s is `FAILED`.
Both tested for the same verb so the pair cannot collapse.

**Query text is built by the executor, never by its caller.** The Defender
telemetry verb takes a template name and refuses anything else, and the
Entra reads escape the principal name into the OData literal. Both are
asserted on the bytes that reach the wire rather than on the arguments,
because asserting on the arguments would be comparing the caller against
itself.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Any

import httpx
import pytest
import respx
from app.clients.aws_cloudtrail_client import AWSCloudTrailClient, CloudTrailLookupError
from app.clients.defender_client import _HUNT_TEMPLATES
from app.live_actions import dispatch
from app.live_actions.investigation_reads import (
    AWSLookupCloudAudit,
    DefenderGetDetections,
    DefenderLookupEndpointTelemetry,
    EntraGetUserActivity,
    GoogleWorkspaceGetUserActivity,
    SentinelOneGetDetections,
    SentinelOneGetHost,
)
from app.live_actions.models import LiveActionRequest, LiveActionStatus

S1_CONSOLE = "https://usea1-partners.sentinelone.net"
S1_API = f"{S1_CONSOLE}/web/api/v2.1"
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
MDE = "https://api.securitycenter.microsoft.com/api"
TOKEN_HOST = "https://login.microsoftonline.com"
GWS_REPORTS = "https://admin.googleapis.com/admin/reports/v1"

S1_CREDS = {"s1_console_url": S1_CONSOLE, "s1_api_token": "s1-token"}
MDE_CREDS = {"mde_tenant_id": "t", "mde_client_id": "c", "mde_client_secret": "s"}
ENTRA_CREDS = {"azure_tenant_id": "t", "azure_client_id": "c", "azure_client_secret": "s"}
AWS_CREDS = {"aws_access_key_id": "AKIAEXAMPLE", "aws_secret_access_key": "secret", "aws_region": "us-east-1"}

#: A Google service-account key has to parse and has to carry a usable RSA
#: private key, because the client signs a JWT during `_mint_token`. Rather
#: than ship a key, the tests that need a token stub `_ensure_token`, and this
#: shape exists only so the factory returns a client at all.
GWS_CREDS = {
    "gws_service_account_key": json.dumps({"client_email": "svc@example.iam.gserviceaccount.com", "private_key": "unused-in-these-tests"}),
    "gws_subject_email": "admin@example.com",
}


#: A fixed tenant so the dispatcher's per-tenant policy lookups are stable
#: across the file. `LiveActionRequest` types both of these as UUIDs.
TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _request(target: str, params: Mapping[str, Any]) -> LiveActionRequest:
    """Build a request. ``Mapping`` because ``dict`` is invariant in its value
    type, so a ``dict[str, str]`` credential bag is not a ``dict[str, object]``
    and every call site would need a cast."""
    return LiveActionRequest(
        request_id=uuid.uuid4(),
        capability="unused",
        vendor_id="unused",
        target=target,
        params=dict(params),
        dry_run=False,
        tenant_id=TENANT,
    )


def _entra_token() -> None:
    respx.post(f"{TOKEN_HOST}/t/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "graph-token"}))


def _mde_token() -> None:
    respx.post(f"{TOKEN_HOST}/t/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "mde-token"}))


# --------------------------------------------------------------- SentinelOne


@pytest.mark.asyncio
@respx.mock
async def test_sentinelone_get_host_projects_the_fields_that_matter() -> None:
    """A SentinelOne agent record is ~60 fields; twelve reach the caller."""
    respx.get(f"{S1_API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "uuid": "agent-uuid-1",
                        "computerName": "WS-42",
                        "osName": "Windows 11 Pro",
                        "osRevision": "22631",
                        "agentVersion": "23.4.2.350",
                        "lastIpToMgmt": "10.1.2.3",
                        "externalIp": "203.0.113.9",
                        "lastActiveDate": "2026-09-26T10:00:00Z",
                        "networkStatus": "connected",
                        "infected": True,
                        "activeThreats": 2,
                        "isUpToDate": True,
                        # Noise the projection must drop rather than forward.
                        "licenseKey": "should-not-travel",
                        "siteName": "Acme",
                        "groupIp": "10.1.2.0",
                    }
                ]
            },
        )
    )
    result = await SentinelOneGetHost().execute(_request("WS-42", S1_CREDS))

    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["found"] is True
    assert result.details["agent_uuid"] == "agent-uuid-1"
    assert result.details["active_threats"] == 2
    # The projection is a bound on token cost and on what attacker-influenced
    # vendor text can carry into a prompt, so it is asserted as a closed set
    # rather than as "contains the fields I care about".
    assert "licenseKey" not in result.details
    assert "siteName" not in result.details


@pytest.mark.asyncio
@respx.mock
async def test_sentinelone_get_host_distinguishes_absent_from_unreadable() -> None:
    """The pair that must never collapse, asserted in one test so it cannot."""
    respx.get(f"{S1_API}/agents").mock(return_value=httpx.Response(200, json={"data": []}))
    absent = await SentinelOneGetHost().execute(_request("GONE-01", S1_CREDS))

    assert absent.status is LiveActionStatus.SUCCEEDED
    assert absent.details["found"] is False

    respx.get(f"{S1_API}/agents").mock(return_value=httpx.Response(503, text="upstream unavailable"))
    broken = await SentinelOneGetHost().execute(_request("WS-42", S1_CREDS))

    assert broken.status is LiveActionStatus.FAILED
    assert "SentinelOne read failed" in (broken.error or "")
    # The load-bearing assertion: nothing in a failed read looks like a clean
    # host. `found` absent rather than False, and no empty record.
    assert "found" not in broken.details


@pytest.mark.asyncio
@respx.mock
async def test_sentinelone_get_detections_reads_the_edr_verdict() -> None:
    respx.get(f"{S1_API}/threats").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "threat-1",
                        "createdAt": "2026-09-26T09:00:00Z",
                        "threatInfo": {
                            "threatName": "Trojan.GenericKD",
                            "classification": "Malware",
                            "confidenceLevel": "malicious",
                            "analystVerdict": "true_positive",
                            "mitigationStatus": "mitigated",
                            "sha256": "a" * 64,
                            "filePath": "C:\\Users\\svc\\AppData\\evil.exe",
                            "processUser": "ACME\\svc_deploy",
                            "createdAt": "2026-09-26T09:00:00Z",
                            "storyline": "A1B2C3",
                        },
                    }
                ]
            },
        )
    )
    result = await SentinelOneGetDetections().execute(_request("WS-42", S1_CREDS))

    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["count"] == 1
    detection = result.details["detections"][0]
    assert detection["verdict"] == "true_positive"
    assert detection["classification"] == "Malware"
    assert detection["sha256"] == "a" * 64


@pytest.mark.asyncio
@respx.mock
async def test_sentinelone_get_detections_failure_is_not_zero_detections() -> None:
    respx.get(f"{S1_API}/threats").mock(return_value=httpx.Response(500, text="boom"))
    result = await SentinelOneGetDetections().execute(_request("WS-42", S1_CREDS))

    assert result.status is LiveActionStatus.FAILED
    # A `count: 0` here would be read as "the EDR has nothing on this host",
    # which is the strongest possible exonerating evidence and would be false.
    assert "count" not in result.details
    assert "detections" not in result.details


# ------------------------------------------------------------------ Defender


@pytest.mark.asyncio
@respx.mock
async def test_defender_get_detections_includes_resolved_alerts() -> None:
    """Resolved alerts are the evidence that settles a repeat finding."""
    _mde_token()
    respx.get(f"{MDE}/machines").mock(return_value=httpx.Response(200, json={"value": [{"id": "machine-1", "computerDnsName": "WS-42"}]}))
    respx.get(f"{MDE}/machines/machine-1/alerts").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "alert-1",
                        "title": "Suspicious PowerShell",
                        "severity": "Medium",
                        "category": "Execution",
                        "status": "Resolved",
                        "classification": "FalsePositive",
                        "determination": "SecurityTesting",
                        "detectionSource": "WindowsDefenderAtp",
                        "alertCreationTime": "2026-09-01T08:00:00Z",
                        "resolvedTime": "2026-09-01T09:00:00Z",
                    },
                    {
                        "id": "alert-2",
                        "title": "Suspicious PowerShell",
                        "severity": "Medium",
                        "status": "New",
                        "alertCreationTime": "2026-09-26T08:00:00Z",
                    },
                ]
            },
        )
    )
    result = await DefenderGetDetections().execute(_request("WS-42", MDE_CREDS))

    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["count"] == 2
    statuses = {row["status"] for row in result.details["detections"]}
    assert statuses == {"Resolved", "New"}
    assert result.details["detections"][0]["classification"] == "FalsePositive"


@pytest.mark.asyncio
@respx.mock
async def test_defender_get_detections_unresolvable_machine_is_not_a_clean_host() -> None:
    """A host Defender does not know is reported as not found, not as clean."""
    _mde_token()
    respx.get(f"{MDE}/machines").mock(return_value=httpx.Response(200, json={"value": []}))
    result = await DefenderGetDetections().execute(_request("UNKNOWN-01", MDE_CREDS))

    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["found"] is False
    assert "no Defender machine matches" in result.summary


@pytest.mark.asyncio
@respx.mock
async def test_defender_telemetry_refuses_anything_but_a_known_template() -> None:
    """The security boundary: no caller supplies query text.

    Refused before the credential is touched, so an operator is not sent to
    look at their Azure app registration for a caller's mistake.
    """
    route = respx.post(f"{MDE}/advancedqueries/run").mock(return_value=httpx.Response(200, json={"Results": []}))

    for attempt in (
        "DeviceProcessEvents | project *",
        "file_hash_sightings; DeviceInfo",
        "",
        "FILE_HASH_SIGHTINGS",
    ):
        result = await DefenderLookupEndpointTelemetry().execute(_request("a" * 64, {**MDE_CREDS, "template": attempt}))
        assert result.status is LiveActionStatus.FAILED, attempt
        assert "Query text is not accepted" in (result.error or ""), attempt

    assert not route.called, "a refused template must not reach the vendor"


@pytest.mark.asyncio
@respx.mock
async def test_defender_telemetry_binds_the_indicator_and_never_interpolates_it() -> None:
    """Asserted on the KQL that reaches the wire, not on the argument."""
    _mde_token()
    captured: dict[str, str] = {}

    def run(request: httpx.Request) -> httpx.Response:
        captured["query"] = json.loads(request.content)["Query"]
        return httpx.Response(200, json={"Results": [{"DeviceName": "WS-42", "FileName": "evil.exe"}]})

    respx.post(f"{MDE}/advancedqueries/run").mock(side_effect=run)

    # A value carrying KQL syntax and a quote. If it were interpolated into
    # the query body rather than bound as a literal, the `|` would start a
    # new pipeline stage.
    hostile = 'abc" | project *; DeviceInfo //'
    result = await DefenderLookupEndpointTelemetry().execute(
        _request(hostile, {**MDE_CREDS, "template": "file_hash_sightings", "hours": 48})
    )

    assert result.status is LiveActionStatus.SUCCEEDED
    query = captured["query"]
    # The escaped form is present and the raw form is not, so the value
    # cannot have closed the literal.
    assert 'let target = "abc\\" | project *; DeviceInfo //";' in query
    assert "let window = 48h;" in query
    # The template body is the shipped constant, character for character.
    assert _HUNT_TEMPLATES["file_hash_sightings"] in query
    assert result.details["distinct_hosts"] == ["WS-42"]


@pytest.mark.asyncio
@respx.mock
async def test_defender_telemetry_caps_the_window_and_the_row_count() -> None:
    _mde_token()
    captured: dict[str, str] = {}

    def run(request: httpx.Request) -> httpx.Response:
        captured["query"] = json.loads(request.content)["Query"]
        return httpx.Response(200, json={"Results": []})

    respx.post(f"{MDE}/advancedqueries/run").mock(side_effect=run)
    await DefenderLookupEndpointTelemetry().execute(
        _request("a" * 64, {**MDE_CREDS, "template": "network_sightings", "hours": 99_999, "limit": 10_000})
    )

    # 720h and 200 rows are the caps. A caller asking for a year of telemetry
    # at ten thousand rows is asking for a different job than a pivot, and an
    # uncapped request is a cheap way to stall a tool loop.
    assert "let window = 720h;" in captured["query"]
    assert "| limit 200" in captured["query"]


# --------------------------------------------------------------- Entra ID


@pytest.mark.asyncio
@respx.mock
async def test_entra_get_user_activity_returns_successes_and_failures() -> None:
    """Both outcomes, because the pattern is the finding."""
    _entra_token()
    respx.get(f"{GRAPH}/auditLogs/signIns").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "createdDateTime": "2026-09-26T10:00:00Z",
                        "ipAddress": "203.0.113.9",
                        "appDisplayName": "Office 365 Exchange Online",
                        "clientAppUsed": "Browser",
                        "status": {"errorCode": 0},
                        "conditionalAccessStatus": "success",
                        "riskLevelDuringSignIn": "high",
                        "riskState": "atRisk",
                        "location": {"countryOrRegion": "NL", "city": "Amsterdam"},
                    },
                    {
                        "createdDateTime": "2026-09-26T09:58:00Z",
                        "ipAddress": "203.0.113.9",
                        "status": {"errorCode": 50126, "failureReason": "Invalid username or password."},
                        "location": {"countryOrRegion": "NL"},
                    },
                ]
            },
        )
    )
    respx.get(f"{GRAPH_BETA}/identityProtection/riskyUsers").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "riskLevel": "high",
                        "riskState": "atRisk",
                        "riskDetail": "none",
                        "riskLastUpdatedDateTime": "2026-09-26T10:01:00Z",
                    }
                ]
            },
        )
    )
    result = await EntraGetUserActivity().execute(_request("j.doe@example.com", ENTRA_CREDS))

    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["count"] == 2
    assert result.details["failed_sign_ins"] == 1
    assert result.details["distinct_source_ips"] == ["203.0.113.9"]
    assert result.details["risk"]["risk_level"] == "high"
    # errorCode 0 is Graph's success. Rendered as a boolean so a model is not
    # asked to interpret a vendor error number.
    assert result.details["sign_ins"][0]["succeeded"] is True
    assert result.details["sign_ins"][1]["succeeded"] is False


@pytest.mark.asyncio
@respx.mock
async def test_entra_missing_risk_record_reads_as_unknown_not_as_clear() -> None:
    """ID Protection is licensed. Its absence must not exonerate an account."""
    _entra_token()
    respx.get(f"{GRAPH}/auditLogs/signIns").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{GRAPH_BETA}/identityProtection/riskyUsers").mock(return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}}))

    result = await EntraGetUserActivity().execute(_request("j.doe@example.com", ENTRA_CREDS))

    # The sign-in read succeeded, so the verb succeeds. The risk leg failing
    # must not take it down, and must not read as "no risk".
    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["risk"] is None
    reason = result.details["risk_unavailable_reason"]
    assert reason
    assert "unknown" in reason.lower() or "HTTPStatusError" in reason


@pytest.mark.asyncio
@respx.mock
async def test_entra_sign_in_read_failure_is_failed_not_empty() -> None:
    _entra_token()
    respx.get(f"{GRAPH}/auditLogs/signIns").mock(return_value=httpx.Response(500, text="boom"))
    result = await EntraGetUserActivity().execute(_request("j.doe@example.com", ENTRA_CREDS))

    assert result.status is LiveActionStatus.FAILED
    assert "count" not in result.details
    assert "sign_ins" not in result.details


@pytest.mark.asyncio
@respx.mock
async def test_entra_escapes_the_principal_into_the_odata_literal() -> None:
    """A UPN out of alert text must not be able to close the literal."""
    _entra_token()
    captured: dict[str, str] = {}

    def signins(request: httpx.Request) -> httpx.Response:
        captured["filter"] = request.url.params.get("$filter", "")
        return httpx.Response(200, json={"value": []})

    respx.get(f"{GRAPH}/auditLogs/signIns").mock(side_effect=signins)
    respx.get(f"{GRAPH_BETA}/identityProtection/riskyUsers").mock(return_value=httpx.Response(200, json={"value": []}))

    await EntraGetUserActivity().execute(_request("a' or userPrincipalName ne 'x", ENTRA_CREDS))

    # OData escapes a quote by doubling it. The doubled form present and the
    # single form absent is what proves the clause could not be closed.
    assert "'a'' or userPrincipalName ne ''x'" in captured["filter"]
    assert "'a' or" not in captured["filter"]


# ------------------------------------------------------- Google Workspace


@pytest.mark.asyncio
@respx.mock
async def test_google_workspace_login_audit_projects_and_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.clients import google_workspace_client as gws_module

    async def _no_token(self, client):  # noqa: ANN001, ANN202
        self._token = "gws-token"

    monkeypatch.setattr(gws_module.GoogleWorkspaceClient, "_ensure_token", _no_token, raising=True)

    respx.get(f"{GWS_REPORTS}/activities/users/user@example.com/applications/login").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": {"time": "2026-09-26T10:00:00.000Z"},
                        "ipAddress": "198.51.100.7",
                        "events": [
                            {
                                "name": "login_success",
                                "parameters": [
                                    {"name": "login_type", "value": "google_password"},
                                    {"name": "is_suspicious", "boolValue": True},
                                ],
                            }
                        ],
                    },
                    {
                        "id": {"time": "2026-09-26T09:59:00.000Z"},
                        "ipAddress": "198.51.100.8",
                        "events": [
                            {
                                "name": "login_failure",
                                "parameters": [{"name": "login_failure_type", "value": "login_failure_invalid_password"}],
                            }
                        ],
                    },
                ]
            },
        )
    )
    result = await GoogleWorkspaceGetUserActivity().execute(_request("user@example.com", GWS_CREDS))

    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["count"] == 2
    assert result.details["flagged_suspicious_by_google"] == 1
    assert result.details["distinct_source_ips"] == ["198.51.100.7", "198.51.100.8"]
    assert result.details["logins"][1]["failure_type"] == "login_failure_invalid_password"


@pytest.mark.asyncio
@respx.mock
async def test_google_workspace_403_names_the_missing_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """A scope gap is a configuration fact, not an account with no logins."""
    from app.clients import google_workspace_client as gws_module

    async def _no_token(self, client):  # noqa: ANN001, ANN202
        self._token = "gws-token"

    monkeypatch.setattr(gws_module.GoogleWorkspaceClient, "_ensure_token", _no_token, raising=True)
    respx.get(f"{GWS_REPORTS}/activities/users/user@example.com/applications/login").mock(
        return_value=httpx.Response(403, json={"error": {"message": "Not Authorized to access this resource/api"}})
    )

    result = await GoogleWorkspaceGetUserActivity().execute(_request("user@example.com", GWS_CREDS))

    assert result.status is LiveActionStatus.FAILED
    assert "admin.reports.audit.readonly" in (result.error or "")
    assert "count" not in result.details


# ------------------------------------------------------------ AWS CloudTrail


def _ct_client(transport: httpx.MockTransport) -> AWSCloudTrailClient:
    return AWSCloudTrailClient(
        access_key_id="AKIAEXAMPLE",
        secret_access_key="secret",
        region="us-east-1",
        transport=transport,
    )


@pytest.mark.asyncio
async def test_cloudtrail_signs_with_the_headers_it_sends() -> None:
    """The signature must cover exactly the headers that reach the wire.

    This is the failure mode of a hand-rolled SigV4: the signed-header list
    and the sent headers drift, and every call 403s. Asserted by parsing
    `SignedHeaders` out of the Authorization header the client produced and
    comparing it against the request's own header names.
    """
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={"Events": []})

    client = _ct_client(httpx.MockTransport(handler))
    await client.lookup_events(attribute_key="Username", attribute_value="svc_deploy")

    request = captured["request"]
    auth = request.headers["authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/")
    assert "/us-east-1/cloudtrail/aws4_request," in auth

    signed = auth.split("SignedHeaders=")[1].split(",")[0].split(";")
    assert signed == sorted(signed), "SignedHeaders must be lowercase-sorted"
    for name in signed:
        assert name in request.headers, f"{name} was signed and not sent"
    assert request.headers["x-amz-target"] == "CloudTrail_20131101.LookupEvents"
    assert request.headers["content-type"] == "application/x-amz-json-1.1"


def test_cloudtrail_canonical_request_is_the_documented_shape() -> None:
    """Pin the algorithm, not just the header it ends up in.

    `canonical_parts` is what `_authorization` itself calls, so this is not a
    second implementation the test compares against a copy of itself.
    """
    client = AWSCloudTrailClient("AKIAEXAMPLE", "secret", region="eu-west-1")
    payload = '{"MaxResults":1}'
    canonical, to_sign, signed_headers = client.canonical_parts(payload, "20260926T120000Z", "20260926")

    lines = canonical.split("\n")
    assert lines[0] == "POST"
    assert lines[1] == "/"
    assert lines[2] == "", "no query string on a CloudTrail POST"
    assert lines[3] == "content-type:application/x-amz-json-1.1"
    assert lines[4] == "host:cloudtrail.eu-west-1.amazonaws.com"
    assert lines[5] == "x-amz-date:20260926T120000Z"
    assert lines[6] == "x-amz-target:CloudTrail_20131101.LookupEvents"
    assert lines[7] == "", "a blank line separates canonical headers from signed headers"
    assert lines[8] == signed_headers == "content-type;host;x-amz-date;x-amz-target"
    # The payload hash is the last line, and it is the hash of the body.
    import hashlib

    assert lines[9] == hashlib.sha256(payload.encode()).hexdigest()

    scope_lines = to_sign.split("\n")
    assert scope_lines[0] == "AWS4-HMAC-SHA256"
    assert scope_lines[1] == "20260926T120000Z"
    assert scope_lines[2] == "20260926/eu-west-1/cloudtrail/aws4_request"
    assert scope_lines[3] == hashlib.sha256(canonical.encode()).hexdigest()


def test_cloudtrail_signing_key_derivation_is_sensitive_to_every_input() -> None:
    """A derivation that ignores an input would still look correct.

    Each of secret, date, region is changed in turn and the key must move.
    Without this the chain could drop a link and every signature would still
    be a plausible-looking hex string.
    """
    from app.clients.aws_cloudtrail_client import _signing_key

    base = _signing_key("secret", "20260926", "us-east-1")
    assert base != _signing_key("other", "20260926", "us-east-1")
    assert base != _signing_key("secret", "20260927", "us-east-1")
    assert base != _signing_key("secret", "20260926", "eu-west-1")
    assert len(base) == 32


@pytest.mark.asyncio
async def test_cloudtrail_session_token_is_signed_when_present() -> None:
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={"Events": []})

    client = AWSCloudTrailClient(
        "AKIAEXAMPLE",
        "secret",
        region="us-east-1",
        session_token="FwoGZXIvYXdzE",
        transport=httpx.MockTransport(handler),
    )
    await client.lookup_events(attribute_key="Username", attribute_value="svc_deploy")

    request = captured["request"]
    signed = request.headers["authorization"].split("SignedHeaders=")[1].split(",")[0].split(";")
    # A session token that is sent and not signed is rejected by AWS, and a
    # token that is signed and not sent is too.
    assert "x-amz-security-token" in signed
    assert request.headers["x-amz-security-token"] == "FwoGZXIvYXdzE"


@pytest.mark.asyncio
async def test_cloudtrail_projects_the_nested_event_record() -> None:
    """`CloudTrailEvent` is a JSON string holding kilobytes per call."""
    inner = {
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.9",
        "userAgent": "aws-cli/2.15.0",
        "errorCode": "AccessDenied",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/deploy/svc_deploy",
            "sessionContext": {"attributes": {"mfaAuthenticated": "false"}},
        },
        "requestParameters": {"noise": "x" * 5000},
        "responseElements": {"more": "y" * 5000},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "Events": [
                    {
                        "EventId": "evt-1",
                        "EventName": "GetSecretValue",
                        "EventSource": "secretsmanager.amazonaws.com",
                        "EventTime": "2026-09-26T10:00:00Z",
                        "Username": "svc_deploy",
                        "ReadOnly": "true",
                        "CloudTrailEvent": json.dumps(inner),
                    }
                ]
            },
        )

    events = await _ct_client(httpx.MockTransport(handler)).lookup_events(attribute_key="Username", attribute_value="svc_deploy")

    assert len(events) == 1
    event = events[0]
    assert event["event_name"] == "GetSecretValue"
    assert event["source_ip"] == "203.0.113.9"
    assert event["error_code"] == "AccessDenied"
    assert event["principal_arn"].endswith("svc_deploy")
    assert event["mfa_authenticated"] == "false"
    # The 10 KB of request parameters and response elements must not travel.
    assert "requestParameters" not in event
    assert "responseElements" not in event
    assert len(json.dumps(event)) < 800


@pytest.mark.asyncio
async def test_cloudtrail_malformed_detail_is_not_a_failed_lookup() -> None:
    """An unparseable record still answers the envelope-level question."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"Events": [{"EventId": "evt-1", "EventName": "AssumeRole", "CloudTrailEvent": "{not json"}]},
        )

    events = await _ct_client(httpx.MockTransport(handler)).lookup_events(attribute_key="EventName", attribute_value="AssumeRole")

    assert len(events) == 1
    assert events[0]["event_name"] == "AssumeRole"
    assert events[0]["source_ip"] is None


@pytest.mark.asyncio
async def test_cloudtrail_refuses_an_attribute_aws_does_not_define() -> None:
    """Refused here, with the supported set named, rather than sent."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"Events": []})

    client = _ct_client(httpx.MockTransport(handler))
    with pytest.raises(CloudTrailLookupError) as exc:
        await client.lookup_events(attribute_key="SourceIPAddress", attribute_value="203.0.113.9")

    assert "not a CloudTrail lookup attribute" in str(exc.value)
    assert "Username" in str(exc.value)
    assert not calls


@pytest.mark.asyncio
async def test_cloudtrail_refuses_an_empty_value() -> None:
    client = _ct_client(httpx.MockTransport(lambda r: httpx.Response(200, json={"Events": []})))
    with pytest.raises(CloudTrailLookupError) as exc:
        await client.lookup_events(attribute_key="Username", attribute_value="   ")
    assert "would match the whole window" in str(exc.value)


@pytest.mark.asyncio
async def test_cloudtrail_executor_reports_failure_rather_than_no_activity() -> None:
    """An AccessDenied must never read as a principal that did nothing."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"__type": "AccessDeniedException", "message": "not authorized"})

    executor = AWSLookupCloudAudit()
    request = _request("svc_deploy", {**AWS_CREDS, "attribute_key": "Username"})

    # The executor builds its own client from credentials, so the transport
    # is injected by patching the factory it calls. Patched at the executor's
    # import site rather than at the factory module, because that is the name
    # the executor actually resolves.
    import app.live_actions.investigation_reads as reads

    original = reads._cloudtrail_client
    reads._cloudtrail_client = lambda params: _ct_client(httpx.MockTransport(handler))  # type: ignore[assignment]
    try:
        result = await executor.execute(request)
    finally:
        reads._cloudtrail_client = original  # type: ignore[assignment]

    assert result.status is LiveActionStatus.FAILED
    assert "AccessDenied" in (result.error or "")
    assert "count" not in result.details
    assert "events" not in result.details


# --------------------------------------------- governed dispatch, end to end


@pytest.mark.asyncio
async def test_every_new_read_verb_is_automatic_and_needs_no_approval() -> None:
    """A read gated behind an analyst is how an agent learns to conclude blind.

    Driven through `dispatch` rather than by reading the contract, so the
    assertion covers the door an agent actually comes through: the contract,
    the approval matrix and the dispatcher composing.
    """
    from app.live_actions import register_builtin_executors

    register_builtin_executors(overwrite=True)

    cases = [
        ("sentinelone", "get_host", "WS-42"),
        ("sentinelone", "get_detections", "WS-42"),
        ("defender", "get_detections", "WS-42"),
        ("entra", "get_user_activity", "j.doe@example.com"),
        ("google_workspace", "get_user_activity", "user@example.com"),
        ("aws", "lookup_cloud_audit", "svc_deploy"),
        ("defender", "lookup_endpoint_telemetry", "a" * 64),
    ]
    for vendor_id, capability, target in cases:
        result = await dispatch(
            LiveActionRequest(
                request_id=uuid.uuid4(),
                capability=capability,
                vendor_id=vendor_id,
                target=target,
                params={},
                dry_run=True,
                tenant_id=TENANT,
                confidence=0.1,
            )
        )
        # A dry run with no credentials, at the lowest possible confidence.
        # The only outcome that must not appear is PENDING_APPROVAL: these
        # verbs change nothing, so nothing is waiting on a human.
        assert result.status is not LiveActionStatus.PENDING_APPROVAL, f"{vendor_id}/{capability} queued for approval"
        assert result.status is not LiveActionStatus.BLOCKED, f"{vendor_id}/{capability} was blocked by policy"

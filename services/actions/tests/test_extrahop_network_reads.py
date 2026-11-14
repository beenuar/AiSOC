"""Network evidence reads, and the one distinction that makes them evidence.

Depth plan wave 2, item 8.2. These two verbs exist so depth 4.5 can pull a
vendor's own network evidence for an alert instead of asserting around the
gap.

The property most of this file is about: **a read that could not happen is
not an empty result.** RevealX 360 record search needs a cloud recordstore
with Premium Investigation, and a deployment without one answers an error.
An investigation that reports "no flows involving this address" when
nothing was ever searched has stated a fact about the customer's network
that it did not establish, and an analyst would reasonably act on it.

Every endpoint, body field and response shape below is from ExtraHop's
current public REST API guide, verified 2026-11-01. The payloads are
synthetic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.clients.extrahop_client import ExtraHopClient, ExtraHopReadError  # noqa: E402

_RECORDS = {
    "records": [
        {
            "_type": "~flow",
            "_source": {
                "timestamp": 1793404800000,
                "clientAddr": "10.4.1.9",
                "serverAddr": "198.51.100.23",
                "clientPort": 51322,
                "serverPort": 443,
                "proto": "tls",
                "bytes": 918_233,
                "date_of_birth": "never-collected",
            },
        }
    ],
    "total": 1,
}

_DEVICES = [
    {
        "id": 77,
        "display_name": "WKS-4219",
        "ipaddr4": "10.4.1.9",
        "macaddr": "00:11:22:33:44:55",
        "role": "workstation",
        "analysis": "advanced",
        "critical": True,
        "notes": "never-collected",
    }
]


def _one_record() -> dict:
    """The single fixture record, typed, so a reader of this file is not
    indexing into an untyped literal three levels deep."""
    records = _RECORDS["records"]
    assert isinstance(records, list)
    return records[0]


def _transport(status: int = 200, payload=None, capture: dict | None = None):  # noqa: ANN001, ANN202
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        if capture is not None:
            capture["request"] = request
        if status != 200:
            return httpx.Response(status, json={"error": "no recordstore"})
        return httpx.Response(200, json=payload)

    return httpx.MockTransport(handle)


def _client(**kw) -> ExtraHopClient:  # noqa: ANN003
    return ExtraHopClient(api_host="https://h", client_id="a", client_secret="b", **kw)


class TestFlowSearch:
    @pytest.mark.asyncio
    async def test_it_searches_every_role_the_address_could_hold(self) -> None:
        """`.ipaddr` covers client, server, sender and receiver. Filtering on
        `clientAddr` alone would answer "this host initiated nothing" while
        missing every connection made to it."""
        capture: dict = {}
        records = await _client(transport=_transport(payload=_RECORDS, capture=capture)).search_flows("10.4.1.9")

        request = capture["request"]
        assert request.url.path == "/api/v1/records/search"
        body = json.loads(request.content)
        assert body["filter"] == {"field": ".ipaddr", "operand": "10.4.1.9", "operator": "="}
        assert body["until"] == 0
        assert body["from"] < 0, "a relative window is negative milliseconds, per the vendor's own documentation"
        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_records_are_projected_rather_than_forwarded(self) -> None:
        """A record carries every field its format defines. Handing all of it
        to a model is an unbounded token cost for a bounded amount of signal,
        and it buries the four fields that matter."""
        records = await _client(transport=_transport(payload=_RECORDS)).search_flows("10.4.1.9")
        assert records, "the fixture carries one record; an empty list here is the test, not the code"
        record = records[0]
        assert record["serverAddr"] == "198.51.100.23"
        assert record["serverPort"] == 443
        assert record["bytes"] == 918_233
        assert record["record_type"] == "~flow"
        assert "date_of_birth" not in record

    @pytest.mark.asyncio
    async def test_a_missing_recordstore_refuses_rather_than_returning_nothing(self) -> None:
        """The whole point of this file. 402 and 404 are the documented
        shapes of "this deployment stores no records"."""
        for status in (402, 404):
            with pytest.raises(ExtraHopReadError) as excinfo:
                await _client(transport=_transport(status=status)).search_flows("10.4.1.9")
            message = str(excinfo.value)
            assert "recordstore" in message
            # The message must say the two apart in words, because the
            # operator reading it is deciding whether to investigate the
            # network or their licensing.
            assert "not the same as no flows" in message

    @pytest.mark.asyncio
    async def test_a_server_error_also_refuses(self) -> None:
        with pytest.raises(ExtraHopReadError):
            await _client(transport=_transport(status=503)).search_flows("10.4.1.9")

    @pytest.mark.asyncio
    async def test_an_empty_recordstore_is_an_empty_list_and_not_an_error(self) -> None:
        """The other direction. A search that ran and matched nothing is a
        real answer, and must not be reported as a failure."""
        assert await _client(transport=_transport(payload={"records": [], "total": 0})).search_flows("10.4.1.9") == []

    @pytest.mark.asyncio
    async def test_a_bare_array_response_is_read_too(self) -> None:
        """Some operations return a bare array rather than an envelope.
        Assuming one shape yields zero rows, which reads as a quiet network."""
        rows = await _client(transport=_transport(payload=[_one_record()])).search_flows("10.4.1.9")
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_the_result_is_bounded(self) -> None:
        """This reaches a model's context window. A record query can match
        millions of rows."""
        many = {"records": [{"_source": {"timestamp": i}} for i in range(5000)]}
        assert len(await _client(transport=_transport(payload=many)).search_flows("10.4.1.9")) <= 100


class TestDeviceSearch:
    @pytest.mark.asyncio
    async def test_it_filters_on_the_documented_field(self) -> None:
        capture: dict = {}
        devices = await _client(transport=_transport(payload=_DEVICES, capture=capture)).search_devices("10.4.1.9")
        body = json.loads(capture["request"].content)
        assert capture["request"].url.path == "/api/v1/devices/search"
        assert body["filter"]["field"] == "ipaddr"
        assert devices[0]["display_name"] == "WKS-4219"
        assert devices[0]["critical"] is True
        assert "notes" not in devices[0]


class TestAuth:
    @pytest.mark.asyncio
    async def test_a_token_failure_is_a_read_error_not_a_crash(self) -> None:
        def handle(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "invalid_client"})

        with pytest.raises(ExtraHopReadError) as excinfo:
            await _client(transport=httpx.MockTransport(handle)).search_flows("10.4.1.9")
        assert "token" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_a_token_response_with_no_access_token_is_refused(self) -> None:
        """A 200 carrying no token would otherwise produce `Bearer None`,
        and the resulting 401 reads to an operator as a bad secret."""

        def handle(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"expires_in": 3600})

        with pytest.raises(ExtraHopReadError):
            await _client(transport=httpx.MockTransport(handle)).search_flows("10.4.1.9")


class TestGovernance:
    def test_both_verbs_are_read_only_and_automatic(self) -> None:
        from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
        from app.live_actions.contract import ActionImpact, ApprovalRequirement

        for capability in ("lookup_network_flows", "lookup_network_device"):
            contract = CAPABILITY_CONTRACTS[capability]
            assert contract.impact == ActionImpact.READ_ONLY, capability
            # Gating a read behind an analyst is how an agent learns to
            # conclude without looking.
            assert contract.approval == ApprovalRequirement.AUTOMATIC, capability

    def test_both_verbs_have_an_executor(self) -> None:
        """A contract with no executor reads as supported wherever
        capabilities are listed and answers executor_not_found at dispatch."""
        from app.live_actions import builtins

        implemented = {cls.capability for cls in builtins._BUILTIN_ADAPTERS}  # noqa: SLF001
        assert {"lookup_network_flows", "lookup_network_device"} <= implemented

    def test_the_client_exposes_no_write_path(self) -> None:
        """Phase 8 is read-only by the plan's rule. ExtraHop's API would
        allow a PATCH on a detection's status and assignee; nothing here
        can reach it."""
        public = {name for name in dir(ExtraHopClient) if not name.startswith("_")}
        assert public == {"search_flows", "search_devices"}

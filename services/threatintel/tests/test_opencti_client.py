"""
Tests for the OpenCTI client (app.clients.opencti).

Replays a fixture captured from a live OpenCTI platform (7.261008.0) on
2026-10-14: a real GraphQL request/response pair against
`POST /graphql` with the FilterGroup incremental query. Synthetic
indicators (RFC5737/RFC2606 ranges) seeded during platform validation.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import json
import pathlib
from datetime import UTC, datetime

import pytest
from app.clients.opencti import (
    STIX_CORE_INDICATORS_QUERY,
    OpenCtiClient,
    _label_values,
    parse_pattern,
    score_to_reliability,
)

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture
def live_response() -> dict:
    return json.loads((FIXTURE_DIR / "opencti_stix_core_objects.json").read_text())


@pytest.fixture
def live_request() -> dict:
    return json.loads((FIXTURE_DIR / "request.json").read_text())


@pytest.fixture
def client() -> OpenCtiClient:
    return OpenCtiClient(
        url="http://10.41.192.56:8080",
        token="test-token",
    )


class TestParsePattern:
    def test_ipv4(self) -> None:
        assert parse_pattern("[ipv4-addr:value = '203.0.113.66']") == [("ipv4-addr", "203.0.113.66")]

    def test_domain(self) -> None:
        assert parse_pattern("[domain-name:value = 'evil.example']") == [("domain-name", "evil.example")]

    def test_sha256(self) -> None:
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert parse_pattern(f"[file:hashes.'SHA-256' = '{h}']") == [("file-hash:SHA-256", h)]

    def test_md5(self) -> None:
        assert parse_pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']") == [
            ("file-hash:MD5", "d41d8cd98f00b204e9800998ecf8427e")
        ]

    def test_multi_clause(self) -> None:
        result = parse_pattern("[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']")
        assert result == [("ipv4-addr", "1.2.3.4"), ("ipv4-addr", "5.6.7.8")]

    def test_unmapped_type_falls_back(self) -> None:
        result = parse_pattern("[x-custom-type:value = 'abc']")
        assert result == [("x-custom-type:value", "abc")]

    def test_empty(self) -> None:
        assert parse_pattern("") == []


class TestLiveFixtureNormalization:
    """Normalize every node of the captured live response."""

    def test_fixture_shape(self, live_response: dict) -> None:
        block = live_response["data"]["stixCoreObjects"]
        assert block["pageInfo"]["hasNextPage"] is False
        assert len(block["edges"]) >= 1
        for edge in block["edges"]:
            node = edge["node"]
            assert node["entity_type"] == "Indicator"
            assert node["pattern"]
            assert edge["cursor"]

    def test_all_nodes_produce_typed_iocs(self, client: OpenCtiClient, live_response: dict) -> None:
        for edge in live_response["data"]["stixCoreObjects"]["edges"]:
            node = edge["node"]
            iocs = client.extract_iocs(node)
            assert iocs, f"no IOCs extracted from {node['standard_id']}"
            for ioc in iocs:
                assert ioc["type"]
                assert ioc["value"]
                assert ioc["source"] == "opencti"
                assert ioc["source_ref"].startswith("opencti:indicator--")
                assert ioc["category"] == "malicious-activity"
                assert ioc["to_ids"] is True

    def test_ipv4_node(self, client: OpenCtiClient, live_response: dict) -> None:
        node = next(
            e["node"]
            for e in live_response["data"]["stixCoreObjects"]["edges"]
            if e["node"]["x_opencti_main_observable_type"] == "IPv4-Addr"
        )
        iocs = client.extract_iocs(node)
        assert iocs[0]["type"] == "ipv4-addr"
        assert iocs[0]["value"] == "203.0.113.66"
        assert iocs[0]["score"] == node["x_opencti_score"]
        assert iocs[0]["reliability"] == "B"  # score 85

    def test_sha256_node(self, client: OpenCtiClient, live_response: dict) -> None:
        node = next(e["node"] for e in live_response["data"]["stixCoreObjects"]["edges"] if "SHA-256" in e["node"]["pattern"])
        iocs = client.extract_iocs(node)
        assert iocs[0]["type"] == "file-hash:SHA-256"
        assert len(iocs[0]["value"]) == 64

    def test_killchain_phase_flattened(self, client: OpenCtiClient, live_response: dict) -> None:
        node = next(e["node"] for e in live_response["data"]["stixCoreObjects"]["edges"] if e["node"]["killChainPhases"])
        iocs = client.extract_iocs(node)
        assert "mitre-attack-v20:command-and-control" in iocs[0]["tags"]


class TestReliability:
    @pytest.mark.parametrize(
        ("score", "band"),
        [(None, "C"), (100, "A"), (90, "A"), (85, "B"), (75, "B"), (50, "C"), (25, "D"), (10, "E")],
    )
    def test_bands(self, score: int | None, band: str) -> None:
        assert score_to_reliability(score) == band


class TestLabelValues:
    def test_flat_labels(self) -> None:
        node = {"objectLabel": [{"value": "tlp:white"}, {"value": "botnet"}]}
        assert _label_values(node) == ["tlp:white", "botnet"]

    def test_missing_is_empty(self) -> None:
        assert _label_values({}) == []


class TestGraphqlDocument:
    def test_matches_live_request_shape(self, live_request: dict) -> None:
        """The shipped query must be the one the platform accepted."""
        doc = live_request["query"]
        assert "FilterGroup" in doc
        assert "updated_at" in doc
        assert "... on Indicator" in doc
        assert "$after: ID" in doc
        # variables used for the incremental watermark
        assert live_request["variables"]["filters"]["mode"] == "and"
        f = live_request["variables"]["filters"]["filters"][0]
        assert f["key"] == ["updated_at"]
        assert f["operator"] == "gt"

    def test_shipped_query_is_byte_identical_to_the_validated_one(self, live_request: dict) -> None:
        """The constant the client sends equals the document the platform accepted.

        The substring checks above read the *fixture*; they cannot notice an
        edit to the shipped constant, and a query that drifts from the
        validated capture fails in the worst way a TI source can — a
        silently empty feed. Byte equality runs in the direction that
        drifts: change either side and this names the divergence.
        """
        assert STIX_CORE_INDICATORS_QUERY == live_request["query"]

    def test_client_builds_the_validated_filter_group(self, live_request: dict, client: OpenCtiClient) -> None:
        """`_filters()` reproduces the captured request's variables exactly.

        The fixture's watermark is 2026-09-01T00:00:00Z, so building the
        filter for that instant must equal the captured FilterGroup — key
        spelling, list-valued `key`, operator and the empty `filterGroups`
        arm included.
        """
        built = client._filters(datetime(2026, 9, 1, tzinfo=UTC))
        assert built == live_request["variables"]["filters"]

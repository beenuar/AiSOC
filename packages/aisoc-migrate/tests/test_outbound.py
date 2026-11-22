"""Outbound rendering under the roundtrip contract (WS1.5).

The load-bearing suite is the ROUNDTRIP class: for every fixture rule,
``render()`` to each inbound-parseable dialect and feed the output through
the REAL ``inbound.translate`` — the parsed ``match_when`` must equal the
original exactly. That is what makes the pair a pair; a rendering inbound
reads back differently is the almost-right defect both modules refuse.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from inbound import translate  # noqa: E402
from outbound import OUTBOUND_DIALECTS, render  # noqa: E402

#: Fixture rules spanning the carryable subset. Shared by every dialect.
FIXTURES = [
    {
        "id": "fx-auth-failure",
        "match_when": {"event_type": "authentication", "outcome": "failure"},
    },
    {
        "id": "fx-ops-and-numbers",
        "match_when": {"action": "login", "severity_id_gte": 3, "attempts_gt": 5},
    },
    {
        "id": "fx-neq-and-bounds",
        "match_when": {"user_name_neq": "svc-scanner", "dst_port_lte": 1024, "bytes_lt": 9000},
    },
    {
        "id": "fx-booleans",
        "match_when": {"mfa_satisfied": True, "event_type": "session"},
    },
]

ROUNDTRIP_DIALECTS = [d for d in OUTBOUND_DIALECTS if d != "aql"]


class TestRoundtrip:
    def test_every_fixture_roundtrips_through_every_parseable_dialect(self) -> None:
        for rule in FIXTURES:
            for dialect in ROUNDTRIP_DIALECTS:
                rendered = render(rule, dialect)
                assert rendered.usable, (rule["id"], dialect, rendered.unsupported, rendered.notes)
                assert rendered.confidence == "roundtrip"
                parsed = translate(rendered.query, dialect)
                assert parsed.usable, (rule["id"], dialect, parsed.notes, rendered.query)
                assert parsed.match_when == rule["match_when"], (
                    f"{rule['id']} via {dialect}: outbound then inbound changed the rule — "
                    f"sent {rule['match_when']}, got back {parsed.match_when} "
                    f"(query: {rendered.query})"
                )

    def test_aql_renders_but_says_the_proof_does_not_cover_it(self) -> None:
        rendered = render(FIXTURES[0], "aql")
        assert rendered.usable and rendered.confidence == "render_only"
        assert "SELECT * FROM events WHERE" in rendered.query
        assert any("roundtrip proof does not cover" in n for n in rendered.notes)


class TestRefusals:
    def test_an_uncarryable_operator_refuses_the_whole_rule(self) -> None:
        rule = {
            "id": "fx-contains",
            "match_when": {"event_type": "process", "command_line_contains": "mimikatz"},
        }
        for dialect in OUTBOUND_DIALECTS:
            rendered = render(rule, dialect)
            assert not rendered.usable, dialect
            assert rendered.query == "", "a partial rendering matches MORE than the original"
            assert any("roundtrip" in u or "literal" in u for u in rendered.unsupported)

    def test_a_windowed_rule_refuses_with_the_inbound_reason(self) -> None:
        rule = {"id": "fx-threshold", "match_when": {"outcome": "failure"}, "threshold": 5, "window_seconds": 600}
        rendered = render(rule, "spl")
        assert not rendered.usable
        assert any("roundtrip clean" in u for u in rendered.unsupported)

    def test_a_wildcard_value_refuses_rather_than_mutating(self) -> None:
        rule = {"id": "fx-wild", "match_when": {"file_path": "C:\\Users\\*\\evil.exe"}}
        rendered = render(rule, "spl")
        assert not rendered.usable
        assert any("would not read back" in u for u in rendered.unsupported)

    def test_spl_routing_fields_refuse_because_inbound_drops_them(self) -> None:
        rule = {"id": "fx-routing", "match_when": {"index": "main", "outcome": "failure"}}
        rendered = render(rule, "spl")
        assert not rendered.usable
        assert any("routing field" in u for u in rendered.unsupported)
        # The same rule renders fine for KQL, where `index` is an ordinary field.
        kql = render(rule, "kql")
        assert kql.usable
        assert translate(kql.query, "kql").match_when == rule["match_when"]

    def test_an_unknown_dialect_is_named(self) -> None:
        rendered = render(FIXTURES[0], "lucene")
        assert not rendered.usable
        assert "unknown dialect" in rendered.notes[0]

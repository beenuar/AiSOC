"""The managed rule document applies on the live triage path.

Two implementations of one grammar
----------------------------------
The insider watchlist generates managed rules in ``services/api``
(`app/services/insider_watchlist.py`); the worker that applies them on the
auto-triage hot path is **this service's** independent re-implementation of
the business-context grammar (separate image, no shared import). Two parsers
of one language drift silently unless something holds them together — so the
API side pins its generator to a golden fixture
(`services/api/tests/fixtures/managed_rules_golden.yaml`) and this suite
parses *the same bytes* with the agents loader and evaluates them with the
agents engine. If either side changes shape, one of the two suites goes red.

The second half covers the row-level split: ``yaml_text`` (authored) and
``managed_yaml`` (machine-owned) are parsed independently, so a syntax error
in the analyst's draft never withdraws watchlist elevation and a managed-rule
bug never disables the tenant's suppressions.
"""

from __future__ import annotations

from pathlib import Path

from app.workers.business_context import (
    _rules_from_row,
    apply_rules,
    load_rules_from_yaml,
)

GOLDEN = Path(__file__).resolve().parents[2] / "api" / "tests" / "fixtures" / "managed_rules_golden.yaml"

AUTHORED = """
rules:
  - id: suppress-backup-noise
    description: nightly backup account
    when:
      field: username
      op: eq
      value: svc_backup
    then:
      suppress: true
"""

BROKEN = "rules:\n  - id: [this is not a slug\n"


def _alert(username: str, severity: str = "low") -> dict:
    return {"username": username, "severity": severity, "hostname": "fin-ws-07"}


class TestGoldenFixtureParsesHere:
    def test_the_agents_loader_accepts_the_generated_document(self) -> None:
        rules = load_rules_from_yaml(GOLDEN.read_text())
        assert len(rules) == 4
        assert all(r.id.startswith("managed-insider-watchlist-") for r in rules)

    def test_the_floor_raises_low_and_tags(self) -> None:
        rules = load_rules_from_yaml(GOLDEN.read_text())
        result = apply_rules(_alert("mallory@example.com", "low"), rules)
        assert result.alert["severity"] == "medium"
        assert "insider-watchlist" in result.alert.get("tags", [])

    def test_the_floor_never_downgrades_high(self) -> None:
        rules = load_rules_from_yaml(GOLDEN.read_text())
        result = apply_rules(_alert("mallory@example.com", "high"), rules)
        assert result.alert["severity"] == "high"

    def test_other_identities_are_untouched(self) -> None:
        rules = load_rules_from_yaml(GOLDEN.read_text())
        result = apply_rules(_alert("alice@example.com", "low"), rules)
        assert result.alert["severity"] == "low"
        assert not result.matched_rule_ids


class TestTwoDocumentSplit:
    def test_both_documents_apply(self) -> None:
        rules = _rules_from_row(AUTHORED, GOLDEN.read_text())
        ids = {r.id for r in rules}
        assert "suppress-backup-noise" in ids
        assert any(i.startswith("managed-insider-watchlist-") for i in ids)

    def test_a_broken_authored_draft_does_not_withdraw_elevation(self) -> None:
        rules = _rules_from_row(BROKEN, GOLDEN.read_text())
        assert rules, "managed rules must survive an authored parse error"
        assert all(r.id.startswith("managed-insider-watchlist-") for r in rules)

    def test_a_broken_managed_document_does_not_disable_suppressions(self) -> None:
        rules = _rules_from_row(AUTHORED, BROKEN)
        assert [r.id for r in rules] == ["suppress-backup-noise"]

    def test_empty_documents_are_no_rules(self) -> None:
        assert _rules_from_row("", "") == []

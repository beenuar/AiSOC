"""Windowed rules must be declarable without editing the engine.

The windowed engine shipped with three hardcoded rules and no loader. That was
not merely inconvenient: a large share of the ~2,000 quarantined Splunk rules
are `| stats count ... by` aggregations, which cannot be expressed in the
stateless `match_when` at all because that matcher sees one event in isolation.
They had nowhere to go, which is most of why the quarantine never shrank. The
quarantine README told contributors to skip them "until it has one".

The loader is deliberately fail-soft in one direction only. A missing or
malformed ruleset falls back to the builtins rather than to an empty corpus,
because silently detecting nothing is worse than detecting only the
high-signal three — and an operator reading "0 rules loaded" in a log line is
far less likely than noticing alerts stopped.
"""

from __future__ import annotations

import json

from app.services.windowed_detection import (
    _BUILTIN_RULES,
    WindowedDetectionEngine,
    load_window_rules,
)

VALID = {
    "id": "wd-test-rule",
    "name": "Test",
    "severity": "high",
    "category": "identity",
    "mitre": ["t1110"],
    "match_when": {"event_type": "authentication"},
    "group_by": "user",
    "threshold": 5,
    "window_seconds": 300,
}


def _write(tmp_path, rules):
    path = tmp_path / "windowed_ruleset.json"
    path.write_text(json.dumps({"count": len(rules), "rules": rules}), encoding="utf-8")
    return path


# ── loading ───────────────────────────────────────────────────────────────


def test_declared_rules_are_added_to_the_builtins(tmp_path):
    rules = load_window_rules(_write(tmp_path, [VALID]))
    assert len(rules) == len(_BUILTIN_RULES) + 1
    assert any(r.id == "wd-test-rule" for r in rules)


def test_the_committed_ruleset_loads(tmp_path):
    """Guards the real artifact, not just a fixture."""
    rules = load_window_rules()
    assert len(rules) > len(_BUILTIN_RULES)
    ids = {r.id for r in rules}
    assert "wd-ai-agent-tool-denials" in ids
    assert "wd-mfa-fatigue" in ids


def test_mitre_ids_are_upper_cased():
    """So coverage mapping joins against the ATT&CK catalogue."""
    rules = load_window_rules()
    for rule in rules:
        for technique in rule.mitre:
            assert technique == technique.upper()


# ── fail-soft, in the right direction ─────────────────────────────────────


def test_a_missing_ruleset_keeps_the_builtins(tmp_path):
    rules = load_window_rules(tmp_path / "absent.json")
    assert rules == _BUILTIN_RULES


def test_malformed_json_keeps_the_builtins(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert load_window_rules(path) == _BUILTIN_RULES


def test_one_bad_rule_does_not_disable_the_others(tmp_path):
    """A single authoring mistake must not empty the corpus."""
    broken = {"id": "wd-broken"}  # missing every required field
    rules = load_window_rules(_write(tmp_path, [broken, VALID]))
    ids = {r.id for r in rules}
    assert "wd-test-rule" in ids
    assert "wd-broken" not in ids


# ── bounds ────────────────────────────────────────────────────────────────


def test_a_zero_threshold_is_rejected(tmp_path):
    """That is a stateless rule wearing a windowed rule's clothes.

    Threshold 0 fires on the first matching event, which means it would
    duplicate the stateless engine while paying for Redis state.
    """
    rules = load_window_rules(_write(tmp_path, [{**VALID, "threshold": 0}]))
    assert not any(r.id == "wd-test-rule" for r in rules)


def test_a_zero_window_is_rejected(tmp_path):
    """Nothing ever accumulates, so the rule can never fire."""
    rules = load_window_rules(_write(tmp_path, [{**VALID, "window_seconds": 0}]))
    assert not any(r.id == "wd-test-rule" for r in rules)


def test_a_duplicate_id_does_not_shadow_a_builtin(tmp_path):
    """Otherwise a declared rule could silently weaken a builtin threshold."""
    clash = {**VALID, "id": _BUILTIN_RULES[0].id, "threshold": 9999}
    rules = load_window_rules(_write(tmp_path, [clash]))
    matching = [r for r in rules if r.id == _BUILTIN_RULES[0].id]
    assert len(matching) == 1
    assert matching[0].threshold == _BUILTIN_RULES[0].threshold


# ── the field namespace must match the stateless engine ───────────────────


def test_vendor_fields_under_raw_event_are_visible():
    """Both engines must agree on the namespace.

    Otherwise a rule that works stateless silently does not work windowed,
    which is the harder failure to notice of the two.
    """
    fields = WindowedDetectionEngine._fields(
        {"ocsf_event": {"raw_data": json.dumps({"source": "imperva", "severity": "high", "raw_event": {"agent_id": "bot-1"}})}}
    )
    assert fields["agent_id"] == "bot-1"
    assert fields["source"] == "imperva"


def test_connector_normalization_wins_on_collision():
    fields = WindowedDetectionEngine._fields(
        {"ocsf_event": {"raw_data": json.dumps({"severity": "critical", "raw_event": {"severity": "SEV-3"}})}}
    )
    assert fields["severity"] == "critical"


def test_a_message_without_an_ocsf_event_is_empty():
    assert WindowedDetectionEngine._fields({}) == {}
    assert WindowedDetectionEngine._fields({"ocsf_event": "not-a-dict"}) == {}


def test_the_engine_defaults_to_the_declared_set():
    """A deployment picks up exported rules without a code change."""
    engine = WindowedDetectionEngine(redis=None)
    assert engine.rule_count > len(_BUILTIN_RULES)


def test_an_explicit_rule_tuple_still_wins():
    """Tests and targeted deployments need to pin the corpus."""
    engine = WindowedDetectionEngine(redis=None, rules=_BUILTIN_RULES)
    assert engine.rule_count == len(_BUILTIN_RULES)

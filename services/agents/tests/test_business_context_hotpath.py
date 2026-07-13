"""Phase B4 — business-context rules in the auto-triage hot path.

Proves the YAML rule engine (when/then, all/any/not, comparators) applies
correctly, that a suppress rule drops the alert BEFORE triage (no spend), that
severity/route/tag mutations flow into triage, and that it's fail-soft.
"""

from __future__ import annotations

import pytest
from app.workers import business_context as bc
from app.workers.business_context import BusinessContextApplier, apply_rules, load_rules_from_yaml
from app.workers.fused_alert_consumer import FusedAlertTriageWorker

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-1111-1111-111111111111"

_RULES_YAML = """
rules:
  - id: prod-bump
    priority: 10
    when:
      field: env
      op: eq
      value: production
    then:
      set_severity: critical
      tag: prod-asset
  - id: maint-suppress
    priority: 5
    when:
      all:
        - {field: source, op: eq, value: scanner}
        - {field: maintenance, op: eq, value: true}
    then:
      suppress: true
  - id: cloud-route
    priority: 20
    when:
      field: category
      op: eq
      value: cloud
    then:
      route_to: cloud
"""


def _fused(**alert):
    base = {"id": "a1", "title": "t", "severity": "medium", "env": "staging", "source": "edr", "category": "endpoint"}
    base.update(alert)
    return {"id": "a1", "tenant_id": TENANT, "incident_id": "b2", "alert": base}


# ── parser + engine ───────────────────────────────────────────────────────────


async def test_parse_yaml_rules():
    rules = load_rules_from_yaml(_RULES_YAML)
    assert {r.id for r in rules} == {"prod-bump", "maint-suppress", "cloud-route"}


async def test_severity_bump_and_tag():
    rules = load_rules_from_yaml(_RULES_YAML)
    res = apply_rules({"severity": "medium", "env": "production"}, rules)
    assert res.alert["severity"] == "critical"
    assert "prod-asset" in res.alert["tags"]
    assert "prod-bump" in res.matched_rule_ids
    assert res.suppressed is False


async def test_suppress_short_circuits():
    rules = load_rules_from_yaml(_RULES_YAML)
    res = apply_rules({"severity": "low", "source": "scanner", "maintenance": True}, rules)
    assert res.suppressed is True
    assert "maint-suppress" in res.matched_rule_ids


async def test_route_rule():
    rules = load_rules_from_yaml(_RULES_YAML)
    res = apply_rules({"severity": "high", "category": "cloud"}, rules)
    assert res.alert["route_to"] == "cloud"


async def test_no_match_is_unchanged():
    rules = load_rules_from_yaml(_RULES_YAML)
    res = apply_rules({"severity": "medium", "env": "staging", "source": "edr", "category": "endpoint"}, rules)
    assert res.changed is False
    assert res.alert["severity"] == "medium"


async def test_invalid_severity_dropped():
    rules = load_rules_from_yaml("rules:\n  - id: bad\n    when: {field: x, op: eq, value: 1}\n    then: {set_severity: SUPER}")
    res = apply_rules({"x": 1, "severity": "low"}, rules)
    assert res.alert["severity"] == "low"  # invalid override ignored


# ── applier file loading + fail-soft ─────────────────────────────────────────


async def test_applier_loads_from_file(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(_RULES_YAML)
    applier = BusinessContextApplier(rules_file=str(f))
    assert applier.rule_count == 3
    res = applier.apply({"severity": "medium", "env": "production"})
    assert res.alert["severity"] == "critical"


async def test_applier_no_file_is_noop():
    applier = BusinessContextApplier(rules_file="")
    res = applier.apply({"severity": "medium", "env": "production"})
    assert res.changed is False


async def test_is_enabled_flag(monkeypatch):
    monkeypatch.delenv("AISOC_BUSINESS_CONTEXT_ENABLED", raising=False)
    assert bc.is_enabled() is True
    monkeypatch.setenv("AISOC_BUSINESS_CONTEXT_ENABLED", "0")
    assert bc.is_enabled() is False


# ── worker integration ───────────────────────────────────────────────────────


async def test_worker_suppress_skips_triage(tmp_path, monkeypatch):
    f = tmp_path / "rules.yaml"
    f.write_text(_RULES_YAML)
    worker = FusedAlertTriageWorker(bootstrap_servers="unused", business_context=BusinessContextApplier(rules_file=str(f)))
    result = await worker.triage(_fused(source="scanner", maintenance=True))
    assert result is not None
    assert result["suppressed"] is True
    assert "maint-suppress" in result["business_context_rules"]
    assert result["response_dispatched"] is False


async def test_worker_severity_mutation_flows_into_triage(tmp_path, monkeypatch):
    monkeypatch.setattr("app.workers.fused_alert_consumer.resolve_llm_config", _fake_llm_config_unavailable())
    f = tmp_path / "rules.yaml"
    f.write_text(_RULES_YAML)
    worker = FusedAlertTriageWorker(bootstrap_servers="unused", business_context=BusinessContextApplier(rules_file=str(f)))
    result = await worker.triage(_fused(env="production"))
    assert result is not None
    assert result.get("suppressed") is not True  # not suppressed
    assert "prod-bump" in result["business_context_rules"]


async def test_worker_without_business_context_is_unaffected(monkeypatch):
    monkeypatch.setattr("app.workers.fused_alert_consumer.resolve_llm_config", _fake_llm_config_unavailable())
    worker = FusedAlertTriageWorker(bootstrap_servers="unused")  # no applier
    result = await worker.triage(_fused(source="scanner", maintenance=True))
    assert result is not None
    assert result.get("suppressed") is not True  # no BC => not suppressed
    assert result["business_context_rules"] == []


def _fake_llm_config_unavailable():
    class _Cfg:
        allowed = False
        api_key = None

    async def _resolve(_tenant):  # noqa: ANN001
        return _Cfg()

    return _resolve

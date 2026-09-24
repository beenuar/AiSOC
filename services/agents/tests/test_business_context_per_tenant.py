"""Business-context rules authored in the console must reach triage.

The console has let a tenant author business-context rules since T3.5 — "this
host is a domain controller, escalate anything touching it", "this service
account runs the nightly backup, suppress its noise". Two independent bugs
meant none of them ever affected a triage decision.

The API stored them in a module-level dict inside whichever process served the
write, so they were lost on restart and invisible to other replicas. And this
worker loaded rules only from a YAML file whose path comes from
`AISOC_BUSINESS_CONTEXT_RULES_FILE`, which nothing sets. The console and the
worker were looking at two different places, and one of them was empty.

A tenant could author a rule, see it saved, preview it against their last 50
alerts, and have it apply to nothing.
"""

from __future__ import annotations

import pytest
from app.workers import business_context as bc_mod
from app.workers.business_context import BusinessContextApplier

pytestmark = pytest.mark.asyncio

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"

SUPPRESS_BACKUP = """
rules:
  - id: backup-noise
    priority: 10
    when:
      field: username
      op: eq
      value: svc_backup
    then:
      suppress: true
"""

ESCALATE_DC = """
rules:
  - id: dc-critical
    priority: 10
    when:
      field: hostname
      op: eq
      value: WIN-DC01
    then:
      set_severity: critical
"""


def _alert(**overrides):
    alert = {"hostname": "WIN-WS42", "username": "alice", "severity": "low"}
    alert.update(overrides)
    return alert


def _stub_tenant_rules(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, str]):
    """Stand in for the Postgres read, keyed by tenant."""

    async def _load(self, tenant_id):  # noqa: ANN001, ANN202
        yaml_text = mapping.get(tenant_id, "")
        return bc_mod.load_rules_from_yaml(yaml_text) if yaml_text else []

    monkeypatch.setattr(BusinessContextApplier, "_load_tenant_rules", _load)


# ── the regression ────────────────────────────────────────────────────────


async def test_a_tenants_authored_suppression_is_applied(monkeypatch: pytest.MonkeyPatch):
    _stub_tenant_rules(monkeypatch, {TENANT_A: SUPPRESS_BACKUP})
    result = await BusinessContextApplier().apply_for_tenant(TENANT_A, _alert(username="svc_backup"))
    assert result.suppressed
    assert "backup-noise" in result.matched_rule_ids


async def test_a_tenants_authored_escalation_is_applied(monkeypatch: pytest.MonkeyPatch):
    _stub_tenant_rules(monkeypatch, {TENANT_A: ESCALATE_DC})
    result = await BusinessContextApplier().apply_for_tenant(TENANT_A, _alert(hostname="WIN-DC01"))
    assert result.alert["severity"] == "critical"


async def test_one_tenants_rules_do_not_affect_another(monkeypatch: pytest.MonkeyPatch):
    """The reason a single global rule set was wrong.

    Tenant A suppressing their backup account must not suppress tenant B's
    alerts for an account that happens to share the name.
    """
    _stub_tenant_rules(monkeypatch, {TENANT_A: SUPPRESS_BACKUP})
    applier = BusinessContextApplier()
    assert (await applier.apply_for_tenant(TENANT_A, _alert(username="svc_backup"))).suppressed
    assert not (await applier.apply_for_tenant(TENANT_B, _alert(username="svc_backup"))).suppressed


async def test_a_tenant_with_no_rules_passes_the_alert_through(
    monkeypatch: pytest.MonkeyPatch,
):
    _stub_tenant_rules(monkeypatch, {})
    result = await BusinessContextApplier().apply_for_tenant(TENANT_A, _alert())
    assert not result.suppressed
    assert result.matched_rule_ids == []


async def test_no_tenant_id_still_works(monkeypatch: pytest.MonkeyPatch):
    """An alert with no tenant must not crash triage."""
    _stub_tenant_rules(monkeypatch, {TENANT_A: SUPPRESS_BACKUP})
    result = await BusinessContextApplier().apply_for_tenant(None, _alert(username="svc_backup"))
    assert not result.suppressed


# ── fail-soft ─────────────────────────────────────────────────────────────


@pytest.mark.touches_database
async def test_an_unreachable_database_never_breaks_triage(
    monkeypatch: pytest.MonkeyPatch,
):
    """Exercises the real loader against a DSN that cannot connect.

    A business-context outage must degrade to "no rules applied", never to a
    dropped alert.
    """
    monkeypatch.setenv("DATABASE_DSN", "postgresql://nobody@127.0.0.1:1/nope")
    applier = BusinessContextApplier()
    applier.clear_tenant_cache()
    assert await applier._load_tenant_rules(TENANT_A) == []
    assert not (await applier.apply_for_tenant(TENANT_A, _alert())).suppressed


@pytest.mark.touches_database
async def test_a_transient_outage_serves_the_last_known_rules(
    monkeypatch: pytest.MonkeyPatch,
):
    """Otherwise a blip silently un-suppresses a tenant's known-noisy alerts."""
    applier = BusinessContextApplier()
    applier._tenant_rules[TENANT_A] = (0.0, bc_mod.load_rules_from_yaml(SUPPRESS_BACKUP))
    monkeypatch.setenv("DATABASE_DSN", "postgresql://nobody@127.0.0.1:1/nope")
    rules = await applier._load_tenant_rules(TENANT_A)
    assert [r.id for r in rules] == ["backup-noise"]


async def test_malformed_tenant_yaml_applies_no_rules_rather_than_crashing():
    """A tenant can save syntactically broken YAML; triage must survive it."""
    assert bc_mod.load_rules_from_yaml("rules:\n  - no_id_field: true") == []


async def test_no_database_configured_is_not_an_error(monkeypatch: pytest.MonkeyPatch):
    """Single-node installs with no DSN must still triage."""
    monkeypatch.delenv("DATABASE_DSN", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    applier = BusinessContextApplier()
    applier.clear_tenant_cache()
    assert await applier._load_tenant_rules(TENANT_A) == []


# ── precedence ────────────────────────────────────────────────────────────


async def test_tenant_rules_are_evaluated_before_deployment_wide_ones(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
):
    """A tenant's statement about their own estate is the more specific one.

    The file-based path is kept so an air-gapped install shipping rules on disk
    keeps working; those rules apply to every tenant.
    """
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(ESCALATE_DC)
    _stub_tenant_rules(monkeypatch, {TENANT_A: SUPPRESS_BACKUP})

    applier = BusinessContextApplier(rules_file=str(rules_file))
    # Deployment-wide rule still applies to a tenant with none of their own.
    assert (await applier.apply_for_tenant(TENANT_B, _alert(hostname="WIN-DC01"))).alert["severity"] == "critical"
    # And the tenant's own suppression is reached.
    assert (await applier.apply_for_tenant(TENANT_A, _alert(username="svc_backup"))).suppressed

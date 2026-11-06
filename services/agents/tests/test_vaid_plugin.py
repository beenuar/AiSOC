"""Unit tests for the optional VAID plugin (beenuar/AiSOC#1739), agents side.

Covers, per the issue's conditions: minting from ``AgentIdentity`` (never a
parallel identity), the ``ToolRegistry.execute`` boundary, fail-closed
behaviour for missing/expired/revoked badges and for a bare identity when
the plugin is on, and the off-by-default negative control.
"""

from __future__ import annotations

import json
import time
import uuid

import pytest

pytest.importorskip("vaid_mint", reason="optional VAID plugin dependency — install the 'vaid' extra to run this suite")

from app.security import vaid_plugin
from app.security.agent_identity import AgentIdentity, issue_identity
from app.tools.registry import Tool, ToolRegistry


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    """Every test gets a clean env flag and a fresh issuer.

    A test process is exactly the "single process" case
    ``AISOC_VAID_ALLOW_EPHEMERAL_KERNEL_SEED`` exists for — there is only
    ever one issuer in play, so a fresh per-run seed cannot produce the
    cross-replica mismatch the flag's absence otherwise refuses.
    """
    monkeypatch.delenv(vaid_plugin._ENABLED_ENV, raising=False)
    monkeypatch.delenv(vaid_plugin._REVOCATION_LIST_PATH_ENV, raising=False)
    monkeypatch.delenv(vaid_plugin._TTL_HOURS_ENV, raising=False)
    monkeypatch.setenv(vaid_plugin._ALLOW_EPHEMERAL_SEED_ENV, "true")
    vaid_plugin.reset_issuer_for_tests()
    yield
    vaid_plugin.reset_issuer_for_tests()


def _enable(monkeypatch):
    monkeypatch.setenv(vaid_plugin._ENABLED_ENV, "true")


def _revocation_file(tmp_path, revoked: list[str]):
    path = tmp_path / "revoked.json"
    path.write_text(json.dumps({"revoked": revoked}))
    return path


# ── Minting: builds on AgentIdentity, never a parallel identity ──────────


def test_issue_vaid_identity_wraps_a_real_agent_identity():
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    assert isinstance(wrapped.identity, AgentIdentity)
    assert wrapped.agent == "triage"
    assert wrapped.scopes == wrapped.identity.scopes
    assert wrapped.badge["capability_set"] == sorted(wrapped.identity.scopes)
    assert wrapped.badge["tenant_id"] == "acme"
    assert wrapped.badge["parent_vaid"] is None


def test_issue_vaid_identity_refuses_unknown_agent_exactly_like_issue_identity():
    with pytest.raises(ValueError, match="unknown agent"):
        vaid_plugin.issue_vaid_identity("not-a-real-agent", run_id="run-1", tenant_id="acme")


def test_with_granted_tools_expands_scope_and_remints_a_matching_badge():
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    base_vaid_id = wrapped.badge["vaid_id"]
    granted = wrapped.with_granted_tools({"fleet_ioc_hunt"})

    assert "fleet_ioc_hunt" in granted.scopes
    assert "fleet_ioc_hunt" not in wrapped.scopes  # original untouched
    assert granted.badge["capability_set"] == sorted(granted.identity.scopes)
    assert granted.badge["vaid_id"] != base_vaid_id  # a fresh root mint, not a mutation
    assert granted.badge["parent_vaid"] is None  # root, not a vaid-mint delegated child
    assert granted.credential_id == wrapped.credential_id  # same run's credential


def test_vaid_backed_identity_delegates_require_and_may():
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    assert wrapped.may("extract_iocs") is True
    assert wrapped.may("isolate_host") is False
    wrapped.require("extract_iocs")  # does not raise
    from app.security.agent_identity import ScopeDenied

    with pytest.raises(ScopeDenied):
        wrapped.require("isolate_host")


def test_audit_row_names_the_vaid_id():
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    row = wrapped.audit_row("extract_iocs", allowed=True)
    assert row["vaid_id"] == wrapped.badge["vaid_id"]
    assert row["agent"] == "triage"


# ── Two vocabularies, never conflated ──────────────────────────────────────
# (the gap a code review found: AGENT_TOOL_SCOPES names tool functions,
# services/actions' ActionType names response capabilities, and a badge
# minted with capability_set = identity.scopes alone could never clear
# verify_badge_for_dispatch for any real action.)


def test_respond_badge_carries_action_dispatch_capabilities_too():
    wrapped = vaid_plugin.issue_vaid_identity("respond", run_id="run-1", tenant_id="acme")
    capability_set = set(wrapped.badge["capability_set"])
    assert capability_set >= vaid_plugin.AGENT_ACTION_CAPABILITIES["respond"]
    assert capability_set >= wrapped.identity.scopes  # tool scopes are still there too
    assert "isolate_host" in capability_set  # the specific capability the review named


def test_only_respond_gets_action_dispatch_capabilities():
    for agent in ("triage", "investigation", "hunt", "detect"):
        wrapped = vaid_plugin.issue_vaid_identity(agent, run_id="run-1", tenant_id="acme")
        assert set(wrapped.badge["capability_set"]) == wrapped.identity.scopes
        assert "isolate_host" not in wrapped.badge["capability_set"]


# ── verify_identity_badge: the off-by-default negative control ───────────


def test_disabled_plugin_is_a_no_op_even_for_a_bare_identity(monkeypatch):
    assert vaid_plugin.vaid_plugin_enabled() is False
    bare = issue_identity("triage", run_id="run-1")
    vaid_plugin.verify_identity_badge(bare)  # must not raise
    vaid_plugin.verify_identity_badge(None)  # must not raise either


# ── Fail-closed behaviour when enabled ────────────────────────────────────


def test_enabled_plugin_refuses_a_bare_agent_identity(monkeypatch):
    _enable(monkeypatch)
    bare = issue_identity("triage", run_id="run-1")
    with pytest.raises(vaid_plugin.BadgeDenied, match="no badge"):
        vaid_plugin.verify_identity_badge(bare)


def test_enabled_plugin_refuses_none(monkeypatch):
    _enable(monkeypatch)
    with pytest.raises(vaid_plugin.BadgeDenied):
        vaid_plugin.verify_identity_badge(None)


def test_enabled_plugin_accepts_a_freshly_minted_badge_with_a_shipped_empty_revocation_list(monkeypatch, tmp_path):
    _enable(monkeypatch)
    monkeypatch.setenv(vaid_plugin._REVOCATION_LIST_PATH_ENV, str(_revocation_file(tmp_path, [])))
    vaid_plugin.reset_issuer_for_tests()
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    vaid_plugin.verify_identity_badge(wrapped)  # must not raise


def test_enabled_plugin_fails_closed_with_no_revocation_list_configured(monkeypatch):
    """Air-gapped posture: no shipped list = UNAVAILABLE = refused, never
    treated as "nothing is revoked"."""
    _enable(monkeypatch)
    vaid_plugin.reset_issuer_for_tests()
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    with pytest.raises(vaid_plugin.BadgeDenied, match="indeterminate"):
        vaid_plugin.verify_identity_badge(wrapped)


def test_enabled_plugin_refuses_a_revoked_badge(monkeypatch, tmp_path):
    _enable(monkeypatch)
    revocation_path = _revocation_file(tmp_path, [])
    monkeypatch.setenv(vaid_plugin._REVOCATION_LIST_PATH_ENV, str(revocation_path))
    vaid_plugin.reset_issuer_for_tests()
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    # The list is re-read from disk on every check (module docstring), so
    # revoking *after* mint — the realistic sequence — still takes effect.
    revocation_path.write_text(json.dumps({"revoked": [wrapped.badge["vaid_id"]]}))
    with pytest.raises(vaid_plugin.BadgeDenied, match="revoked"):
        vaid_plugin.verify_identity_badge(wrapped)


def test_enabled_plugin_refuses_an_unreadable_revocation_list(monkeypatch, tmp_path):
    _enable(monkeypatch)
    missing = tmp_path / "does-not-exist.json"
    monkeypatch.setenv(vaid_plugin._REVOCATION_LIST_PATH_ENV, str(missing))
    vaid_plugin.reset_issuer_for_tests()
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    with pytest.raises(vaid_plugin.BadgeDenied, match="indeterminate"):
        vaid_plugin.verify_identity_badge(wrapped)


def test_enabled_plugin_refuses_an_expired_badge(monkeypatch, tmp_path):
    _enable(monkeypatch)
    monkeypatch.setenv(vaid_plugin._TTL_HOURS_ENV, "0")  # expires immediately
    monkeypatch.setenv(vaid_plugin._REVOCATION_LIST_PATH_ENV, str(_revocation_file(tmp_path, [])))
    vaid_plugin.reset_issuer_for_tests()
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    time.sleep(1.1)  # cross the whole-second expiry boundary
    with pytest.raises(vaid_plugin.BadgeDenied, match="expired"):
        vaid_plugin.verify_identity_badge(wrapped)


def test_enabled_plugin_refuses_a_tampered_badge(monkeypatch, tmp_path):
    _enable(monkeypatch)
    monkeypatch.setenv(vaid_plugin._REVOCATION_LIST_PATH_ENV, str(_revocation_file(tmp_path, [])))
    vaid_plugin.reset_issuer_for_tests()
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    tampered_badge = dict(wrapped.badge)
    tampered_badge["capability_set"] = [*tampered_badge["capability_set"], "isolate_host"]
    tampered = vaid_plugin.VaidBackedIdentity(wrapped.identity, wrapped.tenant_id, tampered_badge)
    with pytest.raises(vaid_plugin.BadgeDenied, match="inauthentic"):
        vaid_plugin.verify_identity_badge(tampered)


# ── badge_sha256 ──────────────────────────────────────────────────────────


def test_mint_refuses_an_unnamed_ephemeral_trust_root_by_default(monkeypatch):
    """The multi-replica hazard: with neither a seed path nor the explicit
    opt-out set, minting must refuse rather than silently generate a
    per-process seed nothing else could ever verify against."""
    monkeypatch.delenv(vaid_plugin._ALLOW_EPHEMERAL_SEED_ENV, raising=False)  # undo the fixture's default
    vaid_plugin.reset_issuer_for_tests()
    with pytest.raises(vaid_plugin.BadgeDenied, match=vaid_plugin._ALLOW_EPHEMERAL_SEED_ENV):
        vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")


def test_badge_sha256_is_deterministic_and_order_independent():
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    h1 = vaid_plugin.badge_sha256(wrapped.badge)
    h2 = vaid_plugin.badge_sha256(dict(reversed(list(wrapped.badge.items()))))
    assert h1 == h2
    assert len(h1) == 64


# ── ToolRegistry boundary ─────────────────────────────────────────────────


def _registry_with_extract_iocs() -> ToolRegistry:
    return ToolRegistry(
        [
            Tool(
                name="extract_iocs",
                description="",
                parameters={"type": "object", "properties": {}},
                fn=lambda: {"iocs": []},
            )
        ]
    )


def test_registry_identity_verifier_defaults_to_none_no_behaviour_change():
    registry = _registry_with_extract_iocs()
    assert registry.identity_verifier is None


def test_install_into_is_a_no_op_when_plugin_disabled():
    registry = _registry_with_extract_iocs()
    installed = vaid_plugin.install_into(registry)
    assert installed is False
    assert registry.identity_verifier is None


def test_install_into_wires_the_hook_when_enabled(monkeypatch):
    _enable(monkeypatch)
    registry = _registry_with_extract_iocs()
    installed = vaid_plugin.install_into(registry)
    assert installed is True
    assert registry.identity_verifier is vaid_plugin.verify_identity_badge
    vaid_plugin.uninstall_from(registry)
    assert registry.identity_verifier is None


@pytest.mark.asyncio
async def test_execute_unaffected_when_plugin_not_installed_negative_control():
    """Off by default: a bare AgentIdentity still runs the tool exactly as
    it did before this plugin existed."""
    registry = _registry_with_extract_iocs()
    identity = issue_identity("triage", run_id="run-1")
    result = await registry.execute("extract_iocs", {}, identity=identity)
    assert result == {"iocs": []}


@pytest.mark.asyncio
async def test_execute_denies_a_bare_identity_once_the_plugin_is_installed(monkeypatch):
    _enable(monkeypatch)
    registry = _registry_with_extract_iocs()
    vaid_plugin.install_into(registry)
    identity = issue_identity("triage", run_id="run-1")
    result = await registry.execute("extract_iocs", {}, identity=identity)
    assert "error" in result
    assert "no badge" in result["error"]


@pytest.mark.asyncio
async def test_execute_allows_a_valid_badge_once_the_plugin_is_installed(monkeypatch, tmp_path):
    _enable(monkeypatch)
    monkeypatch.setenv(vaid_plugin._REVOCATION_LIST_PATH_ENV, str(_revocation_file(tmp_path, [])))
    vaid_plugin.reset_issuer_for_tests()
    registry = _registry_with_extract_iocs()
    vaid_plugin.install_into(registry)
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    result = await registry.execute("extract_iocs", {}, identity=wrapped)
    assert result == {"iocs": []}


@pytest.mark.asyncio
async def test_execute_still_enforces_scope_before_the_badge_check(monkeypatch, tmp_path):
    """The badge check is a second gate, not a replacement for scope."""
    _enable(monkeypatch)
    monkeypatch.setenv(vaid_plugin._REVOCATION_LIST_PATH_ENV, str(_revocation_file(tmp_path, [])))
    vaid_plugin.reset_issuer_for_tests()
    registry = ToolRegistry(
        [Tool(name="isolate_host", description="", parameters={"type": "object", "properties": {}}, fn=lambda: {})]
    )
    vaid_plugin.install_into(registry)
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    result = await registry.execute("isolate_host", {}, identity=wrapped)
    assert "outside the scope" in result["error"]


# ── Investigation Ledger badge-hash write ─────────────────────────────────


@pytest.mark.asyncio
async def test_record_badge_in_ledger_is_a_no_op_when_disabled():
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    result = await vaid_plugin.record_badge_in_ledger(
        wrapped, run_id=uuid.uuid4(), tenant_id=uuid.uuid4(), seq=1
    )
    assert result is None


@pytest.mark.asyncio
async def test_record_badge_in_ledger_writes_the_hash_not_the_badge(monkeypatch):
    _enable(monkeypatch)
    wrapped = vaid_plugin.issue_vaid_identity("triage", run_id="run-1", tenant_id="acme")
    captured = {}

    async def _fake_record_event(**kwargs):
        captured.update(kwargs)
        return uuid.uuid4()

    run_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    result = await vaid_plugin.record_badge_in_ledger(
        wrapped, run_id=run_id, tenant_id=tenant_id, seq=3, _record_event=_fake_record_event
    )

    assert result is not None
    assert captured["run_id"] == run_id
    assert captured["tenant_id"] == tenant_id
    assert captured["seq"] == 3
    assert captured["kind"] == "vaid_badge_issued"
    assert captured["payload"]["badge_sha256"] == vaid_plugin.badge_sha256(wrapped.badge)
    # Never the raw badge, and specifically never its key material.
    assert "public_key_der" not in captured["payload"]
    assert "kernel_signature" not in captured["payload"]
    assert captured["payload"]["vaid_id"] == wrapped.badge["vaid_id"]

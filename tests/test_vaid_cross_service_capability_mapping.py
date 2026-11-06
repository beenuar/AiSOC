"""Cross-service integration test for the optional VAID plugin (#1739).

``services/agents`` mints a badge from a real ``AgentIdentity``;
``services/actions`` verifies it at the response-dispatch boundary. The two
are independently deployable services — separate ``app`` packages that are
never imported together in one running process — so this test loads each
side under its own ``sys.path`` in sequence and carries only the plain-JSON
badge dict across the swap, which is exactly what crosses the real process
boundary in production (a ``LiveActionRequest.vaid_badge`` field, never a
Python object).

Why this test exists
---------------------
A code review of the per-service test suites
(``services/agents/tests/test_vaid_plugin.py``,
``services/actions/tests/test_vaid_verifier.py``,
``services/actions/tests/test_dispatch_vaid_boundary.py``) found that all
three exercise each boundary in isolation with hand-rolled, synthetic
badges — none of them mints through the real agents-side path
(``issue_vaid_identity``) and then verifies through the real actions-side
path (``verify_badge_for_dispatch``) for the same agent/capability pair.
That gap hid a real break: ``AGENT_TOOL_SCOPES`` (the agents service's
tool-call vocabulary — ``extract_iocs``, ``lookup_technique``, …) and
``services/actions``' ``ActionType``/capability vocabulary
(``isolate_host``, ``block_ip``, …) never intersect, so a badge minted with
``capability_set = identity.scopes`` alone could never satisfy
``has_capability(badge, request.capability)`` — every real dispatch would
have been refused. ``app.security.vaid_plugin.AGENT_ACTION_CAPABILITIES``
closes that; this test is what would have caught its absence.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("vaid_mint", reason="optional VAID plugin dependency — install the 'vaid' extra to run this suite")

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_ROOT = REPO_ROOT / "services" / "agents"
ACTIONS_ROOT = REPO_ROOT / "services" / "actions"

_ENV_VARS = (
    "AISOC_VAID_PLUGIN_ENABLED",
    "AISOC_VAID_KERNEL_PUBLIC_KEY_HEX",
    "AISOC_VAID_REVOCATION_LIST_PATH",
    "AISOC_VAID_KERNEL_SEED_PATH",
    "AISOC_VAID_ALLOW_EPHEMERAL_KERNEL_SEED",
    "AISOC_VAID_TTL_HOURS",
    "AISOC_VAID_TRUST_DOMAIN",
)


def _purge_app_modules() -> None:
    """Drop every cached ``app.*`` module so the next ``sys.path`` swap
    resolves ``app`` against the *other* service, instead of silently
    reusing whichever one happened to import first."""
    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            del sys.modules[name]


def _clear_vaid_env() -> None:
    for var in _ENV_VARS:
        os.environ.pop(var, None)


class _ServiceSwap:
    """Runs ``fn()`` with only one service's ``app`` package importable.

    Used as ``with _ServiceSwap(AGENTS_ROOT): ...`` — on exit, restores
    ``sys.path`` and purges every ``app.*`` module so the next swap starts
    clean, regardless of which exception, if any, occurred inside.
    """

    def __init__(self, service_root: Path) -> None:
        self._service_root = service_root
        self._old_path: list[str] | None = None

    def __enter__(self) -> _ServiceSwap:
        self._old_path = list(sys.path)
        _purge_app_modules()
        sys.path.insert(0, str(self._service_root))
        return self

    def __exit__(self, *exc_info: object) -> None:
        assert self._old_path is not None
        sys.path[:] = self._old_path
        _purge_app_modules()
        _clear_vaid_env()


TENANT = "acme"


def _mint_real_badge(agent: str, *, run_id: str, tenant_id: str = TENANT) -> tuple[dict, str]:
    """Mint through the REAL agents-service path — ``issue_identity()``
    (the scope table) then ``issue_vaid_identity()`` (the badge) — and
    return ``(badge, kernel_public_key_hex)`` as plain JSON-safe values.
    Nothing Python-object-shaped survives this function, which is the
    point: that is all that ever crosses the real process boundary.
    """
    with _ServiceSwap(AGENTS_ROOT):
        # A test process is the single-process case this flag exists for —
        # see vaid_plugin._kernel_seed()'s own docstring.
        os.environ["AISOC_VAID_ALLOW_EPHEMERAL_KERNEL_SEED"] = "true"
        vaid_plugin = importlib.import_module("app.security.vaid_plugin")
        vaid_plugin.reset_issuer_for_tests()
        wrapped = vaid_plugin.issue_vaid_identity(agent, run_id=run_id, tenant_id=tenant_id)
        badge = json.loads(json.dumps(wrapped.badge))
        pubkey_hex = vaid_plugin._issuer_handle_singleton().issuer.kernel_public_key().hex()
    return badge, pubkey_hex


def _real_action_types() -> set[str]:
    """The real ``ActionType`` values, loaded from the actions service."""
    with _ServiceSwap(ACTIONS_ROOT):
        action_module = importlib.import_module("app.models.action")
        return {member.value for member in action_module.ActionType}


def _verify_through_real_dispatch_boundary(
    badge: dict, capability: str, *, pubkey_hex: str, revocation_path: Path, tenant_id: str = TENANT
) -> None:
    """Verify through the REAL actions-service path —
    ``verify_badge_for_dispatch``, exactly as ``dispatch()`` calls it,
    including the tenant `dispatch()` passes down from the request. Minting
    under one tenant and verifying under another would make every test below
    pass on the tenant binding, never reaching the capability mapping they
    exist to check."""
    with _ServiceSwap(ACTIONS_ROOT):
        os.environ["AISOC_VAID_PLUGIN_ENABLED"] = "true"
        os.environ["AISOC_VAID_KERNEL_PUBLIC_KEY_HEX"] = pubkey_hex
        os.environ["AISOC_VAID_REVOCATION_LIST_PATH"] = str(revocation_path)
        vaid_verifier = importlib.import_module("app.security.vaid_verifier")
        vaid_verifier.verify_badge_for_dispatch(badge, capability, tenant_id=tenant_id)


@pytest.fixture(autouse=True)
def _clean_env_and_modules():
    _clear_vaid_env()
    _purge_app_modules()
    yield
    _clear_vaid_env()
    _purge_app_modules()


def test_a_respond_badge_minted_the_real_way_clears_dispatch_for_a_real_action(tmp_path):
    """The end-to-end property the per-service suites could not prove:
    mint via issue_vaid_identity("respond", ...), verify via
    verify_badge_for_dispatch for a real ActionType capability, same
    agent, same pair, both through their real (not hand-rolled) paths."""
    revocation_path = tmp_path / "revoked.json"
    revocation_path.write_text(json.dumps({"revoked": []}))

    badge, pubkey_hex = _mint_real_badge("respond", run_id="run-1", tenant_id="acme")

    # Would raise BadgeDenied before this fix: "respond"'s AgentIdentity
    # scope (AGENT_TOOL_SCOPES) is read-only tool names and never contained
    # "isolate_host" — an ActionType string from a different vocabulary.
    _verify_through_real_dispatch_boundary(badge, "isolate_host", pubkey_hex=pubkey_hex, revocation_path=revocation_path)


def test_a_triage_badge_minted_the_real_way_is_refused_for_any_response_action(tmp_path):
    """The negative half of the same property: an agent with no entry in
    AGENT_ACTION_CAPABILITIES (triage is read-only, exposed to
    attacker-controlled text, and must never be able to request a
    response action) stays refused end-to-end, not just in isolation."""
    revocation_path = tmp_path / "revoked.json"
    revocation_path.write_text(json.dumps({"revoked": []}))

    badge, pubkey_hex = _mint_real_badge("triage", run_id="run-2", tenant_id="acme")

    with pytest.raises(Exception, match="does not grant capability"):
        _verify_through_real_dispatch_boundary(badge, "isolate_host", pubkey_hex=pubkey_hex, revocation_path=revocation_path)


def test_agent_action_capabilities_name_only_real_action_types():
    """Drift guard: AGENT_ACTION_CAPABILITIES (services/agents, hand-written
    because the two services don't import each other) must name a subset
    of the actions service's REAL ActionType values. The two are checked
    against each other here specifically so an ActionType rename is caught
    by this test, rather than discovered as every dispatch refusing in
    production — the way the mapping's total *absence* was first found."""
    with _ServiceSwap(AGENTS_ROOT):
        vaid_plugin = importlib.import_module("app.security.vaid_plugin")
        declared = set()
        for capabilities in vaid_plugin.AGENT_ACTION_CAPABILITIES.values():
            declared |= set(capabilities)

    real = _real_action_types()
    assert declared, "AGENT_ACTION_CAPABILITIES has no entries — the mapping this test guards does not exist"
    assert declared <= real, f"named capabilities not in the real ActionType enum: {declared - real}"


def test_a_real_badge_does_not_clear_a_dispatch_for_a_different_tenant(tmp_path):
    """The other end-to-end property, found in review of PR #1741.

    `verify_vaid_standing` answers "is this badge authentic and does it still
    stand". A badge minted through the real agents path under tenant A is
    authentic, stands, and carries `isolate_host` — and before the binding it
    verified cleanly against a dispatch belonging to tenant B. Nothing was
    escalated by that (the actions service's own kill switch, contract,
    approval matrix and blast-radius tier all still run), but the one thing
    #1739 asked for is proof of *under whose authority* an action ran, and a
    credential that is valid under anyone's authority does not provide it.

    Minted and verified through both real paths, because the per-service
    suites each hold one side and neither could see the pair disagree.
    """
    revocation_path = tmp_path / "revoked.json"
    revocation_path.write_text(json.dumps({"revoked": []}))

    badge, pubkey_hex = _mint_real_badge("respond", run_id="run-3", tenant_id="tenant-a")

    # Control: it clears its own tenant, so the refusal below is about the
    # tenant and not about the badge being broken.
    _verify_through_real_dispatch_boundary(
        badge,
        "isolate_host",
        pubkey_hex=pubkey_hex,
        revocation_path=revocation_path,
        tenant_id="tenant-a",
    )

    with pytest.raises(Exception, match="bound to tenant 'tenant-a'"):
        _verify_through_real_dispatch_boundary(
            badge,
            "isolate_host",
            pubkey_hex=pubkey_hex,
            revocation_path=revocation_path,
            tenant_id="tenant-b",
        )

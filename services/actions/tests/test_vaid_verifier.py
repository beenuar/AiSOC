"""Unit tests for the optional VAID plugin (beenuar/AiSOC#1739), actions
side — the response-dispatch boundary. This service never sees an
``AgentIdentity`` object, only the badge (a plain JSON document) that
travelled with the request, so these tests mint badges directly with
``vaid_mint`` rather than importing anything from ``services/agents``.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("vaid_mint", reason="optional VAID plugin dependency — install the 'vaid' extra to run this suite")

from app.security import vaid_verifier
from vaid_mint import ReferenceIssuer
from vaid_mint.revocation import InMemoryLineageStore, RevocationBackend


@pytest.fixture(autouse=True)
def _reset_env(monkeypatch):
    monkeypatch.delenv(vaid_verifier._ENABLED_ENV, raising=False)
    monkeypatch.delenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, raising=False)
    monkeypatch.delenv(vaid_verifier._REVOCATION_LIST_PATH_ENV, raising=False)
    yield


#: The tenant every badge in this module is minted for. The verifier binds
#: a badge to the tenant it is presented for, so a test that mints under one
#: tenant and verifies under another is testing the binding, not the thing it
#: says it is testing.
TENANT = "acme"


def _enable(monkeypatch):
    monkeypatch.setenv(vaid_verifier._ENABLED_ENV, "true")


def _revocation_file(tmp_path, revoked: list[str]):
    path = tmp_path / "revoked.json"
    path.write_text(json.dumps({"revoked": revoked}))
    return path


class _Mint:
    """A standalone issuer, standing in for the agents service's mint. The
    public key is what the actions service is configured with; the private
    half never leaves this test, mirroring the real cross-process split."""

    def __init__(self) -> None:
        self.issuer = ReferenceIssuer.ephemeral(1, "agents.aisoc.local")
        self.issuer.with_revocation_backend(RevocationBackend(check=_AlwaysVouch(), lineage=InMemoryLineageStore()))

    def mint(self, *, capability_set: list[str], tenant_id: str = TENANT) -> dict:
        return self.issuer.issue_vaid_with_lineage(
            agent_class="respond",
            version="1",
            tenant_id=tenant_id,
            parent_vaid=None,
            scope_boundary=[],
            capability_set=capability_set,
        )

    def public_key_hex(self) -> str:
        return self.issuer.kernel_public_key().hex()


class _AlwaysVouch:
    def check_lineage(self, lineage):
        from vaid_mint.revocation import RevocationStatus

        return RevocationStatus.NOT_REVOKED


def _configure(monkeypatch, mint: _Mint, tmp_path, revoked: list[str] | None = None):
    monkeypatch.setenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, mint.public_key_hex())
    monkeypatch.setenv(
        vaid_verifier._REVOCATION_LIST_PATH_ENV,
        str(_revocation_file(tmp_path, revoked if revoked is not None else [])),
    )


# ── Off by default: the negative control ──────────────────────────────────


def test_disabled_plugin_is_a_no_op_even_with_no_badge():
    assert vaid_verifier.vaid_plugin_enabled() is False
    vaid_verifier.verify_badge_for_dispatch(None, "isolate_host")  # must not raise


# ── Fail-closed when enabled ───────────────────────────────────────────────


def test_enabled_plugin_refuses_a_missing_badge(monkeypatch):
    _enable(monkeypatch)
    with pytest.raises(vaid_verifier.BadgeDenied, match="no vaid_badge"):
        vaid_verifier.verify_badge_for_dispatch(None, "isolate_host")


def test_enabled_plugin_accepts_a_valid_badge_granting_the_capability(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    badge = mint.mint(capability_set=["isolate_host"])
    vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)  # must not raise


def test_enabled_plugin_refuses_a_badge_lacking_the_capability(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    badge = mint.mint(capability_set=["search_siem"])
    with pytest.raises(vaid_verifier.BadgeDenied, match="does not grant capability"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


def test_enabled_plugin_refuses_without_a_configured_kernel_public_key(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    monkeypatch.setenv(vaid_verifier._REVOCATION_LIST_PATH_ENV, str(_revocation_file(tmp_path, [])))
    badge = mint.mint(capability_set=["isolate_host"])
    with pytest.raises(vaid_verifier.BadgeDenied, match=vaid_verifier._KERNEL_PUBLIC_KEY_ENV):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


def test_enabled_plugin_fails_closed_with_no_revocation_list_configured(monkeypatch):
    """Air-gapped posture: no shipped list = UNAVAILABLE, never treated as
    "nothing is revoked"."""
    _enable(monkeypatch)
    mint = _Mint()
    monkeypatch.setenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, mint.public_key_hex())
    badge = mint.mint(capability_set=["isolate_host"])
    with pytest.raises(vaid_verifier.BadgeDenied, match="indeterminate"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


def test_enabled_plugin_refuses_a_revoked_badge(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    badge = mint.mint(capability_set=["isolate_host"])
    _configure(monkeypatch, mint, tmp_path, revoked=[badge["vaid_id"]])
    with pytest.raises(vaid_verifier.BadgeDenied, match="revoked"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


def test_enabled_plugin_refuses_a_badge_signed_by_a_different_key(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    other_mint = _Mint()
    _configure(monkeypatch, other_mint, tmp_path)  # configured with the WRONG key
    badge = mint.mint(capability_set=["isolate_host"])
    with pytest.raises(vaid_verifier.BadgeDenied, match="failed verification"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


def test_enabled_plugin_refuses_a_tampered_badge(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    badge = dict(mint.mint(capability_set=["isolate_host"]))
    badge["capability_set"] = [*badge["capability_set"], "revoke_session"]
    with pytest.raises(vaid_verifier.BadgeDenied, match="failed verification"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


def test_enabled_plugin_refuses_a_delegated_child_badge(monkeypatch, tmp_path):
    """This plugin mints and verifies root badges only (module docstring);
    a badge carrying a parent_vaid is refused outright rather than silently
    trusted without lineage resolution."""
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    badge = dict(mint.mint(capability_set=["isolate_host"]))
    badge["parent_vaid"] = "11111111-1111-1111-1111-111111111111"
    with pytest.raises(vaid_verifier.BadgeDenied, match="root VAID badges only"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


# ── Review follow-ups (PR #1741) ───────────────────────────────────────────
#
# Each of these was measured against the first draft of this module, which
# refused four of five malformed-input shapes correctly and raised on the
# fifth. They are regressions in the literal sense: revert the corresponding
# guard in `vaid_verifier.py` and each one goes red.


@pytest.mark.parametrize(
    "badge",
    [
        pytest.param({}, id="empty-object"),
        pytest.param({"hello": "world"}, id="not-a-vaid"),
        pytest.param({"vaid_id": "urn:not-a-uuid"}, id="vaid_id-only"),
        pytest.param({"vaid_id": None, "capability_set": ["isolate_host"]}, id="null-vaid_id"),
    ],
)
def test_enabled_plugin_refuses_a_malformed_badge_rather_than_raising(monkeypatch, tmp_path, badge):
    """A malformed badge must be a refusal with a reason, not an exception.

    vaid-mint 0.11.0's `assemble_lineage` opens with a bare `leaf["vaid_id"]`,
    so before the parse gate these inputs raised `KeyError` out of the
    verifier. `dispatch()` caught only `BadgeDenied`, so the exception escaped
    a route documented as never returning 5xx. The action never ran either
    way — this is about the refusal being *stated* rather than being an
    accident of where the stack unwound.
    """
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    with pytest.raises(vaid_verifier.BadgeDenied, match="well-formed VAID document"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


def test_enabled_plugin_refuses_a_badge_minted_for_another_tenant(monkeypatch, tmp_path):
    """A genuine badge is not automatically *this caller's* badge.

    `verify_vaid_standing` answers "is this authentic and does it still
    stand", which a correctly-signed badge issued under another tenant's
    authority passes. Accepting it would undercut the one thing #1739 asked
    for: proving under whose authority an action ran.
    """
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    badge = mint.mint(capability_set=["isolate_host"], tenant_id="some-other-tenant")
    with pytest.raises(vaid_verifier.BadgeDenied, match="bound to tenant 'some-other-tenant'"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=TENANT)


def test_enabled_plugin_refuses_a_tenant_bound_badge_on_a_tenantless_dispatch(monkeypatch, tmp_path):
    """`LiveActionRequest.tenant_id` is optional. The permissive reading —
    "no tenant named, so nothing to compare against, so allow" — would make
    the binding above trivially bypassable by omitting a field."""
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    badge = mint.mint(capability_set=["isolate_host"])
    with pytest.raises(vaid_verifier.BadgeDenied, match="names no tenant"):
        vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=None)


def test_tenant_binding_accepts_a_uuid_typed_tenant(monkeypatch, tmp_path):
    """The caller passes `request.tenant_id`, a `UUID | None`; the badge
    carries a string. The comparison has to survive that, or the binding
    refuses every real dispatch and reads as "fails closed" while being
    "never works"."""
    from uuid import UUID

    _enable(monkeypatch)
    tenant = UUID("11111111-1111-1111-1111-111111111111")
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    badge = mint.mint(capability_set=["isolate_host"], tenant_id=str(tenant))
    vaid_verifier.verify_badge_for_dispatch(badge, "isolate_host", tenant_id=tenant)  # must not raise


# ── Startup check: fails at boot, not at the first dispatch ──────────────
# beenuar/AiSOC#1739 follow-up, verify-side counterpart of the agents
# service's mint-side `preflight_or_raise`.


def test_preflight_is_a_no_op_when_the_plugin_is_disabled():
    vaid_verifier.preflight_or_raise()  # must not raise


def test_preflight_is_a_strict_no_op_when_disabled_no_reads_no_raise_no_logs(monkeypatch, caplog):
    """Stronger than "does not raise": with the flag unset (the default,
    and the fixture's own baseline — no kernel key, no revocation list,
    nothing configured), this must touch nothing the enabled path would
    touch.

    Proven by making every one of those paths explode if reached, rather
    than by reading the source and trusting the early return."""
    import logging

    def _boom(*a, **kw):
        raise AssertionError("preflight_or_raise touched the enabled-only path with the plugin disabled")

    monkeypatch.setattr(vaid_verifier, "_kernel_public_key", _boom)
    monkeypatch.setattr(vaid_verifier, "_FileRevocationList", _boom)
    monkeypatch.setattr(vaid_verifier.Path, "read_text", _boom)

    with caplog.at_level(logging.DEBUG):
        vaid_verifier.preflight_or_raise()  # must not raise

    assert caplog.records == []


def test_preflight_refuses_when_no_kernel_public_key_is_configured(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    monkeypatch.delenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, raising=False)

    with pytest.raises(vaid_verifier.BadgeDenied, match=vaid_verifier._KERNEL_PUBLIC_KEY_ENV):
        vaid_verifier.preflight_or_raise()


def test_preflight_refuses_when_no_revocation_list_is_configured(monkeypatch):
    """The gap named in the pull request: enabling the plugin with no
    `AISOC_VAID_REVOCATION_LIST_PATH` used to refuse every dispatch, live.
    This must refuse at startup instead."""
    _enable(monkeypatch)
    mint = _Mint()
    monkeypatch.setenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, mint.public_key_hex())

    with pytest.raises(vaid_verifier.BadgeDenied, match=vaid_verifier._REVOCATION_LIST_PATH_ENV):
        vaid_verifier.preflight_or_raise()


def test_preflight_refuses_when_the_revocation_list_file_is_malformed(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    monkeypatch.setenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, mint.public_key_hex())
    bad_path = tmp_path / "revoked.json"
    bad_path.write_text("not json")
    monkeypatch.setenv(vaid_verifier._REVOCATION_LIST_PATH_ENV, str(bad_path))

    with pytest.raises(vaid_verifier.BadgeDenied, match=vaid_verifier._REVOCATION_LIST_PATH_ENV):
        vaid_verifier.preflight_or_raise()


def test_preflight_passes_when_the_plugin_is_fully_configured(monkeypatch, tmp_path):
    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)
    vaid_verifier.preflight_or_raise()  # must not raise


def test_preflight_refuses_when_vaid_mint_is_not_installed(monkeypatch, tmp_path):
    """The likeliest misconfiguration of all, and the one the first draft of
    this check could not see: everything configured correctly, and the
    library absent.

    ``vaid-mint`` is an optional extra, so ``poetry export --only main`` —
    what this service's ``Dockerfile`` installs from — carries none of it.
    The stock image therefore has the flag and not the library, and a
    preflight that reads only environment variables and a JSON file passes
    on it. Measured before the fix: a fully-configured deployment booted
    clean and answered the first badge-bearing dispatch with ``VAID badge
    check failed unexpectedly (ModuleNotFoundError); refusing fail-closed``
    — a containment action refused, blamed on nothing an operator can act
    on, at the hour this check exists to avoid.
    """
    import sys

    _enable(monkeypatch)
    mint = _Mint()
    _configure(monkeypatch, mint, tmp_path)

    class _Absent:
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "vaid_mint" or fullname.startswith("vaid_mint."):
                raise ModuleNotFoundError(f"No module named {fullname!r}")
            return None

    for name in [n for n in sys.modules if n == "vaid_mint" or n.startswith("vaid_mint.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(sys, "meta_path", [_Absent(), *sys.meta_path])

    with pytest.raises(ModuleNotFoundError, match="vaid_mint"):
        vaid_verifier.preflight_or_raise()


def test_preflight_imports_everything_the_verification_path_imports():
    """Binds the two lists together so the preflight cannot fall behind.

    ``preflight_or_raise`` proves the library is importable by importing the
    same names ``verify_badge_for_dispatch`` reaches for. Two hand-written
    lists of the same thing drift, and the drift would show up as the exact
    boot-clean-then-refuse behaviour the test above exists to prevent — so
    this reads the module and fails when the verification path grows a
    ``vaid_mint`` import the preflight does not cover.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(vaid_verifier))
    preflight = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "preflight_or_raise")

    def _vaid_imports(node) -> set[str]:
        return {n.module for n in ast.walk(node) if isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] == "vaid_mint"}

    covered = _vaid_imports(preflight)
    assert covered, "preflight_or_raise imports no vaid_mint module, so it cannot prove the library is installed"
    assert _vaid_imports(tree) <= covered, (
        f"the verification path imports a vaid_mint module the preflight does not: {sorted(_vaid_imports(tree) - covered)}"
    )

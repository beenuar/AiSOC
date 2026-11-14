"""The response-dispatch half of the VAID plugin's two boundaries
(beenuar/AiSOC#1739): ``dispatch()`` must refuse before any executor runs
when the plugin is enabled and the badge does not stand up, and must be
byte-for-byte unaffected when the plugin is off (the negative control).

These badges are hand-minted with ``_mint()`` below, deliberately isolated
from the real agents-service mint path — this file is about ``dispatch()``'s
own mechanics (ordering, the spy-executor proof that a denial never reaches
a vendor, the plugin-off negative control), not about whether a *real*
badge's ``capability_set`` happens to contain the capability being dispatched.
That second question — does a badge minted by
``app.security.vaid_plugin.issue_vaid_identity`` for a real agent actually
clear ``verify_badge_for_dispatch`` for a real ``ActionType`` — is exactly
what a synthetic badge here cannot prove (it was, in fact, how a real
vocabulary mismatch between ``AGENT_TOOL_SCOPES`` and ``ActionType`` stayed
hidden past review once already). See
``tests/test_vaid_cross_service_capability_mapping.py`` at the repo root,
which mints through the real path and verifies through this one.
"""

from __future__ import annotations

import asyncio
import json
from uuid import UUID

import pytest

pytest.importorskip("vaid_mint", reason="optional VAID plugin dependency — install the 'vaid' extra to run this suite")

from app.live_actions import (
    LiveActionExecutor,
    LiveActionRequest,
    LiveActionResult,
    LiveActionStatus,
    dispatch,
    register_executor,
    reset_for_tests,
)
from app.security import vaid_verifier
from vaid_mint import ReferenceIssuer
from vaid_mint.revocation import InMemoryLineageStore, RevocationBackend, RevocationStatus

TENANT = UUID("11111111-1111-1111-1111-111111111111")


class _OkExecutor(LiveActionExecutor):
    vendor_id = "stubvendor"
    capability = "isolate_host"
    description = "succeeds"
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary=f"isolated {request.target}",
        )


class _AlwaysVouch:
    def check_lineage(self, lineage):
        return RevocationStatus.NOT_REVOKED


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    reset_for_tests()
    monkeypatch.delenv(vaid_verifier._ENABLED_ENV, raising=False)
    monkeypatch.delenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, raising=False)
    monkeypatch.delenv(vaid_verifier._REVOCATION_LIST_PATH_ENV, raising=False)
    yield
    reset_for_tests()


def _mint(capability_set: list[str], *, tenant_id: str = str(TENANT)) -> tuple[dict, str]:
    """Mint under ``TENANT`` by default: the verifier binds a badge to the
    tenant it is presented for, so a badge minted under some other name would
    be refused on the binding before any test here reached its own subject."""
    issuer = ReferenceIssuer.ephemeral(1, "agents.aisoc.local")
    issuer.with_revocation_backend(RevocationBackend(check=_AlwaysVouch(), lineage=InMemoryLineageStore()))
    badge = issuer.issue_vaid_with_lineage(
        agent_class="respond",
        version="1",
        tenant_id=tenant_id,
        parent_vaid=None,
        scope_boundary=[],
        capability_set=capability_set,
    )
    return badge, issuer.kernel_public_key().hex()


def test_plugin_disabled_dispatch_ignores_a_missing_badge_negative_control():
    """Off by default: dispatch succeeds with no badge at all, exactly as
    it did before this plugin existed."""
    register_executor(_OkExecutor())
    request = LiveActionRequest(tenant_id=TENANT, capability="isolate_host", vendor_id="stubvendor", target="srv-12", dry_run=True)
    result = asyncio.run(dispatch(request))
    assert result.status == LiveActionStatus.SUCCEEDED


def test_plugin_enabled_refuses_dispatch_with_no_badge_before_any_executor_runs(monkeypatch):
    monkeypatch.setenv(vaid_verifier._ENABLED_ENV, "true")
    ran = {"executed": False}

    class _Spy(_OkExecutor):
        async def execute(self, request: LiveActionRequest) -> LiveActionResult:
            ran["executed"] = True
            return await super().execute(request)

    register_executor(_Spy())
    request = LiveActionRequest(tenant_id=TENANT, capability="isolate_host", vendor_id="stubvendor", target="srv-12", dry_run=True)
    result = asyncio.run(dispatch(request))

    assert result.status == LiveActionStatus.FAILED
    assert "no vaid_badge" in result.error
    assert ran["executed"] is False


def test_plugin_enabled_allows_dispatch_with_a_valid_badge(monkeypatch, tmp_path):
    monkeypatch.setenv(vaid_verifier._ENABLED_ENV, "true")
    badge, pubkey_hex = _mint(["isolate_host"])
    monkeypatch.setenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, pubkey_hex)
    revocation_path = tmp_path / "revoked.json"
    revocation_path.write_text(json.dumps({"revoked": []}))
    monkeypatch.setenv(vaid_verifier._REVOCATION_LIST_PATH_ENV, str(revocation_path))

    register_executor(_OkExecutor())
    request = LiveActionRequest(
        tenant_id=TENANT,
        capability="isolate_host",
        vendor_id="stubvendor",
        target="srv-12",
        dry_run=True,
        vaid_badge=badge,
    )
    result = asyncio.run(dispatch(request))

    assert result.status == LiveActionStatus.SUCCEEDED


def test_plugin_enabled_refuses_dispatch_when_badge_lacks_the_capability(monkeypatch, tmp_path):
    monkeypatch.setenv(vaid_verifier._ENABLED_ENV, "true")
    badge, pubkey_hex = _mint(["search_siem"])  # not isolate_host
    monkeypatch.setenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, pubkey_hex)
    revocation_path = tmp_path / "revoked.json"
    revocation_path.write_text(json.dumps({"revoked": []}))
    monkeypatch.setenv(vaid_verifier._REVOCATION_LIST_PATH_ENV, str(revocation_path))

    register_executor(_OkExecutor())
    request = LiveActionRequest(
        tenant_id=TENANT,
        capability="isolate_host",
        vendor_id="stubvendor",
        target="srv-12",
        dry_run=True,
        vaid_badge=badge,
    )
    result = asyncio.run(dispatch(request))

    assert result.status == LiveActionStatus.FAILED
    assert "does not grant capability" in result.error


# ── Review follow-ups (PR #1741) ───────────────────────────────────────────


def test_malformed_badge_returns_a_result_rather_than_escaping_dispatch(monkeypatch, tmp_path):
    """`dispatch()` documents that it "never raises for expected failure
    modes" and "always returns a LiveActionResult", and the REST route above
    it documents that it "never returns 5xx for executor failures" because
    "the agent loop relies on a uniform success-shape".

    Measured before the fix: a request body carrying `"vaid_badge": {}`
    raised `KeyError: 'vaid_id'` straight out of `dispatch()`, because
    `except BadgeDenied` is narrower than what vaid-mint actually raises.
    """
    monkeypatch.setenv(vaid_verifier._ENABLED_ENV, "true")
    _, pubkey_hex = _mint(["isolate_host"])
    monkeypatch.setenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, pubkey_hex)
    revocation_path = tmp_path / "revoked.json"
    revocation_path.write_text(json.dumps({"revoked": []}))
    monkeypatch.setenv(vaid_verifier._REVOCATION_LIST_PATH_ENV, str(revocation_path))

    ran = {"executed": False}

    class _Spy(_OkExecutor):
        async def execute(self, request: LiveActionRequest) -> LiveActionResult:
            ran["executed"] = True
            return await super().execute(request)

    register_executor(_Spy())
    request = LiveActionRequest(
        tenant_id=TENANT,
        capability="isolate_host",
        vendor_id="stubvendor",
        target="srv-12",
        dry_run=True,
        vaid_badge={},
    )
    result = asyncio.run(dispatch(request))

    assert result.status == LiveActionStatus.FAILED
    assert "well-formed VAID document" in result.error
    assert ran["executed"] is False


def test_an_unexpected_verifier_exception_is_still_a_refusal_not_a_500(monkeypatch):
    """The backstop, proven rather than asserted.

    The parse gate makes today's vaid-mint total for our inputs. It is a
    promise about a third-party library, and the next release is not bound by
    it — so `dispatch()` keeps a broad `except`, and this drives it by making
    the verifier raise something it has no branch for.
    """
    monkeypatch.setenv(vaid_verifier._ENABLED_ENV, "true")

    def _explode(*_args, **_kwargs):
        raise RuntimeError("a future vaid-mint raised something new")

    monkeypatch.setattr("app.live_actions.dispatcher.verify_badge_for_dispatch", _explode)

    ran = {"executed": False}

    class _Spy(_OkExecutor):
        async def execute(self, request: LiveActionRequest) -> LiveActionResult:
            ran["executed"] = True
            return await super().execute(request)

    register_executor(_Spy())
    request = LiveActionRequest(tenant_id=TENANT, capability="isolate_host", vendor_id="stubvendor", target="srv-12", dry_run=True)
    result = asyncio.run(dispatch(request))

    assert result.status == LiveActionStatus.FAILED
    assert "refusing fail-closed" in result.error
    assert ran["executed"] is False


def test_dispatch_refuses_a_badge_minted_for_another_tenant(monkeypatch, tmp_path):
    """The binding reaches the real dispatch path, not just the verifier:
    `dispatch()` has to pass `request.tenant_id` down for it to mean
    anything, and a verifier argument nobody supplies is the shape this
    repository has been bitten by before."""
    monkeypatch.setenv(vaid_verifier._ENABLED_ENV, "true")
    badge, pubkey_hex = _mint(["isolate_host"], tenant_id="22222222-2222-2222-2222-222222222222")
    monkeypatch.setenv(vaid_verifier._KERNEL_PUBLIC_KEY_ENV, pubkey_hex)
    revocation_path = tmp_path / "revoked.json"
    revocation_path.write_text(json.dumps({"revoked": []}))
    monkeypatch.setenv(vaid_verifier._REVOCATION_LIST_PATH_ENV, str(revocation_path))

    ran = {"executed": False}

    class _Spy(_OkExecutor):
        async def execute(self, request: LiveActionRequest) -> LiveActionResult:
            ran["executed"] = True
            return await super().execute(request)

    register_executor(_Spy())
    request = LiveActionRequest(
        tenant_id=TENANT,  # a different tenant from the one the badge names
        capability="isolate_host",
        vendor_id="stubvendor",
        target="srv-12",
        dry_run=True,
        vaid_badge=badge,
    )
    result = asyncio.run(dispatch(request))

    assert result.status == LiveActionStatus.FAILED
    assert "bound to tenant" in result.error
    assert ran["executed"] is False

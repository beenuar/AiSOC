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
from uuid import UUID, uuid4

import pytest

pytest.importorskip("vaid_mint", reason="optional VAID plugin dependency — install the 'vaid' extra to run this suite")

from app.live_actions import LiveActionExecutor, LiveActionRequest, LiveActionResult, LiveActionStatus, dispatch, register_executor, reset_for_tests
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


def _mint(capability_set: list[str]) -> tuple[dict, str]:
    issuer = ReferenceIssuer.ephemeral(1, "agents.aisoc.local")
    issuer.with_revocation_backend(RevocationBackend(check=_AlwaysVouch(), lineage=InMemoryLineageStore()))
    badge = issuer.issue_vaid_with_lineage(
        agent_class="respond",
        version="1",
        tenant_id="acme",
        parent_vaid=None,
        scope_boundary=[],
        capability_set=capability_set,
    )
    return badge, issuer.kernel_public_key().hex()


def test_plugin_disabled_dispatch_ignores_a_missing_badge_negative_control():
    """Off by default: dispatch succeeds with no badge at all, exactly as
    it did before this plugin existed."""
    register_executor(_OkExecutor())
    request = LiveActionRequest(
        tenant_id=TENANT, capability="isolate_host", vendor_id="stubvendor", target="srv-12", dry_run=True
    )
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
    request = LiveActionRequest(
        tenant_id=TENANT, capability="isolate_host", vendor_id="stubvendor", target="srv-12", dry_run=True
    )
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

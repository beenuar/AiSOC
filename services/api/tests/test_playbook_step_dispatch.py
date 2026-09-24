"""The API hop a playbook step takes to reach governed dispatch.

This module decides two things and no more: which vendor, and which
credentials. Everything about whether the verb may run belongs to
``services/actions``, so the tests here are mostly about the answers this
layer gives when it *cannot* dispatch — because those are the answers that
used to be a silent simulation.

The load-bearing assertion in almost every case is ``executed``. It is the
single field that means a vendor was touched, and every path that did not
touch one has to say so and say which path it was.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.services import actions_client, playbook_step_dispatch
from app.services.playbook_step_dispatch import StepDispatchReport, dispatch_step

pytestmark = pytest.mark.asyncio

TENANT = uuid.uuid4()


class _Connector:
    """The fields this module reads off a connector row."""

    def __init__(self, connector_type: str, *, allowed: list[str] | None = None, config: dict | None = None) -> None:
        self.connector_type = connector_type
        self.name = connector_type
        self.auth_config = {"api_token": "vault:v1:ciphertext"}
        self.connector_config = config or {}
        self.allowed_capabilities = allowed


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    implementers: list[str] | Exception,
    connectors: list[_Connector] | None = None,
    response: dict[str, Any] | Exception | None = None,
) -> list[dict[str, Any]]:
    """Stand in for the action registry, the tenant database and the vault."""
    sent: list[dict[str, Any]] = []

    async def _vendors(capability: str) -> list[str]:
        if isinstance(implementers, Exception):
            raise implementers
        return implementers

    async def _dispatch(**kwargs: Any) -> dict[str, Any]:
        sent.append(kwargs)
        if isinstance(response, Exception):
            raise response
        return response or {"result": {"status": "succeeded", "summary": "done", "details": {}}}

    monkeypatch.setattr(actions_client, "vendors_for_capability", _vendors)
    monkeypatch.setattr(actions_client, "dispatch_live_action", _dispatch)
    monkeypatch.setattr(playbook_step_dispatch, "get_vault", lambda: _Vault())

    rows = connectors if connectors is not None else [_Connector("crowdstrike")]

    async def _pick_connector(db, *, tenant_id, capability, implementers, pinned):  # noqa: ANN001
        for connector in rows:
            if pinned and connector.connector_type != pinned:
                continue
            if connector.connector_type not in implementers:
                continue
            if connector.allowed_capabilities is not None and capability not in connector.allowed_capabilities:
                continue
            return connector
        return None

    monkeypatch.setattr(playbook_step_dispatch, "_pick_connector", _pick_connector)
    return sent


class _Vault:
    def decrypt_dict(self, blob: dict) -> dict:
        return {"api_token": "plaintext"}


async def _run(**overrides: Any) -> StepDispatchReport:
    payload: dict[str, Any] = {
        "tenant_id": TENANT,
        "capability": "isolate_host",
        "target": "ws-042",
        "dry_run": False,
    }
    payload.update(overrides)
    return await dispatch_step(None, **payload)  # type: ignore[arg-type]


class TestWhenItCannotDispatch:
    async def test_a_verb_no_executor_implements_is_unsupported_not_simulated(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Distinct from "this tenant has no integration": no configuration helps."""
        _wire(monkeypatch, implementers=[])
        report = await _run()
        assert report.status == "unsupported"
        assert report.executed is False
        assert "KNOWN_CAPABILITIES" in report.detail

    async def test_a_tenant_with_no_connector_says_so(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire(monkeypatch, implementers=["crowdstrike", "defender"], connectors=[])
        report = await _run()
        assert report.status == "no_integration"
        assert report.executed is False
        assert "crowdstrike, defender" in report.detail

    async def test_a_pinned_vendor_the_tenant_does_not_have_is_refused_not_substituted(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Quietly using a different vendor is how an action gets reported
        against one that was never involved."""
        sent = _wire(monkeypatch, implementers=["crowdstrike", "defender"], connectors=[_Connector("crowdstrike")])
        report = await _run(vendor_id="defender")
        assert report.status == "no_integration"
        assert report.executed is False
        assert sent == []

    async def test_per_instance_downscoping_outranks_the_playbook(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A tenant who excluded a verb on an integration meant it."""
        sent = _wire(
            monkeypatch,
            implementers=["crowdstrike"],
            connectors=[_Connector("crowdstrike", allowed=["pull_alerts", "get_host"])],
        )
        report = await _run()
        assert report.status == "no_integration"
        assert sent == []

    async def test_undecryptable_credentials_fail_rather_than_preview(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A step that silently became a preview because a key would not
        decrypt is the failure this whole change removes."""
        from app.security.credential_vault import CredentialVaultError

        sent = _wire(monkeypatch, implementers=["crowdstrike"])

        class _Broken:
            def decrypt_dict(self, blob: dict) -> dict:
                raise CredentialVaultError("key rotated out")

        monkeypatch.setattr(playbook_step_dispatch, "get_vault", lambda: _Broken())
        report = await _run()
        assert report.status == "failed"
        assert report.executed is False
        assert sent == []

    async def test_an_unreachable_registry_is_a_failure_not_an_empty_list(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An outage must not read as "the product cannot do this"."""
        _wire(monkeypatch, implementers=actions_client.ActionsServiceError("connection refused"))
        report = await _run()
        assert report.status == "failed"
        assert report.executed is False


class TestHowItReadsTheResult:
    @pytest.mark.parametrize(
        ("upstream", "status", "executed"),
        [
            ("succeeded", "executed", True),
            ("awaiting_completion", "awaiting_completion", True),
            ("pending_approval", "pending_approval", False),
            ("blocked", "blocked", False),
            ("simulated", "simulated", False),
            ("failed", "failed", False),
        ],
    )
    async def test_every_live_action_status_maps_to_one_honest_outcome(
        self,
        monkeypatch: pytest.MonkeyPatch,
        upstream: str,
        status: str,
        executed: bool,
    ) -> None:
        """`AWAITING_COMPLETION` and `PENDING_APPROVAL` are the pair that
        must not collapse: the vendor was touched in one and not the other."""
        _wire(monkeypatch, implementers=["crowdstrike"], response={"result": {"status": upstream, "summary": "s", "details": {}}})
        report = await _run()
        assert report.status == status
        assert report.executed is executed

    async def test_an_unrecognised_status_is_not_a_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Guessing "it probably worked" is how the collapse got in originally."""
        _wire(monkeypatch, implementers=["crowdstrike"], response={"result": {"status": "invented", "details": {}}})
        report = await _run()
        assert report.status == "failed"
        assert report.executed is False

    async def test_a_dry_run_is_never_an_execution_whatever_came_back(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _wire(monkeypatch, implementers=["crowdstrike"], response={"result": {"status": "succeeded", "details": {}}})
        report = await _run(dry_run=True)
        assert report.status == "dry_run"
        assert report.executed is False

    async def test_the_verification_verdict_is_carried_through_verbatim(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ "Unverifiable means not autonomous" needs the verdict to survive
        the hop, or the step reports success with nothing behind it."""
        _wire(
            monkeypatch,
            implementers=["crowdstrike"],
            response={
                "result": {
                    "status": "succeeded",
                    "summary": "isolated",
                    "details": {"verification": "verified", "verification_reason": "device reports contained"},
                }
            },
        )
        report = await _run()
        assert report.verification == "verified"
        assert report.verification_reason == "device reports contained"

    async def test_an_execution_with_no_probe_reports_unverified_rather_than_blank(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A blank field and a confirmed one look identical to a reader."""
        _wire(monkeypatch, implementers=["crowdstrike"], response={"result": {"status": "succeeded", "details": {}}})
        report = await _run()
        assert report.executed is True
        assert report.verification == "unverified"


class TestWhatItSendsOn:
    async def test_confidence_and_provenance_reach_the_action_service(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sent = _wire(monkeypatch, implementers=["crowdstrike"])
        await _run(confidence=0.93, playbook_run_id="run-7", playbook_step_id="step-2")
        assert sent[0]["confidence"] == 0.93
        assert sent[0]["playbook_run_id"] == "run-7"
        assert sent[0]["playbook_step_id"] == "step-2"

    async def test_non_secret_instance_settings_travel_with_the_credentials(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A vendor that needs a base URL is unusable without one, and a URL
        is configuration rather than a secret."""
        sent = _wire(
            monkeypatch,
            implementers=["crowdstrike"],
            connectors=[_Connector("crowdstrike", config={"base_url": "https://edr.internal", "unrelated": "x"})],
        )
        await _run()
        assert sent[0]["auth_config"]["base_url"] == "https://edr.internal"
        assert "unrelated" not in sent[0]["auth_config"]

    async def test_the_report_only_carries_fields_that_have_a_value(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An empty string in a JSON report reads as an answer."""
        _wire(monkeypatch, implementers=["crowdstrike"], response={"result": {"status": "pending_approval", "details": {}}})
        body = (await _run()).as_dict()
        assert "verification" not in body
        assert body["executed"] is False


class TestCapabilityGuard:
    @pytest.mark.parametrize("value", ["../../admin", "isolate_host/../x", "with space", "", "UPPER"])
    async def test_a_capability_that_could_steer_the_upstream_request_is_refused(self, value: str) -> None:
        """This path carries the service token, so the segment is checked
        rather than trusted — the same guard the browser-facing proxy uses."""
        with pytest.raises(actions_client.ActionsServiceError):
            await actions_client.vendors_for_capability(value)

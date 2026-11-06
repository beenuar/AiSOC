"""The deployment config published three fields it had no business publishing.

``endpoints/deployment.py`` carried a block commented ``# ── Mock state ──``
holding ``update_channel=UpdateChannel.stable``, ``auto_update=True`` and
``telemetry_enabled=True``. None had a reader anywhere in the tree and the
console never calls ``/api/v1/deployment/*`` — ``deploymentApi`` in
``apps/web/src/lib/api.ts`` points at ``/airgap/*`` and ``/llm/*``.

``telemetry_enabled: true`` is the one that mattered, because it reached
``docs/openapi.yaml``: an API consumer reading the published spec concluded
telemetry was on by default. ``docs/trust/data-flows.md`` says there is no
phone-home and three CI gates hold it there —
``scripts/check_default_egress.py``, ``tests/test_no_default_egress.py`` and
``.github/workflows/container-egress.yml``. The spec was contradicting the
trust document about the product's most load-bearing privacy claim.

What is asserted
----------------
* the self-update fields are gone, because AiSOC does not update itself and
  a settable field is a promise that something reads it;
* ``telemetry_enabled`` still exists and reports ``false`` — the real state,
  which is more use to a consumer than the field's absence would be;
* it is no longer writable, because accepting ``true`` would make the API
  assert something no code in this repository can do.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints import deployment as deployment_module
from app.api.v1.endpoints.deployment import DeploymentConfig, DeploymentConfigUpdate


class TestSelfUpdateFieldsAreGone:
    @pytest.mark.parametrize("field", ["update_channel", "auto_update"])
    def test_absent_from_the_response_model(self, field: str) -> None:
        assert field not in DeploymentConfig.model_fields

    @pytest.mark.parametrize("field", ["update_channel", "auto_update"])
    def test_absent_from_the_update_model(self, field: str) -> None:
        assert field not in DeploymentConfigUpdate.model_fields

    def test_the_update_channel_enum_is_gone(self) -> None:
        assert not hasattr(deployment_module, "UpdateChannel")


class TestTelemetryReportsTheTruth:
    def test_still_reported_so_a_consumer_can_ask(self) -> None:
        """Removing it would leave the question unanswerable.

        A consumer who wants to know whether this deployment phones home is
        better served by a field that says ``false`` than by no field at all.
        """
        assert "telemetry_enabled" in DeploymentConfig.model_fields

    def test_reports_false_because_there_is_no_phone_home(self) -> None:
        assert deployment_module._config.telemetry_enabled is False

    def test_cannot_be_turned_on(self) -> None:
        """A writable flag is a claim that something would act on it."""
        assert "telemetry_enabled" not in DeploymentConfigUpdate.model_fields

    def test_the_published_spec_no_longer_defaults_it_true(self) -> None:
        """The spec is where the false claim was actually read."""
        schema = DeploymentConfig.model_json_schema()
        assert schema["properties"]["telemetry_enabled"].get("default") is not True


class TestNoReachableWriterCanReintroduceIt:
    def test_the_update_model_accepts_only_what_is_real(self) -> None:
        """Whatever remains writable must correspond to something that acts.

        ``mode`` and ``llm_provider`` are read by ``get_airgap_status``;
        nothing else is read anywhere.
        """
        assert set(DeploymentConfigUpdate.model_fields) == {"mode", "llm_provider"}

    def test_unknown_fields_are_rejected_rather_than_silently_dropped(self) -> None:
        """A removed field must fail loudly for a caller still sending it.

        Pydantic ignores unknown keys by default, so a client still sending
        ``auto_update: true`` would get a 200 and believe it had configured
        something. That is the same class of defect as the field itself.
        """
        with pytest.raises(ValueError):
            DeploymentConfigUpdate(auto_update=True)

"""An unsigned Slack request is not an approval.

GHSA-vf98-8367-45mp, F02. `SLACK_SIGNING_SECRET` defaults to `""`, and
`signature_verification_enabled` is `bool(...)` of it -- so an empty value
turned Bolt's request verification **off**, and the shipped service accepted a
`block_actions` approval payload carrying no `X-Slack-Signature` and forwarded
the decision to the actions service.

The only thing standing against that was a `logger.warning` at startup saying
the configuration was "acceptable for local dev only". A warning is a note
about a deployment, not a thing that stops one -- and a bot that starts and
silently accepts forged approvals looks healthier than one that refuses, which
is exactly what makes it worse.

Fails closed at construction, matching `require_service_auth` in
`services/actions`, which refuses outright when its token is unset.
"""

from __future__ import annotations

import pytest
from app.core.config import SlackBotSettings


def _settings(secret: str = "") -> SlackBotSettings:
    return SlackBotSettings(SLACK_SIGNING_SECRET=secret, AISOC_API_BASE_URL="http://api:8000")


class TestAnUnsignedProductionDeploymentIsRefused:
    def test_an_empty_signing_secret_in_production_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENVIRONMENT", "production")
        with pytest.raises(RuntimeError) as exc:
            _settings().require_signature_verification()
        assert "SLACK_SIGNING_SECRET" in str(exc.value)
        # The refusal has to name the next action. An operator who gets a bare
        # "refused" has several controls to choose between.
        assert "Signing Secret" in str(exc.value)

    def test_an_unset_environment_is_treated_as_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unconfigured must not mean relaxed.

        `ENVIRONMENT` defaulting to `development` is how a stock install once
        resolved an uncredentialed caller to a demo admin. The default here
        goes the other way.
        """
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        with pytest.raises(RuntimeError):
            _settings().require_signature_verification()


class TestTheControlNarrowsRatherThanCloses:
    """Positive controls.

    A check that refused every configuration would satisfy both tests above
    and make the Slack bot unstartable everywhere -- the fail-closed shape
    this repository has shipped before, where a control withheld every grant
    on every deployment and passed its negative test perfectly.
    """

    def test_a_configured_secret_is_accepted_in_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENVIRONMENT", "production")
        _settings("a-real-signing-secret").require_signature_verification()
        assert _settings("a-real-signing-secret").signature_verification_enabled is True

    @pytest.mark.parametrize("env", ["development", "dev", "test", "testing", "local"])
    def test_a_local_run_may_still_go_without_one(self, monkeypatch: pytest.MonkeyPatch, env: str) -> None:
        """The suite itself runs without a signing secret.

        If this raised, the refusal above would be a reason to set
        `ENVIRONMENT=development` in production and lose the control
        everywhere -- which is how a gate gets switched off.
        """
        monkeypatch.setenv("ENVIRONMENT", env)
        _settings().require_signature_verification()

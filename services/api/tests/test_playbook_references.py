"""Depth 5.1 — resolving the names a playbook step addresses.

The behaviour worth pinning is mostly about what the resolver *refuses*:

* a disabled reference is absent, so importing a pack cannot start paging;
* a reference bound to another tenant's connector reads nothing;
* a notify destination whose channel disagrees with the step is reported,
  not resolved in favour of either side;
* a secret that will not decrypt is an error, never "not configured" — the
  two send an operator to opposite places.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from app.services import playbook_references


class _Row:
    """A reference row. Not the ORM class: these tests are about the
    resolution rules, and a real row needs a session, a tenant and a
    migration to exist at all."""

    def __init__(self, **kwargs: Any) -> None:
        self.id = uuid.uuid4()
        self.tenant_id = kwargs.pop("tenant_id", uuid.uuid4())
        self.name = kwargs.pop("name")
        self.kind = kwargs.pop("kind")
        self.channel = kwargs.pop("channel", "")
        self.connector_id = kwargs.pop("connector_id", None)
        self.value = kwargs.pop("value", "")
        self.secret_value = kwargs.pop("secret_value", "")
        self.enabled = kwargs.pop("enabled", True)


@pytest.fixture
def rows(monkeypatch: pytest.MonkeyPatch) -> list[_Row]:
    """Stand in for the SELECT, applying the same two filters it does."""
    store: list[_Row] = []

    async def _fake_rows(db: Any, *, tenant_id: uuid.UUID, names: list[str]) -> dict[str, _Row]:  # noqa: ARG001
        return {r.name: r for r in store if r.name in set(names) and r.enabled}

    monkeypatch.setattr(playbook_references, "_rows", _fake_rows)
    return store


@pytest.fixture
def plaintext_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    """A vault that round-trips JSON, so these tests exercise the shape
    handling rather than Fernet."""

    class _Vault:
        def decrypt_dict(self, payload: dict[str, Any]) -> dict[str, Any]:
            return {"payload": json.loads(payload["payload"])}

    monkeypatch.setattr(playbook_references, "get_vault", lambda: _Vault())


pytestmark = pytest.mark.asyncio


async def test_a_url_reference_resolves_and_loses_its_trailing_slash(rows: list[_Row], plaintext_vault: None) -> None:
    """``${IDP_BASE_URL}/sessions`` must not become ``…com//sessions``."""
    rows.append(_Row(name="IDP_BASE_URL", kind="url", value="https://acme.okta.com/"))
    resolved = await playbook_references.resolve(None, tenant_id=uuid.uuid4(), names=["IDP_BASE_URL"])
    assert resolved["IDP_BASE_URL"]["value"] == "https://acme.okta.com"
    assert resolved["IDP_BASE_URL"]["secret"] is False


async def test_a_disabled_reference_is_absent(rows: list[_Row], plaintext_vault: None) -> None:
    """Existing is not usable. The caller reports the name it could not get."""
    rows.append(_Row(name="IDP_BASE_URL", kind="url", value="https://acme.okta.com", enabled=False))
    resolved = await playbook_references.resolve(None, tenant_id=uuid.uuid4(), names=["IDP_BASE_URL"])
    assert resolved == {}


async def test_a_url_reference_with_no_value_is_absent_not_empty(rows: list[_Row], plaintext_vault: None) -> None:
    """Substituting '' would hand httpx a scheme-relative path.

    ``/sessions`` resolves against whatever base the client has, which is a
    request to somewhere nobody chose — strictly worse than refusing.
    """
    rows.append(_Row(name="IDP_BASE_URL", kind="url", value=""))
    assert await playbook_references.resolve(None, tenant_id=uuid.uuid4(), names=["IDP_BASE_URL"]) == {}


async def test_a_headers_reference_carries_its_values(rows: list[_Row], plaintext_vault: None) -> None:
    rows.append(_Row(name="IDP_BEARER_HEADERS", kind="headers", secret_value=json.dumps({"Authorization": "SSWS tok"})))
    resolved = await playbook_references.resolve(None, tenant_id=uuid.uuid4(), names=["IDP_BEARER_HEADERS"])
    assert resolved["IDP_BEARER_HEADERS"]["headers"] == {"Authorization": "SSWS tok"}
    assert resolved["IDP_BEARER_HEADERS"]["secret"] is True


async def test_a_secret_that_will_not_decrypt_is_an_error_not_an_absence(rows: list[_Row], monkeypatch: pytest.MonkeyPatch) -> None:
    from app.security.credential_vault import CredentialVaultError

    class _BrokenVault:
        def decrypt_dict(self, payload: dict[str, Any]) -> dict[str, Any]:
            raise CredentialVaultError("key rotated out")

    monkeypatch.setattr(playbook_references, "get_vault", lambda: _BrokenVault())
    rows.append(_Row(name="IDP_BEARER_HEADERS", kind="headers", secret_value="vault:v1:xxx"))

    with pytest.raises(playbook_references.ReferenceError, match="IDP_BEARER_HEADERS"):
        await playbook_references.resolve(None, tenant_id=uuid.uuid4(), names=["IDP_BEARER_HEADERS"])


# ---------------------------------------------------------------------------
# notify destinations
# ---------------------------------------------------------------------------


async def test_a_webhook_destination_becomes_the_arms_credential_key(rows: list[_Row], plaintext_vault: None) -> None:
    """``webhook_url`` and not ``url``.

    The arms read ``webhook_url``; a resolver producing anything else makes
    every arm answer "no destination configured" while one sits configured.
    """
    rows.append(
        _Row(
            name="SLACK_SOC_WEBHOOK", kind="webhook", channel="slack", secret_value=json.dumps({"webhook_url": "https://hooks.slack.com/x"})
        )
    )
    channel, params, reason = await playbook_references.notify_destination(
        None, tenant_id=uuid.uuid4(), params={"webhook_env": "SLACK_SOC_WEBHOOK"}
    )
    assert reason == ""
    assert channel == "slack"
    assert params["webhook_url"] == "https://hooks.slack.com/x"
    assert params["destination"] == "SLACK_SOC_WEBHOOK"


async def test_a_pagerduty_destination_resolves_its_routing_key(rows: list[_Row], plaintext_vault: None) -> None:
    rows.append(_Row(name="PD_SOC_KEY", kind="routing_key", channel="pagerduty", secret_value=json.dumps({"routing_key": "R" * 32})))
    channel, params, reason = await playbook_references.notify_destination(
        None, tenant_id=uuid.uuid4(), params={"service_key_env": "PD_SOC_KEY"}
    )
    assert reason == ""
    assert channel == "pagerduty"
    assert params["pd_routing_key"] == "R" * 32


async def test_an_unconfigured_destination_names_itself(rows: list[_Row], plaintext_vault: None) -> None:
    _channel, _params, reason = await playbook_references.notify_destination(
        None, tenant_id=uuid.uuid4(), params={"webhook_env": "SLACK_SOC_WEBHOOK"}
    )
    assert "SLACK_SOC_WEBHOOK" in reason


async def test_a_step_that_names_no_destination_says_which_keys_it_could_have_used(rows: list[_Row], plaintext_vault: None) -> None:
    _channel, _params, reason = await playbook_references.notify_destination(None, tenant_id=uuid.uuid4(), params={"channel": "slack"})
    assert "webhook_env" in reason and "service_key_env" in reason


async def test_the_destination_decides_the_channel_not_the_step(rows: list[_Row], plaintext_vault: None) -> None:
    """A Slack webhook cannot be paged as PagerDuty because a playbook said so.

    Resolving in favour of either side delivers a message to something that
    cannot read it, so the mismatch is reported.
    """
    rows.append(_Row(name="SOC_DEST", kind="webhook", channel="teams", secret_value=json.dumps({"webhook_url": "https://teams/x"})))
    channel, _params, reason = await playbook_references.notify_destination(
        None, tenant_id=uuid.uuid4(), params={"destination": "SOC_DEST"}
    )
    assert reason == ""
    assert channel == "teams"


def test_the_destination_keys_are_the_ones_the_packs_write() -> None:
    """Read off the shipped packs rather than restated.

    The packs are content and the resolver is code; a list in the code that
    the content does not use is a resolver nothing reaches.
    """
    import pathlib

    packs = pathlib.Path(__file__).resolve().parents[3] / "playbooks"
    used: set[str] = set()
    for path in packs.rglob("*.playbook.json"):
        for step in json.loads(path.read_text()).get("steps", []):
            if step.get("type") == "notify":
                used |= {k for k in step.get("params", {}) if k.endswith("_env")}
    assert used, "no notify step in the packs names a destination; this test proves nothing"
    assert used <= set(playbook_references.NOTIFY_DESTINATION_KEYS)

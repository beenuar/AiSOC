"""The interactive approval prompt carries the operator's product name.

Fix-pass 4.3. The ChatOps bots were the one branded surface with no read
path to branding at all: `services/api` owns the schema and the write
routes, and `services/actions` had no way to ask it anything, so the Slack
`text`, the Teams `summary` and `title`, and the default question inside
both all said "AiSOC" on every deployment regardless of what the operator
had configured.

Four prompts in one card is the reason this is worth a test rather than a
glance. The card's title and the sentence inside it are built at different
points in the executor -- the question is assembled near the top from
`request.parameters`, the title at delivery -- so branding one and not the
other produces a card that is half right, which reads as a bug in the
product rather than a missing setting.

The lookup itself is deliberately total: every "we could not tell" case
(no database, no tenant, no organisation, no row, an empty column, a failed
read) returns the platform default, because each means the same thing to
the person reading the message. These tests pin that, since a branding
lookup that raised would take down the approval prompt it was decorating,
and an approval nobody sees is worse than one under the wrong name.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.services.branding_lookup import DEFAULT_PRODUCT_NAME, product_name_for_tenant
from app.services.chatops_prompt import ChatOpsButton, send_slack_prompt, send_teams_prompt


class _Response:
    status_code = 200
    text = "ok"

    @staticmethod
    def json() -> dict[str, Any]:
        return {"ok": True}


class _Capture:
    """Stands in for httpx.AsyncClient and keeps the payload posted."""

    def __init__(self) -> None:
        self.payload: dict[str, Any] = {}

    async def __aenter__(self) -> _Capture:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def post(self, _url: str, **kwargs: Any) -> _Response:
        self.payload = kwargs.get("json") or {}
        return _Response()


@pytest.fixture
def capture(monkeypatch: pytest.MonkeyPatch) -> _Capture:
    """Captures the posted payload instead of reaching a vendor.

    A real Fernet key is set because the prompt runs every credential
    through the vault before use. The vault returns a plain value
    unchanged, but it refuses to construct without a key at all -- so
    without this the test would fail inside the credential path and never
    reach the branding assertion it exists to make.
    """
    from cryptography.fernet import Fernet

    monkeypatch.setenv("AISOC_CREDENTIAL_KEY", Fernet.generate_key().decode())

    # Both targets are named as strings rather than imported. The module is
    # already imported at the top of this file with a from-import, and
    # importing it a second time as `import app.services.chatops_prompt as
    # mod` is two import styles for one module -- which CodeQL reports as
    # py/import-and-import-from, and which leaves a reader unsure which
    # binding a later edit should patch.
    #
    # `_vault_singleton` is a module-level singleton, not an lru_cache, so
    # it is reset through monkeypatch: the key set above is then the one the
    # vault is built from, and the next test in the session does not inherit
    # this one.
    monkeypatch.setattr("app.security.credential_vault._vault_singleton", None)

    cap = _Capture()
    monkeypatch.setattr("app.services.chatops_prompt.httpx.AsyncClient", lambda *a, **k: cap)
    return cap


def _buttons() -> list[ChatOpsButton]:
    return [ChatOpsButton(label="Yes", url="https://example.invalid/y", style="primary")]


@pytest.mark.asyncio
async def test_slack_text_carries_the_tenants_product_name(capture: _Capture) -> None:
    await send_slack_prompt(
        webhook_url="https://example.invalid/hook",
        question="Did you sign in from Berlin?",
        context="Incident 1",
        buttons=_buttons(),
        product_name="Northwind Defend",
    )
    assert capture.payload["text"].startswith("Northwind Defend verification:")
    assert "AiSOC" not in capture.payload["text"]


@pytest.mark.asyncio
async def test_teams_summary_and_title_both_carry_it(capture: _Capture) -> None:
    """Both, not either.

    The MessageCard shows `title` in the card and `summary` in the
    notification list, so branding one leaves the other visible and wrong
    in whichever surface the analyst happens to look at first.
    """
    await send_teams_prompt(
        webhook_url="https://example.invalid/hook",
        question="Did you sign in from Berlin?",
        context="Incident 1",
        buttons=_buttons(),
        product_name="Northwind Defend",
    )
    assert capture.payload["summary"].startswith("Northwind Defend verification:")
    assert capture.payload["title"] == "Northwind Defend verification"
    assert "AiSOC" not in capture.payload["summary"]
    assert "AiSOC" not in capture.payload["title"]


@pytest.mark.asyncio
async def test_an_unbranded_deployment_still_reads_correctly(capture: _Capture) -> None:
    """The default is a real product name, not an empty string.

    Callers omit `product_name` only when nobody has configured one, and a
    prompt reading " verification:" would look broken rather than
    unbranded.
    """
    await send_slack_prompt(
        webhook_url="https://example.invalid/hook",
        question="Did you sign in from Berlin?",
        context="Incident 1",
        buttons=_buttons(),
    )
    assert capture.payload["text"] == f"{DEFAULT_PRODUCT_NAME} verification: Did you sign in from Berlin?"


@pytest.mark.asyncio
async def test_no_tenant_resolves_to_the_default() -> None:
    assert await product_name_for_tenant(None) == DEFAULT_PRODUCT_NAME


@pytest.mark.asyncio
async def test_no_database_resolves_to_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_DSN", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert await product_name_for_tenant(uuid.uuid4()) == DEFAULT_PRODUCT_NAME


@pytest.mark.asyncio
async def test_a_failed_read_resolves_to_the_default_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The negative control for the module's central promise.

    Pointed at a DSN nothing is listening on, the lookup must still answer.
    If this ever raises, the approval prompt it decorates stops being
    delivered -- so the failure mode would not be an unbranded card, it
    would be an analyst who is never asked.
    """
    monkeypatch.setenv("DATABASE_DSN", "postgresql://nobody@127.0.0.1:1/none")
    assert await product_name_for_tenant(uuid.uuid4()) == DEFAULT_PRODUCT_NAME

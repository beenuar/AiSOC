"""GHSA-g4h7-p63q-r8r4: the actions service was unauthenticated by default.

`require_service_auth` returned early — performing no authentication at all —
when `AISOC_ACTIONS_SERVICE_TOKEN` was empty and `AISOC_DEV_MODE` was set. Read
alone that is a developer convenience. It was not, because of three facts that
only matter together:

  * `docker-compose.yml` defaults `AISOC_DEV_MODE` to `1`,
  * `scripts/ensure_env.py` never generated `AISOC_ACTIONS_SERVICE_TOKEN`,
  * `.env.example` never mentioned it.

So the exemption was not the exceptional path, it was the only path a stock
install ever took: `isolate_host`, `disable_user`, `block_ip`, `kill_process`
and `run_script` were dispatchable by anything that could reach the port,
including any other container on the compose network.

The fix is in two halves and both are tested here, because either alone leaves
the product broken or insecure: the guard no longer exempts itself, and the
token is generated so the documented path still works.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from app.security.authz import require_service_auth
from fastapi import HTTPException

REPO = pathlib.Path(__file__).resolve().parents[3]


class TestTheGuardNoLongerExemptsItself:
    @pytest.mark.asyncio
    async def test_an_unset_token_refuses_even_in_dev_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The exact configuration of a stock `make up` before this fix."""
        from app.core import config

        settings = config.get_settings()
        monkeypatch.setattr(settings, "AISOC_ACTIONS_SERVICE_TOKEN", "", raising=False)
        monkeypatch.setattr(settings, "AISOC_DEV_MODE", True, raising=False)

        with pytest.raises(HTTPException) as exc:
            await require_service_auth(authorization=None)
        assert exc.value.status_code == 503

    @pytest.mark.asyncio
    async def test_the_refusal_says_how_to_fix_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 503 an operator cannot act on turns a fix into an outage."""
        from app.core import config

        settings = config.get_settings()
        monkeypatch.setattr(settings, "AISOC_ACTIONS_SERVICE_TOKEN", "", raising=False)
        monkeypatch.setattr(settings, "AISOC_DEV_MODE", True, raising=False)

        with pytest.raises(HTTPException) as exc:
            await require_service_auth(authorization=None)
        detail = str(exc.value.detail)
        assert "AISOC_ACTIONS_SERVICE_TOKEN" in detail
        assert "make env" in detail

    @pytest.mark.asyncio
    async def test_a_configured_token_still_authenticates_normally(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core import config

        settings = config.get_settings()
        monkeypatch.setattr(settings, "AISOC_ACTIONS_SERVICE_TOKEN", "a-real-token", raising=False)
        monkeypatch.setattr(settings, "AISOC_DEV_MODE", True, raising=False)

        # Returns None on success; asserting "did not raise" is the contract.
        await require_service_auth(authorization="Bearer a-real-token")

        with pytest.raises(HTTPException) as exc:
            await require_service_auth(authorization="Bearer wrong")
        assert exc.value.status_code == 401


class TestTheTokenIsGeneratedSoTheDocumentedPathStillWorks:
    """Failing closed is only safe if `make up` supplies the token.

    `ensure_env.py` backfills every key in GENERATED into an existing `.env`,
    not just a new one, so this also repairs installs created before the fix.
    """

    def test_ensure_env_generates_the_actions_token(self) -> None:
        source = (REPO / "scripts" / "ensure_env.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        generated: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == "GENERATED":
                value = node.value
                if isinstance(value, ast.Dict):
                    generated = [k.value for k in value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        assert generated, "could not read the GENERATED table out of ensure_env.py"
        assert "AISOC_ACTIONS_SERVICE_TOKEN" in generated, (
            "ensure_env.py does not generate AISOC_ACTIONS_SERVICE_TOKEN, so a stock install has "
            "no token and the guard above will 503 on every response action"
        )

    def test_the_variable_is_documented_in_env_example(self) -> None:
        text = (REPO / ".env.example").read_text(encoding="utf-8")
        assert "AISOC_ACTIONS_SERVICE_TOKEN" in text, "an operator reading the documented configuration has no instruction to set it"

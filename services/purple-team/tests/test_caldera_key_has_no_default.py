"""The Caldera client refuses to start without an explicit key.

`caldera_api_key` defaulted to the literal `ADMIN123`, which is Caldera's own
published first-run credential. A deployment that never configured Caldera
still built a client holding it, and pointed that client at whatever
`caldera_url` resolved to — so the failure mode was not "purple-team does not
work", it was "purple-team authenticates to a Caldera instance with the
default password", which succeeds against any Caldera nobody rotated.

The honest default is no default. An unset key means the integration is not
configured, and a route that needs it says so rather than trying a guess.
"""

from __future__ import annotations

import pathlib

import pytest

SERVICE_ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_the_published_literal_is_gone() -> None:
    config = (SERVICE_ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
    code = [line for line in config.splitlines() if not line.lstrip().startswith("#")]
    assert "ADMIN123" not in "\n".join(code), (
        "caldera_api_key still defaults to Caldera's published first-run credential, so an "
        "unconfigured deployment authenticates with it rather than refusing"
    )


def test_the_key_defaults_to_empty() -> None:
    from app.core.config import Settings

    settings = Settings()
    assert settings.caldera_api_key == "", (
        f"expected no default, got {settings.caldera_api_key!r}. A non-empty default is a credential somebody did not choose"
    )


def test_building_a_client_without_a_key_refuses() -> None:
    """And refuses with a message naming the variable to set.

    Returning a client that cannot authenticate would push the failure to
    the first request, where it reads as a Caldera outage rather than as a
    configuration gap.
    """
    from app.api.routes import _caldera
    from app.core.config import settings

    original = settings.caldera_api_key
    settings.caldera_api_key = ""
    try:
        with pytest.raises(Exception) as exc:  # noqa: PT011 - the type is the service's own
            _caldera()
        message = str(exc.value)
        assert "CALDERA_API_KEY" in message, f"the refusal must name the variable; got {message!r}"
    finally:
        settings.caldera_api_key = original


def test_a_configured_key_still_builds_a_client() -> None:
    """The other direction, so this cannot pass on a build with no client."""
    from app.api.routes import _caldera
    from app.core.config import settings

    original = settings.caldera_api_key
    settings.caldera_api_key = "a-real-key"
    try:
        assert _caldera() is not None
    finally:
        settings.caldera_api_key = original

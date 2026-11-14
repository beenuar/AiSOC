"""Regression tests for the threat-actor attribution client URL.

The investigation agent calls the ``threatintel`` service's
``POST /api/v1/actors/attribute`` endpoint. The ``threatintel`` service
binds port **8005** everywhere it is actually run — ``Dockerfile``
(``EXPOSE 8005`` / ``--port 8005``), ``docker-compose.yml``
(``127.0.0.1:8005:8005``), and the canonical service/port table in
``README.md``. An earlier default of ``http://threatintel:8083`` meant the
agent → attribution call could never connect: it has been pointed at a
port nothing listens on since the feature shipped.

These tests lock the contract in two places:

* the default base URL resolves to ``:8005`` (the regression guard for the
  ``8083`` typo), and an operator override via ``AISOC_THREATINTEL_URL`` is
  honoured with the trailing slash stripped;
* ``_call_attribution_service`` posts to ``{base}/api/v1/actors/attribute``
  so neither the port nor the path can silently drift again.

We mock the network with :mod:`respx` so the suite stays offline-safe,
mirroring ``test_fusion_client.py`` which guards the analogous fusion
``/process`` path/port mismatch.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import httpx
import pytest
import respx

# Match the path-mutation pattern used by the rest of services/agents/tests/.
_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))


def _reload_agent(monkeypatch: pytest.MonkeyPatch, url: str | None):
    """Reload ``investigation_agent`` under a controlled env.

    The module reads ``AISOC_THREATINTEL_URL`` at import time, so the env
    must be set/cleared before the reload. We use ``importlib.import_module``
    (rather than ``import app.agents.investigation_agent as ...``) so
    CodeQL's py/import-and-import-from rule doesn't flag this file.
    """
    if url is None:
        monkeypatch.delenv("AISOC_THREATINTEL_URL", raising=False)
    else:
        monkeypatch.setenv("AISOC_THREATINTEL_URL", url)
    module = importlib.import_module("app.agents.investigation_agent")
    return importlib.reload(module)


def test_default_base_url_uses_canonical_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no override, the agent targets ``threatintel:8005`` — never ``:8083``.

    8005 is where the threatintel service actually listens (Dockerfile,
    docker-compose, README service table). A regression to ``:8083`` would
    silently break threat-actor attribution end to end.
    """
    module = _reload_agent(monkeypatch, None)
    assert module.THREAT_INTEL_SERVICE_URL == "http://threatintel:8005"
    assert ":8083" not in module.THREAT_INTEL_SERVICE_URL


def test_env_override_is_honoured_and_trailing_slash_stripped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``AISOC_THREATINTEL_URL`` wins for non-Compose deployments."""
    module = _reload_agent(monkeypatch, "http://ti.internal:9000/")
    assert module.THREAT_INTEL_SERVICE_URL == "http://ti.internal:9000"


async def test_call_attribution_service_posts_to_correct_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client must POST to ``{base}/api/v1/actors/attribute``.

    Guards both the port and the path together, so neither can drift back
    out of sync with where the threatintel router is mounted.
    """
    base = "http://threatintel-test:8005"
    module = _reload_agent(monkeypatch, base)

    attribution = {
        "actor_id": "APT28",
        "actor_name": "APT28 (Fancy Bear)",
        "confidence_score": 0.5,
        "reasoning": ["Matched 2/3 TTPs"],
    }

    async with respx.mock(base_url=base, assert_all_called=True) as router:
        route = router.post("/api/v1/actors/attribute").mock(
            return_value=httpx.Response(200, json=attribution),
        )

        result = await module._call_attribution_service(
            iocs=[{"value": "evil.exe", "type": "filename"}],
            mitre_techniques=["T1566", "T1059"],
            case_metadata={"targets": ["government"]},
        )

    assert result == attribution
    assert route.called
    assert str(route.calls.last.request.url) == f"{base}/api/v1/actors/attribute"

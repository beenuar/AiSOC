"""The threat-actor attribution token must be generated AND delivered.

What happened
-------------
v23.5.0 made the actor-attribution gate fail closed on
``AISOC_THREATINTEL_SERVICE_TOKEN`` (#1904) and the release notes said the
sixteenth secret was generated and forwarded to both ends. On the shipped
tag none of that was true: ``scripts/ensure_env.py`` did not generate the
token, ``.env.example`` carried it commented out, and ``docker-compose.yml``
handed it to the *api* service only — not to ``threatintel``, which enforces
it, and not to ``agents``, whose investigation agent sends it. A fresh
``make up`` therefore served 503 for every ``/api/v1/actors/*`` call with
every secret "correctly" generated, and no unit test could see it because
each service's own gate behaved exactly as designed.

What is asserted
----------------
Tree-derived in both directions, so neither half can drift:

1. ``ensure_env.GENERATED`` contains the token — a fresh install mints it.
2. Every compose service whose source reads the variable receives it in its
   compose ``environment`` block, discovered by scanning ``services/*/app``
   for the ``os.getenv``/Settings read rather than by naming services here.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "AISOC_THREATINTEL_SERVICE_TOKEN"


def _load_ensure_env():
    spec = importlib.util.spec_from_file_location("ensure_env", ROOT / "scripts" / "ensure_env.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["ensure_env"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_generator_mints_the_token() -> None:
    mod = _load_ensure_env()
    generated = getattr(mod, "GENERATED", None)
    assert generated is not None, "ensure_env.py no longer exposes GENERATED"
    assert TOKEN in generated, (
        f"{TOKEN} is not in ensure_env.GENERATED — a fresh install ships a fail-closed gate with no key, so /api/v1/actors/* answers 503."
    )


def _services_reading_token() -> set[str]:
    readers: set[str] = set()
    for src in (ROOT / "services").glob("*/app/**/*.py"):
        try:
            text = src.read_text(encoding="utf-8")
        except OSError:
            continue
        if TOKEN in text:
            readers.add(src.relative_to(ROOT / "services").parts[0])
    return readers


def test_compose_delivers_the_token_to_every_reader() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    services = compose.get("services", {})

    # Map source directories to compose service names where they differ.
    alias = {"api": "api", "threatintel": "threatintel", "agents": "agents"}

    readers = _services_reading_token()
    assert readers, "no service reads the token any more — update this test"

    missing: list[str] = []
    for reader in sorted(readers):
        svc_name = alias.get(reader, reader)
        svc = services.get(svc_name)
        if svc is None:
            # A reader with no compose service (e.g. a library dir) is out of
            # scope for compose delivery.
            continue
        env = svc.get("environment") or {}
        keys = set(env) if isinstance(env, dict) else {e.split("=", 1)[0] for e in env}
        if TOKEN not in keys:
            missing.append(svc_name)

    assert not missing, (
        f"compose does not deliver {TOKEN} to: {missing}. The gate fails "
        "closed, so a reader without the generated value refuses or is "
        "refused — the v23.5.0 defect, shipped once already."
    )


def test_example_env_names_the_token() -> None:
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(rf"^#?\s*{TOKEN}=", example, re.M), (
        f".env.example no longer mentions {TOKEN}; ensure_env appends it, "
        "but the example is the documented inventory of what a deployment "
        "carries."
    )

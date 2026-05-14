"""Development authentication bypass.

When ``ENV`` names a dev-class environment and a request arrives without
a bearer token, we resolve a deterministic demo user. This makes the web
console usable without seeding users + logging in for every contributor
running the stack locally.

The demo IDs are also used by ``services/api/app/scripts/seed_demo.py``
so the data the UI sees actually belongs to the user that the API hands
back.

Production safety: this module reads ``ENV`` from the live process
environment at call time (not from the cached :class:`Settings`
singleton) so a test that does ``monkeypatch.setenv("ENV", "production")``
mid-suite immediately stops handing back the demo user. The canonical
allow-list lives in ``app.core.config.AUTH_BYPASS_ENVIRONMENTS`` and
deliberately excludes ``"test"`` — test suites must seed an
``Authorization`` header rather than rely on the bypass, or genuine auth
regressions get masked.
"""

from __future__ import annotations

import uuid

from app.core.config import current_env_from_os, is_auth_bypass_env

# Deterministic demo IDs — kept in sync with seed_demo.py
DEMO_TENANT_ID: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-000000000001")
DEMO_USER_ID: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-000000000002")
# Use a real TLD (not `.local`, which is reserved for mDNS and rejected by
# pydantic ``EmailStr``). Deterministic, public-demo-only credentials.
DEMO_USER_EMAIL: str = "demo@aisoc.dev"
DEMO_USER_PASSWORD: str = "aisoc-demo"
DEMO_USER_ROLE: str = "admin"


def is_dev_mode() -> bool:
    """True if the running environment permits the auth bypass.

    Reads the environment from ``os.environ`` at call time via
    :func:`app.core.config.current_env_from_os` so tests that
    ``monkeypatch.setenv(...)`` mid-suite see the change immediately.
    """
    return is_auth_bypass_env(current_env_from_os())

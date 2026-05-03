"""Development authentication bypass.

When ``ENV`` is ``development`` and a request arrives without a bearer token,
we resolve a deterministic demo user. This makes the web console usable
without seeding users + logging in for every contributor running the stack
locally.

The demo IDs are also used by ``services/api/app/scripts/seed_demo.py`` so the
data the UI sees actually belongs to the user that the API hands back.

Production safety: this module reads ``ENV`` at call time and refuses to
return a demo user unless ``ENV in {development, dev, local, demo}``.
"""
from __future__ import annotations

import os
import uuid

# Deterministic demo IDs — kept in sync with seed_demo.py
DEMO_TENANT_ID: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-000000000001")
DEMO_USER_ID: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-000000000002")
DEMO_USER_EMAIL: str = "demo@aisoc.local"
DEMO_USER_ROLE: str = "admin"

_DEV_ENVS = {"development", "dev", "local", "demo"}


def is_dev_mode() -> bool:
    """True if the running environment permits the auth bypass."""
    env = (os.getenv("ENV") or os.getenv("ENVIRONMENT") or "").strip().lower()
    return env in _DEV_ENVS

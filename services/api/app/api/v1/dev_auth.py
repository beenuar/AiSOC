"""Development authentication bypass.

When every condition in :func:`app.core.config.auth_bypass_refusal` is met
and a request arrives without a bearer token, we resolve a deterministic demo
user. This makes the web console usable without seeding users and logging in
for every contributor running the stack locally.

The demo IDs are also used by ``services/api/app/scripts/seed_demo.py``
so the data the UI sees actually belongs to the user that the API hands
back.

Three conditions, not one
-------------------------
Naming a dev-class environment used to be sufficient, and that is what made
this a vulnerability rather than a convenience: ``ENVIRONMENT`` defaulted to
``development`` in ``docker-compose.yml`` and in the ``.env`` the setup script
writes, so every stock ``docker compose up`` served an uncredentialed request
as an administrator. The bypass now additionally needs
``AISOC_DEV_AUTH_BYPASS`` set, which no compose file or template sets, and it
is refused outright when the deployment publishes a non-loopback address.

The demo tenant is not the operator's tenant
--------------------------------------------
``DEMO_TENANT_ID`` used to be ``…0001``, byte-identical to
``bootstrap_admin.DEFAULT_TENANT_ID``. So the anonymous principal was an
administrator *in the tenant the real operator had just been bootstrapped
into*, acting on their alerts and their connector credentials. The demo
identity now has a tenant of its own, and ``bootstrap_admin`` refuses to
create a real account in it.

This module reads the environment from ``os.environ`` at call time (not from
the cached :class:`Settings` singleton) so a test that does
``monkeypatch.setenv("ENV", "production")`` mid-suite immediately stops
handing back the demo user. The canonical allow-list lives in
``app.core.config.AUTH_BYPASS_ENVIRONMENTS`` and deliberately excludes
``"test"`` — test suites must seed an ``Authorization`` header rather than
rely on the bypass, or genuine auth regressions get masked.
"""

from __future__ import annotations

import logging
import uuid

from app.core.config import auth_bypass_refusal

logger = logging.getLogger(__name__)

# Deterministic demo IDs — kept in sync with seed_demo.py
#
# The demo tenant ends `…00de` and is the demo's alone. It used to be
# `…0001`, which is the canonical tenant that migration 001 seeds and that
# `bootstrap_admin` puts the real administrator into — so an anonymous caller
# was an administrator over the operator's own alerts and connector
# credentials. The canonical id stays where it is, because ten modules depend
# on it including the ingest-token minter and the agents ledger; it is the
# demo identity that moved.
DEMO_TENANT_ID: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-0000000000de")
DEMO_USER_ID: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-000000000002")
# Deterministic, demo-only credentials. ``example.com`` is reserved by
# RFC 2606 for exactly this: it is valid to ``pydantic.EmailStr`` (unlike
# `.local`, which is reserved for mDNS and rejected), can never be registered
# by anyone, and can never receive mail. A previous value used a real,
# operator-owned domain, which published a well-known login paired with a
# well-known password against a live domain and told self-hosters to type
# somebody else's hostname to sign in to their own install.
#
# Changing this is safe to re-run: ``seed_demo._ensure_user`` reconciles on
# ``DEMO_USER_ID`` (not on the address) and rewrites a stale email in place.
DEMO_USER_EMAIL: str = "demo@example.com"
DEMO_USER_PASSWORD: str = "aisoc-demo"
DEMO_USER_ROLE: str = "admin"


#: Refusals already logged, so a hot path does not emit one line per request.
#: Keyed on the reason rather than counted, so a deployment whose refusal
#: *changes* (someone sets the flag, but on a published address) says so.
_REFUSALS_LOGGED: set[str] = set()


def is_dev_mode() -> bool:
    """True if this process may serve an uncredentialed request as the demo user.

    Reads the environment from ``os.environ`` at call time via
    :func:`app.core.config.auth_bypass_refusal` so tests that
    ``monkeypatch.setenv(...)`` mid-suite see the change immediately.

    A refusal is logged once per distinct reason. Silence here was part of the
    original problem: an operator had no way to tell a deployment that had the
    bypass active from one that did not, because the only difference was a 401
    they never saw.
    """
    refusal = auth_bypass_refusal()
    if refusal is None:
        if "__active__" not in _REFUSALS_LOGGED:
            _REFUSALS_LOGGED.add("__active__")
            logger.warning(
                "ANONYMOUS ACCESS IS ENABLED. Requests with no bearer token resolve "
                "to the demo administrator in tenant %s. This is a development "
                "convenience and must not be used where anyone else can reach this "
                "host.",
                DEMO_TENANT_ID,
            )
        return True
    if refusal not in _REFUSALS_LOGGED:
        _REFUSALS_LOGGED.add(refusal)
        logger.info("anonymous access refused: %s", refusal)
    return False

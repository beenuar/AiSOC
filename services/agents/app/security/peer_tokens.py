"""The credential this service presents when it dials a peer service.

Why this module exists
----------------------
``AISOC_<SERVICE>_SERVICE_TOKEN`` means **"the token that service accepts"**.
Read that way the convention is consistent, and every call site that got it
wrong got it wrong the same way: it resolved its *own* name — the token the
agents service accepts — and presented that to somebody else.

``services/agents/app/context/bundle.py`` did exactly that on
``GET /api/v1/graph/incident-context``, and ``playbook/engine.py`` on
``POST /api/v1/approvals``. Measured from inside ``aisoc-agents``::

    AISOC_AGENTS_SERVICE_TOKEN -> 401
    AISOC_SERVICE_TOKEN        -> 401
    AISOC_API_SERVICE_TOKEN    -> 200

``scripts/ensure_env.py`` generates the names as independent secrets, so the
wrong one is a 401 on every deployment, not an occasional one. The resolution
order below is the one ``resolve_service_token()`` in
``services/api/app/api/v1/deps.py`` validates against, and
``scripts/check_peer_service_token_names.py`` fails the build if the two ever
disagree again.

Deliberately stdlib-only and importing nothing from ``app``: the API's own test
suite loads this file **by path** to assert the two sides agree, and both
services name their top-level package ``app``, so an importable-only contract
could not be measured from the other side at all.

One recorded deviation
----------------------
``services/api/app/api/v1/endpoints/alert_writeback.py::service_token_valid``
guards the ``X-AiSOC-Service-Token`` header against ``AISOC_AGENTS_SERVICE_TOKEN``
— the caller's name rather than its own. Nine agents call sites present that
header and work, so the name is load-bearing where it stands; it is named here
and in the gate so it reads as a known exception rather than as another instance
of the defect. Use :func:`self_token` for that header and :func:`token_for` for
everything else.
"""

from __future__ import annotations

import os

#: This service's own name in the ``AISOC_<SERVICE>_SERVICE_TOKEN`` convention.
SERVICE_NAME = "AGENTS"

#: The header a service caller declares the tenant it is acting for on.
#: ``X-Tenant-ID`` is a different header that the API's authentication never
#: reads — a service token that names no tenant resolves to an **empty** scope
#: and is refused, so getting this name wrong is a 403 even with the right
#: token.
SERVICE_TENANT_HEADER = "X-AiSOC-Tenant-ID"

#: Placeholders that must read as unset. Mirrors ``_INSECURE_SERVICE_TOKENS``
#: in the API's ``deps.py``: accepting a well-known literal would authenticate
#: anybody who read this repository, so presenting one is equally pointless.
_INSECURE = frozenset({"", "changeme", "change-me", "secret", "aisoc_dev_secret"})


class MissingPeerCredential(RuntimeError):
    """No credential is configured for the peer this call was about to dial.

    A distinct type rather than a bare ``RuntimeError`` so a caller can log it
    as the misconfiguration it is without having to guess from the message.
    A diagnostic that names the wrong subsystem sends an operator to debug
    something that is not broken, which is worse than a vague one.
    """


def _clean(value: str | None) -> str:
    token = (value or "").strip()
    return "" if token.lower() in _INSECURE else token


def token_for(peer: str) -> str:
    """The credential ``peer`` accepts, or ``""`` when none is configured.

    ``peer`` is the *callee* — ``"API"``, ``"ACTIONS"``, ``"CONNECTORS"`` — and
    never this service. Per-peer override first, then the shared platform
    token, which is the order the receiving side validates in.
    """
    return _clean(os.getenv(f"AISOC_{peer.upper()}_SERVICE_TOKEN")) or _clean(os.getenv("AISOC_SERVICE_TOKEN"))


def self_token() -> str:
    """The credential *this* service accepts.

    For the ``X-AiSOC-Service-Token`` routes described in the module docstring,
    and for nothing else. A call that presents this to a peer is the defect this
    module exists to stop.
    """
    return _clean(os.getenv(f"AISOC_{SERVICE_NAME}_SERVICE_TOKEN")) or _clean(os.getenv("AISOC_SERVICE_TOKEN"))


def api_token() -> str:
    """The credential the API service accepts."""
    return token_for("API")


def api_bearer_headers(tenant_id: str) -> dict[str, str]:
    """Both halves of an authenticated service call to the API.

    The token and the tenant header are returned together because they fail
    together: the right token with ``X-Tenant-ID`` is a 403, and the right
    header with this service's own token is a 401. Neither half is useful
    without the other, so neither is offered on its own.

    Raises :class:`MissingPeerCredential` when none is configured, rather
    than dialling anyway: a request with no token is a guaranteed 401 that
    reads as the API rejecting us when the truth is that nothing was ever set.
    """
    token = api_token()
    if not token:
        raise MissingPeerCredential(
            "no credential for the API service: set AISOC_API_SERVICE_TOKEN (the token the API accepts) or the shared AISOC_SERVICE_TOKEN"
        )
    return {"Authorization": f"Bearer {token}", SERVICE_TENANT_HEADER: tenant_id}

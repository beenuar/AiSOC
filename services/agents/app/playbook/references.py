"""Resolve the ``${NAME}`` integration references a playbook's ``http`` steps use.

Every ``http`` step in the shipped packs addresses its target the same way::

    "url": "${IDP_BASE_URL}/users/{{alert.user}}/sessions",
    "headers_env": "IDP_BEARER_HEADERS"

``${NAME}`` names a *configured integration*, never a host. That distinction
is the security property, not a formatting convention: a playbook author can
choose which of the tenant's integrations to call and which path under it,
and cannot choose the origin. Substituting a free-text URL would turn every
pack playbook into an outbound request primitive pointed wherever its author
liked.

Resolution happens in ``services/api`` because that service holds the
credential vault and the tenant session — the same division ``action_bridge``
works to. What comes back is a rendered reference, and for a ``*_HEADERS``
reference that includes the header values. They are held in memory for the
duration of one request, passed to httpx, and never written to the run
record: :func:`app.playbook.engine._handle_http` records header *names*.

The outbound call itself stays in this service so it passes
``app.playbook.ssrf_guard.validate_outbound_url`` — after substitution, which
is the only order that works. The stored value of a reference is tenant data,
so a value pointing at ``169.254.169.254`` has to be refused by the guard
rather than trusted because it came from a database.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from .errors import PermanentStepFailure

logger = logging.getLogger("aisoc.playbook.references")

_API_URL = os.getenv("API_SERVICE_URL", os.getenv("API_URL", "http://api:8000"))
_TIMEOUT_S = float(os.getenv("AISOC_PLAYBOOK_REFERENCE_TIMEOUT_S", "15"))


class ReferenceUnavailable(PermanentStepFailure):
    """The references could not be fetched, and a retry will not change that.

    Permanent for the reason ``BridgeMisconfigured`` is: the three ways this
    fails are an unset service token, a tenant missing from the run context
    and an API that refused the request. None of them resolves while a step
    sleeps between attempts.
    """


def _service_token() -> str:
    return os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip()


async def resolve(*, tenant_id: str, names: list[str]) -> dict[str, Any]:
    """Return ``{name: {...}}`` for the references this tenant has configured.

    A name the tenant has not configured is simply absent from the result.
    The caller reports which ones it needed and did not get, because "you
    have no Okta connected" is a different sentence from "the lookup failed"
    and only one of them is about the playbook.
    """
    if not names:
        return {}
    if not tenant_id:
        raise ReferenceUnavailable("this run has no tenant, so no integration reference can be resolved for it")

    token = _service_token()
    if not token:
        raise ReferenceUnavailable(
            f"AISOC_AGENTS_SERVICE_TOKEN is unset, so the API's service path is closed and {', '.join(sorted(names))} cannot be resolved"
        )

    url = f"{_API_URL.rstrip('/')}/api/v1/playbook-steps/references"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.post(
                url,
                json={"tenant_id": tenant_id, "names": sorted(set(names))},
                headers={"X-AiSOC-Service-Token": token},
            )
    except httpx.HTTPError as exc:
        raise ReferenceUnavailable(f"the API could not be reached to resolve {', '.join(sorted(names))}: {exc}") from exc

    if response.status_code >= 400:
        raise ReferenceUnavailable(f"the API refused the reference lookup with HTTP {response.status_code}")

    try:
        body = response.json()
    except ValueError as exc:
        raise ReferenceUnavailable("the API returned a non-JSON body for the reference lookup") from exc

    resolved = body.get("references")
    if not isinstance(resolved, dict):
        raise ReferenceUnavailable("the API returned a reference lookup with no 'references' map")
    return resolved

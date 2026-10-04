"""The credential and tenant every API-to-connectors call must carry.

One helper, because three call sites each reached the connectors service their
own way and two of them reached it with nothing.

The far side
------------
`services/connectors/app/api/router.py` mounts its whole router behind
``Depends(require_console_or_service_auth)``. That dependency requires a
bearer credential, and when the credential is a *service* token it requires
the caller to declare which tenant it is acting for on
``X-AiSOC-Tenant-ID`` as well. An absent tenant there resolves to an **empty**
scope and refuses, rather than widening to every tenant.

What shipped
------------
Only the catalog proxy in ``app/api/v1/endpoints/connectors.py`` sent either.

* ``federated.py`` posted the unified query as ``client.post(url, json=...)``,
  so **every federated search, the agent's federated tool and the retro-hunt
  SIEM sweep were answered 401 by every SIEM**. The console reported no
  results, which is indistinguishable from a SIEM that held none.
* ``case_fanout.py`` pushed cases and polled their status the same way.

Both were written after the catalog proxy was fixed, which is the shape this
module exists to stop: a fix applied where a report pointed, while its
siblings kept shipping.

Why the tenant is explicit
--------------------------
The connectors service holds every tenant's connector rows. A call that does
not name a tenant is not a call for all of them; it is a call whose scope
nobody decided. Passing it here makes the decision visible at every call site
and lets the far side refuse one that forgot.
"""

from __future__ import annotations

import os
import uuid

#: Header the connectors service reads to learn which tenant a service caller
#: is acting for. Spelled identically to ``TENANT_HEADER`` in the vendored
#: ``app/security/tenant_scope.py`` on both sides.
TENANT_HEADER = "X-AiSOC-Tenant-ID"


def service_token() -> str:
    """The shared secret this service presents to the connectors service.

    Per-service override first, then the shared platform token, matching
    ``resolve_service_token`` in the vendored ``tenant_scope`` module that the
    far side resolves its own copy with.
    """
    specific = (os.getenv("AISOC_CONNECTORS_SERVICE_TOKEN") or "").strip()
    return specific or (os.getenv("AISOC_SERVICE_TOKEN") or "").strip()


def connectors_headers(tenant_id: uuid.UUID | str | None) -> dict[str, str]:
    """Credential plus tenant assertion for one connectors-service call.

    An empty token yields no ``Authorization`` header rather than an empty
    one: the far side's refusal then says "missing bearer credential", which
    names the deployment problem, instead of "invalid or missing credential",
    which reads like a wrong secret.
    """
    headers: dict[str, str] = {}
    token = service_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if tenant_id is not None:
        headers[TENANT_HEADER] = str(tenant_id)
    return headers

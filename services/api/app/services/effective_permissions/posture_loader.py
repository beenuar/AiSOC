"""Live posture-snapshot collection for effective permissions (Phase C2).

The resolver (`resolve_effective_permissions`) is pure: it takes a *snapshot*
dict and computes a principal's effective access. Until now the only snapshot
source was an inline dev-only base64 blob — the production loader
(`_default_snapshot_loader`) returned `{}`, so every live call 412'd with "no
policy snapshot ingested yet". This module collects a real snapshot from the
configured connector via its `get_resource_config` read path.

Transport: the API service owns the credential vault, so it decrypts a
connector instance's `auth_config` and POSTs it to the connectors service's
`/connectors/{id}/resource_config` endpoint (same trust model as `/test` and
federated `/query`). A pluggable `ResourceConfigFetcher` keeps the assembly
logic unit-testable without a live connectors service.

Coverage is explicit and honest:

* **okta** — fully assembled here: fetch the user, then its groups and assigned
  apps, and build the resolver's `principals/groups/apps/admin_roles` snapshot.
* **aws / azure / gcp / gws** — consume a connector-provided *reconciled*
  snapshot: the connector returns the full provider snapshot for the sentinel
  resource id `__posture_snapshot__`. Connectors that haven't implemented that
  yet surface as "no snapshot" (the endpoint still 412s, same as before) — so
  we never fabricate a cloud snapshot we didn't actually collect.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

# (connector_id, resource_id, at_ts) -> resource config dict.
ResourceConfigFetcher = Callable[[str, str, str], Awaitable[dict[str, Any]]]

# Provider -> the connector_id whose get_resource_config backs its posture.
PROVIDER_CONNECTOR = {
    "okta": "okta",
    "aws": "aws_security_hub",
    "azure": "azure_entra",
    "gcp": "gcp_scc",
    "gws": "google_workspace",
}

# Sentinel resource id: connectors that expose a full reconciled provider
# snapshot return it from get_resource_config for this id.
POSTURE_SNAPSHOT_ID = "__posture_snapshot__"


async def _collect_okta(principal_id: str, fetcher: ResourceConfigFetcher, at_ts: str) -> dict[str, Any]:
    """Assemble the Okta resolver snapshot for one user principal."""
    user_cfg = await fetcher("okta", principal_id, at_ts)
    raw = user_cfg.get("raw") or user_cfg
    # Okta user payload carries group + app assignments under the profile /
    # embedded blocks; we accept a few shapes so the connector can evolve.
    group_ids = list(raw.get("group_ids") or user_cfg.get("group_ids") or [])
    assigned_apps = list(raw.get("assigned_apps") or user_cfg.get("assigned_apps") or [])
    admin_roles_direct = list(raw.get("admin_roles") or user_cfg.get("admin_roles") or [])

    groups: list[dict[str, Any]] = []
    admin_roles: dict[str, dict[str, Any]] = {}
    apps: dict[str, dict[str, Any]] = {}

    for gid in group_ids:
        gcfg = await fetcher("okta", gid, at_ts)
        graw = gcfg.get("raw") or gcfg
        groups.append(
            {
                "id": gid,
                "name": gcfg.get("name") or graw.get("name") or gid,
                "admin_roles": list(graw.get("admin_roles") or []),
                "assigned_apps": list(graw.get("assigned_apps") or []),
            }
        )
        for r in graw.get("admin_role_defs") or []:
            if isinstance(r, dict) and r.get("id"):
                admin_roles.setdefault(r["id"], {"id": r["id"], "privileges": list(r.get("privileges") or [])})

    for aid in {*assigned_apps, *(a for g in groups for a in g["assigned_apps"])}:
        acfg = await fetcher("okta", aid, at_ts)
        apps[aid] = {"id": aid, "name": acfg.get("name") or aid}

    for r in raw.get("admin_role_defs") or []:
        if isinstance(r, dict) and r.get("id"):
            admin_roles.setdefault(r["id"], {"id": r["id"], "privileges": list(r.get("privileges") or [])})

    return {
        "principals": [
            {
                "id": principal_id,
                "groups": group_ids,
                "assigned_apps": assigned_apps,
                "admin_roles": admin_roles_direct,
            }
        ],
        "groups": groups,
        "admin_roles": list(admin_roles.values()),
        "apps": list(apps.values()),
    }


async def collect_snapshot(
    provider: str,
    principal_id: str,
    *,
    fetcher: ResourceConfigFetcher,
    at_ts: str = "",
) -> dict[str, Any]:
    """Collect a resolver snapshot for ``provider``/``principal_id``.

    Returns an empty dict when nothing could be collected (the endpoint then
    surfaces the same 412 as before — we never fabricate a snapshot).
    """
    connector_id = PROVIDER_CONNECTOR.get(provider)
    if connector_id is None:
        return {}
    try:
        if provider == "okta":
            return await _collect_okta(principal_id, fetcher, at_ts)
        # Cloud providers: consume a connector-provided reconciled snapshot.
        cfg = await fetcher(connector_id, POSTURE_SNAPSHOT_ID, at_ts)
        snap = cfg.get("snapshot") if isinstance(cfg, dict) else None
        if isinstance(snap, dict) and snap:
            return snap
        # Some connectors may already return the snapshot at the top level.
        if isinstance(cfg, dict) and any(k in cfg for k in ("principals", "users", "policies", "role_assignments")):
            return cfg
        return {}
    except Exception as exc:  # noqa: BLE001 — collection failure => empty (412), never a crash
        logger.warning("posture_loader.collect_failed", provider=provider, error=str(exc))
        return {}


class HttpResourceConfigFetcher:
    """Fetch resource configs from the connectors service over HTTP.

    The API layer decrypts the connector instance's ``auth_config`` (vault) and
    passes the plaintext here; the connectors service never sees vault tokens
    (same trust model as ``/test`` and federated ``/query``).
    """

    def __init__(self, base_url: str, auth_config: dict[str, Any], connector_config: dict[str, Any] | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._auth = auth_config
        self._config = connector_config or {}

    async def __call__(self, connector_id: str, resource_id: str, at_ts: str) -> dict[str, Any]:
        url = f"{self._base}/connectors/{connector_id}/resource_config"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                url,
                json={
                    "auth_config": self._auth,
                    "connector_config": self._config,
                    "resource_id": resource_id,
                    "at_ts": at_ts,
                },
            )
            if resp.status_code != 200:
                logger.info("posture_loader.fetch_non_200", connector_id=connector_id, status=resp.status_code)
                return {}
            body = resp.json()
        return body.get("config") if isinstance(body, dict) else {}

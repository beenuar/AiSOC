"""
EASM discovery connectors (Tier 3.6).

Three connector types:
  1. Shodan  — passive search by org / domain / IP.
  2. Censys  — passive search via Censys Search 2.0 API.
  3. Active  — lightweight async TCP connect probe on a configurable port list.

All connectors return a common ``DiscoveredAsset`` dataclass that the scan
orchestrator upserts into ``external_assets``.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

import httpx

from app.core.config import get_settings
from app.models.easm import ExternalAssetType

logger = logging.getLogger("aisoc.easm.discovery")

SHODAN_BASE = "https://api.shodan.io"
CENSYS_HOSTS_BASE = "https://search.censys.io/api/v2"


@dataclass
class DiscoveredAsset:
    asset_type: ExternalAssetType
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)


async def _shodan_search(query: str, api_key: str) -> list[DiscoveredAsset]:
    """Query Shodan /shodan/host/search and return discovered assets."""
    results: list[DiscoveredAsset] = []
    params = {"key": api_key, "query": query, "minify": "true"}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(f"{SHODAN_BASE}/shodan/host/search", params=params)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Shodan search failed for query=%s: %s", query, exc)
            return results

    for match in data.get("matches", []):
        ip = match.get("ip_str", "")
        if not ip:
            continue
        ports = match.get("port")
        meta: dict[str, Any] = {
            "source": "shodan",
            "org": match.get("org", ""),
            "asn": match.get("asn", ""),
            "os": match.get("os"),
            "hostnames": match.get("hostnames", []),
        }
        if ports:
            meta["ports"] = [ports]
        results.append(DiscoveredAsset(
            asset_type=ExternalAssetType.IP,
            value=ip,
            metadata=meta,
        ))
        for hostname in match.get("hostnames", []):
            results.append(DiscoveredAsset(
                asset_type=ExternalAssetType.SUBDOMAIN,
                value=hostname,
                metadata={"source": "shodan", "resolved_ip": ip},
            ))

    logger.info("Shodan returned %d assets for query=%s", len(results), query)
    return results


async def _censys_search(query: str, api_id: str, api_secret: str) -> list[DiscoveredAsset]:
    """Query Censys Hosts 2.0 search and return discovered assets."""
    results: list[DiscoveredAsset] = []
    headers = {"Accept": "application/json"}
    auth = (api_id, api_secret)
    params = {"q": query, "per_page": 100}

    async with httpx.AsyncClient(timeout=30, auth=auth) as client:
        try:
            resp = await client.get(f"{CENSYS_HOSTS_BASE}/hosts/search", params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Censys search failed for query=%s: %s", query, exc)
            return results

    for hit in data.get("result", {}).get("hits", []):
        ip = hit.get("ip", "")
        if not ip:
            continue
        services = hit.get("services", [])
        ports = sorted({s.get("port") for s in services if s.get("port")})
        meta: dict[str, Any] = {
            "source": "censys",
            "autonomous_system": hit.get("autonomous_system", {}),
            "ports": ports,
            "services_count": len(services),
        }
        results.append(DiscoveredAsset(
            asset_type=ExternalAssetType.IP,
            value=ip,
            metadata=meta,
        ))
        for name in hit.get("dns", {}).get("names", []):
            results.append(DiscoveredAsset(
                asset_type=ExternalAssetType.SUBDOMAIN,
                value=name,
                metadata={"source": "censys", "resolved_ip": ip},
            ))

    logger.info("Censys returned %d assets for query=%s", len(results), query)
    return results


async def _probe_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP connect succeeds within *timeout* seconds."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            loop.sock_connect(sock, (host, port)),
            timeout=timeout,
        )
        return True
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        sock.close()


async def _active_scan(targets: Sequence[str], ports: Sequence[int]) -> list[DiscoveredAsset]:
    """Lightweight TCP-connect scan against *targets* on *ports*."""
    results: list[DiscoveredAsset] = []
    tasks = []
    for target in targets:
        for port in ports:
            tasks.append((target, port, _probe_port(target, port)))

    outcomes = await asyncio.gather(*(t[2] for t in tasks), return_exceptions=True)
    host_ports: dict[str, list[int]] = {}
    for (target, port, _), outcome in zip(tasks, outcomes):
        if outcome is True:
            host_ports.setdefault(target, []).append(port)

    for host, open_ports in host_ports.items():
        results.append(DiscoveredAsset(
            asset_type=ExternalAssetType.IP,
            value=host,
            metadata={"source": "active_scan", "ports": sorted(open_ports)},
        ))
    logger.info("Active scan found %d hosts with open ports", len(results))
    return results


async def run_discovery(
    org_query: str,
    *,
    ip_targets: Sequence[str] | None = None,
) -> list[DiscoveredAsset]:
    """
    Run all enabled discovery connectors for *org_query* and return
    the merged set of discovered assets.
    """
    s = get_settings()
    all_assets: list[DiscoveredAsset] = []

    passive_tasks = []
    if s.AISOC_EASM_SHODAN_API_KEY:
        passive_tasks.append(_shodan_search(org_query, s.AISOC_EASM_SHODAN_API_KEY))
    if s.AISOC_EASM_CENSYS_API_ID and s.AISOC_EASM_CENSYS_API_SECRET:
        passive_tasks.append(_censys_search(org_query, s.AISOC_EASM_CENSYS_API_ID, s.AISOC_EASM_CENSYS_API_SECRET))

    if passive_tasks:
        passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)
        for res in passive_results:
            if isinstance(res, list):
                all_assets.extend(res)
            elif isinstance(res, BaseException):
                logger.error("Passive discovery connector error: %s", res)

    if s.AISOC_EASM_ACTIVE_SCAN_ENABLED and ip_targets:
        active_assets = await _active_scan(ip_targets, s.AISOC_EASM_SCAN_PORTS)
        all_assets.extend(active_assets)

    return all_assets

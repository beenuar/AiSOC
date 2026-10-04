"""
Tenable.io / Tenable Vulnerability Management connector.

Tenable.io uses an Access Key + Secret Key as a stable API auth pair.
We model vulnerability data as an "alert" stream of detected
vulnerabilities so the agent can treat them uniformly.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


#: Tenable.io publishes the CVSSv3 severity ladder as 0=Info .. 4=Critical.
#: Shared by the alert path and the vulnerability path so the two cannot drift,
#: and mapped straight onto AiSOC's five tiers: collapsing Tenable's Critical
#: into `high` is the exact defect the connector conventions name.
_SEVERITY_BY_INT: dict[Any, str] = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _first(value: Any) -> str | None:
    """Tenable returns these as lists even when there is one of them."""
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value) if value else None


#: Plugin detail is one HTTP request per plugin against the customer's own
#: scanner, so the fan-out is capped. An uncapped loop over a workbench with a
#: few thousand plugins is a denial of service aimed at the customer, which is
#: worse than not having the feature.
MAX_PLUGIN_LOOKUPS = 60


def _plugin_attribute(detail: dict[str, Any], name: str) -> str | None:
    """Read one attribute out of Tenable's plugin-detail shape.

    Attributes arrive as a list of `{attribute_name, attribute_value}` rather
    than a mapping, and a plugin can repeat a name (several CVEs on one
    plugin), so this returns the first and `_plugin_attributes` returns all.
    """
    for attribute in detail.get("attributes") or []:
        if attribute.get("attribute_name") == name:
            value = attribute.get("attribute_value")
            return str(value) if value is not None else None
    return None


def _plugin_attributes(detail: dict[str, Any], name: str) -> list[str]:
    return [
        str(a.get("attribute_value"))
        for a in detail.get("attributes") or []
        if a.get("attribute_name") == name and a.get("attribute_value") is not None
    ]


class TenableConnector(BaseConnector):
    """Tenable.io VM."""

    connector_id = "tenable_io"
    connector_name = "Tenable.io"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Tenable.io / Tenable Vulnerability Management. Pulls "
                "vulnerability findings as alerts and exposes asset and "
                "vulnerability enrichment for the agent."
            ),
            docs_url="/docs/connectors/tenable-io",
            fields=[
                Field("access_key", "string", "Access Key"),
                Field("secret_key", "secret", "Secret Key"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PIVOT_HOST,
            Capability.PIVOT_IP,
            Capability.ENRICH_VULN,
            Capability.ENRICH_ASSET,
        )

    def __init__(self, access_key: str, secret_key: str):
        self._access = access_key
        self._secret = secret_key
        self._base = "https://cloud.tenable.com"

    def _headers(self) -> dict[str, str]:
        return {
            "X-ApiKeys": f"accessKey={self._access}; secretKey={self._secret}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/server/properties",
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return {"success": True, "connector": self.connector_id}
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # Use the workbenches export filtered by last_found within the window.
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/workbenches/vulnerabilities",
                    headers=self._headers(),
                    params={
                        "filter.search_type": "and",
                        "filter.0.filter": "plugin.attributes.vpr.score",
                        "filter.0.quality": "gte",
                        "filter.0.value": "7.0",
                        "date_range": max(1, since_seconds // 86400),
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "tenable.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("vulnerabilities") or []
                return [self.normalize(i) for i in items[:200]]
        except Exception as exc:
            logger.warning("tenable.fetch_exception", error=str(exc))
            return []

    async def fetch_vulnerability_findings(self) -> list[dict[str, Any]]:
        """Per-asset findings carrying a CVE, which is what a vulnerability row needs.

        `fetch_alerts` above calls `/workbenches/vulnerabilities`, which returns
        plugin-level *aggregates*: no asset, no CVE. `normalize()` sets
        `host: None` outright. So the alert path could never have produced a
        row in `asset_vulnerabilities`, and that table's only writer was a
        route a human calls by hand -- which is why
        `_tenant_has_vulnerability_data` answered "nobody has told me what you
        run" for every Tenable tenant, and KEV exposure reported nothing
        forever.

        Two calls, because Tenable splits the data:

        * `/workbenches/assets/vulnerabilities` gives the asset and which
          plugins fired on it.
        * `/plugins/plugin/{id}` gives that plugin's CVE list.

        The second is per plugin, so it is capped and the distinct plugin set
        is resolved once rather than once per asset.
        """
        assets = await self._fetch_asset_workbench()
        if not assets:
            return []

        plugin_ids: list[int] = []
        for asset in assets:
            for vuln in asset.get("vulnerabilities") or []:
                pid = vuln.get("plugin_id")
                if isinstance(pid, int) and pid not in plugin_ids:
                    plugin_ids.append(pid)

        if len(plugin_ids) > MAX_PLUGIN_LOOKUPS:
            logger.info(
                "tenable.plugin_lookup_capped",
                distinct_plugins=len(plugin_ids),
                cap=MAX_PLUGIN_LOOKUPS,
            )
            plugin_ids = plugin_ids[:MAX_PLUGIN_LOOKUPS]

        cves_by_plugin: dict[int, list[str]] = {}
        titles_by_plugin: dict[int, str] = {}
        for pid in plugin_ids:
            detail = await self._fetch_plugin_detail(pid)
            if detail is None:
                continue
            raw_cves = _plugin_attributes(detail, "cve")
            cves_by_plugin[pid] = [c for c in raw_cves if c.upper().startswith("CVE-")]
            titles_by_plugin[pid] = str(detail.get("name") or f"Tenable plugin {pid}")

        findings: list[dict[str, Any]] = []
        for asset in assets:
            hostname = _first(asset.get("fqdn")) or _first(asset.get("netbios_name"))
            ip = _first(asset.get("ipv4"))
            for vuln in asset.get("vulnerabilities") or []:
                pid = vuln.get("plugin_id")
                if not isinstance(pid, int):
                    continue
                for cve in cves_by_plugin.get(pid, []):
                    findings.append(
                        {
                            "cve_id": cve,
                            # Tenable's ladder is 0..4 and 4 is Critical. The
                            # five-tier map is shared with `normalize()` so a
                            # genuine Critical is not collapsed into `high`.
                            "severity": _SEVERITY_BY_INT.get(vuln.get("severity"), "info"),
                            "hostname": hostname,
                            "ip_address": ip,
                            "asset_ref": str(asset.get("id") or "") or None,
                            "title": titles_by_plugin.get(pid, f"Tenable plugin {pid}"),
                            "plugin_id": pid,
                            "source": "tenable_io",
                        }
                    )
        return findings

    async def _fetch_asset_workbench(self) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/workbenches/assets/vulnerabilities",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    logger.warning(
                        "tenable.asset_workbench_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                return list((resp.json() or {}).get("assets") or [])
        except Exception as exc:
            logger.warning("tenable.asset_workbench_exception", error=str(exc))
            return []

    async def _fetch_plugin_detail(self, plugin_id: int) -> dict[str, Any] | None:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/plugins/plugin/{plugin_id}",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    # One plugin that will not resolve must not lose the whole
                    # sweep; the findings it would have carried are simply
                    # absent, and the count is visible in the log.
                    logger.info(
                        "tenable.plugin_detail_unavailable",
                        plugin_id=plugin_id,
                        status=resp.status_code,
                    )
                    return None
                return dict(resp.json() or {})
        except Exception as exc:
            logger.info("tenable.plugin_detail_exception", plugin_id=plugin_id, error=str(exc))
            return None

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Tenable.io exposes the CVSSv3 severity ladder (0=Info, 1=Low,
        # 2=Medium, 3=High, 4=Critical). Mirror it directly into AiSOC's
        # five-tier ladder so genuine Critical vulnerabilities are not
        # silently downgraded to High.
        sev = _SEVERITY_BY_INT.get(raw.get("severity"), "info")
        return {
            "source": "tenable_io",
            "category": "cloud",
            "severity": sev,
            "title": raw.get("plugin_name") or "Tenable vulnerability",
            "description": raw.get("plugin_family"),
            "alert_id": str(raw.get("plugin_id")) if raw.get("plugin_id") else None,
            "host": None,
            "raw_event": raw,
        }

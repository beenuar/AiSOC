"""
Wiz connector.

Issues are alerts. The other three reads are context.

Depth-2 item 8.1. Until this change the connector pulled ``issues`` and
nothing else, so the only thing AiSOC knew about a cloud estate from a CNAPP
was the findings the vendor had already correlated and raised. The three reads
added here answer a different question -- "what is already known to be wrong
with the resource this alert just touched" -- and they are deliberately *not*
alerts:

* ``vulnerabilityFindings`` -> ``asset_vulnerabilities`` through the existing
  ``fetch_vulnerability_findings`` hook. That path already exists, is already
  driven by the scheduler, and already owns the patch-window policy; a second
  home for per-asset CVE state would be a second answer to "are we exposed".
* ``configurationFindings`` and ``detections`` -> ``posture_findings`` through
  the new ``fetch_cloud_security_findings`` hook.

Each is off unless the tenant turns it on, because each is an additional
standing poll against someone else's API.

Query shapes verified 2026-11-01 against two independently maintained,
shipped integrations rather than against a vendor page this connector cannot
re-fetch in CI: Elastic's Wiz integration (``packages/wiz/data_stream/*`` in
``elastic/integrations``) and Cribl's collector templates. Both drive the same
three queries with the same argument types. Scopes, from Elastic's published
table: ``read:issues``, ``read:vulnerabilities``, ``read:cloud_configuration``
and ``read:detections`` (plus ``read:cloud_events_cloud``,
``read:cloud_events_sensor`` and ``read:security_scans`` for detections).

Secrets are **not** collected, and that is a decision rather than an omission.
Wiz markets secret detection, but no public reference documents a top-level
secrets query the way it documents these three: Elastic ships no secrets data
stream and the third-party query inventories list only issues, configuration
findings and vulnerability findings. Writing a ``secretFindings`` query from
the product's marketing surface would be inventing an endpoint. Secrets
already reach AiSOC as ``issues`` where Wiz raises them as such. See
``DEPTH2_PROGRESS.md`` for the recorded refusal.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# Wiz issues ship a native ``CRITICAL`` tier. AiSOC's 5-tier ladder
# preserves it end-to-end so P1 cloud findings keep their original priority.
_SEVERITY_MAP: dict[str, str] = {
    "INFORMATIONAL": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}

#: Wiz scores vulnerabilities on the same five-tier words, so the issue map is
#: reused rather than re-declared. ``vendorSeverity`` is preferred over
#: ``CVSSSeverity`` for the same reason the issue path prefers ``severity``:
#: it is the tier the customer sees in their own console.

#: One page. Wiz's maximum is higher, but a poll that pulls more than this per
#: cycle is a backfill, and a backfill that runs every five minutes is a
#: standing load on someone else's API.
_PAGE_SIZE = 100

#: Stop after this many pages in one poll. A cap exists for the same reason
#: `MAX_FINDINGS_PER_SYNC` exists one layer down: a misconfigured filter must
#: not turn a five-minute schedule into an unbounded read.
_MAX_PAGES = 10

_ISSUES_QUERY = """
query IssuesTable($filterBy: IssueFilters, $first: Int) {
  issues(filterBy: $filterBy, first: $first) {
    nodes {
      id
      severity
      status
      title
      description
      createdAt
      entitySnapshot {
        id
        name
        type
        cloudPlatform
        region
        subscriptionExternalId
      }
      sourceRule {
        id
        name
      }
    }
  }
}
"""


_VULNERABILITY_QUERY = """
query VulnerabilityFindingsPage($filterBy: VulnerabilityFindingFilters, $first: Int, $after: String) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      name
      CVEDescription
      CVSSSeverity
      vendorSeverity
      score
      hasExploit
      hasCisaKevExploit
      status
      firstDetectedAt
      lastDetectedAt
      detailedName
      version
      fixedVersion
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id
          type
          name
          region
          providerUniqueId
          cloudPlatform
          subscriptionExternalId
        }
        ... on VulnerableAssetVirtualMachine {
          operatingSystem
          ipAddresses
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

_CONFIGURATION_QUERY = """
query CloudConfigurationFindingsPage($filterBy: ConfigurationFindingFilters, $first: Int, $after: String) {
  configurationFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      analyzedAt
      updatedAt
      severity
      result
      remediation
      resource {
        id
        providerId
        name
        nativeType
        type
        region
        cloudPlatform
        subscription {
          externalId
          cloudProvider
        }
      }
      rule {
        id
        shortId
        name
        description
        remediationInstructions
      }
      evidence {
        currentValue
        expectedValue
        configurationPath
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

_DETECTIONS_QUERY = """
query DetectionsTableV2($filterBy: DetectionFilters, $first: Int, $after: String) {
  detections(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      type
      severity
      createdAt
      updatedAt
      description(format: MARKDOWN)
      primaryResource {
        id
        type
        name
        externalId
        region
      }
      primaryActor {
        id
        name
        type
        externalId
      }
      ruleMatch {
        rule {
          id
          name
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""


#: `posture_findings.cloud_provider` carries a CHECK constraint from migration
#: 017. Wiz names more platforms than that constraint allows, so anything
#: outside the set becomes `other` rather than failing the insert — the
#: provider is context on a finding, not the finding.
_CLOUD_PROVIDERS = {"aws", "azure", "gcp", "k8s"}


def _iso(since_seconds: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cloud_provider(platform: Any) -> str:
    value = str(platform or "").strip().lower()
    if value in _CLOUD_PROVIDERS:
        return value
    if value in {"kubernetes", "openshift", "eks", "aks", "gke"}:
        return "k8s"
    return "other"


def _resource_keys(*values: Any) -> list[str]:
    """Every name this resource answers to, lowercased and de-duplicated.

    An alert knows a resource by whichever identifier its own vendor emitted.
    Storing only one of the CNAPP's identifiers would mean a finding on an EC2
    instance never matches an alert that names the same instance by its ARN.
    Order is preserved so the most specific key stays first for a reader.
    """
    out: list[str] = []
    for value in values:
        text = str(value or "").strip().lower()
        if text and text not in out:
            out.append(text)
    return out


def _truthy(value: Any) -> bool:
    """Config toggles arrive as booleans from the wizard and as strings from a
    hand-written instance row. Both have to mean the same thing, and an
    unparseable value has to mean *off* — a collector that defaults to on when
    it cannot read its own switch is a poll the tenant did not ask for."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


class WizConnector(BaseConnector):
    connector_id = "wiz"
    connector_name = "Wiz"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Wiz cloud security issues via the GraphQL API.",
            docs_url="/docs/connectors/wiz",
            fields=[
                Field("client_id", "string", "Client ID"),
                Field("client_secret", "secret", "Client Secret"),
                Field(
                    "api_endpoint_url",
                    "string",
                    "API Endpoint URL",
                    placeholder="https://api.us20.app.wiz.io/graphql",
                    help_text="Your tenant's GraphQL API endpoint.",
                ),
                Field(
                    "auth_url",
                    "string",
                    "Auth URL",
                    required=False,
                    default="https://auth.app.wiz.io/oauth/token",
                    help_text="OAuth2 token endpoint. Override only for gov-cloud tenants.",
                ),
                # Each of the three below is an extra standing poll against the
                # customer's Wiz tenant and needs a scope their API client may
                # not hold, so each is opt-in. Nothing breaks when they are off;
                # the connector keeps pulling issues exactly as before.
                Field(
                    "collect_vulnerabilities",
                    "boolean",
                    "Collect vulnerability findings",
                    required=False,
                    default=False,
                    help_text=(
                        "Pull per-asset CVE findings into the vulnerability inventory "
                        "(not the alert queue). Needs the read:vulnerabilities scope."
                    ),
                ),
                Field(
                    "collect_configuration_findings",
                    "boolean",
                    "Collect configuration findings",
                    required=False,
                    default=False,
                    help_text=(
                        "Pull failed cloud-configuration checks as posture context for triage "
                        "(not the alert queue). Needs the read:cloud_configuration scope."
                    ),
                ),
                Field(
                    "collect_runtime_detections",
                    "boolean",
                    "Collect runtime detections",
                    required=False,
                    default=False,
                    help_text=(
                        "Pull runtime threat detections as posture context for triage "
                        "(not the alert queue). Needs the read:detections scope."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Wiz issues are surfaced to the agent layer as alerts (CSPM findings).
        # PULL_VULNERABILITIES is the declared half of the scheduler's
        # `fetch_vulnerability_findings` hook: findings become inventory rows
        # with patch windows, never console alerts.
        return (Capability.PULL_ALERTS, Capability.PULL_VULNERABILITIES)

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        api_endpoint_url: str,
        auth_url: str = "https://auth.app.wiz.io/oauth/token",
        collect_vulnerabilities: Any = False,
        collect_configuration_findings: Any = False,
        collect_runtime_detections: Any = False,
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._api_url = api_endpoint_url.rstrip("/")
        self._auth_url = auth_url
        self._access_token: str | None = None
        self._collect_vulnerabilities = _truthy(collect_vulnerabilities)
        self._collect_configuration_findings = _truthy(collect_configuration_findings)
        self._collect_runtime_detections = _truthy(collect_runtime_detections)

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self._auth_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "audience": "wiz-api",
                },
            )
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            return self._access_token

    async def test_connection(self) -> dict[str, Any]:
        try:
            token = await self._authenticate()
            return {"success": True, "connector": self.connector_id, "authenticated": bool(token)}
        except Exception as exc:
            logger.warning("wiz.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._access_token:
            await self._authenticate()

        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        headers = {"Authorization": f"Bearer {self._access_token}"}

        payload = {
            "query": _ISSUES_QUERY,
            "variables": {
                "filterBy": {
                    "status": ["OPEN", "IN_PROGRESS"],
                    "createdAt": {"after": since},
                },
                "first": 100,
            },
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self._api_url, headers=headers, json=payload)

            if resp.status_code == 401:
                await self._authenticate()
                headers = {"Authorization": f"Bearer {self._access_token}"}
                resp = await client.post(self._api_url, headers=headers, json=payload)

            resp.raise_for_status()
            issues = resp.json().get("data", {}).get("issues", {}).get("nodes", [])

        return [self.normalize(i) for i in issues]

    async def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """One authenticated GraphQL round trip, with a single 401 retry.

        Raises on a GraphQL-level ``errors`` block. A 200 carrying `errors` and
        a null `data` is how this API reports a missing scope, and treating it
        as an empty page would turn "your API client cannot read configuration
        findings" into "your cloud estate is clean" — the exact substitution
        this item exists to stop making.
        """
        if not self._access_token:
            await self._authenticate()

        payload = {"query": query, "variables": variables}
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {"Authorization": f"Bearer {self._access_token}"}
            resp = await client.post(self._api_url, headers=headers, json=payload)
            if resp.status_code == 401:
                await self._authenticate()
                headers = {"Authorization": f"Bearer {self._access_token}"}
                resp = await client.post(self._api_url, headers=headers, json=payload)
            resp.raise_for_status()
            body = resp.json()

        errors = body.get("errors")
        if errors:
            # The message, not the whole block: a GraphQL error can echo the
            # request, and the request carries no credential but does carry the
            # tenant's filters.
            first = errors[0] if isinstance(errors, list) and errors else errors
            message = first.get("message") if isinstance(first, dict) else str(first)
            raise RuntimeError(f"wiz graphql error: {str(message)[:200]}")
        return body.get("data") or {}

    async def _paginate(self, query: str, root: str, filter_by: dict[str, Any]) -> list[dict[str, Any]]:
        """Walk ``pageInfo`` to the end, or to ``_MAX_PAGES``, whichever first."""
        nodes: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(_MAX_PAGES):
            data = await self._graphql(
                query,
                {"filterBy": filter_by, "first": _PAGE_SIZE, "after": cursor},
            )
            block = data.get(root) or {}
            nodes.extend(n for n in (block.get("nodes") or []) if isinstance(n, dict))
            page = block.get("pageInfo") or {}
            cursor = page.get("endCursor")
            if not page.get("hasNextPage") or not cursor:
                break
        else:
            logger.warning("wiz.pagination_capped", root=root, pages=_MAX_PAGES, nodes=len(nodes))
        return nodes

    async def fetch_vulnerability_findings(self, since_seconds: int = 3600) -> list[dict[str, Any]]:
        """Per-asset CVE findings, shaped for ``app.vulnerabilities.sync_findings``.

        Inventory, not alerts: the scheduler materialises these into
        ``asset_vulnerabilities`` with a patch due date, and the governed
        promotion sweep is the only path from there back to the alert queue.

        Returns ``[]`` when the tenant has not enabled the read, which is
        indistinguishable from "no findings" to the caller *on purpose* — the
        scheduler's contract is that an empty list writes nothing, and a
        connector that raised here would mark the whole instance unhealthy for
        a feature the tenant declined.
        """
        if not self._collect_vulnerabilities:
            return []

        since = _iso(since_seconds)
        nodes = await self._paginate(
            _VULNERABILITY_QUERY,
            "vulnerabilityFindings",
            {"status": ["OPEN", "IN_PROGRESS"], "lastDetectedAt": {"after": since}},
        )

        out: list[dict[str, Any]] = []
        for node in nodes:
            asset = node.get("vulnerableAsset") or {}
            # `name` on a vulnerability finding is the CVE id; `detailedName`
            # is the package. Confusing them puts "openssl" in the cve_id
            # column, where `sync_findings` would drop it as un-matchable
            # against KEV and count it as skipped.
            cve = str(node.get("name") or "").strip()
            hostname = str(asset.get("name") or "").strip()
            if not cve or not hostname:
                continue
            ips = asset.get("ipAddresses")
            out.append(
                {
                    "source": self.connector_id,
                    "cve_id": cve,
                    "hostname": hostname,
                    "ip_address": ips[0] if isinstance(ips, list) and ips else None,
                    "severity": _SEVERITY_MAP.get(str(node.get("vendorSeverity") or node.get("CVSSSeverity") or "").upper(), "medium"),
                    "title": str(node.get("detailedName") or cve),
                    "cvss_score": node.get("score"),
                    "external_id": node.get("id"),
                }
            )
        return out

    async def fetch_cloud_security_findings(self, since_seconds: int = 3600) -> list[dict[str, Any]]:
        """Configuration findings and runtime detections, as posture context.

        Shaped for ``app.cloud_security.sync_cloud_security_findings``. Nothing
        here becomes an alert: the plan's Phase 8 is read-only, and a CNAPP's
        standing backlog of misconfigurations pushed into an analyst queue is
        the noise a CNAPP exists to triage, not a SOC's work.
        """
        findings: list[dict[str, Any]] = []
        if self._collect_configuration_findings:
            findings.extend(await self._configuration_findings(since_seconds))
        if self._collect_runtime_detections:
            findings.extend(await self._runtime_detections(since_seconds))
        return findings

    async def _configuration_findings(self, since_seconds: int) -> list[dict[str, Any]]:
        nodes = await self._paginate(
            _CONFIGURATION_QUERY,
            "configurationFindings",
            # FAIL only. A passing check is a compliance datum, not a finding,
            # and putting one in front of a verdict would say "this resource
            # has a configuration finding" about a resource that passed.
            {"result": ["FAIL"], "updatedAt": {"after": _iso(since_seconds)}},
        )

        out: list[dict[str, Any]] = []
        for node in nodes:
            resource = node.get("resource") or {}
            rule = node.get("rule") or {}
            subscription = resource.get("subscription") or {}
            out.append(
                {
                    "source": self.connector_id,
                    "finding_class": "misconfiguration",
                    "external_id": node.get("id"),
                    "cloud_provider": _cloud_provider(resource.get("cloudPlatform") or subscription.get("cloudProvider")),
                    "cloud_account": subscription.get("externalId"),
                    "cloud_region": resource.get("region"),
                    "resource_type": str(resource.get("nativeType") or resource.get("type") or "unknown"),
                    "resource_id": str(resource.get("providerId") or resource.get("id") or ""),
                    "resource_name": resource.get("name"),
                    "resource_keys": _resource_keys(resource.get("providerId"), resource.get("id"), resource.get("name")),
                    "rule_id": str(rule.get("shortId") or rule.get("id") or "wiz.configuration"),
                    "rule_title": str(rule.get("name") or "Wiz configuration finding"),
                    "description": rule.get("description"),
                    "severity": _SEVERITY_MAP.get(str(node.get("severity") or "").upper(), "medium"),
                    "remediation_guide": rule.get("remediationInstructions") or node.get("remediation"),
                    # `evidence` carries the offending value, which is what makes
                    # the finding actionable. It is the resource's configuration,
                    # not a credential.
                    "evidence": node.get("evidence") or {},
                    "observed_at": node.get("updatedAt") or node.get("analyzedAt"),
                }
            )
        return out

    async def _runtime_detections(self, since_seconds: int) -> list[dict[str, Any]]:
        nodes = await self._paginate(
            _DETECTIONS_QUERY,
            "detections",
            {
                "updatedAt": {"after": _iso(since_seconds)},
                # Wiz applies a default type filter of GENERATED_THREAT the
                # moment any filterBy is sent, which silently drops MATCH_ONLY
                # detections — rule matches that did not raise a threat issue,
                # and exactly the weak signals this read exists to supply. Both
                # types are therefore named explicitly. Pinned by
                # `test_wiz_detections_request_both_types`.
                "type": {"equals": ["GENERATED_THREAT", "MATCH_ONLY"]},
            },
        )

        out: list[dict[str, Any]] = []
        for node in nodes:
            resource = node.get("primaryResource") or {}
            actor = node.get("primaryActor") or {}
            rule = (node.get("ruleMatch") or {}).get("rule") or {}
            out.append(
                {
                    "source": self.connector_id,
                    "finding_class": "runtime_detection",
                    "external_id": node.get("id"),
                    "cloud_provider": _cloud_provider(None),
                    "cloud_account": None,
                    "cloud_region": resource.get("region"),
                    "resource_type": str(resource.get("type") or "unknown"),
                    "resource_id": str(resource.get("externalId") or resource.get("id") or ""),
                    "resource_name": resource.get("name"),
                    "resource_keys": _resource_keys(
                        resource.get("externalId"),
                        resource.get("id"),
                        resource.get("name"),
                        actor.get("name"),
                    ),
                    "rule_id": str(rule.get("id") or "wiz.detection"),
                    "rule_title": str(rule.get("name") or "Wiz runtime detection"),
                    "description": node.get("description"),
                    "severity": _SEVERITY_MAP.get(str(node.get("severity") or "").upper(), "medium"),
                    "remediation_guide": None,
                    "evidence": {"detection_type": node.get("type"), "actor": actor.get("name")},
                    "observed_at": node.get("updatedAt") or node.get("createdAt"),
                }
            )
        return out

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        raw_severity = str(raw.get("severity", "MEDIUM")).upper()
        severity = _SEVERITY_MAP.get(raw_severity, "medium")

        entity = raw.get("entitySnapshot") or {}
        rule = raw.get("sourceRule") or {}

        return {
            "source": self.connector_id,
            "external_id": raw.get("id", ""),
            "title": raw.get("title", "Wiz Issue"),
            "description": raw.get("description", ""),
            "severity": severity,
            "hostname": entity.get("name"),
            "cloud_resource": entity.get("id"),
            "cloud_platform": entity.get("cloudPlatform"),
            "cloud_region": entity.get("region"),
            "rule_name": rule.get("name"),
            "raw_event": raw,
            "created_at": raw.get("createdAt"),
        }

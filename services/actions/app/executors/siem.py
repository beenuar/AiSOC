"""
SIEM action executors: search SIEM, create notable event, sync detection rule, update watcher.

Supports Splunk and Elastic Security as backends, selected by credentials present in parameters.

Splunk credentials (any one of):
    splunk_url: str           e.g. "https://splunk.corp:8089"
    splunk_token: str         Bearer token
    splunk_username: str + splunk_password: str

Elastic credentials:
    elastic_url: str          e.g. "https://my-cluster.es.io:9243"
    elastic_api_key: str      Base64 "id:api_key"
    elastic_username: str + elastic_password: str
    kibana_url: str           (for detection rules and watchers)
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.clients.elastic_client import ElasticClient
from app.clients.qradar_client import QRadarClient
from app.clients.sentinel_client import (
    CLASSIFICATION_BENIGN_POSITIVE,
    CLASSIFICATION_FALSE_POSITIVE,
    SentinelClient,
)
from app.clients.splunk_client import SplunkClient
from app.executors.base import _SIM_FUNNEL_CTA, BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus, BlastRadius
from app.services.disposition_writeback import (
    BENIGN,
    BENIGN_TRUE_POSITIVE,
    FALSE_POSITIVE,
    WritebackAction,
    WritebackPlan,
    plan_writeback,
)

logger = structlog.get_logger()


# ──────────────────────────────────────────────────────────────────────────
# Client factories, and the exact parameter keys each one reads.
#
# The key tuples are exported because ``live_actions.builtins`` enforces
# ``dry_run`` by *stripping credentials* before delegating here. If the strip
# list and the factory's read set disagree, the factory still builds a client
# and a "dry run" calls the customer's production SIEM. That is exactly what
# happened: the strip list named ``splunk_host``/``splunk_token``/
# ``splunk_index`` while this factory reads ``splunk_url`` first and accepts
# basic auth, so a connector-configured tenant previewing an action reached
# the real Splunk. Elastic had the identical mismatch.
#
# ``tests/test_dry_run_credential_strip.py`` re-derives each read set from
# this module's source and fails if a factory grows a key the tuple omits, so
# the two cannot drift again.
# ──────────────────────────────────────────────────────────────────────────

#: Every ``params`` key :func:`_splunk_client` reads.
SPLUNK_CLIENT_PARAM_KEYS: tuple[str, ...] = (
    "splunk_url",
    "splunk_host",
    "splunk_token",
    "splunk_username",
    "splunk_password",
    "splunk_verify_ssl",
)

#: Every ``params`` key :func:`_elastic_client` reads.
ELASTIC_CLIENT_PARAM_KEYS: tuple[str, ...] = (
    "elastic_url",
    "elastic_api_key",
    "elastic_username",
    "elastic_password",
    "kibana_url",
)

#: Every ``params`` key :func:`_sentinel_client` reads.
SENTINEL_CLIENT_PARAM_KEYS: tuple[str, ...] = (
    "sentinel_tenant_id",
    "sentinel_client_id",
    "sentinel_client_secret",
    "sentinel_subscription_id",
    "sentinel_resource_group",
    "sentinel_workspace_name",
)

#: Every ``params`` key :func:`_qradar_client` reads.
QRADAR_CLIENT_PARAM_KEYS: tuple[str, ...] = (
    "qradar_url",
    "qradar_token",
    "qradar_verify_ssl",
)

#: Credential keys the Microsoft Defender arm reads directly (it builds its
#: client inline rather than through a factory).
DEFENDER_CLIENT_PARAM_KEYS: tuple[str, ...] = (
    "mde_tenant_id",
    "mde_client_id",
    "mde_client_secret",
)


def _splunk_client(params: dict) -> SplunkClient | None:
    """Build a Splunk client from request parameters.

    Both ``splunk_url`` and the older ``splunk_host`` key are accepted
    (some playbooks predate the standardisation pass on Wave-E) and
    forwarded to the client's ``host=`` argument.

    The management port is 8089, not a web-UI port — a URL pointing at 8000
    authenticates and then 404s on every REST path.
    """
    url = params.get("splunk_url") or params.get("splunk_host")
    if not url:
        return None
    return SplunkClient(
        host=url,
        token=params.get("splunk_token"),
        username=params.get("splunk_username"),
        password=params.get("splunk_password"),
        verify_ssl=bool(params.get("splunk_verify_ssl", True)),
    )


def _elastic_client(params: dict) -> ElasticClient | None:
    url = params.get("elastic_url")
    if not url:
        return None
    return ElasticClient(
        es_url=url,
        api_key=params.get("elastic_api_key"),
        username=params.get("elastic_username"),
        password=params.get("elastic_password"),
        kibana_url=params.get("kibana_url"),
    )


def _sentinel_client(params: dict) -> SentinelClient | None:
    """Build a Microsoft Sentinel client, or None when any field is absent.

    Sentinel addresses an incident by the full ARM path, so every one of
    subscription / resource group / workspace is required — a partial config
    would produce a URL that resolves to somebody else's workspace or to
    nothing, and neither is a failure mode worth guessing through.
    """
    required = (
        params.get("sentinel_tenant_id"),
        params.get("sentinel_client_id"),
        params.get("sentinel_client_secret"),
        params.get("sentinel_subscription_id"),
        params.get("sentinel_resource_group"),
        params.get("sentinel_workspace_name"),
    )
    if not all(required):
        return None
    tenant, client_id, client_secret, subscription, resource_group, workspace = required
    return SentinelClient(
        tenant_id=str(tenant),
        client_id=str(client_id),
        client_secret=str(client_secret),
        subscription_id=str(subscription),
        resource_group=str(resource_group),
        workspace_name=str(workspace),
    )


def _qradar_client(params: dict) -> QRadarClient | None:
    url = params.get("qradar_url")
    token = params.get("qradar_token")
    if not (url and token):
        return None
    return QRadarClient(
        base_url=str(url),
        api_token=str(token),
        verify_ssl=bool(params.get("qradar_verify_ssl", True)),
    )


class SearchSIEMExecutor(BaseExecutor):
    """Runs a search query against Splunk or Elastic SIEM.

    parameters.query: str — SPL query for Splunk, ES|QL query for Elastic.
    parameters.backend: "splunk" | "elastic" (auto-detected from credentials if absent).
    parameters.max_results: int (default 500).
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        query = request.parameters.get("query", "")
        max_results = request.parameters.get("max_results", 500)
        logger.info("Executing search_siem", query=query[:80])

        splunk = _splunk_client(request.parameters)
        if splunk:
            try:
                # SplunkClient.run_search takes `max_count` (issue #570); the old
                # `max_results=` kwarg raised TypeError on every live Splunk search.
                results = await splunk.run_search(query=query, max_count=max_results)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MINIMAL,
                    output={"backend": "splunk", "query": query, "result_count": len(results), "results": results[:50]},
                    rollback_data={},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("search_siem.splunk.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MINIMAL,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        elastic = _elastic_client(request.parameters)
        if elastic:
            use_esql = request.parameters.get("use_esql", True)
            try:
                if use_esql:
                    results = await elastic.run_esql_search(query=query, limit=max_results)
                else:
                    index = request.parameters.get("elastic_index", "*")
                    results = await elastic.run_dsl_search(index=index, query={"query_string": {"query": query}}, size=max_results)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MINIMAL,
                    output={"backend": "elastic", "query": query, "result_count": len(results), "results": results[:50]},
                    rollback_data={},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("search_siem.elastic.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MINIMAL,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "search_siem.simulation",
            reason="no SIEM credentials provided",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MINIMAL,
            output={
                "action": "search_siem",
                "query": query,
                "results": [],
                "note": (
                    "Simulation mode — provide splunk_url/splunk_token or elastic_url/elastic_api_key "
                    "to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        logger.info("search_siem has no rollback")
        return True


class CreateNotableEventExecutor(BaseExecutor):
    """Creates a notable event / alert in Splunk ES.

    Requires: splunk_url + (splunk_token or splunk_username/splunk_password).
    parameters.event_title: str
    parameters.severity: str (info|low|medium|high|critical)
    parameters.description: str
    parameters.fields: dict[str, str]  (optional extra fields)
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        title = request.parameters.get("event_title", f"AiSOC Alert — {request.target}")
        severity = request.parameters.get("severity", "high")
        description = request.parameters.get("description", request.rationale or "")
        fields = request.parameters.get("fields", {})
        logger.info("Executing create_notable_event", title=title, severity=severity)

        splunk = _splunk_client(request.parameters)
        if splunk:
            try:
                # `SplunkClient.create_notable_event` takes (rule_name, event_data,
                # severity, owner, status). The executor used to pass
                # `title=`/`description=`/`fields=`, so every live call raised
                # TypeError — invisible because simulation mode never builds the
                # client. `tests/test_siem_client_signatures.py` autospecs the
                # client so the two cannot drift apart again.
                result = await splunk.create_notable_event(
                    rule_name=title,
                    event_data={"description": description, **(fields or {})},
                    severity=severity,
                )
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("create_notable_event.splunk.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "create_notable_event.simulation",
            reason="no Splunk credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.LOW,
            output={
                "action": "create_notable_event",
                "title": title,
                "severity": severity,
                "note": ("Simulation mode — provide splunk_url/splunk_token to enable live execution." + _SIM_FUNNEL_CTA),
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        logger.info("create_notable_event has no rollback")
        return True


class SyncDetectionRuleExecutor(BaseExecutor):
    """Creates or updates a detection rule in Kibana Security (Elastic).

    Requires: elastic_url + elastic_api_key (or username/password), kibana_url.
    parameters.rule_config: dict — full Elastic Security rule definition.
    target: rule name or rule_id.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        rule_config = request.parameters.get("rule_config", {})
        if not rule_config:
            rule_config = {
                "name": request.target,
                "type": "query",
                "query": request.parameters.get("query", "*"),
                "language": "kuery",
                "index": request.parameters.get("index", ["*"]),
                "enabled": True,
                "severity": request.parameters.get("severity", "high"),
                "risk_score": request.parameters.get("risk_score", 73),
            }
        logger.info("Executing sync_detection_rule", name=rule_config.get("name"))

        elastic = _elastic_client(request.parameters)
        if elastic:
            try:
                result = await elastic.create_or_update_detection_rule(rule_config)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"rule_id": result.get("rule_id")},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("sync_detection_rule.elastic.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "sync_detection_rule.simulation",
            reason="no Elastic credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "sync_detection_rule",
                "rule_name": rule_config.get("name"),
                "note": ("Simulation mode — provide elastic_url/elastic_api_key/kibana_url to enable live execution." + _SIM_FUNNEL_CTA),
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        rule_id = result.rollback_data.get("rule_id")
        logger.info("sync_detection_rule rollback: would disable rule", rule_id=rule_id)
        return True


class UpdateWatcherExecutor(BaseExecutor):
    """Creates or updates an Elasticsearch Watcher alert.

    Requires: elastic_url + elastic_api_key (or username/password).
    parameters.watcher_id: str
    parameters.watcher_body: dict — full watcher definition.
    parameters.activate: bool (default True) — activate after upsert.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        watcher_id = request.parameters.get("watcher_id", request.target)
        watcher_body = request.parameters.get("watcher_body", {})
        activate = request.parameters.get("activate", True)
        logger.info("Executing update_watcher", watcher_id=watcher_id)

        elastic = _elastic_client(request.parameters)
        if elastic:
            try:
                result = await elastic.update_watcher(watcher_id=watcher_id, watcher_body=watcher_body)
                if activate:
                    await elastic.activate_watcher(watcher_id)
                    result["activated"] = True
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"watcher_id": watcher_id},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("update_watcher.elastic.failed", watcher_id=watcher_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "update_watcher.simulation",
            watcher_id=watcher_id,
            reason="no Elastic credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "update_watcher",
                "watcher_id": watcher_id,
                "note": ("Simulation mode — provide elastic_url/elastic_api_key to enable live execution." + _SIM_FUNNEL_CTA),
            },
            rollback_data={"watcher_id": watcher_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        watcher_id = result.rollback_data.get("watcher_id")
        logger.info("update_watcher rollback: would deactivate watcher", watcher_id=watcher_id)
        return True


class BlockIOCExecutor(BaseExecutor):
    """Blocks an Indicator of Compromise via Microsoft Defender for Endpoint.

    target: the IOC value (IP, hash, URL, domain).
    parameters.ioc_type: "FileSha1" | "FileSha256" | "IpAddress" | "DomainName" | "Url"
    parameters.title: str (optional description)
    Requires: mde_tenant_id, mde_client_id, mde_client_secret in parameters.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        from app.clients.defender_client import DefenderClient

        ioc_value = request.target
        ioc_type = request.parameters.get("ioc_type", "IpAddress")
        title = request.parameters.get("title", f"AiSOC — blocked {ioc_type}: {ioc_value}")
        logger.info("Executing block_ioc", ioc_value=ioc_value, ioc_type=ioc_type)

        tenant_id = request.parameters.get("mde_tenant_id")
        client_id = request.parameters.get("mde_client_id")
        client_secret = request.parameters.get("mde_client_secret")

        if tenant_id and client_id and client_secret:
            mde = DefenderClient(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
            try:
                result = await mde.block_ioc(
                    indicator_value=ioc_value,
                    indicator_type=ioc_type,
                    title=title,
                )
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"ioc_value": ioc_value, "ioc_type": ioc_type, "vendor": "defender"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("block_ioc.defender.failed", ioc=ioc_value, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning("block_ioc.simulation", ioc=ioc_value, reason="no MDE credentials")
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "block_ioc",
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "note": "Simulation mode — provide mde_tenant_id/mde_client_id/mde_client_secret",
            },
            rollback_data={"ioc_value": ioc_value, "ioc_type": ioc_type},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        ioc_value = result.rollback_data.get("ioc_value")
        logger.info("Rolling back block_ioc (removing IoC)", ioc=ioc_value)
        return True


# ──────────────────────────────────────────────────────────────────────────
# Phase 3.3 — alert lifecycle executors (acknowledge + suppress)
# ──────────────────────────────────────────────────────────────────────────


#: Alias → canonical vendor id for the ``alert_vendor`` pin.
_VENDOR_ALIASES: dict[str, str] = {
    "mde": "defender",
    "microsoft_defender": "defender",
    "microsoft_sentinel": "sentinel",
    "azure_sentinel": "sentinel",
    "ibm_qradar": "qradar",
    "elasticsearch": "elastic",
    "splunk_enterprise": "splunk",
}

#: Credential-order fallback, most specific SIEM first. Defender last because
#: an estate with both a SIEM and Defender wired almost always means the SIEM
#: is the system of record for findings.
_VENDOR_PRIORITY: tuple[str, ...] = ("splunk", "elastic", "sentinel", "qradar", "defender")


def _vendor_credentials_present(vendor: str, params: dict) -> bool:
    """Whether ``vendor``'s credentials in ``params`` would build a live client."""
    if vendor == "splunk":
        return _splunk_client(params) is not None
    if vendor == "elastic":
        return _elastic_client(params) is not None
    if vendor == "sentinel":
        return _sentinel_client(params) is not None
    if vendor == "qradar":
        return _qradar_client(params) is not None
    if vendor == "defender":
        return all(params.get(key) for key in DEFENDER_CLIENT_PARAM_KEYS)
    return False


def _no_client_result(request: ActionRequest, vendor: str, blast: BlastRadius) -> ActionResult:
    """Fail closed when a resolved vendor turns out to have no usable client.

    Unreachable by construction (:func:`_ack_vendor` only names a vendor whose
    credentials build one), and kept because the previous guard was ``assert``:
    stripped by ``python -O`` and, before the pin fix, genuinely reachable.
    Reported FAILED rather than simulated — the caller asked for a specific
    vendor and it did not run, which is not the same as having no credentials
    at all.
    """
    return ActionResult(
        action_id=request.id,
        status=ActionStatus.FAILED,
        blast_radius=blast,
        error=f"{vendor} was selected but its credentials did not build a client",
        completed_at=datetime.utcnow(),
    )


def _ack_vendor(params: dict) -> str | None:
    """Pick the vendor for an alert-lifecycle call, or None to simulate.

    Some teams point several SIEMs at the same estate, so a caller may pin one
    with ``alert_vendor`` rather than depend on which credential block happens
    to be present.

    **A pin is a routing hint, never a licence to skip the credential check.**
    This used to return the pinned vendor unconditionally, so a dry run — which
    works by stripping credentials — still resolved to "splunk" and the caller
    then asserted on a client that was None. Worse, a pin naming a vendor the
    tenant has not configured reported a vendor arm that could never have run.

    A pin whose credentials are absent resolves to None (simulation) rather
    than falling through to the next vendor: "write this to Splunk" must never
    become "write this to Elastic instead", because the disposition would land
    on a finding in a system nobody asked about.
    """
    raw = (params.get("alert_vendor") or "").strip().lower()
    if raw:
        pinned = _VENDOR_ALIASES.get(raw, raw)
        if pinned in _VENDOR_PRIORITY and _vendor_credentials_present(pinned, params):
            return pinned
        logger.warning(
            "alert_lifecycle.pinned_vendor_unusable",
            pinned=pinned,
            known_vendor=pinned in _VENDOR_PRIORITY,
            reason="no credentials for the pinned vendor; refusing to silently use another",
        )
        return None
    for vendor in _VENDOR_PRIORITY:
        if _vendor_credentials_present(vendor, params):
            return vendor
    return None


class AckAlertExecutor(BaseExecutor):
    """Acknowledge an alert in Splunk ES, Elastic Security, or MDE.

    ``request.target`` is the vendor-side alert identifier (Splunk
    rule UID, Elastic ``signal_id``, MDE ``alert_id``). The vendor
    is selected by :func:`_ack_vendor` — operators wanting an
    explicit pin should supply ``alert_vendor`` in the request
    parameters.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        alert_id = request.target
        vendor = _ack_vendor(request.parameters)
        logger.info("Executing ack_alert", vendor=vendor, alert_id=alert_id)

        if vendor == "splunk":
            splunk = _splunk_client(request.parameters)
            if splunk is None:  # unreachable: _ack_vendor verified the credentials build a client
                return _no_client_result(request, "splunk", BlastRadius.MINIMAL)
            try:
                owner = request.parameters.get("owner", "aisoc")
                comment = request.parameters.get("comment") or request.rationale or "Acknowledged by AiSOC"
                result = await splunk.acknowledge_notable_event(event_id=alert_id, owner=owner, comment=comment)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MINIMAL,
                    output=result,
                    rollback_data={"vendor": "splunk", "alert_id": alert_id},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("ack_alert.splunk.failed", alert_id=alert_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MINIMAL,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        if vendor == "elastic":
            elastic = _elastic_client(request.parameters)
            if elastic is None:  # unreachable: see above
                return _no_client_result(request, "elastic", BlastRadius.MINIMAL)
            try:
                result = await elastic.acknowledge_alert(signal_id=alert_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MINIMAL,
                    output=result,
                    rollback_data={"vendor": "elastic", "alert_id": alert_id},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("ack_alert.elastic.failed", alert_id=alert_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MINIMAL,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        if vendor == "defender":
            from app.clients.defender_client import DefenderClient

            mde = DefenderClient(
                tenant_id=request.parameters["mde_tenant_id"],
                client_id=request.parameters["mde_client_id"],
                client_secret=request.parameters["mde_client_secret"],
            )
            try:
                comment = request.parameters.get("comment") or request.rationale or "Acknowledged by AiSOC"
                result = await mde.acknowledge_alert(
                    alert_id=alert_id,
                    comment=comment,
                    assigned_to=request.parameters.get("assigned_to"),
                )
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MINIMAL,
                    output=result,
                    rollback_data={"vendor": "defender", "alert_id": alert_id},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("ack_alert.defender.failed", alert_id=alert_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MINIMAL,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning("ack_alert.simulation", alert_id=alert_id, reason="no SIEM credentials")
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MINIMAL,
            output={
                "action": "ack_alert",
                "alert_id": alert_id,
                "note": (
                    "Simulation mode — provide splunk_url/splunk_token, "
                    "elastic_url+kibana_url, or "
                    "mde_tenant_id/mde_client_id/mde_client_secret to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"alert_id": alert_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        # Ack is idempotent and reversible from the SIEM console;
        # we don't auto-rollback because flipping a deliberately
        # acknowledged alert back to "new" would be more
        # disruptive than the original ack.
        logger.info("ack_alert has no auto-rollback (revert from SIEM console if needed)")
        return True


class SuppressAlertExecutor(BaseExecutor):
    """Suppress (close) an alert in Splunk ES, Elastic Security, or MDE."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        alert_id = request.target
        vendor = _ack_vendor(request.parameters)
        logger.info("Executing suppress_alert", vendor=vendor, alert_id=alert_id)

        if vendor == "splunk":
            splunk = _splunk_client(request.parameters)
            if splunk is None:  # unreachable: see AckAlertExecutor
                return _no_client_result(request, "splunk", BlastRadius.LOW)
            try:
                comment = request.parameters.get("comment") or request.rationale or "Suppressed by AiSOC"
                result = await splunk.suppress_notable_event(event_id=alert_id, comment=comment)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={"vendor": "splunk", "alert_id": alert_id},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("suppress_alert.splunk.failed", alert_id=alert_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        if vendor == "elastic":
            elastic = _elastic_client(request.parameters)
            if elastic is None:  # unreachable: see AckAlertExecutor
                return _no_client_result(request, "elastic", BlastRadius.LOW)
            try:
                result = await elastic.close_alert(signal_id=alert_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={"vendor": "elastic", "alert_id": alert_id},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("suppress_alert.elastic.failed", alert_id=alert_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        if vendor == "defender":
            from app.clients.defender_client import DefenderClient

            mde = DefenderClient(
                tenant_id=request.parameters["mde_tenant_id"],
                client_id=request.parameters["mde_client_id"],
                client_secret=request.parameters["mde_client_secret"],
            )
            try:
                comment = request.parameters.get("comment") or request.rationale or "Suppressed by AiSOC"
                result = await mde.suppress_alert(
                    alert_id=alert_id,
                    classification=request.parameters.get("classification", "FalsePositive"),
                    determination=request.parameters.get("determination", "NotAvailable"),
                    comment=comment,
                )
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={"vendor": "defender", "alert_id": alert_id},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("suppress_alert.defender.failed", alert_id=alert_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning("suppress_alert.simulation", alert_id=alert_id, reason="no SIEM credentials")
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.LOW,
            output={
                "action": "suppress_alert",
                "alert_id": alert_id,
                "note": (
                    "Simulation mode — provide splunk_url/splunk_token, "
                    "elastic_url+kibana_url, or "
                    "mde_tenant_id/mde_client_id/mde_client_secret to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"alert_id": alert_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        # See AckAlertExecutor.rollback — same reasoning. Re-opening
        # a closed alert is the analyst's call, not ours.
        logger.info("suppress_alert has no auto-rollback (re-open from SIEM console if needed)")
        return True


# ──────────────────────────────────────────────────────────────────────────
# Two-way loop: write an AiSOC verdict back onto the finding that raised it
# ──────────────────────────────────────────────────────────────────────────


class UpdateAlertDispositionExecutor(BaseExecutor):
    """Project an AiSOC verdict onto the source SIEM finding.

    ``request.target`` is the vendor-side finding id — the Splunk notable's
    rule UID, the Elastic signal id, the Sentinel incident name, the QRadar
    offense id. That value reaches here as ``external_id``, which is the join
    key the reconciliation table exists to preserve.

    ``parameters``:
        ``disposition``     canonical AiSOC disposition (required)
        ``confidence``      0..1, recorded in the comment, never decisive
        ``rationale``       one line of the agent's reasoning
        ``aisoc_alert_id``  so an analyst can find the AiSOC side
        ``alert_vendor``    optional pin, honoured only with credentials
        ``owner``           who to hand an escalation to
        ``qradar_closing_reason_id``  required to close a QRadar offense

    What it refuses is the interesting part. See
    :mod:`app.services.disposition_writeback`: a confirmed true positive is
    escalated rather than closed, and a verdict outside the canonical taxonomy
    is refused rather than interpreted.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        params = request.parameters
        finding_id = request.target
        plan = plan_writeback(params.get("disposition"), confidence=params.get("confidence"))
        comment = self._comment(plan, params, request)

        if plan.action is WritebackAction.REFUSE:
            # A refusal is a successful decision, not a failed action: the
            # executor did exactly what the contract says it should. It is
            # reported with `written: False` so nothing downstream can read it
            # as a writeback that happened.
            logger.info(
                "update_alert_disposition.refused",
                finding_id=finding_id,
                disposition=plan.disposition,
            )
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.COMPLETED,
                blast_radius=BlastRadius.MINIMAL,
                output={
                    "action": "update_alert_disposition",
                    "finding_id": finding_id,
                    "disposition": plan.disposition,
                    "writeback_action": plan.action.value,
                    "written": False,
                    "reason": plan.reason,
                },
                rollback_data={},
                completed_at=datetime.utcnow(),
            )

        vendor = _ack_vendor(params)
        logger.info(
            "update_alert_disposition.dispatch",
            vendor=vendor,
            finding_id=finding_id,
            writeback_action=plan.action.value,
        )

        if vendor is None:
            return self._simulated(request, plan, finding_id)

        try:
            output = await self._write(vendor, finding_id, plan, comment, params)
        except Exception as exc:
            logger.error(
                "update_alert_disposition.failed",
                vendor=vendor,
                finding_id=finding_id,
                error=str(exc),
            )
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius=BlastRadius.LOW,
                error=f"{type(exc).__name__}: {exc}",
                completed_at=datetime.utcnow(),
            )

        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.LOW,
            output={
                "action": "update_alert_disposition",
                "vendor": vendor,
                "finding_id": finding_id,
                "disposition": plan.disposition,
                "writeback_action": plan.action.value,
                "written": True,
                "reason": plan.reason,
                "vendor_response": output,
            },
            rollback_data={"vendor": vendor, "finding_id": finding_id},
            completed_at=datetime.utcnow(),
        )

    async def _write(
        self,
        vendor: str,
        finding_id: str,
        plan: WritebackPlan,
        comment: str,
        params: dict,
    ) -> dict:
        """Run the vendor call for ``plan``. Raises on any vendor error."""
        closing = plan.action is WritebackAction.CLOSE
        owner = params.get("owner") or "aisoc"

        if vendor == "splunk":
            splunk = _splunk_client(params)
            if splunk is None:
                raise RuntimeError("splunk credentials did not build a client")
            if closing:
                return await splunk.suppress_notable_event(event_id=finding_id, comment=comment)
            return await splunk.acknowledge_notable_event(event_id=finding_id, owner=owner, comment=comment)

        if vendor == "elastic":
            elastic = _elastic_client(params)
            if elastic is None:
                raise RuntimeError("elastic credentials did not build a client")
            if closing:
                return await elastic.close_alert(signal_id=finding_id)
            return await elastic.acknowledge_alert(signal_id=finding_id)

        if vendor == "sentinel":
            sentinel = _sentinel_client(params)
            if sentinel is None:
                raise RuntimeError("sentinel credentials did not build a client")
            if closing:
                return await sentinel.close_incident(
                    finding_id,
                    classification=_SENTINEL_CLASSIFICATION[plan.disposition],
                    comment=comment,
                )
            return await sentinel.escalate_incident(finding_id, comment=comment, owner_upn=params.get("owner_upn"))

        if vendor == "qradar":
            qradar = _qradar_client(params)
            if qradar is None:
                raise RuntimeError("qradar credentials did not build a client")
            if closing:
                reason_id = params.get("qradar_closing_reason_id")
                if not reason_id:
                    # QRadar closing reasons are per-deployment. Guessing one
                    # would file the closure under somebody else's category,
                    # so the action fails loudly instead.
                    raise ValueError("qradar_closing_reason_id is required to close a QRadar offense")
                return await qradar.close_offense(finding_id, closing_reason_id=int(reason_id), note_text=comment)
            return await qradar.escalate_offense(finding_id, note_text=comment, assigned_to=params.get("owner_upn"))

        if vendor == "defender":
            from app.clients.defender_client import DefenderClient

            mde = DefenderClient(
                tenant_id=params["mde_tenant_id"],
                client_id=params["mde_client_id"],
                client_secret=params["mde_client_secret"],
            )
            if closing:
                return await mde.suppress_alert(
                    alert_id=finding_id,
                    classification=_DEFENDER_CLASSIFICATION[plan.disposition],
                    determination=_DEFENDER_DETERMINATION[plan.disposition],
                    comment=comment,
                )
            return await mde.acknowledge_alert(alert_id=finding_id, comment=comment, assigned_to=params.get("owner_upn"))

        raise ValueError(f"no disposition writeback arm for vendor {vendor!r}")

    def _comment(self, plan: WritebackPlan, params: dict, request: ActionRequest) -> str:
        """The sentence an analyst reads in their own console.

        It names AiSOC, states the verdict and the reason, and carries the
        AiSOC alert id so the two systems can be reconciled by hand if the
        link table is ever lost.
        """
        parts = [plan.reason]
        rationale = str(params.get("rationale") or request.rationale or "").strip()
        if rationale:
            parts.append(f"Reasoning: {rationale}")
        alert_id = str(params.get("aisoc_alert_id") or "").strip()
        if alert_id:
            parts.append(f"AiSOC alert {alert_id}.")
        return " ".join(parts)[:2000]

    def _simulated(self, request: ActionRequest, plan: WritebackPlan, finding_id: str) -> ActionResult:
        logger.warning(
            "update_alert_disposition.simulation",
            finding_id=finding_id,
            reason="no SIEM credentials for the selected vendor",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.LOW,
            output={
                "action": "update_alert_disposition",
                "finding_id": finding_id,
                "disposition": plan.disposition,
                "writeback_action": plan.action.value,
                "written": False,
                "reason": plan.reason,
                "note": (
                    "Simulation mode — no usable credentials for the selected SIEM, so nothing "
                    "was written to the source finding. Provide splunk_url/splunk_token, "
                    "elastic_url+kibana_url, the six sentinel_* fields, or "
                    "qradar_url/qradar_token to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"finding_id": finding_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        # Re-opening a finding the analyst may since have actioned would race
        # them in their own console. The reverse is declared MANUAL_ONLY in the
        # capability contract for exactly this reason, and saying so here beats
        # returning True for a rollback that does nothing.
        logger.info(
            "update_alert_disposition has no auto-rollback (re-open from the SIEM console)",
            finding_id=result.rollback_data.get("finding_id"),
        )
        return True


#: Sentinel requires a classification on a closed incident, and the three it
#: accepts map cleanly onto the three AiSOC verdicts that may close one.
_SENTINEL_CLASSIFICATION: dict[str, str] = {
    FALSE_POSITIVE: CLASSIFICATION_FALSE_POSITIVE,
    BENIGN: CLASSIFICATION_BENIGN_POSITIVE,
    BENIGN_TRUE_POSITIVE: CLASSIFICATION_BENIGN_POSITIVE,
}

#: Defender splits the same idea across two fields. ``benign_true_positive``
#: is a *correct* detection of authorised activity, so it is classified
#: TruePositive/SecurityTesting rather than being recorded as a false
#: positive — filing it as FP would corrupt the rule's own FP rate, which is
#: the distinction the disposition taxonomy exists to preserve.
_DEFENDER_CLASSIFICATION: dict[str, str] = {
    FALSE_POSITIVE: "FalsePositive",
    BENIGN: "InformationalExpectedActivity",
    BENIGN_TRUE_POSITIVE: "TruePositive",
}

_DEFENDER_DETERMINATION: dict[str, str] = {
    FALSE_POSITIVE: "NotMalicious",
    BENIGN: "NotMalicious",
    BENIGN_TRUE_POSITIVE: "SecurityTesting",
}

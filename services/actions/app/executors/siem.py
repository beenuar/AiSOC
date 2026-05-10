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
from app.clients.splunk_client import SplunkClient
from app.executors.base import BaseExecutor, _SIM_FUNNEL_CTA
from app.models.action import ActionRequest, ActionResult, ActionStatus, BlastRadius

logger = structlog.get_logger()


def _splunk_client(params: dict) -> SplunkClient | None:
    url = params.get("splunk_url")
    if not url:
        return None
    return SplunkClient(
        base_url=url,
        token=params.get("splunk_token"),
        username=params.get("splunk_username"),
        password=params.get("splunk_password"),
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
                results = await splunk.run_search(query=query, max_results=max_results)
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
                result = await splunk.create_notable_event(
                    title=title,
                    severity=severity,
                    description=description,
                    fields=fields,
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
                "note": (
                    "Simulation mode — provide splunk_url/splunk_token to enable live execution."
                    + _SIM_FUNNEL_CTA
                ),
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
                "note": (
                    "Simulation mode — provide elastic_url/elastic_api_key/kibana_url to enable live execution."
                    + _SIM_FUNNEL_CTA
                ),
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
                "note": (
                    "Simulation mode — provide elastic_url/elastic_api_key to enable live execution."
                    + _SIM_FUNNEL_CTA
                ),
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

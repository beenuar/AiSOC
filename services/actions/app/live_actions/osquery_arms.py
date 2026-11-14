"""Distributed osquery live queries, as a governed verb.

``osquery_live_query`` was a step type the playbook engine declared, the
schema published, the natural-language drafter actively offered, and nothing
could run. Its handler lived in ``services/agents`` and opened with::

    from app.clients.osctrl_client import OsctrlClient

``app.clients`` exists only in this service, so every live query in the
shipped agents image raised ``ModuleNotFoundError``. It also fetched
credentials from ``GET /api/v1/connectors/instances/{id}`` and read
``auth_config`` off the response — a field whose own response model
documents that it is deliberately omitted — so in an image that *had* the
clients, the query would have gone out with no token.

Both faults are the same fault: the verb was being executed in the service
that holds neither the clients nor the vault. It belongs here, beside the
three clients that have been able to run it the whole time.

Vendor references
-----------------
* osctrl — https://github.com/jmpsec/osctrl (``POST /api/v1/queries/{env}``)
* FleetDM — https://fleetdm.com/docs/rest-api/rest-api#live-query
* osquery distributed read/write —
  https://osquery.readthedocs.io/en/stable/deployment/remote/

The SQL is never caller-supplied. ``app.clients.osquery_allowlist`` owns a
closed set of templates and the caller passes a template id plus parameters,
which is the same boundary ``lookup_endpoint_telemetry`` draws and for the
same reason: this verb is reachable from a playbook whose inputs came out of
attacker-influenced alert text.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.clients.aisoc_direct_client import AiSOCDirectClient
from app.clients.fleetdm_client import FleetDMClient
from app.clients.osctrl_client import OsctrlClient
from app.clients.osquery_allowlist import AllowlistError
from app.live_actions.capability_contracts import apply_contract
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus

logger = structlog.get_logger(__name__)

#: Hard ceiling on how long an arm will wait for a fleet to answer. Mirrors
#: ``app.playbook.bounds.ABSOLUTE_MAX_TIMEOUT_SECONDS`` on the engine side: a
#: live query holds a worker for its whole duration, and ``params`` bypasses
#: the Pydantic validator that bounds ``PlaybookStep.timeout_seconds``.
_MAX_TIMEOUT_SECONDS = 300
_DEFAULT_TIMEOUT_SECONDS = 60


def _result(
    executor: LiveActionExecutor,
    request: LiveActionRequest,
    status: LiveActionStatus,
    summary: str,
    *,
    details: dict[str, Any] | None = None,
    error: str | None = None,
) -> LiveActionResult:
    return LiveActionResult(
        request_id=request.request_id,
        status=status,
        capability=executor.capability,
        vendor_id=executor.vendor_id,
        summary=summary,
        details=details or {},
        error=error,
    )


def _query_args(request: LiveActionRequest) -> tuple[list[str], str, dict[str, Any], int]:
    params = request.params or {}
    hosts = [str(h).strip() for h in (params.get("target_hosts") or []) if str(h).strip()]
    if not hosts and request.target:
        hosts = [str(request.target).strip()]
    template = str(params.get("template") or "").strip()
    template_params = params.get("template_params") or {}
    try:
        timeout = int(params.get("timeout_seconds") or _DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        timeout = _DEFAULT_TIMEOUT_SECONDS
    return hosts, template, dict(template_params), max(1, min(timeout, _MAX_TIMEOUT_SECONDS))


class _OsqueryLiveQuery(LiveActionExecutor):
    """Shared body for the three fleet backends.

    Declares neither ``vendor_id`` nor ``capability``: the contract gate
    grades an intermediate class naming one without the other as a
    half-declared executor.
    """

    requires_credentials = True

    def _client(self, params: dict[str, Any]) -> Any:
        raise NotImplementedError

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        hosts, template, template_params, timeout = _query_args(request)

        if not template:
            # Refused rather than defaulted. A live query with no template
            # has no SQL, and picking one for the caller would run a query
            # nobody asked for against production endpoints.
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "osquery live query needs a template id",
                error="'template' names an entry in the osquery allowlist and is required; no SQL is accepted from the caller.",
            )
        if not hosts:
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "osquery live query needs at least one target host",
                error="neither 'target_hosts' nor the step's target resolved to a host, so nothing would have been queried.",
            )

        if request.dry_run:
            return _result(
                self,
                request,
                LiveActionStatus.SIMULATED,
                f"would run osquery template {template!r} on {len(hosts)} host(s) via {self.vendor_id}",
                details={"would_query": template, "target_hosts": hosts, "backend": self.vendor_id},
            )

        client = self._client(request.params or {})
        if client is None:
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                f"{self.vendor_id} credentials are not configured",
                error=(
                    f"{self.vendor_id} credentials are not configured, so the live query was not run. "
                    f"This is not a statement about the hosts."
                ),
            )

        try:
            response = await client.live_query(hosts, template, template_params, timeout)
        except AllowlistError as exc:
            # A template the allowlist refuses is a permanent authoring
            # error, reported as such rather than as a vendor failure.
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                f"osquery template {template!r} is not on the allowlist",
                error=f"osquery allowlist violation: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 — a vendor error is FAILED, never silent
            logger.warning("osquery_live_query.failed", backend=self.vendor_id, error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                f"{self.vendor_id} live query failed",
                error=f"{self.vendor_id} live query failed: {exc}",
            )

        rows = response.get("results") if isinstance(response, dict) else None
        return _result(
            self,
            request,
            LiveActionStatus.SUCCEEDED,
            f"Ran osquery template {template!r} on {len(hosts)} host(s) via {self.vendor_id}",
            details={
                "template": template,
                "target_hosts": hosts,
                "backend": self.vendor_id,
                "results": rows if rows is not None else response,
            },
        )


@apply_contract
class OsctrlLiveQuery(_OsqueryLiveQuery):
    vendor_id = "osctrl"
    capability = "osquery_live_query"
    description = "Run an allowlisted osquery template across an osctrl environment."
    _credential_keys: tuple[str, ...] = ("base_url", "environment", "api_token", "verify_tls")

    def _client(self, params: dict[str, Any]) -> Any:
        base_url = str(params.get("base_url") or "").strip()
        api_token = str(params.get("api_token") or "").strip()
        if not base_url or not api_token:
            return None
        return OsctrlClient(
            base_url=base_url,
            environment=str(params.get("environment") or "default"),
            api_token=api_token,
            verify_tls=str(params.get("verify_tls", "true")).strip().lower() not in {"0", "false", "no", "off"},
        )


@apply_contract
class FleetDMLiveQuery(_OsqueryLiveQuery):
    vendor_id = "fleetdm"
    capability = "osquery_live_query"
    description = "Run an allowlisted osquery template across a FleetDM fleet."
    _credential_keys: tuple[str, ...] = ("base_url", "api_token", "username", "password", "verify_tls")

    def _client(self, params: dict[str, Any]) -> Any:
        base_url = str(params.get("base_url") or "").strip()
        api_token = str(params.get("api_token") or "").strip() or None
        username = str(params.get("username") or "").strip() or None
        password = str(params.get("password") or "").strip() or None
        if not base_url or not (api_token or (username and password)):
            return None
        return FleetDMClient(
            base_url=base_url,
            api_token=api_token,
            username=username,
            password=password,
            verify_tls=str(params.get("verify_tls", "true")).strip().lower() not in {"0", "false", "no", "off"},
        )


@apply_contract
class AiSOCDirectLiveQuery(_OsqueryLiveQuery):
    vendor_id = "aisoc_direct"
    capability = "osquery_live_query"
    description = "Run an allowlisted osquery template through AiSOC's own osquery TLS endpoint."
    _credential_keys: tuple[str, ...] = ("base_url", "api_token", "verify_tls")

    def _client(self, params: dict[str, Any]) -> Any:
        base_url = str(params.get("base_url") or "").strip()
        api_token = str(params.get("api_token") or "").strip()
        if not base_url or not api_token:
            return None
        return AiSOCDirectClient(
            base_url=base_url,
            api_token=api_token,
            verify_tls=str(params.get("verify_tls", "true")).strip().lower() not in {"0", "false", "no", "off"},
        )


OSQUERY_ARMS: tuple[type[LiveActionExecutor], ...] = (OsctrlLiveQuery, FleetDMLiveQuery, AiSOCDirectLiveQuery)

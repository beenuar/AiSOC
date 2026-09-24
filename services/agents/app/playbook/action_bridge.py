"""Ask the API to run one playbook step as a governed action.

The engine does not dispatch. This module is one authenticated POST, a
structured log line, and no policy — deliberately, because the API holds the
credential vault and the tenant session, and ``services/actions`` owns the
per-capability contract that decides whether a verb may run at all. A second
opinion here would be a second place that can isolate a customer's host.

Fail closed, not fail soft
--------------------------
``siem_writeback`` next door fails *soft*: the verdict is already durable by
the time it runs and a Splunk outage must not undo it. This is the opposite
case. A step that says it blocked an address and did not must never be
recorded as a success, so every failure path here returns a report with
``executed: false`` and the engine fails the step. The default
``on_failure: abort`` then halts the run, which is the behaviour an operator
reading "block the C2 address" expects when it did not happen.

Preview by default
------------------
``AISOC_PLAYBOOK_ACTIONS_EXECUTE`` is **off** unless an operator turns it on,
so a playbook previews its response steps and reports them as previews. The
switch is read here *and* honoured downstream by the same
``dry_run``-defaults-true rule in ``actions_client``, so neither end can turn
it on alone.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

#: Stdlib logging rather than structlog, matching `engine.py`. The playbook
#: package states "zero external dependencies beyond httpx + stdlib" in its
#: own docstring and it is load-bearing: `scripts/validate_playbooks.py` and
#: the schema-parity gate import the package with only jsonschema, pydantic
#: and httpx installed, so a structlog import here fails the pack validator
#: rather than the module that added it.
logger = logging.getLogger("aisoc.playbook.action_bridge")

_API_URL = os.getenv("API_SERVICE_URL", os.getenv("API_URL", "http://api:8000"))
_TIMEOUT_S = float(os.getenv("AISOC_PLAYBOOK_ACTION_TIMEOUT_S", "45"))


def actions_enabled() -> bool:
    """Whether playbook steps may reach the action registry at all.

    On by default: reaching governed dispatch is not the same as executing.
    A disabled bridge means the step fails closed rather than previewing,
    because "we did not even ask" is a different fact from "we asked and it
    was held".
    """
    return os.getenv("AISOC_PLAYBOOK_ACTIONS_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def actions_execute() -> bool:
    """Whether a playbook step may touch a vendor, as opposed to previewing.

    Off by default, matching the platform's copilot posture. Governance can
    still refuse an execution this allows; it can never allow one this
    refuses.
    """
    return os.getenv("AISOC_PLAYBOOK_ACTIONS_EXECUTE", "0").strip().lower() in {"1", "true", "yes", "on"}


def _service_token() -> str:
    """Shared secret for the API's service path. Empty means "do not call"."""
    return os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip()


class BridgeUnavailable(RuntimeError):
    """The step could not be dispatched. Carries the operator-facing reason.

    Raised rather than returned so a caller cannot forget to check: the
    engine's handler turns it into a failed step, and a failed step halts the
    run under the default policy.
    """


async def dispatch_step(
    *,
    capability: str,
    tenant_id: str,
    target: str = "",
    params: dict[str, Any] | None = None,
    vendor_id: str = "",
    confidence: float | None = None,
    playbook_run_id: str = "",
    playbook_step_id: str = "",
) -> dict[str, Any]:
    """POST one step to the API and return its report verbatim.

    The report's ``executed`` field is the single thing that means a vendor
    was touched. It is returned unmodified — narrowing it to a boolean here
    would throw away the distinction between "held for an analyst", "no
    integration configured" and "previewed", which are the three answers an
    author most needs.
    """
    if not actions_enabled():
        raise BridgeUnavailable(
            f"playbook action dispatch is disabled (AISOC_PLAYBOOK_ACTIONS_ENABLED=0), so '{capability}' was not attempted"
        )
    if not tenant_id:
        # The API refuses a service call with no tenant, and guessing one
        # here would be a cross-tenant action.
        raise BridgeUnavailable(f"'{capability}' has no tenant in the run context, and a response action cannot be run without one")

    token = _service_token()
    if not token:
        raise BridgeUnavailable(
            f"'{capability}' was not dispatched: AISOC_AGENTS_SERVICE_TOKEN is unset, so the API's service path is closed"
        )

    payload: dict[str, Any] = {
        "capability": capability,
        "target": target,
        "params": params or {},
        "vendor_id": vendor_id,
        "dry_run": not actions_execute(),
        "tenant_id": tenant_id,
        "playbook_run_id": playbook_run_id,
        "playbook_step_id": playbook_step_id,
    }
    if confidence is not None:
        payload["confidence"] = max(0.0, min(1.0, float(confidence)))

    url = f"{_API_URL.rstrip('/')}/api/v1/playbook-steps/dispatch"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.post(url, json=payload, headers={"X-AiSOC-Service-Token": token})
    except httpx.HTTPError as exc:
        raise BridgeUnavailable(f"the action service could not be reached for '{capability}': {exc}") from exc

    if response.status_code >= 400:
        raise BridgeUnavailable(f"the API refused '{capability}' with HTTP {response.status_code}")

    try:
        report = response.json()
    except ValueError as exc:
        raise BridgeUnavailable(f"the API returned a non-JSON body for '{capability}'") from exc
    if not isinstance(report, dict) or "executed" not in report:
        raise BridgeUnavailable(f"the API returned a report with no 'executed' field for '{capability}'")

    logger.info(
        # `executed` is echoed verbatim: if it is False no vendor was
        # touched, whatever the HTTP status said.
        "playbook_action.dispatched capability=%s status=%s executed=%s step=%s",
        capability,
        report.get("status"),
        bool(report.get("executed")),
        playbook_step_id,
    )
    return report

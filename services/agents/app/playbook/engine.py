"""
Playbook Engine — Pillar 2
==========================
Executes an AiSOC Playbook against a trigger context (alert/case dict).

Design goals:
- Async, step-by-step execution with per-step structured logging.
- Supports condition gates, on_failure policies, and basic retries.
- Emits events to the realtime service so the UI can stream progress.
- Zero external dependencies beyond httpx + stdlib.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

import httpx

from app.playbook import pause as playbook_pause

from . import action_bridge, idempotency
from .bounds import (
    ABSOLUTE_MAX_LOOP_ITERATIONS,
    ABSOLUTE_MAX_PARALLEL_BRANCHES,
    DEFAULT_MAX_LOOP_ITERATIONS,
    MAX_INLINE_WAIT_SECONDS,
    clamp_timeout,
    clamp_wait_seconds,
)
from .errors import PermanentStepFailure
from .models import Playbook, PlaybookStep, StepCondition, StepType
from .ssrf_guard import SSRFError, validate_outbound_url

logger = logging.getLogger("aisoc.playbook.engine")

_REALTIME_URL = os.getenv("REALTIME_URL", "http://realtime:3001")
# Internal token used to authenticate the agents service to the realtime
# service. Previously this defaulted to the literal string ``"changeme"``,
# which meant an operator who forgot to wire the secret would silently ship a
# well-known token. We now default to empty and let the call sites treat an
# empty token as "no internal auth" (skip the header) so a misconfigured
# deployment fails closed instead of inheriting a public default.
_INTERNAL_TOKEN = os.getenv("REALTIME_INTERNAL_TOKEN", "")
_API_URL = os.getenv("API_URL", "http://api:8000")

#: The service that actually serves IOC enrichment: `POST /enrich` and
#: `POST /enrich/bulk` on `services/enrichment`, port 8082. The same address
#: `app.investigator.tools` reads, and the same default `docker-compose.yml`
#: gives fusion. The enrich step used to post to
#: `{API_URL}/api/v1/enrichment/lookup`, which the API has never served.
_ENRICHMENT_URL = os.getenv("ENRICHMENT_SERVICE_URL", "http://enrichment:8082").rstrip("/")


# ---------------------------------------------------------------------------
# Run status
# ---------------------------------------------------------------------------


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    #: Suspended at an approval step, waiting on a human. Distinct from
    #: FAILED, which is what an approval step produced before parity 5.2
    #: and which reads to an operator as a broken playbook rather than as
    #: one doing exactly what it was written to do.
    PAUSED = "paused"


class StepStatus(str, Enum):
    PENDING = "pending"
    SKIPPED = "skipped"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Run record
# ---------------------------------------------------------------------------


class StepResult(dict):  # thin dict subclass for JSON serialisation
    pass


class PlaybookRun:
    """Mutable run state threaded through the engine."""

    def __init__(self, playbook: Playbook, trigger_context: dict[str, Any]) -> None:
        self.run_id: str = str(uuid.uuid4())
        self.playbook_id: str = playbook.id
        self.playbook_name: str = playbook.name
        #: The top-level step list, so a `wait` can find the index it must
        #: resume from. A nested wait has no such index and is refused
        #: rather than written as a pause nothing can use.
        self.steps: list[PlaybookStep] = list(playbook.steps)
        self.status: RunStatus = RunStatus.PENDING
        self.trigger_context: dict[str, Any] = trigger_context
        # Accumulated output from previous steps — available to later steps as {{prev.*}}
        self.context: dict[str, Any] = dict(trigger_context)
        # Under an engine-reserved key so it cannot be overwritten by a step
        # result flattened into the context. A response action's audit record
        # names the run it came from, and losing that mid-run would leave an
        # isolated host with no trace of what asked for it.
        self.context["_run_id"] = self.run_id
        self.step_results: list[dict[str, Any]] = []
        self.started_at: str = ""
        self.finished_at: str = ""
        self.error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "status": self.status.value,
            "context": self.context,
            "step_results": self.step_results,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------


def _resolve_field(context: dict[str, Any], field: str) -> Any:
    """Resolve a dot-path field from context, e.g. ``alert.severity`` or
    ``entities.0.name``.

    Supports traversal through both ``dict`` keys and ``list``/``tuple``
    indices. A blank field returns ``None`` (rather than the whole context,
    which would conflate "missing path" with "no path requested").
    """
    if not field:
        return None
    cur: Any = context
    for part in field.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list | tuple):
            # Numeric indices may be specified as bare ints in a dot-path.
            try:
                idx = int(part)
            except (TypeError, ValueError):
                return None
            if -len(cur) <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            return None
    return cur


def _to_float(value: Any) -> float | None:
    """Best-effort numeric coercion. Returns ``None`` for non-numeric input
    so callers can decide how to handle the failure rather than crashing.

    ``None`` and ``""`` coerce to ``0.0`` to preserve historical "missing
    means zero" semantics for numeric comparisons.
    """
    if value is None or value == "":
        return 0.0
    if isinstance(value, bool):  # bool is a subclass of int; treat explicitly
        return 1.0 if value else 0.0
    if isinstance(value, int | float):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _evaluate_condition(condition: StepCondition, context: dict[str, Any]) -> bool:
    """Return True if the condition passes.

    Two forms are supported:

    1. Structured: ``StepCondition(field=..., operator=..., value=...)``.
    2. Expression string: ``StepCondition(expression="severity in ['high','critical']")``.
       Evaluated by :func:`_evaluate_expression` with a sandboxed
       ``eval()`` over the run context. Falsy/unparseable expressions
       return ``False`` so a malformed playbook never silently "passes".
    """
    # Expression-string form takes precedence when set. Previously this was
    # silently ignored, which made every expression-only condition evaluate
    # as ``None == None`` (i.e. always true).
    if condition.expression:
        return _evaluate_expression(condition.expression, context)

    if not condition.field:
        # No field and no expression — nothing to evaluate. Treat as "no
        # condition" (i.e. pass) so an empty StepCondition() doesn't gate
        # the step. The engine only invokes us when condition is non-None.
        return True

    value = _resolve_field(context, condition.field)
    op = condition.operator
    expected = condition.value

    if op == "exists":
        return value is not None
    if op == "eq":
        return value == expected
    if op == "ne":
        return value != expected
    if op == "contains":
        # Support both substring containment ("error" contains "err") and
        # set-membership ("severity in ['high','critical']"). The structured
        # form historically used "expected in str(value)" which crashed when
        # expected was a list — and silently false-matched the common SOAR
        # pattern of testing field membership in an allowed set.
        if value is None:
            return False
        if isinstance(expected, list | tuple | set):
            return value in expected
        return str(expected) in str(value)
    if op in ("gt", "lt"):
        lhs = _to_float(value)
        rhs = _to_float(expected)
        if lhs is None or rhs is None:
            return False
        return lhs > rhs if op == "gt" else lhs < rhs
    return False


# Operators allowed in expression-string conditions, in longest-match-first
# order so ``>=`` is tried before ``>``.
_EXPR_OPERATORS: tuple[tuple[str, str], ...] = (
    ("==", "eq"),
    ("!=", "ne"),
    (">=", "gte"),
    ("<=", "lte"),
    (">", "gt"),
    ("<", "lt"),
    (" not in ", "not_in"),
    (" in ", "in_"),
)


def _parse_literal(token: str, context: dict[str, Any]) -> Any:
    """Parse one side of an expression. Strings, numbers, bool/null/None,
    and bracketed list literals are returned as Python values; everything
    else is treated as a dot-path into the run context.
    """
    token = token.strip()
    if not token:
        return None
    if token in ("null", "None"):
        return None
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    # Quoted string literal
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    # List literal: ['a', 'b'] or ["high","critical"]
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_parse_literal(piece, context) for piece in inner.split(",")]
    # Numeric literal
    try:
        if "." in token:
            return float(token)
        return int(token)
    except ValueError:
        pass
    # Otherwise: dot-path into context
    return _resolve_field(context, token)


def _evaluate_expression(expression: str, context: dict[str, Any]) -> bool:
    """Evaluate a single ``"<lhs> <op> <rhs>"`` boolean expression.

    Intentionally restricted: no ``and``/``or`` chains, no function calls,
    no Python ``eval``. Callers that need compound logic should use
    multiple structured conditions across multiple steps. Returns
    ``False`` for any malformed input.
    """
    if not expression or not isinstance(expression, str):
        return False
    expr = expression.strip()

    # "<field> exists" / "<field> is null" sugar.
    lowered = expr.lower()
    if lowered.endswith(" is not null") or lowered.endswith(" != null"):
        base = expr[: -len(" is not null")] if lowered.endswith(" is not null") else expr[: -len(" != null")]
        return _resolve_field(context, base.strip()) is not None
    if lowered.endswith(" is null") or lowered.endswith(" == null"):
        base = expr[: -len(" is null")] if lowered.endswith(" is null") else expr[: -len(" == null")]
        return _resolve_field(context, base.strip()) is None

    for token, op in _EXPR_OPERATORS:
        # Use lowercase comparison for the " in "/" not in " word-operators
        # so capitalization doesn't trip us up, but split on the original
        # string to preserve quoted-literal casing.
        haystack = lowered if op in ("in_", "not_in") else expr
        needle = token if op in ("in_", "not_in") else token
        idx = haystack.find(needle)
        if idx == -1:
            continue
        lhs_raw = expr[:idx]
        rhs_raw = expr[idx + len(needle) :]
        lhs = _parse_literal(lhs_raw, context)
        rhs = _parse_literal(rhs_raw, context)
        try:
            if op == "eq":
                return lhs == rhs
            if op == "ne":
                return lhs != rhs
            if op == "gt":
                lf, rf = _to_float(lhs), _to_float(rhs)
                return lf is not None and rf is not None and lf > rf
            if op == "lt":
                lf, rf = _to_float(lhs), _to_float(rhs)
                return lf is not None and rf is not None and lf < rf
            if op == "gte":
                lf, rf = _to_float(lhs), _to_float(rhs)
                return lf is not None and rf is not None and lf >= rf
            if op == "lte":
                lf, rf = _to_float(lhs), _to_float(rhs)
                return lf is not None and rf is not None and lf <= rf
            if op == "in_":
                if rhs is None:
                    return False
                if isinstance(rhs, list | tuple | set):
                    return lhs in rhs
                return str(lhs) in str(rhs)
            if op == "not_in":
                if rhs is None:
                    return True
                if isinstance(rhs, list | tuple | set):
                    return lhs not in rhs
                return str(lhs) not in str(rhs)
        except TypeError:
            return False

    logger.warning("Could not parse playbook condition expression: %r", expression)
    return False


# ---------------------------------------------------------------------------
# Step handlers
# ---------------------------------------------------------------------------


async def _handle_enrich(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    """Look one indicator up in the enrichment service.

    It used to post to ``{API_URL}/api/v1/enrichment/lookup``. The API has
    never served that path — measured against a running stack, it answers 404
    — so this step could not enrich anything, and the request shape it sent
    (``{"ioc": …}``) is not the one the enrichment service accepts either.

    The route that exists is ``POST /enrich`` on ``services/enrichment``,
    which is what ``app.tools.enrichment`` and ``app.investigator.tools``
    already call. This is the third caller and it now goes to the same place,
    with the payload that service actually reads.

    Failure raises rather than returning an empty result. Enrichment is a
    `full`-profile service, so on a CORE deployment this step *will* fail —
    and "the enrichment service is not running" must not reach a playbook
    author as "nothing is known about this indicator". Those are different
    facts and only one of them is about the indicator.
    """
    ioc = step.params.get("ioc") or context.get("ioc") or context.get("src_ip", "")
    ioc_type = step.params.get("ioc_type", "ip")
    if not ioc:
        return {"skipped": True, "reason": "no indicator in the step parameters or the run context"}
    try:
        r = await http.post(
            f"{_ENRICHMENT_URL}/enrich",
            json={"value": ioc, "ioc_type": ioc_type},
            timeout=step.timeout_seconds,
        )
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise PermanentStepFailure(
            f"enrichment for {ioc!r} did not run: {exc}. This says nothing about the indicator. "
            f"The enrichment service is on the `full` profile — check it is reachable at {_ENRICHMENT_URL}."
        ) from exc
    return r.json()


async def _handle_investigate(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    case_id = step.params.get("case_id") or context.get("case_id") or context.get("id")
    if not case_id:
        return {"skipped": True, "reason": "no case_id in context"}
    r = await http.post(
        f"{_API_URL}/api/v1/cases/{case_id}/investigate",
        json={"dry_run": step.params.get("dry_run", False)},
        timeout=step.timeout_seconds,
    )
    r.raise_for_status()
    return r.json()


async def _handle_notify(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    channel = step.params.get("channel", "webhook")
    url = step.params.get("url", "")
    message = step.params.get("message", "AiSOC playbook notification")
    # Simple template substitution
    for k, v in context.items():
        message = message.replace(f"{{{{{k}}}}}", str(v))

    if channel == "webhook" and url:
        # SSRF guard: webhook URLs are author-controlled; reject loopback,
        # cloud-metadata, and other unsafe destinations before dispatching.
        try:
            validate_outbound_url(url)
        except SSRFError as exc:
            raise SSRFError(f"notify step rejected: {exc}") from exc
        r = await http.post(url, json={"text": message}, timeout=step.timeout_seconds)
        return {"status": r.status_code}
    # Why it did not deliver, accurately. This said "no url" whatever the
    # cause, including when a url *was* supplied and the channel simply
    # was not `webhook` — so an operator debugging a silent playbook went
    # looking for a missing field that was right there in front of them.
    reason = "no url" if not url else f"channel {channel!r} has no sender; only 'webhook' delivers, and a url was supplied"
    return {"channel": channel, "message": message, "delivered": False, "reason": reason}


async def _handle_http(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    method = step.params.get("method", "POST").upper()
    url = step.params.get("url", "")
    body = step.params.get("body", {})
    headers = step.params.get("headers", {})
    # SSRF guard: arbitrary HTTP calls from playbooks must not reach
    # loopback, RFC1918, link-local, or cloud-metadata endpoints by default.
    try:
        validate_outbound_url(url)
    except SSRFError as exc:
        raise SSRFError(f"http step rejected: {exc}") from exc
    r = await http.request(method, url, json=body, headers=headers, timeout=step.timeout_seconds)
    return {"status": r.status_code, "body": r.text[:500]}


# ---------------------------------------------------------------------------
# Response steps — the bridge to governed dispatch
# ---------------------------------------------------------------------------
#
# Fifteen step types name a verb that changes somebody's estate. Three of them
# used to be answered here with ``{"simulated": True}`` and reached no executor
# at all; the other twelve had no handler. `services/actions` has held working
# executors for fourteen of the fifteen the whole time, behind a contract that
# declares each verb's impact, reversibility, approval requirement and whether
# a probe exists to confirm the effect landed.
#
# Each of these steps is now one governed dispatch, graded on its own
# capability. A playbook is not approved as a unit: authorising the playbook
# cannot authorise whatever its steps happen to contain, because the contract
# is applied per step at the far end.
#
# `approval` is the one verb that is not bridged, and the reason is recorded
# at its entry in ``_UNBRIDGEABLE`` rather than papered over with a handler.


#: Where each verb's target lives, in the order it should be looked for:
#: first the step's own params, then the trigger context. A verb with no
#: natural scalar target (the details ride in ``params``) maps to ``()``.
_TARGET_KEYS: dict[StepType, tuple[str, ...]] = {
    StepType.BLOCK_IP: ("ip", "address", "src_ip", "source_ip"),
    StepType.BLOCK_IOC: ("ioc", "indicator", "hash", "domain", "ip"),
    StepType.ISOLATE_HOST: ("host", "hostname", "device_id", "host_id"),
    StepType.KILL_PROCESS: ("host", "hostname", "device_id", "host_id"),
    StepType.QUARANTINE_FILE: ("host", "hostname", "device_id", "host_id"),
    StepType.RUN_AV_SCAN: ("host", "hostname", "device_id", "host_id"),
    StepType.RUN_SCRIPT: ("host", "hostname", "device_id", "host_id"),
    StepType.DISABLE_USER: ("user", "username", "user_id", "upn", "email"),
    StepType.RESET_PASSWORD: ("user", "username", "user_id", "upn", "email"),
    StepType.REVOKE_SESSION: ("user", "username", "user_id", "upn", "email"),
    StepType.FORCE_MFA: ("user", "username", "user_id", "upn", "email"),
    StepType.SEARCH_SIEM: ("query", "search"),
    StepType.CREATE_NOTABLE_EVENT: ("title", "name"),
    StepType.CREATE_TICKET: (),
}

#: Step types that name a verb but deliberately have no bridge, with the
#: reason. The engine reports the reason instead of a bare "no handler", and
#: the schema's ``x-aisoc-execution`` map records the same state, so an author
#: can tell before writing the playbook rather than after running it.
#: Empty since parity 5.2. `approval` was the only entry: the engine had no
#: pause and no resume, so there was nothing to suspend and nothing to wake,
#: and the step failed closed while 12 shipped playbooks aborted on it.
#:
#: It is a durable pause now (`app.playbook.pause`), so the entry is gone
#: rather than reworded. The mechanism it argued against is still true and
#: still worth knowing: every response step is separately graded against
#: its own capability contract at dispatch and returns `pending_approval`
#: on its own, so an approval step in front of one gates a decision that is
#: already gated. That is a reason to leave it out of a playbook, not a
#: reason for the engine to refuse it.
_UNBRIDGEABLE: dict[StepType, str] = {}


def _resolve_target(step: PlaybookStep, context: dict[str, Any]) -> str:
    """First non-empty target for this verb, from params then context."""
    for key in _TARGET_KEYS.get(step.type, ()):
        for source in (step.params, context):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _resolve_confidence(step: PlaybookStep, context: dict[str, Any]) -> float | None:
    """How good the reason for acting is, as a 0..1 fraction.

    Alerts carry confidence as an integer 0-100 and the agent carries it as a
    fraction, so both spellings arrive here. ``None`` is returned when there
    is no score at all rather than a default, because the approval matrix
    treats a missing score as the lowest band and inventing a middling one
    would quietly raise what an unscored action is allowed to do.
    """
    for source in (step.params, context):
        raw = source.get("confidence")
        if isinstance(raw, bool) or raw is None:
            continue
        if isinstance(raw, int | float):
            value = float(raw)
            return min(1.0, value / 100.0) if value > 1.0 else max(0.0, value)
    return None


def _make_response_handler(step_type: StepType):
    """Build the handler for one response verb.

    One factory rather than fifteen near-identical functions: the verb is the
    only thing that differs, and fifteen copies is fifteen chances for one of
    them to drift into doing something the contract did not grade.
    """

    async def _handler(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
        report = await action_bridge.dispatch_step(
            capability=step_type.value,
            tenant_id=str(context.get("tenant_id") or ""),
            target=_resolve_target(step, context),
            params=dict(step.params),
            vendor_id=str(step.params.get("vendor") or step.params.get("vendor_id") or ""),
            confidence=_resolve_confidence(step, context),
            playbook_run_id=str(context.get("_run_id") or ""),
            playbook_step_id=step.id,
        )
        # Returned verbatim. `executed` is the single field that means a
        # vendor was touched, and the run loop reads it rather than assuming
        # that a handler which returned at all did its job.
        return report

    _handler.__name__ = f"_handle_{step_type.value}"
    _handler.__qualname__ = _handler.__name__
    return _handler


async def _handle_close_case(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    case_id = step.params.get("case_id") or context.get("case_id") or context.get("id")
    if not case_id:
        return {"skipped": True, "reason": "no case_id"}
    r = await http.patch(
        f"{_API_URL}/api/v1/cases/{case_id}",
        json={"status": "closed"},
        timeout=step.timeout_seconds,
    )
    r.raise_for_status()
    return {"case_id": case_id, "status": "closed"}


async def _handle_osquery_live_query(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    """Dispatch a distributed osquery live query via osctrl, FleetDM, or aisoc-direct.

    Expected ``step.params`` keys
    ------------------------------
    backend : str
        One of ``"osctrl"``, ``"fleetdm"``, ``"aisoc_direct"``.
    instance_id : str
        Connector instance ID (looked up from the API to retrieve credentials).
    target_hosts : list[str]
        Host UUIDs / hostnames to query.
    template : str
        Allowlist template ID (see ``osquery_allowlist``).
    template_params : dict, optional
        Parameters forwarded to the template renderer.
    timeout_seconds : int, optional
        How long to wait for all hosts to respond (default: 60).
    """
    # These osquery clients live in `services/actions`, not in this service —
    # `services/agents/app/clients/` does not exist. Every `osquery_live_query`
    # step therefore died with an unhandled ModuleNotFoundError at execution
    # time, and the `except AllowlistError` handler below referenced a name
    # that could never bind. The NL playbook drafter actively offers this step
    # type, so a user could author a playbook that was guaranteed to crash.
    #
    # Fail with an actionable message instead of a traceback. Wiring this
    # properly means dispatching through the actions service over HTTP, the
    # same way SIEM writeback already does, rather than importing across a
    # service boundary that does not exist in this image.
    try:
        from app.clients.aisoc_direct_client import AiSOCDirectClient  # noqa: PLC0415
        from app.clients.fleetdm_client import FleetDMClient  # noqa: PLC0415
        from app.clients.osctrl_client import OsctrlClient  # noqa: PLC0415
        from app.clients.osquery_allowlist import AllowlistError  # noqa: PLC0415
    except ModuleNotFoundError as exc:
        # Raised, not returned. A returned dict leaves ``step_status`` at
        # SUCCESS, so every live query in the shipped agents image — where
        # these clients are always absent — was reported as a step that ran
        # while nothing had been asked of any endpoint. That is the same
        # defect the missing-handler branch above exists to remove, and it
        # became reachable from the console the moment the editor could
        # author this step type.
        #
        # Permanent because the module will not appear between attempt one
        # and attempt four: the image either ships the clients or it does not.
        logger.error("playbook.osquery_clients_unavailable: %s", exc)
        raise PermanentStepFailure(
            "osquery_live_query is not executable in the agents service: the "
            "osquery backend clients ship in services/actions. Run this step "
            "through the actions service, or remove it from the playbook."
        ) from exc

    backend: str = step.params.get("backend", "osctrl")
    target_hosts: list[str] = step.params.get("target_hosts") or [context.get("host_id") or context.get("host", "")]
    template: str = step.params.get("template", "")
    template_params: dict[str, Any] = step.params.get("template_params") or {}
    # Runtime clamp — params bypass the Pydantic validator on PlaybookStep, so
    # a malicious or malformed playbook could otherwise pin the connector
    # thread for hours. See services/agents/app/playbook/bounds.py.
    timeout_seconds: int = clamp_timeout(step.params.get("timeout_seconds", 60), default=60)

    if not template:
        return {"error": "osquery_live_query: 'template' param is required", "partial": True}

    # Credential resolution: fetch the connector instance config from the API.
    instance_id: str = step.params.get("instance_id") or context.get("connector_instance_id", "")
    creds: dict[str, Any] = {}
    if instance_id:
        try:
            r = await http.get(
                f"{_API_URL}/api/v1/connectors/instances/{instance_id}",
                timeout=10,
            )
            if r.status_code == 200:
                creds = r.json().get("auth_config") or {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not fetch connector creds for %s: %s", instance_id, exc)

    try:
        if backend == "osctrl":
            client = OsctrlClient(
                base_url=creds.get("base_url") or step.params.get("base_url", ""),
                environment=creds.get("environment") or step.params.get("environment", "default"),
                api_token=creds.get("api_token") or step.params.get("api_token", ""),
                verify_tls=step.params.get("verify_tls", True),
            )
            return await client.live_query(target_hosts, template, template_params, timeout_seconds)

        if backend == "fleetdm":
            client_fleet = FleetDMClient(
                base_url=creds.get("base_url") or step.params.get("base_url", ""),
                api_token=creds.get("api_token") or step.params.get("api_token") or None,
                username=creds.get("username") or step.params.get("username") or None,
                password=creds.get("password") or step.params.get("password") or None,
                verify_tls=step.params.get("verify_tls", True),
            )
            return await client_fleet.live_query(target_hosts, template, template_params, timeout_seconds)

        if backend == "aisoc_direct":
            client_direct = AiSOCDirectClient(
                base_url=creds.get("base_url") or step.params.get("base_url", ""),
                api_token=creds.get("api_token") or step.params.get("api_token", ""),
            )
            return await client_direct.live_query(target_hosts, template, template_params, timeout_seconds)

        return {"error": f"Unknown osquery backend: {backend!r}", "partial": True}

    except AllowlistError as exc:
        return {"error": f"osquery allowlist violation: {exc}", "partial": True}
    except NotImplementedError as exc:
        return {"error": str(exc), "partial": True, "stub": True}


#: Verbs dispatched through the action registry. Derived from `_TARGET_KEYS`
#: so the two cannot drift: a verb added to one without the other would
#: either dispatch with no target or declare a target nothing reads.
RESPONSE_STEP_TYPES: frozenset[StepType] = frozenset(_TARGET_KEYS)

_HANDLERS = {
    StepType.ENRICH: _handle_enrich,
    StepType.INVESTIGATE: _handle_investigate,
    StepType.NOTIFY: _handle_notify,
    StepType.HTTP: _handle_http,
    StepType.CLOSE_CASE: _handle_close_case,
    StepType.OSQUERY_LIVE_QUERY: _handle_osquery_live_query,
    **{step_type: _make_response_handler(step_type) for step_type in sorted(RESPONSE_STEP_TYPES, key=lambda s: s.value)},
}


# ---------------------------------------------------------------------------
# Realtime event helper
# ---------------------------------------------------------------------------


async def _emit(run_id: str, event_type: str, payload: dict, http: httpx.AsyncClient) -> None:
    try:
        headers: dict[str, str] = {}
        # Only include the internal-auth header when an operator has actually
        # configured a token. Sending a literal "changeme" used to make a
        # misconfigured deployment look authenticated to anything that
        # whitelisted the same string.
        if _INTERNAL_TOKEN:
            headers["x-internal-token"] = _INTERNAL_TOKEN
        await http.post(
            f"{_REALTIME_URL}/internal/agent-event",
            json={"channel": f"playbook:{run_id}", "type": event_type, "data": payload},
            headers=headers,
            timeout=3,
        )
    except Exception:
        pass  # non-critical


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


async def _suspend_for_approval(pr: PlaybookRun, step: PlaybookStep, step_idx: int, http: Any) -> Any:
    """Create the approval and persist where to resume.

    Order matters. The approval row is created **first**, so the pause can
    name it: a pause with no approval has nothing for a human to decide
    against, and a human deciding against an approval with no pause wakes
    nothing. If the approval cannot be created the pause is not written
    either, and the caller fails the step closed.
    """
    tenant_id = str(pr.context.get("tenant_id") or pr.trigger_context.get("tenant_id") or "")
    if not tenant_id:
        logger.warning("Approval step %s has no tenant in context; cannot suspend", step.name)
        return None

    approval_id = await _create_approval(pr, step, tenant_id, http)

    return await playbook_pause.suspend(
        tenant_id=tenant_id,
        run_id=pr.run_id,
        playbook_id=pr.playbook_id,
        playbook_name=pr.playbook_name,
        step_index=step_idx,
        step_id=step.id,
        run_context=pr.context,
        step_results=pr.step_results,
        approval_id=approval_id,
        ttl_hours=_approval_ttl(step),
    )


async def _suspend_for_wait(
    pr: PlaybookRun,
    step: PlaybookStep,
    http: Any,
    *,
    seconds: int,
    until_callback: bool,
) -> Any:
    """Persist where a long wait stopped, and how it will be woken.

    The step index is found by identity rather than passed in, because a
    wait can sit inside a ``loop`` or a ``parallel`` branch where there is
    no top-level index to resume from. A nested wait that cannot name its
    resume point is refused here rather than written as a pause nothing
    can use — a row that looks resumable and is not is worse than no row.
    """
    tenant_id = str(pr.context.get("tenant_id") or pr.trigger_context.get("tenant_id") or "")
    if not tenant_id:
        logger.warning("Wait step %s has no tenant in context; cannot suspend", step.name)
        return None

    step_index = next((i for i, candidate in enumerate(pr.steps) if candidate.id == step.id), -1)
    if step_index < 0:
        logger.error(
            "Wait step %s is nested inside control flow, so the run has no index to resume from; failing the step closed",
            step.name,
        )
        return None

    return await playbook_pause.suspend(
        kind="wait",
        resume_at=(datetime.now(UTC) + timedelta(seconds=seconds)) if seconds > 0 and not until_callback else None,
        resume_token=secrets.token_urlsafe(32),
        tenant_id=tenant_id,
        run_id=pr.run_id,
        playbook_id=pr.playbook_id,
        playbook_name=pr.playbook_name,
        step_index=step_index,
        step_id=step.id,
        run_context=pr.context,
        step_results=pr.step_results,
        ttl_hours=_wait_ttl(step, seconds),
    )


def _wait_ttl(step: PlaybookStep, seconds: int) -> float:
    """How long the pause row may sit before it expires with an outcome.

    Comfortably past the wait itself, so a timer that fires a little late
    is still resumable; an author who sets a deadline gets theirs instead.
    """
    raw = step.params.get("expires_in_hours")
    try:
        if raw is not None:
            return float(raw)
    except (TypeError, ValueError):
        pass
    return max(playbook_pause.DEFAULT_WAIT_TTL_HOURS, (seconds / 3600.0) * 2)


def _approval_ttl(step: PlaybookStep) -> float | None:
    """A per-step deadline, if the author set one."""
    raw = step.params.get("expires_in_hours") or step.params.get("timeout_hours")
    try:
        return float(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


async def _create_approval(pr: PlaybookRun, step: PlaybookStep, tenant_id: str, http: Any) -> str | None:
    """Ask the API to open an approval. None when it could not be created.

    Posted to the API rather than written here for the same reason
    `action_bridge` posts there: that service owns the vault and the
    tenant session, and a second writer to `agent_approvals` would be a
    second place the responder app's decision has to be kept in step with.
    """
    token = os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip() or os.getenv("AISOC_SERVICE_TOKEN", "").strip()
    if not token:
        logger.warning(
            "Approval step %s cannot open an approval: AISOC_AGENTS_SERVICE_TOKEN is unset",
            step.name,
        )
        return None
    api_url = os.getenv("AISOC_API_URL", "http://api:8000")
    try:
        response = await http.post(
            f"{api_url}/api/v1/approvals",
            headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_id},
            json={
                "title": step.name or f"Approval for {pr.playbook_name}",
                "description": str(step.params.get("prompt") or step.params.get("reason") or ""),
                "requested_by": f"playbook:{pr.playbook_id}",
                "context": {"run_id": pr.run_id, "step_id": step.id},
            },
            timeout=10.0,
        )
        if response.status_code >= 400:
            logger.warning(
                "Approval creation refused: HTTP %s %s",
                response.status_code,
                response.text[:200],
            )
            return None
        return str(response.json().get("id") or "") or None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Approval creation failed: %s", exc)
        return None


async def resume_after_approval(
    *,
    approval_id: str,
    tenant_id: str,
    approved: bool,
    decided_by: str = "",
    comment: str = "",
) -> PlaybookRun | None:
    """Continue a run suspended on this approval, or record the denial.

    Returns the completed run, or None when there is nothing waiting. The
    pause is resolved **before** the run continues, so a decision that
    arrives twice (a double-tap, a retried webhook) resumes once: the
    second attempt matches no `waiting` row.
    """
    pause = await playbook_pause.find_waiting(approval_id=approval_id, tenant_id=tenant_id)
    if pause is None:
        return None

    if not approved:
        await playbook_pause.resolve(
            pause_id=pause.id,
            tenant_id=pause.tenant_id,
            status="denied",
            resolution=f"denied by {decided_by or 'an analyst'}: {comment}"[:500],
        )
        logger.info("Playbook run %s halted: approval denied", pause.run_id)
        return None

    claimed = await playbook_pause.resolve(
        pause_id=pause.id,
        tenant_id=pause.tenant_id,
        status="resumed",
        resolution=f"approved by {decided_by or 'an analyst'}: {comment}"[:500],
    )
    if not claimed:
        # Somebody else resumed it first. Not an error.
        return None

    from app.playbook.store import PlaybookStore

    playbook = PlaybookStore.default().get(pause.playbook_id)
    if playbook is None:
        logger.warning(
            "Cannot resume run %s: playbook %s is no longer in the store",
            pause.run_id,
            pause.playbook_id,
        )
        return None

    return await PlaybookEngine().resume(playbook, pause)


async def resume_wait(*, resume_token: str) -> PlaybookRun | None:
    """Continue a run suspended at a ``wait`` step.

    Returns the finished run, or None when the token matches no waiting
    pause. The pause is resolved **before** the run continues, so a
    callback delivered twice — which is the normal behaviour of every
    webhook sender that does not get a 2xx quickly enough — resumes once.
    """
    pause = await playbook_pause.find_wait_by_token(resume_token=resume_token)
    if pause is None:
        return None
    return await _resume_pause(pause, resolution="resumed by callback")


async def resume_due_waits(*, now: Any = None, limit: int = 50) -> list[str]:
    """Resume every timer wait that has come due. Returns the run ids.

    Driven by ``app.playbook.sweeper``. Without a caller this function and
    the whole durable half of ``wait`` would be the shape this plan keeps
    finding: a mechanism that exists, passes its tests and is reached by
    nothing, so every long wait hangs and the run record says ``paused``
    forever.
    """
    resumed: list[str] = []
    for pause in await playbook_pause.due_waits(now=now, limit=limit):
        run = await _resume_pause(pause, resolution="resumed on its timer")
        if run is not None:
            resumed.append(pause.run_id)
    return resumed


async def _resume_pause(pause: Any, *, resolution: str) -> PlaybookRun | None:
    """Claim a pause and continue its run. Shared by both wait resumers."""
    claimed = await playbook_pause.resolve(
        pause_id=pause.id,
        tenant_id=pause.tenant_id,
        status="resumed",
        resolution=resolution,
    )
    if not claimed:
        # Another replica, or a second delivery of the same callback, got
        # there first. Not an error.
        return None

    from app.playbook.store import PlaybookStore

    playbook = PlaybookStore.default().get(pause.playbook_id)
    if playbook is None:
        logger.warning(
            "Cannot resume run %s: playbook %s is no longer in the store",
            pause.run_id,
            pause.playbook_id,
        )
        return None
    return await PlaybookEngine().resume(playbook, pause)


# ---------------------------------------------------------------------------
# Control flow — wait, parallel, loop
# ---------------------------------------------------------------------------
#
# A playbook could branch and it could not wait, fan out or repeat. So
# "contain, then re-check in five minutes", "revoke every session this user
# holds" and "ask three vendors at once" each had to be hand-unrolled into a
# fixed chain of steps, which is why none of the 62 shipped packs attempts
# any of them.
#
# Three properties the three steps share, each of which has an opposite that
# would be worse than not having the step at all:
#
# * **Bounded.** A playbook is author-supplied and these are the first steps
#   that multiply work. Iterations, fan-out and nesting all have ceilings in
#   `bounds.py`, and the ceiling is reported in the result rather than
#   silently truncating.
# * **Honest when empty.** A `parallel` or `loop` with no children, or a
#   `loop` over a path that resolved to nothing, fails rather than reporting
#   a success for work it did not do. That is the same rule the missing-
#   handler branch below exists to enforce.
# * **Idempotent per execution.** Every child carries a key derived from its
#   coordinates, so the third iteration is distinguishable from the fourth
#   and a resumed run reproduces the same keys. See `idempotency.py`.


async def _run_children(
    step: PlaybookStep,
    pr: PlaybookRun,
    http: httpx.AsyncClient,
    *,
    dry_run: bool,
    path: tuple[str, ...],
    context: dict[str, Any],
) -> tuple[bool, list[dict]]:
    """Run a child list in order. Returns ``(all_succeeded, results)``.

    Children are executed through ``_invoke_step``, so a child gets the same
    retry policy and the same ``executed`` check a top-level step gets.

    Each child's result is merged into the *local* context rather than the
    run's, so two parallel branches cannot overwrite each other's values and
    then be read by whichever happened to finish last. The branch results
    are attached to the parent step's result, which is what a later step
    reads through ``_step_<parent id>``.
    """
    results: list[dict] = []
    succeeded = True
    for child in step.steps:
        if child.condition and not _evaluate_condition(child.condition, context):
            results.append({"step_id": child.id, "name": child.name, "status": StepStatus.SKIPPED})
            continue
        child_pr = _scoped_run(pr, context)
        status, result = await _invoke_step(child, child_pr, http, dry_run=dry_run, path=path)
        results.append({"step_id": child.id, "name": child.name, "status": status, "result": result})
        for key, value in result.items():
            if not key.startswith("_"):
                context[key] = value
        if status == StepStatus.FAILED:
            succeeded = False
            if child.on_failure == "abort":
                break
    return succeeded, results


def _scoped_run(pr: PlaybookRun, context: dict[str, Any]) -> PlaybookRun:
    """A view of the run whose context is the child's.

    ``_invoke_step`` reads ``pr.context`` (for the dispatch tenant and the
    response verbs' targets) and ``pr.run_id`` (for the audit trail). A
    child needs the second unchanged and the first scoped, so it gets a
    shallow stand-in rather than a copy of the whole run — copying would
    give a loop iteration its own ``step_results`` and lose them.
    """
    scoped = object.__new__(PlaybookRun)
    scoped.__dict__.update(pr.__dict__)
    scoped.context = context
    return scoped


async def _control_wait(
    step: PlaybookStep,
    pr: PlaybookRun,
    http: httpx.AsyncClient,
    *,
    dry_run: bool,
    path: tuple[str, ...],
) -> tuple[StepStatus, dict]:
    """Hold the run for a timer or until something calls back.

    Two forms, and the split is about worker occupancy rather than about
    how long an author may wait:

    * a short timer sleeps in process, because suspending to Postgres and
      waking again costs more than the wait;
    * anything longer, or ``until: callback``, becomes a **durable pause**
      on the same table the approval step uses, so it survives a restart.
      A ``wait`` that lived in a process would be lost by a deploy, and the
      run would hang with no record of why.

    A dry run neither sleeps nor suspends: a preview that took five minutes
    to tell an author their playbook is sound is a preview nobody runs.
    """
    until = str(step.params.get("until") or "").strip().lower()
    seconds = clamp_wait_seconds(step.params.get("seconds", step.params.get("duration_seconds")))

    if dry_run:
        return StepStatus.SUCCESS, {
            "dry_run": True,
            "executed": False,
            "would_wait_seconds": seconds,
            "would_wait_for_callback": until == "callback",
        }

    if until != "callback" and 0 < seconds <= MAX_INLINE_WAIT_SECONDS:
        await asyncio.sleep(seconds)
        return StepStatus.SUCCESS, {"waited_seconds": seconds, "durable": False}

    if until != "callback" and seconds <= 0:
        # Refused rather than treated as "no wait". A `wait` step with no
        # duration and no callback is an authoring mistake, and passing it
        # through would make the step a no-op that reports success — which
        # is indistinguishable from a wait that happened.
        return StepStatus.FAILED, {
            "executed": False,
            "error": 'a wait step needs `seconds` or `until: "callback"`; it waited for nothing and did not report that it had',
        }

    pause = await _suspend_for_wait(pr, step, http, seconds=seconds, until_callback=until == "callback")
    if pause is None:
        # Nothing can resume this run, so continuing past the wait would
        # run the steps the wait exists to delay. Same reasoning as the
        # approval step failing closed when its pause cannot be written.
        return StepStatus.FAILED, {
            "executed": False,
            "error": "the wait could not be persisted, so nothing could resume this run; it was failed rather than skipped",
        }
    return StepStatus.PENDING, {
        "paused": True,
        "pause_id": pause.id,
        "resume_token": pause.resume_token,
        "resume_at": pause.resume_at.isoformat() if pause.resume_at else None,
        "durable": True,
    }


async def _control_parallel(
    step: PlaybookStep,
    pr: PlaybookRun,
    http: httpx.AsyncClient,
    *,
    dry_run: bool,
    path: tuple[str, ...],
) -> tuple[StepStatus, dict]:
    """Run each child concurrently, then join.

    ``join`` is ``all`` (default) or ``any``. ``all`` fails the parallel
    step when any branch failed; ``any`` succeeds when at least one did.
    There is deliberately no "ignore failures" join — that is what
    ``on_failure: continue`` on the parallel step itself already means, and
    spelling it twice would let a playbook say two different things.

    Each branch gets its **own context**, snapshotted from the run before
    the branches start. Sharing one dict would make the merged result
    depend on which branch finished first, and two branches enriching the
    same indicator would race to overwrite each other.
    """
    branches = step.steps
    if not branches:
        return StepStatus.FAILED, {
            "executed": False,
            "error": "a parallel step with no branches runs nothing; declare its `steps` or remove it",
        }
    if len(branches) > ABSOLUTE_MAX_PARALLEL_BRANCHES:
        return StepStatus.FAILED, {
            "executed": False,
            "error": f"a parallel step may fan out to at most {ABSOLUTE_MAX_PARALLEL_BRANCHES} branches; this one declares {len(branches)}",
        }

    join = str(step.params.get("join") or "all").strip().lower()
    if join not in {"all", "any"}:
        return StepStatus.FAILED, {"executed": False, "error": f"unknown join {join!r}; expected 'all' or 'any'"}

    async def _branch(index: int, child: PlaybookStep) -> tuple[bool, dict]:
        branch_path = idempotency.child_path(path, "b", index)
        context = dict(pr.context)
        if child.condition and not _evaluate_condition(child.condition, context):
            return True, {"step_id": child.id, "name": child.name, "status": StepStatus.SKIPPED}
        status, result = await _invoke_step(child, _scoped_run(pr, context), http, dry_run=dry_run, path=branch_path)
        return status != StepStatus.FAILED, {"step_id": child.id, "name": child.name, "status": status, "result": result}

    outcomes = await asyncio.gather(*(_branch(i, child) for i, child in enumerate(branches)))
    succeeded = [ok for ok, _ in outcomes]
    results = [record for _, record in outcomes]

    joined = all(succeeded) if join == "all" else any(succeeded)
    payload: dict[str, Any] = {
        "join": join,
        "branches": results,
        "branches_succeeded": sum(1 for ok in succeeded if ok),
        "branches_total": len(results),
    }
    if not joined:
        payload["error"] = f"{len(results) - sum(succeeded)} of {len(results)} parallel branches failed under join {join!r}"
    return (StepStatus.SUCCESS if joined else StepStatus.FAILED), payload


async def _control_loop(
    step: PlaybookStep,
    pr: PlaybookRun,
    http: httpx.AsyncClient,
    *,
    dry_run: bool,
    path: tuple[str, ...],
) -> tuple[StepStatus, dict]:
    """Run the child steps once per item, bounded.

    ``over`` is a dot-path into the run context — never a literal list in
    the playbook, which would make the loop a copy-paste of its body. The
    list it resolves to routinely came out of an enrichment response, which
    is to say out of attacker-influenced data, so the iteration count is
    capped and the cap is reported rather than silently truncating.

    Each iteration binds ``item`` and ``index`` into a context of its own,
    so a later iteration cannot read a value an earlier one left behind
    unless the author asked for it through the loop's own result.
    """
    if not step.steps:
        return StepStatus.FAILED, {
            "executed": False,
            "error": "a loop step with no body runs nothing; declare its `steps` or remove it",
        }

    over = str(step.params.get("over") or "").strip()
    if not over:
        return StepStatus.FAILED, {"executed": False, "error": "a loop step needs `over`, a dot-path into the run context"}

    items = _resolve_field(pr.context, over)
    if items is None:
        # Distinct from an empty list below: "the path resolved to nothing"
        # is usually a typo in the path, and reporting it as "zero items"
        # sends the author looking at their data instead of their playbook.
        return StepStatus.FAILED, {"executed": False, "error": f"loop `over` path {over!r} resolved to nothing in the run context"}
    if not isinstance(items, list | tuple):
        return StepStatus.FAILED, {
            "executed": False,
            "error": f"loop `over` path {over!r} resolved to a {type(items).__name__}, not a list",
        }

    requested = len(items)
    ceiling = min(
        int(step.params.get("max_iterations") or DEFAULT_MAX_LOOP_ITERATIONS),
        ABSOLUTE_MAX_LOOP_ITERATIONS,
    )
    truncated = requested > ceiling
    items = list(items)[:ceiling]

    iterations: list[dict] = []
    failures = 0
    for index, item in enumerate(items):
        context = dict(pr.context)
        context["item"] = item
        context["index"] = index
        ok, results = await _run_children(
            step,
            pr,
            http,
            dry_run=dry_run,
            path=idempotency.child_path(path, "i", index),
            context=context,
        )
        iterations.append({"index": index, "item": item, "steps": results})
        if not ok:
            failures += 1
            if step.params.get("on_item_failure", "continue") == "abort":
                break

    payload: dict[str, Any] = {
        "over": over,
        "items_seen": requested,
        "iterations_run": len(iterations),
        "iterations": iterations,
        "failed_iterations": failures,
    }
    if truncated:
        # Said out loud. A loop that quietly stopped at 25 of 300 sessions
        # leaves 275 live and a run record that reads as a clean sweep.
        payload["truncated"] = True
        payload["error"] = (
            f"loop over {over!r} had {requested} items and the ceiling is {ceiling}; {requested - ceiling} were not processed"
        )
        return StepStatus.FAILED, payload
    if failures:
        payload["error"] = f"{failures} of {len(iterations)} loop iterations failed"
        return StepStatus.FAILED, payload
    return StepStatus.SUCCESS, payload


#: Step types the run loop hands to a control-flow coroutine rather than to
#: ``_HANDLERS``. Keyed here rather than tested with an ``in`` against a set
#: so a type added to one and not the other cannot silently fall through to
#: "no handler".
_CONTROL_FLOW: dict[StepType, Any] = {
    StepType.WAIT: _control_wait,
    StepType.PARALLEL: _control_parallel,
    StepType.LOOP: _control_loop,
}


async def _invoke_step(
    step: PlaybookStep,
    pr: PlaybookRun,
    http: httpx.AsyncClient,
    *,
    dry_run: bool,
    path: tuple[str, ...] = (),
) -> tuple[StepStatus, dict]:
    """Run one step and report ``(status, result)``.

    Lifted out of ``PlaybookEngine.run`` unchanged so ``parallel`` and
    ``loop`` execute their children through exactly the same path as a
    top-level step — the retry policy, the permanent-failure rule and the
    ``executed`` check are properties of a step, not of where it sits in a
    playbook. A second copy for children would be a second place for "a
    handler that returned is not a step that ran" to drift out of.

    What stays in the caller: branching, cycle detection and the approval
    suspension, all of which are about a step's *position* in a run rather
    than about running it.

    ``path`` is the control-flow coordinates (``("b1", "i3")``). It reaches
    only the idempotency key, which is the one thing that has to tell the
    third loop iteration from the fourth.
    """
    result: dict = {}
    step_status = StepStatus.SUCCESS
    attempt = 0
    handler = _HANDLERS.get(step.type)
    unbridgeable = _UNBRIDGEABLE.get(step.type)
    idempotency_key = idempotency.step_key(run_id=pr.run_id, step_id=step.id, path=path)

    if step.type in _CONTROL_FLOW:
        # Control flow needs the run, the client and the dry-run flag, none
        # of which a `_HANDLERS` entry receives. Routed here rather than by
        # widening the handler signature, so the fifteen response verbs are
        # not handed a mutable run object they have no business touching.
        step_status, result = await _CONTROL_FLOW[step.type](step, pr, http, dry_run=dry_run, path=path)
        result["idempotency_key"] = idempotency_key
        return step_status, result

    if handler is None and not dry_run:
        # Fail closed, and skip the retry loop — a missing handler
        # will still be missing on the next attempt.
        #
        # This branch used to return ``{"skipped": True}`` while
        # leaving step_status at SUCCESS, so twelve of the
        # twenty-two declared step types reported that they had run
        # when nothing had. The worst of them was ``approval``: a
        # human decision point that passed on its own and let the
        # run continue into the very action an analyst was supposed
        # to authorise. Falling through to the shared tail below
        # means the default ``on_failure: abort`` halts the run.
        step_status = StepStatus.FAILED
        result = {
            "error": (
                f"step type {step.type.value!r} is not runnable: {unbridgeable}"
                if unbridgeable
                else f"step type {step.type.value!r} has no handler in this engine"
            ),
            "unimplemented": True,
            "executed": False,
            "_elapsed_ms": 0,
        }
        logger.error(
            "Step %s (%s) has no handler; failing closed rather than reporting success",
            step.name,
            step.type.value,
        )
    else:
        while True:
            attempt += 1
            t0 = time.perf_counter()
            try:
                if dry_run:
                    result = {"dry_run": True, "executed": False, "step": step.name}
                    if handler is None:
                        # A dry run exists to tell the author what
                        # would happen. "dry_run: true" alone would
                        # imply this step is fine.
                        result["unimplemented"] = True
                        result["would_fail"] = True
                        if unbridgeable:
                            result["reason"] = unbridgeable
                    elif step.type in RESPONSE_STEP_TYPES:
                        # Name the verb a live run would dispatch,
                        # so a preview of a containment playbook
                        # reads as a containment playbook.
                        result["would_dispatch"] = step.type.value
                        result["target"] = _resolve_target(step, pr.context)
                else:
                    result = await handler(step, pr.context, http)
                elapsed = time.perf_counter() - t0
                result["_elapsed_ms"] = round(elapsed * 1000)
                # A handler that returned is not a step that ran.
                # Every response verb reports `executed`, and a
                # False there means the action was previewed, held
                # for an analyst, blocked, unconfigured or refused
                # — none of which is a step that did what it says.
                # Reporting those as SUCCESS is the defect this
                # whole path exists to remove, so they fail closed
                # and the default `on_failure: abort` halts the run.
                if step.type in RESPONSE_STEP_TYPES and not result.get("executed"):
                    step_status = StepStatus.FAILED
                    result.setdefault(
                        "error",
                        f"{step.type.value} did not execute ({result.get('status', 'unknown')}): "
                        f"{result.get('summary') or result.get('detail') or 'no vendor was touched'}",
                    )
                break  # the handler answered; status is set above
            except Exception as exc:  # noqa: BLE001
                elapsed = time.perf_counter() - t0
                # A permanent failure will not become a different
                # failure by being asked again. Sleeping 2s, 4s
                # then 8s before repeating "this run has no
                # tenant" costs an operator fourteen seconds of an
                # incident and, worse, dresses a misconfiguration
                # up as flakiness — so they wait for it to settle
                # instead of going and fixing it.
                permanent = isinstance(exc, PermanentStepFailure)
                logger.error(
                    "Step %s attempt %d failed (%s): %s",
                    step.name,
                    attempt,
                    "permanent, not retried" if permanent else "retryable",
                    exc,
                )
                if not permanent and attempt <= step.retry_max:
                    await asyncio.sleep(min(2**attempt, 30))
                else:
                    step_status = StepStatus.FAILED
                    result = {
                        "error": str(exc),
                        # Says, in the run record, why there was
                        # one attempt and not four.
                        "permanent": permanent,
                        "attempts": attempt,
                        "_elapsed_ms": round(elapsed * 1000),
                    }
                    break

    result["idempotency_key"] = idempotency_key
    return step_status, result


class PlaybookEngine:
    """Executes playbooks step-by-step, emitting realtime events."""

    async def resume(self, playbook: Playbook, pause: Any) -> PlaybookRun:
        """Continue a suspended run from the step after its approval.

        Rebuilds the run from what was stored rather than re-running the
        first half: the steps before the approval already executed, and
        repeating them would re-send notifications and re-dispatch
        actions.
        """
        return await self.run(
            playbook,
            pause.run_context,
            resume_from=pause.resume_index,
            resume_run_id=pause.run_id,
            resume_results=pause.step_results,
        )

    async def run(
        self,
        playbook: Playbook,
        trigger_context: dict[str, Any],
        *,
        dry_run: bool = False,
        resume_from: int = 0,
        resume_run_id: str | None = None,
        resume_results: list[dict[str, Any]] | None = None,
    ) -> PlaybookRun:
        pr = PlaybookRun(playbook, trigger_context)
        if resume_run_id:
            # Keep the original run id, so a resumed run stays one run in
            # the realtime stream and the ledger rather than appearing as
            # a second, unrelated one that starts halfway through.
            pr.run_id = resume_run_id
        if resume_results:
            pr.step_results = list(resume_results)
        pr.started_at = datetime.now(UTC).isoformat()
        pr.status = RunStatus.RUNNING

        async with httpx.AsyncClient() as http:
            await _emit(pr.run_id, "run.started", {"playbook": playbook.name, "dry_run": dry_run}, http)

            # Build a step index for branching
            step_index = {s.id: i for i, s in enumerate(playbook.steps)}
            visited: set[str] = set()
            current_idx = resume_from
            if resume_from:
                # The steps before the approval already ran. Marking them
                # visited keeps the cycle detector honest without
                # re-executing them.
                for earlier in playbook.steps[:resume_from]:
                    visited.add(earlier.id)

            while current_idx < len(playbook.steps):
                step = playbook.steps[current_idx]

                if step.id in visited:
                    logger.warning("Cycle detected at step %s, aborting", step.id)
                    pr.status = RunStatus.FAILED
                    pr.error = f"cycle at step {step.id}"
                    break
                visited.add(step.id)

                # Condition gate
                condition_passed = True
                if step.condition:
                    condition_passed = _evaluate_condition(step.condition, pr.context)

                if not condition_passed:
                    pr.step_results.append({"step_id": step.id, "name": step.name, "status": StepStatus.SKIPPED})
                    # Branching: use next_false if set
                    if step.next_false and step.next_false in step_index:
                        current_idx = step_index[step.next_false]
                    else:
                        current_idx += 1
                    continue

                # CONDITION type — just branch, no external action
                if step.type == StepType.CONDITION:
                    branch_id = step.next_true if condition_passed else step.next_false
                    if branch_id and branch_id in step_index:
                        current_idx = step_index[branch_id]
                    else:
                        current_idx += 1
                    pr.step_results.append({"step_id": step.id, "name": step.name, "status": StepStatus.SUCCESS, "branch": branch_id})
                    continue

                await _emit(pr.run_id, "step.started", {"step": step.name, "type": step.type}, http)

                # Parity 5.2. An approval step is a pause, and this engine
                # had nowhere to pause to, so it failed closed and 12
                # shipped playbooks aborted here. The position and the
                # context go to Postgres, because "survives restarts" is
                # the requirement and an in-memory pause is lost by the
                # thing most likely to interrupt a long approval.
                if step.type == StepType.APPROVAL and not dry_run:
                    pause = await _suspend_for_approval(pr, step, current_idx, http)
                    if pause is not None:
                        pr.status = RunStatus.PAUSED
                        pr.step_results.append(
                            {
                                "step_id": step.id,
                                "name": step.name,
                                "status": StepStatus.PENDING,
                                "paused": True,
                                "pause_id": pause.id,
                                "approval_id": pause.approval_id,
                                "expires_at": pause.expires_at.isoformat(),
                            }
                        )
                        await _emit(
                            pr.run_id,
                            "run.paused",
                            {"step": step.name, "pause_id": pause.id},
                            http,
                        )
                        break
                    # The pause could not be written, so nothing can resume
                    # this run. Falling through fails the step closed, which
                    # is correct: continuing past an approval nobody can
                    # grant is the original defect this replaced.
                    logger.error(
                        "Approval step %s could not be suspended; failing closed rather than continuing into the action it gates",
                        step.name,
                    )

                step_status, result = await _invoke_step(step, pr, http, dry_run=dry_run)

                pr.step_results.append({"step_id": step.id, "name": step.name, "status": step_status, "result": result})
                # Merge result into context for downstream steps. The namespaced
                # key ``_step_<id>`` always reflects this step's full result.
                pr.context[f"_step_{step.id}"] = result
                # Flatten top-level keys for convenience so downstream steps can
                # reference ``alert.severity`` or ``user_id`` directly without
                # the ``_step_<id>.`` prefix. We *overwrite* prior values so a
                # later enrichment step can refine context (e.g. replacing a
                # placeholder ``user_id`` from the trigger with the resolved
                # canonical id). Keys starting with ``_`` are reserved for
                # engine bookkeeping and never auto-flattened.
                for k, v in result.items():
                    if not k.startswith("_"):
                        pr.context[k] = v

                await _emit(
                    pr.run_id,
                    "step.done",
                    {
                        "step": step.name,
                        "status": step_status,
                        "result_keys": list(result.keys()),
                    },
                    http,
                )

                if step_status == StepStatus.FAILED and step.on_failure == "abort":
                    pr.status = RunStatus.FAILED
                    pr.error = f"step '{step.name}' failed"
                    break

                # Advance: branching on success
                if step_status == StepStatus.SUCCESS and step.next_true and step.next_true in step_index:
                    current_idx = step_index[step.next_true]
                else:
                    current_idx += 1

            if pr.status == RunStatus.RUNNING:
                # `on_failure: continue` decides whether the run keeps going.
                # It does not decide what the run is called afterwards, and
                # 346 of the 380 steps in the shipped packs carry it — so
                # reading it as "report this as completed" would put a green
                # tick over a containment that never happened, which is the
                # failure this whole path exists to remove. The run finished;
                # it did not do everything it said.
                failed = [r["name"] for r in pr.step_results if r["status"] == StepStatus.FAILED]
                if failed:
                    pr.status = RunStatus.FAILED
                    shown = ", ".join(f"'{name}'" for name in failed[:3])
                    more = f" and {len(failed) - 3} more" if len(failed) > 3 else ""
                    pr.error = (
                        f"{len(failed)} of {len(pr.step_results)} steps failed ({shown}{more}); the run continued past them by policy"
                    )
                else:
                    pr.status = RunStatus.COMPLETED

            pr.finished_at = datetime.now(UTC).isoformat()
            await _emit(pr.run_id, "run.done", pr.to_dict(), http)

        return pr

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
import time
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import httpx

from .models import Playbook, PlaybookStep, StepCondition, StepType

logger = logging.getLogger("aisoc.playbook.engine")

_REALTIME_URL = os.getenv("REALTIME_URL", "http://realtime:3001")
_INTERNAL_TOKEN = os.getenv("REALTIME_INTERNAL_TOKEN", "changeme")
_API_URL = os.getenv("API_URL", "http://api:8000")


# ---------------------------------------------------------------------------
# Run status
# ---------------------------------------------------------------------------


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


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
        self.status: RunStatus = RunStatus.PENDING
        self.trigger_context: dict[str, Any] = trigger_context
        # Accumulated output from previous steps — available to later steps as {{prev.*}}
        self.context: dict[str, Any] = dict(trigger_context)
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
        elif isinstance(cur, (list, tuple)):
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
    if isinstance(value, (int, float)):
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
        if isinstance(expected, (list, tuple, set)):
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
                if isinstance(rhs, (list, tuple, set)):
                    return lhs in rhs
                return str(lhs) in str(rhs)
            if op == "not_in":
                if rhs is None:
                    return True
                if isinstance(rhs, (list, tuple, set)):
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
    ioc = step.params.get("ioc") or context.get("ioc") or context.get("src_ip", "")
    ioc_type = step.params.get("ioc_type", "ip")
    r = await http.post(
        f"{_API_URL}/api/v1/enrichment/lookup",
        json={"ioc": ioc, "ioc_type": ioc_type},
        timeout=step.timeout_seconds,
    )
    r.raise_for_status()
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
        r = await http.post(url, json={"text": message}, timeout=step.timeout_seconds)
        return {"status": r.status_code}
    return {"channel": channel, "message": message, "delivered": False, "reason": "no url"}


async def _handle_http(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    method = step.params.get("method", "POST").upper()
    url = step.params.get("url", "")
    body = step.params.get("body", {})
    headers = step.params.get("headers", {})
    r = await http.request(method, url, json=body, headers=headers, timeout=step.timeout_seconds)
    return {"status": r.status_code, "body": r.text[:500]}


async def _handle_block_ip(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    ip = step.params.get("ip") or context.get("src_ip", "")
    return {"action": "block_ip", "ip": ip, "simulated": True}


async def _handle_isolate_host(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    host = step.params.get("host") or context.get("host", "")
    return {"action": "isolate_host", "host": host, "simulated": True}


async def _handle_create_ticket(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    return {"action": "create_ticket", "params": step.params, "simulated": True}


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
    # Import clients here to avoid circular imports at module load time.
    from app.clients.aisoc_direct_client import AiSOCDirectClient  # noqa: PLC0415
    from app.clients.fleetdm_client import FleetDMClient  # noqa: PLC0415
    from app.clients.osctrl_client import OsctrlClient  # noqa: PLC0415
    from app.clients.osquery_allowlist import AllowlistError  # noqa: PLC0415

    backend: str = step.params.get("backend", "osctrl")
    target_hosts: list[str] = step.params.get("target_hosts") or [context.get("host_id") or context.get("host", "")]
    template: str = step.params.get("template", "")
    template_params: dict[str, Any] = step.params.get("template_params") or {}
    timeout_seconds: int = step.params.get("timeout_seconds", 60)

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


_HANDLERS = {
    StepType.ENRICH: _handle_enrich,
    StepType.INVESTIGATE: _handle_investigate,
    StepType.NOTIFY: _handle_notify,
    StepType.HTTP: _handle_http,
    StepType.BLOCK_IP: _handle_block_ip,
    StepType.ISOLATE_HOST: _handle_isolate_host,
    StepType.CREATE_TICKET: _handle_create_ticket,
    StepType.CLOSE_CASE: _handle_close_case,
    StepType.OSQUERY_LIVE_QUERY: _handle_osquery_live_query,
}


# ---------------------------------------------------------------------------
# Realtime event helper
# ---------------------------------------------------------------------------


async def _emit(run_id: str, event_type: str, payload: dict, http: httpx.AsyncClient) -> None:
    try:
        await http.post(
            f"{_REALTIME_URL}/internal/agent-event",
            json={"channel": f"playbook:{run_id}", "type": event_type, "data": payload},
            headers={"x-internal-token": _INTERNAL_TOKEN},
            timeout=3,
        )
    except Exception:
        pass  # non-critical


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PlaybookEngine:
    """Executes playbooks step-by-step, emitting realtime events."""

    async def run(
        self,
        playbook: Playbook,
        trigger_context: dict[str, Any],
        *,
        dry_run: bool = False,
    ) -> PlaybookRun:
        pr = PlaybookRun(playbook, trigger_context)
        pr.started_at = datetime.now(UTC).isoformat()
        pr.status = RunStatus.RUNNING

        async with httpx.AsyncClient() as http:
            await _emit(pr.run_id, "run.started", {"playbook": playbook.name, "dry_run": dry_run}, http)

            # Build a step index for branching
            step_index = {s.id: i for i, s in enumerate(playbook.steps)}
            visited: set[str] = set()
            current_idx = 0

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

                result: dict = {}
                step_status = StepStatus.SUCCESS
                attempt = 0
                handler = _HANDLERS.get(step.type)

                while True:
                    attempt += 1
                    t0 = time.perf_counter()
                    try:
                        if dry_run:
                            result = {"dry_run": True, "step": step.name}
                        elif handler:
                            result = await handler(step, pr.context, http)
                        else:
                            result = {"skipped": True, "reason": f"no handler for {step.type}"}
                        elapsed = time.perf_counter() - t0
                        result["_elapsed_ms"] = round(elapsed * 1000)
                        break  # success
                    except Exception as exc:  # noqa: BLE001
                        elapsed = time.perf_counter() - t0
                        logger.error("Step %s attempt %d failed: %s", step.name, attempt, exc)
                        if attempt <= step.retry_max:
                            await asyncio.sleep(min(2**attempt, 30))
                        else:
                            step_status = StepStatus.FAILED
                            result = {"error": str(exc), "_elapsed_ms": round(elapsed * 1000)}
                            break

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
                pr.status = RunStatus.COMPLETED

            pr.finished_at = datetime.now(UTC).isoformat()
            await _emit(pr.run_id, "run.done", pr.to_dict(), http)

        return pr

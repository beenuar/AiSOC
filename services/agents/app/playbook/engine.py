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
    """Resolve a dot-path field from context, e.g. 'alert.severity'."""
    parts = field.split(".")
    cur: Any = context
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _evaluate_condition(condition: StepCondition, context: dict[str, Any]) -> bool:
    """Return True if the condition passes."""
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
        return expected in str(value) if value is not None else False
    if op == "gt":
        return float(value or 0) > float(expected or 0)
    if op == "lt":
        return float(value or 0) < float(expected or 0)
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


_HANDLERS = {
    StepType.ENRICH: _handle_enrich,
    StepType.INVESTIGATE: _handle_investigate,
    StepType.NOTIFY: _handle_notify,
    StepType.HTTP: _handle_http,
    StepType.BLOCK_IP: _handle_block_ip,
    StepType.ISOLATE_HOST: _handle_isolate_host,
    StepType.CREATE_TICKET: _handle_create_ticket,
    StepType.CLOSE_CASE: _handle_close_case,
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
                    pr.step_results.append(
                        {"step_id": step.id, "name": step.name, "status": StepStatus.SKIPPED}
                    )
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
                    pr.step_results.append(
                        {"step_id": step.id, "name": step.name, "status": StepStatus.SUCCESS, "branch": branch_id}
                    )
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
                            await asyncio.sleep(min(2 ** attempt, 30))
                        else:
                            step_status = StepStatus.FAILED
                            result = {"error": str(exc), "_elapsed_ms": round(elapsed * 1000)}
                            break

                pr.step_results.append(
                    {"step_id": step.id, "name": step.name, "status": step_status, "result": result}
                )
                # Merge result into context for downstream steps
                pr.context.update({f"_step_{step.id}": result})
                # Also flatten top-level keys without underscore prefix for convenience
                for k, v in result.items():
                    if not k.startswith("_"):
                        pr.context.setdefault(k, v)

                await _emit(pr.run_id, "step.done", {
                    "step": step.name,
                    "status": step_status,
                    "result_keys": list(result.keys()),
                }, http)

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

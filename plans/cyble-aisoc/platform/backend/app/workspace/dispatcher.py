"""@agent mention dispatcher (Theme 2l).

When the API layer persists a ``mention`` workspace op, it hands the
mention(s) off to this dispatcher. The dispatcher:

1. **Acknowledges synchronously.** For every dispatchable agent named in
   the mention, it appends an ``agent.started`` op to the workspace
   *before* the agent actually runs. This is what gives the UI a live
   "Investigator is looking at this…" pill the instant the analyst hits
   send — even if the LLM call later takes 30 seconds.

2. **Runs the agent on its own task / session.** Agents are async and
   can take a long time. We never block the request that posted the
   mention on agent execution. The dispatcher opens its own
   :func:`session_scope` so the agent's DB writes are in a separate
   transaction from the originating request.

3. **Closes the loop.** When the agent returns (or raises), the
   dispatcher writes an ``agent.finished`` op with the agent's summary
   so connected clients get the result inline in the workspace, not
   buried in the case detail panel.

Failure modes we deliberately surface, not hide
-----------------------------------------------

* Mention names an agent that has no runnable class. Some entries in
  :data:`app.workspace.mentions._DISPATCHABLE` exist for UX (so the
  parser will recognize ``@detection``) but aren't first-class
  ``BaseAgent`` subclasses yet. We still emit ``agent.finished`` with
  an explanatory summary so the analyst sees their request was acked.

* Agent raises during ``run()``. We catch the exception, log it, and
  emit ``agent.finished`` with a sanitized error string. Letting an
  unhandled exception escape the background task would silently leave
  the UI stuck on "Investigator is looking at this…" forever.

* Case has been deleted / belongs to another tenant between mention
  time and dispatch time. We re-check tenant scope inside the
  background task and bail out with a finish op that says "case not
  found" so we don't operate against a stale case id.

Separation from the workspace service
-------------------------------------

The dispatcher and :mod:`app.workspace.service` are intentionally
distinct modules. ``service.apply_op`` is sync, transactional, and
called from request-handling threads (humans typing). The dispatcher
is async, opens its own session, and runs in the background. Mixing
them would leak the synchronous transaction boundary into agent
execution, and a slow agent run would block keystroke-rate writes.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable

from app.agents.base import AgentResult, BaseAgent
from app.agents.cdr import CDRAgent
from app.agents.investigator import InvestigatorAgent
from app.agents.itdr import ITDRAgent
from app.agents.phishing_triage import PhishingTriageAgent
from app.agents.reporter import ReporterAgent
from app.agents.responder import ResponderAgent
from app.agents.saas_posture import SaaSPostureAgent
from app.agents.triager import TriagerAgent
from app.db import session_scope
from app.models.case import Case
from app.models.trace import AgentName
from app.models.workspace import WorkspaceAuthorKind, WorkspaceOpKind
from app.workspace.service import apply_op

log = logging.getLogger(__name__)


# ── Runtime agent registry ─────────────────────────────────────────────
# This mirrors :data:`app.agents.orchestrator.AGENT_MAP`, but we keep
# our own copy so the dispatcher can decide independently which agents
# are reachable from a workspace mention. (For example, the orchestrator
# may chain through ``REPORTER`` automatically, while a workspace
# mention of ``@reporter`` should also work as a manual entry point.)
#
# Agents listed in :data:`app.workspace.mentions._DISPATCHABLE` that
# don't appear here are *parseable but not runnable*: we still ack the
# mention with a started/finished pair so the analyst sees a response.
DISPATCHABLE_AGENTS: dict[AgentName, type[BaseAgent]] = {
    AgentName.TRIAGER: TriagerAgent,
    AgentName.INVESTIGATOR: InvestigatorAgent,
    AgentName.ITDR: ITDRAgent,
    AgentName.CDR: CDRAgent,
    AgentName.SAAS_POSTURE: SaaSPostureAgent,
    AgentName.PHISHING_TRIAGE: PhishingTriageAgent,
    AgentName.RESPONDER: ResponderAgent,
    AgentName.REPORTER: ReporterAgent,
}


# Cap on concurrent agent runs across the whole process. A single
# enthusiastic analyst typing ``@investigator @responder @reporter
# @triager`` shouldn't be able to spin up unbounded background tasks
# and burn through the LLM quota in one keystroke. The semaphore is
# generous (we expect typical concurrency in single digits) but not
# infinite.
_DISPATCH_SEMAPHORE = asyncio.Semaphore(8)


def dispatch_mentions(
    *,
    tenant_id: str,
    case_id: int,
    mention_op_id: int,
    agents: Iterable[AgentName],
    requested_by: str = "unknown",
) -> list[asyncio.Task[None]]:
    """Fan a parsed mention out to one background task per agent.

    The caller (the API route handler) must have already persisted the
    parent ``mention`` op and committed its session. We pass
    ``mention_op_id`` (not the op object) because the agent's
    background task will look it up in its own session — passing an
    ORM object across sessions is the canonical way to corrupt
    transactional state in SQLAlchemy.

    ``agents`` must be the deduplicated list of agents (see
    :func:`app.workspace.mentions.unique_agents`). We do *not*
    re-deduplicate here — emitting one ``agent.started`` per duplicate
    mention would be visually confusing in the workspace.

    Returns the list of asyncio tasks for the agent runs so the caller
    (or tests) can ``await`` them in deterministic order. Callers that
    don't care can ignore the return value; tasks are scheduled on the
    running loop and will execute regardless.
    """
    loop = _get_running_loop_or_warn(tenant_id=tenant_id, case_id=case_id)

    tasks: list[asyncio.Task[None]] = []
    for agent in agents:
        # Synchronously record that we acknowledged the mention. This
        # has to happen on the caller's session (which is already
        # committed by the time we're invoked from the route handler)
        # so the analyst sees an immediate "started" event without
        # waiting for the background task to schedule.
        with session_scope() as s:
            try:
                apply_op(
                    s,
                    case_id=case_id,
                    tenant_id=tenant_id,
                    kind=WorkspaceOpKind.AGENT_STARTED.value,
                    payload={
                        "agent": agent.value,
                        "mention_op_id": mention_op_id,
                        "requested_by": requested_by,
                    },
                    author_kind=WorkspaceAuthorKind.SYSTEM.value,
                    author_id="dispatcher",
                )
            except Exception:
                # If we can't even ack, don't queue the run — a missing
                # start op would orphan the finish op on the UI.
                log.exception(
                    "dispatcher: failed to record agent.started "
                    "tenant=%s case=%s agent=%s mention_op_id=%s",
                    tenant_id, case_id, agent.value, mention_op_id,
                )
                continue

        if loop is None:
            # No running loop: we're in a sync context (e.g. a smoke
            # test). Skip scheduling — the started op is durable and
            # callers can drive the agent themselves if they want.
            continue

        task = loop.create_task(
            _run_agent(
                tenant_id=tenant_id,
                case_id=case_id,
                mention_op_id=mention_op_id,
                agent=agent,
            )
        )
        tasks.append(task)
    return tasks


async def _run_agent(
    *,
    tenant_id: str,
    case_id: int,
    mention_op_id: int,
    agent: AgentName,
) -> None:
    """Background task: run one agent for one mention.

    Wraps the agent execution with the cross-process concurrency
    semaphore, a fresh session, tenant re-validation, and a try /
    except / finally that *always* emits ``agent.finished`` (with the
    summary on success, or a sanitized error on failure). Without the
    guaranteed finish op the UI would stay stuck on the started
    indicator forever.
    """
    async with _DISPATCH_SEMAPHORE:
        agent_cls = DISPATCHABLE_AGENTS.get(agent)
        if agent_cls is None:
            _emit_finished(
                tenant_id=tenant_id,
                case_id=case_id,
                mention_op_id=mention_op_id,
                agent=agent,
                summary=(
                    f"@{agent.value} is recognized but has no runnable "
                    f"agent implementation yet."
                ),
                ok=False,
            )
            return

        summary = ""
        ok = True
        try:
            with session_scope() as s:
                case = s.get(Case, case_id)
                if case is None or case.tenant_id != tenant_id:
                    _emit_finished(
                        tenant_id=tenant_id,
                        case_id=case_id,
                        mention_op_id=mention_op_id,
                        agent=agent,
                        summary="case not found (deleted or cross-tenant)",
                        ok=False,
                    )
                    return

                runner = agent_cls(s, case_id, tenant_id)
                try:
                    result: AgentResult = await runner.run()
                    summary = result.summary or f"{agent.value} completed"
                except Exception as exc:
                    log.exception(
                        "dispatcher: agent %s raised during run "
                        "tenant=%s case=%s",
                        agent.value, tenant_id, case_id,
                    )
                    summary = f"{agent.value} failed: {exc}"
                    ok = False
        except Exception:
            # session_scope() itself blew up (DB unavailable, etc.).
            # We still want a finish op so the UI doesn't hang.
            log.exception(
                "dispatcher: session failure while running %s "
                "tenant=%s case=%s",
                agent.value, tenant_id, case_id,
            )
            summary = f"{agent.value} failed: internal error"
            ok = False

        _emit_finished(
            tenant_id=tenant_id,
            case_id=case_id,
            mention_op_id=mention_op_id,
            agent=agent,
            summary=summary,
            ok=ok,
        )


def _emit_finished(
    *,
    tenant_id: str,
    case_id: int,
    mention_op_id: int,
    agent: AgentName,
    summary: str,
    ok: bool,
) -> None:
    """Best-effort write of the closing ``agent.finished`` op.

    Opens a fresh session — we never reuse the agent's session for the
    finish op because the agent may have left its session in a
    rolled-back state.
    """
    try:
        with session_scope() as s:
            apply_op(
                s,
                case_id=case_id,
                tenant_id=tenant_id,
                kind=WorkspaceOpKind.AGENT_FINISHED.value,
                payload={
                    "agent": agent.value,
                    "mention_op_id": mention_op_id,
                    "summary": summary,
                    "ok": ok,
                },
                # ``agent.finished`` carries the agent's actual output,
                # so the UI should attribute it to the agent (avatar,
                # badge) — not to the dispatcher.
                author_kind=WorkspaceAuthorKind.AGENT.value,
                author_id=agent.value,
            )
    except Exception:
        # If we can't even record the failure, log it loudly — the
        # workspace UI will be stuck, but there's nothing more this
        # task can do.
        log.exception(
            "dispatcher: failed to record agent.finished "
            "tenant=%s case=%s agent=%s mention_op_id=%s",
            tenant_id, case_id, agent.value, mention_op_id,
        )


def _get_running_loop_or_warn(
    *, tenant_id: str, case_id: int
) -> asyncio.AbstractEventLoop | None:
    """Return the currently running loop or None.

    We log a warning rather than raise because the parent caller
    (the route handler) has already committed the mention op and the
    analyst's UI has rendered it. Raising here would 500 the request
    even though the workspace state is fine.
    """
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        log.warning(
            "dispatcher: no running event loop, agent run deferred "
            "tenant=%s case=%s",
            tenant_id, case_id,
        )
        return None

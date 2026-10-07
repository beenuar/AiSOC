"""Orchestrate one replay evaluation across three services, then score it.

Gap-closure Phase 1.4.

Why this lives in the API
-------------------------
No process can hold two of these services. ``services/actions`` owns the SIEM
credential path and the history readers; ``services/agents`` owns triage;
``services/connectors`` owns ``normalize()``. All three package their code as
top-level ``app``, so a process that imported two of them would import two
modules called ``app`` and get one of them.

The API is the service that already does this. It holds the vault and the
tenant session, it already proxies ``/cases/{id}/investigate`` to agents, and
it already dispatches live actions to actions. So it reads the history from
actions, hands it to agents for the shadow triage, and scores the result with
the vendored benchmark package, which is the one link in the chain with no
round trip.

The chain, and where each link can fail
---------------------------------------
1. the connector row, tenant-scoped, and its vault-decrypted credentials
2. ``POST {actions}/api/v1/replay/history`` for the closed findings
3. ``POST {agents}/api/v1/replay/run`` for the shadow decisions, which itself
   reaches the connectors service for the production ``normalize()``
4. ``score_replay`` and ``format_replay_report``, in process
5. one write of the report and the decisions behind it

Every failure is terminal and carries its reason onto the row. There is no
partial result: a run that read half a window and scored it would publish a
number over whichever findings happened to arrive, and the report would look
exactly like one that worked.

Determinism
-----------
Nothing here contributes a timestamp, a random value or an unsorted iteration
to the report. The seed and the resample count travel from the request onto
the row and into the renderer's method section, so two runs over the same
history with the deterministic model path produce the same bytes. The wall
clock appears only in ``created_at`` / ``started_at`` / ``completed_at``, which
are columns rather than report content.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app._vendor.aisoc_benchmark.replay import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    format_replay_report,
    score_replay,
)
from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services.actions_client import base_url as actions_base_url
from app.services.actions_client import service_headers as actions_headers
from app.services.replay_evaluation import store
from app.services.replay_evaluation.vendors import (
    UnsupportedConnector,
    credentials_for,
)

log = structlog.get_logger(__name__)

__all__ = [
    "BOOTSTRAP_RESAMPLES",
    "BOOTSTRAP_SEED",
    "ReplayJobError",
    "ReplayRequest",
    "run_evaluation",
]

#: A window of a few hundred findings through a model is not a fast call. The
#: ceiling is generous on purpose: a timeout that fires mid-run would record a
#: failure for a job that was working.
_HISTORY_TIMEOUT_S = 180.0
_REPLAY_TIMEOUT_S = 1800.0

#: Caps on the frozen context. Production's triage prompt reads the same
#: ceiling for statements (`analyst_feedback.active_statements`), and a prior
#: list is bounded because a tenant with a long history would otherwise push
#: a multi-megabyte body through a call that already carries the findings.
_STATEMENT_LIMIT = 200
_PRIOR_LIMIT = 2000

#: Written by `app.services.human_priors` and by the agents-side
#: `app.memory.outcomes`; both spell the key this way. The replay sends the
#: bare signature, because that is what the agents side looks a prior up by.
_OUTCOME_KEY_PREFIX = "outcome:"


class ReplayJobError(Exception):
    """A link in the chain failed. The message is what lands on the row.

    Carries no partial result by design. The caller records it as a terminal
    failure with this reason, which is the difference between an operator
    knowing their Splunk credentials expired and an operator reading a
    confident report over eleven findings.
    """


@dataclass(frozen=True)
class ReplayRequest:
    """One evaluation as the route resolved it, tenant already from the credential."""

    tenant_id: uuid.UUID
    evaluation_id: uuid.UUID
    connector_row_id: uuid.UUID
    connector_type: str
    vendor: str
    window_start: datetime
    window_end: datetime
    train_fraction: float
    limit: int
    bootstrap_seed: int
    bootstrap_resamples: int

    #: Gap-closure Phase 6.2. Tenant skills to hand the replay as frozen
    #: context, carrying their ``activated_at`` so the agents side can drop
    #: any activated after the split. ``None`` means "send no context block",
    #: which is what an ordinary replay does and is byte-identical to the
    #: behaviour before this field existed.
    skills: tuple[dict[str, Any], ...] | None = None

    #: The one skill a backtest is measuring, applied to the whole test window
    #: even though it was authored after it. Travels separately from
    #: ``skills`` all the way to the report's method note, where it is named
    #: and caveated, because an accuracy figure produced by guidance written
    #: after the window is a statement about that window and not a forecast.
    skill_under_test: dict[str, Any] | None = None


def _agents_base_url() -> str:
    """Where the agents service lives.

    Read exactly the way ``endpoints/cases.py`` reads it for the investigate
    proxy, including both spellings, so a deployment that configured one of
    them does not have to learn a third name for this call. Resolved per call
    rather than at import so a test can point it at a local server.
    """
    raw = os.getenv("AGENTS_SERVICE_URL") or os.getenv("AGENTS_API_URL") or "http://agents:8084"
    return raw.rstrip("/")


def _agents_headers(tenant_id: uuid.UUID) -> dict[str, str]:
    """Service credential plus the tenant this call acts for.

    The agents service resolves a service token with no tenant header to an
    **empty** scope and refuses, rather than widening to every tenant. So the
    header is always sent, and it always carries the tenant the route took
    from the caller's credential.
    """
    token = (os.getenv("AISOC_AGENTS_SERVICE_TOKEN") or os.getenv("AISOC_SERVICE_TOKEN") or "").strip()
    headers = {"Accept": "application/json", "X-AiSOC-Tenant-ID": str(tenant_id)}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _load_connector(db: AsyncSession, request: ReplayRequest) -> tuple[str, dict[str, Any]]:
    """The connector's type and its decrypted credentials, scoped to the tenant.

    Returns the credential mapping the actions readers expect, not the raw
    ``auth_config``: the translation lives in one place and this is where it
    is applied.
    """
    row = (
        await db.execute(
            select(Connector).where(
                Connector.id == request.connector_row_id,
                Connector.tenant_id == request.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise ReplayJobError("the connector was not found for this tenant")

    try:
        decrypted = get_vault().decrypt_dict(row.auth_config or {})
    except CredentialVaultError as exc:
        raise ReplayJobError(
            f"stored credentials for this connector could not be decrypted ({exc}); "
            f"the vault key that wrote them is not in the current keyring"
        ) from exc

    try:
        credentials = credentials_for(row.connector_type, decrypted, row.connector_config or {})
    except UnsupportedConnector as exc:
        raise ReplayJobError(str(exc)) from exc
    return row.connector_type, credentials


async def _read_history(request: ReplayRequest, credentials: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "vendor": request.vendor,
        "credentials": credentials,
        "since": request.window_start.isoformat(),
        "until": request.window_end.isoformat(),
        "limit": request.limit,
    }
    # The two vendor-specific knobs the readers take. Sent only when the
    # connector stored one, so the reader keeps its own default otherwise.
    if credentials.get("search_override"):
        payload["search_override"] = credentials["search_override"]
    if credentials.get("index"):
        payload["index"] = credentials["index"]

    url = f"{actions_base_url()}/api/v1/replay/history"
    try:
        async with httpx.AsyncClient(timeout=_HISTORY_TIMEOUT_S) as client:
            response = await client.post(url, headers=actions_headers(), json=payload)
    except httpx.HTTPError as exc:
        raise ReplayJobError(f"the actions service is unreachable at {actions_base_url()}: {exc}") from exc

    if response.status_code >= 400:
        raise ReplayJobError(f"reading {request.vendor} history failed with HTTP {response.status_code}: {response.text[:400]}")
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("findings"), list):
        raise ReplayJobError("the actions service returned an unexpected history shape")
    return body


@dataclass(frozen=True)
class FrozenContextCapture:
    """What production would have had, read at capture time with its dates.

    The split filter is **not** applied here. Each row travels with its own
    recorded time and `capture_context` on the agents side drops the late
    ones, so "what counts as after the split" is decided in one place rather
    than re-implemented either side of an HTTP call -- the drift this
    repository keeps finding between two surfaces over the same rows.

    `unread` names each part that could not be read. A replay must not die
    because institutional memory was briefly unavailable, but it must not
    quietly report a score produced with less context than it claims either,
    so the gap is published in the method note.
    """

    statements: list[dict[str, Any]]
    priors: dict[str, dict[str, Any]]
    business_context: dict[str, Any] | None
    unread: tuple[str, ...]

    def as_payload(self, request: ReplayRequest) -> dict[str, Any]:
        return {
            "statements": self.statements,
            "priors": self.priors,
            "business_context": self.business_context,
            "skills": list(request.skills or ()),
            "skills_under_test": [request.skill_under_test] if request.skill_under_test else [],
        }


@asynccontextmanager
async def _optional_read(db: AsyncSession, part: str, unread: list[str]) -> AsyncIterator[None]:
    """Run one context read so a failure costs only that read.

    The savepoint is the whole point. PostgreSQL aborts the **entire**
    transaction on a failed statement and refuses everything after it with
    `current transaction is aborted, commands ignored until end of
    transaction block` -- so catching the exception and carrying on does not
    isolate the failure, it poisons the write that stores the report. A
    plain try/except here did exactly that: the replay scored correctly and
    then died on its own `UPDATE`, which reads as a storage bug rather than
    as a missing table.

    `begin_nested` issues a SAVEPOINT and rolls back to it, which is the
    only construct that confines a failed statement on this engine. Same
    finding as `tests/test_audit_chain_survives_a_failed_write.py`.
    """
    savepoint = await db.begin_nested()
    try:
        yield
    except Exception as exc:  # noqa: BLE001 - fail soft, and say which part
        await savepoint.rollback()
        log.warning(f"replay.context.{part}_unread", error=str(exc))
        unread.append(part)
    else:
        await savepoint.commit()


def _jsonable(row: Any) -> dict[str, Any]:
    """A row as JSON the agents service can parse.

    Datetimes are rendered ISO rather than dropped: the recorded time is
    exactly what the split filter reads on the other side, so losing it
    would silently make every row undated and therefore kept.
    """
    out: dict[str, Any] = {}
    for key, value in dict(row).items():
        out[key] = value.isoformat() if hasattr(value, "isoformat") else value
    return out


async def _capture_frozen_context(db: AsyncSession, request: ReplayRequest) -> FrozenContextCapture:
    """Organisation memory, outcome priors and the tenant's business rules.

    Production triages every alert with all three
    (`services/agents/app/workers/fused_alert_consumer.py` and
    `main.py`), so a replay that omits them is not measuring production. The
    direction of that error is the reason it matters: memory and priors
    mostly *suppress*, so a bare replay re-raises alerts production would
    have closed.
    """
    statements: list[dict[str, Any]] = []
    priors: dict[str, dict[str, Any]] = {}
    business_context: dict[str, Any] | None = None
    unread: list[str] = []

    async with _optional_read(db, "statements", unread):
        rows = await db.execute(
            text(
                "SELECT statement, reason_code, scope, scope_value, observations, updated_at "
                "FROM aisoc_context_statements "
                "WHERE tenant_id = CAST(:t AS uuid) "
                "  AND (expires_at IS NULL OR expires_at > :split) "
                "ORDER BY observations DESC, updated_at DESC "
                "LIMIT :lim"
            ).bindparams(t=str(request.tenant_id), split=request.window_end, lim=_STATEMENT_LIMIT)
        )
        statements = [_jsonable(row) for row in rows.mappings()]

    async with _optional_read(db, "priors", unread):
        rows = await db.execute(
            text(
                "SELECT key, value FROM aisoc_institutional_memory WHERE tenant_id = CAST(:t AS uuid) AND key LIKE :prefix LIMIT :lim"
            ).bindparams(t=str(request.tenant_id), prefix=f"{_OUTCOME_KEY_PREFIX}%", lim=_PRIOR_LIMIT)
        )
        for row in rows.mappings():
            key = str(row["key"])
            value = row["value"]
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except ValueError:
                    continue
            if isinstance(value, dict):
                priors[key[len(_OUTCOME_KEY_PREFIX) :]] = _jsonable(value)

    async with _optional_read(db, "business_context", unread):
        rows = await db.execute(
            text(
                "SELECT yaml_text, enabled, updated_at FROM aisoc_business_context_rule_sets WHERE tenant_id = CAST(:t AS uuid)"
            ).bindparams(t=str(request.tenant_id))
        )
        row = next(iter(rows.mappings()), None)
        if row is not None:
            updated_at = row["updated_at"]
            business_context = {
                "yaml_text": row["yaml_text"] or "",
                "enabled": bool(row["enabled"]),
                "updated_at": updated_at.isoformat() if hasattr(updated_at, "isoformat") else updated_at,
            }

    return FrozenContextCapture(
        statements=statements,
        priors=priors,
        business_context=business_context,
        unread=tuple(unread),
    )


async def _run_replay(
    request: ReplayRequest,
    connector_type: str,
    findings: list[dict[str, Any]],
    context: FrozenContextCapture,
) -> dict[str, Any]:
    url = f"{_agents_base_url()}/api/v1/replay/run"
    # Always sent. Before fix-pass 3.1 the block went only when a caller
    # passed skills, so the ordinary replay ran with an empty snapshot while
    # the docs described one carrying organisation memory.
    payload: dict[str, Any] = {
        "connector_id": connector_type,
        "findings": findings,
        "train_fraction": request.train_fraction,
        "context": context.as_payload(request),
    }
    try:
        async with httpx.AsyncClient(timeout=_REPLAY_TIMEOUT_S) as client:
            response = await client.post(url, headers=_agents_headers(request.tenant_id), json=payload)
    except httpx.HTTPError as exc:
        raise ReplayJobError(f"the agents service is unreachable at {_agents_base_url()}: {exc}") from exc

    if response.status_code >= 400:
        raise ReplayJobError(f"the replay run failed with HTTP {response.status_code}: {response.text[:400]}")
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("decisions"), list):
        raise ReplayJobError("the agents service returned an unexpected replay shape")
    return body


async def run_evaluation(db: AsyncSession, request: ReplayRequest) -> None:
    """Drive the whole chain and write the result. Never raises to the caller.

    Every exception becomes a ``failed`` row with its reason, because this
    runs detached from the request that started it and an exception escaping
    here would leave the row ``running`` forever with nothing to read.
    """
    try:
        await store.mark_running(db, tenant_id=request.tenant_id, evaluation_id=request.evaluation_id)
        connector_type, credentials = await _load_connector(db, request)

        history = await _read_history(request, credentials)
        findings = history["findings"]
        if not findings:
            raise ReplayJobError(
                "no closed findings were returned for this window. Nothing was graded, and reporting "
                "a result over zero findings would describe the window rather than the agent."
            )

        context = await _capture_frozen_context(db, request)
        run = await _run_replay(request, connector_type, findings, context)
        decisions = run["decisions"]
        method = dict(run.get("method") or {})
        if context.unread:
            # Published rather than logged: a score produced with less context
            # than the method section describes is the defect this capture
            # exists to close, and a silent partial capture would recreate it.
            method["frozen_context_unread"] = list(context.unread)

        score = score_replay(
            decisions,
            bootstrap_seed=request.bootstrap_seed,
            bootstrap_resamples=request.bootstrap_resamples,
        )
        # The sample sizes the report's method section publishes. Added here
        # rather than in the renderer so the console and the Markdown agree
        # about what was read, which is the disagreement this repository keeps
        # finding between two surfaces over the same rows.
        method["history"] = {
            "vendor": request.vendor,
            "connector_type": connector_type,
            "window_start": request.window_start.isoformat(),
            "window_end": request.window_end.isoformat(),
            "findings_read": int(history.get("count") or len(findings)),
            "findings_labelled": int(history.get("labelled") or 0),
            "findings_unlabeled": int(history.get("unlabeled") or 0),
        }
        report = format_replay_report(score, method=method)

        await store.store_result(
            db,
            tenant_id=request.tenant_id,
            evaluation_id=request.evaluation_id,
            score=score.as_dict(),
            method=method,
            report_markdown=report,
            decisions=decisions,
            findings_read=int(history.get("count") or len(findings)),
            findings_labelled=int(history.get("labelled") or 0),
        )
        log.info(
            "replay.evaluation.completed",
            evaluation_id=str(request.evaluation_id),
            findings=len(findings),
            decisions=len(decisions),
            graded=score.graded,
        )
    except ReplayJobError as exc:
        await _record_failure(db, request, str(exc))
    except Exception as exc:  # noqa: BLE001 - a detached job must terminate its own row
        log.exception("replay.evaluation.unexpected_failure", evaluation_id=str(request.evaluation_id))
        await _record_failure(db, request, f"{type(exc).__name__}: {exc}")


async def _record_failure(db: AsyncSession, request: ReplayRequest, reason: str) -> None:
    try:
        await db.rollback()
        await store.fail_evaluation(
            db,
            tenant_id=request.tenant_id,
            evaluation_id=request.evaluation_id,
            error=reason,
        )
    except Exception:  # noqa: BLE001 - nothing left to do but say so
        log.exception("replay.evaluation.failure_not_recorded", evaluation_id=str(request.evaluation_id))

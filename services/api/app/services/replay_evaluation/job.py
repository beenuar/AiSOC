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

import os
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
import structlog
from sqlalchemy import select
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


async def _run_replay(request: ReplayRequest, connector_type: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    url = f"{_agents_base_url()}/api/v1/replay/run"
    payload = {
        "connector_id": connector_type,
        "findings": findings,
        "train_fraction": request.train_fraction,
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

        run = await _run_replay(request, connector_type, findings)
        decisions = run["decisions"]
        method = dict(run.get("method") or {})

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

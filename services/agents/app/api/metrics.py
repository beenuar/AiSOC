"""Prometheus metrics for the agents service.

Four of nineteen services expose `/metrics`, and this is the one whose
absence hurts most: the auto-triage worker is where alerts either get a
verdict or quietly do not. It already counts everything worth counting —
triaged, deduplicated, deterministic versus LLM, business-context
suppressions, ungrounded demotions, dead-letters, errors — into a module
dict that was only ever read by a log line at shutdown. A counter nobody can
scrape is a counter nobody watches.

Two of these are the operator's early warning and neither was reachable:
`dead_lettered` rising means alerts are being dropped rather than triaged,
and a `deterministic` count climbing while `llm` stays flat means the LLM
path is failing open to the fallback — which looks fine from the outside
because alerts still get verdicts.

Auth mirrors `services/api`: a token when configured, and a refusal rather
than an anonymous scrape outside development. Copied deliberately — an
operator should not have to learn two rules for the same surface, and the
failure mode of getting this wrong is shipping internal counters to the
open internet.
"""

from __future__ import annotations

import hmac
import os

import structlog
from fastapi import APIRouter, HTTPException, Response, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, generate_latest

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["system"])

_bearer = HTTPBearer(auto_error=False)

#: A private registry rather than the global default. The worker's counters
#: are re-published on each scrape from a plain dict, so re-registering into
#: the process-wide registry would raise on the second import — and the
#: global registry also carries collectors from anything else that happens
#: to be linked in.
_REGISTRY = CollectorRegistry()

_TRIAGE = Counter(
    "aisoc_agents_triage_total",
    "Auto-triage outcomes by result.",
    ["result"],
    registry=_REGISTRY,
)

#: Environments where an unauthenticated scrape is acceptable.
_DEV_ENVIRONMENTS = frozenset({"dev", "development", "local", "test", "testing"})


def _environment_is_dev() -> bool:
    env = (os.getenv("AISOC_ENV") or os.getenv("ENVIRONMENT") or "").strip().lower()
    return env in _DEV_ENVIRONMENTS


def _authorise(creds: HTTPAuthorizationCredentials | None) -> None:
    token = (os.getenv("METRICS_TOKEN") or "").strip()
    if token:
        presented = (creds.credentials if creds else "") or ""
        # compare_digest rather than ==, so a wrong token does not leak its
        # correct prefix through response timing.
        if not hmac.compare_digest(presented, token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid metrics token",
                headers={"WWW-Authenticate": 'Bearer realm="metrics"'},
            )
        return

    if not _environment_is_dev():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="metrics endpoint requires METRICS_TOKEN outside development",
            headers={"WWW-Authenticate": 'Bearer realm="metrics"'},
        )


def _publish_worker_counters() -> None:
    """Mirror the worker's dict into the Prometheus counters.

    Set rather than incremented, because the worker owns the running total
    and this is a projection of it. Incrementing here would double-count
    every scrape — and the resulting graph would look like traffic.
    """
    try:
        from app.workers.fused_alert_consumer import FusedAlertTriageWorker
    except ImportError:
        # The worker is optional (it needs Kafka). Its absence means zero
        # triage activity, not a broken metrics endpoint.
        return

    try:
        counters = FusedAlertTriageWorker.get_metrics()
    except Exception as exc:  # noqa: BLE001 - a scrape must not take the service down
        logger.warning("metrics.worker_counters_unavailable", error=str(exc))
        return

    for name, value in counters.items():
        child = _TRIAGE.labels(result=name)
        current = child._value.get()  # noqa: SLF001 - no public setter on Counter
        delta = value - current
        if delta > 0:
            child.inc(delta)


@router.get("/metrics")
async def metrics(
    creds: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> Response:
    """Prometheus scrape endpoint.

    Auth gate matches `services/api`: a token when `METRICS_TOKEN` is set,
    and a refusal outside a development environment when it is not.
    """
    _authorise(creds)
    _publish_worker_counters()
    return Response(generate_latest(_REGISTRY), media_type=CONTENT_TYPE_LATEST)

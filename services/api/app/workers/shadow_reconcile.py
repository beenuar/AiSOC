"""Poll every measuring tenant's SIEM for the closures their analysts made there.

Gap-closure Phase 2.1, closing D15.

``services/actions/app/services/shadow_reconcile.py`` shipped complete, with
eleven tests, and nothing called it. Half of shadow mode therefore worked and
half of it only appeared to: a tenant whose analysts close their queue in
AiSOC accumulated a track record on every read of the agreement endpoint, and
a tenant whose analysts close their queue in Splunk ES watched a scorecard
that could not fill in. Phase 2's premise is that autonomy is earned on a
measured track record, so a track record that cannot accumulate is the
difference between the feature working and the feature appearing to.

This is the caller. It runs in ``services/api`` because that is the only
service that can drive it: the vault and the tenant session are here, the five
readers and the matcher are in ``services/actions``, and no process can hold
both because all three services package their code as top-level ``app`` (D8).
So a pass resolves a connector's credentials here and posts them with a window
to ``POST /api/v1/shadow/reconcile`` there, which is the same round trip
``siem_writeback``, ``/connectors/{id}/normalize`` and ``/replay/history``
already take.

Four outcomes, because two is not enough
========================================

A scheduled sweep is a consumer, and the rule this repository learned from the
UEBA consumer and the graph broadcaster applies: it has to tell a condition
that will never resolve from one that might, and say which. Reporting both as
"tick failed" turns a revoked API key into churn nobody reads, and reporting
neither leaves a stopped sweep looking exactly like an idle one.

``ok``         a window was read and reconciled. The watermark advances.
``idle``       there was nothing to do. The tenant is measuring but has no
               replayable connector, or the window has not moved since the
               last pass. Recorded rather than skipped, because "nothing to
               do" and "stopped" are the two states an outside observer
               cannot otherwise tell apart.
``blocked``    permanent until an operator acts: the vault cannot decrypt the
               stored credentials, or the vendor refused them. Polling stops
               for that connector and resumes on the single event that could
               have fixed it, which is the connector row being saved again.
               A timer would be the churn this state exists to avoid.
``transient``  the vendor timed out, rate-limited us, or the actions service
               was unreachable. Retried on the next tick, with the run length
               recorded so a fault that has outlived any explanation a retry
               would fix is visible as such.

Bounded work against somebody else's API
========================================

Every limit here is a limit on what this deployment does to a customer's SIEM.
The watermark stops a window being re-read forever, the per-connector floor
stops a short tick cadence becoming a poll storm, the per-tick cap spreads a
large estate across passes rather than fanning out at once, a vendor's own
``Retry-After`` is stored and honoured, and one window is capped so a connector
that was blocked for a month catches up in steps rather than asking for the
month in a single search.

Default off
===========

``SHADOW_RECONCILE_ENABLED`` defaults to false. The plan's standing rule is
that a feature which calls out ships off by default, and the two people
involved are different: a tenant enabling shadow mode has asked to be
measured, and the operator of the deployment is the one who decides whether
the platform may reach a third-party API on a timer. The health endpoint says
"disabled" in those words rather than reporting a healthy idle sweep.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.core.config import settings
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.database import AsyncSessionLocal
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services.actions_client import base_url as actions_base_url
from app.services.actions_client import service_headers as actions_headers
from app.services.replay_evaluation.vendors import (
    UnsupportedConnector,
    credentials_for,
    replayable_connector_ids,
    vendor_for,
)
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.shadow_reconcile")

__all__ = [
    "ConnectorOutcome",
    "SweepRun",
    "run_forever",
    "run_once",
]

#: A vendor search over a window of closures, not a containment. Generous
#: enough that a slow Splunk dispatch is not recorded as a fault, bounded so a
#: hung vendor cannot hold the tick open behind it.
_RECONCILE_TIMEOUT_S = 120.0

#: Statuses the actions route uses for a condition that will not clear on its
#: own: 422 is "these credentials cannot build a client, or the vendor refused
#: them". Kept as a set rather than a comparison so adding one is one edit.
_PERMANENT_STATUSES = frozenset({422})

#: Deployment-level refusals. These are not about any one connector, so they
#: halt the pass and are reported once instead of being written onto every
#: connector's row as if each had its own problem.
_DEPLOYMENT_STATUSES = frozenset({401, 403, 404, 503})


@dataclass(frozen=True)
class ConnectorOutcome:
    """What one pass did for one connector, in the words the state row stores."""

    tenant_id: uuid.UUID
    connector_id: uuid.UUID
    vendor: str
    status: str
    detail: str
    considered: int = 0
    matched: int = 0
    unmatched: int = 0
    #: Present only on ``ok``. The close time the watermark advances to.
    watermark_at: datetime | None = None
    #: Present only when a vendor asked us to wait.
    retry_after: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["tenant_id"] = str(self.tenant_id)
        out["connector_id"] = str(self.connector_id)
        out["watermark_at"] = self.watermark_at.isoformat() if self.watermark_at else None
        out["retry_after"] = self.retry_after.isoformat() if self.retry_after else None
        return out


@dataclass
class SweepRun:
    """One pass over every due connector.

    ``measuring_tenants`` and ``candidates`` are both reported, and the pair is
    the point: zero measuring tenants means nobody asked for this, while
    measuring tenants with zero candidates means somebody asked and has no
    connector this can poll. Only the second is worth telling them about.
    """

    started_at: datetime
    measuring_tenants: int = 0
    candidates: int = 0
    outcomes: list[ConnectorOutcome] = field(default_factory=list)
    #: Set when the pass stopped for a reason that applies to every connector.
    halted_reason: str | None = None

    def count(self, status: str) -> int:
        return sum(1 for o in self.outcomes if o.status == status)

    def as_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "measuring_tenants": self.measuring_tenants,
            "candidates": self.candidates,
            "polled": len(self.outcomes),
            "ok": self.count("ok"),
            "idle": self.count("idle"),
            "blocked": self.count("blocked"),
            "transient": self.count("transient"),
            "halted_reason": self.halted_reason,
            "outcomes": [o.as_dict() for o in self.outcomes],
        }


class _Halt(Exception):
    """A refusal that applies to every connector, so the pass stops."""


@dataclass(frozen=True)
class _Candidate:
    """A connector this pass may poll, and everything needed to decide whether to."""

    tenant_id: uuid.UUID
    connector_id: uuid.UUID
    connector_type: str
    auth_config: dict[str, Any]
    connector_config: dict[str, Any]
    connector_updated_at: datetime | None
    measuring_since: datetime | None
    watermark_at: datetime | None
    last_run_at: datetime | None
    retry_after: datetime | None
    blocked_reason: str | None
    blocked_connector_updated_at: datetime | None
    consecutive_failures: int


#: One statement, because the decision "may this connector be polled now" reads
#: four tables and splitting it would mean a candidate list assembled from rows
#: that were true at four different instants.
#:
#: The connector must be enabled and of a type with a reader; the tenant must
#: have at least one alert class in shadow mode, since reconciling closures for
#: a tenant that is not measuring grades nothing. ``measuring_since`` is the
#: earliest ``enabled_at`` across that tenant's classes, which is the first
#: moment there was anything to grade.
_CANDIDATES_SQL = """
SELECT
    c.id                       AS connector_id,
    c.tenant_id                AS tenant_id,
    c.connector_type           AS connector_type,
    c.auth_config              AS auth_config,
    c.connector_config         AS connector_config,
    c.updated_at               AS connector_updated_at,
    m.measuring_since          AS measuring_since,
    s.watermark_at             AS watermark_at,
    s.last_run_at              AS last_run_at,
    s.retry_after              AS retry_after,
    s.blocked_reason           AS blocked_reason,
    s.blocked_connector_updated_at AS blocked_connector_updated_at,
    COALESCE(s.consecutive_failures, 0) AS consecutive_failures
FROM connectors c
JOIN (
    SELECT tenant_id, MIN(COALESCE(enabled_at, updated_at, created_at)) AS measuring_since
    FROM aisoc_shadow_mode
    WHERE enabled IS TRUE
    GROUP BY tenant_id
) m ON m.tenant_id = c.tenant_id
LEFT JOIN aisoc_shadow_reconcile_state s
       ON s.tenant_id = c.tenant_id AND s.connector_id = c.id
WHERE c.is_enabled IS TRUE
  AND c.connector_type = ANY(:replayable)
ORDER BY s.last_run_at ASC NULLS FIRST, c.id ASC
"""

_MEASURING_TENANTS_SQL = "SELECT COUNT(DISTINCT tenant_id)::int FROM aisoc_shadow_mode WHERE enabled IS TRUE"

_UPSERT_STATE_SQL = """
INSERT INTO aisoc_shadow_reconcile_state (
    tenant_id, connector_id, vendor, watermark_at, last_run_at, last_status, last_detail,
    last_considered, last_matched, last_unmatched, consecutive_failures,
    blocked_reason, blocked_at, blocked_connector_updated_at, retry_after, updated_at
) VALUES (
    :tenant_id, :connector_id, :vendor, :watermark_at, :last_run_at, :last_status, :last_detail,
    :considered, :matched, :unmatched, :consecutive_failures,
    :blocked_reason, :blocked_at, :blocked_connector_updated_at, :retry_after, now()
)
ON CONFLICT (tenant_id, connector_id) DO UPDATE SET
    vendor        = EXCLUDED.vendor,
    -- Never moves backwards. A transient pass leaves it where the last
    -- successful one put it, so a failure cannot make the sweep re-read a
    -- window it already graded, and a clock that jumps cannot make it skip one.
    watermark_at  = GREATEST(
        COALESCE(EXCLUDED.watermark_at, aisoc_shadow_reconcile_state.watermark_at),
        COALESCE(aisoc_shadow_reconcile_state.watermark_at, EXCLUDED.watermark_at)
    ),
    last_run_at   = EXCLUDED.last_run_at,
    last_status   = EXCLUDED.last_status,
    last_detail   = EXCLUDED.last_detail,
    last_considered = EXCLUDED.last_considered,
    last_matched    = EXCLUDED.last_matched,
    last_unmatched  = EXCLUDED.last_unmatched,
    consecutive_failures = EXCLUDED.consecutive_failures,
    blocked_reason = EXCLUDED.blocked_reason,
    blocked_at     = EXCLUDED.blocked_at,
    blocked_connector_updated_at = EXCLUDED.blocked_connector_updated_at,
    retry_after    = EXCLUDED.retry_after,
    updated_at     = now()
"""


def _interval() -> int:
    """Tick cadence, floored so a misconfigured value cannot become a poll storm."""
    return max(int(getattr(settings, "SHADOW_RECONCILE_INTERVAL_SECONDS", 900)), 60)


def _min_connector_interval() -> int:
    return max(int(getattr(settings, "SHADOW_RECONCILE_MIN_CONNECTOR_INTERVAL_SECONDS", 3600)), 60)


def _max_per_tick() -> int:
    return max(int(getattr(settings, "SHADOW_RECONCILE_MAX_CONNECTORS_PER_TICK", 10)), 1)


def _overlap() -> timedelta:
    return timedelta(seconds=max(int(getattr(settings, "SHADOW_RECONCILE_OVERLAP_SECONDS", 900)), 0))


def _max_lookback() -> timedelta:
    return timedelta(hours=max(int(getattr(settings, "SHADOW_RECONCILE_MAX_LOOKBACK_HOURS", 168)), 1))


def _max_window() -> timedelta:
    return timedelta(hours=max(int(getattr(settings, "SHADOW_RECONCILE_MAX_WINDOW_HOURS", 24)), 1))


def _limit() -> int:
    return max(min(int(getattr(settings, "SHADOW_RECONCILE_LIMIT", 1000)), 5000), 1)


def _safe(value: object, cap: int = 300) -> str:
    """One-line, length-capped rendering for a log record and for the state row."""
    return str(value).replace("\r", "").replace("\n", " ")[:cap]


def _aware(value: datetime | None) -> datetime | None:
    """Postgres hands back aware values; a test fixture may not. Compare like for like."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _window_for(candidate: _Candidate, now: datetime) -> tuple[datetime, datetime] | None:
    """The window to ask the vendor for, or ``None`` when there is nothing to ask.

    The start is the watermark less the overlap, because a vendor's search
    index lags its own close events and a window beginning exactly where the
    last one ended steps over anything indexed late. Re-reading the overlap is
    free of consequence: ``reconcile_findings`` only writes decisions whose
    ``resolved_at`` is null, so an already-graded finding comes back as
    ``already_resolved``.

    With no watermark the start is when this tenant began measuring, floored at
    the maximum lookback. Reaching back further would grade closures made
    before there was a decision to grade them against.
    """
    watermark = _aware(candidate.watermark_at)
    floor = now - _max_lookback()
    if watermark is not None:
        start = watermark - _overlap()
    else:
        measuring_since = _aware(candidate.measuring_since)
        start = measuring_since if measuring_since is not None else floor
    start = max(start, floor)

    # One window at a time. A connector that was blocked for a month catches up
    # over several passes rather than asking a customer's SIEM for the month in
    # a single search, which is the request most likely to be refused or to time
    # out and so the one least likely to ever succeed.
    end = min(now, start + _max_window())
    if end <= start:
        return None
    return start, end


def _is_due(candidate: _Candidate, now: datetime) -> tuple[bool, str]:
    """Whether to poll this connector now, and the reason when not."""
    if candidate.blocked_reason:
        # Permanent until the connector row changes, and nothing else. Comparing
        # against the recorded value rather than clearing on a timer is what
        # makes "somebody acted" the only thing that resumes polling.
        recorded = _aware(candidate.blocked_connector_updated_at)
        current = _aware(candidate.connector_updated_at)
        if recorded is not None and current is not None and current <= recorded:
            return False, candidate.blocked_reason
        if recorded is None and current is None:
            return False, candidate.blocked_reason

    retry_after = _aware(candidate.retry_after)
    if retry_after is not None and retry_after > now:
        return False, f"the vendor asked us to wait until {retry_after.isoformat()}"

    last_run = _aware(candidate.last_run_at)
    if last_run is not None and (now - last_run) < timedelta(seconds=_min_connector_interval()):
        return False, "polled recently"
    return True, ""


async def _load_candidates(db: AsyncSession) -> list[_Candidate]:
    rows = (await db.execute(text(_CANDIDATES_SQL), {"replayable": replayable_connector_ids()})).mappings().all()
    return [
        _Candidate(
            tenant_id=row["tenant_id"],
            connector_id=row["connector_id"],
            connector_type=row["connector_type"],
            auth_config=dict(row["auth_config"] or {}),
            connector_config=dict(row["connector_config"] or {}),
            connector_updated_at=row["connector_updated_at"],
            measuring_since=row["measuring_since"],
            watermark_at=row["watermark_at"],
            last_run_at=row["last_run_at"],
            retry_after=row["retry_after"],
            blocked_reason=row["blocked_reason"],
            blocked_connector_updated_at=row["blocked_connector_updated_at"],
            consecutive_failures=int(row["consecutive_failures"] or 0),
        )
        for row in rows
    ]


def _retry_after_at(response: httpx.Response, now: datetime) -> datetime:
    """When the vendor said to come back, or one interval from now.

    Only the delta-seconds form is parsed. The HTTP-date form is legal and rare
    here, and a date this code misparsed would either hammer a vendor that
    asked us not to or park a connector for an arbitrary time. Falling back to
    our own interval is wrong by at most one tick in one direction.
    """
    raw = (response.headers.get("Retry-After") or "").strip()
    try:
        seconds = int(raw)
    except ValueError:
        seconds = _interval()
    return now + timedelta(seconds=max(min(seconds, 86400), 1))


async def _poll(
    candidate: _Candidate, vendor: str, credentials: dict[str, Any], window: tuple[datetime, datetime], now: datetime
) -> ConnectorOutcome:
    """One request to the actions service, classified into one of the four states."""
    start, end = window
    payload: dict[str, Any] = {
        "vendor": vendor,
        "credentials": credentials,
        "since": start.isoformat(),
        "until": end.isoformat(),
        "limit": _limit(),
    }
    if credentials.get("search_override"):
        payload["search_override"] = credentials["search_override"]
    if credentials.get("index"):
        payload["index"] = credentials["index"]

    url = f"{actions_base_url()}/api/v1/shadow/reconcile"
    headers = {**actions_headers(), "X-AiSOC-Tenant-ID": str(candidate.tenant_id)}

    try:
        # The hop this service makes is to an internal service. The vendor hop
        # is made by the actions service against the connector URL an operator
        # configured, which in an air-gapped deployment is on the isolated
        # network by construction.
        enforce_airgap_for_url(url)
    except AirgapViolation as exc:
        raise _Halt(f"air-gap policy refuses the actions service at {actions_base_url()}: {exc}") from exc

    try:
        async with httpx.AsyncClient(timeout=_RECONCILE_TIMEOUT_S) as client:
            response = await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        return _outcome(
            candidate,
            vendor,
            "transient",
            f"the actions service is unreachable at {actions_base_url()}: {type(exc).__name__}",
        )

    if response.status_code == 429:
        return _outcome(
            candidate,
            vendor,
            "transient",
            "the vendor asked us to slow down",
            retry_after=_retry_after_at(response, now),
        )
    if response.status_code in _PERMANENT_STATUSES:
        return _outcome(candidate, vendor, "blocked", _safe(_detail(response)))
    if response.status_code in _DEPLOYMENT_STATUSES:
        raise _Halt(f"the actions service refused the sweep with HTTP {response.status_code}: {_safe(_detail(response))}")
    if response.status_code >= 400:
        return _outcome(candidate, vendor, "transient", f"the actions service returned HTTP {response.status_code}")

    try:
        body = response.json()
    except ValueError:
        return _outcome(candidate, vendor, "transient", "the actions service returned a non-JSON body")
    if not isinstance(body, dict):
        return _outcome(candidate, vendor, "transient", "the actions service returned an unexpected body shape")

    considered = int(body.get("considered") or 0)
    matched = int(body.get("matched") or 0)
    unmatched = int(body.get("unmatched") or 0)
    latest = body.get("latest_closed_at")

    # The watermark advances to the latest close time actually seen, not to the
    # end of the window we asked for. A vendor that indexes late would otherwise
    # have those findings stepped over the moment the clock moved past them.
    watermark: datetime | None = None
    if isinstance(latest, str) and latest:
        try:
            watermark = _aware(datetime.fromisoformat(latest))
        except ValueError:
            watermark = None
    if watermark is None:
        # An empty window still has to make progress or the sweep re-reads the
        # same quiet hours forever. It advances only to the end of the window
        # less the overlap, so nothing indexed inside the overlap is skipped.
        watermark = end - _overlap()

    if considered and not matched:
        # Both halves read fine and nothing joined. That is the vendor finding
        # id not reaching `aisoc_shadow_decisions.external_id`, which is a
        # wiring fault an operator can act on, and it is reported as one rather
        # than as a successful quiet pass.
        detail = (
            f"read {considered} closure(s) and matched none. The vendor's finding id is not reaching "
            f"aisoc_shadow_decisions.external_id, so closures cannot be joined to the verdicts they grade"
        )
    elif considered:
        detail = f"matched {matched} of {considered} closure(s)"
    else:
        detail = "the vendor reported no closures in this window"

    return _outcome(
        candidate,
        vendor,
        "ok",
        detail,
        considered=considered,
        matched=matched,
        unmatched=unmatched,
        watermark_at=watermark,
    )


def _detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"the actions service returned {response.status_code}"
    if isinstance(payload, dict) and isinstance(payload.get("detail"), str) and payload["detail"].strip():
        return payload["detail"]
    return f"the actions service returned {response.status_code}"


def _outcome(candidate: _Candidate, vendor: str, status: str, detail: str, **extra: Any) -> ConnectorOutcome:
    return ConnectorOutcome(
        tenant_id=candidate.tenant_id,
        connector_id=candidate.connector_id,
        vendor=vendor,
        status=status,
        detail=detail,
        **extra,
    )


async def _record(db: AsyncSession, candidate: _Candidate, outcome: ConnectorOutcome, now: datetime) -> None:
    """Write the state row for one connector, including the quiet outcomes."""
    blocked = outcome.status == "blocked"
    failures = candidate.consecutive_failures + 1 if outcome.status == "transient" else 0
    await db.execute(
        text(_UPSERT_STATE_SQL),
        {
            "tenant_id": str(candidate.tenant_id),
            "connector_id": str(candidate.connector_id),
            "vendor": outcome.vendor,
            "watermark_at": outcome.watermark_at,
            "last_run_at": now,
            "last_status": outcome.status,
            "last_detail": _safe(outcome.detail),
            "considered": outcome.considered,
            "matched": outcome.matched,
            "unmatched": outcome.unmatched,
            "consecutive_failures": failures,
            "blocked_reason": _safe(outcome.detail) if blocked else None,
            "blocked_at": now if blocked else None,
            "blocked_connector_updated_at": candidate.connector_updated_at if blocked else None,
            "retry_after": outcome.retry_after,
        },
    )


async def run_once(*, db: AsyncSession | None = None, now: datetime | None = None) -> SweepRun:
    """One sweep across every connector that is due, capped per pass."""
    now = now or datetime.now(UTC)
    own_session = db is None
    if db is None:
        db = AsyncSessionLocal()
    run = SweepRun(started_at=now)

    try:
        await assert_cross_tenant_session(db, "shadow reconciliation sweep")
        run.measuring_tenants = int((await db.execute(text(_MEASURING_TENANTS_SQL))).scalar_one() or 0)
        candidates = await _load_candidates(db)
        run.candidates = len(candidates)

        polled = 0
        for candidate in candidates:
            if polled >= _max_per_tick():
                break
            vendor = candidate.connector_type
            try:
                vendor = vendor_for(candidate.connector_type)
                due, reason = _is_due(candidate, now)
                if not due:
                    # Still recorded. A connector skipped silently for an hour
                    # is indistinguishable from one the sweep forgot about.
                    await _record(db, candidate, _outcome(candidate, vendor, "idle", reason or "not due"), now)
                    continue

                window = _window_for(candidate, now)
                if window is None:
                    await _record(db, candidate, _outcome(candidate, vendor, "idle", "the window has not moved since the last pass"), now)
                    continue

                # Decrypted only once the connector is actually going to be
                # polled, so a not-due connector whose vault key is missing is
                # not recorded as blocked on a pass that was never going to
                # reach its vendor.
                credentials = _credentials_for(candidate)
                outcome = await _poll(candidate, vendor, credentials, window, now)
            except _Halt:
                raise
            except (CredentialVaultError, UnsupportedConnector) as exc:
                outcome = _outcome(candidate, vendor or candidate.connector_type, "blocked", _blocked_detail(exc))
            except Exception as exc:  # noqa: BLE001 - one connector must not end the pass
                logger.warning(
                    "shadow_reconcile.connector_failed connector=%s err=%s detail=%s",
                    _safe(candidate.connector_id, 64),
                    type(exc).__name__,
                    _safe(exc),
                )
                outcome = _outcome(candidate, vendor or candidate.connector_type, "transient", f"{type(exc).__name__}")

            await _record(db, candidate, outcome, now)
            run.outcomes.append(outcome)
            polled += 1

        await db.commit()
    except _Halt as exc:
        # Applies to every connector, so it is said once. Nothing is written
        # onto the per-connector rows: blaming each connector for a deployment
        # fault is how an operator ends up re-saving fifty connectors.
        await db.rollback()
        run.halted_reason = _safe(exc)
        logger.error("shadow_reconcile.halted reason=%s", run.halted_reason)
    finally:
        if own_session:
            await db.close()

    _log_pass(run)
    return run


def _blocked_detail(exc: Exception) -> str:
    if isinstance(exc, CredentialVaultError):
        return (
            f"the stored credentials could not be decrypted ({type(exc).__name__}); the vault key that wrote "
            f"them is not in the current keyring. Re-save this connector's credentials"
        )
    return _safe(exc)


def _credentials_for(candidate: _Candidate) -> dict[str, Any]:
    """The reader's credential keys for one connector, decrypted here.

    The vault lives in this service and nowhere else, so this is the only place
    a connector's stored secrets are readable. They are forwarded per call and
    never persisted downstream, which is the same trust model
    ``/replay/history`` and ``/connectors/{id}/normalize`` already use.
    """
    decrypted = get_vault().decrypt_dict(candidate.auth_config)
    return credentials_for(candidate.connector_type, decrypted, candidate.connector_config)


def _log_pass(run: SweepRun) -> None:
    """Say what the pass did, including when it did nothing.

    The quiet cases are logged at info rather than skipped, because the whole
    point of this worker is that an empty scorecard should never again be the
    first place somebody learns nothing is running.
    """
    if run.halted_reason:
        return
    if run.measuring_tenants == 0:
        logger.info("shadow_reconcile idle: no tenant has shadow mode enabled, so there is nothing to reconcile")
        return
    if run.candidates == 0:
        logger.info(
            "shadow_reconcile idle: %d tenant(s) are measuring but none has an enabled connector of a type with a "
            "closed-finding reader (%s), so agreement is measured on AiSOC closures only",
            run.measuring_tenants,
            ", ".join(replayable_connector_ids()),
        )
        return
    logger.info(
        "shadow_reconcile pass tenants=%d candidates=%d polled=%d ok=%d idle=%d blocked=%d transient=%d matched=%d",
        run.measuring_tenants,
        run.candidates,
        len(run.outcomes),
        run.count("ok"),
        run.count("idle"),
        run.count("blocked"),
        run.count("transient"),
        sum(o.matched for o in run.outcomes),
    )
    for outcome in run.outcomes:
        if outcome.status == "blocked":
            logger.error(
                "shadow_reconcile blocked connector=%s vendor=%s; this will not clear on its own: %s",
                _safe(outcome.connector_id, 64),
                _safe(outcome.vendor, 32),
                _safe(outcome.detail),
            )


async def run_forever() -> None:
    """Tick until cancelled. Owned by the API ``lifespan``, like the other workers."""
    interval = _interval()
    logger.info(
        "shadow_reconcile started interval=%ds per-connector-floor=%ds max-per-tick=%d window-cap=%dh",
        interval,
        _min_connector_interval(),
        _max_per_tick(),
        int(_max_window().total_seconds() // 3600),
    )
    failures = TickFailures("shadow_reconcile", logger)
    try:
        while True:
            try:
                await run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                failures.record_failure(exc)
            else:
                failures.record_success()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("shadow_reconcile stopped")
        raise

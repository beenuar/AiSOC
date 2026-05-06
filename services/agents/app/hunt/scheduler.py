"""Continuous hunt scheduler (Wave 2 — w2-hac).

Runs the YAML hunt corpus on the cadence declared per hunt. Each tick:

1. Loads (or reloads) the corpus from disk.
2. For each enabled hunt whose interval has elapsed, pulls a slice of recent
   telemetry, hands events to :class:`HuntEngine`, and persists the run +
   findings via :mod:`app.hunt.store`.
3. Sleeps until the next due hunt.

Telemetry source resolution — in priority order:

* ``HUNT_TELEMETRY_PROVIDER`` env var set to ``synthetic`` (the default in
  dev/CI) reads from
  ``services/agents/tests/eval_data/synthetic_telemetry.jsonl`` and treats
  each line as a discrete event. This is what the substrate eval uses and
  is what the public benchmark scoreboard scores against.
* ``ingest`` is a placeholder for the live event warehouse path; it
  returns an empty stream until the federated-search layer (Wave 3 —
  w3-fed) lands. This keeps the scheduler safe to leave running in
  production: it records an empty run rather than crashing.

The scheduler is feature-flagged via ``AISOC_FEATURE_HUNT_AS_CODE``. The
caller (``app/main.py``) wires it into the FastAPI lifespan so it starts
on app boot and stops cleanly on shutdown.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .engine import HuntEngine
from .loader import HuntCorpus, HuntDefinition
from .store import record_run, sync_catalog

logger = structlog.get_logger()


# How often the scheduler wakes up to check for due hunts. Individual hunts
# declare their own ``interval_minutes`` and we honour that — this is just
# the polling cadence of the dispatch loop.
_TICK_SECONDS = int(os.environ.get("HUNT_SCHEDULER_TICK_SECONDS", "60"))


class HuntScheduler:
    """APScheduler-driven runner for the YAML hunt corpus."""

    JOB_ID = "hunt-scheduler-tick"

    def __init__(
        self,
        *,
        corpus: HuntCorpus | None = None,
        engine: HuntEngine | None = None,
        tick_seconds: int = _TICK_SECONDS,
        tenant_ref: str = "default",
    ) -> None:
        self._corpus = corpus or HuntCorpus.default()
        self._engine = engine or HuntEngine()
        self._tick_seconds = tick_seconds
        self._tenant_ref = tenant_ref
        self._scheduler = AsyncIOScheduler()
        # Tracks last run time per hunt id so we don't re-run more often
        # than the hunt's declared interval.
        self._last_run: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._tick_seconds <= 0:
            logger.info("hunt.scheduler.disabled", reason="tick<=0")
            return

        # Reload + sync the corpus on boot so the catalog table is current.
        try:
            count = self._corpus.reload()
            logger.info("hunt.scheduler.corpus_loaded", count=count)
            await sync_catalog(self._corpus.list(), tenant_ref=self._tenant_ref)
        except Exception as exc:  # noqa: BLE001
            logger.warning("hunt.scheduler.corpus_load_failed", error=str(exc))

        self._scheduler.add_job(
            func=self._tick,
            trigger=IntervalTrigger(seconds=self._tick_seconds),
            id=self.JOB_ID,
            name="Hunt-as-code dispatch",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        if not self._scheduler.running:
            self._scheduler.start()
        logger.info("hunt.scheduler.started", tick_seconds=self._tick_seconds)

    async def stop(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("hunt.scheduler.stopped")

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def _tick(self) -> None:
        """Run every hunt whose interval has elapsed since its last run."""
        now = time.time()
        events = _load_telemetry()  # one shared snapshot per tick

        for hunt in self._corpus.list():
            if not hunt.schedule.enabled:
                continue
            interval = max(60, hunt.schedule.interval_minutes * 60)
            last = self._last_run.get(hunt.id)
            if last is not None and (now - last) < interval:
                continue
            try:
                await self._run_hunt(hunt, events)
            except Exception as exc:  # noqa: BLE001
                logger.warning("hunt.scheduler.run_failed", hunt_id=hunt.id, error=str(exc))
            finally:
                self._last_run[hunt.id] = now

    async def _run_hunt(self, hunt: HuntDefinition, events: list[dict[str, Any]]) -> None:
        result = self._engine.run(hunt, events)
        await record_run(
            hunt,
            result,
            tenant_ref=self._tenant_ref,
            trigger_source="scheduler",
        )
        logger.info(
            "hunt.scheduler.completed",
            hunt_id=hunt.id,
            events_scanned=result.events_scanned,
            findings=len(result.findings),
            match_score=round(result.match_score, 3),
        )

    # ------------------------------------------------------------------
    # Manual trigger (used by the API)
    # ------------------------------------------------------------------

    async def run_one(self, hunt_id: str) -> dict[str, Any]:
        """Run a single hunt on demand. Returns a summary dict."""
        hunt = self._corpus.get(hunt_id)
        if hunt is None:
            return {"ok": False, "error": f"hunt {hunt_id} not found"}
        result = self._engine.run(hunt, _load_telemetry())
        await record_run(
            hunt,
            result,
            tenant_ref=self._tenant_ref,
            trigger_source="manual",
        )
        self._last_run[hunt.id] = time.time()
        return {
            "ok": True,
            "hunt_id": hunt.id,
            "events_scanned": result.events_scanned,
            "findings": len(result.findings),
            "match_score": round(result.match_score, 3),
        }


# ---------------------------------------------------------------------------
# Telemetry loaders
# ---------------------------------------------------------------------------


def _load_telemetry() -> list[dict[str, Any]]:
    """Resolve and load events according to ``HUNT_TELEMETRY_PROVIDER``.

    Defaults to ``synthetic`` so the scheduler is useful out of the box —
    that's also what the public benchmark scoreboard scores hunts against.
    """
    provider = os.environ.get("HUNT_TELEMETRY_PROVIDER", "synthetic").strip().lower()
    if provider == "synthetic":
        return _load_synthetic_events()
    if provider == "ingest":
        # Live event-warehouse path is wired up by the federated search work
        # in Wave 3 (w3-fed). Until then the scheduler records empty runs
        # rather than crashing — that's deliberate, it lets ops watch the
        # job heartbeat without faking findings.
        return []
    logger.warning("hunt.telemetry.unknown_provider", provider=provider)
    return []


_SYNTHETIC_PATH_OVERRIDE = "HUNT_SYNTHETIC_TELEMETRY_PATH"


def _resolve_synthetic_path() -> Path | None:
    override = os.environ.get(_SYNTHETIC_PATH_OVERRIDE, "").strip()
    if override:
        p = Path(override)
        return p if p.exists() else None

    # Walk up from this file: services/agents/app/hunt/scheduler.py
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "tests" / "eval_data" / "synthetic_telemetry.jsonl",
        here.parents[3] / "services" / "agents" / "tests" / "eval_data" / "synthetic_telemetry.jsonl",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _load_synthetic_events() -> list[dict[str, Any]]:
    path = _resolve_synthetic_path()
    if path is None:
        logger.debug("hunt.telemetry.synthetic.missing")
        return []
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.warning("hunt.telemetry.synthetic.read_failed", error=str(exc))
        return []
    return events


# Singleton — set up by ``app.main`` on startup so the API router can call
# ``run_one`` without re-instantiating.
_INSTANCE: HuntScheduler | None = None


def get_scheduler() -> HuntScheduler:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = HuntScheduler()
    return _INSTANCE


async def start_scheduler() -> HuntScheduler:
    sched = get_scheduler()
    await sched.start()
    return sched


async def stop_scheduler() -> None:
    global _INSTANCE
    if _INSTANCE is not None:
        await _INSTANCE.stop()

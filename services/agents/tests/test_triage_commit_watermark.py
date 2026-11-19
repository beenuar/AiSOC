"""The triage loop's commit discipline: watermarks, on a timer, never ahead.

Two properties the previous shape got wrong in opposite directions:

* ``commit()`` with no arguments commits the FETCH position — which runs
  ahead of everything prefetched and mid-triage, so a crash loses alerts
  that were received but never triaged. Commits must carry an explicit
  watermark: the lowest offset still in flight.
* The window was evaluated when a message arrived, so a topic that went
  quiet after a burst left finished work uncommitted indefinitely. The
  committer runs on a timer instead.
"""

from __future__ import annotations

import asyncio
from collections import namedtuple
from types import SimpleNamespace

import pytest

from app.workers import fused_alert_consumer as fac

_Msg = namedtuple("_Msg", "partition offset value")


class RecordingConsumer:
    """Yields its messages, then simulates a topic that went quiet forever."""

    def __init__(self, messages: list) -> None:
        self._messages = list(messages)
        self.commits: list[dict | None] = []
        self._never = asyncio.Event()

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def commit(self, offsets=None) -> None:  # noqa: ANN001
        self.commits.append(offsets)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._messages:
            return self._messages.pop(0)
        await self._never.wait()  # quiet topic: no further messages, no error
        raise AssertionError("unreachable")


def _msg(offset: int) -> _Msg:
    return _Msg(partition=0, offset=offset, value={"alert_id": f"a{offset}", "title": "t"})


def _worker(monkeypatch, consumer: RecordingConsumer):
    monkeypatch.setattr(fac, "AIOKafkaConsumer", lambda *a, **k: consumer)
    monkeypatch.setattr(fac, "_COMMIT_WINDOW_SECONDS", 0.05)
    worker = fac.FusedAlertTriageWorker(bootstrap_servers="fake:9092", topic="t")
    return worker


def _watermarks(consumer: RecordingConsumer) -> list[int]:
    out = []
    for offsets in consumer.commits:
        assert offsets is not None, "commits must carry explicit offsets, never bare commit()"
        for meta in offsets.values():
            out.append(meta.offset)
    return out


@pytest.mark.asyncio
async def test_quiet_topic_still_commits_finished_work(monkeypatch) -> None:
    consumer = RecordingConsumer([_msg(0), _msg(1), _msg(2)])
    worker = _worker(monkeypatch, consumer)

    async def _patched(self, message):
        return True

    monkeypatch.setattr(type(worker), "_process_with_retry", _patched)
    task = asyncio.create_task(worker._attempt_start())
    try:
        # The topic is quiet from the first moment; only the timer can commit.
        for _ in range(100):
            await asyncio.sleep(0.05)
            if any(w >= 3 for w in _watermarks(consumer)):
                break
        assert any(w >= 3 for w in _watermarks(consumer)), (
            "finished work must commit on the timer even when no further messages arrive"
        )
    finally:
        worker.stop()
        await asyncio.wait_for(task if not task.done() else asyncio.sleep(0), timeout=5)
        task.cancel()


@pytest.mark.asyncio
async def test_watermark_never_advances_past_in_flight_work(monkeypatch) -> None:
    consumer = RecordingConsumer([_msg(0), _msg(1), _msg(2)])
    worker = _worker(monkeypatch, consumer)

    gate = asyncio.Event()

    async def _patched(self, message):
        if isinstance(message, dict) and message.get("alert_id") == "a0":
            await gate.wait()  # offset 0 stays in flight for the whole probe
        return True

    monkeypatch.setattr(type(worker), "_process_with_retry", _patched)
    task = asyncio.create_task(worker._attempt_start())
    try:
        await asyncio.sleep(0.5)  # many commit windows; 1 and 2 already finished
        assert all(w == 0 for w in _watermarks(consumer)), (
            f"watermark jumped past the in-flight offset: {consumer.commits}"
        )
        gate.set()
        for _ in range(100):
            await asyncio.sleep(0.05)
            if any(w >= 3 for w in _watermarks(consumer)):
                break
        assert any(w >= 3 for w in _watermarks(consumer))
    finally:
        worker.stop()
        task.cancel()

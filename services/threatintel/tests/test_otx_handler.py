"""The OTX handler must stream a huge aggregate pulse, not choke on it.

A subscribed OTX pulse can be an aggregate feed carrying over a million
indicators (observed live: one pulse with 1,263,473). The handler built one
``all_iocs`` list from every pulse and handed the whole thing to
``ingest_iocs``, which dedups per item against Redis and embeds into Qdrant —
on a million items the poll stalls and nothing lands (observed: otx=0 across
all stores after a clean start). IOCs must stream through in bounded batches,
and the pulse-level context (ATT&CK ids, malware families, tags) must ride on
each IOC so enrichment/scoring can use it.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.clients.otx import OtxClient
from app.feeds.handlers import handle_otx_feed


def _pulse(n: int, **ctx: Any) -> dict[str, Any]:
    base = {
        "id": "p1",
        "name": "mega-aggregate",
        "tags": ["dump"],
        "malware_families": ["M1"],
        "attack_ids": ["T1566"],
        "tlp": "white",
        "indicators": [{"type": "domain", "indicator": f"d{i}.example", "description": ""} for i in range(n)],
    }
    base.update(ctx)
    return base


class _FakeOtx(OtxClient):
    """Real extract/iter logic (that is what we test); only the network fetch is stubbed."""

    def __init__(self, pulses: list[dict[str, Any]]) -> None:
        super().__init__(api_key="test")
        self._pulses = pulses

    async def get_subscribed_pulses(self, modified_since: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        return self._pulses


class _RecordingPipeline:
    def __init__(self) -> None:
        self.batches: list[int] = []

    async def ingest_iocs(self, iocs: list[dict[str, Any]], source: str) -> dict[str, Any]:
        self.batches.append(len(iocs))
        return {"total": len(iocs), "new": len(iocs), "duplicate": 0}


@pytest.mark.asyncio
async def test_a_mega_pulse_is_ingested_in_bounded_batches() -> None:
    pipe = _RecordingPipeline()
    # The fake satisfies the one method the handler calls; same idiom as the
    # sink fakes in test_pipeline_sink_reporting.py.
    await handle_otx_feed(client=_FakeOtx([_pulse(2500)]), pipeline=pipe)  # type: ignore[arg-type]

    assert pipe.batches, "nothing was ingested"
    assert max(pipe.batches) <= 1000, f"a batch exceeded the cap: max={max(pipe.batches)}"
    assert sum(pipe.batches) == 2500, "indicators were lost"


class _Capturing:
    def __init__(self) -> None:
        self.iocs: list[dict[str, Any]] = []

    async def ingest_iocs(self, iocs: list[dict[str, Any]], source: str) -> dict[str, Any]:
        self.iocs.extend(iocs)
        return {"total": len(iocs), "new": len(iocs), "duplicate": 0}


@pytest.mark.asyncio
async def test_pulse_context_rides_on_each_ioc() -> None:
    pulse = _pulse(
        1,
        name="UAC report",
        tags=["phishing"],
        malware_families=["HOMESTEEL"],
        attack_ids=["T1566"],
        indicators=[{"type": "domain", "indicator": "evil.example", "description": "c2"}],
    )
    cap = _Capturing()
    await handle_otx_feed(client=_FakeOtx([pulse]), pipeline=cap)  # type: ignore[arg-type]

    assert cap.iocs, "nothing was ingested"
    ioc = cap.iocs[0]
    assert ioc["value"] == "evil.example"
    assert ioc["source"] == "otx"
    assert ioc["malware_families"] == ["HOMESTEEL"]
    assert ioc["attack_ids"] == ["T1566"]
    assert ioc["pulse_name"] == "UAC report"

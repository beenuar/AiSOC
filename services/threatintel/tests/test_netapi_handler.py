"""Tests for the NetAPI feed handler and its registration contract.

The handler's job is narrow but the two failure modes are expensive:

* It must stream. Holding a 285k-line list in memory as dicts before handing
  it over is how a poll stalls the service.
* It must not enter the pipeline at all when the list is unchanged. The
  per-indicator dedup cost is paid whether or not an indicator is new, so a
  304 that still ingests has thrown away the entire benefit of the 304.
"""

from __future__ import annotations

import httpx
import pytest
from app.clients.netapi import NetApiClient
from app.feeds.handlers import handle_netapi_feed

pytestmark = pytest.mark.asyncio


class RecordingPipeline:
    """Captures what ``ingest_iocs`` was handed, batch by batch."""

    def __init__(self) -> None:
        self.batches: list[list[dict]] = []
        self.sources: list[str] = []

    async def ingest_iocs(self, iocs, source):
        self.batches.append(list(iocs))
        self.sources.append(source)
        return {"total": len(iocs), "new": len(iocs), "duplicate": 0}

    @property
    def all_iocs(self) -> list[dict]:
        return [ioc for batch in self.batches for ioc in batch]


def _client(handler, **kwargs) -> NetApiClient:
    return NetApiClient(transport=httpx.MockTransport(handler), **kwargs)


class TestIngest:
    async def test_both_lists_are_ingested_under_the_netapi_source(self):
        def handler(request):
            if "ips" in str(request.url):
                return httpx.Response(200, text="1.2.3.4\n5.6.7.8\n")
            return httpx.Response(200, text="evil.example\nbad.example.org\n")

        pipeline = RecordingPipeline()
        await handle_netapi_feed(client=_client(handler), pipeline=pipeline)

        assert sorted(i["value"] for i in pipeline.all_iocs) == [
            "1.2.3.4",
            "5.6.7.8",
            "bad.example.org",
            "evil.example",
        ]
        # One source string for every batch, and it must be the one the
        # confidence scorer recognises.
        assert set(pipeline.sources) == {"netapi"}

    async def test_ingest_is_batched_not_accumulated(self):
        # 2,500 indicators against a 1,000-item batch size: the handler must
        # flush three times rather than build one 2,500-item list.
        body = "\n".join(f"10.0.{n // 256}.{n % 256}" for n in range(2500))

        def handler(request):
            if "ips" in str(request.url):
                return httpx.Response(200, text=body)
            return httpx.Response(200, text="")

        pipeline = RecordingPipeline()
        await handle_netapi_feed(client=_client(handler), pipeline=pipeline)

        assert [len(b) for b in pipeline.batches] == [1000, 1000, 500]


class TestUnchangedListCostsNothing:
    async def test_304_does_not_enter_the_pipeline(self):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if request.headers.get("If-None-Match"):
                return httpx.Response(304)
            return httpx.Response(200, text="1.2.3.4\n", headers={"ETag": '"v1"'})

        client = _client(handler)
        pipeline = RecordingPipeline()

        await handle_netapi_feed(client=client, pipeline=pipeline)
        first = len(pipeline.batches)
        assert first > 0

        await handle_netapi_feed(client=client, pipeline=pipeline)

        # The second poll must have added no batch at all. Anything else means
        # the per-indicator dedup cost is still being paid for a list that did
        # not change, which is the cost the conditional request exists to avoid.
        assert len(pipeline.batches) == first


class TestFailureIsNotSilence:
    async def test_unreachable_list_ingests_nothing_and_does_not_raise(self):
        def handler(request):
            return httpx.Response(500)

        pipeline = RecordingPipeline()
        # The scheduler treats a raising handler as a crashed feed; this one
        # degrades to "no indicators" the way the other public feeds do.
        await handle_netapi_feed(client=_client(handler), pipeline=pipeline)

        assert pipeline.batches == []

    async def test_one_failing_list_does_not_stop_the_other(self):
        def handler(request):
            if "ips" in str(request.url):
                return httpx.Response(503)
            return httpx.Response(200, text="evil.example\n")

        pipeline = RecordingPipeline()
        await handle_netapi_feed(client=_client(handler), pipeline=pipeline)

        assert [i["value"] for i in pipeline.all_iocs] == ["evil.example"]


class TestAirgap:
    async def test_airgapped_deployment_ingests_nothing(self, monkeypatch):
        from app import airgap

        monkeypatch.setattr(airgap.settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setattr(airgap.settings, "AISOC_AIRGAP_ALLOWLIST", [])

        def handler(request):  # pragma: no cover - must never be reached
            raise AssertionError("air-gapped deployment issued an outbound request")

        pipeline = RecordingPipeline()
        await handle_netapi_feed(client=_client(handler), pipeline=pipeline)

        assert pipeline.batches == []

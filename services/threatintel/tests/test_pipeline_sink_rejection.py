"""A sink that refuses documents without raising is not a sink that stored them.

What was wrong
--------------
``bulk_index_iocs`` called ``async_bulk(raise_on_error=False)``, which
reports a rejected document by *returning* it in the errors list rather than
raising — a mapping conflict or a disk flood-stage cluster block (429) comes
back through the no-exception path. The method logged only ``count`` and
returned the success count, so the pipeline's per-sink dedup (the backfill
half of issue #1278) recorded every *refused* document as stored. The next
poll read the whole batch as duplicate and never offered it again: on a live
stack whose OpenSearch sat behind a flood-stage block, the KEV corpus was in
Qdrant and Neo4j while ``threatintel-iocs`` held **zero documents,
permanently** — and ``match_ioc_values``, the actor-attribution verifier,
reads exactly that index.

What this asserts
-----------------
* ``bulk_index_iocs`` returns a :class:`BulkIndexOutcome` naming each
  rejected ``_id`` and carrying the vendor's reason strings, and the warning
  log says *why*, not only how many.
* The pipeline withholds refused documents from the per-sink dedup record:
  the next poll re-offers exactly them (writes are idempotent upserts on a
  stable ``_id``), while accepted documents stay deduplicated.
* A wholesale refusal (every document 429ed) records nothing for that sink,
  so the batch backfills after the block clears — the same recovery the
  unreachable-sink path already had.
* Positive control: a sink that accepts everything still dedups everything,
  and the healthy sinks beside a refusing one are unaffected.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.feeds.pipeline import ThreatIntelPipeline
from app.storage.opensearch import BulkIndexOutcome, OpenSearchStore, _stable_id

IOCS = [{"type": "vulnerability", "value": f"CVE-2026-{n:04d}", "source": "cisa-kev"} for n in range(4)]


def _doc_id(ioc: dict[str, Any]) -> str:
    return _stable_id(ioc.get("type", ""), ioc.get("value", ""), ioc.get("source", ""))


class _Bloom:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    async def contains(self, key: str) -> bool:
        return key in self._seen

    async def add(self, key: str) -> None:
        self._seen.add(key)


class _RejectingOpenSearch:
    """Accepts some documents and refuses the rest, the way a bulk API does."""

    def __init__(self, reject: set[str]) -> None:
        self.reject = reject
        self.offered: list[list[str]] = []

    async def bulk_index_iocs(self, iocs: list[dict[str, Any]]) -> BulkIndexOutcome:
        ids = [_doc_id(i) for i in iocs]
        self.offered.append(ids)
        rejected = frozenset(i for i in ids if i in self.reject)
        return BulkIndexOutcome(
            accepted=len(ids) - len(rejected),
            rejected_ids=rejected,
            error_sample=("status=429 cluster_block_exception: flood-stage",) if rejected else (),
        )


class _AcceptingSink:
    async def upsert_iocs(self, iocs: list[dict[str, Any]], **_kw: Any) -> None:
        return None


def _pipeline(os_store: Any) -> tuple[ThreatIntelPipeline, _Bloom]:
    bloom = _Bloom()
    pipe = ThreatIntelPipeline(
        bloom=bloom,  # type: ignore[arg-type]
        os_store=os_store,
        qdrant_store=_AcceptingSink(),  # type: ignore[arg-type]
        neo4j_store=_AcceptingSink(),  # type: ignore[arg-type]
        kafka_producer=None,
    )
    return pipe, bloom


@pytest.mark.asyncio
async def test_rejected_documents_are_reoffered_on_the_next_poll():
    rejected_ioc = IOCS[1]
    os_store = _RejectingOpenSearch(reject={_doc_id(rejected_ioc)})
    pipe, _ = _pipeline(os_store)

    first = await pipe.ingest_iocs(list(IOCS), source="cisa-kev")
    assert first["sinks"]["opensearch"] == len(IOCS) - 1  # stored all but the refused one

    second = await pipe.ingest_iocs(list(IOCS), source="cisa-kev")

    # The second poll offered OpenSearch exactly the refused document — not
    # the whole batch (accepted ones are deduplicated), and not nothing
    # (which is what marking refusals as stored used to produce).
    assert os_store.offered[1] == [_doc_id(rejected_ioc)]
    assert second["sinks"]["opensearch"] == 0  # still refused; still not marked


@pytest.mark.asyncio
async def test_wholesale_refusal_backfills_after_the_block_clears():
    os_store = _RejectingOpenSearch(reject={_doc_id(i) for i in IOCS})
    pipe, _ = _pipeline(os_store)

    first = await pipe.ingest_iocs(list(IOCS), source="cisa-kev")
    assert first["sinks"]["opensearch"] == 0

    # The block clears (sink stops refusing); the next poll must re-offer
    # the entire batch and succeed.
    os_store.reject = set()
    second = await pipe.ingest_iocs(list(IOCS), source="cisa-kev")

    assert sorted(os_store.offered[1]) == sorted(_doc_id(i) for i in IOCS)
    assert second["sinks"]["opensearch"] == len(IOCS)

    # And once stored, a third poll offers nothing — dedup still works.
    third = await pipe.ingest_iocs(list(IOCS), source="cisa-kev")
    assert len(os_store.offered) == 2
    assert third["sinks"]["opensearch"] == 0


@pytest.mark.asyncio
async def test_accepting_sink_still_deduplicates_everything():
    os_store = _RejectingOpenSearch(reject=set())
    pipe, _ = _pipeline(os_store)

    first = await pipe.ingest_iocs(list(IOCS), source="cisa-kev")
    second = await pipe.ingest_iocs(list(IOCS), source="cisa-kev")

    assert first["sinks"]["opensearch"] == len(IOCS)
    assert second["sinks"]["opensearch"] == 0
    assert len(os_store.offered) == 1  # nothing re-offered


@pytest.mark.asyncio
async def test_bulk_outcome_extracts_rejected_ids_and_reasons(monkeypatch):
    """The store reads async_bulk's error items into ids + reason samples."""
    from app.storage import opensearch as os_mod

    captured: dict[str, Any] = {}

    async def _fake_async_bulk(client: Any, actions: list[dict], **kw: Any):
        captured["actions"] = actions
        errors = [
            {
                "index": {
                    "_index": "threatintel-iocs",
                    "_id": actions[0]["_id"],
                    "status": 429,
                    "error": {
                        "type": "cluster_block_exception",
                        "reason": "index [threatintel-iocs] blocked by: "
                        "[TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark ...]",
                    },
                }
            }
        ]
        return len(actions) - 1, errors

    monkeypatch.setattr(os_mod.helpers, "async_bulk", _fake_async_bulk)

    store = OpenSearchStore(client=object())  # client is only handed to async_bulk
    outcome = await store.bulk_index_iocs(list(IOCS))

    assert isinstance(outcome, BulkIndexOutcome)
    assert outcome.accepted == len(IOCS) - 1
    assert outcome.rejected == 1
    assert captured["actions"][0]["_id"] in outcome.rejected_ids
    assert "cluster_block_exception" in outcome.error_sample[0]
    assert "flood-stage" in outcome.error_sample[0]

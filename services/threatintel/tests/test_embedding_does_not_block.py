"""The embedding path must not stop the service answering.

Found by the weekly chaos `qdrant` leg, which failed twice in a row on
"threatintel stopped serving" while the store it was grading was not the
cause. `QdrantStore._embed` was `async def` and awaited nothing:
`model.embed(texts)` is synchronous ONNX inference, so it ran on the event
loop and the process answered nothing at all for its duration -- including
`/health`. threatintel's first CISA KEV poll embeds 1,756 indicators about
25 s after boot, which is exactly where a readiness read was landing.

What is asserted here is the property, not the implementation: while an
embed is in flight, another coroutine must still get scheduled. A test that
only checked for `asyncio.to_thread` in the source would pass for a future
edit that reintroduces the block by another route.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from app.storage import qdrant as qdrant_module
from app.storage.qdrant import QdrantStore


class _SlowModel:
    """Stands in for `TextEmbedding` at the one thing that matters: it blocks.

    `time.sleep` rather than `asyncio.sleep` on purpose -- the defect is CPU
    work that never yields, and an awaitable double could not reproduce it.
    """

    def __init__(self, seconds: float = 0.5) -> None:
        self.seconds = seconds
        self.calls = 0

    def embed(self, texts: list[str]):
        self.calls += 1
        time.sleep(self.seconds)
        return [[0.1] * 384 for _ in texts]


@pytest.mark.asyncio
async def test_the_event_loop_keeps_running_while_an_embed_is_in_flight(monkeypatch) -> None:
    model = _SlowModel(seconds=0.5)
    monkeypatch.setattr(qdrant_module, "_EMBEDDING_MODEL", model)

    store = QdrantStore(client=None)  # type: ignore[arg-type]
    heartbeats = 0

    # The deadline is absolute and fixed BEFORE the embed starts, which is
    # the whole load-bearing detail. A relative window computed inside the
    # heartbeat is useless here: a blocking embed simply runs first and the
    # heartbeat then gets its full window afterwards, so the test passes
    # against the defect. That version was written, run against the pre-fix
    # implementation, and did not catch it.
    deadline = time.monotonic() + 0.4

    async def _heartbeat() -> None:
        nonlocal heartbeats
        # Stands in for anything the service still owes an answer to while a
        # feed is ingesting: a health probe, a search, a push.
        while time.monotonic() < deadline:
            await asyncio.sleep(0.02)
            heartbeats += 1

    heartbeat = asyncio.create_task(_heartbeat())
    vectors = await store._embed(["a", "b", "c"])
    await heartbeat

    assert model.calls == 1, "the embed never ran, so this proves nothing"
    assert len(vectors) == 3
    # Negative control: with the inference back on the event loop the
    # heartbeat cannot be scheduled until the embed returns, by which time
    # the deadline has passed, and this lands at 0.
    assert heartbeats > 5, f"the event loop was blocked during the embed ({heartbeats} heartbeats)"


@pytest.mark.asyncio
async def test_the_model_is_loaded_once_and_reused(monkeypatch) -> None:
    """`TextEmbedding()` reads an ONNX model off disk; the old code paid that per call."""
    loads = 0
    model = _SlowModel(seconds=0.0)

    def _fake_text_embedding(**_kwargs):
        nonlocal loads
        loads += 1
        return model

    monkeypatch.setattr(qdrant_module, "_EMBEDDING_MODEL", None)
    import fastembed  # noqa: PLC0415 - patched per test, not at import time

    monkeypatch.setattr(fastembed, "TextEmbedding", _fake_text_embedding)

    store = QdrantStore(client=None)  # type: ignore[arg-type]
    await store._embed(["a"])
    await store._embed(["b"])
    await store._embed(["c"])

    assert loads == 1, f"the embedding model was constructed {loads} times"
    assert model.calls == 3


@pytest.mark.asyncio
async def test_an_unavailable_model_still_returns_vectors_rather_than_raising(monkeypatch) -> None:
    """Unchanged behaviour: embeddings degrade to zeros, ingestion continues."""

    class _Broken:
        def embed(self, _texts):
            raise RuntimeError("onnxruntime is not installed")

    monkeypatch.setattr(qdrant_module, "_EMBEDDING_MODEL", _Broken())

    store = QdrantStore(client=None)  # type: ignore[arg-type]
    vectors = await store._embed(["a", "b"])

    assert len(vectors) == 2
    assert all(all(component == 0.0 for component in vector) for vector in vectors)

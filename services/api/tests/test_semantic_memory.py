"""Semantic memory: provenance, conflict review, and refusing to fake a recall.

Depth plan 9.2 (parity 6.5).

The properties, each asserted by name below:

* an ingest records the **authenticated** principal as the author, not
  whatever the body claimed -- provenance a caller can set is not provenance;
* two claims about the same subject suspend **both** sides rather than
  last-write-wins, and recall returns neither until a human settles it;
* re-ingesting the identical content is idempotent and does not re-embed;
* retirement is not deletion: the row and its provenance survive;
* recall is **tenant-scoped in the filter itself**, and the function refuses
  to run unscoped rather than defaulting;
* with no embedding backend, recall is **503 with the reason** -- never an
  empty list, because "found nothing" and "could not look" are different
  facts;
* an oversized embedding is refused rather than truncated, because
  truncating measured as a worse retriever that nobody could see.

The database is real, on the SQLite-compiles-Postgres-types basis
``test_mcp_registry.py`` uses. Qdrant and the embedding backend are stubbed
at the HTTP boundary with a real ``httpx`` transport rather than by patching
the functions under test, so what runs is the request this service really
makes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints.semantic_memory import router as memory_router
from app.db.database import Base, get_db
from app.db.rls import get_tenant_db
from app.models.audit import AuditLog
from app.models.semantic_memory import MemoryItem
from app.services import semantic_memory as svc
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-0000000000b1")
OTHER_TENANT = uuid.UUID("bbbbbbbb-0000-0000-0000-0000000000b2")
ANALYST = uuid.UUID("33333333-3333-3333-3333-333333333333")


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


@compiles(INET, "sqlite")
def _inet_sqlite(_type_, _compiler_, **_kw_):
    return "VARCHAR(45)"


class FakeVectorBackend:
    """Qdrant and an embedding backend, behind a real httpx transport.

    A deterministic embedding: the vector is a bag of character counts, so
    two similar strings land near each other and the search below ranks for
    a reason rather than by insertion order. Crude, and that is the point --
    the test is about the plumbing and the filter, not about retrieval
    quality, which ``scripts/score_memory_recall.py`` measures properly.
    """

    def __init__(self, *, embed_dim: int = 1536) -> None:
        self.embed_dim = embed_dim
        self.points: dict[str, dict] = {}
        self.searches: list[dict] = []
        self.embed_calls = 0
        self.collection_created = False

    def _vector(self, text: str) -> list[float]:
        vec = [0.0] * self.embed_dim
        for index, ch in enumerate(text.lower()[:400]):
            vec[(ord(ch) * 7 + index) % self.embed_dim] += 1.0
        return vec

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/embeddings"):
            self.embed_calls += 1
            body = request.read().decode()
            import json as _json

            inputs = _json.loads(body)["input"]
            return httpx.Response(200, json={"data": [{"embedding": self._vector(t)} for t in inputs]})
        if path == f"/collections/{svc.COLLECTION}" and request.method == "GET":
            if not self.collection_created:
                return httpx.Response(404, json={})
            return httpx.Response(
                200,
                json={
                    "result": {
                        "config": {"params": {"vectors": {"size": self.embed_dim}}},
                        "points_count": len(self.points),
                    }
                },
            )
        if path == f"/collections/{svc.COLLECTION}" and request.method == "PUT":
            self.collection_created = True
            return httpx.Response(200, json={"result": True})
        if path == f"/collections/{svc.COLLECTION}/points":
            import json as _json

            for point in _json.loads(request.read().decode())["points"]:
                self.points[str(point["id"])] = point
            return httpx.Response(200, json={"result": {"status": "completed"}})
        if path == f"/collections/{svc.COLLECTION}/points/delete":
            import json as _json

            for pid in _json.loads(request.read().decode())["points"]:
                self.points.pop(str(pid), None)
            return httpx.Response(200, json={"result": {"status": "completed"}})
        if path == f"/collections/{svc.COLLECTION}/points/search":
            import json as _json

            body = _json.loads(request.read().decode())
            self.searches.append(body)
            wanted = {c["key"]: c["match"]["value"] for c in body["filter"]["must"] if "value" in c.get("match", {})}
            results = []
            for point in self.points.values():
                payload = point["payload"]
                if any(payload.get(k) != v for k, v in wanted.items()):
                    continue
                score = sum(a * b for a, b in zip(point["vector"], body["vector"], strict=False))
                results.append({"id": point["id"], "score": score, "payload": payload})
            results.sort(key=lambda r: -r["score"])
            return httpx.Response(200, json={"result": results[: body["limit"]]})
        return httpx.Response(404, json={})


@pytest.fixture
def backend(monkeypatch):
    """Point the service at the fake, through a real transport."""
    fake = FakeVectorBackend()
    transport = httpx.MockTransport(fake.handler)
    original = httpx.AsyncClient

    def _client(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(svc.httpx, "AsyncClient", _client)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://embeddings.test/v1")
    monkeypatch.setattr(svc, "DEFAULT_EMBEDDING_MODEL", "test-embed")
    monkeypatch.setattr(svc.settings, "QDRANT_URL", "http://qdrant.test", raising=False)
    return fake


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=[MemoryItem.__table__, AuditLog.__table__])
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _principal(tenant: uuid.UUID = TENANT, key_prefix: str = "aisoc_analyst") -> CurrentUser:
    return CurrentUser(
        user_id=ANALYST,
        tenant_id=tenant,
        role="analyst",
        email="analyst@example.com",
        scopes=["*"],
        api_key_prefix=key_prefix,
    )


@pytest_asyncio.fixture
async def client(session_factory):
    app = FastAPI()
    app.include_router(memory_router, prefix="/api/v1")
    state = {"user": _principal()}

    async def _db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_tenant_db] = _db
    app.dependency_overrides[get_current_user] = lambda: state["user"]
    with TestClient(app) as c:
        c.state_holder = state  # type: ignore[attr-defined]
        yield c


def _ingest(client, subject: str, content: str, **kw):
    return client.post(
        "/api/v1/memory/items",
        json={"kind": kw.pop("kind", "memory"), "subject": subject, "content": content, **kw},
    )


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_author_is_the_principal_not_the_body(client, backend) -> None:
    res = _ingest(client, "10.40.0.0/16", "The card payment estate.", source="import")
    assert res.status_code == 201, res.text
    item = res.json()["item"]
    # The caller chose `source`, which is a fact about where the content came
    # from. It did not get to choose `author`, which is a claim about who is
    # standing behind it.
    assert item["source"] == "import"
    assert item["author"] == "aisoc_analyst"
    assert item["scope"] == "tenant"
    assert item["state"] == "in_use"
    assert res.json()["indexed"] is True
    assert item["embedding_model"] == "test-embed"
    assert item["embedded_at"] is not None


@pytest.mark.asyncio
async def test_re_ingesting_the_same_content_is_idempotent_and_does_not_re_embed(client, backend) -> None:
    _ingest(client, "10.40.0.0/16", "The card payment estate.")
    calls_after_first = backend.embed_calls
    again = _ingest(client, "10.40.0.0/16", "The card payment estate.")
    assert again.json()["outcome"] == "unchanged"
    # Re-embedding a vector that cannot have changed spends a model call per
    # re-ingest, and a nightly re-sync would spend one per item per night.
    assert backend.embed_calls == calls_after_first


# ---------------------------------------------------------------------------
# Conflict review
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_contradiction_suspends_both_sides_and_recall_returns_neither(client, backend) -> None:
    first = _ingest(client, "10.40.0.0/16", "The card payment estate, PCI in scope.").json()["item"]
    second = _ingest(client, "10.40.0.0/16", "Decommissioned in March; nothing lives there.")
    assert second.json()["outcome"] == "conflict"

    conflicts = client.get("/api/v1/memory/conflicts").json()
    assert len(conflicts) == 1
    pair = {conflicts[0]["left"]["id"], conflicts[0]["right"]["id"]}
    assert first["id"] in pair

    # Neither side is recalled. Preferring the newer one would silently undo
    # an analyst's correction the next time the job that wrote the bad entry
    # ran again, which is the case the feature exists for.
    hits = client.post("/api/v1/memory/recall", json={"query": "card payment estate"}).json()
    assert hits == []


@pytest.mark.asyncio
async def test_resolving_a_conflict_restores_exactly_one_side(client, backend) -> None:
    first = _ingest(client, "10.40.0.0/16", "The card payment estate, PCI in scope.").json()["item"]
    second = _ingest(client, "10.40.0.0/16", "Decommissioned in March.").json()["item"]

    resolved = client.post(
        f"/api/v1/memory/conflicts/{second['id']}/resolve",
        json={"keep": first["id"], "note": "the decommission was a different range"},
    )
    assert resolved.status_code == 200, resolved.text

    states = {row["id"]: row["state"] for row in client.get("/api/v1/memory/items").json()}
    assert states[first["id"]] == "in_use"
    assert states[second["id"]] == "not_in_use"
    assert client.get("/api/v1/memory/conflicts").json() == []

    hits = client.post("/api/v1/memory/recall", json={"query": "card payment estate PCI"}).json()
    assert [h["item"]["id"] for h in hits] == [first["id"]]


@pytest.mark.asyncio
async def test_resolving_must_name_one_of_the_two(client, backend) -> None:
    first = _ingest(client, "subject-a", "one").json()["item"]
    second = _ingest(client, "subject-a", "two").json()["item"]
    unrelated = _ingest(client, "subject-b", "three").json()["item"]
    res = client.post(f"/api/v1/memory/conflicts/{second['id']}/resolve", json={"keep": unrelated["id"]})
    assert res.status_code == 422
    assert first["id"] not in res.text or "one of the two" in res.text


# ---------------------------------------------------------------------------
# Retirement, expiry, isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retirement_keeps_the_row_and_its_provenance(client, backend, session_factory) -> None:
    item = _ingest(client, "subject-a", "a claim").json()["item"]
    res = client.delete(f"/api/v1/memory/items/{item['id']}?reason=wrong")
    assert res.status_code == 200
    assert res.json()["state"] == "not_in_use"
    assert res.json()["author"] == "aisoc_analyst"

    async with session_factory() as session:
        row = (await session.execute(select(MemoryItem).where(MemoryItem.id == uuid.UUID(item["id"])))).scalar_one()
        # "What did the agent know when it decided that" has to stay
        # answerable after somebody decides the item was wrong.
        assert row.content == "a claim"
        assert row.state_reason == "wrong"


@pytest.mark.asyncio
async def test_an_expired_item_is_not_recalled_without_a_sweep_job(client, backend, session_factory) -> None:
    item = _ingest(client, "subject-a", "temporary maintenance window").json()["item"]
    async with session_factory() as session:
        row = (await session.execute(select(MemoryItem).where(MemoryItem.id == uuid.UUID(item["id"])))).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await session.commit()
    # Expiry is applied at read, so a worker being down cannot resurrect it.
    assert client.post("/api/v1/memory/recall", json={"query": "maintenance window"}).json() == []


@pytest.mark.asyncio
async def test_recall_is_scoped_in_the_filter_itself(client, backend) -> None:
    _ingest(client, "subject-a", "tenant one's claim")
    client.post("/api/v1/memory/recall", json={"query": "claim"})
    assert backend.searches, "no search reached the vector store"
    must = backend.searches[-1]["filter"]["must"]
    assert {"key": "tenant_id", "match": {"value": str(TENANT)}} in must
    # `state` is matched in the store as well as in Postgres: a point whose
    # row was retired but whose delete failed would otherwise be recalled and
    # discarded late.
    assert {"key": "state", "match": {"value": "in_use"}} in must


@pytest.mark.asyncio
async def test_another_tenant_sees_none_of_it(client, backend) -> None:
    _ingest(client, "subject-a", "tenant one's claim")
    client.state_holder["user"] = _principal(OTHER_TENANT, "aisoc_other")  # type: ignore[attr-defined]
    assert client.post("/api/v1/memory/recall", json={"query": "claim"}).json() == []
    assert client.get("/api/v1/memory/items").json() == []


@pytest.mark.asyncio
async def test_search_refuses_to_run_unscoped() -> None:
    """No `tenant_id=None` branch. Nothing here is shared, so there is no caller."""
    with pytest.raises(ValueError, match="scoped to a tenant"):
        await svc.search("anything", tenant_id=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Honest unavailability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_embedding_backend_is_503_with_a_reason_not_an_empty_list(client, monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_GATEWAY_URL", raising=False)
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    monkeypatch.setattr(svc, "embedding_backend", lambda: None)
    res = client.post("/api/v1/memory/recall", json={"query": "anything"})
    # An empty list here would render as "we searched your memory and found
    # nothing", which is a confident claim about a search that never ran.
    assert res.status_code == 503
    assert "No embedding backend is configured" in res.json()["detail"]


@pytest.mark.asyncio
async def test_an_item_stored_but_not_indexed_says_so(client, monkeypatch) -> None:
    monkeypatch.setattr(svc, "embedding_backend", lambda: None)
    res = _ingest(client, "subject-a", "a claim nobody can recall yet")
    assert res.status_code == 201
    body = res.json()
    assert body["indexed"] is False
    assert "No embedding backend" in body["index_error"]
    assert body["item"]["embedding_model"] is None


def test_an_oversized_embedding_is_refused_rather_than_truncated() -> None:
    """Truncating measured as a worse retriever that nobody could see.

    Scored over the probe set with the 3072-dimension model available
    locally, truncation put recall@1 at 0.167 against a 0.667 lexical
    baseline -- a number measuring the truncation, not the model.
    """
    with pytest.raises(svc.EmbeddingsUnavailable, match="3072-dimension"):
        svc._fit([0.1] * 3072)
    # Padding is harmless under cosine and stays allowed.
    assert len(svc._fit([0.1] * 768)) == svc.EMBEDDING_DIM


@pytest.mark.asyncio
async def test_status_distinguishes_never_embedded_from_embedded_by_another_model(client, backend, session_factory) -> None:
    item = _ingest(client, "subject-a", "a claim").json()["item"]
    _ingest(client, "subject-b", "another claim")
    async with session_factory() as session:
        row = (await session.execute(select(MemoryItem).where(MemoryItem.id == uuid.UUID(item["id"])))).scalar_one()
        row.embedding_model = "a-model-nobody-runs-now"
        await session.commit()

    status = client.get("/api/v1/memory/status").json()
    # Two different states calling for two different actions. Collapsing
    # them into one "needs attention" number is how an operator ends up
    # re-embedding rows that were never embedded in the first place.
    assert status["in_use_embedded_by_another_model"] == 1
    assert status["in_use_never_embedded"] == 0
    assert status["items_by_state"]["in_use"] == 2
    assert status["recall_available"] is True


@pytest.mark.asyncio
async def test_status_says_recall_is_unavailable_rather_than_reporting_zeroes(client, monkeypatch) -> None:
    monkeypatch.setattr(svc, "embedding_backend", lambda: None)
    status = client.get("/api/v1/memory/status").json()
    assert status["recall_available"] is False
    assert status["embedding_backend"] is None
    # Not 0 — a dimension nobody could ask about is unknown, not zero.
    assert status["collection_dimension"] is None


# ---------------------------------------------------------------------------
# The automatic writer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_closing_a_case_writes_a_memory_item(backend, session_factory) -> None:
    """``kind='case'`` would be permanently empty without this caller."""
    case_id = uuid.uuid4()
    async with session_factory() as session:
        item_id = await svc.remember_closed_case(
            session,
            tenant_id=TENANT,
            case_id=case_id,
            title="Ransomware on the file server",
            summary="Closed as a true positive; the appliance was not in the asset register.",
            author="analyst@example.com",
        )
        await session.commit()
    assert item_id is not None
    async with session_factory() as session:
        row = (await session.execute(select(MemoryItem).where(MemoryItem.id == item_id))).scalar_one()
        assert row.kind == "case"
        assert row.subject == f"case:{case_id}"
        assert row.source == "case_closure"
        assert row.embedding_model == "test-embed"


@pytest.mark.asyncio
async def test_a_case_closed_with_no_narrative_writes_nothing(backend, session_factory) -> None:
    """Padding recall with rows whose content is a title makes it answer worse."""
    async with session_factory() as session:
        assert (
            await svc.remember_closed_case(
                session,
                tenant_id=TENANT,
                case_id=uuid.uuid4(),
                title="A case",
                summary="   ",
                author="analyst@example.com",
            )
            is None
        )

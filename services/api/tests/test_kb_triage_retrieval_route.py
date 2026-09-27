"""Who may read the triage retrieval route, and what it returns when nothing survives.

Gap-closure Phase 6.3 gate, API half.

What is *not* here, and why. The statement this route runs is PostgreSQL:
``to_tsvector``, ``plainto_tsquery``, ``ts_rank``, ``FILTER (WHERE ...)`` and
``LEFT JOIN LATERAL``. This suite runs on SQLite, where it does not parse, so
the filtering itself is proven against a real database in
``tests/isolation/test_kb_retrieval_cutoff_live.py`` instead, running the same
``triage_retrieval_sql`` this route calls. Stating that here rather than
writing a SQLite-shaped approximation, because an approximation would pass
while the real statement was broken.

What is here is everything that holds regardless of the database:

* the credential, including that a console session is *not* one;
* that a caller who names no instant gets no cutoff, so an unfrozen read can
  never be reported as a frozen one;
* that the counts survive a result set with no rows in it, which is the case
  they exist for.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from app.api.v1.deps import CurrentUser, get_current_user, get_db
from app.api.v1.endpoints import knowledge_base as kb_endpoint
from app.api.v1.endpoints.knowledge_base import router as kb_router
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-0000000000cb")
SERVICE_TOKEN = "service-token-for-the-agents-worker"


class _Row:
    def __init__(self, **fields: Any) -> None:
        self.__dict__.update(fields)


class _Result:
    def __init__(self, rows: list[_Row]) -> None:
        self._rows = rows

    def fetchall(self) -> list[_Row]:
        return self._rows


class _Session:
    """Records the statement and its parameters; returns what the test set."""

    def __init__(self, rows: list[_Row]) -> None:
        self.rows = rows
        self.statements: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, statement: Any) -> _Result:
        self.statements.append((str(statement), dict(statement.compile().params)))
        return _Result(self.rows)


def _app(session: _Session, *, user: CurrentUser | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(kb_router, prefix="/api/v1")

    async def _db() -> Any:
        yield session

    app.dependency_overrides[get_db] = _db
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _chunk_row(**over: Any) -> _Row:
    fields: dict[str, Any] = {
        "excluded_after_cutoff": 0,
        "without_timestamp": 0,
        "id": uuid.uuid4(),
        "title": "Password spray runbook",
        "doc_kind": "runbook",
        "source_url": None,
        "chunk_index": 0,
        "chunk_total": 1,
        "content": "Check the VPN pool.",
        "created_at": datetime(2026, 4, 1, tzinfo=UTC),
        "rank": 0.5,
    }
    fields.update(over)
    return _Row(**fields)


@pytest.fixture
def _service_token(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)

    async def _noop(_db, _tenant):
        return None

    # The route sets the RLS GUC, which SQLite and this fake session have no
    # notion of. The policy itself is exercised in tests/isolation.
    monkeypatch.setattr(kb_endpoint, "set_rls_context", _noop)
    yield


_URL = "/api/v1/kb/runbooks/for-triage"
_HEADERS = {"X-AiSOC-Service-Token": SERVICE_TOKEN}


class TestCredential:
    def test_a_missing_token_is_refused(self, _service_token) -> None:
        client = TestClient(_app(_Session([])))
        response = client.get(_URL, params={"tenant_id": str(TENANT), "q": "password spray"})
        assert response.status_code == 401

    def test_a_wrong_token_is_refused(self, _service_token) -> None:
        client = TestClient(_app(_Session([])))
        response = client.get(
            _URL,
            params={"tenant_id": str(TENANT), "q": "password spray"},
            headers={"X-AiSOC-Service-Token": "not-the-token"},
        )
        assert response.status_code == 401

    def test_a_valid_console_session_is_still_refused(self, _service_token) -> None:
        """A session is a credential for ``/kb/query``, not for this route.

        Same reasoning as ``/tenant-skills/resolved/active``: this route has
        one caller, and a route with one caller should accept one kind of
        credential. An analyst who wants these chunks has ``/kb/query``, which
        returns more.
        """
        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="tenant_admin", email="a@example.invalid", scopes=["*"])
        client = TestClient(_app(_Session([]), user=user))
        response = client.get(_URL, params={"tenant_id": str(TENANT), "q": "password spray"})
        assert response.status_code == 401


class TestCutoff:
    def test_no_instant_named_means_no_cutoff_predicate_and_no_cutoff_echoed(self, _service_token) -> None:
        """An unfrozen read must never be reportable as a frozen one.

        The reader decides whether it is replaying by reading ``as_of`` back
        off the reply, so a route that echoed an instant it had not applied,
        or defaulted one nobody asked for, would make a live replay look
        point-in-time.
        """
        session = _Session([_chunk_row()])
        client = TestClient(_app(session))
        response = client.get(_URL, params={"tenant_id": str(TENANT), "q": "password spray"}, headers=_HEADERS)

        assert response.status_code == 200
        assert response.json()["as_of"] is None
        statement, params = session.statements[0]
        assert "created_at <= " not in statement
        assert "as_of" not in params

    def test_naming_an_instant_puts_the_predicate_in_the_statement_and_echoes_it(self, _service_token) -> None:
        session = _Session([_chunk_row()])
        client = TestClient(_app(session))
        response = client.get(
            _URL,
            params={"tenant_id": str(TENANT), "q": "password spray", "as_of": "2026-05-01T12:00:00+00:00"},
            headers=_HEADERS,
        )

        assert response.status_code == 200
        assert response.json()["as_of"] == "2026-05-01T12:00:00Z"
        statement, params = session.statements[0]
        assert "created_at <= :as_of" in statement
        assert params["as_of"] == datetime(2026, 5, 1, 12, 0, tzinfo=UTC)

    def test_the_counts_survive_a_cutoff_that_refused_everything(self, _service_token) -> None:
        """The case the LATERAL join exists for.

        When nothing survives the cutoff the statement still returns one row,
        carrying the counts and NULLs for the chunk. A plain join would return
        no rows at all and the refusal count would be lost exactly when it
        matters most: a replay would report "no runbooks" and a reader could
        not tell that from a knowledge base with nothing in it.
        """
        session = _Session([_chunk_row(id=None, title=None, excluded_after_cutoff=7, without_timestamp=2)])
        client = TestClient(_app(session))
        response = client.get(
            _URL,
            params={"tenant_id": str(TENANT), "q": "password spray", "as_of": "2026-05-01T12:00:00+00:00"},
            headers=_HEADERS,
        )

        body = response.json()
        assert body["chunks"] == []
        assert body["excluded_after_cutoff"] == 7
        assert body["without_timestamp"] == 2


class TestScope:
    def test_only_the_document_kinds_that_tell_an_analyst_what_to_do(self, _service_token) -> None:
        """A policy or a wiki page is prompt budget the evidence does not get."""
        session = _Session([_chunk_row()])
        client = TestClient(_app(session))
        client.get(_URL, params={"tenant_id": str(TENANT), "q": "password spray"}, headers=_HEADERS)

        _, params = session.statements[0]
        assert params["kinds"] == ["runbook", "playbook", "sop"]

    def test_the_tenant_is_bound_as_a_parameter_not_interpolated(self, _service_token) -> None:
        session = _Session([_chunk_row()])
        client = TestClient(_app(session))
        client.get(_URL, params={"tenant_id": str(TENANT), "q": "password spray"}, headers=_HEADERS)

        statement, params = session.statements[0]
        assert params["tenant_id"] == TENANT
        assert str(TENANT) not in statement

    def test_the_query_string_is_bound_rather_than_concatenated(self, _service_token) -> None:
        """The query is built from the alert summary, which an attacker influences."""
        session = _Session([_chunk_row()])
        client = TestClient(_app(session))
        hostile = "'; DROP TABLE aisoc_kb_documents; --"
        client.get(_URL, params={"tenant_id": str(TENANT), "q": hostile}, headers=_HEADERS)

        statement, params = session.statements[0]
        assert params["q"] == hostile
        assert "DROP TABLE" not in statement

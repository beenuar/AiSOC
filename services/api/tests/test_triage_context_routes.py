"""The two remaining triage-context routes: who may read, and what the cutoff does.

Gap-closure Phase 6.3 gate, API half.

``/feedback/recent-dispositions`` runs PostgreSQL that SQLite cannot parse
(``FILTER (WHERE ...)``, ``LEFT JOIN LATERAL``, ``ANY(CAST(... AS text[]))``,
``context ->> 'rule_id'``), so its filtering is proven against a real database
in ``tests/isolation/test_recent_dispositions_cutoff_live.py``, running the
same ``recent_dispositions_sql`` the route calls. Here: the credential, the
presence or absence of the cutoff predicate, and the counts surviving an empty
result set.

``/graph/identity-context`` is the opposite shape. Its cutoff is applied in
Python, on an import stamp the graph returns, so the filtering *is* testable
here and is. What cannot be tested here is the Cypher, which needs Neo4j.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from app.api.v1.deps import CurrentUser, get_current_user, get_db
from app.api.v1.endpoints import feedback as feedback_endpoint
from app.api.v1.endpoints import graph as graph_endpoint
from app.api.v1.endpoints.feedback import router as feedback_router
from app.api.v1.endpoints.graph import router as graph_router
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-0000000000df")
SERVICE_TOKEN = "service-token-for-the-agents-worker"
HEADERS = {"X-AiSOC-Service-Token": SERVICE_TOKEN}


class _Row:
    def __init__(self, **fields: Any) -> None:
        self.__dict__.update(fields)


class _Result:
    def __init__(self, rows: list[_Row]) -> None:
        self._rows = rows

    def fetchall(self) -> list[_Row]:
        return self._rows


class _Session:
    def __init__(self, rows: list[_Row]) -> None:
        self.rows = rows
        self.statements: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, statement: Any) -> _Result:
        self.statements.append((str(statement), dict(statement.compile().params)))
        return _Result(self.rows)


def _app(session: _Session | None = None, *, user: CurrentUser | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(feedback_router, prefix="/api/v1")
    app.include_router(graph_router, prefix="/api/v1")

    async def _db() -> Any:
        yield session

    app.dependency_overrides[get_db] = _db
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _decision_row(**over: Any) -> _Row:
    fields: dict[str, Any] = {
        "excluded_after_cutoff": 0,
        "without_timestamp": 0,
        "analyst_disposition": "benign_true_positive",
        "ai_disposition": "true_positive",
        "reason_code": "known_admin_tool",
        "scope": "binary",
        "scope_value": "powershell.exe",
        "note": "Nightly reconciliation batch.",
        "created_at": datetime(2026, 4, 2, tzinfo=UTC),
        "rule_id": "rule-encoded-powershell",
    }
    fields.update(over)
    return _Row(**fields)


@pytest.fixture
def _service_token(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)

    async def _noop(_db, _tenant):
        return None

    monkeypatch.setattr(feedback_endpoint, "set_rls_context", _noop)
    yield


_DISPO_URL = "/api/v1/feedback/recent-dispositions"
_IDENTITY_URL = "/api/v1/graph/identity-context"


class TestRecentDispositionsCredential:
    def test_a_missing_token_is_refused(self, _service_token) -> None:
        client = TestClient(_app(_Session([])))
        assert client.get(_DISPO_URL, params={"tenant_id": str(TENANT), "rule_id": "r"}).status_code == 401

    def test_a_valid_console_session_is_still_refused(self, _service_token) -> None:
        """Unlike ``/feedback/context-statements`` next door, which is dual-mode.

        That route also serves a console panel. This one has a single caller,
        and a route with one caller should accept one kind of credential.
        """
        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="tenant_admin", email="a@example.invalid", scopes=["*"])
        client = TestClient(_app(_Session([]), user=user))
        assert client.get(_DISPO_URL, params={"tenant_id": str(TENANT), "rule_id": "r"}).status_code == 401


class TestRecentDispositionsCutoff:
    def test_no_instant_named_means_no_predicate_and_no_echo(self, _service_token) -> None:
        session = _Session([_decision_row()])
        client = TestClient(_app(session))
        response = client.get(_DISPO_URL, params={"tenant_id": str(TENANT), "rule_id": "rule-encoded-powershell"}, headers=HEADERS)

        assert response.status_code == 200
        assert response.json()["as_of"] is None
        statement, params = session.statements[0]
        assert "created_at <= " not in statement
        assert "as_of" not in params

    def test_naming_an_instant_puts_the_predicate_in_and_echoes_it(self, _service_token) -> None:
        session = _Session([_decision_row()])
        client = TestClient(_app(session))
        response = client.get(
            _DISPO_URL,
            params={"tenant_id": str(TENANT), "rule_id": "r", "as_of": "2026-05-01T12:00:00+00:00"},
            headers=HEADERS,
        )

        assert response.json()["as_of"] == "2026-05-01T12:00:00Z"
        statement, params = session.statements[0]
        assert "created_at <= :as_of" in statement
        assert params["as_of"] == datetime(2026, 5, 1, 12, 0, tzinfo=UTC)

    def test_the_counts_survive_a_cutoff_that_refused_everything(self, _service_token) -> None:
        session = _Session([_decision_row(analyst_disposition=None, excluded_after_cutoff=9, without_timestamp=1)])
        client = TestClient(_app(session))
        body = client.get(
            _DISPO_URL,
            params={"tenant_id": str(TENANT), "rule_id": "r", "as_of": "2026-05-01T12:00:00+00:00"},
            headers=HEADERS,
        ).json()

        assert body["dispositions"] == []
        assert body["excluded_after_cutoff"] == 9
        assert body["without_timestamp"] == 1

    def test_the_reason_label_travels_with_the_code(self, _service_token) -> None:
        """``bad_detection_logic`` is a key in a table the prompt's reader lacks."""
        session = _Session([_decision_row(reason_code="bad_detection_logic")])
        client = TestClient(_app(session))
        body = client.get(_DISPO_URL, params={"tenant_id": str(TENANT), "rule_id": "r"}, headers=HEADERS).json()

        assert body["dispositions"][0]["reason_label"] == "Bad detection logic"

    def test_an_unknown_reason_code_falls_back_to_the_code_rather_than_raising(self, _service_token) -> None:
        """A row written before a code was retired must not 500 the route."""
        session = _Session([_decision_row(reason_code="retired_code")])
        client = TestClient(_app(session))
        body = client.get(_DISPO_URL, params={"tenant_id": str(TENANT), "rule_id": "r"}, headers=HEADERS).json()

        assert body["dispositions"][0]["reason_label"] == "retired_code"

    def test_entities_are_lowercased_and_deduplicated_before_binding(self, _service_token) -> None:
        session = _Session([_decision_row()])
        client = TestClient(_app(session))
        client.get(
            _DISPO_URL,
            params=[("tenant_id", str(TENANT)), ("rule_id", "r"), ("entities", "FIN-APP-03"), ("entities", "fin-app-03")],
            headers=HEADERS,
        )

        _, params = session.statements[0]
        assert params["entities"] == ["fin-app-03"]


class TestIdentityContextRoute:
    @pytest.fixture
    def _graph(self, monkeypatch):
        rows: list[dict[str, Any]] = []

        async def _fake(tenant_id: str, accounts: list[str], *, limit: int = 5, session: Any = None) -> list[dict[str, Any]]:
            return list(rows)

        monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)
        monkeypatch.setattr(graph_endpoint, "get_identity_context_for_accounts", _fake)
        yield rows

    def test_a_missing_token_is_refused(self, _graph) -> None:
        client = TestClient(_app())
        assert client.get(_IDENTITY_URL, params={"tenant_id": str(TENANT), "accounts": "a"}).status_code == 401

    def test_a_record_imported_after_the_cutoff_is_refused_and_counted(self, _graph) -> None:
        _graph.extend(
            [
                {"account": "a", "employee": "Before", "imported_at": "2026-04-01T00:00:00+00:00"},
                {"account": "a", "employee": "After", "imported_at": "2026-06-01T00:00:00+00:00"},
            ]
        )
        client = TestClient(_app())
        body = client.get(
            _IDENTITY_URL,
            params={"tenant_id": str(TENANT), "accounts": "a", "as_of": "2026-05-01T12:00:00+00:00"},
            headers=HEADERS,
        ).json()

        assert [i["employee"] for i in body["identities"]] == ["Before"]
        assert body["excluded_after_cutoff"] == 1

    def test_every_served_row_is_counted_untestable_not_just_the_undated_ones(self, _graph) -> None:
        """The freeze here is partial and the count is how a reader learns that.

        An ``Employee`` node's ``updated_at`` is the import stamp. Surviving a
        cutoff on it is not evidence the fact predates the split: the snapshot
        may have been imported before the split and updated in place since.
        Counting only the rows with no stamp at all would claim a tighter
        freeze than the data supports.
        """
        _graph.extend(
            [
                {"account": "a", "employee": "Dated", "imported_at": "2026-04-01T00:00:00+00:00"},
                {"account": "b", "employee": "Undated"},
            ]
        )
        client = TestClient(_app())
        body = client.get(
            _IDENTITY_URL,
            params=[("tenant_id", str(TENANT)), ("accounts", "a"), ("accounts", "b"), ("as_of", "2026-05-01T12:00:00+00:00")],
            headers=HEADERS,
        ).json()

        assert len(body["identities"]) == 2
        assert body["without_timestamp"] == 2

    def test_no_cutoff_asked_for_means_nothing_is_refused(self, _graph) -> None:
        _graph.append({"account": "a", "employee": "Whenever", "imported_at": "2099-01-01T00:00:00+00:00"})
        client = TestClient(_app())
        body = client.get(_IDENTITY_URL, params={"tenant_id": str(TENANT), "accounts": "a"}, headers=HEADERS).json()

        assert body["as_of"] is None
        assert body["excluded_after_cutoff"] == 0
        assert len(body["identities"]) == 1

    def test_an_unparseable_import_stamp_is_kept_and_counted_rather_than_dropped(self, _graph) -> None:
        """The conservative direction for a freeze that already declares itself partial."""
        _graph.append({"account": "a", "employee": "Odd", "imported_at": "not a date"})
        client = TestClient(_app())
        body = client.get(
            _IDENTITY_URL,
            params={"tenant_id": str(TENANT), "accounts": "a", "as_of": "2026-05-01T12:00:00+00:00"},
            headers=HEADERS,
        ).json()

        assert len(body["identities"]) == 1
        assert body["excluded_after_cutoff"] == 0
        assert body["without_timestamp"] == 1

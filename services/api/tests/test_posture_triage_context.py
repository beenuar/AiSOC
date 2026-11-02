"""The posture surface: who may read it, and when zero means something.

Depth-2 item 8.1.

What was wrong
--------------
`GET /posture/summary` counted `posture_findings`, a table whose only writer
in the whole tree was `POST /posture/findings` — a route a human calls by
hand. So every deployment that had never POSTed a finding read a confident
`total: 0, critical: 0`, which says "your cloud estate is clean" about an
estate nobody has looked at. A count reading zero is the direction nobody
investigates.

What is proven where, stated rather than implied
------------------------------------------------
The SQL this route runs is proven against **real Postgres** in
`tests/isolation/test_cloud_security_findings_live.py`: the `text[]` round
trip, the GIN overlap actually matching, the CHECK constraints and the
partial unique index are properties of the database and a fake session can
show none of them.

What a fake session *can* show honestly, and what this file asserts: the
credential, whether the compiled statement carries the tenant predicate and
the cutoff predicate at all, and the summary's collected/not-collected
decision, which is pure Python over two row sets.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from app.api.v1.deps import CurrentUser, get_current_user, get_db
from app.api.v1.endpoints.posture import router as posture_router
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-0000000000c1")
SERVICE_TOKEN = "service-token-for-the-agents-worker"
HEADERS = {"X-AiSOC-Service-Token": SERVICE_TOKEN}


class _Scalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)

    def first(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalar_one(self) -> Any:
        return self._rows[0] if self._rows else 0


class _Session:
    """Answers each statement from a queue, and records the SQL it was given.

    A queue rather than one canned answer: this route runs up to three
    different statements and a session that returns the same rows to all of
    them would make the cutoff count equal the finding count, which is the
    one number the freeze rests on.
    """

    def __init__(self, answers: list[list[Any]]) -> None:
        self._answers = list(answers)
        self.sql: list[str] = []

    async def execute(self, statement: Any) -> _Result:
        self.sql.append(str(statement))
        return _Result(self._answers.pop(0) if self._answers else [])


def _finding(**over: Any) -> Any:
    row = {
        "finding_class": "misconfiguration",
        "severity": "critical",
        "status": "open",
        "rule_title": "S3 bucket is publicly readable",
        "resource_name": "quarterly-reports",
        "resource_type": "bucket",
        "source": "wiz",
        "cloud_provider": "aws",
        "resource_keys": ["arn:aws:s3:::quarterly-reports", "wiz-res-9"],
        "first_detected_at": datetime(2026, 10, 10, tzinfo=UTC),
    }
    row.update(over)
    return type("Row", (), row)()


def _app(session: _Session, *, user: CurrentUser | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(posture_router, prefix="/api/v1")

    async def _db() -> Any:
        yield session

    app.dependency_overrides[get_db] = _db
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    # `AISOC_AGENTS_SERVICE_TOKEN`, which is what `service_token_valid` reads.
    # Setting the wrong name leaves the token unconfigured, and an unset token
    # fails closed -- so the two 401 cases below would have passed for the
    # wrong reason while every authorised case 401'd.
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)


def _user() -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=TENANT,
        email="analyst@example.com",
        role="analyst",
        resolved_permissions=frozenset({"*"}),
    )


class TestZeroStopsMeaningClean:
    def test_a_tenant_that_has_never_collected_gets_nulls_and_a_false_flag(self) -> None:
        """The defect. Eight confident zeros on an estate nobody scanned."""
        session = _Session([[], []])  # no runs, no findings
        client = TestClient(_app(session, user=_user()))

        body = client.get("/api/v1/posture/summary").json()

        assert body["collected"] is False
        assert body["total"] is None, "an absent measurement rendered as a number"
        assert body["critical"] is None
        assert body["last_collected_at"] is None

    def test_a_tenant_whose_estate_is_clean_gets_a_real_zero(self) -> None:
        """The other half, and the reason the flag exists rather than just
        returning nulls whenever the count is zero: a CNAPP that collected
        and found nothing is a genuine, publishable zero."""
        run = type("Run", (), {"started_at": datetime(2026, 11, 1, tzinfo=UTC), "source": "wiz"})()
        session = _Session([[run], []])
        client = TestClient(_app(session, user=_user()))

        body = client.get("/api/v1/posture/summary").json()

        assert body["collected"] is True
        assert body["total"] == 0
        assert body["critical"] == 0
        assert body["sources"] == ["wiz"]
        assert body["last_collected_at"].startswith("2026-11-01")

    def test_hand_posted_findings_count_as_a_measurement_even_with_no_run(self) -> None:
        """The REST route was this table's only writer for its whole life. An
        operator who used it must not be told their own findings do not
        count."""
        session = _Session([[], [_finding()]])
        client = TestClient(_app(session, user=_user()))

        body = client.get("/api/v1/posture/summary").json()

        assert body["collected"] is True
        assert body["total"] == 1
        assert body["critical"] == 1


class TestOnlyAServiceMayAskTheTriageQuestion:
    def test_no_token_is_401(self) -> None:
        client = TestClient(_app(_Session([])))
        response = client.get(
            "/api/v1/posture/resource-findings",
            params={"tenant_id": str(TENANT), "resources": ["web-01"]},
        )
        assert response.status_code == 401

    def test_a_wrong_token_is_401(self) -> None:
        client = TestClient(_app(_Session([])))
        response = client.get(
            "/api/v1/posture/resource-findings",
            params={"tenant_id": str(TENANT), "resources": ["web-01"]},
            headers={"X-AiSOC-Service-Token": "not-the-token"},
        )
        assert response.status_code == 401

    def test_the_route_is_absent_from_the_published_spec(self) -> None:
        """An internal service route does not belong in the customer-facing
        contract."""
        app = _app(_Session([]))
        paths = app.openapi()["paths"]
        assert "/api/v1/posture/resource-findings" not in paths


class TestWhatTheStatementActuallyAsksFor:
    def test_both_statements_name_the_tenant(self) -> None:
        session = _Session([[object()], [_finding()]])
        client = TestClient(_app(session))

        client.get(
            "/api/v1/posture/resource-findings",
            params={"tenant_id": str(TENANT), "resources": ["arn:aws:s3:::quarterly-reports"]},
            headers=HEADERS,
        )

        assert len(session.sql) == 2
        for sql in session.sql:
            assert "tenant_id" in sql, f"a statement ran with no tenant predicate: {sql}"

    def test_only_open_findings_are_offered_to_a_verdict(self) -> None:
        session = _Session([[object()], [_finding()]])
        client = TestClient(_app(session))

        client.get(
            "/api/v1/posture/resource-findings",
            params={"tenant_id": str(TENANT), "resources": ["web-01"]},
            headers=HEADERS,
        )

        assert "status" in session.sql[-1]

    def test_no_cutoff_means_no_cutoff_predicate(self) -> None:
        session = _Session([[object()], [_finding()]])
        client = TestClient(_app(session))

        body = client.get(
            "/api/v1/posture/resource-findings",
            params={"tenant_id": str(TENANT), "resources": ["web-01"]},
            headers=HEADERS,
        ).json()

        assert "first_detected_at >" not in " ".join(session.sql)
        assert body["as_of"] is None
        assert body["excluded_after_cutoff"] == 0

    def test_a_cutoff_adds_the_predicate_and_counts_what_it_refused(self) -> None:
        """The refused count is the only evidence the freeze did anything: a
        cutoff that matched nothing and one that threw away fifty rows both
        return an empty list."""
        # runs probe, then the excluded count, then the rows.
        session = _Session([[object()], [4], [_finding()]])
        client = TestClient(_app(session))

        body = client.get(
            "/api/v1/posture/resource-findings",
            params={
                "tenant_id": str(TENANT),
                "resources": ["web-01"],
                "as_of": "2026-10-15T00:00:00+00:00",
            },
            headers=HEADERS,
        ).json()

        joined = " ".join(session.sql)
        assert "first_detected_at >" in joined, "the cutoff was accepted and never applied"
        assert "first_detected_at <=" in joined
        assert body["excluded_after_cutoff"] == 4
        assert body["as_of"].startswith("2026-10-15")


class TestAbsentIsNotCleanHereToo:
    def test_an_unconnected_tenant_is_reported_as_not_collected(self) -> None:
        session = _Session([[], []])
        client = TestClient(_app(session))

        body = client.get(
            "/api/v1/posture/resource-findings",
            params={"tenant_id": str(TENANT), "resources": ["web-01"]},
            headers=HEADERS,
        ).json()

        assert body["collected"] is False
        assert body["findings"] == []

    def test_the_matched_key_names_which_alias_hit(self) -> None:
        """An operator reading the ledger has to be able to tell which of the
        resource's several names matched, or the citation points at nothing
        they can look up."""
        session = _Session([[object()], [_finding()]])
        client = TestClient(_app(session))

        body = client.get(
            "/api/v1/posture/resource-findings",
            params={"tenant_id": str(TENANT), "resources": ["wiz-res-9"]},
            headers=HEADERS,
        ).json()

        assert body["findings"][0]["matched_key"] == "wiz-res-9"
        assert body["matched_resources"] == 1

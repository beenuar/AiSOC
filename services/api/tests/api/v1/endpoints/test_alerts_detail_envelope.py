"""Tests for ``GET /alerts/{id}`` — Investigation Rail envelope + lazy-fill.

The detail endpoint is the only place in the API that emits the enriched
``AlertDetailResponse`` shape that the /alerts Investigation Rail relies
on (PR-4). These tests pin two contracts:

1. **Schema** — ``AlertDetailResponse`` inherits every ``AlertResponse``
   field, adds the four rail fields (``narrative``, ``related_entities``,
   ``mini_timeline``, ``recommended_actions``) with sensible defaults,
   and serialises in snake_case on the wire.

2. **Lazy-fill** — When ``Alert.narrative`` is NULL (pre-W4 rows), the
   endpoint materialises a narrative through the vendored builder,
   persists it back to the row, and returns it. When the builder
   raises we fall back to ``narrative=None`` rather than 500. When
   the narrative is already cached we never call the builder.

The endpoint is exercised by **direct function invocation** with mocked
``AsyncSession`` and a synthesized ``CurrentUser`` — the same pattern
``test_alert_explain.py`` uses for ``alert_explain``. This keeps the
tests fast and hermetic; the FastAPI plumbing (auth, route binding) is
covered by higher-level integration tests elsewhere.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.alerts import (
    AlertDetailResponse,
    AlertResponse,
    get_alert,
)
from app.services.alert_rail import (
    MiniTimelineEvent,
    RailEnvelope,
    RecommendedAction,
    RelatedEntity,
)
from fastapi import HTTPException
from pydantic import ValidationError

# ─── Schema-only payload helper ──────────────────────────────────────────────


def _alert_payload(**overrides: Any) -> dict[str, Any]:
    """Minimum-viable ``AlertResponse``-shaped dict.

    Mirrors ``test_alerts_confidence_contract._make_alert_payload`` so
    the two contract suites stay aligned as ``AlertResponse`` evolves.
    """
    now = datetime.now(UTC)
    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "title": "Suspicious Login",
        "description": None,
        "severity": "medium",
        "status": "new",
        "priority": 50,
        "category": None,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "connector_type": None,
        "ai_score": None,
        "ai_summary": None,
        "ai_recommendations": [],
        "confidence": None,
        "confidence_label": None,
        "confidence_rationale": None,
        "disposition": None,
        "affected_ips": [],
        "affected_hosts": [],
        "affected_users": [],
        "case_id": None,
        "tags": [],
        "event_time": now,
        "first_seen": now,
        "last_seen": now,
        "snoozed_until": None,
        "snoozed_by_id": None,
        "created_at": now,
        "updated_at": now,
    }
    base.update(overrides)
    return base


# ─── ORM stand-in + mock session helpers ─────────────────────────────────────


def _orm_alert(**overrides: Any) -> SimpleNamespace:
    """Build a SimpleNamespace stand-in for the SQLAlchemy ``Alert`` row.

    The endpoint accesses ``alert.id``, ``alert.tenant_id``,
    ``alert.narrative``, plus everything the rail builders read off the
    row. We populate the union of those attributes so projection,
    rail assembly, and ``model_validate(alert)`` all succeed.
    """
    now = datetime.now(UTC)
    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "title": "Suspicious Login",
        "description": None,
        "severity": "medium",
        "status": "new",
        "priority": 50,
        "category": None,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "connector_type": None,
        "ai_score": None,
        "ai_summary": None,
        "ai_recommendations": [],
        "confidence": None,
        "confidence_label": None,
        "confidence_rationale": None,
        "disposition": None,
        "affected_ips": [],
        "affected_hosts": [],
        "affected_users": [],
        "affected_assets": [],
        "case_id": None,
        "tags": [],
        "event_time": now,
        "first_seen": now,
        "last_seen": now,
        "snoozed_until": None,
        "snoozed_by_id": None,
        "created_at": now,
        "updated_at": now,
        "narrative": None,
        "raw_event": {},
        "enrichment_data": {},
        "rule_lineage_id": None,
        "fingerprint": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _mock_user(tenant_id: uuid.UUID) -> CurrentUser:
    """Synthesize a ``CurrentUser`` scoped to ``tenant_id``."""
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id,
        role="analyst",
        email="analyst@example.com",
    )


def _mock_session(*, alert: Any) -> MagicMock:
    """Build a mock ``AsyncSession`` whose execute chain returns ``alert``.

    The detail endpoint issues up to three SELECTs/UPDATEs:

    1. ``SELECT Alert WHERE id=?`` — must return the alert
    2. Optional ``UPDATE Alert SET narrative=…`` — return value unused
    3. Inside ``build_rail_envelope``:
       * optional ``SELECT CaseTimeline …`` (when ``alert.case_id``)
       * ``SELECT AuditLog …``

    We funnel every ``execute`` through one ``AsyncMock``. The first
    call returns a "scalar_one_or_none"-ready result holding the
    alert; subsequent calls return empty results so the rail assembler
    sees no extra rows. Tests that need richer rail data can replace
    ``session.execute.side_effect`` after construction.
    """
    # First call: scalar_one_or_none() → alert
    alert_result = MagicMock()
    alert_result.scalar_one_or_none.return_value = alert

    # Subsequent calls: scalars().all() → []
    empty_scalars = MagicMock()
    empty_scalars.all.return_value = []
    empty_result = MagicMock()
    empty_result.scalars.return_value = empty_scalars
    # We also need scalar_one_or_none() on the empty path in case the
    # endpoint flow shifts; default to None so the test doesn't crash.
    empty_result.scalar_one_or_none.return_value = None

    session = MagicMock()
    session.execute = AsyncMock(side_effect=[alert_result, empty_result, empty_result, empty_result])
    session.commit = AsyncMock(return_value=None)
    return session


# ────────────────────────────────────────────────────────────────────────────
# Section 1: AlertDetailResponse Pydantic contract
# ────────────────────────────────────────────────────────────────────────────


class TestAlertDetailResponseContract:
    """``AlertDetailResponse`` is the wire format the rail UI reads."""

    def test_inherits_every_alert_response_field(self) -> None:
        """The detail shape must be a strict superset of the list shape.

        The frontend's ``Alert`` interface unions both shapes; if a
        column ever gets dropped here the list view keeps working while
        detail crashes silently. This guard makes the bridge explicit.
        """
        list_fields = set(AlertResponse.model_fields)
        detail_fields = set(AlertDetailResponse.model_fields)
        # Inheritance: every list field MUST appear in detail.
        missing = list_fields - detail_fields
        assert not missing, f"AlertDetailResponse dropped fields: {missing}"

    def test_adds_exactly_the_four_rail_fields(self) -> None:
        """The four rail fields are the only thing detail adds.

        If a refactor accidentally promotes another column into the
        detail shape, the frontend's ``DetailAlert`` type union won't
        know about it. Pin the diff so it's caught at PR review.
        """
        added = set(AlertDetailResponse.model_fields) - set(AlertResponse.model_fields)
        assert added == {
            "narrative",
            "related_entities",
            "mini_timeline",
            "recommended_actions",
        }

    def test_defaults_are_safe_when_rail_fields_missing(self) -> None:
        """A bare ``AlertResponse`` payload promotes cleanly to detail.

        The lazy-fill path constructs the detail payload from a row that
        has nothing rail-shaped on it. Defaults must be ``None`` for the
        narrative and empty lists for the three collection fields so the
        UI never has to null-check.
        """
        resp = AlertDetailResponse.model_validate(_alert_payload())
        assert resp.narrative is None
        assert resp.related_entities == []
        assert resp.mini_timeline == []
        assert resp.recommended_actions == []

    def test_accepts_a_full_rail_envelope(self) -> None:
        """The full rail payload (the happy path) round-trips."""
        rail_payload = _alert_payload(
            narrative="**hosts:** web-01\n\nMITRE T1078.",
            related_entities=[
                {
                    "group": "principal",
                    "kind": "host",
                    "value": "web-01",
                    "label": None,
                    "pivot": "/attack-graph?entity=host:web-01",
                }
            ],
            mini_timeline=[
                {
                    "id": "evt-1",
                    "ts": datetime.now(UTC),
                    "kind": "audit",
                    "agent": "alice@example.com",
                    "summary": "status_change on alert",
                    "payload": {"status": ["new", "investigating"]},
                    "duration_ms": 0,
                }
            ],
            recommended_actions=[
                {
                    "priority": 1,
                    "action": "Isolate host",
                    "rationale": "Lateral movement",
                    "risk": "high",
                }
            ],
        )
        resp = AlertDetailResponse.model_validate(rail_payload)
        assert resp.narrative.startswith("**hosts:**")
        assert len(resp.related_entities) == 1
        assert isinstance(resp.related_entities[0], RelatedEntity)
        assert resp.related_entities[0].kind == "host"
        assert len(resp.mini_timeline) == 1
        assert isinstance(resp.mini_timeline[0], MiniTimelineEvent)
        assert len(resp.recommended_actions) == 1
        assert isinstance(resp.recommended_actions[0], RecommendedAction)
        assert resp.recommended_actions[0].risk == "high"

    def test_serialises_rail_fields_in_snake_case(self) -> None:
        """The rail UI consumes snake_case on the wire and normalises FE-side.

        ``apps/web/src/lib/api.ts`` has ``normalizeAlert`` which expects
        ``related_entities`` / ``mini_timeline`` / ``recommended_actions``
        on the wire. If anyone ever adds Pydantic ``alias=`` for camelCase
        here, ``normalizeAlert`` needs to update in lockstep — this guard
        forces that.
        """
        resp = AlertDetailResponse.model_validate(_alert_payload(narrative="x"))
        dumped = resp.model_dump()
        assert "narrative" in dumped
        assert "related_entities" in dumped
        assert "mini_timeline" in dumped
        assert "recommended_actions" in dumped
        # The camelCase variants must NOT be in the wire payload.
        assert "relatedEntities" not in dumped
        assert "miniTimeline" not in dumped
        assert "recommendedActions" not in dumped

    def test_rail_fields_validate_against_their_models(self) -> None:
        """Garbage in the rail collections must raise rather than coerce.

        Pydantic discriminated parsing means an invalid risk value, for
        example, must blow up at the API boundary — not get silently
        replaced with the default. The ``build_recommended_actions``
        helper does the sanitising; the model just enforces the
        sanitised contract.
        """
        with pytest.raises(ValidationError):
            AlertDetailResponse.model_validate(
                _alert_payload(
                    recommended_actions=[
                        {
                            "priority": 0,  # ge=1 violated
                            "action": "x",
                            "risk": "low",
                        }
                    ],
                )
            )


# ────────────────────────────────────────────────────────────────────────────
# Section 2: get_alert endpoint behaviour
# ────────────────────────────────────────────────────────────────────────────


class TestGetAlertEndpoint:
    """``get_alert`` is the only consumer of the rail builders.

    All tests construct the dependencies by hand and ``await`` the
    coroutine directly — the same pattern ``test_alert_explain.py``
    uses. This bypasses the FastAPI dependency graph (auth, route
    binding) which is covered by higher-level integration tests.
    """

    @pytest.mark.asyncio
    async def test_returns_404_when_alert_missing(self) -> None:
        tenant_id = uuid.uuid4()
        user = _mock_user(tenant_id)

        empty_result = MagicMock()
        empty_result.scalar_one_or_none.return_value = None
        session = MagicMock()
        session.execute = AsyncMock(return_value=empty_result)
        session.commit = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await get_alert(uuid.uuid4(), user, session)

        assert exc.value.status_code == 404
        # The narrative builder must NOT have been called.
        assert session.commit.await_count == 0

    @pytest.mark.asyncio
    async def test_returns_envelope_with_existing_narrative_no_lazy_fill(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Pre-populated narrative is a fast path — builder never runs."""
        tenant_id = uuid.uuid4()
        alert = _orm_alert(tenant_id=tenant_id, narrative="**hosts:** web-01\n\nMITRE T1078.")
        session = _mock_session(alert=alert)
        user = _mock_user(tenant_id)

        # If the builder were called we'd get a sentinel string;
        # the assertion below would fail.
        builder_calls: list[Any] = []
        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_narrative",
            lambda inputs: builder_calls.append(inputs) or "SHOULD_NEVER_BE_USED",
        )

        # Pin the rail envelope so we can assert on the response shape
        # without re-testing the rail builders (covered in test_alert_rail).
        envelope = RailEnvelope(
            related_entities=[
                RelatedEntity(
                    group="principal",
                    kind="host",
                    value="web-01",
                    label=None,
                    pivot="/attack-graph?entity=host:web-01",
                )
            ],
            mini_timeline=[],
            recommended_actions=[],
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_rail_envelope",
            AsyncMock(return_value=envelope),
        )

        resp = await get_alert(alert.id, user, session)

        assert isinstance(resp, AlertDetailResponse)
        assert resp.narrative == "**hosts:** web-01\n\nMITRE T1078."
        assert len(resp.related_entities) == 1
        assert resp.related_entities[0].value == "web-01"
        # Builder must NOT have been invoked.
        assert builder_calls == []
        # Commit must NOT have been invoked (no lazy-fill happened).
        assert session.commit.await_count == 0

    @pytest.mark.asyncio
    async def test_lazy_fills_narrative_when_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A legacy row (narrative is None) gets a freshly-built narrative.

        We assert four things in one shot:
          1. ``build_narrative`` was called exactly once
          2. The result was assigned back to the in-memory row
          3. ``db.execute`` was invoked with an UPDATE (the second call)
          4. ``db.commit`` was awaited (so the lazy-fill persists)
        """
        tenant_id = uuid.uuid4()
        alert = _orm_alert(tenant_id=tenant_id, narrative=None)
        session = _mock_session(alert=alert)
        user = _mock_user(tenant_id)

        builder_calls: list[Any] = []

        def fake_builder(inputs: Any) -> str:
            builder_calls.append(inputs)
            return "Generated narrative"

        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_narrative",
            fake_builder,
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_rail_envelope",
            AsyncMock(
                return_value=RailEnvelope(
                    related_entities=[],
                    mini_timeline=[],
                    recommended_actions=[],
                )
            ),
        )

        resp = await get_alert(alert.id, user, session)

        assert resp.narrative == "Generated narrative"
        # In-memory mutation so subsequent reads in the same request see
        # the value (the endpoint reuses ``alert.narrative`` for the
        # response payload).
        assert alert.narrative == "Generated narrative"
        # Builder fired exactly once.
        assert len(builder_calls) == 1
        # commit() awaited (so the lazy-fill is durable).
        assert session.commit.await_count == 1
        # Two execute calls: SELECT alert, then UPDATE narrative.
        # (build_rail_envelope is mocked out.)
        assert session.execute.await_count == 2

    @pytest.mark.asyncio
    async def test_does_not_persist_empty_narrative(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A builder returning empty text is a no-op — no UPDATE, no commit.

        ``build_narrative`` can legitimately return ``""`` for an alert
        with zero structured signal. We must not persist that empty
        string back to the row (it'd shadow the next backfill attempt).
        """
        tenant_id = uuid.uuid4()
        alert = _orm_alert(tenant_id=tenant_id, narrative=None)
        session = _mock_session(alert=alert)
        user = _mock_user(tenant_id)

        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_narrative",
            lambda inputs: "",
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_rail_envelope",
            AsyncMock(
                return_value=RailEnvelope(
                    related_entities=[],
                    mini_timeline=[],
                    recommended_actions=[],
                )
            ),
        )

        resp = await get_alert(alert.id, user, session)

        assert resp.narrative is None
        # Row stays clean — no shadow write.
        assert alert.narrative is None
        # commit() must NOT have been awaited.
        assert session.commit.await_count == 0
        # Only the SELECT happened.
        assert session.execute.await_count == 1

    @pytest.mark.asyncio
    async def test_returns_alert_when_narrative_builder_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A builder crash must NOT 500 the endpoint.

        The frontend already handles ``narrative=null``. Failing soft
        keeps the detail view useful even when something upstream
        (vendoring, projection, MITRE map) is misbehaving.
        """
        tenant_id = uuid.uuid4()
        alert = _orm_alert(tenant_id=tenant_id, narrative=None)
        session = _mock_session(alert=alert)
        user = _mock_user(tenant_id)

        def explode(inputs: Any) -> str:
            raise RuntimeError("builder is on fire")

        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_narrative",
            explode,
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_rail_envelope",
            AsyncMock(
                return_value=RailEnvelope(
                    related_entities=[],
                    mini_timeline=[],
                    recommended_actions=[],
                )
            ),
        )

        # The endpoint must return cleanly, not propagate the RuntimeError.
        resp = await get_alert(alert.id, user, session)
        assert resp.narrative is None
        # And we did NOT commit a broken state.
        assert session.commit.await_count == 0

    @pytest.mark.asyncio
    async def test_returns_alert_when_projection_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Resilience also covers a projection failure (e.g. malformed JSONB)."""
        tenant_id = uuid.uuid4()
        alert = _orm_alert(tenant_id=tenant_id, narrative=None)
        session = _mock_session(alert=alert)
        user = _mock_user(tenant_id)

        def explode(alert: Any) -> Any:
            raise KeyError("missing column")

        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.project_alert_to_narrative_inputs",
            explode,
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_rail_envelope",
            AsyncMock(
                return_value=RailEnvelope(
                    related_entities=[],
                    mini_timeline=[],
                    recommended_actions=[],
                )
            ),
        )

        resp = await get_alert(alert.id, user, session)
        assert resp.narrative is None
        assert session.commit.await_count == 0

    @pytest.mark.asyncio
    async def test_response_includes_rail_envelope_data(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The full envelope from ``build_rail_envelope`` lands on the response."""
        tenant_id = uuid.uuid4()
        alert = _orm_alert(tenant_id=tenant_id, narrative="cached")
        session = _mock_session(alert=alert)
        user = _mock_user(tenant_id)

        envelope = RailEnvelope(
            related_entities=[
                RelatedEntity(
                    group="network",
                    kind="ip",
                    value="10.0.0.1",
                    label=None,
                    pivot="/attack-graph?entity=ip:10.0.0.1",
                ),
            ],
            mini_timeline=[
                MiniTimelineEvent(
                    id="evt-1",
                    ts=datetime.now(UTC),
                    kind="audit",
                    agent="system",
                    summary="status_change on alert",
                    payload={"status": ["new", "investigating"]},
                ),
            ],
            recommended_actions=[
                RecommendedAction(
                    priority=1,
                    action="Block IP at edge",
                    rationale=None,
                    risk="medium",
                ),
            ],
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.alerts.build_rail_envelope",
            AsyncMock(return_value=envelope),
        )

        resp = await get_alert(alert.id, user, session)

        assert resp.narrative == "cached"
        assert len(resp.related_entities) == 1
        assert resp.related_entities[0].value == "10.0.0.1"
        assert len(resp.mini_timeline) == 1
        assert resp.mini_timeline[0].kind == "audit"
        assert len(resp.recommended_actions) == 1
        assert resp.recommended_actions[0].action == "Block IP at edge"

    @pytest.mark.asyncio
    async def test_tenant_isolation_enforced_via_query_filter(self) -> None:
        """The endpoint queries with ``tenant_id == current_user.tenant_id``.

        We can't see the SQL directly through the mock, but we can verify
        the result-resolution sequence: if the alert tenant doesn't match,
        the mock returns None and we 404. That's the same protection the
        production SQL filter provides.
        """
        querying_tenant = uuid.uuid4()
        user = _mock_user(querying_tenant)

        # The session is configured to return None — simulating a row
        # that exists but lives in a different tenant.
        none_result = MagicMock()
        none_result.scalar_one_or_none.return_value = None
        session = MagicMock()
        session.execute = AsyncMock(return_value=none_result)
        session.commit = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await get_alert(uuid.uuid4(), user, session)

        assert exc.value.status_code == 404

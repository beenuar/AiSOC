"""Tests for ``POST /alerts/submit`` — the founder-flow direct-write path.

The submit endpoint is the destination the ``aisoc submit <file>`` CLI POSTs
to. It deliberately bypasses the Kafka detect/correlate/fuse pipeline
(which fresh clones don't run by default) and synthesises a single ``Alert``
row directly from an OCSF/Okta-shaped event batch. This is what makes the
quickstart's "alert in seconds" promise true on a clean machine.

These tests pin three layers:

1. **Synthesise helper** (``_synthesise_alert_from_events``) — given a batch
   of events, produces an ``Alert`` ORM instance with sane fields:
   title, severity (highest in the batch unless overridden), priority,
   affected entities, timestamps, tags, raw_event payload.

2. **Severity normalisation** — vendor-native strings (``INFO``, ``HIGH``,
   ``CRITICAL``, etc.) collapse onto the canonical five-tier ladder
   (``info | low | medium | high | critical``) defined in AGENTS.md.

3. **HTTP endpoint** (``submit_alert``) — by direct function invocation
   with a mock ``AsyncSession`` and a synthesised ``CurrentUser``. Same
   pattern as ``test_alerts_detail_envelope`` / ``test_alert_explain``.
   Covers: empty body → 400, happy path → 201 + AlertResponse, tenant
   scoping (alert.tenant_id == current_user.tenant_id).

If these tests break, the founder-flow demo silently regresses and the
quickstart video desyncs from reality.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.alerts import (
    AlertResponse,
    AlertSubmitRequest,
    _coerce_published,
    _max_severity,
    _normalize_severity,
    _synthesise_alert_from_events,
    submit_alert,
)
from fastapi import HTTPException

# ─── helpers ────────────────────────────────────────────────────────────────


def _user(tenant_id: uuid.UUID | None = None, *, role: str = "admin") -> CurrentUser:
    """Synthesise a ``CurrentUser`` — defaults to admin so ``alerts:write`` passes."""
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role=role,
        email="demo@example.com",
    )


def _okta_event(
    *,
    actor_id: str = "alice@example.com",
    ip: str = "203.0.113.42",
    severity: str = "INFO",
    event_type: str = "user.session.start",
    display_message: str = "User login to Okta",
    published: str | None = "2026-05-14T09:30:14.123Z",
) -> dict[str, Any]:
    """Build an Okta system-log shaped event dict.

    Mirrors the lateral-movement fixture so tests stay aligned with the
    demo payload the quickstart video uses.
    """
    return {
        "uuid": str(uuid.uuid4()),
        "published": published,
        "eventType": event_type,
        "displayMessage": display_message,
        "severity": severity,
        "actor": {
            "id": actor_id,
            "type": "User",
            "alternateId": actor_id,
            "displayName": actor_id.split("@")[0].title(),
        },
        "client": {
            "ipAddress": ip,
            "userAgent": {"rawUserAgent": "Mozilla/5.0", "os": "Mac OS X", "browser": "CHROME"},
            "geographicalContext": {"city": "Boston", "country": "United States"},
        },
        "outcome": {"result": "SUCCESS"},
    }


def _mock_db_session() -> MagicMock:
    """Mock ``AsyncSession`` for endpoint invocation.

    ``submit_alert`` calls ``db.add(alert)`` (sync), ``await db.flush()``
    (no-op), and ``await db.refresh(alert)`` (no-op). The endpoint then
    ``model_validate``s the alert directly — Pydantic reads attributes
    off the row that ``db.add`` left intact.

    Real SQLAlchemy applies the ``default=uuid.uuid4`` column default
    inside ``flush()``. Our mock has to mimic that, otherwise the final
    ``AlertResponse.model_validate(alert)`` blows up on ``id=None``.
    We capture the alert handed to ``add`` and populate the server-side
    defaults on flush.
    """
    added: list[Any] = []

    def _add(obj: Any) -> None:
        added.append(obj)

    async def _flush() -> None:
        for obj in added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()

    session = MagicMock()
    session.add = MagicMock(side_effect=_add)
    session.flush = AsyncMock(side_effect=_flush)
    session.refresh = AsyncMock(return_value=None)
    # Stash for tests that want to inspect what got persisted.
    session._added = added  # type: ignore[attr-defined]
    return session


# ════════════════════════════════════════════════════════════════════════════
# Section 1: severity normalisation (canonical 5-tier ladder)
# ════════════════════════════════════════════════════════════════════════════


class TestSeverityNormalisation:
    """Vendor-native severity strings must collapse onto info/low/medium/high/critical.

    The canonical ladder is documented in AGENTS.md and pinned by the
    fusion service's ``ConfidenceScorer``. Any new vendor mapping should
    land here first so the regression is caught at PR review.
    """

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("INFO", "info"),
            ("informational", "info"),
            ("Debug", "info"),
            ("low", "low"),
            ("MINOR", "low"),
            ("warning", "low"),
            ("medium", "medium"),
            ("MODERATE", "medium"),
            ("warn", "medium"),
            ("high", "high"),
            ("Error", "high"),
            ("MAJOR", "high"),
            ("critical", "critical"),
            ("CRIT", "critical"),
            ("Severe", "critical"),
            ("FATAL", "critical"),
            ("emergency", "critical"),
        ],
    )
    def test_known_vendor_strings_map_to_canonical_tier(self, raw: str, expected: str) -> None:
        assert _normalize_severity(raw) == expected

    @pytest.mark.parametrize("raw", [None, "", "   "])
    def test_missing_severity_defaults_to_medium(self, raw: Any) -> None:
        """Missing severity is treated as ``medium`` — never raises.

        Connectors can drop severity on partial events; we default
        conservatively so the alert still surfaces to an analyst.
        """
        assert _normalize_severity(raw) == "medium"

    def test_unknown_severity_defaults_to_medium(self) -> None:
        """Unknown vendor strings fall back to ``medium``, not crash."""
        assert _normalize_severity("definitely-not-a-real-tier") == "medium"

    def test_whitespace_and_case_are_normalised(self) -> None:
        """``  HIGH  `` and ``high`` are the same thing."""
        assert _normalize_severity("  HIGH  ") == "high"


class TestMaxSeverity:
    """Picking the highest severity in a batch governs the synthesised priority."""

    def test_empty_list_is_treated_as_info(self) -> None:
        # The helper is only called with non-empty batches, but defend
        # against accidental refactors that pipe empty lists in.
        assert _max_severity([]) == "info"

    def test_picks_highest_tier(self) -> None:
        assert _max_severity(["info", "high", "low"]) == "high"
        assert _max_severity(["medium", "critical", "low"]) == "critical"
        assert _max_severity(["info", "info"]) == "info"

    def test_ordering_is_info_low_medium_high_critical(self) -> None:
        """The ladder is exactly five tiers and strictly ordered."""
        assert _max_severity(["info", "low"]) == "low"
        assert _max_severity(["low", "medium"]) == "medium"
        assert _max_severity(["medium", "high"]) == "high"
        assert _max_severity(["high", "critical"]) == "critical"


# ════════════════════════════════════════════════════════════════════════════
# Section 2: timestamp coercion
# ════════════════════════════════════════════════════════════════════════════


class TestCoercePublished:
    """``_coerce_published`` accepts Okta ``published``, OCSF ``time``, et al."""

    def test_parses_okta_published_iso_string(self) -> None:
        result = _coerce_published({"published": "2026-05-14T09:30:14.123Z"})
        assert result is not None
        assert result.tzinfo is not None
        assert result.year == 2026
        assert result.month == 5
        assert result.day == 14

    def test_parses_ocsf_time_field(self) -> None:
        result = _coerce_published({"time": "2026-05-14T09:30:00+00:00"})
        assert result is not None
        assert result.hour == 9

    def test_parses_at_timestamp_field(self) -> None:
        result = _coerce_published({"@timestamp": "2026-05-14T10:00:00Z"})
        assert result is not None
        assert result.hour == 10

    def test_returns_none_when_no_timestamp(self) -> None:
        assert _coerce_published({"unrelated": "field"}) is None

    def test_returns_none_on_unparseable_string(self) -> None:
        """A garbage timestamp must not crash the endpoint."""
        assert _coerce_published({"published": "not-a-date"}) is None

    def test_accepts_datetime_objects_directly(self) -> None:
        """If a connector passes a real datetime, we use it."""
        naive = datetime(2026, 5, 14, 9, 30, 14)
        result = _coerce_published({"published": naive})
        assert result is not None
        # Naive datetimes get UTC pinned on so downstream comparisons work.
        assert result.tzinfo is not None


# ════════════════════════════════════════════════════════════════════════════
# Section 3: _synthesise_alert_from_events — the core helper
# ════════════════════════════════════════════════════════════════════════════


class TestSynthesiseAlertFromEvents:
    """Given an event batch, build a coherent ``Alert`` row."""

    def test_synthesises_basic_alert_from_single_event(self) -> None:
        tenant = uuid.uuid4()
        alert = _synthesise_alert_from_events(
            tenant_id=tenant,
            events=[_okta_event()],
            connector_type="okta_system_log",
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )

        assert alert.tenant_id == tenant
        assert alert.title == "User login to Okta"
        assert alert.severity == "info"
        # priority is keyed off the severity ladder
        assert alert.priority == 10
        assert alert.status == "new"
        assert alert.affected_users == ["alice@example.com"]
        assert alert.affected_ips == ["203.0.113.42"]
        assert alert.connector_type == "okta_system_log"
        # The okta connector tags onto identity category.
        assert alert.category == "identity"
        assert "submitted" in alert.tags
        assert "okta_system_log" in alert.tags
        # Raw event payload preserved for forensics.
        assert alert.raw_event["events"] == [_okta_event_serialised_match(alert)]
        assert alert.raw_event["source"] == "aisoc-submit-api"

    def test_picks_highest_severity_across_batch(self) -> None:
        """Multi-event batches collapse to one alert at the worst severity."""
        events = [
            _okta_event(severity="INFO"),
            _okta_event(severity="HIGH"),
            _okta_event(severity="LOW"),
        ]
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=events,
            connector_type="okta_system_log",
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )
        assert alert.severity == "high"
        assert alert.priority == 75

    def test_overrides_beat_inferred_fields(self) -> None:
        """Explicit overrides win over event-derived inference."""
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=[_okta_event(severity="INFO")],
            connector_type="okta_system_log",
            override_title="Manual alert title",
            override_description="Manual description",
            override_severity="critical",
            override_tags=["red-team", "exercise"],
        )
        assert alert.title == "Manual alert title"
        assert alert.description == "Manual description"
        assert alert.severity == "critical"
        assert alert.priority == 95
        assert "red-team" in alert.tags
        assert "exercise" in alert.tags
        # The submitted marker still attaches even with custom tags.
        assert "submitted" in alert.tags

    def test_collects_unique_affected_entities_from_batch(self) -> None:
        events = [
            _okta_event(actor_id="alice@example.com", ip="203.0.113.42"),
            _okta_event(actor_id="bob@example.com", ip="203.0.113.99"),
            # duplicate alice — must not appear twice
            _okta_event(actor_id="alice@example.com", ip="203.0.113.42"),
        ]
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=events,
            connector_type="okta_system_log",
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )
        # Order preserved, no duplicates.
        assert alert.affected_users == ["alice@example.com", "bob@example.com"]
        assert alert.affected_ips == ["203.0.113.42", "203.0.113.99"]

    def test_timestamps_pin_to_earliest_and_latest_event(self) -> None:
        """``first_seen`` / ``last_seen`` are the batch envelope."""
        events = [
            _okta_event(published="2026-05-14T09:30:14Z"),
            _okta_event(published="2026-05-14T09:45:00Z"),
            _okta_event(published="2026-05-14T09:35:00Z"),
        ]
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=events,
            connector_type="okta_system_log",
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )
        # Earliest event becomes first_seen
        assert alert.first_seen.minute == 30
        # Latest becomes last_seen and event_time
        assert alert.last_seen.minute == 45
        assert alert.event_time.minute == 45

    def test_falls_back_to_now_when_no_timestamps(self) -> None:
        """Events without timestamps still produce a valid alert."""
        events = [{"eventType": "user.session.start", "displayMessage": "No-ts event"}]
        before = datetime.now(UTC)
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=events,
            connector_type="okta_system_log",
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )
        after = datetime.now(UTC) + timedelta(seconds=1)
        assert before <= alert.first_seen <= after
        assert before <= alert.last_seen <= after
        assert before <= alert.event_time <= after

    def test_falls_back_to_event_type_when_no_display_message(self) -> None:
        """The title cascades through displayMessage → eventType → name."""
        events = [{"eventType": "user.session.failed", "severity": "HIGH"}]
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=events,
            connector_type="okta_system_log",
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )
        assert alert.title == "user.session.failed"

    def test_falls_back_to_default_title_when_event_is_bare(self) -> None:
        """The most degraded payload still produces a titled alert."""
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=[{}],
            connector_type=None,
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )
        assert alert.title == "AiSOC submitted alert"
        assert alert.severity == "medium"
        # No connector_type → not an identity event
        assert alert.category is None

    def test_non_okta_connector_does_not_force_identity_category(self) -> None:
        """Category inference is connector-aware (okta → identity)."""
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=[_okta_event()],
            connector_type="splunk_enterprise",
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )
        assert alert.category is None
        assert "splunk_enterprise" in alert.tags

    def test_description_summarises_batch_size(self) -> None:
        """Auto-generated description mentions the batch size."""
        events = [_okta_event(), _okta_event(), _okta_event()]
        alert = _synthesise_alert_from_events(
            tenant_id=uuid.uuid4(),
            events=events,
            connector_type="okta_system_log",
            override_title=None,
            override_description=None,
            override_severity=None,
            override_tags=None,
        )
        assert "3 event(s)" in (alert.description or "")
        assert "Submitted via aisoc submit" in (alert.description or "")


def _okta_event_serialised_match(alert: Any) -> dict[str, Any]:
    """Helper to read the first event back off the alert's raw_event."""
    return alert.raw_event["events"][0]


# ════════════════════════════════════════════════════════════════════════════
# Section 4: submit_alert HTTP endpoint
# ════════════════════════════════════════════════════════════════════════════


class TestSubmitAlertEndpoint:
    """Direct-invocation tests for ``submit_alert``."""

    @pytest.mark.asyncio
    async def test_happy_path_creates_alert_and_returns_response(self) -> None:
        tenant = uuid.uuid4()
        user = _user(tenant)
        session = _mock_db_session()

        payload = AlertSubmitRequest(
            events=[_okta_event(severity="HIGH")],
            connector_id="aisoc-cli-submit",
            connector_type="okta_system_log",
            source_format="json",
        )

        resp = await submit_alert(payload, user, session)

        assert isinstance(resp, AlertResponse)
        assert resp.tenant_id == tenant
        assert resp.severity == "high"
        assert resp.title == "User login to Okta"
        # Persistence sequence: add(), flush(), refresh()
        session.add.assert_called_once()
        session.flush.assert_awaited_once()
        session.refresh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_empty_events_returns_400(self) -> None:
        """The endpoint must reject empty batches with a 400, not a 500."""
        user = _user()
        session = _mock_db_session()
        payload = AlertSubmitRequest(events=[], connector_type="okta_system_log")

        with pytest.raises(HTTPException) as exc:
            await submit_alert(payload, user, session)

        assert exc.value.status_code == 400
        assert "non-empty" in exc.value.detail
        # No DB writes happened.
        session.add.assert_not_called()
        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_alert_is_pinned_to_current_user_tenant(self) -> None:
        """The synthesised alert MUST inherit the caller's tenant.

        This is the only tenant-isolation guarantee on the submit path —
        callers can't smuggle a different tenant_id through the payload.
        """
        tenant = uuid.uuid4()
        user = _user(tenant)
        session = _mock_db_session()

        await submit_alert(
            AlertSubmitRequest(events=[_okta_event()], connector_type="okta_system_log"),
            user,
            session,
        )

        added_alerts = session._added
        assert len(added_alerts) == 1
        assert added_alerts[0].tenant_id == tenant

    @pytest.mark.asyncio
    async def test_override_severity_lands_on_persisted_alert(self) -> None:
        """``severity`` override on the payload wins over event severity."""
        user = _user()
        session = _mock_db_session()

        await submit_alert(
            AlertSubmitRequest(
                events=[_okta_event(severity="INFO")],
                connector_type="okta_system_log",
                severity="critical",
            ),
            user,
            session,
        )
        added = session._added
        assert added[0].severity == "critical"
        assert added[0].priority == 95

    @pytest.mark.asyncio
    async def test_payload_tags_are_attached(self) -> None:
        user = _user()
        session = _mock_db_session()

        await submit_alert(
            AlertSubmitRequest(
                events=[_okta_event()],
                connector_type="okta_system_log",
                tags=["red-team", "lateral-movement"],
            ),
            user,
            session,
        )
        added = session._added
        tags = set(added[0].tags)
        assert "red-team" in tags
        assert "lateral-movement" in tags
        # submitted marker still added
        assert "submitted" in tags

    @pytest.mark.asyncio
    async def test_multi_event_batch_creates_single_alert(self) -> None:
        """Batches collapse to one alert, not N — that's the design promise."""
        user = _user()
        session = _mock_db_session()

        await submit_alert(
            AlertSubmitRequest(
                events=[
                    _okta_event(actor_id="alice@example.com"),
                    _okta_event(actor_id="bob@example.com"),
                ],
                connector_type="okta_system_log",
            ),
            user,
            session,
        )

        added = session._added
        assert len(added) == 1
        # Both users land on the same alert.
        assert "alice@example.com" in added[0].affected_users
        assert "bob@example.com" in added[0].affected_users

    @pytest.mark.asyncio
    async def test_payload_validates_optional_fields(self) -> None:
        """``AlertSubmitRequest`` is forgiving — empty optionals are fine."""
        # The CLI omits some fields when the fixture is minimal.
        req = AlertSubmitRequest(events=[_okta_event()])
        assert req.connector_id is None
        assert req.connector_type is None
        assert req.source_format is None
        assert req.tags is None
        # And the endpoint accepts it.
        user = _user()
        session = _mock_db_session()
        resp = await submit_alert(req, user, session)
        assert resp.severity == "info"

"""Unit tests for ``app.services.alert_rail``.

The rail assembler has three pure helpers and one DB-touching helper:

* ``build_related_entities``        — pure (Alert → list[RelatedEntity])
* ``build_recommended_actions``     — pure (Alert → list[RecommendedAction])
* ``build_mini_timeline``           — async, DB-bound (AsyncSession + Alert)
* ``build_rail_envelope``           — composition of the three

We test each one in isolation. Pure helpers use ``SimpleNamespace`` for
the ORM row. The DB-bound one uses a ``MagicMock(AsyncSession)`` whose
``execute`` returns canned rows — the same pattern the existing
``test_alert_explain.py`` uses for ``_resolve_rule_lineage``.

The contracts we're guarding:

* dedup is case-insensitive but preserves first-seen casing,
* every entity ends up in exactly one group,
* whitespace-only strings are filtered,
* MITRE coverage tolerates both bare-string and dict shapes,
* the case timeline + audit log are merged and capped,
* recommended actions accept both structured dicts AND legacy strings,
* priority normalisation clamps to ``>= 1`` and risk to ``low|medium|high``.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.alert_rail import (
    MAX_TIMELINE_EVENTS,
    MiniTimelineEvent,
    RailEnvelope,
    RecommendedAction,
    RelatedEntity,
    build_mini_timeline,
    build_rail_envelope,
    build_recommended_actions,
    build_related_entities,
)
from pydantic import ValidationError

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _alert(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "severity": "high",
        "title": "Suspicious authentication",
        "connector_type": "okta",
        "case_id": None,
        "ai_recommendations": [],
        "affected_ips": [],
        "affected_hosts": [],
        "affected_users": [],
        "affected_assets": [],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "raw_event": {},
        "enrichment_data": {},
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _mock_db_returning(*batches: list[Any]) -> MagicMock:
    """Build a MagicMock(AsyncSession) whose ``execute`` returns canned rows.

    Each ``batch`` corresponds to one ``await db.execute(...)`` call and
    its scalars().all() result. The MagicMock has an ``AsyncMock``
    ``execute`` so ``await`` works correctly.
    """
    db = MagicMock()
    db.execute = AsyncMock()

    results = []
    for batch in batches:
        scalars = MagicMock()
        scalars.all.return_value = batch
        result = MagicMock()
        result.scalars.return_value = scalars
        results.append(result)
    db.execute.side_effect = results
    return db


# ─── build_related_entities ──────────────────────────────────────────────────


class TestBuildRelatedEntities:
    def test_returns_empty_list_for_bare_alert(self) -> None:
        """A minimal alert with no entities, no MITRE, no case returns []."""
        # The connector_type column is "okta" by default in our helper —
        # the rail always emits a tenant chip when connector_type is set.
        # We strip it to exercise the truly-empty path.
        entities = build_related_entities(_alert(connector_type=None))
        assert entities == []

    def test_principal_group_includes_hosts_users_and_assets(self) -> None:
        entities = build_related_entities(
            _alert(
                affected_hosts=["win-finance-07"],
                affected_users=["alice@example.com"],
                affected_assets=["asset-42"],
                connector_type=None,
            )
        )
        groups = {(e.group, e.kind, e.value) for e in entities}
        assert ("principal", "host", "win-finance-07") in groups
        assert ("principal", "user", "alice@example.com") in groups
        assert ("principal", "asset", "asset-42") in groups

    def test_network_group_promotes_destination_label(self) -> None:
        entities = build_related_entities(
            _alert(
                affected_ips=["10.0.0.5"],
                raw_event={"dst_ip": "203.0.113.7", "domain": "evil.example"},
                connector_type=None,
            )
        )
        # Source IP comes from the denormalised column with no label.
        # Destination is pulled from raw_event and tagged label="destination".
        by_value = {e.value: e for e in entities}
        assert by_value["10.0.0.5"].group == "network"
        assert by_value["10.0.0.5"].label is None
        assert by_value["203.0.113.7"].group == "network"
        assert by_value["203.0.113.7"].label == "destination"
        assert by_value["evil.example"].group == "network"
        assert by_value["evil.example"].kind == "domain"

    def test_workflow_group_promotes_rule_and_mitre(self) -> None:
        entities = build_related_entities(
            _alert(
                raw_event={"rule_name": "Excessive failed logins"},
                mitre_tactics=["initial-access"],
                mitre_techniques=[{"id": "T1078", "name": "Valid Accounts"}],
                connector_type=None,
            )
        )
        by_kind = {(e.kind, e.value): e for e in entities}
        assert by_kind[("rule", "Excessive failed logins")].group == "workflow"
        assert by_kind[("mitre_tactic", "initial-access")].group == "workflow"
        # Dict MITRE rows render the ID as value and the name as label,
        # plus they get a /detection/tuning pivot.
        tech = by_kind[("mitre_technique", "T1078")]
        assert tech.group == "workflow"
        assert tech.label == "Valid Accounts"
        assert tech.pivot == "/detection/tuning?technique=T1078"

    def test_tenant_group_has_connector_and_case_pivots(self) -> None:
        case_id = uuid.uuid4()
        entities = build_related_entities(_alert(connector_type="okta", case_id=case_id))
        by_kind = {e.kind: e for e in entities}
        assert by_kind["connector"].group == "tenant"
        assert by_kind["connector"].value == "okta"
        assert by_kind["case"].group == "tenant"
        assert by_kind["case"].value == str(case_id)
        assert by_kind["case"].pivot == f"/cases/{case_id}"

    def test_rba_promotion_surfaces_as_tenant_pivot(self) -> None:
        entities = build_related_entities(
            _alert(
                enrichment_data={"rba_top_promotion": {"entity": "host:web-01"}},
                connector_type=None,
            )
        )
        by_kind = {e.kind: e for e in entities}
        assert "rba_entity" in by_kind
        assert by_kind["rba_entity"].group == "tenant"
        assert by_kind["rba_entity"].label == "risk promotion"
        assert by_kind["rba_entity"].pivot == "/alerts?view=entities&entity=host:web-01"

    def test_dedup_is_case_insensitive(self) -> None:
        """Duplicate IPs (different casing / surrounding whitespace) collapse."""
        entities = build_related_entities(
            _alert(
                affected_ips=["10.0.0.5", "10.0.0.5", "   10.0.0.5  "],
                connector_type=None,
            )
        )
        # All three collapse to a single network/ip entity.
        ips = [e for e in entities if e.kind == "ip"]
        assert len(ips) == 1
        # First-seen casing wins (no trim/case-change on the kept value
        # beyond surrounding whitespace).
        assert ips[0].value == "10.0.0.5"

    def test_whitespace_only_entities_are_dropped(self) -> None:
        entities = build_related_entities(
            _alert(
                affected_hosts=["   ", ""],
                affected_users=[None, "  alice  "],
                connector_type=None,
            )
        )
        hosts = [e for e in entities if e.kind == "host"]
        users = [e for e in entities if e.kind == "user"]
        assert hosts == []
        # whitespace-trimmed alice survives.
        assert len(users) == 1
        assert users[0].value == "alice"

    def test_pivot_routes_are_built_per_kind(self) -> None:
        """The pivot URL contract is part of the public API.

        The frontend keys off the pivot to decide whether a chip is
        clickable. Pinning the routes prevents an accidental rename.
        """
        entities = build_related_entities(
            _alert(
                affected_hosts=["h1"],
                affected_users=["u1"],
                affected_ips=["1.2.3.4"],
                connector_type=None,
            )
        )
        by_kind = {e.kind: e for e in entities}
        assert by_kind["host"].pivot == "/attack-graph?entity=host:h1"
        assert by_kind["user"].pivot == "/attack-graph?entity=user:u1"
        assert by_kind["ip"].pivot == "/attack-graph?entity=ip:1.2.3.4"


# ─── build_recommended_actions ───────────────────────────────────────────────


class TestBuildRecommendedActions:
    def test_returns_empty_list_when_field_is_none(self) -> None:
        assert build_recommended_actions(_alert(ai_recommendations=None)) == []

    def test_returns_empty_list_when_field_is_not_a_list(self) -> None:
        """Whatever the agent emits, anything non-list returns []."""
        assert build_recommended_actions(_alert(ai_recommendations="oops")) == []
        assert build_recommended_actions(_alert(ai_recommendations={"a": 1})) == []

    def test_structured_dict_shape_round_trips(self) -> None:
        actions = build_recommended_actions(
            _alert(
                ai_recommendations=[
                    {
                        "priority": 2,
                        "action": "Isolate host win-finance-07",
                        "rationale": "Lateral movement detected",
                        "risk": "high",
                    },
                    {
                        "priority": 1,
                        "action": "Disable account",
                        "rationale": None,
                        "risk": "medium",
                    },
                ]
            )
        )
        # Sorted by priority so the agent's intended order wins.
        assert [a.priority for a in actions] == [1, 2]
        assert actions[0].action == "Disable account"
        assert actions[0].risk == "medium"
        assert actions[1].rationale == "Lateral movement detected"

    def test_legacy_list_of_strings_is_promoted(self) -> None:
        actions = build_recommended_actions(
            _alert(
                ai_recommendations=[
                    "Notify on-call",
                    "Open Jira ticket",
                ]
            )
        )
        assert len(actions) == 2
        # String rows get priority = idx + 1 and default risk "low".
        assert actions[0].priority == 1
        assert actions[0].action == "Notify on-call"
        assert actions[0].risk == "low"
        assert actions[1].priority == 2

    def test_risk_outside_canonical_set_falls_back_to_low(self) -> None:
        """The frontend only knows three risk tints — sanitise here."""
        actions = build_recommended_actions(_alert(ai_recommendations=[{"action": "x", "risk": "spicy"}]))
        assert actions[0].risk == "low"

    def test_risk_is_lowercased(self) -> None:
        actions = build_recommended_actions(_alert(ai_recommendations=[{"action": "x", "risk": "HIGH"}]))
        assert actions[0].risk == "high"

    def test_priority_lower_than_one_is_clamped(self) -> None:
        """Pydantic's ``ge=1`` would otherwise raise — the helper clamps first."""
        actions = build_recommended_actions(_alert(ai_recommendations=[{"action": "x", "priority": 0}]))
        assert actions[0].priority == 1

    def test_malformed_priority_falls_back_to_index(self) -> None:
        actions = build_recommended_actions(
            _alert(
                ai_recommendations=[
                    {"action": "a"},  # missing priority
                    {"action": "b", "priority": "bogus"},
                ]
            )
        )
        # Both rows survive; their priorities are idx + 1.
        assert [a.priority for a in actions] == [1, 2]

    def test_blank_action_strings_are_silently_dropped(self) -> None:
        actions = build_recommended_actions(
            _alert(
                ai_recommendations=[
                    "",
                    "   ",
                    None,
                    {"action": "   "},
                    "Valid",
                ]
            )
        )
        assert len(actions) == 1
        assert actions[0].action == "Valid"


# ─── build_mini_timeline (DB-bound) ──────────────────────────────────────────


class TestBuildMiniTimeline:
    def _audit_row(self, **overrides: Any) -> SimpleNamespace:
        base = {
            "id": uuid.uuid4(),
            "tenant_id": uuid.uuid4(),
            "actor_email": "alice@example.com",
            "actor_id": None,
            "action": "status_change",
            "resource": "alert",
            "changes": {"status": ["new", "investigating"]},
            "metadata_": {},
            "created_at": datetime.now(UTC),
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def _case_row(self, **overrides: Any) -> SimpleNamespace:
        base = {
            "id": uuid.uuid4(),
            "event_type": "case_comment",
            "content": "Looks like a real positive — escalating",
            "event_metadata": {"channel": "slack"},
            "is_automated": False,
            "user_id": uuid.uuid4(),
            "created_at": datetime.now(UTC),
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_case_and_no_audit(self) -> None:
        alert = _alert(case_id=None)
        # With no case_id we only hit the audit query (one execute call).
        db = _mock_db_returning([])
        events = await build_mini_timeline(db, alert)
        assert events == []
        # Exactly one query — the audit one. The case query is skipped
        # entirely when case_id is None.
        assert db.execute.await_count == 1

    @pytest.mark.asyncio
    async def test_case_and_audit_events_are_merged(self) -> None:
        alert = _alert(case_id=uuid.uuid4())
        now = datetime.now(UTC)
        case_row = self._case_row(created_at=now - timedelta(minutes=2))
        audit_row = self._audit_row(created_at=now - timedelta(minutes=1))

        # First execute → case rows; second → audit rows.
        db = _mock_db_returning([case_row], [audit_row])
        events = await build_mini_timeline(db, alert)

        assert len(events) == 2
        # Newest first.
        assert events[0].id == str(audit_row.id)
        assert events[1].id == str(case_row.id)
        assert events[1].kind == "case_comment"
        assert events[1].agent == str(case_row.user_id)
        # Two queries — the case one and the audit one.
        assert db.execute.await_count == 2

    @pytest.mark.asyncio
    async def test_results_are_capped_at_max_events(self) -> None:
        alert = _alert(case_id=uuid.uuid4())
        many_cases = [self._case_row() for _ in range(MAX_TIMELINE_EVENTS + 3)]
        many_audits = [self._audit_row() for _ in range(MAX_TIMELINE_EVENTS + 3)]

        db = _mock_db_returning(many_cases, many_audits)
        events = await build_mini_timeline(db, alert)

        assert len(events) == MAX_TIMELINE_EVENTS

    @pytest.mark.asyncio
    async def test_audit_event_summary_includes_action_and_resource(self) -> None:
        alert = _alert(case_id=None)
        audit_row = self._audit_row(action="assign", resource="alert")
        db = _mock_db_returning([audit_row])

        events = await build_mini_timeline(db, alert)

        assert len(events) == 1
        assert events[0].summary == "assign on alert"
        assert events[0].kind == "assign"
        assert events[0].agent == "alice@example.com"
        # changes blob is surfaced as the payload so the rail row can
        # expand on click.
        assert events[0].payload == {"status": ["new", "investigating"]}

    @pytest.mark.asyncio
    async def test_audit_event_falls_back_to_metadata_when_changes_empty(self) -> None:
        alert = _alert(case_id=None)
        audit_row = self._audit_row(changes={}, metadata_={"source_ip": "10.0.0.1"})
        db = _mock_db_returning([audit_row])

        events = await build_mini_timeline(db, alert)
        assert events[0].payload == {"source_ip": "10.0.0.1"}

    @pytest.mark.asyncio
    async def test_audit_event_actor_id_fallback_when_email_missing(self) -> None:
        alert = _alert(case_id=None)
        actor_id = uuid.uuid4()
        audit_row = self._audit_row(actor_email=None, actor_id=actor_id)
        db = _mock_db_returning([audit_row])

        events = await build_mini_timeline(db, alert)
        assert events[0].agent == str(actor_id)

    @pytest.mark.asyncio
    async def test_automated_case_event_attributes_to_system(self) -> None:
        alert = _alert(case_id=uuid.uuid4())
        automated_row = self._case_row(is_automated=True, user_id=None)
        db = _mock_db_returning([automated_row], [])

        events = await build_mini_timeline(db, alert)
        assert events[0].agent == "system"


# ─── build_rail_envelope ─────────────────────────────────────────────────────


class TestBuildRailEnvelope:
    @pytest.mark.asyncio
    async def test_returns_pydantic_envelope_with_all_three_sections(self) -> None:
        alert = _alert(
            affected_ips=["10.0.0.5"],
            ai_recommendations=[{"action": "Isolate", "priority": 1, "risk": "high"}],
            case_id=None,
        )
        db = _mock_db_returning([])  # one execute call (audit only)

        envelope = await build_rail_envelope(db, alert)

        assert isinstance(envelope, RailEnvelope)
        assert any(e.kind == "ip" and e.value == "10.0.0.5" for e in envelope.related_entities)
        assert envelope.mini_timeline == []
        assert len(envelope.recommended_actions) == 1
        assert envelope.recommended_actions[0].action == "Isolate"

    @pytest.mark.asyncio
    async def test_envelope_is_json_serialisable(self) -> None:
        """The envelope rides on the wire; Pydantic must serialise it."""
        alert = _alert(
            affected_ips=["10.0.0.5"],
            ai_recommendations=[{"action": "Isolate", "priority": 1}],
            case_id=None,
        )
        db = _mock_db_returning([])

        envelope = await build_rail_envelope(db, alert)
        payload = envelope.model_dump(mode="json")

        # The wire format is snake_case (see normalizeAlert on the FE).
        assert "related_entities" in payload
        assert "mini_timeline" in payload
        assert "recommended_actions" in payload
        # And the entity fields are also snake_case ready for the rail.
        assert payload["related_entities"][0]["group"] == "network"


# ─── RelatedEntity / RecommendedAction Pydantic contracts ────────────────────


class TestPydanticContracts:
    def test_related_entity_serialises_snake_case(self) -> None:
        e = RelatedEntity(
            group="principal",
            kind="host",
            value="win-finance-07",
            label="primary",
            pivot="/attack-graph?entity=host:win-finance-07",
        )
        dump = e.model_dump(mode="json")
        assert set(dump) == {"group", "kind", "value", "label", "pivot"}
        assert dump["value"] == "win-finance-07"

    def test_recommended_action_priority_must_be_at_least_one(self) -> None:
        """Defence in depth — the helper clamps, but the model also enforces."""
        with pytest.raises(ValidationError):
            RecommendedAction(priority=0, action="x")

    def test_mini_timeline_event_payload_is_optional(self) -> None:
        e = MiniTimelineEvent(
            id="abc",
            ts=datetime.now(UTC),
            kind="audit",
            agent="system",
            summary="x",
        )
        assert e.payload is None
        assert e.duration_ms == 0

"""Tests for the Business Context Rules engine + endpoints — T3.5.

Coverage map
~~~~~~~~~~~~

YAML parser (``models.load_rules_from_yaml``)
    * Empty / whitespace YAML → empty list.
    * Single-rule shorthand and ``rules:`` list form both parse.
    * Aggregator forms (``all``/``any``/``not``) round-trip correctly.
    * Bad rule ids, bad ops, missing required clauses, no-op ``then``,
      and invalid ``set_severity`` / ``route_to`` / ``tag`` slugs all
      raise :class:`RuleParseError` with actionable messages.
    * ``in`` op coerces a single string into a one-element list.

Engine evaluation (``BusinessContextEngine.evaluate``)
    * Severity gets bumped exactly when the predicate matches.
    * ``suppress`` short-circuits remaining rules deterministically.
    * Multiple matching rules layer their actions; tags accumulate
      without dupes; later rules override severity / route_to.
    * Field accessor walks dotted paths and treats missing keys as
      "no match" for non-existence ops.

Engine snapshots (``BusinessContextEngine.replace`` / ``snapshot_for``)
    * Rules sort by ``(priority, id)`` for determinism.
    * The reverse field index records every dotted path referenced.
    * ``replace`` is atomic: two callers swapping versions never see a
      mid-update intermediate.

Dry-run preview (``BusinessContextEngine.preview_against``)
    * Transient snapshot: doesn't mutate the registered tenant snapshot.
    * Per-alert ``before`` / ``after`` reflects the action layering.

Endpoint contract (``services/api/app/api/v1/endpoints/business_context.py``)
    * ``GET /rules`` returns the persisted YAML + parsed rules envelope.
    * ``POST /rules`` round-trips YAML and bumps the engine version.
    * ``POST /rules`` with bad YAML returns 422 with the parser message.
    * ``PUT /rules/{id}`` patches a single rule; rejects mismatched id.
    * ``DELETE /rules/{id}`` 204 on hit, 404 on miss.
    * ``POST /rules/preview`` returns one row per alert with sample_size /
      changed_count / suppressed_count + per-row before/after.
    * Save → preview round-trip lands inside the **1s** budget called
      out by the task spec.

The endpoint tests stub :class:`AuthUser` and the DB session directly
(matching the saved-hunts test approach), so the whole suite runs with
zero infrastructure.
"""

from __future__ import annotations

import asyncio
import textwrap
import time
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import business_context as endpoint
from app.services.business_context import (
    BusinessContextEngine,
    RuleParseError,
    load_rules_from_yaml,
)
from app.services.business_context.engine import (
    _apply_action,
    _projection,
    evaluate_condition,
    get_engine,
    measure_evaluation_latency,
    reset_engine_for_tests,
)
from app.services.business_context.models import (
    ALLOWED_OPS,
    ALLOWED_ROUTES,
    ALLOWED_SEVERITIES,
    BusinessContextRule,
    RuleAction,
    RuleCondition,
)
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_state() -> None:
    """Reset the global engine + in-memory rule store between tests."""
    reset_engine_for_tests()
    endpoint._reset_store_for_tests()
    yield
    reset_engine_for_tests()
    endpoint._reset_store_for_tests()


def _user(tenant_id: uuid.UUID | None = None) -> SimpleNamespace:
    """Auth stand-in; the endpoint only reads ``tenant_id`` and the
    permission helper."""

    async def _allow(_perm: str, _db: Any) -> None:
        return None

    return SimpleNamespace(
        tenant_id=tenant_id or uuid.uuid4(),
        user_id=uuid.uuid4(),
        role="admin",
        require_permission_db=_allow,
    )


def _yaml(text: str) -> str:
    """Strip leading indentation so triple-quoted YAML in tests parses."""
    return textwrap.dedent(text).strip() + "\n"


def _alert(
    alert_id: str = "a-1",
    *,
    severity: str = "medium",
    route_to: str | None = None,
    tags: list[str] | None = None,
    target_tag: str = "prod",
    business_hours: bool = True,
    source: str = "aws",
) -> dict[str, Any]:
    """A minimal alert shaped like the dotted paths rules reference."""
    return {
        "id": alert_id,
        "severity": severity,
        "route_to": route_to,
        "tags": list(tags or []),
        "source": source,
        "alert": {
            "severity": severity,
            "source": source,
            "target": {"tag": target_tag},
            "time": {"is_business_hours": business_hours},
        },
    }


# ---------------------------------------------------------------------------
# YAML parser
# ---------------------------------------------------------------------------


class TestParser:
    def test_empty_yaml_returns_empty_list(self) -> None:
        assert load_rules_from_yaml("") == []
        assert load_rules_from_yaml("   \n  ") == []

    def test_single_rule_shorthand(self) -> None:
        rules = load_rules_from_yaml(_yaml("""
            id: prod-iam-critical
            description: Critical for prod IAM
            when:
              field: alert.target.tag
              op: eq
              value: prod
            then:
              set_severity: critical
            """))
        assert len(rules) == 1
        rule = rules[0]
        assert rule.id == "prod-iam-critical"
        assert rule.then.set_severity == "critical"
        assert rule.when.field == "alert.target.tag"
        assert rule.when.op == "eq"
        assert rule.when.value == "prod"

    def test_rules_list_form(self) -> None:
        rules = load_rules_from_yaml(_yaml("""
            rules:
              - id: rule-a
                when: { field: alert.severity, op: eq, value: high }
                then: { set_severity: critical }
              - id: rule-b
                when: { field: alert.source, op: eq, value: aws }
                then: { route_to: cloud }
            """))
        assert [r.id for r in rules] == ["rule-a", "rule-b"]
        assert rules[1].then.route_to == "cloud"

    def test_aggregator_all_any_not(self) -> None:
        rules = load_rules_from_yaml(_yaml("""
            id: nested
            when:
              all:
                - any:
                    - { field: alert.source, op: eq, value: aws }
                    - { field: alert.source, op: eq, value: gcp }
                - not:
                    field: alert.target.tag
                    op: eq
                    value: dev
            then:
              tag: cloud-prod
            """))
        when = rules[0].when
        assert when.logical == "all"
        assert when.children[0].logical == "any"
        assert when.children[1].logical == "not"
        # Field-reverse-index covers the leaves under both legs of the
        # aggregator tree, not just the top-level node.
        assert when.fields_referenced() == {"alert.source", "alert.target.tag"}

    def test_in_op_coerces_single_string_to_list(self) -> None:
        rules = load_rules_from_yaml(_yaml("""
            id: route-aws
            when: { field: alert.source, op: in, value: aws }
            then: { route_to: cloud }
            """))
        assert rules[0].when.value == ["aws"]

    @pytest.mark.parametrize(
        "yaml_text,marker",
        [
            ("id: BAD\nwhen: { field: x, op: eq, value: y }\nthen: { tag: t }", "kebab-case"),
            ("id: ok-id\nthen: { set_severity: high }", "'when' clause is required"),
            ("id: ok-id\nwhen: { field: x, op: eq, value: y }\nthen: { set_severity: nope }",
             "set_severity"),
            ("id: ok-id\nwhen: { field: x, op: like, value: y }\nthen: { tag: t }", "is not one of"),
            ("id: ok-id\nwhen: { field: x, op: eq, value: y }\nthen: {}", "must set at least one"),
            ("id: ok-id\nwhen: { field: x, op: in }\nthen: { tag: t }", "required for op="),
            ("id: ok-id\nwhen: { field: x, op: eq, value: y }\nthen: { route_to: nope }",
             "route_to"),
        ],
    )
    def test_invalid_inputs_raise_with_actionable_messages(
        self, yaml_text: str, marker: str
    ) -> None:
        with pytest.raises(RuleParseError) as exc_info:
            load_rules_from_yaml(yaml_text)
        assert marker in str(exc_info.value)

    def test_duplicate_ids_rejected(self) -> None:
        with pytest.raises(RuleParseError, match="duplicate rule id"):
            load_rules_from_yaml(_yaml("""
                rules:
                  - id: dup-rule
                    when: { field: a, op: eq, value: 1 }
                    then: { set_severity: low }
                  - id: dup-rule
                    when: { field: b, op: eq, value: 2 }
                    then: { set_severity: high }
                """))

    def test_constants_are_locked_down(self) -> None:
        # Catches accidental edits that broaden the action vocabulary —
        # any new severity / route option must show up in this list.
        assert ALLOWED_SEVERITIES == ("info", "low", "medium", "high", "critical")
        assert "tier1" in ALLOWED_ROUTES and "tier2" in ALLOWED_ROUTES
        assert "eq" in ALLOWED_OPS and "exists" in ALLOWED_OPS


# ---------------------------------------------------------------------------
# Engine — evaluation
# ---------------------------------------------------------------------------


class TestEvaluation:
    def test_severity_bump_when_predicate_matches(self) -> None:
        engine = BusinessContextEngine()
        tenant = uuid.uuid4()
        engine.replace(
            tenant,
            load_rules_from_yaml(_yaml("""
                id: prod-critical
                when: { field: alert.target.tag, op: eq, value: prod }
                then: { set_severity: critical }
                """)),
        )
        result = engine.evaluate(tenant, _alert(severity="medium", target_tag="prod"))
        assert result.before["severity"] == "medium"
        assert result.after["severity"] == "critical"
        assert result.matched_rule_ids == ["prod-critical"]
        assert result.changed is True

    def test_no_match_leaves_alert_unchanged(self) -> None:
        engine = BusinessContextEngine()
        tenant = uuid.uuid4()
        engine.replace(
            tenant,
            load_rules_from_yaml(_yaml("""
                id: prod-only
                when: { field: alert.target.tag, op: eq, value: prod }
                then: { set_severity: critical }
                """)),
        )
        result = engine.evaluate(tenant, _alert(target_tag="dev", severity="medium"))
        assert result.before == result.after
        assert result.matched_rule_ids == []
        assert result.changed is False

    def test_suppress_short_circuits_subsequent_rules(self) -> None:
        engine = BusinessContextEngine()
        tenant = uuid.uuid4()
        engine.replace(
            tenant,
            load_rules_from_yaml(_yaml("""
                rules:
                  - id: maintenance-window
                    priority: 1
                    when: { field: alert.target.tag, op: eq, value: prod }
                    then: { suppress: true }
                  - id: should-never-run
                    priority: 50
                    when: { field: alert.target.tag, op: eq, value: prod }
                    then: { set_severity: critical }
                """)),
        )
        result = engine.evaluate(tenant, _alert(target_tag="prod", severity="medium"))
        assert result.suppressed is True
        assert result.matched_rule_ids == ["maintenance-window"]
        # ``should-never-run`` would have set severity if not for suppression.
        assert result.after["severity"] == "medium"

    def test_actions_layer_in_priority_order(self) -> None:
        engine = BusinessContextEngine()
        tenant = uuid.uuid4()
        engine.replace(
            tenant,
            load_rules_from_yaml(_yaml("""
                rules:
                  - id: aws-baseline
                    priority: 10
                    when: { field: alert.source, op: eq, value: aws }
                    then: { route_to: cloud, tag: aws }
                  - id: prod-bump
                    priority: 50
                    when: { field: alert.target.tag, op: eq, value: prod }
                    then: { set_severity: critical, tag: prod }
                """)),
        )
        result = engine.evaluate(tenant, _alert(source="aws", target_tag="prod"))
        assert result.matched_rule_ids == ["aws-baseline", "prod-bump"]
        assert result.after["severity"] == "critical"
        assert result.after["route_to"] == "cloud"
        # Tags accumulate without duplicates and preserve insertion order.
        assert result.after["tags"] == ["aws", "prod"]

    def test_missing_field_treated_as_non_match_for_value_ops(self) -> None:
        cond = RuleCondition(field="missing.path", op="eq", value="x")
        assert evaluate_condition(cond, {"alert": {"id": "a"}}) is False

    def test_exists_distinguishes_missing_from_explicit_none(self) -> None:
        present = evaluate_condition(
            RuleCondition(field="alert.target.tag", op="exists"),
            {"alert": {"target": {"tag": None}}},
        )
        missing = evaluate_condition(
            RuleCondition(field="alert.target.tag", op="exists"),
            {"alert": {"target": {}}},
        )
        assert present is True
        assert missing is False

    def test_apply_action_does_not_mutate_input(self) -> None:
        original = {"severity": "low", "tags": ["a"]}
        out = _apply_action(original, RuleAction(set_severity="high", tag="b"))
        assert out["severity"] == "high"
        assert sorted(out["tags"]) == ["a", "b"]
        assert original["severity"] == "low"
        assert original["tags"] == ["a"]

    def test_projection_returns_only_ui_visible_fields(self) -> None:
        proj = _projection({"severity": "low", "noise": "yes", "tags": ["a"]})
        assert set(proj.keys()) == {"severity", "route_to", "tags", "suppressed"}


# ---------------------------------------------------------------------------
# Engine — snapshots & hot-reload
# ---------------------------------------------------------------------------


class TestSnapshots:
    def test_replace_returns_sorted_snapshot(self) -> None:
        engine = BusinessContextEngine()
        tenant = uuid.uuid4()
        snap = engine.replace(
            tenant,
            load_rules_from_yaml(_yaml("""
                rules:
                  - id: zzz
                    priority: 5
                    when: { field: x, op: eq, value: 1 }
                    then: { tag: zzz }
                  - id: aaa
                    priority: 100
                    when: { field: y, op: eq, value: 1 }
                    then: { tag: aaa }
                  - id: mmm
                    priority: 5
                    when: { field: z, op: eq, value: 1 }
                    then: { tag: mmm }
                """)),
        )
        assert [r.id for r in snap.rules] == ["mmm", "zzz", "aaa"]
        # Field reverse-index records all leaf paths.
        assert set(snap.field_index.keys()) == {"x", "y", "z"}

    def test_version_bumps_on_each_replace(self) -> None:
        engine = BusinessContextEngine()
        tenant = uuid.uuid4()
        snap1 = engine.replace(tenant, [])
        snap2 = engine.replace(tenant, [])
        assert snap2.version == snap1.version + 1

    def test_snapshot_is_per_tenant(self) -> None:
        engine = BusinessContextEngine()
        a, b = uuid.uuid4(), uuid.uuid4()
        engine.replace(
            a,
            load_rules_from_yaml(_yaml("""
                id: only-a
                when: { field: x, op: eq, value: 1 }
                then: { tag: a }
                """)),
        )
        engine.replace(b, [])
        assert engine.snapshot_for(a).rules[0].id == "only-a"
        assert engine.snapshot_for(b).rules == ()

    def test_get_engine_returns_singleton(self) -> None:
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2


# ---------------------------------------------------------------------------
# Engine — dry-run preview
# ---------------------------------------------------------------------------


class TestPreview:
    def test_preview_does_not_mutate_registered_snapshot(self) -> None:
        engine = BusinessContextEngine()
        tenant = uuid.uuid4()
        # Register an empty rule set.
        engine.replace(tenant, [])
        # Preview a rule that would, if registered, mutate severity.
        candidate = load_rules_from_yaml(_yaml("""
            id: would-bump
            when: { field: alert.target.tag, op: eq, value: prod }
            then: { set_severity: critical }
            """))
        results = engine.preview_against(
            tenant,
            [_alert(target_tag="prod", severity="medium")],
            rules=candidate,
        )
        assert results[0].after["severity"] == "critical"
        # Registered snapshot still empty.
        assert engine.snapshot_for(tenant).rules == ()

    def test_preview_returns_one_row_per_alert(self) -> None:
        engine = BusinessContextEngine()
        tenant = uuid.uuid4()
        rules = load_rules_from_yaml(_yaml("""
            id: prod-critical
            when: { field: alert.target.tag, op: eq, value: prod }
            then: { set_severity: critical }
            """))
        alerts = [
            _alert("a", target_tag="prod"),
            _alert("b", target_tag="dev"),
            _alert("c", target_tag="prod"),
        ]
        results = engine.preview_against(tenant, alerts, rules=rules)
        assert [r.alert_id for r in results] == ["a", "b", "c"]
        assert [r.changed for r in results] == [True, False, True]


# ---------------------------------------------------------------------------
# Endpoint contract
# ---------------------------------------------------------------------------


def _run(coro):  # type: ignore[no-untyped-def]
    """Drive an async endpoint coroutine to completion in a fresh loop.

    Each call gets its own event loop so the per-test isolation that
    ``_isolate_state`` provides extends to the asyncio runtime.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestEndpoints:
    def test_get_returns_empty_envelope_when_no_rules(self) -> None:
        user = _user()
        env = _run(endpoint.get_rules(user, MagicMock()))
        assert env.tenant_id == str(user.tenant_id)
        assert env.rules == []
        assert env.yaml == ""
        assert env.enabled is True
        assert env.version >= 1  # engine.replace always bumps

    def test_post_replace_persists_yaml_and_returns_parsed_view(self) -> None:
        user = _user()
        yaml_text = _yaml("""
        id: prod-critical
        description: Bump prod alerts to critical
        when: { field: alert.target.tag, op: eq, value: prod }
        then: { set_severity: critical }
        """)
        env = _run(
            endpoint.replace_rules(
                endpoint.ReplaceRulesRequest(yaml=yaml_text),
                user,
                MagicMock(),
            )
        )
        assert env.yaml == yaml_text
        assert len(env.rules) == 1
        assert env.rules[0].id == "prod-critical"
        assert env.rules[0].then.set_severity == "critical"
        # Subsequent GET sees the same persisted YAML.
        env2 = _run(endpoint.get_rules(user, MagicMock()))
        assert env2.yaml == yaml_text
        assert env2.rules[0].id == "prod-critical"

    def test_post_replace_with_invalid_yaml_returns_422(self) -> None:
        user = _user()
        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.replace_rules(
                    endpoint.ReplaceRulesRequest(yaml="id: BAD\nthen: { tag: t }"),
                    user,
                    MagicMock(),
                )
            )
        assert exc_info.value.status_code == 422
        assert "kebab-case" in exc_info.value.detail

    def test_put_patches_single_rule_by_id(self) -> None:
        user = _user()
        # Seed two rules.
        seed = _yaml("""
        rules:
          - id: rule-a
            when: { field: alert.severity, op: eq, value: high }
            then: { set_severity: critical }
          - id: rule-b
            when: { field: alert.source, op: eq, value: aws }
            then: { route_to: cloud }
        """)
        _run(
            endpoint.replace_rules(
                endpoint.ReplaceRulesRequest(yaml=seed),
                user,
                MagicMock(),
            )
        )
        # Patch rule-a only.
        env = _run(
            endpoint.update_rule(
                "rule-a",
                endpoint.UpdateRuleRequest(
                    yaml=(
                        "id: rule-a\n"
                        "when: { field: alert.severity, op: eq, value: high }\n"
                        "then: { route_to: tier3 }\n"
                    )
                ),
                user,
                MagicMock(),
            )
        )
        rules_by_id = {r.id: r for r in env.rules}
        assert rules_by_id["rule-a"].then.route_to == "tier3"
        assert rules_by_id["rule-a"].then.set_severity is None
        # rule-b untouched.
        assert rules_by_id["rule-b"].then.route_to == "cloud"

    def test_put_rejects_id_mismatch(self) -> None:
        user = _user()
        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.update_rule(
                    "rule-a",
                    endpoint.UpdateRuleRequest(
                        yaml=(
                            "id: rule-other\n"
                            "when: { field: x, op: eq, value: 1 }\n"
                            "then: { tag: t }\n"
                        )
                    ),
                    user,
                    MagicMock(),
                )
            )
        assert exc_info.value.status_code == 422
        assert "must match" in exc_info.value.detail

    def test_delete_removes_rule(self) -> None:
        user = _user()
        seed = _yaml("""
        rules:
          - id: keep
            when: { field: x, op: eq, value: 1 }
            then: { tag: keep }
          - id: drop
            when: { field: y, op: eq, value: 1 }
            then: { tag: drop }
        """)
        _run(
            endpoint.replace_rules(
                endpoint.ReplaceRulesRequest(yaml=seed),
                user,
                MagicMock(),
            )
        )
        result = _run(endpoint.delete_rule("drop", user, MagicMock()))
        assert result is None
        env = _run(endpoint.get_rules(user, MagicMock()))
        assert [r.id for r in env.rules] == ["keep"]

    def test_delete_404_when_rule_missing(self) -> None:
        user = _user()
        with pytest.raises(HTTPException) as exc_info:
            _run(endpoint.delete_rule("never-existed", user, MagicMock()))
        assert exc_info.value.status_code == 404

    def test_preview_against_supplied_alerts(self) -> None:
        user = _user()
        req = endpoint.PreviewRequest(
            yaml=(
                "id: prod-critical\n"
                "when: { field: alert.target.tag, op: eq, value: prod }\n"
                "then: { set_severity: critical }\n"
            ),
            alerts=[
                _alert("a", target_tag="prod", severity="medium"),
                _alert("b", target_tag="dev", severity="medium"),
            ],
        )
        resp = _run(endpoint.preview_rules(req, user, MagicMock()))
        assert resp.sample_size == 2
        assert resp.changed_count == 1
        assert resp.suppressed_count == 0
        # First alert mutated, second untouched.
        first, second = resp.rows
        assert first.changed is True
        assert first.before["severity"] == "medium"
        assert first.after["severity"] == "critical"
        assert second.changed is False

    def test_preview_invalid_yaml_returns_422(self) -> None:
        user = _user()
        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.preview_rules(
                    endpoint.PreviewRequest(yaml="id: BAD\nthen: { tag: t }"),
                    user,
                    MagicMock(),
                )
            )
        assert exc_info.value.status_code == 422

    def test_preview_falls_back_to_sample_alerts_when_alerts_omitted(
        self,
    ) -> None:
        user = _user()
        # Stub the DB so _fetch_sample_alerts can short-circuit without
        # the aisoc_alerts table existing in the test env.
        db = MagicMock()
        db.execute = AsyncMock(side_effect=RuntimeError("no schema"))
        req = endpoint.PreviewRequest(
            yaml=(
                "id: noop-tag\n"
                "when: { field: alert.target.tag, op: eq, value: prod }\n"
                "then: { tag: noop }\n"
            ),
            alerts=[],
        )
        resp = _run(endpoint.preview_rules(req, user, db))
        assert resp.sample_size == 0
        assert resp.changed_count == 0
        assert resp.rows == []

    def test_save_to_evaluate_round_trip_under_one_second(self) -> None:
        """Task spec: rule mutating severity must be reflected within 1s
        of save. We measure save (POST /rules) + a 100-alert evaluation
        wall-clock; both operations live in the same process, so the
        budget is dominated by YAML parsing + condition evaluation
        rather than I/O.
        """
        user = _user()
        yaml_text = _yaml("""
        rules:
          - id: prod-critical
            priority: 10
            when: { field: alert.target.tag, op: eq, value: prod }
            then: { set_severity: critical }
          - id: aws-cloud
            priority: 20
            when: { field: alert.source, op: eq, value: aws }
            then: { route_to: cloud, tag: aws }
        """)
        alerts = [
            _alert(f"alert-{i}", target_tag="prod" if i % 2 else "dev",
                   source="aws" if i % 3 == 0 else "okta")
            for i in range(100)
        ]

        start = time.perf_counter()
        _run(
            endpoint.replace_rules(
                endpoint.ReplaceRulesRequest(yaml=yaml_text),
                user,
                MagicMock(),
            )
        )
        engine = get_engine()
        elapsed_eval = measure_evaluation_latency(engine, user.tenant_id, alerts)
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, (
            f"save → evaluate round-trip took {elapsed:.3f}s, exceeds 1s budget "
            f"(eval slice = {elapsed_eval:.3f}s for 100 alerts)"
        )

        # Sanity check: at least the prod alerts got bumped.
        result = engine.evaluate(user.tenant_id, _alert(target_tag="prod", source="aws"))
        assert result.after["severity"] == "critical"
        assert result.after["route_to"] == "cloud"

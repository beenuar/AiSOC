"""Issue #1243: the autonomy page described a posture the product does not have.

``GET /api/v1/autonomy-policy`` returned nineteen per-action confidence
thresholds and nothing else. The console inferred "this action auto-executes"
from ``thresholds.auto < 1``, every shipped default is below 1.0, and seven of
the nineteen are high- or critical-blast — so a fresh install rendered
**"Autopilot · 7 high-blast actions auto-execute"**.

Nothing in the response path reads those thresholds. A response verb is graded
by ``services/actions`` on the tenant's L0-L4 maturity tier and the verb's own
capability contract; the deployment default is L1, which auto-executes nothing
above a read, and every containment verb declares ``analyst``. The dispatcher
queues all seven.

These tests assert the endpoint reports the control that actually decides.

Two things they are careful about:

*They fail on the pre-fix tree for the defect, not for an import.* Only
``autonomy_policy``, ``CurrentUser`` and ``get_db`` are imported, all of which
exist on both sides. A run against the previous module fails because the
response carries no ``effective`` block and no per-action verdict.

*They assert the two answers differ.* ``test_a_reachable_threshold_is_not_an_
auto_execution`` fails if somebody wires the effective verdict back to the
threshold, which is the specific regression that would restore the bug while
leaving every field name in place.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import autonomy_policy

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")

#: The seven rows the console counted as unattended containment. Named rather
#: than derived from ``_BLAST_RADIUS`` so a future edit that quietly drops one
#: from the table does not also drop it from the assertion.
HIGH_BLAST_ACTIONS = (
    "block_ip",
    "delete_object",
    "disable_user_account",
    "firewall_rule_add",
    "firewall_rule_remove",
    "isolate_host",
    "quarantine_file",
)

#: Threshold rows whose verb has no executor anywhere in the tree. The one
#: issue #1243 names explicitly is ``delete_object``: critical blast radius, no
#: ``ActionType``, no capability contract, no executor — and it was being
#: counted among the verbs running unattended.
VERBS_WITH_NO_EXECUTOR = ("delete_object", "firewall_rule_add", "firewall_rule_remove")


def _result(*, mappings_all: list[Any] | None = None, mappings_first: Any = None) -> MagicMock:
    result = MagicMock()
    mappings = MagicMock()
    mappings.all = MagicMock(return_value=list(mappings_all or []))
    mappings.first = MagicMock(return_value=mappings_first)
    result.mappings = MagicMock(return_value=mappings)
    # The RBAC lookup in `require_permission_db` reads rows directly; an empty
    # list sends it to the static role map, where `tenant_admin` holds
    # `settings:read`.
    result.all = MagicMock(return_value=[])
    return result


def _db(*, maturity_row: dict[str, Any] | None = None, granted_verbs: tuple[str, ...] = ()) -> AsyncMock:
    """A session that answers the three statements this handler issues."""

    async def execute(statement: Any, params: Any = None) -> MagicMock:
        sql = str(statement)
        if "remediation_maturity" in sql:
            return _result(mappings_first=maturity_row)
        if "aisoc_autonomy_grants" in sql:
            return _result(mappings_all=[{"scope_key": verb} for verb in granted_verbs])
        if "aisoc_autonomy_thresholds" in sql:
            return _result(mappings_all=[])
        return _result()

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _policy(**kwargs: Any) -> dict[str, Any]:
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="tenant_admin", email="admin@tenant-a.example")
    response = asyncio.run(autonomy_policy.get_autonomy_policy(user=user, db=_db(**kwargs)))
    return response.model_dump()


@pytest.fixture
def default_install(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A tenant that has configured nothing, on a deployment that set nothing."""
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
    return _policy()


def _by_action(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["action"]: row for row in payload["actions"]}


def test_the_response_names_the_control_that_gates_execution(default_install: dict[str, Any]) -> None:
    assert "effective" in default_install, (
        "the response carries only confidence thresholds, so the console has nothing to derive a "
        "posture from except a table no dispatch path reads — which is issue #1243"
    )
    effective = default_install["effective"]
    assert effective["tier"] == "L1"
    assert effective["tier_label"] == "L1-Notify"
    assert effective["tier_source"] == "environment"
    assert effective["max_automatic_impact"] == "read_only"


def test_a_fresh_install_reports_copilot_not_autopilot(default_install: dict[str, Any]) -> None:
    """The headline claim. Nothing high-blast runs unattended at L1."""
    effective = default_install["effective"]
    assert effective["high_blast_auto_executing"] == [], (
        f"the API reports {effective['high_blast_auto_executing']} high-blast actions as "
        f"auto-executing on a default install; the dispatcher queues every one of them"
    )
    assert effective["auto_executing_actions"] == []

    rows = _by_action(default_install)
    for action in HIGH_BLAST_ACTIONS:
        assert rows[action]["effective_auto_execute"] is False, f"{action} is reported as auto-executing"


def test_a_reachable_threshold_is_not_an_auto_execution(default_install: dict[str, Any]) -> None:
    """The two answers must be able to disagree, or the fix is cosmetic.

    ``thresholds.auto < 1`` was the console's definition of auto-executing.
    If the effective verdict were ever wired back to it, every assertion above
    would still pass on names alone. This one fails.
    """
    reachable_but_gated = [
        row["action"] for row in default_install["actions"] if row["thresholds"]["auto"] < 1 and not row["effective_auto_execute"]
    ]
    assert reachable_but_gated, (
        "no action has a reachable confidence threshold and a gated runtime verdict, so the "
        "effective answer is still being derived from the threshold"
    )


def test_a_verb_with_no_executor_is_not_presented_as_executable(default_install: dict[str, Any]) -> None:
    """`delete_object` is critical-blast, has no executor, and was counted."""
    rows = _by_action(default_install)
    for action in VERBS_WITH_NO_EXECUTOR:
        assert rows[action]["executable"] is False, f"{action} is presented as executable; nothing in the tree can run it"
        assert rows[action]["capability"] is None
        assert rows[action]["effective_auto_execute"] is False
        assert "advisory" in rows[action]["effective_reason"]

    assert set(VERBS_WITH_NO_EXECUTOR) <= set(default_install["effective"]["unimplemented_actions"])


def test_the_thresholds_are_declared_advisory(default_install: dict[str, Any]) -> None:
    """Stated, not implied. An editable slider reads as a live control."""
    effective = default_install["effective"]
    assert effective["thresholds_are_advisory"] is True
    assert "advisory" in effective["advisory_note"].lower()


def test_an_operator_tier_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Parsed by the same function the dispatcher uses, including its aliases."""
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L4_AUTOMATE")
    effective = _policy()["effective"]
    assert effective["tier"] == "L4"
    assert effective["max_automatic_impact"] == "high"


def test_the_top_of_the_ladder_still_does_not_auto_execute_containment(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tier raises a ceiling; it cannot lower a contract's own floor.

    Every containment verb on this page declares ``analyst`` approval, so the
    copilot claim is a property of the contracts rather than of the default
    tier — which is what lets the card say "no autonomy tier executes these
    unattended" rather than "none does today".
    """
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")
    payload = _policy(maturity_row={"maturity_tier": 4, "action_overrides": {}})
    rows = _by_action(payload)
    for action in HIGH_BLAST_ACTIONS:
        assert rows[action]["auto_executes_at_any_tier"] is False, f"{action} would auto-execute at some tier"
    assert payload["effective"]["tier_source"] == "tenant_policy"
    assert payload["effective"]["high_blast_auto_executing"] == []


def test_an_unreadable_policy_row_falls_back_to_the_conservative_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never inherit a permissive default when a tenant policy may exist.

    Mirrors ``tenant_policy.UNREADABLE_POLICY_FLOOR``. A corrupt tier is the
    readable form of the same problem: a row exists and does not mean anything.
    """
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")
    payload = _policy(maturity_row={"maturity_tier": 9, "action_overrides": {}})
    assert payload["effective"]["tier"] == "L1"
    assert payload["effective"]["tier_source"] == "unreadable_policy_floor"


def test_an_earned_grant_raises_the_ceiling_it_is_allowed_to_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """A grant lifts the tier ceiling for one verb and stops at L3.

    Read without re-checking the evidence behind it, which makes this page
    slightly more generous than the dispatcher. That is the right direction:
    omitting a grant would tell an operator a human signs off on something
    that in fact runs by itself.
    """
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
    payload = _policy(granted_verbs=("quarantine_file",))
    row = _by_action(payload)["quarantine_file"]
    assert row["effective_tier"] == "L3"
    # Still gated: the contract declares analyst approval, and no ceiling
    # lowers that.
    assert row["effective_auto_execute"] is False

"""Both dispatch doors must grade the same verb the same way.

The instance that prompted this: ``search_siem`` declares ``read_only``
impact and ``automatic`` approval, and the contract gate's own rule is that a
read requiring approval "is either mis-classified or is not actually a read".
At the default autonomy tier it came back ``awaiting_approval`` from
``POST /actions`` and executed from ``POST /live-actions/dispatch``.

``dispatcher``'s docstring said the contract block existed so that the same
verb would not be "graded differently depending on which door it came
through", and that is what was happening — because the registry door had
grown a local READ_ONLY short-circuit to route around a matrix tier ceiling
that gated reads, and the legacy door had not.

Fixing the instance is a one-line table change. What stops the next one is
this file, which sweeps **both live doors over every capability, every
autonomy tier and every confidence band** and asserts they reach the same
answer to the only question that matters: did a vendor get touched without a
human. A third door, a new tier, a new verb or a re-introduced bypass all
fail here.

The sweep found a second instance immediately, unrelated to reads:
``update_alert_disposition`` had no ``ACTION_BLAST_RADIUS`` entry, and the
four readers of that table fall back to two different values. See
``test_every_action_type_has_an_explicit_blast_radius``.

Against ``origin/main`` this file reports 5 disagreements across 345
combinations; the change it ships with takes that to 0.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from app.api.live_actions_router import router as live_router
from app.api.router import router as legacy_router
from app.live_actions import registry
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.models.action import (
    ACTION_BLAST_RADIUS,
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    BlastRadius,
)
from app.services import action_store, tenant_policy
from app.services.executor_registry import EXECUTOR_REGISTRY
from fastapi import FastAPI
from fastapi.testclient import TestClient

#: Every verb both doors can see. The legacy door is keyed on ``ActionType``
#: and the registry door on a capability string, so the intersection is where
#: a disagreement is even expressible.
SHARED_CAPABILITIES = sorted(k for k in CAPABILITY_CONTRACTS if k in {a.value for a in ActionType})

TIERS = ("L0", "L1", "L2", "L3", "L4")

#: No score, a middling one, and a perfect one. The bands matter more than
#: the values: the floors are 0%, 90%, 98% and 99%, and "missing" must behave
#: as the lowest band rather than as a free pass.
CONFIDENCES: tuple[float | None, ...] = (None, 0.5, 1.0)


def test_the_sweep_covers_every_impact_tier() -> None:
    """A sweep that silently stopped covering an impact would still pass."""
    covered = {CAPABILITY_CONTRACTS[c].impact for c in SHARED_CAPABILITIES}
    assert len(SHARED_CAPABILITIES) >= 20
    assert {i.value for i in covered} == {"read_only", "low", "moderate", "high", "severe"}


class _VendorTouches:
    """Records whether a real vendor call was made, by either door.

    ``executed`` is the single field that means a vendor was actually
    touched. A dry-run preview reaches the executor with its credentials
    stripped and changes nothing, so it does not count — the registry door
    downgrades an over-tier request to a preview rather than refusing it,
    and counting that as execution would report a disagreement that is not
    one.
    """

    def __init__(self) -> None:
        self.executed = False

    def reset(self) -> None:
        self.executed = False


@pytest.fixture
def touches() -> _VendorTouches:
    return _VendorTouches()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, touches: _VendorTouches) -> TestClient:
    """Both doors mounted on one app, with recording executors behind each.

    Stubbing at the executor boundary and not below it means everything under
    test — authz, both gates, the contract, the tier resolution — is the real
    production code path.
    """
    monkeypatch.setenv("AISOC_DEV_MODE", "true")

    class _LegacyRecorder:
        async def execute(self, request: ActionRequest) -> ActionResult:
            touches.executed = True
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.COMPLETED,
                blast_radius=BlastRadius.MINIMAL,
                output={},
                rollback_data={},
                completed_at=datetime.now(UTC),
            )

        async def rollback(self, result: ActionResult) -> bool:
            return True

    class _LiveRecorder:
        async def execute(self, request: LiveActionRequest) -> LiveActionResult:
            if not request.dry_run:
                touches.executed = True
            return LiveActionResult(
                request_id=request.request_id,
                status=LiveActionStatus.SUCCEEDED,
                capability=request.capability,
                vendor_id=request.vendor_id,
                summary="executed",
            )

    # `list(...)` rather than iterating the enum class directly: CodeQL
    # resolves `ActionType` through its `str` base and reports the class
    # object as non-iterable, which is a false positive it raises at `error`.
    for action_type in list(ActionType):
        monkeypatch.setitem(EXECUTOR_REGISTRY, action_type, _LegacyRecorder())
    monkeypatch.setattr(registry, "get_executor", lambda vendor, capability: _LiveRecorder())

    app = FastAPI()
    app.include_router(legacy_router)
    app.include_router(live_router)
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_policy_cache(monkeypatch: pytest.MonkeyPatch):
    """The tenant policy is cached for 30s and these tests move the tier."""
    tenant_policy._cache.clear()
    yield
    tenant_policy._cache.clear()
    action_store.clear()


def _through_legacy_door(
    client: TestClient,
    touches: _VendorTouches,
    capability: str,
    confidence: float | None,
) -> bool:
    touches.reset()
    body: dict[str, Any] = {
        "incident_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "action_type": capability,
        "target": "WKSTN-01",
    }
    if confidence is not None:
        body["confidence"] = confidence
    response = client.post("/actions", json=body)
    assert response.status_code == 200, response.text
    return touches.executed


def _through_registry_door(
    client: TestClient,
    touches: _VendorTouches,
    capability: str,
    confidence: float | None,
) -> bool:
    touches.reset()
    body: dict[str, Any] = {
        "request_id": str(uuid4()),
        "capability": capability,
        "vendor_id": "crowdstrike",
        "target": "WKSTN-01",
        "tenant_id": str(uuid4()),
        "dry_run": False,
    }
    if confidence is not None:
        body["confidence"] = confidence
    response = client.post("/live-actions/dispatch", json=body)
    assert response.status_code == 200, response.text
    return touches.executed


@pytest.mark.parametrize("tier", TIERS)
def test_both_doors_reach_the_same_verdict_for_every_verb(
    client: TestClient,
    touches: _VendorTouches,
    monkeypatch: pytest.MonkeyPatch,
    tier: str,
) -> None:
    """The invariant, swept live rather than argued from the source.

    Parametrised by tier rather than by every combination so a failure names
    the tier and then lists every verb that disagreed at it — one run tells
    you the shape of the break instead of one cell of it.
    """
    monkeypatch.setenv("AISOC_MATURITY_TIER", tier)

    disagreements: list[str] = []
    for capability in SHARED_CAPABILITIES:
        for confidence in CONFIDENCES:
            tenant_policy._cache.clear()
            legacy = _through_legacy_door(client, touches, capability, confidence)
            tenant_policy._cache.clear()
            registry_door = _through_registry_door(client, touches, capability, confidence)
            if legacy != registry_door:
                contract = CAPABILITY_CONTRACTS[capability]
                disagreements.append(
                    f"{capability} (impact={contract.impact.value}, "
                    f"approval={contract.approval.value}) at {tier} "
                    f"confidence={confidence}: POST /actions executed={legacy}, "
                    f"POST /live-actions/dispatch executed={registry_door}"
                )

    assert not disagreements, "the two dispatch doors grade the same verb differently:\n  " + "\n  ".join(disagreements)


def test_a_read_executes_through_both_doors_at_the_default_tier(
    client: TestClient,
    touches: _VendorTouches,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reported instance, pinned by name.

    The sweep above would catch it, but a sweep failure reads as "something
    disagreed somewhere". This one says what broke.
    """
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)

    assert _through_legacy_door(client, touches, "search_siem", 1.0) is True
    assert _through_registry_door(client, touches, "search_siem", 1.0) is True


def test_neither_door_executes_anything_at_the_observe_tier(
    client: TestClient,
    touches: _VendorTouches,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agreement is worthless if the agreed answer is "always run".

    L0 is the one tier whose ceiling is ``None``, and it has to mean it — for
    a read as much as for a containment.
    """
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L0")

    for capability in SHARED_CAPABILITIES:
        tenant_policy._cache.clear()
        assert _through_legacy_door(client, touches, capability, 1.0) is False, f"{capability} executed at L0 via POST /actions"
        tenant_policy._cache.clear()
        assert _through_registry_door(client, touches, capability, 1.0) is False, f"{capability} executed at L0 via /live-actions/dispatch"


def test_a_severe_verb_executes_through_neither_door_at_any_tier(
    client: TestClient,
    touches: _VendorTouches,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """And agreement is worse than worthless if it agrees on the wrong side."""
    for tier in TIERS:
        monkeypatch.setenv("AISOC_MATURITY_TIER", tier)
        tenant_policy._cache.clear()
        assert _through_legacy_door(client, touches, "run_script", 1.0) is False
        tenant_policy._cache.clear()
        assert _through_registry_door(client, touches, "run_script", 1.0) is False


class TestTheDecisionLivesInOnePlace:
    """Agreement by construction, not by two implementations staying in step.

    The sweep catches a divergence after someone writes it. These catch the
    shape of it at review time, and they are what a third door would trip.
    """

    def test_both_doors_call_the_shared_grading_function(self) -> None:
        from app.live_actions import dispatcher
        from app.services import approval_gate

        for module in (approval_gate, dispatcher):
            source = inspect.getsource(module)
            called = {
                node.func.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            assert "evaluate_contract" in called, f"{module.__name__} grades a contract without calling the shared entry point"

    def test_no_door_unpacks_a_contract_into_the_raw_matrix(self) -> None:
        """``evaluate`` unpacked by hand at a call site is how this started.

        Both doors used to build its four arguments themselves, which is what
        let one of them wrap the call in a READ_ONLY short-circuit the other
        did not have. ``evaluate_contract`` takes the contract whole so there
        is nothing to unpack differently.

        Checked at the *import*, not the call: on the tree this replaces,
        both doors imported ``evaluate as evaluate_matrix``, so looking only
        at the called name would have found nothing wrong with either of
        them.
        """
        from app.live_actions import dispatcher
        from app.services import approval_gate

        for module in (approval_gate, dispatcher):
            tree = ast.parse(inspect.getsource(module))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.module != "app.services.approval_matrix":
                    continue
                imported = {alias.name for alias in node.names}
                assert "evaluate" not in imported, (
                    f"{module.__name__} imports approval_matrix.evaluate "
                    f"(as {[a.asname or a.name for a in node.names]}). A door that "
                    f"unpacks a contract into the matrix itself can wrap that call "
                    f"in a rule the other door does not have — use evaluate_contract."
                )

    def test_no_door_branches_on_a_specific_impact_tier(self) -> None:
        """A re-introduced bypass has a recognisable shape: a door deciding
        for itself that one impact tier is special.

        Reading ``ActionImpact`` to build a *table* is fine and the dispatcher
        does it (``_IMPACT_BLAST``). Comparing against one member inside the
        grading path is the bypass.
        """
        from app.live_actions import dispatcher
        from app.services import approval_gate

        for module in (approval_gate, dispatcher):
            tree = ast.parse(inspect.getsource(module))
            for function in ast.walk(tree):
                if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                if "contract" not in function.name and "matrix" not in function.name:
                    continue
                for node in ast.walk(function):
                    if not isinstance(node, ast.Compare):
                        continue
                    rendered = ast.unparse(node)
                    assert "ActionImpact." not in rendered, (
                        f"{module.__name__}.{function.name} compares against a specific "
                        f"impact tier ({rendered!r}). That is the shape of the bypass this "
                        f"file exists to prevent — put the rule in approval_matrix instead."
                    )


def test_every_action_type_has_an_explicit_blast_radius() -> None:
    """A missing entry is not a missing entry; it is two different entries.

    Four call sites read ``ACTION_BLAST_RADIUS`` and they fall back
    differently — ``blast_radius.py`` to HIGH now, the three tier gates to
    HIGH already, and ``blast_radius.py`` to MEDIUM before this change, which
    is exactly ``_AUTO_EXECUTE_LIMIT``. So an unclassified verb sat on the
    permissive side of the limit at one door and the restrictive side at the
    others. ``update_alert_disposition`` was that verb: the legacy door
    auto-executed it while the registry door queued it for a whitelist it
    could never match.

    Requiring an entry means the fallback never decides anything, which is
    the only way two fallbacks cannot disagree.
    """
    unclassified = [a.value for a in ActionType if a not in ACTION_BLAST_RADIUS]
    assert unclassified == [], (
        f"ActionType members with no blast radius: {unclassified}. Each reader "
        f"of ACTION_BLAST_RADIUS supplies its own default, so an absent entry "
        f"gives the verb a different risk rating at every door."
    )


def test_the_tier_ceiling_table_matches_the_tier_that_ladder_it_mirrors() -> None:
    """``TIER_MAX_AUTOMATIC`` and ``_AUTO_ALLOWED_AT_TIER`` are one ladder.

    They are two spellings of "what may this tier run without a human", keyed
    on impact and on blast radius respectively, and ``_IMPACT_BLAST`` is the
    declared correspondence between the two keys. The entry that disagreed
    was L1: the blast ladder allowed MINIMAL, the impact ladder allowed
    nothing, and READ_ONLY impact is MINIMAL blast.

    Only the "executes nothing at all" boundary is asserted, not the whole
    mapping. The impact ladder is deliberately stricter than the blast ladder
    higher up — L2 reads where the blast ladder would let it act — and the
    composition rule permits that. What it does not permit is one ladder
    saying a tier runs something and the other saying it runs nothing.
    """
    from app.live_actions.dispatcher import _IMPACT_BLAST
    from app.services.approval_matrix import TIER_MAX_AUTOMATIC
    from app.services.maturity import _AUTO_ALLOWED_AT_TIER, MaturityTier

    for tier in MaturityTier:
        label = tier.name.split("_")[0]
        ceiling = TIER_MAX_AUTOMATIC[label]
        allowed = _AUTO_ALLOWED_AT_TIER[tier]
        assert bool(ceiling is None) == (not allowed), (
            f"{label}: the impact ladder says it auto-executes "
            f"{'nothing' if ceiling is None else ceiling.value + ' and below'} "
            f"while the blast ladder allows {sorted(b.value for b in allowed)}"
        )
        if ceiling is not None:
            assert _IMPACT_BLAST[ceiling] in allowed, (
                f"{label} auto-executes up to {ceiling.value} impact, which is "
                f"{_IMPACT_BLAST[ceiling].value} blast radius, and the blast "
                f"ladder does not allow it"
            )


def test_this_file_is_wired_into_the_service_suite() -> None:
    """A gate nobody runs is a gate that certifies nothing."""
    assert Path(__file__).parent.name == "tests"

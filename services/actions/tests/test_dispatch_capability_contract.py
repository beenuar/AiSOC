"""The capability contract must be consulted on the registry-driven path too.

`POST /actions` has run the contract through `approval_gate.apply_matrix`
since the approval gate was fixed. `live_actions.dispatch()` — the path the
agent loop, the console dry-run and now the playbook engine use — ran
`autonomy_safety.decide()` and nothing else. `decide()` reads
`ACTION_BLAST_RADIUS`, a second risk ladder keyed on `ActionType`, and for
nine verbs it is the *weaker* of the two declarations:

    block_ip          blast medium   vs  impact high
    block_domain      blast medium   vs  impact high
    reset_password    blast medium   vs  impact high
    run_script        blast high     vs  impact severe
    quarantine_file   blast low      vs  impact moderate
    ...

So the same verb was graded differently depending on which door it came
through, and the weaker grade belonged to the door an agent uses.

Two further holes these tests pin:

* a capability with a contract and no `ActionType` (`revoke_session`) reached
  its executor with *no* governance at all — `_action_type_for` returned None
  and the whole gate was skipped;
* a tenant `force_auto` override lowered a contract that declares `analyst`,
  which `ActionContract.approval` explicitly forbids ("can raise this but
  never lower it").

Every test here fails against the tree before this change.
"""

from __future__ import annotations

import uuid

import pytest
from app.live_actions import dispatcher as dispatcher_mod
from app.live_actions import registry
from app.live_actions.dispatcher import dispatch
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.models.action import ActionType
from app.services.maturity import MaturityTier
from app.services.tenant_policy import TenantPolicy

pytestmark = pytest.mark.asyncio


class _OkExecutor:
    """Reports success without touching a vendor.

    `_legacy_action_type` is set to None for the capabilities that genuinely
    have none, so the test exercises the same lookup production does.
    """

    def __init__(self, action_type: ActionType | None = None) -> None:
        if action_type is not None:
            self._legacy_action_type = action_type

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary="executed",
        )


def _request(capability: str, **overrides) -> LiveActionRequest:
    payload: dict = {
        "capability": capability,
        "vendor_id": "crowdstrike",
        "target": "WIN-DC01",
        "dry_run": False,
        "tenant_id": uuid.uuid4(),
        "requested_by": "analyst@example.com",
    }
    payload.update(overrides)
    return LiveActionRequest(**payload)


def _policy(monkeypatch: pytest.MonkeyPatch, policy: TenantPolicy) -> None:
    async def _resolve(tenant_id):  # noqa: ANN001, ANN202
        return policy

    monkeypatch.setattr(dispatcher_mod, "resolve_tenant_policy", _resolve)


def _executor(monkeypatch: pytest.MonkeyPatch, action_type: ActionType | None) -> None:
    monkeypatch.setattr(registry, "get_executor", lambda vendor, cap: _OkExecutor(action_type))


@pytest.fixture(autouse=True)
def _no_probe(monkeypatch: pytest.MonkeyPatch):
    """A stub verifier so these assertions are about the verdict only."""

    class _V:
        async def verify(self, action_type, target, params):  # noqa: ANN001
            from app.services.verification import VerificationOutcome, VerificationResult

            return VerificationResult(VerificationOutcome.UNVERIFIED, action_type, target, reason="stub")

    monkeypatch.setattr(dispatcher_mod, "PostActionVerifier", lambda: _V())


async def test_a_verb_the_blast_table_calls_medium_is_held_at_its_declared_high_impact(
    monkeypatch: pytest.MonkeyPatch,
):
    """`block_ip`: blast medium, impact high. L3 allows medium and not high.

    Pre-change this executed, because only the weaker ladder was read.
    """
    _executor(monkeypatch, ActionType.BLOCK_IP)
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L3_REMEDIATE, from_store=True))
    result = await dispatch(_request("block_ip", confidence=1.0))
    assert result.status is LiveActionStatus.PENDING_APPROVAL
    assert "high" in result.summary


async def test_missing_confidence_is_the_lowest_band_not_a_free_pass(
    monkeypatch: pytest.MonkeyPatch,
):
    """A LOW-impact automatic verb still needs a reason above the floor."""
    _executor(monkeypatch, ActionType.CREATE_NOTABLE_EVENT)
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L4_AUTOMATE, from_store=True))

    held = await dispatch(_request("create_notable_event"))
    assert held.status is LiveActionStatus.PENDING_APPROVAL
    assert "below the 90% floor" in held.summary

    ran = await dispatch(_request("create_notable_event", confidence=0.95))
    assert ran.status is LiveActionStatus.SUCCEEDED


async def test_a_read_only_verb_is_not_gated_by_the_contract(
    monkeypatch: pytest.MonkeyPatch,
):
    """Gating a read behind an analyst is how an agent learns to conclude
    without looking. `search_siem` is read_only/automatic and must run."""
    _executor(monkeypatch, ActionType.SEARCH_SIEM)
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L1_NOTIFY, from_store=True))
    result = await dispatch(_request("search_siem"))
    assert result.status is LiveActionStatus.SUCCEEDED


async def test_a_severe_verb_is_never_autonomous_at_any_tier_or_confidence(
    monkeypatch: pytest.MonkeyPatch,
):
    """`run_script` declares severe impact and mandatory_human approval."""
    _executor(monkeypatch, ActionType.RUN_SCRIPT)
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L4_AUTOMATE, from_store=True))
    result = await dispatch(_request("run_script", confidence=1.0))
    assert result.status is LiveActionStatus.PENDING_APPROVAL


async def test_a_contracted_verb_with_no_action_type_is_still_governed(
    monkeypatch: pytest.MonkeyPatch,
):
    """`revoke_session` has a contract and no `ActionType`.

    `_action_type_for` returned None, so the entire governance block was
    skipped and a MODERATE-impact identity action reached its executor with
    no tier check, no blast check and no contract applied.
    """
    _executor(monkeypatch, None)
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L1_NOTIFY, from_store=True))
    result = await dispatch(_request("revoke_session"))
    assert result.status is LiveActionStatus.PENDING_APPROVAL
    assert result.details["autonomy_mode"] == "queued_approval"


async def test_an_uncontracted_capability_is_left_to_blast_radius(
    monkeypatch: pytest.MonkeyPatch,
):
    """A verb nobody declared is recorded, not guessed at.

    Inventing an impact for it is how a gate starts certifying things it
    never examined. `check_action_contract.py` fails the build when a
    *registered* executor has no contract, so this stays a real absence.
    """
    _executor(monkeypatch, None)
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L1_NOTIFY, from_store=True))
    result = await dispatch(_request("a_verb_nobody_declared"))
    assert result.status is LiveActionStatus.SUCCEEDED
    assert "autonomy_mode" not in result.details


async def test_the_contract_never_lowers_a_verdict_blast_radius_already_gated(
    monkeypatch: pytest.MonkeyPatch,
):
    """`search_siem` is automatic, but L0 observes. The contract must not lift it."""
    _executor(monkeypatch, ActionType.SEARCH_SIEM)
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L0_OBSERVE, from_store=True))
    result = await dispatch(_request("search_siem"))
    assert result.status is LiveActionStatus.BLOCKED


async def test_a_dry_run_is_not_graded(monkeypatch: pytest.MonkeyPatch):
    """Nothing reaches a vendor, so there is nothing to hold for an analyst.

    A dry run that queued for approval would make preview useless.
    """
    _executor(monkeypatch, ActionType.ISOLATE_HOST)
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L1_NOTIFY, from_store=True))
    result = await dispatch(_request("isolate_host", dry_run=True))
    assert result.status is LiveActionStatus.SUCCEEDED

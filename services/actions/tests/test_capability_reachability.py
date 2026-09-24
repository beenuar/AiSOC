"""An executor and the registries that make it reachable must agree, both ways.

Four things have to line up before a verb can be dispatched under governance:
the legacy ``ActionType`` executor, the live-action adapter, the capability
contract, and the capability vocabulary. Nothing compared them, so a verb could
be complete in three of the four and unreachable.

``ack_alert`` and ``suppress_alert`` were exactly that — real executors with
Splunk, Elastic and Defender arms, wired into ``EXECUTOR_REGISTRY``, and absent
from the adapters, the contracts and the vocabulary. Governed dispatch answered
``executor_not_found`` for code that worked, which reads as a misconfigured
integration rather than a capability nobody connected.

The tests below assert both directions of every comparison. A one-directional
version would have passed on all of this: the drift is in the direction nothing
was looking, which is what the graph-schema check demonstrated when it reported
OK with 17 labels declared and 28 implemented.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from app.live_actions import builtins, registry
from app.live_actions.capabilities import KNOWN_CAPABILITIES
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.models.action import ActionType
from app.services.executor_registry import EXECUTOR_REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[3]
GATE = REPO_ROOT / "scripts" / "check_action_contract.py"

# The gate owns the exemption baselines; the tests read them from there rather
# than restating them, so a second copy cannot drift from the enforced one.
sys.path.insert(0, str(REPO_ROOT / "scripts"))

ADAPTERS = builtins._BUILTIN_ADAPTERS  # noqa: SLF001

#: Adapters that bridge to a legacy ``ActionType`` executor. The read-only
#: investigation verbs and the vendor-breadth executors are native
#: ``LiveActionExecutor`` implementations with no legacy counterpart, so the
#: ActionType comparisons below do not apply to them.
BRIDGING_ADAPTERS = [cls for cls in ADAPTERS if getattr(cls, "_legacy_action_type", None) is not None]


@pytest.fixture(autouse=True)
def _registered() -> None:
    registry.reset_for_tests()
    builtins.register_builtin_executors(overwrite=True)


@pytest.mark.parametrize("capability", ["ack_alert", "suppress_alert"])
@pytest.mark.parametrize("vendor", ["splunk", "elastic", "defender"])
def test_alert_lifecycle_verbs_resolve_through_governed_dispatch(vendor: str, capability: str) -> None:
    """The regression. Every one of these six returned None before this change."""
    assert registry.get_executor(vendor, capability) is not None, (
        f"{vendor}/{capability} does not resolve, so dispatcher.dispatch answers "
        f"executor_not_found for an executor that has a working {vendor} arm."
    )


@pytest.mark.parametrize("capability", sorted({cls.capability for cls in ADAPTERS}))
def test_every_implemented_capability_is_in_the_vocabulary(capability: str) -> None:
    """Direction the mirror check never ran.

    ``check_capability_mirror`` compares the connectors enum against the
    actions mirror in both directions and neither against the executors, which
    is how ``create_ticket`` and ``notify`` came to be registered, contracted
    and dispatchable while absent from the vocabulary they are validated
    against — four executors logging ``capability_unknown`` at every startup.
    """
    assert capability in KNOWN_CAPABILITIES


@pytest.mark.parametrize("capability", sorted({cls.capability for cls in ADAPTERS}))
def test_every_implemented_capability_has_a_contract(capability: str) -> None:
    detail = f"{capability} is dispatchable and nothing declares its impact, reversibility, verification or approval tier."
    assert capability in CAPABILITY_CONTRACTS, detail


def test_every_legacy_executor_is_reachable_or_explicitly_exempt() -> None:
    """Direction 4: a legacy executor with no adapter is ungoverned.

    The ActionType REST route has no capability contract, no approval matrix
    and no autonomy policy in front of it, so an executor reachable only that
    way bypasses every control the contract system exists to apply.
    """
    from check_action_contract import KNOWN_UNGOVERNED_EXECUTORS

    reachable = {cls._legacy_action_type for cls in BRIDGING_ADAPTERS}
    unreachable = {at.value for at in EXECUTOR_REGISTRY if at not in reachable}
    assert unreachable <= set(KNOWN_UNGOVERNED_EXECUTORS), (
        f"{sorted(unreachable - set(KNOWN_UNGOVERNED_EXECUTORS))} have executors that "
        f"governed dispatch cannot reach and no recorded reason."
    )


def test_every_adapter_delegates_to_an_executor_that_exists() -> None:
    """Direction 5, the mirror of the above: the failure would be at execute()."""
    for cls in BRIDGING_ADAPTERS:
        action_type = cls._legacy_action_type
        assert action_type in EXECUTOR_REGISTRY, f"{cls.__name__} delegates to {action_type} and EXECUTOR_REGISTRY has no executor for it"


def test_exemption_lists_only_ever_shrink() -> None:
    """A baseline is where the next one hides if nothing prunes it."""
    from check_action_contract import (
        KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR,
        KNOWN_UNGOVERNED_EXECUTORS,
    )

    reachable = {cls._legacy_action_type for cls in BRIDGING_ADAPTERS}
    assert not (set(KNOWN_UNGOVERNED_EXECUTORS) & {at.value for at in reachable})
    assert not (set(KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR) & {at.value for at in EXECUTOR_REGISTRY})

    # Every exemption carries a reason, because "why is this here" is the
    # question a stale baseline cannot answer.
    for reason in (*KNOWN_UNGOVERNED_EXECUTORS.values(), *KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR.values()):
        assert len(reason.strip()) > 40


def test_both_exemption_baselines_are_empty() -> None:
    """The ratchet's floor, asserted rather than assumed.

    Both lists held entries and both are now empty: ``capture_forensics``
    gained a Defender arm, ``chatops_verify`` gained the status its honest
    result needed, and ``add_ioc_to_blocklist`` / ``run_playbook`` left the
    ``ActionType`` surface because neither had an implementation path. The
    previous form of this test compared the lists against reality and passed
    vacuously once they were empty, so it could not notice a new entry being
    added. This can: a verb may only be exempted by editing this assertion,
    which is a reviewable act rather than a quiet append.
    """
    from check_action_contract import (
        KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR,
        KNOWN_UNGOVERNED_EXECUTORS,
    )

    assert KNOWN_UNGOVERNED_EXECUTORS == {}
    assert KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR == {}


def test_every_action_type_has_an_executor() -> None:
    """No exemptions left, so this is the whole claim.

    The API accepts any ``ActionType`` and then answers "No executor found for
    action type" for one with nothing behind it, which reads as a broken
    deployment rather than a verb nobody built.
    """
    missing = sorted(at.value for at in ActionType if at not in EXECUTOR_REGISTRY)
    assert missing == [], f"{missing} are accepted by the action API and dispatch to nothing"


def test_every_legacy_executor_is_reachable_through_governed_dispatch() -> None:
    """Likewise: nothing is reachable only through the ungoverned route."""
    reachable = {cls._legacy_action_type for cls in BRIDGING_ADAPTERS}
    unreachable = sorted(at.value for at in EXECUTOR_REGISTRY if at not in reachable)
    assert unreachable == [], f"{unreachable} work and governed dispatch answers executor_not_found for them"


def test_the_agent_proposes_only_verbs_this_service_can_execute() -> None:
    """The fifth registry: what the agent recommends to a human.

    ``investigation_agent`` proposes ``capture_forensics`` on the C2 /
    exfiltration path with ``requires_approval=True``, and no executor
    implemented it — so the product raised an approval for evidence
    acquisition on its most serious incidents and failed on approval. The
    other five directions compare the actions service against itself; this is
    the one that compares it against the thing that puts a verb in front of a
    person.
    """
    from check_action_contract import _proposed_action_verbs

    proposed = _proposed_action_verbs()
    assert proposed, "found no ProposedAction call sites; the parser has drifted from the agents package"

    executable = {action.value for action in EXECUTOR_REGISTRY}
    dead = {verb: locations for verb, locations in proposed.items() if verb not in executable}
    assert dead == {}, f"the agent recommends verbs that dispatch to nothing: {dead}"


def _run_gate() -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(GATE)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def test_the_gate_passes_on_the_tree_as_committed() -> None:
    result = _run_gate()
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("drift", "expected"),
    [
        # Remove a verb from the vocabulary while its executors stay: the
        # direction check_capability_mirror covers.
        ("vocabulary", "absent from KNOWN_CAPABILITIES"),
        # Remove an adapter while the legacy executor stays: the direction
        # nothing covered, and the one ack_alert drifted in.
        ("adapter", "no live-action adapter reaches it"),
        # Remove the contract while the adapter stays.
        ("contract", "no capability contract declares"),
        # Remove the executor for a verb the agent proposes by name: the
        # direction that spans two services, and the one capture_forensics
        # drifted in for as long as it existed.
        ("agent_proposal", "Implement the verb or stop proposing it"),
    ],
)
def test_the_gate_fails_when_drift_is_introduced_in_each_direction(tmp_path: Path, drift: str, expected: str) -> None:
    """The gate has to fail for the right reason, not merely fail.

    A check that only ever runs green is indistinguishable from one that does
    nothing, so each direction is driven by removing exactly one registration
    and asserting the message names it.
    """
    script = {
        "vocabulary": (
            "import app.live_actions.capabilities as caps\n"
            "caps.KNOWN_CAPABILITIES = frozenset(c for c in caps.KNOWN_CAPABILITIES if c != 'ack_alert')\n"
        ),
        "adapter": (
            "import app.live_actions.builtins as b\n"
            "b._BUILTIN_ADAPTERS = tuple(c for c in b._BUILTIN_ADAPTERS if c.capability != 'ack_alert')\n"
        ),
        "contract": "import app.live_actions.capability_contracts as cc\ncc.CAPABILITY_CONTRACTS.pop('ack_alert', None)\n",
        # The adapter goes too, otherwise direction 5 fires first and the
        # assertion would pass on the wrong message.
        "agent_proposal": (
            "import app.services.executor_registry as er\n"
            "import app.models.action as ma\n"
            "import app.live_actions.builtins as b\n"
            "er.EXECUTOR_REGISTRY.pop(ma.ActionType.CAPTURE_FORENSICS, None)\n"
            "b._BUILTIN_ADAPTERS = tuple(c for c in b._BUILTIN_ADAPTERS if c.capability != 'capture_forensics')\n"
        ),
    }[drift]

    driver = tmp_path / "drive.py"
    driver.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT / 'services' / 'actions')!r})\n"
        f"sys.path.insert(0, {str(REPO_ROOT / 'scripts')!r})\n"
        f"{script}"
        "import check_action_contract as gate\n"
        "raise SystemExit(gate.main([]))\n",
        encoding="utf-8",
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(driver)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 1, f"the gate passed with {drift} drift injected:\n{result.stdout}"
    assert expected in result.stderr, result.stderr

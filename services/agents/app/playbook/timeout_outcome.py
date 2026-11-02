"""What an approval step does when its deadline passes.

Wave-2 Phase 6.3. ``pause.expire_due`` marks a waiting pause ``expired``
and logs it, which is honest as far as it goes and is the only outcome the
product has. Every approval therefore behaves identically at its deadline:
the action does not happen, and nothing else happens either.

For some steps that is right. For the step that isolates a host believed to
be exfiltrating, "nobody answered, so we did nothing" is a decision nobody
made on purpose. For a step that sits after an action already taken, the
right answer may be to undo it rather than leave the estate half-changed.

So the step declares its own deadline behaviour:

``stay_paused``
    The existing behaviour, now chosen rather than implied.

``rollback``
    Reverse what this run already did, through the platform rollback path,
    and record that the deadline caused it.

``contain``
    Run one **named** limited containment verb.

Why ``contain`` is safe to offer
--------------------------------
Two guard rails, and the second is the load-bearing one.

The verb is named in the playbook, so a timeout cannot run something the
author did not write down — there is no "escalate to whatever is most
appropriate".

And it is dispatched through the ordinary governed path, so it is graded by
its own capability contract exactly like any other action. **A timeout is
not a tier promotion.** A verb the tenant's autonomy tier would not
auto-execute does not auto-execute here either; it queues, and the operator
who eventually looks sees an action waiting rather than an action taken.
That is the property that stops "declare a timeout containment" from being
a way to route around the approval you just failed to get.

Validation happens when the playbook is saved, not at the deadline. A verb
that does not resolve should fail while somebody is reading the playbook,
not three hours into an incident.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("aisoc.playbook.timeout_outcome")

STAY_PAUSED = "stay_paused"
ROLLBACK = "rollback"
CONTAIN = "contain"

VALID_OUTCOMES = frozenset({STAY_PAUSED, ROLLBACK, CONTAIN})


class TimeoutOutcomeError(ValueError):
    """The declared timeout outcome is not runnable. Raised at validation."""


@dataclass(frozen=True)
class TimeoutOutcome:
    """A validated deadline behaviour for one approval step."""

    outcome: str = STAY_PAUSED
    capability: str = ""
    target: str = ""
    params: dict[str, Any] | None = None
    #: Whether the capability name was checked against the contract
    #: vocabulary at validation time. ``False`` means this image could not
    #: read it, not that the check failed — see ``validate_timeout_outcome``.
    verified: bool = True

    @property
    def is_default(self) -> bool:
        return self.outcome == STAY_PAUSED

    def to_row(self) -> dict[str, Any]:
        """The three columns migration 143 adds to a pause row."""
        return {
            "timeout_outcome": self.outcome,
            "timeout_capability": self.capability or None,
            "timeout_params": {**(self.params or {}), **({"target": self.target} if self.target else {})},
        }


def graded_capabilities() -> set[str]:
    """Verbs with a capability contract that are not read-only.

    Read from the contract rather than from a list here, so a verb added to
    the product is offerable as a timeout containment without a second
    edit, and a verb removed stops being offerable without one either.

    Returns an empty set when the contract module is unavailable — which is
    the case in the agents image, where the contracts live in another
    service. ``validate_timeout_outcome`` treats that as "cannot check" and
    says so, rather than silently accepting any string.
    """
    try:
        from app._vendor.action_contracts.capability_contracts import (  # noqa: PLC0415 - optional across service images
            CAPABILITY_CONTRACTS,
        )
    except Exception:  # noqa: BLE001
        return set()
    return {name for name, contract in CAPABILITY_CONTRACTS.items() if contract.impact.value != "read_only"}


def validate_timeout_outcome(params: dict[str, Any], *, known_verbs: set[str] | None = None) -> TimeoutOutcome:
    """Read and check an approval step's declared deadline behaviour.

    ``known_verbs`` is injectable so the caller supplies the vocabulary it
    can actually see. ``None`` asks this module to look, and an empty result
    means the check could not be made — which is reported rather than
    treated as a pass.
    """
    raw = params.get("timeout_outcome")
    if raw in (None, ""):
        return TimeoutOutcome()

    outcome = str(raw).strip()
    if outcome not in VALID_OUTCOMES:
        raise TimeoutOutcomeError(f"timeout_outcome {outcome!r} is not one of {sorted(VALID_OUTCOMES)}")

    if outcome != CONTAIN:
        if params.get("timeout_capability"):
            raise TimeoutOutcomeError(
                f"timeout_capability is declared but timeout_outcome is {outcome!r}; the verb would never be dispatched"
            )
        return TimeoutOutcome(outcome=outcome)

    capability = str(params.get("timeout_capability") or "").strip()
    if not capability:
        raise TimeoutOutcomeError(
            "timeout_outcome 'contain' needs a 'timeout_capability'. A timeout "
            "that escalates to whatever seems appropriate is not a declared "
            "outcome, it is an undeclared one with a name."
        )

    verbs = graded_capabilities() if known_verbs is None else known_verbs
    if verbs and capability not in verbs:
        raise TimeoutOutcomeError(
            f"{capability!r} is not a graded verb. A timeout containment must "
            f"be a capability with a contract declaring what it does when the "
            f"finding is wrong; read-only verbs are excluded because a timeout "
            f"that runs a search has not contained anything."
        )

    return TimeoutOutcome(
        outcome=CONTAIN,
        capability=capability,
        target=str(params.get("timeout_target") or ""),
        params=dict(params.get("timeout_params") or {}),
        # False means this image could not read the contract vocabulary, not
        # that the verb failed a check. The *authority* on whether a verb is
        # graded is the governed dispatch path, which refuses one it cannot
        # resolve; this flag says whether the author also got told early.
        # Recorded rather than silently treated as a pass, because an
        # unknown bucket that passes is the defect this codebase keeps
        # finding in its own gates.
        verified=bool(verbs),
    )

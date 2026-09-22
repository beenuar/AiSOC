"""The action contract: what every response action must declare about itself.

Pillar 3. An action registry is only as good as what it can tell you *before*
it runs. Today an executor declares four things — vendor, capability, whether
it needs credentials, and a description — and everything that actually
governs execution is inferred elsewhere or not at all:

* risk is inferred from the capability name in one place and from a policy
  table in another, and the two can disagree
* reversibility is not declared, so the rollback path has a hardcoded list of
  four actions and nothing tells you whether a fifth is reversible
* verification is not declared, so an action reports success on an HTTP 200
  and nobody knows whether a probe exists to check the effect landed
* nothing distinguishes "needs approval" from "no tier may ever auto-execute
  this"

This module makes all of it declarative, and
``scripts/check_action_contract.py`` makes it enforced. The point is not
tidiness: the gap between "the API returned 200" and "the host is actually
contained" is how a SOC comes to believe it responded when it did not.

Adding a field here is a breaking change for every executor, which is
deliberate. An action that cannot say what it does to a production estate
should not be dispatchable.
"""

from __future__ import annotations

from enum import Enum


class ActionImpact(str, Enum):
    """What this action does to the estate if it is wrong.

    Impact is a property of the action, not of the confidence in the
    finding. The two are combined by the approval matrix; conflating them is
    how "we were 99% sure" becomes justification for an irreversible action.
    """

    #: Reads only. No state changes anywhere.
    READ_ONLY = "read_only"

    #: Changes state, trivially undone, no user-visible disruption.
    #: Blocking a known-bad hash; adding a watchlist entry.
    LOW = "low"

    #: Disrupts one user or one process. Reversible in seconds.
    #: Killing a process; revoking a session.
    MODERATE = "moderate"

    #: Disrupts one person's ability to work, or one host's connectivity.
    #: Reversible, but someone notices immediately.
    #: Disabling an account; isolating a workstation.
    HIGH = "high"

    #: Disrupts a service other people depend on. Reversible in principle,
    #: but the outage is real while it lasts.
    #: Isolating a production server; blocking a shared egress address.
    SEVERE = "severe"

    #: Cannot be undone. Deleting a resource; rotating a key whose old value
    #: is gone. No autonomy tier may execute these, ever.
    IRREVERSIBLE = "irreversible"


class ApprovalRequirement(str, Enum):
    """Who, if anyone, must sign off before this executes."""

    #: Safe to run without asking, subject to the tenant's autonomy tier.
    AUTOMATIC = "automatic"

    #: Requires an analyst approval, recorded with the approving principal.
    ANALYST = "analyst"

    #: Requires a human regardless of confidence or tier. Not "a high bar" —
    #: an actual floor that autonomy cannot lift.
    MANDATORY_HUMAN = "mandatory_human"

    #: No path executes this from the platform. Present in the vocabulary so
    #: an action can be *declared* prohibited rather than merely unimplemented,
    #: which is the difference between a control and an absence.
    PROHIBITED = "prohibited"


#: Impact tiers that no autonomy level may auto-execute, whatever the
#: confidence. Kept as data rather than an `if` so the gate can assert it.
NEVER_AUTONOMOUS: frozenset[ActionImpact] = frozenset({ActionImpact.SEVERE, ActionImpact.IRREVERSIBLE})


class Reversal(str, Enum):
    """How the effect of an action is undone, if it can be.

    "Reversible" is not one thing, and collapsing it into a boolean forces
    wrong answers. Killing a process cannot be un-killed, but the effect does
    not persist — the service restarts, or the user runs the program again.
    Isolating a host persists until something un-isolates it. Those need
    different handling and a different conversation with an approver.
    """

    #: Nothing to undo; the action changed no state.
    NOT_APPLICABLE = "not_applicable"

    #: The platform can undo it by dispatching ``reverse_capability``.
    PLATFORM = "platform"

    #: The effect does not persist: a killed process can be restarted, a
    #: cleared session can be re-established by logging in. Disruptive at the
    #: moment it happens, gone shortly after, with no operator action needed.
    SELF_HEALING = "self_healing"

    #: Persists and the platform cannot undo it. An operator has to undo it
    #: by hand, during an incident, from a runbook they have not read.
    MANUAL_ONLY = "manual_only"

    #: Cannot be undone by anyone.
    NONE = "none"


#: Impact tiers that must declare *some* route back. Not necessarily a
#: platform reverse: self-healing is an honest answer for a killed process.
#: MANUAL_ONLY at these tiers is what the gate rejects, because an action
#: that disrupts a person or a service and leaves no route back is one
#: somebody has to fix by hand at 3am.
MUST_HAVE_A_ROUTE_BACK: frozenset[ActionImpact] = frozenset({ActionImpact.MODERATE, ActionImpact.HIGH, ActionImpact.SEVERE})

#: Backwards-compatible alias; the gate imports this name.
MUST_BE_REVERSIBLE = MUST_HAVE_A_ROUTE_BACK


_IMPACT_ORDER: tuple[ActionImpact, ...] = (
    ActionImpact.READ_ONLY,
    ActionImpact.LOW,
    ActionImpact.MODERATE,
    ActionImpact.HIGH,
    ActionImpact.SEVERE,
    ActionImpact.IRREVERSIBLE,
)


def _impact_rank(impact: ActionImpact) -> int:
    return _IMPACT_ORDER.index(impact)


class ActionContract:
    """Declarative contract mixed into every ``LiveActionExecutor``.

    Every field has a deliberately unsafe default. An executor that forgets
    to declare its impact is treated as irreversible and prohibited, so the
    omission fails closed and the conformance gate names it — rather than the
    action quietly defaulting to "safe to auto-execute".
    """

    #: What this does to the estate if the finding is wrong.
    impact: ActionImpact = ActionImpact.IRREVERSIBLE

    #: Baseline approval requirement. The tenant's autonomy policy and the
    #: confidence matrix can raise this but never lower it.
    approval: ApprovalRequirement = ApprovalRequirement.PROHIBITED

    #: JSON schema for ``LiveActionRequest.params``. Used to validate before
    #: dispatch and to render the approval UI, so an approver sees what they
    #: are approving rather than an opaque dict.
    parameters_schema: dict = {}  # noqa: RUF012 - overridden per executor

    #: RBAC permission the invoking principal must hold. Enforced by the
    #: dispatcher; declared here so the gate can assert every state-changing
    #: action has one.
    required_permission: str = ""

    #: How the effect is undone. Defaults to NONE so an undeclared action
    #: fails closed.
    reversal: Reversal = Reversal.NONE

    #: Capability that undoes this one, e.g. ``unisolate_host`` for
    #: ``isolate_host``. Required when and only when ``reversal`` is PLATFORM.
    reverse_capability: str = ""

    #: Whether a post-action probe exists that reads the vendor's state to
    #: confirm the effect landed. Without one, "succeeded" means "the API
    #: accepted the request", which is not the same claim.
    has_verification_probe: bool = False

    #: Why no probe exists, for an action disruptive enough to need one.
    #: Required when a HIGH or SEVERE action declares no probe, so the
    #: absence is a recorded decision rather than an omission nobody
    #: noticed. Some vendors genuinely expose no read-back; that is an
    #: acceptable answer and an unacceptable silence.
    verification_gap: str = ""

    #: Whether ``execute()`` honours ``dry_run`` by making no state change.
    #: Declared rather than assumed because a dry run that still calls the
    #: vendor has happened here before.
    supports_dry_run: bool = True

    @classmethod
    def contract_violations(cls) -> list[str]:
        """Self-check. Returns the ways this declaration is inconsistent.

        Called by the conformance gate for every registered executor, and
        usable directly in a plugin author's own tests.
        """
        problems: list[str] = []
        impact = cls.impact
        approval = cls.approval

        if impact == ActionImpact.READ_ONLY:
            # A read that requires approval is either mis-classified or is
            # not actually a read.
            if approval in (ApprovalRequirement.MANDATORY_HUMAN, ApprovalRequirement.PROHIBITED):
                problems.append(
                    f"impact is read_only but approval is {approval.value}; " f"a read that nobody may perform is mis-classified"
                )
            return problems

        if not cls.required_permission:
            problems.append("state-changing action declares no required_permission, so the " "dispatcher has nothing to authorise against")

        # The route-back requirement exists to bound *autonomous* damage. An
        # action a human must personally approve is one where the approver is
        # accepting the irreversibility knowingly, which is a legitimate
        # declared posture — running an RTR script is the example. Actions
        # that can execute without a human still need a way back.
        human_gated = approval in (
            ApprovalRequirement.MANDATORY_HUMAN,
            ApprovalRequirement.PROHIBITED,
        )

        if (
            impact in MUST_HAVE_A_ROUTE_BACK
            and not human_gated
            and cls.reversal in (Reversal.NONE, Reversal.MANUAL_ONLY, Reversal.NOT_APPLICABLE)
        ):
            problems.append(
                f"impact is {impact.value} but reversal is {cls.reversal.value}; "
                f"an action that disrupts a person or a service must either be "
                f"undoable by the platform or self-healing, otherwise somebody "
                f"undoes it by hand during an incident"
            )

        if cls.reversal == Reversal.PLATFORM and not cls.reverse_capability:
            problems.append("reversal is 'platform' but no reverse_capability is named, so the " "rollback path has nothing to dispatch")

        if cls.reversal != Reversal.PLATFORM and cls.reverse_capability:
            problems.append(
                f"reverse_capability {cls.reverse_capability!r} is declared but "
                f"reversal is {cls.reversal.value}; the rollback path would not use it"
            )

        if impact in NEVER_AUTONOMOUS and approval == ApprovalRequirement.AUTOMATIC:
            problems.append(
                f"impact is {impact.value} but approval is automatic; no autonomy " f"tier may auto-execute this regardless of confidence"
            )

        # A probe is required wherever the effect is mechanically checkable.
        # It is waived only for a human-gated action whose effect is not — you
        # cannot probe whether an arbitrary script did the right thing, and the
        # human who approved it is watching. HIGH impact is never waived: that
        # is the containment tier, where believing a host is contained when it
        # is not is the specific failure this contract exists to prevent.
        # An action that can execute without a human *and* disrupts something
        # must be verifiable: nothing else is checking, so "the API returned
        # 200" becomes the whole of the evidence.
        #
        # Scoped to MODERATE and above on purpose. Creating a ticket or
        # posting a message returns the created object's id, so the response
        # genuinely is the confirmation — demanding a second read there would
        # be ceremony, and a rule that fires on cases nobody can act on is a
        # rule people learn to suppress.
        if (
            approval == ApprovalRequirement.AUTOMATIC
            and _impact_rank(impact) >= _impact_rank(ActionImpact.MODERATE)
            and not cls.has_verification_probe
        ):
            # Unverifiable means not autonomous. A verification_gap explains
            # why no probe exists; it does not buy back the right to execute
            # without anyone checking. Downgrade the action to analyst
            # approval and the contract is coherent again.
            problems.append(
                "approval is automatic at "
                f"{impact.value} impact with no verification probe. Nothing would "
                "check the effect, so the action certifies itself. Either add a "
                "probe or require analyst approval — an unverifiable action is not "
                "an autonomous one, whatever the confidence."
            )

        # For the containment tiers, an absent probe is allowed but must be
        # explained. Some vendors genuinely expose no read-back — that is an
        # acceptable answer. Silence is not, because an omission and a
        # deliberate decision look identical afterwards, and this is the
        # claim the whole contract exists to make trustworthy.
        if impact in (ActionImpact.HIGH, ActionImpact.SEVERE) and not cls.has_verification_probe and not cls.verification_gap.strip():
            problems.append(
                f"impact is {impact.value} and no verification probe is declared, "
                f"with no verification_gap explaining why. The action would report "
                f"success on an accepted request with nothing checking the effect — "
                f"which is how a SOC comes to believe a host is contained when it is "
                f"not. State the reason if the vendor offers no read-back."
            )

        if not cls.supports_dry_run and approval != ApprovalRequirement.PROHIBITED:
            problems.append("action does not support dry_run, so it cannot be previewed or " "exercised in copilot mode")

        if cls.parameters_schema and not isinstance(cls.parameters_schema, dict):
            problems.append("parameters_schema must be a JSON-schema object")

        return problems

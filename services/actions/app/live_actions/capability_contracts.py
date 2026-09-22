"""Contract per capability, not per vendor.

What an action does to an estate is a property of the verb. Isolating a host
is equally disruptive on CrowdStrike, Defender and SentinelOne, so declaring
it three times invites the three to drift — and the one that drifts low is
the one that auto-executes.

Adding a vendor for an existing verb therefore inherits the classification
automatically. Adding a *new verb* requires an entry here, which the
conformance gate enforces, so a capability cannot reach dispatch without
somebody having decided what it does when the finding is wrong.

The classifications below are deliberately conservative. The cost of an
unnecessary approval is a few minutes of analyst time. The cost of a wrong
autonomous containment is an outage plus the organisational trust needed to
ever enable autonomy again, and that second one does not come back.
"""

from __future__ import annotations

from dataclasses import dataclass

from .contract import ActionImpact, ApprovalRequirement, Reversal


@dataclass(frozen=True)
class CapabilityContract:
    impact: ActionImpact
    approval: ApprovalRequirement
    reversal: Reversal
    required_permission: str
    reverse_capability: str = ""
    has_verification_probe: bool = False
    note: str = ""


_READ = "actions:read"
_CONTAIN = "actions:contain"
_IDENTITY = "actions:identity"
_NETWORK = "actions:network"
_TICKET = "actions:ticket"

CAPABILITY_CONTRACTS: dict[str, CapabilityContract] = {
    # ── Read-only ──────────────────────────────────────────────────────────
    "search_siem": CapabilityContract(
        impact=ActionImpact.READ_ONLY,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.NOT_APPLICABLE,
        required_permission=_READ,
        note="A query. Safe at any confidence, which is the point of separating impact from confidence.",
    ),
    # ── Endpoint containment ───────────────────────────────────────────────
    "isolate_host": CapabilityContract(
        impact=ActionImpact.HIGH,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="unisolate_host",
        required_permission=_CONTAIN,
        has_verification_probe=True,
        note=(
            "Cuts one machine off the network. Reversible, but somebody notices "
            "immediately. The verification probe matters more here than anywhere: "
            "believing a host is contained when it is not is the failure this "
            "whole contract exists to prevent."
        ),
    ),
    "unisolate_host": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="isolate_host",
        required_permission=_CONTAIN,
        has_verification_probe=True,
        note="Restoring connectivity is itself a decision; it needs the same approval.",
    ),
    "quarantine_file": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="restore_file",
        required_permission=_CONTAIN,
        note="Quarantining a legitimate binary breaks whatever depended on it.",
    ),
    "restore_file": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="quarantine_file",
        required_permission=_CONTAIN,
    ),
    "kill_process": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.SELF_HEALING,
        required_permission=_CONTAIN,
        note=(
            "A killed process cannot be un-killed, but the effect does not "
            "persist: a service restarts, a user runs the program again. "
            "Self-healing is the honest answer here, not 'irreversible'."
        ),
    ),
    "run_av_scan": CapabilityContract(
        impact=ActionImpact.LOW,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.SELF_HEALING,
        required_permission=_CONTAIN,
        note="Consumes CPU on one host and finishes. Nothing to undo.",
    ),
    "run_script": CapabilityContract(
        impact=ActionImpact.SEVERE,
        approval=ApprovalRequirement.MANDATORY_HUMAN,
        reversal=Reversal.MANUAL_ONLY,
        required_permission=_CONTAIN,
        has_verification_probe=False,
        note=(
            "Arbitrary code on a production host. The platform cannot reason "
            "about what a script does, so no confidence score is meaningful and "
            "no autonomy tier executes it. Classified SEVERE rather than HIGH "
            "precisely because its blast radius is not knowable in advance."
        ),
    ),
    # ── Identity ───────────────────────────────────────────────────────────
    "disable_user": CapabilityContract(
        impact=ActionImpact.HIGH,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="enable_user",
        required_permission=_IDENTITY,
        has_verification_probe=True,
        note="Stops one person working. Reversible, and instantly noticed.",
    ),
    "enable_user": CapabilityContract(
        impact=ActionImpact.HIGH,
        approval=ApprovalRequirement.MANDATORY_HUMAN,
        reversal=Reversal.PLATFORM,
        reverse_capability="disable_user",
        required_permission=_IDENTITY,
        has_verification_probe=True,
        note=(
            "Re-enabling an account is a higher bar than disabling it: the "
            "failure mode is restoring access to a compromised identity, and "
            "no model output should be sufficient for that."
        ),
    ),
    "suspend_session": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.SELF_HEALING,
        required_permission=_IDENTITY,
        note=(
            "Forces re-authentication. Cheap, and the user restores their own "
            "access by logging in — which is why it can be automatic where "
            "disabling the account cannot."
        ),
    ),
    "revoke_session": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.SELF_HEALING,
        required_permission=_IDENTITY,
    ),
    "reset_password": CapabilityContract(
        impact=ActionImpact.HIGH,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.SELF_HEALING,
        required_permission=_IDENTITY,
        has_verification_probe=True,
        note="The user recovers through the normal reset flow, but is locked out until they do.",
    ),
    "force_mfa": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.SELF_HEALING,
        required_permission=_IDENTITY,
        note="Re-enrolment friction, not a lockout.",
    ),
    "block_user_signin": CapabilityContract(
        impact=ActionImpact.HIGH,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="enable_user",
        required_permission=_IDENTITY,
        has_verification_probe=True,
    ),
    # ── Network ────────────────────────────────────────────────────────────
    "block_ip": CapabilityContract(
        impact=ActionImpact.HIGH,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="allow_ip",
        required_permission=_NETWORK,
        has_verification_probe=True,
        note=(
            "Blocking a shared egress address, a CDN edge or a SaaS endpoint "
            "takes out far more than the intended target, and the alert rarely "
            "says which kind of address it is."
        ),
    ),
    "allow_ip": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="block_ip",
        required_permission=_NETWORK,
        has_verification_probe=True,
        note="Removing a block is a security decision, so it is not automatic.",
    ),
    "block_domain": CapabilityContract(
        impact=ActionImpact.HIGH,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="allow_domain",
        required_permission=_NETWORK,
        has_verification_probe=True,
    ),
    "allow_domain": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="block_domain",
        required_permission=_NETWORK,
    ),
    "block_hash": CapabilityContract(
        impact=ActionImpact.LOW,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.PLATFORM,
        reverse_capability="allow_hash",
        required_permission=_CONTAIN,
        note=(
            "A hash identifies one exact binary, so a wrong block affects only "
            "that file. The narrowest containment the platform has, and the "
            "one genuinely safe to automate at high confidence."
        ),
    ),
    "allow_hash": CapabilityContract(
        impact=ActionImpact.LOW,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="block_hash",
        required_permission=_CONTAIN,
    ),
    "block_ioc": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="allow_ioc",
        required_permission=_NETWORK,
        note="Breadth depends on the indicator type, so it is classified at the worst case.",
    ),
    "allow_ioc": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="block_ioc",
        required_permission=_NETWORK,
    ),
    # ── SIEM / detection content ───────────────────────────────────────────
    "create_notable_event": CapabilityContract(
        impact=ActionImpact.LOW,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.MANUAL_ONLY,
        required_permission=_TICKET,
        note="Writes a record into someone else's queue. Noise, not damage.",
    ),
    "sync_detection_rule": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="sync_detection_rule",
        required_permission=_CONTAIN,
        note=(
            "Changing detection content in the customer's SIEM can silence a "
            "rule as easily as add one. Its own reverse: sync the prior version."
        ),
    ),
    "update_watcher": CapabilityContract(
        impact=ActionImpact.MODERATE,
        approval=ApprovalRequirement.ANALYST,
        reversal=Reversal.PLATFORM,
        reverse_capability="update_watcher",
        required_permission=_CONTAIN,
    ),
    # ── Ticketing and notification ─────────────────────────────────────────
    "create_ticket": CapabilityContract(
        impact=ActionImpact.LOW,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.MANUAL_ONLY,
        required_permission=_TICKET,
    ),
    "push_case": CapabilityContract(
        impact=ActionImpact.LOW,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.MANUAL_ONLY,
        required_permission=_TICKET,
    ),
    "push_status": CapabilityContract(
        impact=ActionImpact.LOW,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.MANUAL_ONLY,
        required_permission=_TICKET,
    ),
    "notify": CapabilityContract(
        impact=ActionImpact.LOW,
        approval=ApprovalRequirement.AUTOMATIC,
        reversal=Reversal.MANUAL_ONLY,
        required_permission=_TICKET,
        note=("A message cannot be unsent, but paging the wrong channel is " "embarrassment rather than impact."),
    ),
}


def apply_contract(cls: type) -> type:
    """Class decorator: stamp the capability's contract onto an executor.

    Used instead of per-class declarations so twenty vendors implementing
    ``isolate_host`` cannot disagree about how dangerous it is — and the one
    that disagrees low is the one that auto-executes.
    """
    contract = CAPABILITY_CONTRACTS.get(getattr(cls, "capability", ""))
    if contract is None:
        # Left with the unsafe defaults, so the conformance gate names it
        # rather than the action quietly becoming dispatchable.
        return cls
    cls.impact = contract.impact
    cls.approval = contract.approval
    cls.reversal = contract.reversal
    cls.reverse_capability = contract.reverse_capability
    cls.required_permission = contract.required_permission
    cls.has_verification_probe = contract.has_verification_probe
    return cls

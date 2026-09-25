#!/usr/bin/env python3
"""Gate: every response action must declare what it does to a production estate,
and every verb the agent recommends must be one this service can perform.

Pillar 3. An action registry is only useful if it can answer, before running,
what an action does when the finding is wrong. Four things were previously
inferred rather than declared, each with its own failure mode:

  risk            inferred from the capability name in one place and a policy
                  table in another, which can disagree
  reversibility   a hardcoded list of four actions; nothing said whether a
                  fifth could be undone
  verification    absent, so an action reported success on an HTTP 200 and
                  nobody knew whether a probe existed to check the effect
  approval        no way to express "no tier may ever auto-execute this", only
                  "the current tier happens not to"

This asserts every registered executor declares a coherent contract, and that
the declarations are internally consistent — a HIGH-impact action with no
verification probe fails here rather than in an incident.

Run:  python3 scripts/check_action_contract.py
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import TypeVar

import structlog

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
ACTIONS = REPO_ROOT / "services" / "actions"
sys.path.insert(0, str(ACTIONS))


def _import_builtin_executors() -> None:
    """Import the adapter modules so they self-register."""
    import importlib

    for module in (
        "app.executors.endpoint",
        "app.executors.identity",
        "app.executors.network",
        "app.executors.siem",
        "app.executors.notification",
        "app.executors.chatops",
    ):
        try:
            importlib.import_module(module)
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            print(f"  note: could not import {module}: {type(exc).__name__}", file=sys.stderr)


def check_contracts() -> list[str]:
    from app.live_actions.contract import (
        MUST_BE_REVERSIBLE,
        NEVER_AUTONOMOUS,
        ActionContract,
        ActionImpact,
        ApprovalRequirement,
    )
    from app.live_actions.executor import LiveActionExecutor

    errors: list[str] = []

    # The contract must be reachable from the base class, or executors
    # inherit nothing and every check below passes vacuously.
    if not issubclass(LiveActionExecutor, ActionContract):
        errors.append(
            "LiveActionExecutor no longer inherits ActionContract; every executor "
            "would declare nothing and this gate would pass on an empty set"
        )
        return errors

    # Unsafe defaults are the whole reason omissions fail closed.
    if ActionContract.impact != ActionImpact.IRREVERSIBLE:
        errors.append(
            f"ActionContract.impact defaults to {ActionContract.impact.value}; it must "
            f"default to irreversible so an undeclared action fails closed"
        )
    if ActionContract.approval != ApprovalRequirement.PROHIBITED:
        errors.append(f"ActionContract.approval defaults to {ActionContract.approval.value}; it " f"must default to prohibited")
    if ActionContract.has_verification_probe is not False:
        errors.append("ActionContract.has_verification_probe must default to False")

    # The two impact tables must stay consistent with each other.
    overlap = NEVER_AUTONOMOUS & MUST_BE_REVERSIBLE
    if ActionImpact.IRREVERSIBLE in overlap:
        errors.append(
            "ActionImpact.IRREVERSIBLE appears in MUST_BE_REVERSIBLE; an " "irreversible action cannot be required to declare a reverse"
        )

    # Every concrete executor's own declaration.
    _import_builtin_executors()
    subclasses = [cls for cls in _all_subclasses(LiveActionExecutor) if not getattr(cls, "__abstractmethods__", None)]

    for cls in subclasses:
        name = f"{cls.__module__}.{cls.__name__}"

        # An intermediate base declaring neither vendor nor capability is not
        # dispatchable: the registry refuses to register it. Grading its
        # contract would report a violation nobody can act on.
        if not cls.vendor_id and not cls.capability:
            continue
        if not cls.vendor_id or not cls.capability:
            errors.append(f"{name}: declares one of vendor_id/capability but not the other")
            continue

        for problem in cls.contract_violations():
            errors.append(f"{name}: {problem}")

        # A reverse that names a capability nobody implements is worse than
        # no reverse: the rollback path believes it has one.
        if cls.reverse_capability:
            from app.live_actions.capabilities import KNOWN_CAPABILITIES

            if cls.reverse_capability not in KNOWN_CAPABILITIES:
                errors.append(
                    f"{name}: reverse_capability {cls.reverse_capability!r} is not a "
                    f"known capability, so the rollback path would look up nothing"
                )

    return errors


def check_approval_matrix() -> list[str]:
    """The matrix must never be able to lower a requirement."""
    from app.live_actions.contract import ActionImpact, ApprovalRequirement
    from app.services.approval_matrix import (
        AUTOMATIC_CONFIDENCE_FLOOR,
        TIER_MAX_AUTOMATIC,
        evaluate,
    )

    errors: list[str] = []

    # No tier may auto-execute severe or irreversible impact.
    for tier, ceiling in TIER_MAX_AUTOMATIC.items():
        if ceiling in (ActionImpact.SEVERE, ActionImpact.IRREVERSIBLE):
            errors.append(f"tier {tier} permits automatic execution up to {ceiling.value}; " f"no tier may auto-execute at that impact")

    # Severe and irreversible must have no confidence floor at all —
    # an unreachable threshold invites someone to lower it.
    for impact in (ActionImpact.SEVERE, ActionImpact.IRREVERSIBLE):
        if impact in AUTOMATIC_CONFIDENCE_FLOOR:
            errors.append(f"{impact.value} has a confidence floor defined; it must have none, " f"because no confidence makes it automatic")

    # Full confidence at the highest tier must still not auto-execute these.
    for impact in (ActionImpact.SEVERE, ActionImpact.IRREVERSIBLE):
        decision = evaluate(
            impact=impact,
            declared_approval=ApprovalRequirement.AUTOMATIC,
            confidence=1.0,
            tier="L4",
        )
        if decision.can_auto_execute:
            errors.append(
                f"{impact.value} at 100% confidence and tier L4 auto-executed; " f"the matrix lowered a requirement it must only raise"
            )

    # A contract demanding a human must survive any tier and confidence.
    decision = evaluate(
        impact=ActionImpact.LOW,
        declared_approval=ApprovalRequirement.MANDATORY_HUMAN,
        confidence=1.0,
        tier="L4",
    )
    if decision.can_auto_execute:
        errors.append("a MANDATORY_HUMAN contract auto-executed at L4/100%; the tier " "overrode the action's own declaration")

    # Absent confidence must behave as the lowest band.
    decision = evaluate(
        impact=ActionImpact.MODERATE,
        declared_approval=ApprovalRequirement.AUTOMATIC,
        confidence=None,
        tier="L4",
    )
    if decision.can_auto_execute:
        errors.append("an action with no confidence score auto-executed; a scoring bug " "would become an autonomous action")

    return errors


#: Capabilities with a contract and no executor, as of the read-only-verb
#: work. Every one is a declared rollback or integration that answers
#: `executor_not_found` at dispatch, which reads as a misconfiguration
#: rather than a capability that was never built.
#:
#: A baseline rather than a pass: the gate fails on anything new, and fails
#: again when one of these gains an executor and is not removed from the
#: list. `unisolate_host` was in this set and is not any more — the rollback
#: for the platform's most disruptive action resolved to nothing, and both
#: clients already supported it.
#:
#: Ordered by what it costs to be missing:
#:   restore_file  — the reverse of quarantine_file; a quarantined file
#:                   cannot be released through the platform that took it
#:   allow_hash    — the reverse of block_hash and vice versa; neither arm
#:   allow_ioc       exists, and allow_ioc reverses a block Defender does
#:   block_hash      implement
#:   block_user_signin — an identity verb with no vendor arm
#:   push_case, push_status — ITSM sync, never wired
#:
#: Left this set when their clients turned out to already implement them:
#: enable_user (Entra, Google Workspace), revoke_session (both),
#: allow_domain (Cloudflare), allow_ip (Cloudflare, PAN-OS, FortiGate),
#: unisolate_host (CrowdStrike, Defender, SentinelOne).
KNOWN_ORPHANS: frozenset[str] = frozenset(
    {
        "restore_file",
        "allow_hash",
        "allow_ioc",
        "block_hash",
        "block_user_signin",
        "push_case",
        "push_status",
    }
)


def check_no_orphan_capabilities() -> list[str]:
    """A declared capability must have at least one executor.

    The recurring defect in this repository, in its purest form: a
    capability with a contract, a permission and a place in the vocabulary,
    and nothing that runs it. It reads as a supported integration
    everywhere it is listed, and answers `executor_not_found` at dispatch —
    which looks like a configuration problem rather than a capability that
    was never built.

    Caught this on the read-only verbs while adding them: `search_hash` had
    a contract describing exactly why fleet-wide hash prevalence matters,
    and no implementation behind it.
    """
    from app.live_actions import builtins
    from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS

    implemented = {cls.capability for cls in builtins._BUILTIN_ADAPTERS}  # noqa: SLF001
    orphans = sorted(set(CAPABILITY_CONTRACTS) - implemented)

    errors = [
        f"{capability}: has a capability contract but no executor implements it. "
        f"It reads as supported wherever capabilities are listed and answers "
        f"executor_not_found at dispatch. Implement it or remove the contract."
        for capability in orphans
        if capability not in KNOWN_ORPHANS
    ]

    # Ratchet. A capability that finds an implementation must leave the
    # baseline, or the list becomes a place to hide new orphans.
    resolved = sorted(KNOWN_ORPHANS & implemented)
    if resolved:
        errors.append(
            f"KNOWN_ORPHANS lists {', '.join(resolved)}, which now have "
            f"executors. Remove them from the baseline — a stale exemption is "
            f"a gate that stops checking."
        )

    return errors


def check_verification_probes() -> list[str]:
    """A declared verification probe must actually exist.

    The contract marks nine capabilities `has_verification_probe=True` and
    three probes are registered. Nothing compared the two, so the declaration
    was a claim rather than a fact — and it is the specific claim the whole
    contract exists to make trustworthy: "this action is checked against the
    vendor rather than assumed from a 200".

    A capability that cannot be verified is allowed. Saying it is verified
    when it is not is what this rejects.
    """
    from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
    from app.models.action import ActionType
    from app.services.verification import _DEFAULT_PROBES

    errors: list[str] = []
    registered = {a.value for a in _DEFAULT_PROBES}
    known_action_types = {a.value for a in ActionType}

    for capability, contract in sorted(CAPABILITY_CONTRACTS.items()):
        if not contract.has_verification_probe:
            continue
        if capability in registered:
            continue
        # A capability with no matching ActionType cannot be probed at all,
        # which is a different problem and worth naming differently.
        if capability not in known_action_types:
            errors.append(
                f"{capability}: declares has_verification_probe=True but has no " f"ActionType, so the verifier can never be reached for it"
            )
        else:
            errors.append(
                f"{capability}: declares has_verification_probe=True but no probe is "
                f"registered in verification._DEFAULT_PROBES. The action would report "
                f"success on an accepted request with nothing checking the effect — "
                f"which is the claim this contract exists to make true."
            )

    # And the reverse: a probe nobody declares is a probe nobody runs
    # through the contract, so the capability is silently unverified in
    # every governance decision that reads the declaration.
    for action in sorted(registered):
        contract = CAPABILITY_CONTRACTS.get(action)
        if contract is not None and not contract.has_verification_probe:
            errors.append(
                f"{action}: a probe is registered but the contract declares "
                f"has_verification_probe=False, so governance treats it as unverified"
            )

    return errors


#: Legacy ``ActionType`` executors that are deliberately not reachable through
#: governed live-action dispatch, with the reason each one is not.
#:
#: A baseline, not a pass: the gate fails on anything new, and fails again when
#: one of these gains an adapter and is not removed.
#:
#: **Empty, and that is the point.** It held one entry, ``chatops_verify``,
#: whose reason was that it returns ``ActionStatus.RUNNING`` — the prompt went
#: out and nobody has answered — while ``LiveActionStatus`` had no state for
#: that and ``_to_live_status`` folded everything not FAILED or simulated into
#: SUCCEEDED. Registering it then would have reported an unanswered question
#: as a completed action. The answer was to build the missing state
#: (``AWAITING_COMPLETION``) rather than to keep the exemption, and the same
#: state turned out to be what evidence acquisition needed too.
KNOWN_UNGOVERNED_EXECUTORS: dict[str, str] = {}

#: ``ActionType`` members with no executor behind them at all. The legacy REST
#: route answers "No executor found for action type", which reads as a
#: misconfiguration rather than a verb nobody built.
#:
#: **Also empty.** It held three. ``capture_forensics`` was the urgent one —
#: ``services/agents/app/agents/investigation_agent.py`` proposes it by name on
#: the C2 / exfiltration path, so on the most serious class of incident the
#: product recommended evidence acquisition it could not perform — and it now
#: has a Defender investigation-package arm and a probe that reads the package
#: back. The other two were removed rather than built: ``add_ioc_to_blocklist``
#: was a second name for ``block_ioc``, and ``run_playbook`` belongs to
#: ``services/agents`` and has no verb-level contract to declare. A verb with
#: no implementation path should leave the surface, not sit on it dead.
KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR: dict[str, str] = {}


def check_capability_reachability() -> list[str]:
    """Every direction between an executor and the things that make it reachable.

    Four registries have to agree before a verb can be dispatched under
    governance: the legacy ``ActionType`` executor, the live-action adapter,
    the capability contract, and the capability vocabulary. Nothing compared
    them, so a verb could be complete in three of the four and unreachable.

    ``ack_alert`` and ``suppress_alert`` were exactly that — real executors
    with Splunk, Elastic and Defender arms, wired into ``EXECUTOR_REGISTRY``,
    and absent from the adapters, the contracts and the vocabulary. Governed
    dispatch answered ``executor_not_found`` for code that worked.

    Every comparison below runs **both ways**, which is the part that matters.
    The dominant failure in this repository is a check that compares A against
    B and never B against A: the graph-schema drift check reported OK while the
    YAML declared 17 labels and the Go code had 28, because it only ever looked
    for labels the YAML had and the code lacked. A one-directional version of
    this check would have passed on ``ack_alert`` too — it is missing in the
    direction nothing was looking.
    """
    from app.live_actions import builtins, registry
    from app.live_actions.capabilities import KNOWN_CAPABILITIES
    from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
    from app.models.action import ActionType
    from app.services.executor_registry import EXECUTOR_REGISTRY

    errors: list[str] = []
    adapters = builtins._BUILTIN_ADAPTERS  # noqa: SLF001
    adapter_capabilities = {cls.capability for cls in adapters}
    # Built by filtering rather than by adding `None` and discarding it: the
    # discard is invisible to a reader three hundred lines below, where the
    # set is unpacked as `a.value`.
    adapter_action_types = {t for t in (getattr(cls, "_legacy_action_type", None) for cls in adapters) if t is not None}

    # ── Direction 1: adapter → vocabulary ──────────────────────────────────
    # register_executor() only *warns* on an unknown capability, so this drift
    # is invisible outside a startup log. check_capability_mirror compares the
    # connectors enum against the mirror in both directions but neither
    # against the executors, which is how create_ticket and notify came to be
    # registered, contracted and dispatchable while absent from the vocabulary
    # they are validated against.
    for capability in sorted(adapter_capabilities - KNOWN_CAPABILITIES):
        errors.append(
            f"{capability}: a registered executor implements it, but it is absent "
            f"from KNOWN_CAPABILITIES and therefore from the connectors "
            f"Capability enum. The registry logs live_action.capability_unknown "
            f"for it at every startup and anything validating against the "
            f"vocabulary rejects it. Add it to both."
        )

    # ── Direction 2: adapter → contract ────────────────────────────────────
    # apply_contract() leaves the unsafe defaults when there is no entry, which
    # the per-executor grading catches indirectly. Name it directly so the
    # failure says what to do rather than "declares no required_permission".
    for capability in sorted(adapter_capabilities - set(CAPABILITY_CONTRACTS)):
        errors.append(
            f"{capability}: a registered executor implements it and no capability "
            f"contract declares what it does to an estate. Nothing decided its "
            f"impact, reversibility, verification or approval tier."
        )

    # ── Direction 3: adapter → live-action registry ────────────────────────
    # An adapter that never registers is as unreachable as one that does not
    # exist, and the only difference is that this one looks finished.
    #
    # Registering ~60 executors emits a line each; the gate's own output is
    # what a failing build needs to be readable, so drop anything below ERROR
    # for the duration.
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
    registry.reset_for_tests()
    builtin_count = builtins.register_builtin_executors(overwrite=True)
    for cls in adapters:
        if registry.get_executor(cls.vendor_id, cls.capability) is None:
            errors.append(f"{cls.__module__}.{cls.__name__}: declares " f"{cls.vendor_id}/{cls.capability} but did not register")
    if builtin_count != len(adapters):
        errors.append(f"register_builtin_executors registered {builtin_count} of " f"{len(adapters)} adapters")

    # ── Direction 4: legacy executor → adapter ─────────────────────────────
    # The one that was missing. A legacy executor with no adapter is reachable
    # only through the ActionType REST route, which has no contract, no
    # approval matrix and no autonomy policy in front of it.
    for action_type in sorted(EXECUTOR_REGISTRY, key=lambda a: a.value):
        if action_type in adapter_action_types:
            continue
        if action_type.value in KNOWN_UNGOVERNED_EXECUTORS:
            continue
        executor = EXECUTOR_REGISTRY[action_type]
        errors.append(
            f"{action_type.value}: {type(executor).__name__} is registered in "
            f"EXECUTOR_REGISTRY and no live-action adapter reaches it. Governed "
            f"dispatch answers executor_not_found for a verb that works, so the "
            f"code is unreachable from the agent loop, the planner and the "
            f"approval matrix. Add an adapter per vendor arm, a capability "
            f"contract, and the verb to the vocabulary."
        )

    # ── Direction 5: adapter → legacy executor ─────────────────────────────
    # The mirror of 4. An adapter pointing at an ActionType with no legacy
    # executor raises at execute() rather than at registration.
    for action_type in sorted(adapter_action_types, key=lambda a: a.value):
        if action_type not in EXECUTOR_REGISTRY:
            errors.append(
                f"{action_type.value}: a live-action adapter delegates to this "
                f"ActionType and EXECUTOR_REGISTRY has no executor for it. The "
                f"failure would surface at execute(), not at registration."
            )

    # ── Direction 6: ActionType → legacy executor ──────────────────────────
    for action_type in sorted(ActionType, key=lambda a: a.value):
        if action_type in EXECUTOR_REGISTRY:
            continue
        if action_type.value in KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR:
            continue
        errors.append(
            f"{action_type.value}: an ActionType with no executor in "
            f"EXECUTOR_REGISTRY. The API accepts it and then answers 'No "
            f"executor found for action type', which reads as a broken "
            f"deployment rather than a verb that was never built."
        )

    # ── Direction 7: ActionType → capability contract ──────────────────────
    # An ActionType with no reachable contract is not a cosmetic gap. The
    # submit path looks the contract up *by ActionType value* to run the
    # confidence matrix; a miss means the matrix is skipped and blast radius
    # decides alone, so a 40%-confidence guess is graded like a corroborated
    # finding. That is what happened to `notify_slack` for as long as the
    # capability was called `notify` and nothing connected the two.
    from app.live_actions.capability_contracts import (
        ACTION_TYPE_CAPABILITY_ALIASES,
        CAPABILITY_CONTRACTS,
        contract_for_action_type,
    )

    for action_type in sorted(ActionType, key=lambda a: a.value):
        if contract_for_action_type(action_type.value) is None:
            errors.append(
                f"{action_type.value}: no capability contract resolves for this "
                f"ActionType. The approval matrix has no impact to reason about, "
                f"so it is skipped and blast radius decides alone. Give the verb a "
                f"contract, or — if this is only a naming difference for a verb "
                f"that already has one — add it to ACTION_TYPE_CAPABILITY_ALIASES."
            )

    # ── Direction 8: alias map → the rest of the world, both ways ──────────
    # An alias is a claim that two names mean one verb. Three ways it can rot,
    # each checked here, because an alias nothing validates is just a lookup
    # that happens to succeed.
    known_action_type_values = {a.value for a in ActionType}
    adapter_bridges = {
        (getattr(cls, "capability", ""), getattr(cls, "_legacy_action_type", None))
        for cls in adapters
        if getattr(cls, "_legacy_action_type", None) is not None
    }
    for legacy_value, capability in sorted(ACTION_TYPE_CAPABILITY_ALIASES.items()):
        if legacy_value not in known_action_type_values:
            errors.append(
                f"ACTION_TYPE_CAPABILITY_ALIASES maps {legacy_value!r}, which is not an "
                f"ActionType. The alias can never fire; delete it or fix the key."
            )
        if capability not in CAPABILITY_CONTRACTS:
            errors.append(
                f"ACTION_TYPE_CAPABILITY_ALIASES points {legacy_value!r} at capability "
                f"{capability!r}, which has no contract — the alias resolves to nothing."
            )
        # The alias must describe a bridge that actually exists. If no adapter
        # pairs this capability with this ActionType, the two names are not
        # two names for one verb and the alias is asserting something false.
        if not any(cap == capability and lat is not None and lat.value == legacy_value for cap, lat in adapter_bridges):
            errors.append(
                f"ACTION_TYPE_CAPABILITY_ALIASES claims {legacy_value!r} and {capability!r} "
                f"are the same verb, but no adapter pairs them (no executor with "
                f"capability={capability!r} and _legacy_action_type={legacy_value!r}). "
                f"An alias asserting a bridge nobody built is worse than no alias."
            )

    # And the other way: an alias must not shadow a real capability of the
    # same name, which would silently redirect a verb that has its own contract.
    for legacy_value in sorted(ACTION_TYPE_CAPABILITY_ALIASES):
        if legacy_value in CAPABILITY_CONTRACTS:
            errors.append(
                f"{legacy_value!r} has its own capability contract AND an alias entry. "
                f"The alias is dead code at best and a silent redirect at worst; remove it."
            )

    errors.extend(_ratchet("KNOWN_UNGOVERNED_EXECUTORS", KNOWN_UNGOVERNED_EXECUTORS, {a.value for a in adapter_action_types}))
    errors.extend(
        _ratchet(
            "KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR",
            KNOWN_ACTION_TYPES_WITHOUT_EXECUTOR,
            {a.value for a in EXECUTOR_REGISTRY},
        )
    )
    return errors


#: Where the agent decides what to recommend. Parsed rather than imported: the
#: gate runs with ``services/actions`` on the path and importing the agents
#: package would pull in its whole dependency tree for three string literals.
AGENTS_APP = REPO_ROOT / "services" / "agents" / "app"


def _proposed_action_verbs() -> dict[str, list[str]]:
    """Every verb the agent can put in front of an analyst, and where from.

    Returns ``{verb: [source locations]}``. Handles the conditional form
    (``action_type=("isolate_host" if ... else "disable_user")``) because
    ``attack_path_agent`` uses it and a walker that only understood plain
    literals would silently grade half the vocabulary.
    """
    import ast

    found: dict[str, list[str]] = {}
    if not AGENTS_APP.exists():
        return found

    for path in sorted(AGENTS_APP.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if name != "ProposedAction":
                continue
            for keyword in node.keywords:
                if keyword.arg != "action_type":
                    continue
                for value in _string_literals(keyword.value):
                    found.setdefault(value, []).append(f"{path.relative_to(REPO_ROOT)}:{keyword.value.lineno}")
    return found


def _string_literals(node: object) -> list[str]:
    """Constant strings a value expression can evaluate to."""
    import ast

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return _string_literals(node.body) + _string_literals(node.orelse)
    return []


def check_agent_proposed_actions() -> list[str]:
    """A verb the agent recommends must be one this service can perform.

    The fifth registry, and the one that made ``capture_forensics`` urgent
    rather than merely untidy. The other five directions compare the actions
    service against itself; this compares it against the thing that puts a
    verb in front of a human.

    ``investigation_agent`` proposes ``capture_forensics`` by name whenever an
    investigation reaches the C2 or exfiltration stage, with
    ``requires_approval=True``. So on the most serious class of incident the
    product recommended evidence acquisition, raised an approval for it, and
    answered "No executor found for action type" when somebody approved — a
    dead control on the path where preserving evidence matters most.

    Nothing compared the two, because they live in different services and the
    proposal is a free-text string rather than the enum. That is exactly the
    shape of drift this file exists to catch, so it is checked here rather
    than left to be rediscovered.
    """
    from app.models.action import ActionType
    from app.services.executor_registry import EXECUTOR_REGISTRY

    errors: list[str] = []
    executable = {action.value for action in EXECUTOR_REGISTRY}
    known = {action.value for action in ActionType}

    for verb, locations in sorted(_proposed_action_verbs().items()):
        where = ", ".join(sorted(set(locations)))
        if verb not in known:
            errors.append(
                f"{verb}: the agent proposes this at {where} and it is not an "
                f"ActionType at all, so the action API rejects it outright. "
                f"Implement the verb or stop proposing it."
            )
        elif verb not in executable:
            errors.append(
                f"{verb}: the agent proposes this at {where} and no executor "
                f"implements it. An analyst who approves the recommendation "
                f"gets 'No executor found for action type' — a control that is "
                f"reachable from a recommendation and dead on approval. "
                f"Implement the verb or stop proposing it."
            )
    return errors


def _ratchet(name: str, baseline: dict[str, str], resolved_set: set[str]) -> list[str]:
    """A baseline may only ever shrink.

    Without this the exemption list is where the next one hides: an entry that
    quietly gained an implementation leaves the gate checking one fewer thing
    every release, and nothing says so.
    """
    resolved = sorted(set(baseline) & resolved_set)
    if not resolved:
        return []
    return [
        f"{name} lists {', '.join(resolved)}, which is no longer missing. "
        f"Remove the entry — a stale exemption is a gate that stopped checking."
    ]


def check_capability_mirror() -> list[str]:
    """The actions mirror must match the connectors Capability enum.

    capabilities.py used to document this check as a test file under
    ``services/actions/tests`` that had never been written, so the mirror it
    described had never been verified — which is how four reverse verbs the
    action contracts name ended up missing from both. This function is the
    check; capabilities.py now points at it.
    """
    import importlib.util

    errors: list[str] = []
    base = REPO_ROOT / "services" / "connectors" / "app" / "connectors" / "base.py"
    if not base.exists():
        return ["services/connectors/app/connectors/base.py not found"]

    # Loaded by path: importing the connectors package pulls in its whole
    # dependency tree, which this gate does not need.
    import re

    source = base.read_text(encoding="utf-8")
    match = re.search(r"class Capability\(str, Enum\):(.*?)\n\n\n", source, re.S)
    if not match:
        return ["could not locate the Capability enum in connectors/base.py"]
    connector_caps = set(re.findall(r'^\s+[A-Z_]+ = "([^"]+)"', match.group(1), re.M))
    del importlib

    from app.live_actions.capabilities import KNOWN_CAPABILITIES

    missing_here = connector_caps - KNOWN_CAPABILITIES
    if missing_here:
        errors.append(f"capabilities declared in connectors but missing from the actions " f"mirror: {', '.join(sorted(missing_here))}")
    missing_there = KNOWN_CAPABILITIES - connector_caps
    if missing_there:
        errors.append(
            f"capabilities in the actions mirror but missing from the connectors " f"Capability enum: {', '.join(sorted(missing_there))}"
        )
    return errors


_T = TypeVar("_T")


def _all_subclasses(cls: type[_T]) -> list[type[_T]]:
    found: list[type[_T]] = []
    for sub in cls.__subclasses__():
        found.append(sub)
        found.extend(_all_subclasses(sub))
    return found


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)

    try:
        errors = (
            check_contracts()
            + check_approval_matrix()
            + check_capability_mirror()
            + check_verification_probes()
            + check_no_orphan_capabilities()
            + check_capability_reachability()
            + check_agent_proposed_actions()
        )
    except ImportError as exc:
        print(f"action-contract: cannot import the actions package: {exc}", file=sys.stderr)
        return 2

    if errors:
        print("ACTION CONTRACT GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    from app.live_actions.executor import LiveActionExecutor

    concrete = [c for c in _all_subclasses(LiveActionExecutor) if not getattr(c, "__abstractmethods__", None)]
    print(
        f"action-contract: OK — {len(concrete)} executors declare a coherent " f"contract; the approval matrix cannot lower a requirement"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

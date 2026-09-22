#!/usr/bin/env python3
"""Gate: every response action must declare what it does to a production estate.

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
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
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
        errors.append(
            f"ActionContract.approval defaults to {ActionContract.approval.value}; it "
            f"must default to prohibited"
        )
    if ActionContract.has_verification_probe is not False:
        errors.append("ActionContract.has_verification_probe must default to False")

    # The two impact tables must stay consistent with each other.
    overlap = NEVER_AUTONOMOUS & MUST_BE_REVERSIBLE
    if ActionImpact.IRREVERSIBLE in overlap:
        errors.append(
            "ActionImpact.IRREVERSIBLE appears in MUST_BE_REVERSIBLE; an "
            "irreversible action cannot be required to declare a reverse"
        )

    # Every concrete executor's own declaration.
    _import_builtin_executors()
    subclasses = [
        cls
        for cls in _all_subclasses(LiveActionExecutor)
        if not getattr(cls, "__abstractmethods__", None)
    ]

    for cls in subclasses:
        name = f"{cls.__module__}.{cls.__name__}"

        # An intermediate base declaring neither vendor nor capability is not
        # dispatchable: the registry refuses to register it. Grading its
        # contract would report a violation nobody can act on.
        if not cls.vendor_id and not cls.capability:
            continue
        if not cls.vendor_id or not cls.capability:
            errors.append(
                f"{name}: declares one of vendor_id/capability but not the other"
            )
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
            errors.append(
                f"tier {tier} permits automatic execution up to {ceiling.value}; "
                f"no tier may auto-execute at that impact"
            )

    # Severe and irreversible must have no confidence floor at all —
    # an unreachable threshold invites someone to lower it.
    for impact in (ActionImpact.SEVERE, ActionImpact.IRREVERSIBLE):
        if impact in AUTOMATIC_CONFIDENCE_FLOOR:
            errors.append(
                f"{impact.value} has a confidence floor defined; it must have none, "
                f"because no confidence makes it automatic"
            )

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
                f"{impact.value} at 100% confidence and tier L4 auto-executed; "
                f"the matrix lowered a requirement it must only raise"
            )

    # A contract demanding a human must survive any tier and confidence.
    decision = evaluate(
        impact=ActionImpact.LOW,
        declared_approval=ApprovalRequirement.MANDATORY_HUMAN,
        confidence=1.0,
        tier="L4",
    )
    if decision.can_auto_execute:
        errors.append(
            "a MANDATORY_HUMAN contract auto-executed at L4/100%; the tier "
            "overrode the action's own declaration"
        )

    # Absent confidence must behave as the lowest band.
    decision = evaluate(
        impact=ActionImpact.MODERATE,
        declared_approval=ApprovalRequirement.AUTOMATIC,
        confidence=None,
        tier="L4",
    )
    if decision.can_auto_execute:
        errors.append(
            "an action with no confidence score auto-executed; a scoring bug "
            "would become an autonomous action"
        )

    return errors


def check_capability_mirror() -> list[str]:
    """The actions mirror must match the connectors Capability enum.

    capabilities.py documents a CI check at
    ``services/actions/tests/test_capability_mirror.py`` that compares the two
    sets. No such file exists, so the mirror it describes has never been
    verified — which is how four reverse verbs the action contracts name
    ended up missing from both.
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
        errors.append(
            f"capabilities declared in connectors but missing from the actions "
            f"mirror: {', '.join(sorted(missing_here))}"
        )
    missing_there = KNOWN_CAPABILITIES - connector_caps
    if missing_there:
        errors.append(
            f"capabilities in the actions mirror but missing from the connectors "
            f"Capability enum: {', '.join(sorted(missing_there))}"
        )
    return errors


def _all_subclasses(cls: type) -> list[type]:
    found: list[type] = []
    for sub in cls.__subclasses__():
        found.append(sub)
        found.extend(_all_subclasses(sub))
    return found


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)

    try:
        errors = check_contracts() + check_approval_matrix() + check_capability_mirror()
    except ImportError as exc:
        print(f"action-contract: cannot import the actions package: {exc}", file=sys.stderr)
        return 2

    if errors:
        print("ACTION CONTRACT GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    from app.live_actions.executor import LiveActionExecutor

    concrete = [
        c for c in _all_subclasses(LiveActionExecutor) if not getattr(c, "__abstractmethods__", None)
    ]
    print(
        f"action-contract: OK — {len(concrete)} executors declare a coherent "
        f"contract; the approval matrix cannot lower a requirement"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

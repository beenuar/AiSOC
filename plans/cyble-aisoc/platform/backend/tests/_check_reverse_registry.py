"""Registry-level invariants for the reverse-action pairing system.

This is the static counterpart to ``tests/_check_rollback`` (which exercises
the live rollback flow). Here we verify the *shape* of the tool registry
after every concrete tool module has been imported:

  1. Every tool whose ``reverse_tool`` is set names an actually-registered
     tool. A typo (``edr.relase_host``) would otherwise only surface the
     first time someone tried to roll that action back in production.
  2. Every ``WRITE_REVERSIBLE`` tool has both a ``reverse_tool`` AND a
     ``reverse_params_builder``. The rollback service refuses to invent
     reverse params, so a half-wired pair (reverse_tool set, builder
     missing) would deadlock the rollback path at runtime.
  3. ``reverse_params_builder`` is only set when ``reverse_tool`` is — a
     dangling builder usually means someone renamed/removed the reverse
     pair but forgot to drop the builder.
  4. The set of risk classes that the rollback service considers eligible
     (``_REVERSIBLE_RISK_CLASSES``) is consistent with what tools advertise:
     if a tool sets ``reverse_tool`` its risk class must be in that set,
     otherwise the audit pairing exists but ``rollback_eligibility`` will
     refuse to ever use it — a silent footgun.

Convention note (matches the comments in the WRITE-tool modules):
  - ``WRITE_REVERSIBLE`` = forward action with a paired reverse handler.
  - ``WRITE_SIGNIFICANT`` = a write action whose effect cannot be cleanly
    auto-undone, OR a tool that exists primarily as the reverse handler
    of another tool (and so deliberately does not register its own
    reverse to prevent rollback-of-rollback chains).
  - ``edr.isolate_host`` is the documented exception: ``WRITE_SIGNIFICANT``
    because isolating a host is a major blast-radius action, but
    ``edr.release_host`` is registered as its reverse so an analyst can
    still trigger paired rollback. The service includes
    ``WRITE_SIGNIFICANT`` in its eligible set specifically to allow this.

Run with:

    cd platform/backend
    python -m tests._check_reverse_registry
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Avoid touching the real DB. We don't actually open a session here, but
# importing `app.config.settings` may resolve the DB path eagerly.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-rev-registry-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "rev-registry.db")
os.environ.setdefault("AISOC_ENV", "development")

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

# Importing each tool module triggers registration on the global registry.
# Importing `app.tools` pulls in every concrete tool module via its
# package __init__ so the static check sees the full reverse-pairing
# surface, not just the modules the orchestrator happens to load at boot.
import app.tools as _all_tools  # noqa: F401, E402
from app.models.tool_call import RiskClass  # noqa: E402
from app.rollback.service import _REVERSIBLE_RISK_CLASSES  # noqa: E402
from app.tools.registry import registry  # noqa: E402


def _check_reverse_tool_targets_exist() -> None:
    """Every `reverse_tool` reference must resolve in the registry."""
    broken: list[tuple[str, str]] = []
    for td in registry.all():
        if td.reverse_tool is None:
            continue
        if registry.get(td.reverse_tool) is None:
            broken.append((td.name, td.reverse_tool))
    if broken:
        msg = "; ".join(f"{fwd} -> missing {rev}" for fwd, rev in broken)
        raise AssertionError(
            f"reverse_tool references that don't resolve in the registry: {msg}"
        )
    print(
        f"OK  all reverse_tool references resolve "
        f"({sum(1 for t in registry.all() if t.reverse_tool)} pairs)"
    )


def _check_write_reversible_has_pair() -> None:
    """`WRITE_REVERSIBLE` must be either fully paired OR explicitly opted out.

    The default expectation for a ``WRITE_REVERSIBLE`` tool is that it
    advertises both ``reverse_tool`` and ``reverse_params_builder``. The
    one allowed escape hatch is ``forward_only_reason``: a tool can be
    semantically reversible (idempotent / non-destructive) yet still
    choose not to pair a reverse handler — but only with a documented
    reason that survives code review. ``asset.upsert`` is the canonical
    example (idempotent CMDB write, no paired delete).

    What we still reject:
      * ``WRITE_REVERSIBLE`` with neither pair nor reason — undocumented
        gap, the rollback service will silently refuse.
      * ``WRITE_REVERSIBLE`` with a half-wired pair (reverse_tool set,
        builder missing). The service refuses to invent params, so this
        would deadlock at runtime.
    """
    missing: list[str] = []
    half_wired: list[str] = []
    for td in registry.all():
        if td.risk_class is not RiskClass.WRITE_REVERSIBLE:
            continue
        if td.reverse_tool is None:
            if td.is_forward_only:
                # Explicit opt-out with a documented reason — covered by
                # _check_every_write_tool_is_accounted_for. Allowed.
                continue
            missing.append(td.name)
            continue
        if td.reverse_params_builder is None:
            half_wired.append(td.name)
    if missing:
        raise AssertionError(
            "WRITE_REVERSIBLE tools without a reverse_tool AND without a "
            "forward_only_reason — rollback service can never undo them "
            "and the gap is undocumented: " + ", ".join(missing)
        )
    if half_wired:
        raise AssertionError(
            "WRITE_REVERSIBLE tools with reverse_tool but no "
            "reverse_params_builder — rollback service will refuse to "
            "dispatch them: " + ", ".join(half_wired)
        )
    paired = sum(
        1
        for t in registry.all()
        if t.risk_class is RiskClass.WRITE_REVERSIBLE and t.is_reversible
    )
    opted_out = sum(
        1
        for t in registry.all()
        if t.risk_class is RiskClass.WRITE_REVERSIBLE and t.is_forward_only
    )
    print(
        f"OK  every WRITE_REVERSIBLE tool is paired or opted out "
        f"({paired} paired + {opted_out} forward-only)"
    )


def _check_builder_implies_reverse_tool() -> None:
    """Dangling `reverse_params_builder` is almost always a bug."""
    dangling = [
        td.name
        for td in registry.all()
        if td.reverse_params_builder is not None and td.reverse_tool is None
    ]
    if dangling:
        raise AssertionError(
            "tools define reverse_params_builder but no reverse_tool — "
            "the builder is dead code and likely a rename oversight: "
            + ", ".join(dangling)
        )
    print("OK  no dangling reverse_params_builder definitions")


def _check_risk_class_eligible_when_paired() -> None:
    """If a tool exposes a reverse, its risk class must be eligible.

    Otherwise the audit pairing exists in the registry but
    ``rollback_eligibility`` will short-circuit on the risk-class gate and
    silently refuse — exactly the bug we want this check to catch.
    """
    bad: list[tuple[str, str]] = []
    for td in registry.all():
        if td.reverse_tool is None:
            continue
        if td.risk_class not in _REVERSIBLE_RISK_CLASSES:
            bad.append((td.name, td.risk_class.value))
    if bad:
        msg = "; ".join(f"{name} (risk={rc})" for name, rc in bad)
        raise AssertionError(
            "tools with a reverse_tool whose risk_class is not in the "
            f"rollback service's eligible set {_REVERSIBLE_RISK_CLASSES}: "
            f"{msg}"
        )
    print(
        "OK  every tool with a reverse_tool has a rollback-eligible risk_class"
    )


def _check_every_write_tool_is_accounted_for() -> None:
    """Every WRITE_* tool must opt into rollback OR opt out explicitly.

    The rollback subsystem treats ``WRITE_REVERSIBLE`` and
    ``WRITE_SIGNIFICANT`` tools as in-scope for paired rollback. Each such
    tool has exactly two valid shapes:

      (a) ``reverse_tool`` set (with ``reverse_params_builder``) — the
          tool participates in paired rollback.
      (b) ``forward_only_reason`` set — the tool is intentionally
          forward-only, with a documented reason that survives code
          review and shows up in the audit trail when an analyst asks
          why this action can't be undone.

    A tool with NEITHER is a coverage bug: the rollback service will
    silently refuse, and there's no documented reason why, so future
    operators / auditors can't tell intent (forward-only by design) from
    accident (someone forgot to wire the reverse). This check fails CI
    until that ambiguity is resolved one way or the other.

    Mutual exclusivity (a tool can't be both paired AND forward-only) is
    already enforced by the @tool decorator at registration time, so we
    don't re-check it here.
    """
    in_scope = (RiskClass.WRITE_REVERSIBLE, RiskClass.WRITE_SIGNIFICANT)
    gaps: list[tuple[str, str, str]] = []
    paired = 0
    forward_only = 0
    for td in registry.all():
        if td.risk_class not in in_scope:
            continue
        if td.is_reversible:
            paired += 1
        elif td.is_forward_only:
            forward_only += 1
        else:
            gaps.append((td.name, td.risk_class.value, td.integration))
    if gaps:
        msg = "; ".join(
            f"{name} [risk={rc}, integration={integ}]"
            for name, rc, integ in gaps
        )
        raise AssertionError(
            "WRITE_* tools that neither register a reverse_tool NOR set "
            "forward_only_reason — undocumented rollback gap, must pick "
            "one: " + msg
        )
    total = paired + forward_only
    print(
        f"OK  every WRITE_* tool is accounted for "
        f"({paired} paired + {forward_only} forward-only = {total} total)"
    )


def main() -> None:
    _check_reverse_tool_targets_exist()
    _check_write_reversible_has_pair()
    _check_builder_implies_reverse_tool()
    _check_risk_class_eligible_when_paired()
    _check_every_write_tool_is_accounted_for()
    print("PASS  reverse-action registry invariants")


if __name__ == "__main__":
    main()

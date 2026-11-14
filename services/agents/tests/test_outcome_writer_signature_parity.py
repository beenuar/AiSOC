"""Every outcome writer accepts what the caller passes.

Four classes implement `record_outcome` — the real persister, the shadow
writer, the replay shadow, and the protocol they share. Adding
`injection_suspected` to the caller broke three of them, and **not one test
failed on the exception**: the call site sits inside
`contextlib.suppress(Exception)`, so a `TypeError` for an unexpected keyword
was swallowed and the write simply stopped happening.

What surfaced was `writes_attempted["record_outcome"] == 0` in an unrelated
replay test, three files away from the cause. That is the same shape as the
SOAR executors whose client signatures drifted because simulation mode never
constructed the client: a call that is never made in the tested path cannot
reveal a signature that no longer matches.

So the parity is asserted directly, by comparing parameters rather than by
calling through and hoping something notices.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest
from app.memory import outcomes as outcomes_module
from app.replay.shadow import ShadowTriageWriter as ReplayShadowWriter
from app.workers.shadow_mode import ShadowModeTriageWriter
from app.workers.triage_persistence import LiveTriageWriter, TriageWriter

#: The free function is the contract. Everything else must accept what it
#: accepts, minus `self` and the two positional arguments.
CANONICAL = outcomes_module.record_outcome

WRITERS = (
    ("TriageWriter protocol", TriageWriter),
    ("shadow_mode.ShadowModeTriageWriter", ShadowModeTriageWriter),
    ("triage_persistence.LiveTriageWriter", LiveTriageWriter),
    ("replay.shadow.ShadowTriageWriter", ReplayShadowWriter),
)


def _keyword_params(fn) -> set[str]:
    return {
        name
        for name, p in inspect.signature(fn).parameters.items()
        if name not in ("self", "tenant_id", "signature") and p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD)
    }


def test_the_canonical_writer_declares_the_injection_flag() -> None:
    """The rule the others are measured against.

    Stated separately so a future change that removes it from the canonical
    function fails here rather than silently relaxing every parity case
    below into a comparison of two empty sets.
    """
    assert "injection_suspected" in _keyword_params(CANONICAL)


@pytest.mark.parametrize(("label", "cls"), WRITERS)
def test_every_writer_accepts_the_canonical_keywords(label: str, cls: Any) -> None:
    missing = _keyword_params(CANONICAL) - _keyword_params(cls.record_outcome)
    assert not missing, (
        f"{label}.record_outcome does not accept {sorted(missing)}. The call site is inside "
        "contextlib.suppress(Exception), so the TypeError is swallowed and the write stops "
        "happening with no error anywhere"
    )


@pytest.mark.parametrize(("label", "cls"), WRITERS)
def test_no_writer_requires_something_the_caller_does_not_pass(label: str, cls: Any) -> None:
    """The other direction.

    A writer that adds a required keyword of its own is just as broken, and
    fails in exactly the same silent way.
    """
    required = {
        name
        for name, p in inspect.signature(cls.record_outcome).parameters.items()
        if name not in ("self", "tenant_id", "signature")
        and p.default is inspect.Parameter.empty
        and p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD)
    }
    unknown = required - _keyword_params(CANONICAL)
    assert not unknown, f"{label}.record_outcome requires {sorted(unknown)}, which no caller passes"


def test_the_concrete_writer_passes_the_flag_through() -> None:
    """Accepting it and dropping it is the same defect one layer down.

    `PostgresTriageWriter.record_outcome` forwards to the free function; a
    parameter it accepts and never forwards would satisfy every case above
    while the prior still lost the flag.
    """
    from app.workers import triage_persistence

    source = inspect.getsource(triage_persistence)
    forwarding = source.split("await outcomes_module.record_outcome(")[1]
    assert "injection_suspected=injection_suspected" in forwarding.split(")")[0], (
        "the concrete writer accepts injection_suspected and does not forward it, so the "
        "flag stops at the port and the prior never carries it"
    )

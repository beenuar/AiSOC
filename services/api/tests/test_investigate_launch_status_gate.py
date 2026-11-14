"""Launching an agent investigation must advance the case's status.

The defect
----------
The v17 canonical ladder declares `new -> triaged` only, and the launch
path gated its status bump with `_status_transition_ok(current,
"investigating")` — a strict one-edge check. Cases created at `new`
(auto-triage default) therefore never advanced: the gate returned False,
no UPDATE ran, and the failure was silent because nothing raised.

The launch gate is deliberately *not* the PATCH gate. An investigation is
a deliberate analyst action on the case, so it may walk forward along the
ladder; PATCH stays one-edge-only, and terminal cases stay terminal —
reopening is the explicit POST /reopen path.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints.cases import (
    _forward_to_investigating_ok,
    _status_transition_ok,
)


@pytest.mark.parametrize("status", ["new", "triaged"])
def test_launch_advances_open_pre_investigating_cases(status: str) -> None:
    # The exact regression: `new` used to be rejected here.
    assert _forward_to_investigating_ok(status) is True


@pytest.mark.parametrize("status", ["investigating", "contained"])
def test_launch_never_moves_backwards_or_repeats(status: str) -> None:
    assert _forward_to_investigating_ok(status) is False


@pytest.mark.parametrize("status", ["resolved", "closed"])
def test_launch_never_touches_terminal_cases(status: str) -> None:
    assert _forward_to_investigating_ok(status) is False


def test_patch_stays_one_edge_only() -> None:
    # The strict ladder gate is unchanged: new cannot PATCH to investigating.
    assert _status_transition_ok("new", "investigating") is False
    assert _status_transition_ok("triaged", "investigating") is True

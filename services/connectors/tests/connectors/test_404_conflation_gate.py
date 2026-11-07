"""A 404 and a 403 stay different facts in the connector tree.

Runs the gate's own two-directional self-test inside the connectors suite,
so the detector cannot quietly stop detecting while the gate keeps printing
a comfortable OK. The same arrangement as ``test_paging_gate.py``, and for
the same reason: these two defects are siblings, and both were invisible
precisely because the thing that should have reported them was silent.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_GATE = Path(__file__).resolve().parents[4] / "scripts" / "check_connector_404_conflation.py"


def _load():  # noqa: ANN202 — module object
    spec = importlib.util.spec_from_file_location("check_connector_404_conflation", _GATE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_connector_404_conflation"] = module
    spec.loader.exec_module(module)
    return module


pytestmark = pytest.mark.skipif(not _GATE.exists(), reason="gate script is outside this service's build context")


@pytest.mark.parametrize(
    "shape",
    ["_VIOLATION", "_VIOLATION_BOOLOP", "_VIOLATION_NOT_IN"],
)
def test_the_detector_fires_on_every_spelling_of_the_conflation(shape: str) -> None:
    """A detector that knows one syntax is the hole this repository keeps finding."""
    gate = _load()
    assert gate._classify(getattr(gate, shape)) is True


@pytest.mark.parametrize(
    "shape",
    ["_CLEAN_SPLIT", "_CLEAN_404_ALONE", "_CLEAN_UNRELATED_NUMBERS"],
)
def test_the_detector_stays_quiet_on_correct_code(shape: str) -> None:
    """Both directions.

    ``_CLEAN_UNRELATED_NUMBERS`` is the one that matters: 404 is an ordinary
    integer, and the first cut of this gate flagged ``page_size in (403,
    404)``. A gate that flags correct code is switched off within a week.
    """
    gate = _load()
    assert gate._classify(getattr(gate, shape)) is False


def test_no_connector_files_a_404_as_a_permissions_problem() -> None:
    """A regression here means a new connector is reporting our wrong URL as the tenant's plan."""
    gate = _load()
    undeclared, _ = gate.audit()
    assert undeclared == [], (
        "a 404 is accepted alongside a 401/403 with no vendor response list behind it. Either split "
        "the branch, or record in _REVIEWED where the vendor publishes 404 for that endpoint.\n"
        + "\n".join(f"  {module}.{function}:{line}" for module, function, line, _why in undeclared)
    )


def test_gitlab_no_longer_conflates_them() -> None:
    """Issue #1754: the stream that polled a route GitLab never served."""
    gate = _load()
    undeclared, reviewed = gate.audit()
    assert not [entry for entry in undeclared if entry[0] == "gitlab"]
    assert not [name for name in reviewed if name.startswith("gitlab.")]

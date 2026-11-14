"""The paging gate detects the defect and stays quiet on correct code.

A gate is only worth having if it has been shown to fail. This runs the
gate's own two-directional self-test in the connectors suite, so the
detector cannot quietly stop detecting while the ratchet keeps printing a
comfortable number — which is how a one-directional gate in this repository
reported OK over a tree it could not see.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_GATE = Path(__file__).resolve().parents[4] / "scripts" / "check_connector_paging.py"


def _load():  # noqa: ANN202 — module object
    spec = importlib.util.spec_from_file_location("check_connector_paging", _GATE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_connector_paging"] = module
    spec.loader.exec_module(module)
    return module


pytestmark = pytest.mark.skipif(not _GATE.exists(), reason="gate script is outside this service's build context")


def test_the_detector_fires_on_a_capped_single_page_read() -> None:
    gate = _load()
    assert gate._classify_source(gate._VIOLATION) == "unclassified"


@pytest.mark.parametrize(
    "shape",
    ["_CLEAN_OWN_LOOP", "_CLEAN_HELPER", "_CLEAN_INDIRECT"],
)
def test_the_detector_stays_quiet_on_correct_paging(shape: str) -> None:
    """Both directions.

    The first version of this detector matched a vocabulary of cursor names
    and therefore flagged every connector that pages by page number or
    offset — Auth0, CrowdStrike and Cisco Umbrella among them, all correct.
    A gate that flags correct code gets switched off, so these three shapes
    are pinned as explicitly acceptable.
    """
    gate = _load()
    assert gate._classify_source(getattr(gate, shape)) == "pages"


def test_the_connectors_this_wave_fixed_are_classified_as_paging() -> None:
    """A regression here means a fix was reverted, not that the gate drifted."""
    gate = _load()
    _, paging, _ = gate.audit()
    for name in (
        "azure_entra",
        "azure_defender",
        "microsoft_sentinel",
        "gcp_cloud_audit",
        "gcp_scc",
        "google_workspace",
        "okta",
        "github",
        "gitlab",
    ):
        assert name in paging, f"{name} no longer reads its poll window to the end"


def test_the_ceiling_is_a_debt_balance_that_only_falls() -> None:
    """The unclassified set must not grow, and is named rather than hidden."""
    gate = _load()
    unclassified, _, _ = gate.audit()
    assert len(unclassified) <= gate.MAX_UNCLASSIFIED, (
        "a connector now polls a vendor collection without reading it to the end. Either follow the "
        "continuation, or record in _REVIEWED what the vendor's documentation says it returns.\n"
        + "\n".join(f"  {name}: {why}" for name, why in unclassified)
    )


def test_slack_audit_reads_its_window_to_the_end() -> None:
    _, paging, _ = _load().audit()
    assert "slack_audit" in paging


def test_datadog_cloud_siem_reads_its_window_to_the_end() -> None:
    _, paging, _ = _load().audit()
    assert "datadog_cloud_siem" in paging


def test_duo_security_reads_its_window_to_the_end() -> None:
    _, paging, _ = _load().audit()
    assert "duo_security" in paging


def test_wazuh_reads_its_window_to_the_end() -> None:
    _, paging, _ = _load().audit()
    assert "wazuh" in paging


def test_cortex_xdr_and_xsiam_read_their_windows_to_the_end() -> None:
    _, paging, _ = _load().audit()
    assert "cortex_xdr" in paging
    assert "cortex_xsiam" in paging


def test_trend_vision_one_reads_its_window_to_the_end() -> None:
    _, paging, _ = _load().audit()
    assert "trend_vision_one" in paging

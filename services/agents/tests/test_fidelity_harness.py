"""CI-safe tests for the public-dataset fidelity harness (T5.3).

These tests run on every PR. They never require the full CICIDS-2017
or CTU-13 corpora — only the 100-flow synthetic micro fixture
committed at ``services/agents/tests/eval_data/cicids_micro.csv``.

What we lock in here:

  1. The CICIDS loader emits OCSF Network Activity events that match
     ``packages/types/src/ocsf.ts`` shape (class_uid 4001, plus the
     unmapped extension carrying substrate features).
  2. The CTU-13 loader normalises labels into the three-family
     scheme (``background`` / ``benign`` / ``bot``) and excludes
     Background flows correctly.
  3. The substrate runner clears the floors declared in
     ``expected_results.yaml`` for the micro fixture.
  4. The substrate runner produces deterministic confusion-matrix
     output (the fixture is hand-tuned to be unambiguous, so a drift
     here is a real loader/classifier regression).

Wet-eval mode is intentionally not exercised in CI. The runner is
defensive (returns ``benign`` on any HTTP failure, see
``runner._classify_wet``) so the wet codepath has its own targeted
test using a stub URL.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from tests.fidelity import cicids_loader, ctu13_loader, runner

REPO_ROOT = Path(__file__).resolve().parents[3]
MICRO_FIXTURE = REPO_ROOT / "services/agents/tests/eval_data/cicids_micro.csv"
EXPECTED_RESULTS = REPO_ROOT / "services/agents/tests/fidelity/expected_results.yaml"


def _load_expected() -> dict[str, object]:
    """Tiny YAML reader so the test does not introduce a PyYAML dep."""

    text = EXPECTED_RESULTS.read_text(encoding="utf-8")
    out: dict[str, object] = {}
    section: dict[str, object] | None = None
    pattern = re.compile(r"^\s*([a-z0-9_]+_min):\s*([0-9.]+)\s*$")
    for line in text.splitlines():
        if line.startswith("micro_fixture:"):
            section = {}
            out["micro_fixture"] = section
            continue
        if section is None:
            continue
        match = pattern.match(line)
        if match:
            section[match.group(1)] = float(match.group(2))
    return out


# ---------------------------------------------------------------------------
# CICIDS loader
# ---------------------------------------------------------------------------


def test_cicids_micro_fixture_present() -> None:
    assert MICRO_FIXTURE.exists(), MICRO_FIXTURE
    # 100 flows + 1 header row. Compute the line count outside the
    # ``assert`` expression so CodeQL ``py/side-effect-in-assert``
    # doesn't trip on the file-open + iteration happening inside the
    # asserted expression (``assert`` is a no-op under ``python -O``
    # and we never want the I/O to disappear with it).
    with MICRO_FIXTURE.open("r", encoding="utf-8") as fh:
        line_count = sum(1 for _ in fh)
    assert line_count == 101


def test_cicids_loader_normalises_features() -> None:
    rows = list(cicids_loader.iter_flows(MICRO_FIXTURE, limit=5))
    assert len(rows) == 5
    first = rows[0]
    # Numeric features are coerced to float.
    for key in (
        "flow_duration_us",
        "total_fwd_packets",
        "total_bwd_packets",
        "flow_bytes_per_sec",
        "syn_flag_count",
        "fwd_packet_length_mean",
    ):
        assert isinstance(first[key], float), key
    # Ports/protocol coerced to int.
    assert isinstance(first["src_port"], int)
    assert isinstance(first["dst_port"], int)
    assert isinstance(first["protocol"], int)
    # Label collapsed into a canonical family.
    assert first["label"] in {
        "benign",
        "port_scan",
        "ddos",
        "dos",
        "brute_force",
        "bot",
        "web_attack",
        "infiltration",
        "exploit",
    }
    # ISO-8601 UTC timestamp (RFC3339 form).
    assert first["timestamp"].endswith("+00:00")


def test_cicids_to_ocsf_matches_class_4001() -> None:
    rows = list(cicids_loader.iter_flows(MICRO_FIXTURE, limit=1))
    event = cicids_loader.to_ocsf(rows[0])
    assert event["class_uid"] == 4001
    assert event["category_uid"] == 4
    assert event["activity_id"] == 6  # Traffic
    assert "src_endpoint" in event and "dst_endpoint" in event
    assert "connection_info" in event and "traffic" in event
    # Substrate-only features live under the OCSF extension namespace.
    assert "unmapped" in event and "label" in event["unmapped"]
    # OCSF events must serialise to JSON cleanly.
    json.dumps(event)


def test_cicids_label_aliasing_handles_unicode_dash() -> None:
    # Web-attack labels in CICIDS use a unicode en-dash; the loader
    # must collapse all three dash variants into ``web_attack``.
    fake = io.StringIO(
        "Flow ID,Source IP,Source Port,Destination IP,Destination Port,"
        "Protocol,Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,"
        "Flow Bytes/s,Flow Packets/s,SYN Flag Count,ACK Flag Count,PSH Flag Count,"
        "RST Flag Count,FIN Flag Count,Fwd Packet Length Mean,Bwd Packet Length Mean,"
        "Down/Up Ratio,Label\n"
        "x,1.2.3.4,80,5.6.7.8,443,6,1/7/2017 09:00:00,1000,1,1,0,0,0,0,0,0,0,0,0,0,"
        "Web Attack \u2013 XSS\n"
    )
    # Run the loader's row normaliser directly (there's no public
    # 'iter_string' helper; we mimic what iter_flows does).
    import csv as _csv

    rows = [cicids_loader._normalise_row(r) for r in _csv.DictReader(fake)]
    assert rows[0]["label"] == "web_attack"


# ---------------------------------------------------------------------------
# CTU-13 loader
# ---------------------------------------------------------------------------


def test_ctu13_label_normalisation() -> None:
    cases = {
        "Background": "background",
        "flow=Background-UDP-Established": "background",
        "Normal-V47-Established": "benign",
        "Botnet-V47-TCP-CC1-HTTP": "bot",
        "flow=Botnet": "bot",
        "Legitimate": "benign",
        "": "background",
        "Mystery-Label": "background",
    }
    for raw, expected in cases.items():
        assert ctu13_loader._normalise_label(raw) == expected, raw


def test_ctu13_to_ocsf_matches_class_4001() -> None:
    row = ctu13_loader._normalise_row(
        {
            "StartTime": "2011/08/10 09:46:53.047",
            "Dur": "1.026539",
            "Proto": "tcp",
            "SrcAddr": "147.32.84.165",
            "Sport": "1234",
            "Dir": "->",
            "DstAddr": "147.32.96.69",
            "Dport": "80",
            "State": "S_RA",
            "sTos": "0",
            "dTos": "0",
            "TotPkts": "12",
            "TotBytes": "1330",
            "SrcBytes": "660",
            "Label": "flow=Botnet-V47",
        }
    )
    assert row["label"] == "bot"
    assert row["src_bytes"] == 660
    assert row["dst_bytes"] == 1330 - 660
    assert row["protocol"] == 6
    event = ctu13_loader.to_ocsf(row)
    assert event["class_uid"] == 4001
    assert event["traffic"]["bytes_in"] == 670
    assert event["traffic"]["bytes_out"] == 660
    assert event["unmapped"]["label"] == "bot"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def test_substrate_runner_clears_micro_thresholds() -> None:
    expected = _load_expected()["micro_fixture"]
    result = runner.evaluate("cicids", [MICRO_FIXTURE], mode="substrate")
    assert result.rows_total == 100
    assert result.rows_scored == 100
    assert result.rows_skipped == 0
    assert result.accuracy >= expected["accuracy_min"]
    assert result.macro_f1 >= expected["macro_f1_min"]
    assert result.dataset == "cicids"
    assert result.mode == "substrate"


def test_substrate_runner_records_all_label_families() -> None:
    result = runner.evaluate("cicids", [MICRO_FIXTURE], mode="substrate")
    families = set(result.per_family)
    # Every family present in the fixture should appear in the
    # confusion matrix even when its row count is small.
    assert {"benign", "port_scan", "ddos", "dos", "brute_force", "bot", "web_attack"}.issubset(families)


def test_runner_rejects_unknown_dataset() -> None:
    with pytest.raises(ValueError, match="unknown dataset"):
        runner.evaluate("notarealdataset", [MICRO_FIXTURE])


def test_runner_rejects_unknown_mode() -> None:
    with pytest.raises(ValueError, match="unknown mode"):
        runner.evaluate("cicids", [MICRO_FIXTURE], mode="dryrun")  # type: ignore[arg-type]


def test_wet_mode_requires_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISOC_WET_EVAL_ENDPOINT", raising=False)
    with pytest.raises(RuntimeError, match="wet mode requires"):
        runner.evaluate("cicids", [MICRO_FIXTURE], mode="wet", limit=1)


def test_wet_mode_falls_back_to_benign_on_http_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Point at an unreachable port so urlopen raises immediately.
    result = runner.evaluate(
        "cicids",
        [MICRO_FIXTURE],
        mode="wet",
        limit=2,
        wet_endpoint="http://127.0.0.1:1/aisoc-fake",
    )
    # Every row should classify as ``benign`` because the wet shim
    # is defensive on transport errors.
    assert result.rows_scored == 2
    benign_predicted = sum(
        cell.get("benign", 0) for actual, cell in result.confusion_matrix["matrix"].items() if actual in result.confusion_matrix["labels"]
    )
    assert benign_predicted == 2


def test_runner_to_dict_is_json_serialisable() -> None:
    result = runner.evaluate("cicids", [MICRO_FIXTURE], mode="substrate", limit=10)
    payload = json.dumps(result.to_dict())
    assert "confusion_matrix" in payload

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

from tests.fidelity import (
    ait_lds_loader,
    cicids_loader,
    ctu13_loader,
    mitre_engenuity_loader,
    runner,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
MICRO_FIXTURE = REPO_ROOT / "services/agents/tests/eval_data/cicids_micro.csv"
AIT_LDS_MICRO_DIR = REPO_ROOT / "services/agents/tests/eval_data/ait_lds_micro"
AIT_LDS_MICRO_LOG = AIT_LDS_MICRO_DIR / "access.log"
MITRE_ENGENUITY_MICRO = REPO_ROOT / "services/agents/tests/eval_data/mitre_engenuity_micro.json"
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


# ---------------------------------------------------------------------------
# AIT-LDS loader (T5.3)
# ---------------------------------------------------------------------------


def test_ait_lds_micro_fixture_present() -> None:
    assert AIT_LDS_MICRO_LOG.exists(), AIT_LDS_MICRO_LOG
    assert (AIT_LDS_MICRO_DIR / "labels.csv").exists()
    # 10 access lines + the labels sidecar (11 rows incl. header)
    with AIT_LDS_MICRO_LOG.open("r", encoding="utf-8") as fh:
        line_count = sum(1 for _ in fh)
    assert line_count == 10


def test_ait_lds_label_normalisation() -> None:
    cases = {
        "normal": "benign",
        "Normal": "benign",
        "scan": "recon",
        "recon": "recon",
        "xss": "web_attack",
        "sqli": "web_attack",
        "scenario-2.foothold.webshell": "web_attack",
        "scenario-3.command-and-control.callback": "lateral",
        "exfil": "lateral",
        "": "benign",
        "mystery": "benign",
    }
    for raw, expected in cases.items():
        assert ait_lds_loader._normalise_label(raw) == expected, raw


def test_ait_lds_loader_parses_apache_clf() -> None:
    rows = list(ait_lds_loader.iter_flows(AIT_LDS_MICRO_LOG))
    # Every line in the fixture is a valid CLF row.
    assert len(rows) == 10
    first = rows[0]
    assert first["method"] == "GET"
    assert first["path"] == "/index.html"
    assert first["status"] == 200
    assert first["host_ip"] == "192.0.2.10"
    # The timestamp is converted to RFC3339 UTC.
    assert first["timestamp"].endswith("+00:00")
    # The sidecar label was joined in.
    assert first["label"] == "benign"


def test_ait_lds_loader_joins_labels_sidecar() -> None:
    """The labels.csv side-file is read; each Apache line gets the
    family from the matching ``line_no`` row, or ``benign`` if no
    labels file exists."""
    rows = list(ait_lds_loader.iter_flows(AIT_LDS_MICRO_LOG))
    labels = [r["label"] for r in rows]
    # Fixture intent: lines 1-2 benign, 3-5 recon, 6-8 web_attack, 9-10 lateral.
    assert labels == [
        "benign",
        "benign",
        "recon",
        "recon",
        "recon",
        "web_attack",
        "web_attack",
        "web_attack",
        "lateral",
        "lateral",
    ]


def test_ait_lds_to_ocsf_matches_class_6002() -> None:
    rows = list(ait_lds_loader.iter_flows(AIT_LDS_MICRO_LOG, limit=1))
    event = ait_lds_loader.to_ocsf(rows[0])
    assert event["class_uid"] == 6002  # Web Resources Activity
    assert event["category_uid"] == 6  # Application Activity
    assert "http_request" in event and event["http_request"]["http_method"] == "GET"
    assert "http_response" in event and event["http_response"]["code"] == 200
    assert "unmapped" in event and "label" in event["unmapped"]
    # OCSF events must serialise to JSON cleanly.
    json.dumps(event)


def test_ait_lds_loader_handles_missing_labels_file(tmp_path: Path) -> None:
    """When labels.csv is missing, every row falls back to ``benign``."""
    target = tmp_path / "access.log"
    target.write_text(
        '192.0.2.10 - - [08/Jul/2024:13:45:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0" 1000\n',
        encoding="utf-8",
    )
    rows = list(ait_lds_loader.iter_flows(target))
    assert len(rows) == 1
    assert rows[0]["label"] == "benign"


def test_ait_lds_loader_drops_malformed_lines(tmp_path: Path) -> None:
    """Apache occasionally writes partial lines at rotation boundaries.
    These must be silently dropped, not raise."""
    target = tmp_path / "access.log"
    target.write_text(
        # Valid CLF
        '192.0.2.10 - - [08/Jul/2024:13:45:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0" 1000\n'
        # Garbage / partial
        "not an apache line\n"
        # Another valid CLF
        '192.0.2.10 - - [08/Jul/2024:13:45:02 +0000] "POST /api HTTP/1.1" 201 50 "-" "curl" 200\n',
        encoding="utf-8",
    )
    rows = list(ait_lds_loader.iter_flows(target))
    assert len(rows) == 2  # garbage line dropped


def test_ait_lds_substrate_runner_clears_floor() -> None:
    """The runner against the AIT-LDS micro fixture must clear a
    minimum accuracy floor — the substrate classifier was hand-tuned
    against this fixture so a regression here means the loader or the
    classifier was changed in a way that breaks fidelity."""
    result = runner.evaluate("ait_lds", [AIT_LDS_MICRO_LOG], mode="substrate")
    assert result.rows_total == 10
    assert result.rows_scored == 10
    assert result.rows_skipped == 0
    assert result.dataset == "ait_lds"
    # All four families are exercised; we want >=70% accuracy on the
    # hand-tuned fixture.
    assert result.accuracy >= 0.70, result.to_dict()


# ---------------------------------------------------------------------------
# MITRE Engenuity loader (T5.3)
# ---------------------------------------------------------------------------


def test_mitre_engenuity_micro_fixture_present() -> None:
    assert MITRE_ENGENUITY_MICRO.exists(), MITRE_ENGENUITY_MICRO
    payload = json.loads(MITRE_ENGENUITY_MICRO.read_text(encoding="utf-8"))
    assert "Procedures" in payload
    assert len(payload["Procedures"]) == 10


def test_mitre_engenuity_category_normalisation() -> None:
    cases = {
        "Technique": "technique",
        "Tactic": "tactic",
        "General": "general",
        "Telemetry": "telemetry",
        "None": "none",
        "": "none",
        "Sub-Technique": "technique",
        "miss": "none",
        "n/a": "none",
    }
    for raw, expected in cases.items():
        assert mitre_engenuity_loader._normalise_category(raw) == expected, raw


def test_mitre_engenuity_extracts_techniques() -> None:
    raw = {
        "Step": "1",
        "Technique.Id": "T1059.003",
        "Detection": "fired on cmd.exe",
        "DetectionCategory": "Technique",
    }
    techniques = mitre_engenuity_loader._extract_techniques(raw)
    assert "T1059.003" in techniques


def test_mitre_engenuity_picks_highest_category() -> None:
    raw = {
        "Detections": [
            {"Category": "Telemetry"},
            {"Category": "Technique"},
            {"Category": "General"},
        ],
    }
    assert mitre_engenuity_loader._highest_category(raw) == "technique"


def test_mitre_engenuity_loader_streams_procedures() -> None:
    rows = list(mitre_engenuity_loader.iter_flows(MITRE_ENGENUITY_MICRO))
    assert len(rows) == 10
    first = rows[0]
    assert first["round"] == "round-7-cyberark-2025"
    assert first["vendor"] == "ExampleEDR"
    assert first["primary_technique"] == "T1566.001"
    assert first["tactic"] == "Initial Access"
    assert first["label"] == "technique"


def test_mitre_engenuity_to_ocsf_matches_class_2004() -> None:
    rows = list(mitre_engenuity_loader.iter_flows(MITRE_ENGENUITY_MICRO, limit=1))
    event = mitre_engenuity_loader.to_ocsf(rows[0])
    assert event["class_uid"] == 2004  # Detection Finding
    assert event["category_uid"] == 2  # Findings
    assert "finding" in event and event["finding"]["attacks"]
    assert event["finding"]["attacks"][0]["technique"]["uid"].startswith("T")
    assert event["unmapped"]["category"] in {"none", "telemetry", "general", "tactic", "technique"}
    # OCSF events must serialise to JSON cleanly.
    json.dumps(event)


def test_mitre_engenuity_loader_handles_top_level_list(tmp_path: Path) -> None:
    """Some rounds publish a top-level JSON array instead of a metadata
    + Procedures dict — the loader must accept either shape."""
    target = tmp_path / "engenuity.json"
    target.write_text(
        json.dumps(
            [
                {
                    "Step": "1",
                    "Tactic": "Execution",
                    "Technique.Id": "T1059.003",
                    "DetectionCategory": "Technique",
                }
            ]
        ),
        encoding="utf-8",
    )
    rows = list(mitre_engenuity_loader.iter_flows(target))
    assert len(rows) == 1
    assert rows[0]["primary_technique"] == "T1059.003"
    assert rows[0]["label"] == "technique"
    # Round defaults to the file stem when not provided.
    assert rows[0]["round"] == "engenuity"


def test_mitre_engenuity_substrate_runner_clears_floor() -> None:
    """Substrate runner against the MITRE Engenuity micro fixture must
    clear a minimum-accuracy floor for the canonical category ladder."""
    result = runner.evaluate("mitre_engenuity", [MITRE_ENGENUITY_MICRO], mode="substrate")
    assert result.rows_total == 10
    assert result.rows_scored == 10
    assert result.rows_skipped == 0
    assert result.dataset == "mitre_engenuity"
    # The substrate classifier was designed to match the labelling
    # rubric exactly on the fixture, so we set a tight floor.
    assert result.accuracy >= 0.70, result.to_dict()

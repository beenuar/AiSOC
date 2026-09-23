"""The model matrix must never invent a number it did not measure.

Phase 4's last open item was a model matrix: the wet eval runs one model,
so its numbers describe the agent *on that model* and say nothing about
whether the result is a property of the agent or of the backend. Those are
different claims and only one is about this project.

Which makes the honesty requirement sharper than usual. A matrix exists to
be compared across rows, so a row that reads `0.000` because nothing ran
is worse than a missing row — it invites the conclusion that the model was
graded and scored zero.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE = REPO_ROOT / "scripts" / "run_model_matrix.py"

spec = importlib.util.spec_from_file_location("run_model_matrix", MODULE)
assert spec and spec.loader
matrix = importlib.util.module_from_spec(spec)
sys.modules["run_model_matrix"] = matrix
spec.loader.exec_module(matrix)


WET_BLOCK = {
    "model": "stub",
    "incidents": 200,
    "mitre_accuracy": 0.97,
    "abstention_rate": 0.04,
    "mean_groundedness": 0.93,
    "latency_seconds": {"p95": 4.2},
    "tokens": {"total": {"mean": 3100}},
    "usd": {"total": 1.84, "mean": 0.0092},
}


@pytest.fixture
def stub_eval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A stand-in for run_evals.py emitting the same wet-block shape."""
    script = tmp_path / "fake_run_evals.py"
    script.write_text(
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "out = Path(args[args.index('--wet-out') + 1])\n"
        "model = os.environ.get('AISOC_MODEL_PIN_TRIAGE', 'unknown')\n"
        "if model == 'broken':\n"
        "    sys.stderr.write('provider returned 400\\n'); raise SystemExit(1)\n"
        "out.parent.mkdir(parents=True, exist_ok=True)\n"
        f"block = {WET_BLOCK!r}\n"
        "block['model'] = model\n"
        "out.write_text(json.dumps(block))\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(matrix, "RUN_EVALS", script)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    return script


class TestUnmeasuredIsNotZero:
    def test_no_key_reports_not_measured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("WET_EVAL_OPENAI_KEY", raising=False)
        assert matrix.has_live_key() is False

        result = matrix.ModelResult("gpt-4o", measured=False, error="no live key")
        assert "metrics" not in result.to_dict()

    def test_the_table_says_not_measured_rather_than_dashes(self) -> None:
        """Dashes across seven columns read as zero at a glance."""
        table = matrix.render_markdown([matrix.ModelResult("gpt-4o", measured=False, error="no live key")])
        assert "not measured" in table
        assert "0.0%" not in table

    def test_absent_key_exits_zero(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        """An absent key is a configuration state, not a build failure.
        Failing here would make every fork's CI red."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("WET_EVAL_OPENAI_KEY", raising=False)
        assert matrix.main(["--models", "gpt-4o"]) == 0


class TestMeasurement:
    def test_each_model_is_graded(self, stub_eval: Path, tmp_path: Path) -> None:
        out = tmp_path / "matrix.json"
        matrix.main(["--models", "a,b", "--out", str(out)])
        payload = json.loads(out.read_text())
        assert [r["model"] for r in payload["results"]] == ["a", "b"]
        assert all(r["measured"] for r in payload["results"])

    def test_every_pin_role_is_set(self, stub_eval: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Setting one role leaves the others on their default model, which
        makes the matrix a comparison of one agent rather than the system."""
        captured: dict = {}
        real_run = subprocess.run

        def spy(cmd, **kwargs):
            captured.update(kwargs.get("env") or {})
            return real_run(cmd, **kwargs)

        monkeypatch.setattr(matrix.subprocess, "run", spy)
        matrix.main(["--models", "modelX"])
        for role in matrix.PIN_ROLES:
            assert captured.get(f"AISOC_MODEL_PIN_{role.upper()}") == "modelX"

    def test_a_failing_model_is_a_result_not_an_abort(self, stub_eval: Path, tmp_path: Path) -> None:
        """A model that cannot complete the corpus is exactly what a reader
        wants to know, and must not take the other rows with it."""
        out = tmp_path / "matrix.json"
        matrix.main(["--models", "good,broken,alsogood", "--out", str(out)])
        payload = json.loads(out.read_text())
        by_model = {r["model"]: r for r in payload["results"]}
        assert by_model["good"]["measured"] is True
        assert by_model["alsogood"]["measured"] is True
        assert by_model["broken"]["measured"] is False
        assert "400" in by_model["broken"]["error"]

    def test_the_projection_keeps_the_comparable_fields(self) -> None:
        projected = matrix._project(WET_BLOCK)
        for key in ("mitre_accuracy", "abstention_rate", "usd_per_incident", "latency_p95_s"):
            assert projected[key] is not None

    def test_a_limited_run_is_marked_partial(self, stub_eval: Path, tmp_path: Path) -> None:
        """A limited matrix is not comparable with a full one, and must not
        be published as one."""
        out = tmp_path / "matrix.json"
        matrix.main(["--models", "a", "--limit", "10", "--out", str(out)])
        payload = json.loads(out.read_text())
        assert payload["partial"] is True
        assert payload["limit"] == 10


def test_it_wraps_the_real_eval_rather_than_reimplementing_it() -> None:
    """A second definition of "accuracy" can drift from the one on the
    scoreboard — which is exactly what the alert-reduction suite did.
    """
    source = MODULE.read_text(encoding="utf-8")
    assert "run_evals.py" in source
    for reimplementation in ("def grade", "def score_incident", "def _accuracy"):
        assert reimplementation not in source, (
            f"{reimplementation} suggests the matrix is computing its own " f"metrics rather than collating the eval's"
        )

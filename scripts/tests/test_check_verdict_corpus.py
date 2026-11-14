"""The verdict-corpus gate fails on a corpus it should fail on.

Depth plan 1.1. `check_verdict_corpus.py --self-test` already injects one
violation of each rule into an in-memory copy of the shipped corpus. This
suite is the half that cannot be faked from inside the gate: it writes a
doctored corpus to disk, points the real program at it through `--repo-root`,
and reads the process exit code.

The distinction matters here more than usual. A gate's own self-test is
written by whoever wrote the gate, against the data structure the gate
already parses correctly. What it cannot prove is that the program as CI
invokes it — argument parsing, root resolution, file loading, exit codes —
refuses anything at all. Five gates in this repository reported OK over a
repository containing nothing, and every one of them had tests.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts" / "check_verdict_corpus.py"
CORPUS_REL = Path("services/agents/tests/eval_data/verdict/verdict_corpus_v1.json")


def _corpus() -> dict:
    return json.loads((ROOT / CORPUS_REL).read_text(encoding="utf-8"))


def _run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(GATE), "--repo-root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def tree(tmp_path: Path):
    """A directory holding a writable copy of the corpus and nothing else."""

    def write(doc: dict) -> Path:
        target = tmp_path / CORPUS_REL
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(doc), encoding="utf-8")
        return tmp_path

    return write


class TestItPassesTheCorpusThatShipped:
    def test_the_real_tree_is_clean(self) -> None:
        """The negative control for every refusal below. Without it they
        would all pass against a gate that refuses everything."""
        done = _run(ROOT)
        assert done.returncode == 0, done.stdout + done.stderr

    def test_it_prints_what_a_constant_answer_would_score(self) -> None:
        """The number the plan's 60% ceiling is about. Printing it on every
        run means a corpus drifting towards one class is visible in the log
        before it is a failure."""
        done = _run(ROOT)
        assert "a constant answer scores at most 50.0%" in done.stdout


class TestItRefusesAnUnbalancedCorpus:
    def test_a_corpus_over_the_sixty_percent_ceiling_fails(self, tree) -> None:
        """The headline negative control. Relabel enough items that answering
        `true_positive` to everything would score 69%, and the gate must say
        so rather than counting four classes and calling it balanced."""
        doc = _corpus()
        flipped = 0
        for item in doc["decisions"]:
            if item["expected_disposition"] != "true_positive" and flipped < 14:
                item["expected_disposition"] = "true_positive"
                flipped += 1
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "over the 60% ceiling" in done.stderr
        assert "without reading anything" in done.stderr

    def test_an_all_malicious_corpus_fails(self, tree) -> None:
        """The shape every other labelled set in this tree actually has."""
        doc = _corpus()
        for item in doc["decisions"]:
            item["expected_disposition"] = "true_positive"
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "one class" in done.stderr

    def test_a_minority_class_under_the_scorers_floor_fails(self, tree) -> None:
        """The gate's floor is the scorer's floor. If they drifted apart, a
        corpus could pass here and be refused at the point of publication."""
        doc = _corpus()
        kept = 1
        for item in doc["decisions"]:
            if item["expected_disposition"] == "false_positive":
                if kept:
                    kept -= 1
                    continue
                item["expected_disposition"] = "benign"
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "under the 5% floor" in done.stderr


class TestItRefusesTheOtherWaysTheCorpusCanRot:
    def test_a_benign_item_without_a_malicious_twin_fails(self, tree) -> None:
        doc = _corpus()
        for item in doc["decisions"]:
            if item["expected_disposition"] != "true_positive":
                item["twin_of"] = "VRD-NOT-A-REAL-ID"
                break
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "not in the corpus" in done.stderr

    def test_a_twin_pair_separable_on_something_other_than_evidence_fails(self, tree) -> None:
        """If the malicious half of a pair is always the more severe one, an
        agent scores well on severity alone and the corpus measures nothing."""
        doc = _corpus()
        for item in doc["decisions"]:
            if item["expected_disposition"] == "true_positive":
                item["severity"] = "critical"
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "shortcut an agent can take instead of reading" in done.stderr

    def test_an_item_with_no_licence_fails(self, tree) -> None:
        """'Refuse any source without a licence', in the plan's words."""
        doc = _corpus()
        doc["decisions"][0]["provenance"].pop("license")
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "A source without a licence is refused, not assumed" in done.stderr

    def test_a_non_redistributable_licence_fails(self, tree) -> None:
        doc = _corpus()
        doc["decisions"][0]["is_synthetic"] = False
        doc["decisions"][0]["provenance"].update({"source": "ctu-13", "license": "CC-BY-NC-SA-4.0"})
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "redistribution allow-list" in done.stderr

    def test_a_synthetic_item_claiming_real_provenance_fails(self, tree) -> None:
        """The binding honesty rule, enforced rather than documented. An
        invented event that names a dataset is the one failure mode a reader
        cannot detect for themselves."""
        doc = _corpus()
        doc["decisions"][0]["provenance"]["source"] = "a-real-customer-queue"
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "must not imply it came from somewhere" in done.stderr

    def test_a_routable_address_fails(self, tree) -> None:
        doc = _corpus()
        doc["decisions"][0]["evidence"]["sourceIPAddress"] = "8.8.8.8"
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "outside the RFC 5737 documentation" in done.stderr

    def test_a_header_count_drifting_from_the_body_fails(self, tree) -> None:
        """The README quotes these. A header nobody checks takes the
        documentation stale with it."""
        doc = _corpus()
        doc["synthetic_items"] = 40
        done = _run(tree(doc))
        assert done.returncode == 1
        assert "header says" in done.stderr


class TestItRefusesToRenderAVerdictOnNothing:
    def test_a_tree_with_no_corpus_is_an_error_not_a_pass(self, tmp_path: Path) -> None:
        """Found nothing and scanned nothing print the same word unless the
        second one raises."""
        done = _run(tmp_path)
        assert done.returncode == 2
        assert "does not exist" in done.stderr

    def test_an_empty_decisions_list_is_an_error(self, tree) -> None:
        doc = _corpus()
        doc["decisions"] = []
        done = _run(tree(doc))
        assert done.returncode == 2
        assert "cannot measure anything" in done.stderr

    def test_malformed_json_is_an_error(self, tmp_path: Path) -> None:
        target = tmp_path / CORPUS_REL
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{not json", encoding="utf-8")
        done = _run(tmp_path)
        assert done.returncode == 2
        assert "not valid JSON" in done.stderr


class TestTheGateProvesItself:
    def test_the_self_test_passes(self) -> None:
        """One command answers "does this gate still detect what it claims",
        which is the point of running it before CI does."""
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, str(GATE), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        )
        assert done.returncode == 0, done.stdout + done.stderr
        assert "FAIL" not in done.stdout

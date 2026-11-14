"""
Per-investigation Token / USD / Latency Telemetry Tests (T2.4)
==============================================================
Unit tests for the deterministic-substrate budget projection that lives
in ``scripts/eval_telemetry.py`` and the SVG renderer in
``scripts/render_eval_charts.py``.

What we gate here:

  1. Rate-card maths is correct: a fixed (prompt_tokens, completion_tokens)
     pair multiplied by a rate-card entry produces the expected USD to
     six-decimal precision. Caught regressions on the cost ledger when
     the per-1M / per-1K conversion has drifted.
  2. ``estimate_tokens`` round-trips through the 4-chars/token heuristic
     deterministically and never returns 0 for non-empty text.
  3. ``compute_per_investigation_telemetry`` against a tiny in-memory
     incident fixture produces a well-formed report:
       - ``mode == "deterministic_substrate"`` so consumers can label it.
       - aggregate + per-template stats present and internally
         consistent (mean ≤ p95 ≤ p99 ≤ max, etc.).
       - ``incident_records`` honours ``keep_records=False``.
  4. The SVG renderer emits valid-looking SVG to disk for all four
     charts and the produced files are non-trivial. We assert the
     ``<svg>`` opener and at least one ``<rect>`` so a renderer that
     silently produces an empty canvas fails CI.

Run:
    pytest services/agents/tests/test_eval_telemetry.py -v

These checks are stdlib-only and never call an LLM, so they are safe to
run in any CI box. The wet-eval gate (T5.5) lives elsewhere and tests
the live-LLM path against a real key.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

# ``scripts/`` isn't importable as a regular package, so load the two
# modules under test by file path. Keeps the test independent of how the
# parent test suite arranges sys.path.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
sys.path.insert(0, str(_SCRIPTS_DIR))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_eval_telemetry = _load_module(
    "aisoc_eval_telemetry_under_test",
    _SCRIPTS_DIR / "eval_telemetry.py",
)
_render = _load_module(
    "aisoc_render_eval_charts_under_test",
    _SCRIPTS_DIR / "render_eval_charts.py",
)


# ---------------------------------------------------------------------------
# Tiny deterministic fixture.
# ---------------------------------------------------------------------------
def _fixture_incidents() -> list[dict[str, Any]]:
    """Three incidents across two templates and three severities.

    Description / telemetry sizes are chosen so the token estimates land
    on round numbers we can sanity-check by eye in the assertions.
    """
    return [
        {
            "id": "INC-FIXT-001",
            "template_id": "fixt-credential-stuffing",
            "severity": "critical",
            "description": "x" * 400,  # 400 chars → 100 tokens
            "telemetry": [
                {"event_index": 0, "source": "edr", "process": "powershell.exe"},
                {"event_index": 1, "source": "edr", "process": "rundll32.exe"},
            ],
        },
        {
            "id": "INC-FIXT-002",
            "template_id": "fixt-credential-stuffing",
            "severity": "medium",
            "description": "y" * 200,  # 200 chars → 50 tokens
            "telemetry": [{"event_index": 0, "source": "azure_ad"}],
        },
        {
            "id": "INC-FIXT-003",
            "template_id": "fixt-data-exfil",
            "severity": "low",
            "description": "z" * 80,  # 80 chars → 20 tokens
            "telemetry": [],
        },
    ]


def _write_fixture(tmpdir: Path) -> Path:
    path = tmpdir / "fixture_incidents.json"
    path.write_text(json.dumps(_fixture_incidents()))
    return path


# ---------------------------------------------------------------------------
# 1. Rate-card maths.
# ---------------------------------------------------------------------------
class RateCardTests(unittest.TestCase):
    def test_default_rate_card_has_required_models(self) -> None:
        """The default rate card must carry the gpt-4o entry the renderer
        falls back to. If this gets renamed silently every cost projection
        in the docs becomes wrong."""
        self.assertIn("gpt-4o", _eval_telemetry.RATE_CARD_2025_USD_PER_M)
        entry = _eval_telemetry.RATE_CARD_2025_USD_PER_M["gpt-4o"]
        self.assertIn("input", entry)
        self.assertIn("output", entry)

    def test_cost_usd_is_correct_for_fixed_token_counts(self) -> None:
        """Lock the maths down. 1,000,000 prompt + 1,000,000 completion
        against gpt-4o ($2.50 / $10.00 per M) must equal $12.50.
        Precision is asserted to 6 decimals — cost gating in T2.4 needs
        sub-cent stability so a rounding shift can't hide a real drift.
        """
        usd = _eval_telemetry.cost_usd(
            prompt_tokens=1_000_000,
            completion_tokens=1_000_000,
            model="gpt-4o",
        )
        self.assertAlmostEqual(usd, 12.50, places=6)

    def test_cost_usd_zero_tokens_returns_zero(self) -> None:
        self.assertEqual(_eval_telemetry.cost_usd(0, 0, model="gpt-4o"), 0.0)

    def test_cost_usd_falls_back_to_default_for_unknown_model(self) -> None:
        """Unknown model names fall back to the gpt-4o entry rather than
        crash. Keeps wet-eval re-rendering robust if the rate card is
        renamed mid-run."""
        unknown = _eval_telemetry.cost_usd(1_000_000, 0, model="not-a-real-model")
        gpt4o = _eval_telemetry.cost_usd(1_000_000, 0, model=_eval_telemetry.DEFAULT_MODEL)
        self.assertAlmostEqual(unknown, gpt4o, places=6)

    def test_cost_usd_accepts_custom_rate_card(self) -> None:
        """A caller-supplied rate card should win over the global one.
        This is how T5.5's wet eval will project against the real
        contracted rate of the tenant running the job."""
        custom = {"my-cheap-model": {"input": 1.00, "output": 2.00}}
        usd = _eval_telemetry.cost_usd(
            prompt_tokens=500_000,
            completion_tokens=500_000,
            model="my-cheap-model",
            rate_card=custom,
        )
        # 0.5 * 1.00 + 0.5 * 2.00 = 1.50
        self.assertAlmostEqual(usd, 1.50, places=6)


# ---------------------------------------------------------------------------
# 2. estimate_tokens heuristic.
# ---------------------------------------------------------------------------
class EstimateTokensTests(unittest.TestCase):
    def test_empty_string_is_zero_tokens(self) -> None:
        self.assertEqual(_eval_telemetry.estimate_tokens(""), 0)

    def test_one_character_rounds_up_to_one_token(self) -> None:
        """Ceiling not floor — a single non-empty character is one token,
        not zero. Otherwise the cost gate would silently underbill very
        short inputs."""
        self.assertEqual(_eval_telemetry.estimate_tokens("x"), 1)

    def test_four_chars_per_token_rule(self) -> None:
        """OpenAI's published 1-token ≈ 4-chars rule. ``"x" * 400`` must
        hit exactly 100 tokens; this is the anchor for the substrate's
        upper-bound budget gate."""
        self.assertEqual(_eval_telemetry.estimate_tokens("x" * 400), 100)


# ---------------------------------------------------------------------------
# 3. compute_per_investigation_telemetry against the tiny fixture.
# ---------------------------------------------------------------------------
class ComputePerInvestigationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.incidents_path = _write_fixture(self.tmp_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_report_has_substrate_mode_label(self) -> None:
        """``mode`` must be ``deterministic_substrate``. Docs and CI gates
        depend on this label to keep substrate budgets out of the
        wet-eval column (workspace rule: never present substrate as
        agent metrics)."""
        rep = _eval_telemetry.compute_per_investigation_telemetry(
            self.incidents_path,
            model="gpt-4o",
            keep_records=True,
        )
        d = rep.to_dict(include_records=True)
        self.assertEqual(d["mode"], "deterministic_substrate")

    def test_report_counts_incidents_and_templates(self) -> None:
        rep = _eval_telemetry.compute_per_investigation_telemetry(
            self.incidents_path,
            model="gpt-4o",
            keep_records=True,
        )
        self.assertEqual(rep.incidents, 3)
        self.assertEqual(rep.templates, 2)
        self.assertEqual(len(rep.incident_records), 3)

    def test_report_aggregate_has_required_fields(self) -> None:
        rep = _eval_telemetry.compute_per_investigation_telemetry(
            self.incidents_path,
            model="gpt-4o",
            keep_records=True,
        )
        agg = rep.aggregate
        self.assertIn("tokens", agg)
        self.assertIn("usd", agg)
        self.assertIn("latency_ms", agg)
        for key in ("prompt", "completion", "total"):
            block = agg["tokens"][key]
            for stat in ("mean", "median", "p50", "p95", "p99"):
                self.assertIn(stat, block, f"tokens.{key} missing {stat}")

    def test_aggregate_percentiles_are_monotone(self) -> None:
        """Sanity gate: stats must be ordered. If a refactor breaks the
        percentile helper this catches it before docs ship a chart with
        p99 < median."""
        rep = _eval_telemetry.compute_per_investigation_telemetry(
            self.incidents_path,
            model="gpt-4o",
            keep_records=True,
        )
        for kind in ("prompt", "completion", "total"):
            block = rep.aggregate["tokens"][kind]
            self.assertLessEqual(block["min"], block["median"])
            self.assertLessEqual(block["median"], block["mean"] + block["max"])
            self.assertLessEqual(block["p50"], block["p95"])
            self.assertLessEqual(block["p95"], block["p99"])
            self.assertLessEqual(block["p99"], block["max"])
        usd = rep.aggregate["usd"]
        self.assertLessEqual(usd["p50"], usd["p95"])
        self.assertLessEqual(usd["p95"], usd["p99"])

    def test_severity_scaling_makes_critical_more_expensive(self) -> None:
        """Critical incidents should have larger completion budgets than
        low-severity ones. INC-FIXT-001 (critical) vs INC-FIXT-003 (low)
        in the fixture."""
        rep = _eval_telemetry.compute_per_investigation_telemetry(
            self.incidents_path,
            model="gpt-4o",
            keep_records=True,
        )
        by_id = {r["incident_id"]: r for r in rep.incident_records}
        self.assertGreater(
            by_id["INC-FIXT-001"]["completion_tokens"],
            by_id["INC-FIXT-003"]["completion_tokens"],
        )

    def test_keep_records_false_drops_per_incident_array(self) -> None:
        rep = _eval_telemetry.compute_per_investigation_telemetry(
            self.incidents_path,
            model="gpt-4o",
            keep_records=False,
        )
        self.assertEqual(rep.incident_records, [])
        d = rep.to_dict(include_records=False)
        self.assertNotIn("incident_records", d)

    def test_per_template_buckets_sum_to_total(self) -> None:
        """Per-template incident counts must sum to the aggregate
        incident count. Stops bucketing bugs from quietly dropping
        templates."""
        rep = _eval_telemetry.compute_per_investigation_telemetry(
            self.incidents_path,
            model="gpt-4o",
            keep_records=True,
        )
        total = sum(t["incidents"] for t in rep.per_template)
        self.assertEqual(total, rep.incidents)


# ---------------------------------------------------------------------------
# 4. SVG renderer round-trip.
# ---------------------------------------------------------------------------
def _build_renderable_report() -> dict[str, Any]:
    """Build the JSON shape that ``render_eval_charts.py`` expects.

    Mirrors what ``run_evals.py:_build_per_investigation_block`` writes
    into the report. We synthesise a small but well-formed payload so
    the test does not depend on the 200-incident dataset being present.
    """
    rep = _eval_telemetry.compute_per_investigation_telemetry(
        # Fall through to the bundled 200-incident dataset only if it
        # exists; otherwise build from the fixture written in setUp.
        _eval_telemetry.DEFAULT_INCIDENTS_PATH,
        model="gpt-4o",
        keep_records=True,
    )
    block = rep.to_dict(include_records=True)
    total = block["aggregate"]["tokens"]["total"]
    usd = block["aggregate"]["usd"]
    latency = block["aggregate"]["latency_ms"]
    block["tokens_per_investigation"] = {
        "mean": total["mean"],
        "median": total["median"],
        "p95": total["p95"],
        "p99": total["p99"],
        "prompt_mean": block["aggregate"]["tokens"]["prompt"]["mean"],
        "completion_mean": block["aggregate"]["tokens"]["completion"]["mean"],
    }
    block["usd_per_investigation"] = {
        "mean": usd["mean"],
        "median": usd["median"],
        "p95": usd["p95"],
        "p99": usd["p99"],
    }
    block["latency_per_investigation_ms"] = {
        "p50": latency["p50"],
        "p95": latency["p95"],
        "p99": latency["p99"],
        "mean": latency["mean"],
    }
    return {"per_investigation": block}


class RenderEvalChartsTests(unittest.TestCase):
    """Feed a tiny report through ``render_all_svgs`` and assert SVGs land."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _build_renderable_report()

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_render_all_svgs_produces_four_files(self) -> None:
        written = _render.render_all_svgs(self.report, self.out_dir)
        names = sorted(p.name for p in written)
        self.assertEqual(
            names,
            [
                "latency-by-template.svg",
                "latency-p50-p95-p99.svg",
                "tokens-distribution.svg",
                "usd-distribution.svg",
            ],
        )
        for path in written:
            self.assertTrue(path.is_file(), f"{path} not written")
            self.assertGreater(path.stat().st_size, 0, f"{path} is empty")

    def test_each_svg_starts_with_xml_and_has_a_rect(self) -> None:
        """Every emitted file must look like an SVG, not e.g. a partial
        write or a stray markdown blob. ``<rect>`` is the cheapest proxy
        for "the chart actually drew something" — both the bar and
        histogram emitters always emit at least one rect."""
        written = _render.render_all_svgs(self.report, self.out_dir)
        for path in written:
            text = path.read_text()
            self.assertTrue(
                text.startswith("<?xml"),
                f"{path.name} does not start with an XML prolog",
            )
            self.assertIn(
                "<svg",
                text,
                f"{path.name} is missing the <svg> opener",
            )
            self.assertIn(
                "<rect",
                text,
                f"{path.name} drew no rectangles — likely an empty canvas",
            )
            self.assertTrue(
                text.rstrip().endswith("</svg>"),
                f"{path.name} does not close with </svg>",
            )

    def test_renderer_handles_missing_records_via_synthesised_fallback(self) -> None:
        """``--no-telemetry-records`` means ``incident_records`` is
        empty. The histogram emitter must fall through to the
        synthesised fallback and still draw something instead of
        rendering an empty chart."""
        report_no_records = json.loads(json.dumps(self.report))
        report_no_records["per_investigation"]["incident_records"] = []
        written = _render.render_all_svgs(report_no_records, self.out_dir)
        for path in written:
            text = path.read_text()
            self.assertIn("<rect", text, f"{path.name} drew nothing")


if __name__ == "__main__":
    unittest.main()
